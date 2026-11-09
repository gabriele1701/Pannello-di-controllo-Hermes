"""Fondamenta: vocabolari, tabelle, vista del tier effettivo, invarianti.

Revision ID: 0001_fondamenta
Revises:
Create Date: 2026-11-09

Questa migrazione contiene lo schema completo e **tutti gli invarianti del
dominio espressi come vincoli del database**, non come controlli applicativi.

La ragione e' nel perimetro del problema. Questa applicazione decide cosa gli
agenti LLM possono fare: se un invariante vivesse solo nel codice Python,
basterebbe un'altra via d'accesso al database — una console psql, uno script
di manutenzione, un bug in una rotta futura — per aggirarlo. Un'applicazione
si aggira, un vincolo di integrita' no.

Gli invarianti applicati qui:

1. **Monotonia del tier.** Un override deve avere un tier STRETTAMENTE
   superiore al tier effettivo corrente, dove il tier effettivo e' il massimo
   fra il tier dichiarato e tutti gli override gia' registrati. Trigger
   ``tier_overrides_monotonia``, SQLSTATE ``HM409``.
2. **Append-only su ``tier_overrides``.** Nessun UPDATE, nessun DELETE.
   Trigger ``vieta_modifica``, SQLSTATE ``HM403``.
3. **Append-only su ``audit_events``.** Stesso trigger, stessa ragione.
4. **Forma canonica dei CIDR.** Il tipo ``cidr`` di PostgreSQL rifiuta da
   solo un valore con bit a destra della maschera.
5. **Alias dentro il perimetro.** Un alias deve cadere in una delle reti
   dichiarate, al momento dell'inserimento E al momento in cui una rete viene
   rimossa. Due trigger, SQLSTATE ``HM422``.

Perche' la monotonia e' un trigger e non un CHECK: un CHECK valuta una sola
riga e non puo' leggere le altre righe della tabella, quindi non puo'
confrontarsi con il massimo gia' registrato per quel tool. Il confronto
richiede una query, e una query in un vincolo e' un trigger.
"""

from __future__ import annotations

from alembic import op

revision: str = "0001_fondamenta"
down_revision: str | None = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ---------------------------------------------------------------------- #
    # Vocabolari
    #
    # Sono gli stessi enum di hermes-core (mcp_server/contracts.py,
    # mcp_server/audit.py). Riprodotti come tipi ENUM nativi e non come
    # colonne di testo con un CHECK: un ENUM nativo rende impossibile
    # scrivere un valore fuori vocabolario da qualunque client, e per `tier`
    # porta in piu' l'ORDINAMENTO.
    # ---------------------------------------------------------------------- #

    # L'ordine di dichiarazione E' l'ordinamento del tipo. Da qui `verde <
    # giallo < rosso`, `max()` e `GREATEST()` funzionano nativamente sul tier,
    # e l'invariante di monotonia si scrive come un confronto, senza colonne
    # di rango parallele da tenere sincronizzate.
    op.execute("CREATE TYPE tier AS ENUM ('verde', 'giallo', 'rosso')")
    op.execute(
        "COMMENT ON TYPE tier IS "
        "'Asse tecnico del rischio. L''ordine di dichiarazione e'' "
        "l''ordinamento: verde < giallo < rosso.'"
    )

    # Esito di una invocazione. `denied` separato da `error` di proposito:
    # un rifiuto deliberato della policy non e' un guasto, e contare i due
    # insieme confonderebbe «la macchina ha fallito» con «la policy ha detto
    # no» su uno strumento il cui prodotto e' la traccia.
    op.execute("CREATE TYPE call_outcome AS ENUM ('ok', 'error', 'denied', 'pending')")

    # Agenti. Vocabolario chiuso, come in hermes-core: un agente non e' una
    # stringa libera, e un tool registrato per un agente inesistente sarebbe
    # un tool che nessuno possiede.
    op.execute(
        "CREATE TYPE owner_agent AS ENUM "
        "('orchestrator', 'echo_dummy', 'vuln_assessment', 'pentest_kali')"
    )

    # Che bersaglio accetta un tool, e quindi se il perimetro gli si applica.
    # `none` e' il default e sta sul lato restrittivo: un tool che non
    # dichiara un bersaglio non ne accetta uno.
    op.execute("CREATE TYPE target_kind AS ENUM ('none', 'host')")

    # Origine dell'autorizzazione di una invocazione.
    op.execute("CREATE TYPE authorized_by AS ENUM ('policy', 'user', 'none')")

    # Tipi di evento del log. Tutti e dodici quelli di hermes-core
    # (LogAction), non un sottoinsieme: il log e' una vista di un file JSONL
    # prodotto da quel server, e un vocabolario piu' povero renderebbe
    # l'ingestione una riscrittura. `concurrency_not_shared` non viene piu'
    # emessa ma resta nel vocabolario, perche' i log scritti prima la
    # contengono e un log append-only non si rilegge togliendo un valore.
    op.execute(
        """
        CREATE TYPE log_action AS ENUM (
            'agent_invoked',
            'agent_result',
            'tool_registered',
            'tool_registration_rejected',
            'tool_alias_detected',
            'override_set',
            'override_rejected',
            'override_store_loaded',
            'override_not_persisted',
            'concurrency_not_shared',
            'tool_call',
            'secret_access'
        )
        """
    )

    # Da dove viene un override registrato, e quindi quanto dura.
    # Corrisponde a OverrideScope di hermes-core, meno i due valori che non
    # possono descrivere una riga persistita: `none` (nessun override) e
    # `session` (vale solo per la connessione, quindi non si scrive).
    op.execute("CREATE TYPE override_source AS ENUM ('config', 'persistent')")

    # ---------------------------------------------------------------------- #
    # users
    # ---------------------------------------------------------------------- #
    op.execute(
        """
        CREATE TABLE users (
            id            bigserial PRIMARY KEY,
            username      text        NOT NULL UNIQUE,
            password_hash text        NOT NULL,
            created_at    timestamptz NOT NULL DEFAULT now(),
            CONSTRAINT users_username_non_vuoto
                CHECK (length(btrim(username)) > 0),
            -- L'hash argon2 inizia sempre con $argon2. Il CHECK impedisce che
            -- un hash di altro tipo — o una password in chiaro — finisca in
            -- questa colonna per una svista in uno script di manutenzione.
            CONSTRAINT users_password_hash_argon2
                CHECK (password_hash LIKE '$argon2%')
        )
        """
    )
    op.execute(
        "COMMENT ON COLUMN users.password_hash IS "
        "'Hash argon2id. Mai la password in chiaro, mai uno SHA nudo.'"
    )

    # ---------------------------------------------------------------------- #
    # tools
    #
    # L'identita' di un tool e' (exec_path, exec_sha256, exec_args): e' cio'
    # che viene davvero eseguito. I tre campi sono di SOLA LETTURA per questa
    # applicazione — li registra hermes-core all'avvio — e i pattern dei
    # CHECK sono gli stessi dei validatori di ToolSpec.
    # ---------------------------------------------------------------------- #
    op.execute(
        """
        CREATE TABLE tools (
            id              bigserial    PRIMARY KEY,
            tool_id         text         NOT NULL UNIQUE,
            agent           owner_agent  NOT NULL,
            declared_tier   tier         NOT NULL,
            personal_data   boolean      NOT NULL,
            requires_container boolean   NOT NULL DEFAULT false,
            target_kind     target_kind  NOT NULL DEFAULT 'none',
            exec_path       text         NOT NULL,
            exec_sha256     text         NOT NULL,
            exec_args       text[]       NOT NULL DEFAULT '{}',
            description     text         NOT NULL,
            registered_at   timestamptz  NOT NULL DEFAULT now(),

            CONSTRAINT tools_tool_id_formato
                CHECK (tool_id ~ '^[a-z0-9]+([._-][a-z0-9]+)*$'
                       AND length(tool_id) BETWEEN 3 AND 64),

            -- Lo SHA pinna la versione eseguita: uno script modificato non
            -- corrisponde e non va eseguito. Un valore che non sia 64 esadecimali
            -- minuscoli non e' uno SHA-256 e non pinna niente.
            CONSTRAINT tools_exec_sha256_formato
                CHECK (exec_sha256 ~ '^[0-9a-f]{64}$'),

            -- exec_path deve restare dentro il repo versionato: un percorso
            -- assoluto o con '..' puntarebbe a un eseguibile arbitrario del
            -- filesystem, aggirando il pinning via SHA.
            CONSTRAINT tools_exec_path_confinato
                CHECK (exec_path <> ''
                       AND exec_path NOT LIKE '/%'
                       -- chr(92) e non un pattern LIKE: il backslash
                       -- e' il carattere di escape di LIKE, quindi
                       -- cercarlo come letterale richiederebbe tre
                       -- livelli di quoting annidati.
                       AND strpos(exec_path, chr(92)) = 0
                       AND exec_path NOT LIKE '%..%'),

            CONSTRAINT tools_description_non_vuota
                CHECK (length(btrim(description)) > 0
                       AND length(description) <= 512)
        )
        """
    )
    op.execute(
        "COMMENT ON COLUMN tools.declared_tier IS "
        "'Tier dichiarato all''integrazione. E'' un PAVIMENTO: nessun "
        "override lo abbassa. Corrisponde a ToolSpec.default_tier di "
        "hermes-core.'"
    )
    op.execute(
        "COMMENT ON COLUMN tools.personal_data IS "
        "'Secondo asse del rischio, indipendente dal tier. Un tool verde che "
        "indaga persone fisiche richiede comunque una conferma dedicata.'"
    )
    op.execute(
        "COMMENT ON COLUMN tools.target_kind IS "
        "'Se il tool accetta un bersaglio, e quindi se il perimetro gli si "
        "applica. Il default none non ne accetta nessuno.'"
    )
    op.execute("CREATE INDEX tools_agent_idx ON tools (agent)")

    # ---------------------------------------------------------------------- #
    # tier_overrides — append-only, monotona
    # ---------------------------------------------------------------------- #
    op.execute(
        """
        CREATE TABLE tier_overrides (
            id         bigserial       PRIMARY KEY,
            tool_id    bigint          NOT NULL
                                       REFERENCES tools (id) ON DELETE RESTRICT,
            tier       tier            NOT NULL,
            reason     text            NOT NULL,
            source     override_source NOT NULL DEFAULT 'persistent',
            created_by text            NOT NULL,
            created_at timestamptz     NOT NULL DEFAULT now(),

            -- NOT NULL non basta: la stringa vuota soddisfa NOT NULL e non
            -- dice niente. Un innalzamento senza motivo e' illeggibile a
            -- distanza di mesi, che e' quando lo si rilegge.
            CONSTRAINT tier_overrides_reason_non_vuoto
                CHECK (length(btrim(reason)) >= 3),

            CONSTRAINT tier_overrides_created_by_non_vuoto
                CHECK (length(btrim(created_by)) > 0)
        )
        """
    )
    # ON DELETE RESTRICT e non CASCADE: cancellare un tool porterebbe via lo
    # storico dei suoi innalzamenti, che e' esattamente cio' che la tabella
    # esiste per conservare. Un CASCADE qui sarebbe un DELETE su una tabella
    # append-only con un'interfaccia comoda.
    op.execute("CREATE INDEX tier_overrides_tool_id_idx ON tier_overrides (tool_id)")
    op.execute(
        "COMMENT ON TABLE tier_overrides IS "
        "'Storico degli innalzamenti di tier. Append-only: UPDATE e DELETE "
        "sono rifiutati da trigger. Un tier puo'' solo salire.'"
    )

    # ---------------------------------------------------------------------- #
    # Perimetro dei bersagli
    # ---------------------------------------------------------------------- #
    op.execute(
        """
        CREATE TABLE scope_networks (
            id    bigserial PRIMARY KEY,
            -- Il tipo `cidr` rifiuta da solo un valore con bit a destra della
            -- maschera: '192.168.205.10/24' non entra, e questo E' il vincolo.
            -- Il messaggio di PostgreSQL dice che il valore non e' valido ma
            -- non dice perche': la spiegazione la da' il livello applicativo,
            -- che e' quello che parla all'operatore.
            cidr  cidr      NOT NULL UNIQUE,
            label text      NOT NULL,
            CONSTRAINT scope_networks_label_non_vuota
                CHECK (length(btrim(label)) > 0)
        )
        """
    )
    op.execute(
        "COMMENT ON COLUMN scope_networks.cidr IS "
        "'Rete autorizzata, in forma canonica. Il tipo cidr impone che "
        "l''indirizzo sia quello di rete: 192.168.205.0/24 si'', "
        "192.168.205.10/24 no.'"
    )

    op.execute(
        """
        CREATE TABLE scope_aliases (
            id      bigserial PRIMARY KEY,
            name    text      NOT NULL UNIQUE,
            -- `inet` e non `text`: un alias punta a un INDIRIZZO, non a un
            -- altro nome. L'alias E' la risoluzione, non un secondo livello
            -- da risolvere. Nessun DNS: un nome risolto al momento del
            -- controllo puo' puntare altrove al momento dell'esecuzione.
            address inet      NOT NULL,
            CONSTRAINT scope_aliases_name_formato
                CHECK (name ~ '^[a-z0-9]+([.-][a-z0-9]+)*$'
                       AND length(name) BETWEEN 2 AND 64)
        )
        """
    )
    op.execute("CREATE INDEX scope_aliases_address_idx ON scope_aliases (address)")

    # ---------------------------------------------------------------------- #
    # scope_consents
    # ---------------------------------------------------------------------- #
    op.execute(
        """
        CREATE TABLE scope_consents (
            id         bigserial   PRIMARY KEY,
            -- NULL = il consenso vale per l'agente intero, non per un singolo
            -- tool. ON DELETE RESTRICT per la stessa ragione degli override:
            -- un consenso dato resta tracciato.
            tool_id    bigint      REFERENCES tools (id) ON DELETE RESTRICT,
            agent      owner_agent NOT NULL,
            scope      text        NOT NULL,
            granted_by text        NOT NULL,
            granted_at timestamptz NOT NULL DEFAULT now(),
            -- NOT NULL: un consenso che non scade non e' un consenso, e' una
            -- autorizzazione permanente con un altro nome.
            expires_at timestamptz NOT NULL,
            -- Revoca per annullamento, non cancellazione: la riga resta e
            -- dice che e' stata revocata, perche' sapere che un consenso c'e'
            -- stato conta tanto quanto sapere che non vale piu'.
            revoked_at timestamptz,

            CONSTRAINT scope_consents_scade_dopo_concessione
                CHECK (expires_at > granted_at),
            CONSTRAINT scope_consents_revoca_non_anteriore
                CHECK (revoked_at IS NULL OR revoked_at >= granted_at),
            CONSTRAINT scope_consents_scope_non_vuoto
                CHECK (length(btrim(scope)) > 0),
            CONSTRAINT scope_consents_granted_by_non_vuoto
                CHECK (length(btrim(granted_by)) > 0)
        )
        """
    )
    op.execute("CREATE INDEX scope_consents_agent_idx ON scope_consents (agent)")
    op.execute("CREATE INDEX scope_consents_tool_id_idx ON scope_consents (tool_id)")

    # ---------------------------------------------------------------------- #
    # audit_events — sola lettura
    #
    # `tool_id` e `agent` sono TESTO e non chiavi esterne, deliberatamente.
    # Il log e' una vista di un file JSONL prodotto da hermes-core, e quel
    # file contiene righe che si riferiscono a tool non piu' registrati —
    # `tool_registration_rejected` ne e' l'esempio: registra proprio un tool
    # che NON e' stato registrato. Una FK renderebbe quelle righe
    # inseribili, cioe' renderebbe il log incapace di registrare i rifiuti.
    # ---------------------------------------------------------------------- #
    op.execute(
        """
        CREATE TABLE audit_events (
            id                  bigserial     PRIMARY KEY,
            correlation_id      uuid          NOT NULL,
            -- Cio' che dichiara l'altro lato del confine di processo, tenuto
            -- separato dalla catena propria: un client non deve poter
            -- scrivere le proprie righe sotto la catena di un'altra
            -- invocazione.
            peer_correlation_id text,
            event_type          log_action    NOT NULL,
            agent               owner_agent,
            tool_id             text,
            target              text,
            tier_effective      tier,
            authorized_by       authorized_by,
            -- Il NOME del segreto consultato, mai il valore.
            secret_name         text,
            outcome             call_outcome  NOT NULL,
            detail              text          NOT NULL DEFAULT '',
            occurred_at         timestamptz   NOT NULL DEFAULT now(),

            CONSTRAINT audit_events_detail_limite
                CHECK (length(detail) <= 4096),

            -- Una chiamata eseguita deve avere un'autorizzazione tracciata.
            -- Un esito `ok` o `error` con authorized_by = 'none'
            -- descriverebbe un'esecuzione senza autorizzazione registrata:
            -- e' lo stato che l'audit esiste per rendere indichiarabile.
            -- Vale solo per gli eventi di invocazione: gli altri tipi di
            -- evento non passano dal gate e non hanno un'autorizzazione.
            CONSTRAINT audit_events_esecuzione_autorizzata
                CHECK (
                    event_type <> 'tool_call'
                    OR outcome NOT IN ('ok', 'error')
                    OR (authorized_by IS NOT NULL AND authorized_by <> 'none')
                )
        )
        """
    )
    op.execute(
        "COMMENT ON TABLE audit_events IS "
        "'Vista del log d''audit, non la fonte di verita''. La fonte e'' un "
        "file JSONL append-only con chattr +a sulla macchina del server MCP. "
        "Questa tabella e'' una copia ricostruibile e scartabile: "
        "append-only, nessuna rotta di scrittura.'"
    )
    op.execute(
        "CREATE INDEX audit_events_correlation_id_idx ON audit_events (correlation_id)"
    )
    op.execute(
        "CREATE INDEX audit_events_occurred_at_idx ON audit_events (occurred_at DESC)"
    )
    op.execute("CREATE INDEX audit_events_agent_idx ON audit_events (agent)")
    op.execute("CREATE INDEX audit_events_tool_id_idx ON audit_events (tool_id)")
    op.execute("CREATE INDEX audit_events_outcome_idx ON audit_events (outcome)")

    # ---------------------------------------------------------------------- #
    # Vista del tier effettivo
    #
    # Il tier effettivo e' una VISTA, non una colonna denormalizzata su
    # `tools`. Una colonna andrebbe tenuta sincronizzata a ogni inserimento di
    # override, e una colonna non sincronizzata e' un tier sbagliato mostrato
    # all'operatore. La vista non puo' divergere: ricalcola.
    #
    # GREATEST con il tier dichiarato e non solo max(override): il tier
    # dichiarato e' un PAVIMENTO. Anche nell'ipotesi in cui una riga di
    # override piu' bassa finisse nella tabella — aggirando il trigger, per
    # esempio disabilitandolo da superutente — la vista continuerebbe a
    # riportare almeno il pavimento. L'invariante vale in due punti
    # indipendenti.
    # ---------------------------------------------------------------------- #
    op.execute(
        """
        CREATE VIEW tool_effective_tier AS
        SELECT
            t.id                                     AS tool_pk,
            t.tool_id                                AS tool_id,
            t.declared_tier                          AS declared_tier,
            GREATEST(
                t.declared_tier,
                COALESCE(max(o.tier), t.declared_tier)
            )                                        AS effective_tier,
            count(o.id)                              AS override_count,
            max(o.created_at)                        AS last_override_at
        FROM tools t
        LEFT JOIN tier_overrides o ON o.tool_id = t.id
        GROUP BY t.id, t.tool_id, t.declared_tier
        """
    )
    op.execute(
        "COMMENT ON VIEW tool_effective_tier IS "
        "'tier_effettivo = max(tier dichiarato, override piu'' alto "
        "registrato). Il tier dichiarato e'' un pavimento: la vista lo "
        "include nel massimo, quindi non puo'' riportare un valore inferiore "
        "a quello dichiarato nemmeno se una riga di override piu'' bassa "
        "arrivasse in tabella.'"
    )

    # ---------------------------------------------------------------------- #
    # INVARIANTE 1 — Monotonia del tier
    #
    # Il tier puo' solo salire. Mai scendere.
    #
    # Non e' una convenzione: permettere un declassamento sarebbe un modo di
    # disattivare i controlli di sicurezza. Un tool portato a `rosso` dopo un
    # incidente richiede una conferma puntuale a ogni invocazione; se
    # esistesse un modo di riportarlo a `giallo`, quel modo verrebbe chiamato
    # — e prima o poi verrebbe chiamato da qualcosa di automatico, che e'
    # precisamente lo scenario che il modello dei tier esiste per impedire.
    #
    # Il confronto e' STRETTO (`<=` viene rifiutato, non solo `<`): un
    # override pari al tier effettivo corrente non innalza niente. Accettarlo
    # riempirebbe lo storico di righe inerti, e lo storico e' cio' che si
    # legge per capire perche' un tool sta dov'e'.
    # ---------------------------------------------------------------------- #
    op.execute(
        """
        CREATE FUNCTION tier_overrides_monotonia() RETURNS trigger
        LANGUAGE plpgsql AS $fn$
        DECLARE
            tier_dichiarato tier;
            tier_corrente   tier;
            id_tool         text;
        BEGIN
            -- FOR UPDATE sulla riga del tool: e' cio' che SERIALIZZA due
            -- innalzamenti concorrenti dello stesso tool. Senza il lock,
            -- due transazioni leggerebbero entrambe lo stesso massimo e
            -- inserirebbero entrambe. Con il lock, la seconda attende, e al
            -- proprio turno rilegge il massimo (READ COMMITTED apre uno
            -- snapshot nuovo a ogni statement) trovando la riga della prima.
            -- `tools` e' in sola lettura per questa applicazione, quindi il
            -- lock non contende con nient'altro.
            SELECT t.declared_tier, t.tool_id
              INTO tier_dichiarato, id_tool
              FROM tools t
             WHERE t.id = NEW.tool_id
               FOR UPDATE;

            IF NOT FOUND THEN
                RAISE EXCEPTION
                    'override su un tool inesistente (id %)', NEW.tool_id
                    USING ERRCODE = 'HM404';
            END IF;

            -- Il massimo fra il pavimento dichiarato e gli override gia'
            -- registrati. Protetto dal lock preso sopra.
            SELECT GREATEST(
                       tier_dichiarato,
                       COALESCE(max(o.tier), tier_dichiarato)
                   )
              INTO tier_corrente
              FROM tier_overrides o
             WHERE o.tool_id = NEW.tool_id;

            IF NEW.tier <= tier_corrente THEN
                RAISE EXCEPTION
                    'il tier puo'' solo salire: % ha tier effettivo %, '
                    'un override a % non lo innalza',
                    id_tool, tier_corrente, NEW.tier
                    USING ERRCODE = 'HM409',
                          HINT = 'Sono ammessi solo i tier superiori a '
                                 || tier_corrente || '.';
            END IF;

            RETURN NEW;
        END;
        $fn$
        """
    )
    op.execute(
        """
        CREATE TRIGGER tier_overrides_monotonia_trg
            BEFORE INSERT ON tier_overrides
            FOR EACH ROW EXECUTE FUNCTION tier_overrides_monotonia()
        """
    )

    # ---------------------------------------------------------------------- #
    # INVARIANTE 2 e 3 — Append-only
    #
    # Una tabella append-only non e' una tabella su cui l'applicazione evita
    # di chiamare UPDATE: e' una tabella su cui UPDATE non funziona. La
    # differenza si vede quando qualcuno apre psql.
    #
    # Una sola funzione per le due tabelle: il nome della tabella arriva da
    # TG_TABLE_NAME, quindi il messaggio dice quale tabella ha rifiutato
    # senza duplicare il codice.
    # ---------------------------------------------------------------------- #
    op.execute(
        """
        CREATE FUNCTION vieta_modifica() RETURNS trigger
        LANGUAGE plpgsql AS $fn$
        BEGIN
            RAISE EXCEPTION
                '% e'' append-only: % non e'' consentito',
                TG_TABLE_NAME, TG_OP
                USING ERRCODE = 'HM403',
                      HINT = 'Le righe si aggiungono e non si toccano piu''. '
                             'Per annullare un consenso si usa la revoca; per '
                             'un override non esiste annullamento, perche'' '
                             'sarebbe un declassamento.';
        END;
        $fn$
        """
    )
    op.execute(
        """
        CREATE TRIGGER tier_overrides_append_only_trg
            BEFORE UPDATE OR DELETE ON tier_overrides
            FOR EACH ROW EXECUTE FUNCTION vieta_modifica()
        """
    )
    op.execute(
        """
        CREATE TRIGGER audit_events_append_only_trg
            BEFORE UPDATE OR DELETE ON audit_events
            FOR EACH ROW EXECUTE FUNCTION vieta_modifica()
        """
    )
    # TRUNCATE non passa dai trigger FOR EACH ROW: svuoterebbe la tabella
    # senza che nessuno dei due trigger intervenga. Serve un trigger di
    # statement dedicato, altrimenti «append-only» e' vero solo per le
    # operazioni che qualcuno si e' ricordato di coprire.
    op.execute(
        """
        CREATE FUNCTION vieta_truncate() RETURNS trigger
        LANGUAGE plpgsql AS $fn$
        BEGIN
            RAISE EXCEPTION
                '% e'' append-only: TRUNCATE non e'' consentito',
                TG_TABLE_NAME
                USING ERRCODE = 'HM403';
        END;
        $fn$
        """
    )
    op.execute(
        """
        CREATE TRIGGER tier_overrides_no_truncate_trg
            BEFORE TRUNCATE ON tier_overrides
            FOR EACH STATEMENT EXECUTE FUNCTION vieta_truncate()
        """
    )
    op.execute(
        """
        CREATE TRIGGER audit_events_no_truncate_trg
            BEFORE TRUNCATE ON audit_events
            FOR EACH STATEMENT EXECUTE FUNCTION vieta_truncate()
        """
    )

    # ---------------------------------------------------------------------- #
    # INVARIANTE 4 — Ogni alias cade dentro una rete dichiarata
    #
    # Un alias fuori perimetro renderebbe il perimetro contraddittorio: lo
    # stesso insieme di dati direbbe nello stesso momento che un indirizzo e'
    # ammesso (perche' ha un alias) e che non lo e' (perche' nessuna rete lo
    # contiene).
    #
    # Il vincolo si applica in DUE punti, perche' ci sono due modi di
    # violarlo:
    #   - inserendo o modificando un alias fuori dalle reti;
    #   - rimuovendo la rete che conteneva un alias esistente.
    # Coprire solo il primo lascerebbe il secondo come via d'uscita, e
    # sarebbe la via d'uscita piu' facile da imboccare per sbaglio.
    # ---------------------------------------------------------------------- #
    op.execute(
        """
        CREATE FUNCTION scope_alias_dentro_perimetro() RETURNS trigger
        LANGUAGE plpgsql AS $fn$
        DECLARE
            reti text;
        BEGIN
            IF EXISTS (
                SELECT 1 FROM scope_networks n WHERE NEW.address <<= n.cidr
            ) THEN
                RETURN NEW;
            END IF;

            SELECT COALESCE(string_agg(n.cidr::text, ', ' ORDER BY n.cidr), '(nessuna)')
              INTO reti
              FROM scope_networks n;

            RAISE EXCEPTION
                'l''alias % punta a %, che non cade in nessuna rete '
                'dichiarata del perimetro',
                NEW.name, host(NEW.address)
                USING ERRCODE = 'HM422',
                      HINT = 'Reti dichiarate: ' || reti || '.';
        END;
        $fn$
        """
    )
    op.execute(
        """
        CREATE TRIGGER scope_aliases_dentro_perimetro_trg
            BEFORE INSERT OR UPDATE ON scope_aliases
            FOR EACH ROW EXECUTE FUNCTION scope_alias_dentro_perimetro()
        """
    )

    op.execute(
        """
        CREATE FUNCTION scope_network_senza_alias_orfani() RETURNS trigger
        LANGUAGE plpgsql AS $fn$
        DECLARE
            orfani text;
        BEGIN
            -- Quali alias resterebbero fuori perimetro dopo questa rimozione.
            -- La riga e' gia' sparita dalla vista della transazione, quindi la
            -- query vede il perimetro COME SARA'.
            SELECT string_agg(a.name || ' (' || host(a.address) || ')',
                              ', ' ORDER BY a.name)
              INTO orfani
              FROM scope_aliases a
             WHERE NOT EXISTS (
                 SELECT 1 FROM scope_networks n WHERE a.address <<= n.cidr
             );

            IF orfani IS NOT NULL THEN
                RAISE EXCEPTION
                    'rimuovere la rete % lascerebbe fuori perimetro: %',
                    OLD.cidr, orfani
                    USING ERRCODE = 'HM422',
                          HINT = 'Rimuovere prima quegli alias, o dichiarare '
                                 'un''altra rete che li contenga.';
            END IF;

            RETURN OLD;
        END;
        $fn$
        """
    )
    # AFTER e non BEFORE: il controllo deve vedere il perimetro come sara'
    # DOPO la rimozione, e in un trigger BEFORE DELETE la riga e' ancora
    # presente. In AFTER l'eccezione annulla comunque la transazione.
    op.execute(
        """
        CREATE TRIGGER scope_networks_no_alias_orfani_trg
            AFTER DELETE OR UPDATE ON scope_networks
            FOR EACH ROW EXECUTE FUNCTION scope_network_senza_alias_orfani()
        """
    )


def downgrade() -> None:
    """Smontaggio dello schema.

    Esiste per completezza di Alembic, ma non e' la via per azzerare i dati:
    `tier_overrides` e `audit_events` sono append-only, e il modo supportato
    per ripartire da zero e' rimuovere il volume del database
    (`docker compose down -v`). Un DROP TABLE riesce perche' DROP non passa
    dai trigger di riga — ed e' il motivo per cui l'append-only vero sta
    fuori dal database, nel file con `chattr +a` sulla macchina del server
    MCP, di cui questa tabella e' soltanto una vista.
    """
    op.execute("DROP TRIGGER IF EXISTS scope_networks_no_alias_orfani_trg ON scope_networks")
    op.execute("DROP TRIGGER IF EXISTS scope_aliases_dentro_perimetro_trg ON scope_aliases")
    op.execute("DROP TRIGGER IF EXISTS audit_events_no_truncate_trg ON audit_events")
    op.execute("DROP TRIGGER IF EXISTS tier_overrides_no_truncate_trg ON tier_overrides")
    op.execute("DROP TRIGGER IF EXISTS audit_events_append_only_trg ON audit_events")
    op.execute("DROP TRIGGER IF EXISTS tier_overrides_append_only_trg ON tier_overrides")
    op.execute("DROP TRIGGER IF EXISTS tier_overrides_monotonia_trg ON tier_overrides")

    op.execute("DROP FUNCTION IF EXISTS scope_network_senza_alias_orfani()")
    op.execute("DROP FUNCTION IF EXISTS scope_alias_dentro_perimetro()")
    op.execute("DROP FUNCTION IF EXISTS vieta_truncate()")
    op.execute("DROP FUNCTION IF EXISTS vieta_modifica()")
    op.execute("DROP FUNCTION IF EXISTS tier_overrides_monotonia()")

    op.execute("DROP VIEW IF EXISTS tool_effective_tier")

    op.execute("DROP TABLE IF EXISTS audit_events")
    op.execute("DROP TABLE IF EXISTS scope_consents")
    op.execute("DROP TABLE IF EXISTS scope_aliases")
    op.execute("DROP TABLE IF EXISTS scope_networks")
    op.execute("DROP TABLE IF EXISTS tier_overrides")
    op.execute("DROP TABLE IF EXISTS tools")
    op.execute("DROP TABLE IF EXISTS users")

    for tipo in (
        "override_source",
        "log_action",
        "authorized_by",
        "target_kind",
        "owner_agent",
        "call_outcome",
        "tier",
    ):
        op.execute(f"DROP TYPE IF EXISTS {tipo}")
