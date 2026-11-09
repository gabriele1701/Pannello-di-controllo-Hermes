"""Ruolo applicativo non proprietario, concessioni minime, lock senza privilegi.

Revision ID: 0002_ruolo_applicativo
Revises: 0001_fondamenta
Create Date: 2026-11-09

Il buco che questa migrazione chiude
------------------------------------

La migrazione 0001 ha messo gli invarianti del dominio in trigger di
PostgreSQL, e il README affermava che quei vincoli non si aggirano. L'
affermazione era piu' forte del vero: **il proprietario di una tabella puo'
disabilitarne i trigger.**

    ALTER TABLE tier_overrides DISABLE TRIGGER ALL;

Finche' l'applicazione si connette con il ruolo che possiede le tabelle, quel
comando e' a disposizione del codice applicativo — e quindi di qualunque
difetto del codice applicativo. Il trigger proteggeva da chi passa dalle
tabelle, non da chi possiede le tabelle.

C'e' anche una seconda via, piu' corta:

    SET session_replication_role = replica;   -- i trigger non scattano piu'

che richiede il superutente.

Separazione in due ruoli
------------------------

* **Il ruolo proprietario** (``POSTGRES_USER``, di norma ``hermes``) possiede
  schema, tabelle, funzioni e trigger. Lo usano **soltanto** le migrazioni e
  il seed, tramite ``MIGRATIONS_DATABASE_URL``. Che possa cambiare lo schema
  non e' un difetto: e' il suo compito.
* **``hermes_app``** non possiede niente e non e' superutente. Lo usa
  l'applicazione in esercizio, tramite ``DATABASE_URL``. Non puo'
  disabilitare un trigger, rimuoverlo, rimuovere un vincolo, cambiare
  ``session_replication_role``, ne' creare oggetti nello schema.

Da qui le concessioni sono scritte per tabella, e la tabella delle
concessioni **e'** una dichiarazione del dominio:

==================  ======  ======  ===============  ======
Tabella             SELECT  INSERT  UPDATE           DELETE
==================  ======  ======  ===============  ======
``users``             si                             
``tools``             si                             
``tier_overrides``    si      si                     
``audit_events``      si                             
``scope_networks``    si      si                       si
``scope_aliases``     si      si                       si
``scope_consents``    si      si    solo revoked_at   
``alembic_version``                                  
==================  ======  ======  ===============  ======

Tre righe di quella tabella sono affermazioni che prima erano solo
convenzioni del codice:

* ``tools`` in sola lettura. Lo SPEC dice che l'identita' di un tool
  — ``(exec_path, exec_sha256, exec_args)`` — e' di sola lettura per questa
  applicazione, perche' la registra ``hermes-core``. Ora non e' l'assenza di
  una rotta a garantirlo: e' l'assenza del privilegio.
* ``audit_events`` senza ``INSERT``. «Nessuna rotta permette di scrivere nel
  log» diventa «nessuna scrittura nel log e' possibile da questa
  connessione», che e' un'affermazione diversa e piu' forte.
* ``scope_consents`` con ``UPDATE`` **su una sola colonna**. L'applicazione
  puo' revocare un consenso e non puo' cambiargli scope, agente o scadenza:
  un consenso non si riscrive, si revoca.

E ``alembic_version`` non e' raggiungibile: l'applicazione non puo' mentire
su quale versione dello schema sta girando.

Perche' il lock cambia forma
----------------------------

Il trigger di monotonia della 0001 prendeva ``SELECT ... FOR UPDATE`` sulla
riga di ``tools`` per serializzare due innalzamenti concorrenti. Con un ruolo
in sola lettura su ``tools`` non funziona piu': in PostgreSQL **ogni** clausola
di blocco di riga — ``FOR UPDATE``, ``FOR SHARE``, ``FOR KEY SHARE`` — richiede
piu' del privilegio ``SELECT`` sulla tabella.

Le alternative erano tre:

1. concedere ``UPDATE`` su ``tools``, che butterebbe via la sola lettura, cioe'
   la cosa che si stava guadagnando;
2. rendere la funzione ``SECURITY DEFINER``, cioe' farla girare con i
   privilegi del proprietario. Funziona, ma mette un'escalation di privilegi
   dentro il percorso di applicazione del vincolo, e obbliga a fissare
   ``search_path`` per non lasciare aperta la via d'attacco classica di
   ``SECURITY DEFINER``;
3. un **advisory lock di transazione**, che non richiede privilegi su nessuna
   tabella.

Si sceglie la terza, e non come ripiego. Il lock sulla riga di ``tools`` era
un *sostituto* della cosa che si voleva davvero serializzare, che e' la catena
di override di un tool: l'advisory lock la nomina direttamente. Non introduce
escalation, non tocca ``tools``, e si rilascia da solo alla fine della
transazione.

La chiave e' doppia — un nome fisso piu' l'identificativo del tool — perche'
gli advisory lock vivono in un unico spazio di chiavi per database: una chiave
singola potrebbe collidere con quella di un'altra funzionalita' futura.
"""

from __future__ import annotations

import os

from alembic import op

revision: str = "0002_ruolo_applicativo"
down_revision: str | None = "0001_fondamenta"
branch_labels = None
depends_on = None

#: Nome del ruolo con cui l'applicazione si connette in esercizio.
RUOLO_APP = "hermes_app"

#: Tabelle su cui il ruolo applicativo puo' solo leggere.
SOLA_LETTURA = ("users", "tools", "audit_events")

#: Sequenze dei `bigserial` su cui il ruolo deve poter inserire.
SEQUENZE = (
    "tier_overrides_id_seq",
    "scope_networks_id_seq",
    "scope_aliases_id_seq",
    "scope_consents_id_seq",
)


def upgrade() -> None:
    # ---------------------------------------------------------------------- #
    # 1. Il lock del trigger di monotonia, senza privilegi di tabella
    #
    # Va prima delle concessioni: appena il ruolo applicativo esiste con la
    # sola lettura su `tools`, un trigger che prende FOR UPDATE su quella
    # tabella renderebbe impossibile ogni innalzamento.
    # ---------------------------------------------------------------------- #
    op.execute(
        """
        CREATE OR REPLACE FUNCTION tier_overrides_monotonia() RETURNS trigger
        LANGUAGE plpgsql AS $fn$
        DECLARE
            tier_dichiarato tier;
            tier_corrente   tier;
            id_tool         text;
        BEGIN
            -- Serializza gli innalzamenti concorrenti DELLO STESSO tool.
            --
            -- Senza, due transazioni leggerebbero entrambe lo stesso massimo e
            -- inserirebbero entrambe. Con il lock la seconda attende, e al
            -- proprio turno rilegge il massimo -- READ COMMITTED apre uno
            -- snapshot nuovo a ogni statement -- trovando la riga della prima.
            --
            -- E' un advisory lock e non `SELECT ... FOR UPDATE` su `tools`
            -- perche' ogni clausola di blocco di riga richiede piu' del
            -- privilegio SELECT, e il ruolo applicativo ha `tools` in sola
            -- lettura. Vedi il docstring di questa migrazione.
            --
            -- Chiave doppia: un nome fisso per questo scopo, piu'
            -- l'identificativo del tool. Gli advisory lock condividono un solo
            -- spazio di chiavi per database, e una chiave singola potrebbe
            -- collidere con quella di un'altra funzionalita'. Il cast a int4
            -- regge oltre due miliardi di tool, e oltre quel numero solleva
            -- un errore invece di collidere in silenzio.
            PERFORM pg_advisory_xact_lock(
                hashtext('hermes.tier_overrides'), NEW.tool_id::int
            );

            SELECT t.declared_tier, t.tool_id
              INTO tier_dichiarato, id_tool
              FROM tools t
             WHERE t.id = NEW.tool_id;

            IF NOT FOUND THEN
                RAISE EXCEPTION
                    'override su un tool inesistente (id %)', NEW.tool_id
                    USING ERRCODE = 'HM404';
            END IF;

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

    # ---------------------------------------------------------------------- #
    # 2. Il ruolo applicativo
    #
    # Creato SENZA password. Una password si imposta solo se
    # HERMES_APP_DB_PASSWORD e' presente nell'ambiente, e passa come
    # parametro di bind dentro `set_config`, non come testo dello statement:
    # cosi' non finisce nel log delle query se `log_statement` e' attivo.
    #
    # Senza password il ruolo non puo' autenticarsi con scram, quindi un
    # DATABASE_URL che puntasse a lui fallirebbe con un errore di
    # autenticazione -- rumoroso, che e' il comportamento voluto. Il compose
    # rende la variabile obbligatoria.
    # ---------------------------------------------------------------------- #
    op.execute(
        f"""
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_roles WHERE rolname = '{RUOLO_APP}'
            ) THEN
                -- NOSUPERUSER, NOCREATEDB, NOCREATEROLE, NOBYPASSRLS sono i
                -- default, ma scritti qui perche' questa riga e' il punto in
                -- cui si decide cosa il ruolo NON puo' fare, e un default
                -- implicito non si legge in review.
                CREATE ROLE {RUOLO_APP}
                    LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS
                    NOINHERIT;
            END IF;
        END
        $$
        """
    )

    password = os.environ.get("HERMES_APP_DB_PASSWORD")
    if password:
        connessione = op.get_bind()
        connessione.exec_driver_sql(
            "SELECT set_config('hermes.app_password', %s, true)", (password,)
        )
        op.execute(
            f"""
            DO $$
            BEGIN
                EXECUTE format(
                    'ALTER ROLE {RUOLO_APP} PASSWORD %L',
                    current_setting('hermes.app_password')
                );
            END
            $$
            """
        )

    # ---------------------------------------------------------------------- #
    # 3. Concessioni minime
    # ---------------------------------------------------------------------- #

    # In PostgreSQL 15 e successivi PUBLIC non ha piu' CREATE sullo schema
    # public. La revoca e' comunque esplicita: cosi' la garanzia e' scritta
    # qui e non dipende dalla versione del server su cui si gira.
    op.execute("REVOKE CREATE ON SCHEMA public FROM PUBLIC")

    op.execute(f"GRANT USAGE ON SCHEMA public TO {RUOLO_APP}")

    # -- sola lettura ------------------------------------------------------- #
    op.execute(f"GRANT SELECT ON {', '.join(SOLA_LETTURA)} TO {RUOLO_APP}")
    op.execute(f"GRANT SELECT ON tool_effective_tier TO {RUOLO_APP}")

    # -- append-only: si aggiunge, non si tocca ----------------------------- #
    # Nessun UPDATE e nessun DELETE. I trigger della 0001 restano, e ora sono
    # il secondo livello invece dell'unico: il primo e' che il privilegio non
    # c'e'. Nemmeno TRUNCATE, che e' un privilegio separato e non concesso.
    op.execute(f"GRANT SELECT, INSERT ON tier_overrides TO {RUOLO_APP}")

    # -- perimetro: si modifica, ed e' il suo scopo ------------------------- #
    # Niente UPDATE: le rotte non ne hanno, una rete o un alias si rimuove e
    # si ridichiara. Il trigger sugli alias orfani copre comunque il caso.
    op.execute(
        f"GRANT SELECT, INSERT, DELETE ON scope_networks, scope_aliases "
        f"TO {RUOLO_APP}"
    )

    # -- consensi: revoca, non riscrittura ---------------------------------- #
    op.execute(f"GRANT SELECT, INSERT ON scope_consents TO {RUOLO_APP}")
    # Concessione a livello di COLONNA. L'applicazione puo' scrivere la data
    # di revoca e nient'altro: non puo' prolungare una scadenza, cambiare
    # l'agente o lo scope di un consenso gia' dato.
    op.execute(f"GRANT UPDATE (revoked_at) ON scope_consents TO {RUOLO_APP}")

    # -- sequenze ----------------------------------------------------------- #
    op.execute(f"GRANT USAGE, SELECT ON SEQUENCE {', '.join(SEQUENZE)} TO {RUOLO_APP}")

    # Nessuna concessione su `alembic_version`: l'applicazione non deve poter
    # leggere ne' alterare quale versione dello schema e' applicata.
    #
    # Nessun ALTER DEFAULT PRIVILEGES, deliberatamente: una tabella aggiunta
    # da una migrazione futura NON sara' raggiungibile dal ruolo applicativo
    # finche' qualcuno non le scrive una concessione esplicita. E' scomodo una
    # volta per tabella, ed e' il verso giusto in cui essere scomodi.


def downgrade() -> None:
    """Rimuove le concessioni e il ruolo, e ripristina il lock su `tools`.

    Il ``REASSIGN``/``DROP OWNED`` non serve: il ruolo non possiede niente,
    che e' il punto per cui esiste.
    """
    op.execute(f"REVOKE ALL ON ALL TABLES IN SCHEMA public FROM {RUOLO_APP}")
    op.execute(f"REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM {RUOLO_APP}")
    op.execute(f"REVOKE ALL ON SCHEMA public FROM {RUOLO_APP}")
    op.execute(f"DROP ROLE IF EXISTS {RUOLO_APP}")

    op.execute(
        """
        CREATE OR REPLACE FUNCTION tier_overrides_monotonia() RETURNS trigger
        LANGUAGE plpgsql AS $fn$
        DECLARE
            tier_dichiarato tier;
            tier_corrente   tier;
            id_tool         text;
        BEGIN
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
