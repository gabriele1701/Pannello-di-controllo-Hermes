"""Perimetro dei percorsi, e l'isolamento come vincolo.

Revision ID: 0004_perimetro_percorsi
Revises: 0003_bersagli_estesi
Create Date: 2026-11-11

Due perimetri, non uno
----------------------

`scope_networks` e `scope_aliases` dichiarano dove un tool con bersaglio di
rete puo' arrivare. `scope_paths` fa la stessa cosa per i file. Sono due
tabelle e non una con una colonna «tipo», perche' le regole sono diverse: una
rete ha una forma che PostgreSQL verifica da se', un percorso no, e cio' che
il pannello puo' promettere sui due non e' la stessa cosa.

Cosa il pannello puo' verificare di un percorso, e cosa no
----------------------------------------------------------

Con le reti si e' stati fortunati. Il tipo `cidr` rifiuta da solo
`192.168.205.10/24`, e il vincolo e' gratuito: non c'e' codice da scrivere ne'
da mantenere, perche' la regola sta nel tipo.

Per i percorsi non esiste niente di equivalente, e la differenza non e' di
comodita' ma architetturale. Il pannello puo' verificare **la forma del
prefisso dichiarato** -- assoluto, canonico, senza risalite -- e lo fa con i
`CHECK` qui sotto.

Il pannello NON puo' verificare che un bersaglio cada dentro il perimetro.
Un prefisso `/srv/analisi` sembra sicuro finche' qualcuno passa
`/srv/analisi/x`, dove `x` e' un collegamento simbolico verso `/etc/shadow`:
il controllo di prefisso passa, l'apertura legge altro. I collegamenti
simbolici vivono nel filesystem del container, non in questo database, e
nessun `CHECK` li vede.

Quel controllo tocca al gate di `hermes-core`, che al momento dell'esecuzione
risolve il percorso richiesto -- collegamenti simbolici, `..`, componenti
relative -- verifica che il percorso **risolto** abbia uno dei prefissi
dichiarati come antenato, e opera sul risolto, preferibilmente su un
descrittore aperto durante la risoluzione, cosi' che controllo e uso si
riferiscano allo stesso oggetto. Nel log d'audit finiscono entrambi: se
differiscono, e' esattamente l'informazione che un audit serve a conservare.

E' la stessa divisione che regge tutto il progetto: **il pannello dichiara,
il gate applica.** Qui si vede bene perche' e' una scelta e non un limite --
il pannello non ha accesso al filesystem su cui il tool girera', e un
controllo scritto qui sarebbe una promessa che nessuno puo' mantenere.

Perche' `process` non ha una tabella di scope
---------------------------------------------

Un PID non e' dichiarabile come policy: e' effimero e viene riciclato, quindi
una riga che dicesse «il PID 4312 e' autorizzato» sarebbe falsa qualche
secondo dopo essere stata scritta. Un nome di processo e' aggirabile da
chiunque controlli il processo.

La risposta e' che **il confine di isolamento *e'* il perimetro**: un tool che
aggancia processi gira in un container effimero dove esiste solo il processo
bersaglio, e non si dichiara quali PID siano agganciabili perche' non ce ne
sono altri.

Questo diventa il vincolo `tools_bersaglio_isolato`, che e' il pezzo di
questa migrazione che vale piu' della tabella:

    target_kind NOT IN ('path', 'process') OR requires_container

Sta su `tools`, che e' di sola lettura per il ruolo applicativo: e' chi
registra i tool a doverlo rispettare, e non puo' registrare uno strumento che
aggancia processi senza isolamento. Verificato contro `hermes-core`: la' il
campo esiste con lo stesso significato, e l'executor **nega** l'esecuzione se
`requires_container` e' vero e nessun runtime di container e' disponibile
(`mcp_server/executor.py`). Il vincolo di qui e il rifiuto di la' sono i due
capi della stessa regola.

*Compromesso accettato:* la regola e' piu' stretta del minimo necessario. Si
puo' immaginare un tool che legge un file di configurazione fidato senza
bisogno di un container. Se quel caso si presenta, lo si allenta con una
migrazione e una motivazione scritta. Partire stretti e allentare con un
motivo e' piu' sicuro del contrario.

Le concessioni stanno qui, non dopo
-----------------------------------

La 0002 non ha `ALTER DEFAULT PRIVILEGES`, deliberatamente: una tabella nuova
nasce irraggiungibile per il ruolo applicativo finche' qualcuno non le scrive
una concessione. E' la scelta che paga adesso -- nessuno puo' leggere
`scope_paths` per sbaglio -- ma ha un rovescio preciso: **dimenticare le due
righe di `GRANT` produce un 500 in esercizio, non un errore in migrazione.**
Lo schema sarebbe valido e l'applicazione rotta.

Per questo stanno nella stessa migrazione che crea la tabella, e per questo
`tests/test_privilegi_ruolo.py` contiene la controprova che le concessioni
bastino a lavorare, non solo che i divieti valgano.

Niente alias per i percorsi
---------------------------

Gli alias di rete esistono perche' ricordare un indirizzo IP e' difficile.
Ricordare `/srv/analisi` non lo e'. Un livello di indirezione su una stringa
che l'operatore scrive comunque a mano aggiungerebbe solo un posto in cui
sbagliare.

Niente vincolo di non-annidamento
---------------------------------

`/srv` e `/srv/analisi` insieme sono ridondanti, non pericolosi. Vietarli
impedirebbe la transizione legittima «aggiungo il piu' stretto, poi tolgo il
piu' largo», che e' il modo corretto di restringere un perimetro senza
lasciare un buco nel mezzo.
"""

from __future__ import annotations

from alembic import op

revision: str = "0004_perimetro_percorsi"
down_revision: str | None = "0003_bersagli_estesi"
branch_labels: str | None = None
depends_on: str | None = None

RUOLO_APP = "hermes_app"

#: Lunghezza massima di un prefisso.
#:
#: 256 e non 512, e il numero viene da `hermes-core`. Il campo `target` di
#: un'invocazione e della riga di audit e' dichiarato `max_length=256`
#: (`mcp_server/contracts.py`, `mcp_server/audit.py`), e il perimetro la'
#: rifiuta qualunque bersaglio piu' lungo, con questa ragione: «un bersaglio
#: che non entra nella riga di audit non e' registrabile, e un'esecuzione non
#: registrabile non si fa».
#:
#: Un prefisso piu' lungo di 256 potrebbe contenere solo bersagli piu' lunghi
#: di 256, cioe' bersagli che il gate rifiuta sempre: sarebbe un perimetro
#: sotto il quale niente e' invocabile. Dichiararlo e' peggio che inutile,
#: perche' sembra autorizzare qualcosa.
#:
#: 512 e' il limite di `exec_path` e `description`, che sono altri campi.
MAX_PREFISSO = 256


def upgrade() -> None:
    # ---------------------------------------------------------------------- #
    # scope_paths
    #
    # Ogni regola di forma ha il proprio vincolo con un nome parlante, invece
    # di un unico CHECK che le somma. PostgreSQL riporta il nome del vincolo
    # violato e niente altro: con un vincolo unico il messaggio direbbe «il
    # prefisso non va bene» e l'operatore dovrebbe indovinare quale delle
    # sette regole ha infranto. Con i nomi separati, la rotta traduce il nome
    # in una spiegazione precisa.
    # ---------------------------------------------------------------------- #
    op.execute(
        f"""
        CREATE TABLE scope_paths (
            id     bigserial PRIMARY KEY,
            -- `text` e non un tipo dedicato: PostgreSQL non ha un tipo per i
            -- percorsi del filesystem. La forma canonica la impongono i
            -- CHECK qui sotto, una regola per vincolo.
            prefix text      NOT NULL UNIQUE,
            label  text      NOT NULL,

            -- Assoluto. Un prefisso relativo non significa niente senza
            -- sapere qual e' la directory corrente del processo che lo usa, e
            -- quella cambia.
            CONSTRAINT scope_paths_prefix_assoluto
                CHECK (prefix LIKE '/%'),

            -- Non la radice. Dichiarare l'intero filesystem non e' un
            -- perimetro: e' la rinuncia a un perimetro scritta come se fosse
            -- una policy.
            CONSTRAINT scope_paths_prefix_non_radice
                CHECK (prefix <> '/'),

            -- Niente risalita. `/srv/analisi/..` ha come antenato `/srv`, non
            -- `/srv/analisi`, quindi un prefisso che contiene `..` dichiara
            -- un perimetro diverso da quello che sembra.
            CONSTRAINT scope_paths_prefix_senza_risalita
                CHECK (strpos(prefix, '..') = 0),

            -- Niente doppie barre. `/srv//analisi` e `/srv/analisi` sono lo
            -- stesso percorso per il kernel e due stringhe diverse per
            -- l'UNIQUE qui sopra: ammetterle vorrebbe dire poter dichiarare
            -- due volte lo stesso perimetro e crederlo dichiarato una.
            CONSTRAINT scope_paths_prefix_senza_doppie_barre
                CHECK (strpos(prefix, '//') = 0),

            -- Niente barra finale, per la stessa ragione: `/srv/analisi` e
            -- `/srv/analisi/` direbbero la stessa cosa in due righe.
            CONSTRAINT scope_paths_prefix_senza_barra_finale
                CHECK (prefix NOT LIKE '%/'),

            -- Niente backslash. Non e' un separatore su Linux, quindi un
            -- backslash in un percorso e' parte di un nome di file -- il che
            -- e' legale e quasi sempre un errore di trascrizione. Scritto con
            -- `chr(92)` e non con un letterale: un backslash dentro una
            -- stringa SQL dentro una stringa Python passa per tre livelli di
            -- quoting, e il vincolo finirebbe per cercare qualcosa che non e'
            -- un backslash.
            CONSTRAINT scope_paths_prefix_senza_backslash
                CHECK (strpos(prefix, chr(92)) = 0),

            -- Niente spazi all'inizio o alla fine. `/srv/analisi ` e
            -- `/srv/analisi` sono due percorsi diversi per il kernel e
            -- indistinguibili a occhio, quindi uno dei due e' sempre un
            -- errore di trascrizione.
            --
            -- Si RIFIUTA invece di normalizzare, e la ragione viene da
            -- `hermes-core`, che fa la stessa scelta sul bersaglio di
            -- un'invocazione: «normalizzare significa eseguire qualcosa di
            -- diverso da cio' che e' stato chiesto» (`mcp_server/scope.py`).
            -- Un `btrim()` silenzioso qui autorizzerebbe un prefisso che
            -- nessuno ha scritto.
            --
            -- Gli spazi INTERNI restano ammessi: `/srv/dati condivisi` e' un
            -- percorso legittimo, e vietarlo sarebbe una regola sul
            -- filesystem di qualcun altro.
            CONSTRAINT scope_paths_prefix_senza_spazi_esterni
                CHECK (prefix = btrim(prefix)),

            -- Niente byte nulli e niente caratteri di controllo: un percorso
            -- che li contiene non e' trascrivibile in un file di policy ne'
            -- leggibile in una riga di log.
            CONSTRAINT scope_paths_prefix_stampabile
                CHECK (prefix !~ '[\\x00-\\x1f\\x7f]'),

            -- Lunghezza. Il tetto viene da `hermes-core`: vedi MAX_PREFISSO.
            --
            -- Il minimo e' 1 e non 2, deliberatamente. Con 2, l'unica stringa
            -- di un carattere che passi il vincolo `assoluto` -- cioe' `/` --
            -- veniva intercettata qui invece che da `non_radice`, e
            -- l'operatore che prova a dichiarare l'intero filesystem leggeva
            -- «il prefisso e' troppo corto» al posto della spiegazione vera.
            -- Peggio: PostgreSQL non garantisce l'ordine di valutazione dei
            -- CHECK, quindi quale dei due messaggi arrivava non era nemmeno
            -- prevedibile. Con il minimo a 1 il caso appartiene a un solo
            -- vincolo, e il minimo effettivo resta 2 perche' `/x` e' il piu'
            -- corto che passi sia `assoluto` sia `non_radice`.
            CONSTRAINT scope_paths_prefix_lunghezza
                CHECK (length(prefix) BETWEEN 1 AND {MAX_PREFISSO}),

            CONSTRAINT scope_paths_label_non_vuota
                CHECK (length(btrim(label)) > 0)
        )
        """
    )
    op.execute(
        "COMMENT ON TABLE scope_paths IS "
        "'Perimetro dei bersagli di tipo file o directory. Dichiara prefissi "
        "assoluti in forma canonica; che un bersaglio vi cada dentro lo "
        "verifica il gate di hermes-core, risolvendo il percorso prima di "
        "aprirlo.'"
    )
    op.execute(
        "COMMENT ON COLUMN scope_paths.prefix IS "
        "'Prefisso assoluto in forma canonica: senza componenti .., senza "
        "doppie barre, senza barra finale, e diverso da /.'"
    )

    # ---------------------------------------------------------------------- #
    # L'isolamento come vincolo, non come convenzione
    # ---------------------------------------------------------------------- #
    op.execute(
        """
        ALTER TABLE tools ADD CONSTRAINT tools_bersaglio_isolato
            CHECK (target_kind NOT IN ('path', 'process') OR requires_container)
        """
    )
    op.execute(
        "COMMENT ON CONSTRAINT tools_bersaglio_isolato ON tools IS "
        "'Un tool che punta a file o processi deve girare nel container "
        "isolato. Per i processi il container E'' il perimetro, perche'' un "
        "PID non e'' dichiarabile come policy.'"
    )

    # ---------------------------------------------------------------------- #
    # Concessioni minime sulla tabella nuova
    #
    # SELECT, INSERT, DELETE: le stesse di `scope_networks`. Nessun UPDATE,
    # e l'assenza e' deliberata -- cambiare un prefisso sul posto renderebbe
    # ambiguo cosa era autorizzato prima della modifica. Si rimuove e si
    # dichiara, che e' due righe nel log d'audit invece di una riga mutata.
    # ---------------------------------------------------------------------- #
    op.execute(f"GRANT SELECT, INSERT, DELETE ON scope_paths TO {RUOLO_APP}")
    op.execute(f"GRANT USAGE, SELECT ON SEQUENCE scope_paths_id_seq TO {RUOLO_APP}")


def downgrade() -> None:
    # Le concessioni se ne vanno con la tabella: PostgreSQL le rimuove al
    # DROP. La sequenza del bigserial pure, perche' e' di proprieta' della
    # colonna.
    op.execute("ALTER TABLE tools DROP CONSTRAINT IF EXISTS tools_bersaglio_isolato")
    op.execute("DROP TABLE IF EXISTS scope_paths")
