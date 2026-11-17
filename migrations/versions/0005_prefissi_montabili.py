"""I prefissi di percorso devono poter diventare un montaggio.

Revision ID: 0005_prefissi_montabili
Revises: 0004_perimetro_percorsi
Create Date: 2026-11-17

Cosa e' cambiato da quando e' stata scritta la 0004
---------------------------------------------------

La 0004 immaginava il gate di `hermes-core` come un controllo che risolve il
percorso e confronta. Ora quel perimetro ha un secondo strato: il wrapper dei
tool avvia l'unita' in uno spazio dei nomi di mount in cui esistono soltanto
i prefissi dichiarati, e li passa a systemd in una direttiva::

    BindReadOnlyPaths=/usr ... /srv/hermes/campioni /srv/hermes/esiti

In quella direttiva **lo spazio separa due percorsi e i due punti separano
sorgente e destinazione**. `hermes-core` rifiuta quindi, al caricamento del
perimetro, qualunque prefisso che non sia fatto di soli alfanumerici, `.`,
`_` e `-` — e il rifiuto colpisce il file intero, reti comprese, perche' il
perimetro e' un file solo.

Il pannello accettava invece `/srv/dati condivisi`, e lo faceva per una
ragione scritta nei test: uno spazio interno e' parte di un nome di directory
legittimo, e vietarlo sarebbe stata una regola sul filesystem di qualcun
altro. Era vero finche' il prefisso restava una stringa da confrontare. Non
lo e' piu' adesso che deve diventare un mount: una policy che il pannello
accetta e il server non puo' applicare e' una policy dichiarata e non in
vigore, che e' il difetto peggiore per un registro dello stato.

La direzione conta. Una regola piu' stretta qui e' innocua — tutto cio' che
il pannello accetta, il server lo accetta. Una piu' larga no. Per questo si
chiude qui e non allargando il server: accettare spazi la' vorrebbe dire fare
l'escape di un percorso dentro una direttiva, cioe' reintrodurre la classe di
difetto che la regola esiste per escludere.

I due vincoli
-------------

`scope_paths_prefix_senza_punto`
    Nessun segmento `.`: `/srv/./lab` e `/srv/lab` sono lo stesso percorso e
    due righe diverse. `hermes-core` lo rifiuta come forma non canonica.

`scope_paths_prefix_trascrivibile`
    Solo alfanumerici, `.`, `_`, `-` e la barra. Il nome non e' casuale:
    PostgreSQL valuta i `CHECK` in ordine alfabetico di nome e riporta il
    primo violato. Un prefisso con una tabulazione viola anche questo, ma la
    spiegazione giusta per l'operatore resta quella di
    `scope_paths_prefix_stampabile` — e lo stesso vale per il backslash e
    per gli spazi esterni. Con un nome che viene dopo tutti gli altri, questo
    vincolo risponde solo quando nessuna regola piu' specifica ha gia' detto
    perche'.

Le righe che ci sono gia'
-------------------------

`ADD CONSTRAINT` fallisce se una riga esistente viola il vincolo, e il
messaggio di PostgreSQL nomina il vincolo e non la riga. Qui si guarda prima,
e ci si ferma **dicendo quali prefissi** vanno tolti: una migrazione non
cancella una riga di policy per conto dell'operatore, nemmeno una che il
server non potrebbe applicare.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0005_prefissi_montabili"
down_revision: str | None = "0004_perimetro_percorsi"
branch_labels: str | None = None
depends_on: str | None = None

#: Le due regole, come espressioni SQL sul prefisso. Usate sia per cercare le
#: righe esistenti che le violano sia per i vincoli: una sola scrittura,
#: cosi' il controllo preventivo e il vincolo non possono dire cose diverse.
SENZA_PUNTO = r"prefix !~ '(^|/)\.(/|$)'"
TRASCRIVIBILE = r"prefix ~ '^[A-Za-z0-9._/-]+$'"


def upgrade() -> None:
    violano = (
        op.get_bind()
        .execute(
            sa.text(
                f"SELECT prefix FROM scope_paths "
                f"WHERE NOT ({SENZA_PUNTO}) OR NOT ({TRASCRIVIBILE}) "
                f"ORDER BY prefix"
            )
        )
        .scalars()
        .all()
    )
    if violano:
        elenco = "\n".join(f"  - {prefisso!r}" for prefisso in violano)
        raise RuntimeError(
            "La migrazione 0005 non puo' procedere: il perimetro contiene "
            "prefissi che hermes-core non puo' montare.\n"
            f"{elenco}\n"
            "Un prefisso puo' contenere solo lettere, cifre, '.', '_', '-' e "
            "'/', e nessun segmento '.': finisce in una direttiva di "
            "montaggio, dove lo spazio e i due punti sono sintassi.\n"
            "Rimuoverli dal pannello (Perimetro -> Percorsi autorizzati) e "
            "ridichiararli con un nome di directory montabile, poi rilanciare "
            "la migrazione. Non vengono cancellati in automatico: una riga di "
            "policy la toglie l'operatore."
        )

    op.execute(
        f"""
        ALTER TABLE scope_paths
            ADD CONSTRAINT scope_paths_prefix_senza_punto
                CHECK ({SENZA_PUNTO}),
            ADD CONSTRAINT scope_paths_prefix_trascrivibile
                CHECK ({TRASCRIVIBILE})
        """
    )
    op.execute(
        "COMMENT ON COLUMN scope_paths.prefix IS "
        "'Prefisso assoluto in forma canonica: senza componenti .. o ., senza "
        "doppie barre, senza barra finale, diverso da /, e fatto di soli "
        "alfanumerici, punto, trattino basso, trattino e barra, perche'' "
        "hermes-core lo scrive in una direttiva di montaggio.'"
    )


def downgrade() -> None:
    op.execute(
        """
        ALTER TABLE scope_paths
            DROP CONSTRAINT IF EXISTS scope_paths_prefix_trascrivibile,
            DROP CONSTRAINT IF EXISTS scope_paths_prefix_senza_punto
        """
    )
