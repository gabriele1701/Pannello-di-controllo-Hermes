"""I valori `path` e `process` nell'enum dei bersagli.

Revision ID: 0003_bersagli_estesi
Revises: 0002_ruolo_applicativo
Create Date: 2026-11-11

Perche' due migrazioni, e perche' non bastano
---------------------------------------------

Questa migrazione aggiunge **soltanto** i due valori all'enum. I vincoli che
li usano stanno nella 0004, perche' PostgreSQL **non permette di usare un
valore di enum nella stessa transazione che lo aggiunge**:

    ERROR:  unsafe use of new value "path" of enum type target_kind
    HINT:  New enum values must be committed before they can be used.

Ma la divisione in due file da sola non basta, e l'ho scoperto provandola:
`alembic upgrade head` esegue **tutta la catena in una sola transazione**, non
una transazione per migrazione. Con le due migrazioni separate e nessun altro
accorgimento, l'errore qui sopra si presenta identico -- solo piu' tardi,
dentro la 0004, su un `ALTER TABLE` che sembra innocente.

Da qui l'`autocommit_block()`: Alembic esce dalla transazione della
migrazione, esegue l'`ALTER TYPE` in autocommit, e rientra. E' il meccanismo
che esiste in Alembic proprio per questo caso.

La scelta alternativa era `transaction_per_migration=True` in
`migrations/env.py`, che avrebbe risolto lo stesso problema cambiando il
comportamento di **ogni** migrazione del progetto: un guasto a meta' catena
lascerebbe applicate quelle precedenti invece di annullare tutto. Non vale la
pena cambiare la semantica di tutte per il caso di una.

Conseguenza da conoscere: cio' che sta nell'autocommit_block **non viene
annullato** se una migrazione successiva fallisce. Non e' una perdita, perche'
un valore aggiunto a un enum non si rimuove comunque (vedi sotto), ed e' il
motivo per cui gli `ALTER TYPE` qui sotto hanno `IF NOT EXISTS`: al secondo
tentativo i valori ci sono gia', e senza quella clausola il ritentativo
fallirebbe su di loro invece che sul problema vero.

Il buco che questa migrazione comincia a chiudere
-------------------------------------------------

Il perimetro del pannello e' fatto di reti: `scope_networks` e' di tipo
`cidr`, `scope_aliases` di tipo `inet`, e `target_kind` ha due soli valori,
`none` e `host`. Ma gli strumenti che stanno arrivando -- REA, GDB, Frida --
puntano a **file e processi**, non a host.

Un tool che aggancia processi senza perimetro, sulla macchina sbagliata, e'
esattamente l'azione intrusiva non confermata che questo progetto esiste per
impedire. Il modello dei bersagli va esteso prima di integrarli, non dopo:
farlo dopo significherebbe adattare due volte il contratto fra pannello e
server.

I quattro valori, e quale perimetro si applica a ciascuno:

=============  ==========================  ==================================
`target_kind`  Bersaglio                   Perimetro
=============  ==========================  ==================================
`none`         nessuno                     nessuno
`host`         indirizzo o rete            `scope_networks` / `scope_aliases`
`path`         file o directory            `scope_paths` (creata dalla 0004)
`process`      processo in esecuzione      **il container stesso**
=============  ==========================  ==================================

Sul perche' `process` non abbia una tabella, vedi il docstring della 0004.

`downgrade` non torna indietro
------------------------------

PostgreSQL non ha `ALTER TYPE ... DROP VALUE`: un valore aggiunto a un enum
non si rimuove. Si potrebbe ricreare il tipo da zero, riscrivendo ogni
colonna che lo usa, ma sarebbe un'operazione piu' rischiosa del problema che
risolve -- e andrebbe comunque a vuoto se qualche riga usasse i valori nuovi.

Il `downgrade` quindi non fa niente e lo dichiara. Fingere un ripristino che
non avviene e' peggio di non averlo: chi lo esegue crede di essere tornato
allo stato precedente e non lo e'.
"""

from __future__ import annotations

from alembic import op

revision: str = "0003_bersagli_estesi"
down_revision: str | None = "0002_ruolo_applicativo"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    # Fuori dalla transazione della migrazione: vedi il docstring. Senza
    # questo blocco i valori restano non utilizzabili fino alla fine di
    # `alembic upgrade head`, e la 0004 fallisce sul `CHECK` che li nomina.
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE target_kind ADD VALUE IF NOT EXISTS 'path'")
        op.execute("ALTER TYPE target_kind ADD VALUE IF NOT EXISTS 'process'")


def downgrade() -> None:
    """Non rimuove i valori: PostgreSQL non lo permette.

    Vedi il docstring del modulo. Volutamente senza `raise`: un downgrade che
    solleva bloccherebbe il ritorno alla 0002 anche per le migrazioni che
    stanno sopra, e l'enum con due valori in piu' non rompe nulla dello
    schema precedente -- nessuna riga li usa, perche' il `CHECK` e la tabella
    che li usano se ne sono andati con il downgrade della 0004.
    """
