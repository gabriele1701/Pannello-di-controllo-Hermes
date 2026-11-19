"""Ruolo di sola lettura per l'assessor VSPT: ``hermes_assess``.

Revision ID: 0006_ruolo_assess
Revises: 0005_prefissi_montabili
Create Date: 2026-11-19

SCRITTA, NON APPLICATA in questo scaffold. Si applica con l'ambiente VM
(milestone di venerdi'), insieme alla creazione del ruolo sul cluster demo.

Perche' un terzo ruolo
----------------------

Il pannello ha gia' due ruoli (migrazione 0002): il **proprietario**
(migrazioni e seed) e **``hermes_app``** (l'applicazione in esercizio).
L'assessor non puo' usare nessuno dei due:

* il proprietario puo' cambiare lo schema — un assessor che lo possedesse
  potrebbe alterare cio' che misura;
* ``hermes_app`` **non e' in sola lettura**: ha ``INSERT``/``DELETE`` su
  ``scope_networks``/``scope_aliases``/``scope_paths``, ``INSERT`` su
  ``tier_overrides`` e ``scope_consents``, ``UPDATE`` su
  ``scope_consents.revoked_at``. Un assessor che si connettesse con lui
  potrebbe scrivere, e la regola dura del VSPT e' che il DB si legge e basta.

Quindi un ruolo nuovo, ``hermes_assess``, **SELECT-only su tutto**, che non
possiede niente e non e' superutente. E' il canale `db` della spec §4.

Concessioni
-----------

==================  ======  ======  ======  ======
Tabella / vista     SELECT  INSERT  UPDATE  DELETE
==================  ======  ======  ======  ======
``users``             si
``tools``             si
``tier_overrides``    si
``audit_events``      si
``scope_networks``    si
``scope_aliases``     si
``scope_paths``       si
``scope_consents``    si
``tool_effective_tier`` si
``alembic_version``
==================  ======  ======  ======  ======

Solo ``SELECT``, su ogni tabella e sulla vista del tier effettivo. Nessuna
colonna di scrittura, nessuna sequenza (un ruolo che non inserisce non ha
bisogno di ``USAGE`` sulle sequenze), nessun ``INSERT``/``UPDATE``/``DELETE``/
``TRUNCATE`` da nessuna parte.

``alembic_version`` resta irraggiungibile, come per ``hermes_app``: l'assessor
misura lo schema reale (``pg_catalog``), non si fida di un numero di versione.

``pg_catalog`` e ``information_schema`` sono gia' leggibili da ``PUBLIC`` in
PostgreSQL: non serve un grant per leggerli, ed e' li' che il collector DB
andra' a prendere ruoli e grant (via ``aclexplode`` su ``pg_class``, leggibile
da chiunque). ``information_schema.role_table_grants`` mostra solo i grant del
ruolo corrente: per l'introspezione completa del modello a due ruoli si usa
``pg_catalog``, non ``information_schema``.

Come ``hermes_app``, nessun ``ALTER DEFAULT PRIVILEGES``: una tabella aggiunta
da una migrazione futura non sara' leggibile da ``hermes_assess`` finche'
qualcuno non le scrive una ``GRANT SELECT`` esplicita. E' il verso giusto in
cui essere scomodi.
"""

from __future__ import annotations

import os

from alembic import op

revision: str = "0006_ruolo_assess"
down_revision: str | None = "0005_prefissi_montabili"
branch_labels = None
depends_on = None

#: Nome del ruolo di sola lettura dell'assessor.
RUOLO_ASSESS = "hermes_assess"

#: Tabelle su cui il ruolo ha SELECT. Tutte: l'assessor legge l'intero schema
#: del dominio. (``alembic_version`` esclusa di proposito.)
TABELLE = (
    "users",
    "tools",
    "tier_overrides",
    "audit_events",
    "scope_networks",
    "scope_aliases",
    "scope_paths",
    "scope_consents",
)

#: Viste leggibili dall'assessor.
VISTE = ("tool_effective_tier",)


def upgrade() -> None:
    # ---------------------------------------------------------------------- #
    # 1. Il ruolo, senza privilegi di scrittura
    #
    # NOSUPERUSER, NOCREATEDB, NOCREATEROLE, NOBYPASSRLS sono i default, ma
    # scritti perche' questa riga e' dove si decide cosa il ruolo NON puo'
    # fare, e un default implicito non si legge in review. NOINHERIT come
    # hermes_app.
    # ---------------------------------------------------------------------- #
    op.execute(
        f"""
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_roles WHERE rolname = '{RUOLO_ASSESS}'
            ) THEN
                CREATE ROLE {RUOLO_ASSESS}
                    LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS
                    NOINHERIT;
            END IF;
        END
        $$
        """
    )

    # Password opzionale da ASSESS_DB_PASSWORD, come 0002 per hermes_app: passa
    # come parametro di bind dentro set_config, non come testo dello statement,
    # cosi' non finisce nel log delle query se log_statement e' attivo. Senza
    # password il ruolo non puo' autenticarsi con scram: un DSN che puntasse a
    # lui fallirebbe rumorosamente, che e' il comportamento voluto.
    password = os.environ.get("ASSESS_DB_PASSWORD")
    if password:
        connessione = op.get_bind()
        connessione.exec_driver_sql(
            "SELECT set_config('hermes.assess_password', %s, true)", (password,)
        )
        op.execute(
            f"""
            DO $$
            BEGIN
                EXECUTE format(
                    'ALTER ROLE {RUOLO_ASSESS} PASSWORD %L',
                    current_setting('hermes.assess_password')
                );
            END
            $$
            """
        )

    # ---------------------------------------------------------------------- #
    # 2. Concessioni minime: USAGE sullo schema, SELECT su tutto
    # ---------------------------------------------------------------------- #
    op.execute(f"GRANT USAGE ON SCHEMA public TO {RUOLO_ASSESS}")
    op.execute(f"GRANT SELECT ON {', '.join(TABELLE)} TO {RUOLO_ASSESS}")
    op.execute(f"GRANT SELECT ON {', '.join(VISTE)} TO {RUOLO_ASSESS}")

    # Nessuna concessione su alembic_version, nessuna sequenza, nessun
    # INSERT/UPDATE/DELETE/TRUNCATE: SELECT-only, deliberatamente. pg_catalog e
    # information_schema sono gia' leggibili da PUBLIC: non serve un grant.


def downgrade() -> None:
    """Rimuove le concessioni e il ruolo.

    Nessun ``REASSIGN``/``DROP OWNED``: il ruolo non possiede niente, che e' il
    punto per cui esiste."""
    op.execute(f"REVOKE ALL ON ALL TABLES IN SCHEMA public FROM {RUOLO_ASSESS}")
    op.execute(f"REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM {RUOLO_ASSESS}")
    op.execute(f"REVOKE ALL ON SCHEMA public FROM {RUOLO_ASSESS}")
    op.execute(f"DROP ROLE IF EXISTS {RUOLO_ASSESS}")
