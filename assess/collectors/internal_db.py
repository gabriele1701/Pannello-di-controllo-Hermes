"""Collector interno: postgres (ruoli, grant, config) via ``hermes_assess``.

Query reali (implementazione live, venerdi'), tutte in **sola lettura** con il
ruolo ``hermes_assess`` (SELECT-only, migrazione 0006):

    -- ruoli e loro attributi
    SELECT rolname, rolsuper, rolcreatedb, rolcreaterole, rolbypassrls
      FROM pg_catalog.pg_roles
     WHERE rolname LIKE 'hermes%';

    -- grant per tabella
    SELECT grantee, table_name, privilege_type
      FROM information_schema.role_table_grants
     WHERE table_schema = 'public'
     ORDER BY grantee, table_name;

    -- grant a livello di colonna (es. scope_consents.revoked_at)
    SELECT grantee, table_name, column_name, privilege_type
      FROM information_schema.column_privileges
     WHERE table_schema = 'public';

    -- impostazioni rilevanti
    SELECT name, setting FROM pg_catalog.pg_settings
     WHERE name IN ('session_replication_role', 'log_statement');

Serve a produrre l'**attestazione** del modello a due ruoli documentato: che
``hermes_app`` non abbia UPDATE/DELETE dove non deve, che ``audit_events`` sia
senza INSERT, che ``scope_consents`` abbia UPDATE solo su ``revoked_at``. Un
controllo positivo: la conferma che i privilegi reali coincidono col modello,
non un finding di vulnerabilita'.

Richiede ``db``: la connessione read-only di ``hermes_assess``. Senza, il check
e' saltato, non superato.
"""

from __future__ import annotations

from assess.collectors.base import (
    CollectorBase,
    EsecuzioneLiveNonDisponibile,
    RunContext,
)
from assess.model import RawResult, Scope, Source


class DbCollector(CollectorBase):
    name = "postgres"
    source = Source.POSTGRES
    scope = Scope.INTERNAL
    requires = frozenset({"db"})
    comando = (
        "SELECT ... FROM pg_catalog.pg_roles / "
        "information_schema.role_table_grants / pg_settings  (hermes_assess, SELECT-only)"
    )

    def run(self, ctx: RunContext) -> RawResult:
        raise EsecuzioneLiveNonDisponibile(
            "postgres live non disponibile nello scaffold; query: " + self.comando
        )


__all__ = ["DbCollector"]
