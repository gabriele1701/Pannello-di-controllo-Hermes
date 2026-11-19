"""Collector interno: postgres (ruoli, grant, config) via ``hermes_assess``.

Query reali, tutte in sola lettura con il ruolo ``hermes_assess`` (SELECT-only,
migrazione 0006). Il collector live le esegue via psycopg e serializza i
risultati in JSON; ``parse`` confronta quel JSON col **modello a due ruoli**
documentato e produce un'**attestazione** per ciascuna regola: un controllo
positivo (i privilegi reali combaciano col modello) o una deviazione.

Struttura del JSON che ``parse`` riceve::

    {
      "roles":         [{"rolname": "...", "rolsuper": false, ...}, ...],
      "table_grants":  [{"grantee": "...", "table_name": "...",
                         "privilege_type": "SELECT|INSERT|UPDATE|DELETE"}, ...],
      "column_grants": [{"grantee": "...", "table_name": "...",
                         "column_name": "...", "privilege_type": "UPDATE"}, ...],
      "settings":      [{"name": "session_replication_role", "setting": "origin"}]
    }

``parse``: JSON malformato o senza i ruoli attesi → ``FALLITO`` (la query non e'
stata eseguita dove doveva). Altrimenti ``COMPLETATO`` con le attestazioni —
conformi (verdi) e non.
"""

from __future__ import annotations

import json
from typing import Any

from assess.collectors.base import (
    CollectorBase,
    EsecuzioneLiveNonDisponibile,
    RunContext,
    raw_completato,
    raw_fallito,
)
from assess.model import RawResult, Scope, Source

#: Query del collector. Sono documentazione E il comando reale.
QUERY = (
    "SELECT rolname, rolsuper, rolcreatedb, rolcreaterole, rolbypassrls "
    "FROM pg_catalog.pg_roles WHERE rolname LIKE 'hermes%'",
    "SELECT grantee, table_name, privilege_type FROM information_schema."
    "role_table_grants WHERE table_schema = 'public'",
    "SELECT grantee, table_name, column_name, privilege_type FROM "
    "information_schema.column_privileges WHERE table_schema = 'public'",
    "SELECT name, setting FROM pg_catalog.pg_settings WHERE name IN "
    "('session_replication_role', 'log_statement')",
)

#: Privilegi di scrittura: la loro presenza dove non deve esserci e' la deviazione.
_SCRITTURA = {"INSERT", "UPDATE", "DELETE", "TRUNCATE"}


def _privilegi(grants: list[dict], grantee: str, table: str) -> set[str]:
    return {
        g["privilege_type"]
        for g in grants
        if g.get("grantee") == grantee and g.get("table_name") == table
    }


def _col_privilegi(cols: list[dict], grantee: str, table: str) -> set[tuple[str, str]]:
    return {
        (g["column_name"], g["privilege_type"])
        for g in cols
        if g.get("grantee") == grantee and g.get("table_name") == table
    }


class DbCollector(CollectorBase):
    name = "postgres"
    source = Source.POSTGRES
    scope = Scope.INTERNAL
    requires = frozenset({"db"})
    comando = "SELECT ... pg_roles / role_table_grants / column_privileges / pg_settings (hermes_assess, SELECT-only)"

    def costruisci_comando(self, ctx: RunContext) -> list[str]:
        # Non e' un comando shell: sono le query. Restituite come lista cosi'
        # il runner e i test possono ispezionarle.
        return list(QUERY)

    def _attestazioni(self, dati: dict[str, Any]) -> list[dict]:
        roles = {r["rolname"]: r for r in dati.get("roles", [])}
        tg = dati.get("table_grants", [])
        cg = dati.get("column_grants", [])
        settings = {s["name"]: s["setting"] for s in dati.get("settings", [])}
        att: list[dict] = []

        def regola(controllo, bersaglio, atteso, osservato, conforme, **extra):
            att.append({
                "controllo": controllo, "bersaglio": bersaglio,
                "atteso": atteso, "osservato": osservato, "conforme": conforme,
                "references": ["migrazioni 0002/0006"], **extra,
            })

        # R1 — hermes_app non e' superutente.
        app = roles.get("hermes_app", {})
        regola(
            "hermes_app non e' superutente", "hermes_app",
            "rolsuper=false", f"rolsuper={app.get('rolsuper')}",
            app.get("rolsuper") is False, impact=5, probability=4,
            recommendation="Revocare SUPERUSER dal ruolo applicativo.",
        )

        # R2 — hermes_app in sola lettura su audit_events.
        scrittura_audit = _privilegi(tg, "hermes_app", "audit_events") & _SCRITTURA
        regola(
            "hermes_app senza scrittura su audit_events", "audit_events",
            "nessun INSERT/UPDATE/DELETE",
            ", ".join(sorted(scrittura_audit)) or "nessuno",
            not scrittura_audit, impact=4, probability=3,
            recommendation="Revocare i privilegi di scrittura su audit_events.",
        )

        # R3 — scope_consents: UPDATE solo sulla colonna revoked_at.
        update_tabella = "UPDATE" in _privilegi(tg, "hermes_app", "scope_consents")
        col_update = _col_privilegi(cg, "hermes_app", "scope_consents")
        solo_revoked = col_update == {("revoked_at", "UPDATE")} or (
            ("revoked_at", "UPDATE") in col_update
            and all(p != "UPDATE" or c == "revoked_at" for c, p in col_update)
        )
        regola(
            "hermes_app aggiorna solo scope_consents.revoked_at", "scope_consents",
            "UPDATE solo su revoked_at, non sulla tabella",
            ("UPDATE tabella intera" if update_tabella
             else "UPDATE(" + ", ".join(sorted(c for c, p in col_update if p == "UPDATE")) + ")"),
            (not update_tabella) and solo_revoked, impact=3, probability=3,
            recommendation="Concedere UPDATE solo sulla colonna revoked_at.",
        )

        # R4 — hermes_assess e' SELECT-only.
        scrittura_assess = {
            (g["table_name"], g["privilege_type"])
            for g in tg
            if g.get("grantee") == "hermes_assess" and g["privilege_type"] in _SCRITTURA
        }
        regola(
            "hermes_assess e' SELECT-only", "hermes_assess",
            "nessun privilegio di scrittura",
            ", ".join(sorted(f"{t}:{p}" for t, p in scrittura_assess)) or "nessuno",
            not scrittura_assess, impact=4, probability=3,
            recommendation="Revocare ogni INSERT/UPDATE/DELETE da hermes_assess.",
        )

        # R5 — session_replication_role in origine (i trigger scattano).
        srr = settings.get("session_replication_role")
        regola(
            "session_replication_role = origin", "cluster",
            "origin", str(srr), srr == "origin", impact=5, probability=2,
            recommendation="Riportare session_replication_role a 'origin'.",
        )
        return att

    def parse(self, grezzo: str) -> RawResult:
        try:
            dati = json.loads(grezzo)
        except json.JSONDecodeError as exc:
            return raw_fallito(
                self.source, self.comando, f"output postgres non JSON: {exc}"
            )
        if not isinstance(dati, dict) or "roles" not in dati or "table_grants" not in dati:
            return raw_fallito(
                self.source, self.comando,
                "struttura inattesa: mancano 'roles'/'table_grants'.",
            )
        nomi = {r.get("rolname") for r in dati.get("roles", [])}
        if "hermes_app" not in nomi:
            return raw_fallito(
                self.source, self.comando,
                "il ruolo hermes_app non compare: query eseguita sul database "
                "sbagliato o schema non applicato (esito esplicito).",
            )
        att = self._attestazioni(dati)
        nonconformi = sum(1 for a in att if not a["conforme"])
        nota = (
            f"{len(att)} attestazioni del modello a due ruoli, "
            f"{nonconformi} deviazioni."
        )
        return raw_completato(self.source, self.comando, att, nota)

    def _esegui_live(self, ctx: RunContext) -> str:
        raise EsecuzioneLiveNonDisponibile(
            "postgres live non disponibile nello scaffold; query: "
            + " ; ".join(QUERY)
        )


__all__ = ["DbCollector", "QUERY"]
