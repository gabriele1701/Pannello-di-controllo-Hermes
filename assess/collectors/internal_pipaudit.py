"""Collector interno: pip-audit (CVE note sulle dipendenze).

Comando reale:

    pip-audit --format json -r <repo>/requirements.txt

Output JSON: ``dependencies[]`` con ``name``, ``version`` e ``vulns[]``
(``id``, ``fix_versions``, ``description``, ``aliases``). Il DB degli advisory
si aggiorna in uno step separato ed esplicito, non durante il run confinato.

``parse``: almeno una dipendenza con vulnerabilita' → ``COMPLETATO``; nessuna
vulnerabilita' su nessuna dipendenza → ``COMPLETATO`` a zero (controllo
positivo); JSON malformato o struttura inattesa → ``FALLITO``.
"""

from __future__ import annotations

import json

from assess.collectors.base import (
    CollectorBase,
    EsecuzioneLiveNonDisponibile,
    RunContext,
    raw_completato,
    raw_fallito,
    raw_vuoto,
)
from assess.model import RawResult, Scope, Source


class PipAuditCollector(CollectorBase):
    name = "pip-audit"
    source = Source.PIP_AUDIT
    scope = Scope.INTERNAL
    requires = frozenset({"ssh"})
    comando = "pip-audit --format json -r requirements.txt"

    def costruisci_comando(self, ctx: RunContext) -> list[str]:
        requisiti = str(ctx.repo_root / "requirements.txt")
        return ["pip-audit", "--format", "json", "-r", requisiti]

    def parse(self, grezzo: str) -> RawResult:
        try:
            dati = json.loads(grezzo)
        except json.JSONDecodeError as exc:
            return raw_fallito(
                self.source, self.comando, f"output pip-audit non JSON: {exc}"
            )
        # pip-audit usa {"dependencies": [...]}; alcune versioni danno la lista
        # diretta. Si accettano entrambe, qualunque altra forma e' malformata.
        if isinstance(dati, dict) and "dependencies" in dati:
            dipendenze = dati["dependencies"]
        elif isinstance(dati, list):
            dipendenze = dati
        else:
            return raw_fallito(
                self.source, self.comando,
                "output pip-audit malformato: ne' {'dependencies': [...]} ne' lista.",
            )
        con_vuln = [d for d in dipendenze if d.get("vulns")]
        if con_vuln:
            return raw_completato(self.source, self.comando, con_vuln)
        return raw_vuoto(
            self.source, self.comando,
            f"nessuna CVE nota sulle {len(dipendenze)} dipendenze analizzate "
            "(controllo positivo).",
        )

    def _esegui_live(self, ctx: RunContext) -> str:
        raise EsecuzioneLiveNonDisponibile(
            "pip-audit live non disponibile nello scaffold; comando: "
            + " ".join(self.costruisci_comando(ctx))
        )


__all__ = ["PipAuditCollector"]
