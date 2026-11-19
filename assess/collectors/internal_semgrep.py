"""Collector interno: semgrep (analisi statica del sorgente).

Comando reale (implementazione live, venerdi'):

    semgrep scan --json --no-git-ignore \\
            --config p/python --config p/owasp-top-ten \\
            backend/

* Ruleset OWASP/Python **bundled** (offline): nessun download durante lo scan.
* Sorgente ``backend/`` prelevato dalla macchina via SSH ristretto.
* Output JSON: ``results[]`` con ``check_id``, ``path``, ``start.line``,
  ``extra.message``, ``extra.severity``, ``extra.metadata.cwe``.

Lo scope e' interno: richiede l'accesso autenticato alla macchina. Il
sorgente non si scarica da Internet — e' quello del target, letto in sola
lettura.
"""

from __future__ import annotations

from assess.collectors.base import (
    CollectorBase,
    EsecuzioneLiveNonDisponibile,
    RunContext,
)
from assess.model import RawResult, Scope, Source


class SemgrepCollector(CollectorBase):
    name = "semgrep"
    source = Source.SEMGREP
    scope = Scope.INTERNAL
    requires = frozenset({"ssh"})
    comando = (
        "semgrep scan --json --no-git-ignore "
        "--config p/python --config p/owasp-top-ten backend/"
    )

    def run(self, ctx: RunContext) -> RawResult:
        raise EsecuzioneLiveNonDisponibile(
            "semgrep live non disponibile nello scaffold; comando: " + self.comando
        )


__all__ = ["SemgrepCollector"]
