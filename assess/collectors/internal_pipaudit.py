"""Collector interno: pip-audit (CVE note sulle dipendenze).

Comando reale (implementazione live, venerdi'):

    pip-audit --format json --require-hashes -r requirements.txt

* Fonte CVE locale (il DB di pip-audit si aggiorna in uno step separato ed
  esplicito, non durante il run confinato).
* Output JSON: ``dependencies[]`` con ``name``, ``version``, ``vulns[]``
  (``id``, ``fix_versions``, ``description``).

Nota sul file: la spec parla di ``requirements.lock``; nel repo il file
pinnato e' ``requirements.txt`` (pin esatti, generato dall'ambiente). Il
collector usa quello reale. Se in futuro nascesse un vero lockfile con hash,
cambia solo l'argomento ``-r``.
"""

from __future__ import annotations

from assess.collectors.base import (
    CollectorBase,
    EsecuzioneLiveNonDisponibile,
    RunContext,
)
from assess.model import RawResult, Scope, Source


class PipAuditCollector(CollectorBase):
    name = "pip-audit"
    source = Source.PIP_AUDIT
    scope = Scope.INTERNAL
    requires = frozenset({"ssh"})
    comando = "pip-audit --format json -r requirements.txt"

    def run(self, ctx: RunContext) -> RawResult:
        raise EsecuzioneLiveNonDisponibile(
            "pip-audit live non disponibile nello scaffold; comando: " + self.comando
        )


__all__ = ["PipAuditCollector"]
