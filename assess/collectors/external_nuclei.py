"""Collector esterno: nuclei (template offline).

Comando reale (implementazione live, venerdi'):

    nuclei -silent -jsonl -no-color \\
           -t templates_nuclei/ \\
           -H "Cookie: hermes_session=<cookie di sessione>" \\
           -list <endpoint dal contratto> \\
           -disable-update-check

* Template **offline** versionati in ``templates_nuclei/``: nessun
  auto-update durante lo scan (``-disable-update-check``), cosi' il run
  confinato usa solo cio' che e' gia' locale.
* Cookie di sessione iniettato (login operatore demo).
* Lista di URL costruita dall'inventario (``openapi.json``) piu' il base URL.
* Output JSONL, una riga per match: ``template-id``, ``info.name``,
  ``info.severity``, ``matched-at``.

Esito onesto atteso: pochi o nessun match su una webapp piccola e
parametrizzata; cio' che trova va verificato, non preso per confermato.
"""

from __future__ import annotations

from assess.collectors.base import (
    CollectorBase,
    EsecuzioneLiveNonDisponibile,
    RunContext,
)
from assess.model import RawResult, Scope, Source


class NucleiCollector(CollectorBase):
    name = "nuclei"
    source = Source.NUCLEI
    scope = Scope.EXTERNAL
    requires = frozenset({"target"})
    comando = (
        "nuclei -silent -jsonl -no-color -t templates_nuclei/ "
        '-H "Cookie: hermes_session=***" -list <endpoint> -disable-update-check'
    )

    def run(self, ctx: RunContext) -> RawResult:
        raise EsecuzioneLiveNonDisponibile(
            "nuclei live non disponibile nello scaffold; comando: " + self.comando
        )


__all__ = ["NucleiCollector"]
