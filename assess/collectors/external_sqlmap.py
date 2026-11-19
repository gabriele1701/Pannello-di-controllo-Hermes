"""Collector esterno: sqlmap (profilo non distruttivo).

Comando reale (implementazione live, venerdi'), un invocazione per endpoint
iniettabile ricavato dal contratto:

    sqlmap -u "<base_url><path>" \\
           --cookie="hermes_session=<cookie>" \\
           --data="<campi del corpo>"   # per POST \\
           --batch --level=1 --risk=1 \\
           --technique=BEU \\
           --dbms=postgresql \\
           --flush-session --answers="quit=N"

* **Profilo non distruttivo**: livello/rischio bassi, tecniche limitate a
  Boolean/Error/Union (``BEU``) — niente stacked queries, niente time-based
  che apra la via a comandi OS o a scritture. Nessuna azione su dati o sistema.
* Endpoint e parametri da ``openapi.json`` (``parametri_iniettabili``), non da
  una lista scritta a mano.
* Autenticato col cookie di sessione. Una **sessione scaduta** deve dare un
  esito esplicito (un 401/redirect al login), mai un falso negativo
  silenzioso: lo stato del check diventa *fallito con nota*, non *negative*.

Esito onesto atteso: nessuna SQLi — il backend usa query parametrizzate
SQLAlchemy — cioe' ``pentest_result = negative`` con nota di controllo
positivo (*non rilevato nei test svolti*), non "sicuro".
"""

from __future__ import annotations

from assess.collectors.base import (
    CollectorBase,
    EsecuzioneLiveNonDisponibile,
    RunContext,
)
from assess.model import RawResult, Scope, Source


class SqlmapCollector(CollectorBase):
    name = "sqlmap"
    source = Source.SQLMAP
    scope = Scope.EXTERNAL
    requires = frozenset({"target"})
    comando = (
        'sqlmap -u "<base_url><path>" --cookie="hermes_session=***" '
        "--batch --level=1 --risk=1 --technique=BEU --dbms=postgresql"
    )

    def run(self, ctx: RunContext) -> RawResult:
        raise EsecuzioneLiveNonDisponibile(
            "sqlmap live non disponibile nello scaffold; comando: " + self.comando
        )


__all__ = ["SqlmapCollector"]
