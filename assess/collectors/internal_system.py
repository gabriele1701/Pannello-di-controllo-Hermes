"""Collector interno: system (porte, processi, servizi, permessi) via SSH.

Comandi reali (implementazione live, venerdi'), tutti read-only, inviati dal
``WrapperSsh`` e autorizzati dal ``ForceCommand`` validatore sul server:

    ss -tlnp                 # porte in ascolto — attesa: 8000 e 5432 solo su
                             #   loopback/rete interna, nessun servizio inatteso
    ps aux                   # processi
    systemctl list-units --type=service --state=running
    docker ps                # stato dei container del compose
    ls -la <percorsi sensibili>   # permessi (.env 600, chiavi, volumi)

Serve a verificare che l'ambiente combaci con quello dichiarato: nessuna porta
di troppo esposta, i permessi del ``.env`` stretti, nessun processo estraneo.

Richiede ``ssh``. Senza il canale, il check e' saltato.
"""

from __future__ import annotations

from assess.collectors.base import (
    CollectorBase,
    EsecuzioneLiveNonDisponibile,
    RunContext,
)
from assess.model import RawResult, Scope, Source


class SystemCollector(CollectorBase):
    name = "system"
    source = Source.SYSTEM
    scope = Scope.INTERNAL
    requires = frozenset({"ssh"})
    comando = "ss -tlnp ; ps aux ; systemctl list-units --state=running ; docker ps ; ls -la"

    def run(self, ctx: RunContext) -> RawResult:
        raise EsecuzioneLiveNonDisponibile(
            "system live non disponibile nello scaffold; comandi: " + self.comando
        )


__all__ = ["SystemCollector"]
