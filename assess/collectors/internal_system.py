"""Collector interno: system (porte, processi, servizi, permessi) via SSH.

Comandi reali, tutti read-only, inviati dal ``WrapperSsh`` e autorizzati dal
``ForceCommand`` validatore sul server (``assess/ssh/hermes-assess-ssh``):

    ss -tlnp
    ps aux
    systemctl list-units --type=service --state=running
    docker ps --format '{{.Names}} {{.Status}} {{.Ports}}'
    ls -la <percorsi sensibili>

``parse`` qui interpreta l'output di ``ss -tlnp`` — le porte in ascolto, il
controllo piu' rivelatore — e ne ricava attestazioni: le porte attese
(``app`` 8000, ``db`` 5432) sono conformi, ogni altra porta in ascolto e' una
deviazione (un servizio di troppo esposto).

Casi: output non riconoscibile → ``FALLITO``; header presente ma nessuna porta
in ascolto → ``COMPLETATO`` a zero (nota); porte in ascolto → ``COMPLETATO``
con le attestazioni.
"""

from __future__ import annotations

import re

from assess.collectors.base import (
    CollectorBase,
    EsecuzioneLiveNonDisponibile,
    RunContext,
    raw_completato,
    raw_fallito,
    raw_vuoto,
)
from assess.model import RawResult, Scope, Source

#: Porte attese in ascolto: l'app e il database del compose.
PORTE_ATTESE = {8000: "app (uvicorn)", 5432: "db (postgres)"}

_COMANDI = (
    "ss -tlnp",
    "ps aux",
    "systemctl list-units --type=service --state=running",
    "docker ps --format '{{.Names}} {{.Status}} {{.Ports}}'",
)

#: Riga di ss: cattura la colonna Local Address:Port dopo lo stato LISTEN.
_RE_LISTEN = re.compile(r"^LISTEN\s+\d+\s+\d+\s+(\S+)", re.MULTILINE)


def _porta(local_addr_port: str) -> int | None:
    """Estrae la porta da 'indirizzo:porta' (gestisce IPv6 [::]:8000)."""
    _, _, coda = local_addr_port.rpartition(":")
    return int(coda) if coda.isdigit() else None


class SystemCollector(CollectorBase):
    name = "system"
    source = Source.SYSTEM
    scope = Scope.INTERNAL
    requires = frozenset({"ssh"})
    comando = "ss -tlnp ; ps aux ; systemctl list-units --state=running ; docker ps"

    def costruisci_comando(self, ctx: RunContext) -> list[str]:
        # L'elenco dei comandi diagnostici che il collector invia via SSH.
        return list(_COMANDI)

    def parse(self, grezzo: str) -> RawResult:
        prima_riga = grezzo.splitlines()[0] if grezzo.strip() else ""
        riconosciuto = (
            "LISTEN" in grezzo or "Local Address" in grezzo or "State" in prima_riga
        )
        indirizzi = _RE_LISTEN.findall(grezzo)
        if not indirizzi:
            if not riconosciuto:
                return raw_fallito(
                    self.source, self.comando,
                    "output di 'ss -tlnp' non riconoscibile: ne' intestazione ne' "
                    "righe LISTEN (comando non eseguito o troncato).",
                )
            return raw_vuoto(
                self.source, self.comando,
                "nessuna porta TCP in ascolto rilevata.",
            )

        att: list[dict] = []
        for indirizzo in indirizzi:
            porta = _porta(indirizzo)
            if porta is None:
                continue
            attesa = porta in PORTE_ATTESE
            att.append({
                "controllo": f"porta {porta} in ascolto",
                "bersaglio": indirizzo,
                "atteso": "solo app:8000 e db:5432",
                "osservato": f"{indirizzo} ({PORTE_ATTESE.get(porta, 'servizio inatteso')})",
                "conforme": attesa,
                "references": ["compose.assess.yaml"],
                "impact": 3,
                "probability": 3,
                "recommendation": (
                    "Nessuna azione." if attesa else
                    "Chiudere o non esporre questa porta: non e' app ne' db."
                ),
            })
        nonconformi = sum(1 for a in att if not a["conforme"])
        return raw_completato(
            self.source, self.comando, att,
            f"{len(att)} porte in ascolto, {nonconformi} inattese.",
        )

    def _esegui_live(self, ctx: RunContext) -> str:
        raise EsecuzioneLiveNonDisponibile(
            "system live non disponibile nello scaffold; comandi: "
            + " ; ".join(_COMANDI)
        )


__all__ = ["SystemCollector", "PORTE_ATTESE"]
