"""Client del protocollo SSH dell'assessor — lato trasporto.

Parla il contratto di ``assess/ssh/PROTOCOL.md``: invia un **verbo logico**
(mai un comando shell), riceve **una riga** di JSON, la valida come envelope e
la restituisce strutturata. Non e' il controllo di sicurezza — quello e' il
ForceCommand ``vspt-ssh-wrapper`` sulla VM — ma e' la meta' client dello stesso
contratto, e deve combaciarci.

L'unico punto di I/O (aprire la connessione SSH e inviare il verbo) e' lo stub
``_invia``: nello scaffold solleva ``EsecuzioneLiveNonDisponibile``. Tutto il
resto — quali verbi esistono, come si legge e valida l'envelope — e'
implementato e testato.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from assess.collectors.base import EsecuzioneLiveNonDisponibile
from assess.config import ConfigSsh

#: Versione del protocollo che questo client parla. Una risposta con un valore
#: diverso viene rifiutata: il contratto e' esplicito, non si indovina.
PROTOCOL_VERSION = 1

#: I verbi ammessi, con il loro check_id. Devono combaciare con
#: ``ALLOWED_COMMANDS`` del wrapper (PROTOCOL.md ne e' la fonte condivisa).
VERBI: dict[str, str] = {
    "system.info": "SYS-01",
    "system.listeners": "SYS-02",
    "system.processes": "SYS-03",
    "source.export": "SRC-01",
}


class ProtocolloNonValido(Exception):
    """La risposta non e' un envelope valido del protocollo: non e' JSON, non e'
    un oggetto, manca un campo, o ``protocol_version`` non e' quella attesa."""


@dataclass(slots=True)
class Envelope:
    """Una risposta del wrapper, gia' validata."""

    protocol_version: int
    check_id: str
    status: str  # "ok" | "error"
    data: dict[str, Any] | None
    error: dict[str, Any] | None

    @property
    def ok(self) -> bool:
        return self.status == "ok"

    @property
    def codice_errore(self) -> str | None:
        return (self.error or {}).get("code") if self.error else None


def leggi_envelope(riga: str) -> Envelope:
    """Parsa e valida una riga di risposta. Solleva ``ProtocolloNonValido`` se
    non e' un envelope conforme. Pura: non fa I/O."""
    try:
        oggetto = json.loads(riga)
    except json.JSONDecodeError as exc:
        raise ProtocolloNonValido(f"risposta non JSON: {exc}") from exc
    if not isinstance(oggetto, dict):
        raise ProtocolloNonValido("la risposta non e' un oggetto JSON")
    if oggetto.get("protocol_version") != PROTOCOL_VERSION:
        raise ProtocolloNonValido(
            f"protocol_version {oggetto.get('protocol_version')!r}, atteso {PROTOCOL_VERSION}"
        )
    status = oggetto.get("status")
    if status not in ("ok", "error"):
        raise ProtocolloNonValido(f"status non valido: {status!r}")
    check_id = oggetto.get("check_id")
    if not isinstance(check_id, str) or not check_id:
        raise ProtocolloNonValido("check_id assente")
    return Envelope(
        protocol_version=PROTOCOL_VERSION,
        check_id=check_id,
        status=status,
        data=oggetto.get("data"),
        error=oggetto.get("error"),
    )


class WrapperSsh:
    """Interfaccia SSH del tool verso l'host della VM, a verbi logici."""

    def __init__(self, config: ConfigSsh) -> None:
        self._config = config

    @property
    def destinazione(self) -> str:
        return f"{self._config.user}@{self._config.host}:{self._config.port}"

    def esegui(self, verbo: str) -> Envelope:
        """Invia un verbo e restituisce l'envelope validato.

        Rifiuta un verbo non ammesso prima ancora di aprire la connessione: il
        client non spedisce stringhe che il contratto non prevede."""
        if verbo not in VERBI:
            raise ValueError(f"verbo non ammesso dal protocollo: {verbo!r}")
        return leggi_envelope(self._invia(verbo))

    def _invia(self, verbo: str) -> str:
        """UNICO punto di I/O: apre la connessione SSH, invia il verbo come
        ``SSH_ORIGINAL_COMMAND`` e restituisce la riga di risposta grezza.

        Nello scaffold non e' implementato: solleva
        ``EsecuzioneLiveNonDisponibile``. L'implementazione live (Paramiko o
        ``ssh`` via subprocess) arriva con la VM."""
        raise EsecuzioneLiveNonDisponibile(
            f"SSH live non disponibile nello scaffold ({self.destinazione}); "
            f"verbo: {verbo}"
        )


__all__ = [
    "Envelope",
    "PROTOCOL_VERSION",
    "ProtocolloNonValido",
    "VERBI",
    "WrapperSsh",
    "leggi_envelope",
]
