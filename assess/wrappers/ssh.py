"""Client del protocollo SSH dell'assessor — lato trasporto.

Parla il contratto di ``assess/ssh/PROTOCOL.md``: invia un **verbo logico**
(mai un comando shell), riceve **una riga** di JSON, la valida come envelope e
la restituisce strutturata. Non e' il controllo di sicurezza — quello e' il
ForceCommand ``vspt-ssh-wrapper`` sulla VM — ma e' la meta' client dello stesso
contratto, e deve combaciarci.

L'unico punto di I/O e' ``_invia``, che esegue ``ssh`` con le opzioni di
hardening (BatchMode, IdentitiesOnly, StrictHostKeyChecking, known_hosts, chiave
dedicata, ConnectTimeout) e restituisce la prima riga di stdout. Un guasto del
trasporto (ssh non avviabile, nessun envelope, timeout) solleva
``TrasportoSshFallito`` — un FALLITO, mai un finto esito. I percorsi di chiave e
known_hosts vengono dalla config (``scope.toml``), non da un default.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from typing import Any

from assess.collectors.base import EsecuzioneLiveNonDisponibile
from assess.config import ConfigSsh

#: Versione del protocollo che questo client parla. Una risposta con un valore
#: diverso viene rifiutata: il contratto e' esplicito, non si indovina.
PROTOCOL_VERSION = 1

#: Timeout complessivo del comando SSH (connessione + risposta del wrapper).
#: La connessione ha il suo ConnectTimeout=10; questo copre l'intera chiamata.
SSH_TIMEOUT_S = 30


class TrasportoSshFallito(RuntimeError):
    """Il trasporto SSH non ha prodotto una risposta utilizzabile: ssh non
    avviabile, nessun envelope su stdout, o timeout. Non e'
    ``EsecuzioneLiveNonDisponibile`` (che il runner tratta come *saltato*): e'
    un **guasto**, che il runner traduce in check FALLITO. Mai un finto esito."""

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

    def riga_grezza(self, verbo: str) -> str:
        """Invia un verbo e restituisce la **riga grezza** dell'envelope, senza
        parsarla. Serve a chi deve riunire piu' risposte e passarle a un parser
        gia' esistente (il collector ``system``), senza farle due volte il
        giro envelope->oggetto.

        Rifiuta un verbo non ammesso prima di aprire la connessione: il client
        non spedisce stringhe che il contratto non prevede."""
        if verbo not in VERBI:
            raise ValueError(f"verbo non ammesso dal protocollo: {verbo!r}")
        return self._invia(verbo)

    def esegui(self, verbo: str) -> Envelope:
        """Invia un verbo e restituisce l'envelope validato."""
        return leggi_envelope(self.riga_grezza(verbo))

    def _argv(self, verbo: str) -> list[str]:
        """Costruisce l'argv di ``ssh``. Il verbo e' un SINGOLO argomento, non
        una riga di shell: nessuna possibilita' di injection, e il ForceCommand
        sul server lo confronta comunque per uguaglianza esatta."""
        cfg = self._config
        return [
            "ssh",
            "-i", cfg.key_path,
            "-o", "BatchMode=yes",            # mai prompt interattivi
            "-o", "IdentitiesOnly=yes",       # solo la chiave data, non l'agent
            "-o", "StrictHostKeyChecking=yes",  # host sconosciuto -> rifiuta
            "-o", f"UserKnownHostsFile={cfg.known_hosts_path}",
            "-o", "ConnectTimeout=10",
            f"{cfg.user}@{cfg.host}",
            verbo,
        ]

    def _invia(self, verbo: str) -> str:
        """UNICO punto di I/O: apre la connessione SSH, invia il verbo come
        ``SSH_ORIGINAL_COMMAND`` e restituisce la **prima riga non vuota** di
        stdout (l'envelope).

        Un ssh non avviabile, uno stdout senza alcuna riga, o un timeout sono
        **guasti**: si solleva ``TrasportoSshFallito`` (che il runner traduce in
        FALLITO), mai un finto esito. Se invece il server ha risposto con un
        envelope (anche di errore, su exit non-zero), quella riga viene
        restituita: a giudicarla e' ``leggi_envelope``, non il trasporto."""
        argv = self._argv(verbo)
        try:
            esito = subprocess.run(
                argv, capture_output=True, text=True,
                timeout=SSH_TIMEOUT_S, check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise TrasportoSshFallito(
                f"timeout SSH verso {self.destinazione} ({verbo})"
            ) from exc
        except OSError as exc:  # ssh assente, ecc.
            raise TrasportoSshFallito(
                f"impossibile avviare ssh verso {self.destinazione}: {exc}"
            ) from exc

        for riga in esito.stdout.splitlines():
            if riga.strip():
                return riga

        raise TrasportoSshFallito(
            f"nessun envelope da {self.destinazione} ({verbo}): "
            f"exit {esito.returncode}, stderr: {esito.stderr.strip()[:200]!r}"
        )


__all__ = [
    "Envelope",
    "EsecuzioneLiveNonDisponibile",
    "PROTOCOL_VERSION",
    "ProtocolloNonValido",
    "SSH_TIMEOUT_S",
    "TrasportoSshFallito",
    "VERBI",
    "WrapperSsh",
    "leggi_envelope",
]
