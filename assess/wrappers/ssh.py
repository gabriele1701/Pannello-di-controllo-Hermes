"""Interfaccia SSH del tool — **non** il controllo di sicurezza.

Va detto chiaro, perche' e' il rilievo del consulente recepito nella spec
(§4): un wrapper client-side decide solo *cosa il nostro tool invia*. Non
impedisce a chi possiede la chiave di aprire una shell o lanciare comandi
arbitrari. Il minimo privilegio reale richiede il **confine lato server**:

* account ``assess`` non privilegiato (niente sudo, niente gruppi extra);
* ``restrict`` nella riga di ``authorized_keys`` (niente forwarding, niente
  pty, niente user-rc);
* ``ForceCommand`` → uno script validatore sul server che legge
  ``$SSH_ORIGINAL_COMMAND``, lo confronta con un'allowlist di comandi
  read-only ed esegue solo i consentiti.

Quell'allowlist vive sul server, applicata da ``sshd``. La lista qui sotto e'
soltanto *l'insieme dei comandi che il tool chiede*: serve a documentare e a
far combaciare le due parti, non a garantire alcunche'. Se diverge da quella
del server, e' il server a rifiutare.

In questo scaffold ``esegui`` non apre connessioni: solleva
``EsecuzioneLiveNonDisponibile``. L'implementazione live (Paramiko o
``subprocess`` su ``ssh``) arriva con la VM.
"""

from __future__ import annotations

from assess.collectors.base import EsecuzioneLiveNonDisponibile
from assess.config import ConfigSsh

#: Comandi read-only che il tool invia. DEVE coincidere con l'allowlist del
#: ForceCommand lato server; qui e' documentazione, non enforcement.
COMANDI_DIAGNOSTICI: tuple[str, ...] = (
    "ss -tlnp",            # porte in ascolto
    "ps aux",              # processi
    "systemctl list-units --type=service --state=running",  # servizi attivi
    "docker ps --format '{{.Names}} {{.Status}} {{.Ports}}'",  # stato container
    "ls -la",              # permessi su percorsi sensibili (argomento pinnato)
    "cat",                 # lettura sorgente (percorso pinnato, read-only)
)


class WrapperSsh:
    """Interfaccia SSH del tool verso l'host della VM.

    Non e' un controllo di sicurezza (vedi il docstring del modulo). Tiene solo
    l'indirizzamento del canale e l'elenco dei comandi che il tool emette.
    """

    def __init__(self, config: ConfigSsh) -> None:
        self._config = config

    @property
    def destinazione(self) -> str:
        return f"{self._config.user}@{self._config.host}:{self._config.port}"

    def comando_ammesso(self, comando: str) -> bool:
        """Vero se il comando e' fra quelli che il tool invia. Non e' una
        garanzia: il rifiuto autorevole e' del ForceCommand sul server."""
        base = comando.strip().split()
        if not base:
            return False
        for ammesso in COMANDI_DIAGNOSTICI:
            if comando.strip() == ammesso or base[0] == ammesso.split()[0]:
                return True
        return False

    def esegui(self, comando: str) -> str:
        """Esegue un comando diagnostico via SSH e restituisce l'output.

        In questo scaffold non apre connessioni: l'implementazione live e' di
        competenza dell'ambiente VM. Solleva ``EsecuzioneLiveNonDisponibile``.
        """
        raise EsecuzioneLiveNonDisponibile(
            f"SSH live non disponibile nello scaffold ({self.destinazione}); "
            "comando: " + comando
        )


__all__ = ["COMANDI_DIAGNOSTICI", "WrapperSsh"]
