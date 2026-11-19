"""Scope guard: egress self-check fail-closed e validazione del target.

Due livelli, e il livello che conta e' la rete (spec §5). Questo modulo e'
il **secondo** livello — la tripwire in profondita' — non il primo:

* **Enforcement (autorevole):** lo scanner gira su una rete docker
  ``internal: true`` che raggiunge solo ``app`` e ``db``. Ogni altra uscita e'
  bloccata al confine, da una regola di rete, non da un ``if`` di questo file.
  La garanzia vive li'.
* **Tripwire (questo modulo):** prima di ogni scansione il tool prova a
  raggiungere sentinelle esterne. Se **anche una sola** risponde, la rete non
  e' confinata come dovrebbe: il tool **rifiuta di partire**. Non dimostra che
  ogni uscita sia chiusa — dimostra che una rete mal configurata viene colta e
  fa fallire in sicurezza.

La sonda e' iniettabile (parametro ``sonda``) perche' il controllo dev'essere
testabile senza rete reale: i test passano una sonda finta che simula egress
aperto o chiuso. In esercizio la sonda di default apre socket TCP veri.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable, Iterable
from urllib.parse import urlsplit

#: Sentinelle esterne di default. Indirizzi pubblici notoriamente raggiungibili
#: se c'e' egress: se una risponde, la rete non e' confinata. Sono un default;
#: ``scope.toml`` puo' ampliarle.
SENTINELLE_DEFAULT: tuple[tuple[str, int], ...] = (
    ("1.1.1.1", 53),
    ("8.8.8.8", 443),
    ("1.1.1.1", 443),
)

#: Firma della sonda: (host, porta, timeout) -> raggiungibile?
Sonda = Callable[[str, int, float], bool]


class EgressAperto(Exception):
    """Una sentinella esterna e' risultata raggiungibile: la rete non e'
    confinata. Fail-closed: il run non parte."""


class TargetFuoriPerimetro(Exception):
    """Il target non e' un host ammesso: non e' in allowlist, o e' un
    indirizzo pubblico. Il run non parte."""


def _sonda_socket(host: str, porta: int, timeout: float) -> bool:
    """Sonda reale: vero se si riesce ad aprire un socket TCP.

    ``OSError`` (rifiutato, irraggiungibile, timeout) significa *non
    raggiungibile*: e' il caso normale su una rete confinata. Qualunque altra
    eccezione non viene mascherata — sarebbe un bug della sonda, non una
    risposta della rete."""
    try:
        with socket.create_connection((host, porta), timeout=timeout):
            return True
    except OSError:
        return False


def egress_self_check(
    sentinelle: Iterable[tuple[str, int]] = SENTINELLE_DEFAULT,
    *,
    sonda: Sonda = _sonda_socket,
    timeout: float = 2.0,
) -> list[tuple[str, int]]:
    """Esegue il self-check. Se **almeno una** sentinella e' raggiungibile,
    solleva ``EgressAperto``. Altrimenti restituisce la lista (vuota) delle
    raggiungibili, cioe' nessuna, e il run puo' procedere.

    Restituire la lista invece di ``None`` serve ai test e ai metadati: si puo'
    registrare *quali* sentinelle sono state provate e che nessuna ha
    risposto."""
    raggiungibili = [
        (host, porta) for host, porta in sentinelle if sonda(host, porta, timeout)
    ]
    if raggiungibili:
        elenco = ", ".join(f"{h}:{p}" for h, p in raggiungibili)
        raise EgressAperto(
            f"egress NON confinato: raggiungibili {elenco}. "
            "La rete dello scanner deve essere internal:true; il run non parte."
        )
    return raggiungibili


def valida_target(base_url: str, allowlist: Iterable[str]) -> str:
    """Valida il target contro l'allowlist, **senza risoluzione DNS esterna**.

    Il controllo e' sul nome letterale, non sull'indirizzo a cui risolve: un
    nome risolto adesso potrebbe puntare altrove al momento dell'esecuzione —
    e' la stessa ragione per cui il perimetro del pannello non fa DNS sugli
    alias. Restituisce l'host validato (il "pin" che il runner passa ai
    collector).

    Rifiuta: schema non http(s); host assente; indirizzo IP pubblico; host non
    presente in allowlist.
    """
    ammessi = set(allowlist)
    parti = urlsplit(base_url)
    if parti.scheme not in ("http", "https"):
        raise TargetFuoriPerimetro(
            f"schema non ammesso: {parti.scheme!r} (solo http/https)"
        )
    host = parti.hostname
    if not host:
        raise TargetFuoriPerimetro(f"nessun host in {base_url!r}")

    # Se e' un indirizzo IP letterale, un IP pubblico e' rifiutato a priori:
    # nessun perimetro lecito punta a Internet. Un IP privato e' ammesso solo
    # se e' esplicitamente in allowlist (come un nome qualsiasi).
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None and ip.is_global:
        raise TargetFuoriPerimetro(f"indirizzo pubblico non ammesso: {host}")

    if host not in ammessi:
        elenco = ", ".join(sorted(ammessi)) or "(vuota)"
        raise TargetFuoriPerimetro(
            f"host {host!r} non in allowlist [{elenco}]: fuori perimetro"
        )
    return host


__all__ = [
    "EgressAperto",
    "SENTINELLE_DEFAULT",
    "Sonda",
    "TargetFuoriPerimetro",
    "egress_self_check",
    "valida_target",
]
