"""Interfaccia dei collector e contesto di run.

Un collector dichiara **cosa gli serve** (``requires``) e **da che lato
guarda** (``scope``), ed espone un ``run(ctx)`` che restituisce un
``RawResult``. Il runner usa ``requires`` per decidere se puo' eseguirlo: un
collector che chiede ``ssh`` non parte se il run non ha un canale SSH, e il suo
check risulta *saltato* — non *superato*.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Protocol, runtime_checkable

from assess.config import ConfigScope
from assess.inventory.openapi_endpoints import Endpoint
from assess.model import RawResult, Scope, Source

#: Risorse che un collector puo' richiedere. Il runner le confronta con quelle
#: effettivamente disponibili nel contesto.
Risorsa = Literal["target", "ssh", "db"]


class EsecuzioneLiveNonDisponibile(NotImplementedError):
    """Lo stub non ha un'implementazione live in questo scaffold.

    Il runner la traduce in un check **saltato** con motivo esplicito, distinto
    da un check *fallito* (che e' un errore imprevisto) e da uno *saltato per
    requisiti non soddisfatti* (manca ssh/db/target). Tre modi diversi di non
    aver eseguito, tenuti distinti perche' dicono cose diverse."""


@dataclass(slots=True)
class RunContext:
    """Tutto cio' che un collector puo' usare durante un run.

    Nello scaffold indipendente dal target ``http``, ``ssh`` e ``db`` sono
    ``None``: senza VM non esiste un canale verso il target. I collector che li
    richiedono vengono percio' saltati, ed e' corretto cosi'.
    """

    config: ConfigScope
    repo_root: Path
    #: Host del target, gia' validato da ``scope.valida_target`` (il "pin").
    #: ``None`` se non c'e' un target raggiungibile in questo run.
    target: str | None = None
    base_url: str | None = None
    #: Inventario degli endpoint dal contratto, per i collector esterni.
    inventario: Sequence[Endpoint] = field(default_factory=tuple)
    #: Sessione HTTP autenticata (cookie). ``Any`` per non legare lo scaffold a
    #: una libreria client finche' non serve davvero.
    http: Any | None = None
    #: Wrapper SSH ristretto. Interfaccia del tool, non il controllo di
    #: sicurezza (quello sta sul server).
    ssh: Any | None = None
    #: Connessione DB in sola lettura (ruolo ``hermes_assess``).
    db: Any | None = None
    #: Commit del pannello bersaglio, per i metadati del run.
    commit_pannello: str | None = None

    def ha(self, risorsa: Risorsa) -> bool:
        """Vero se la risorsa richiesta e' presente in questo contesto."""
        if risorsa == "target":
            return self.target is not None and self.http is not None
        if risorsa == "ssh":
            return self.ssh is not None
        if risorsa == "db":
            return self.db is not None
        return False

    def risorse_mancanti(self, requires: Sequence[Risorsa]) -> list[Risorsa]:
        """Le risorse richieste che questo contesto non ha."""
        return [r for r in requires if not self.ha(r)]


@runtime_checkable
class Collector(Protocol):
    """Interfaccia di un collector. Un oggetto che la soddisfa ha un nome, uno
    scope, le risorse richieste e un ``run``."""

    name: str
    scope: Scope
    source: Source
    requires: frozenset[Risorsa]

    def run(self, ctx: RunContext) -> RawResult: ...


class CollectorBase(ABC):
    """Base comune ai collector concreti.

    Sottoclassi dichiarano gli attributi di classe ``name``, ``source``,
    ``scope``, ``requires``, ``comando`` e implementano ``run``. ``comando`` e'
    il comando reale che il collector esegue (o, nello stub, eseguirebbe): e'
    insieme documentazione e evidenza, e finisce nel ``RawResult``.
    """

    name: str
    source: Source
    scope: Scope
    requires: frozenset[Risorsa] = frozenset()
    #: Il comando reale, come stringa leggibile. Negli stub documenta cosa fara'
    #: l'implementazione live.
    comando: str = ""

    @abstractmethod
    def run(self, ctx: RunContext) -> RawResult:
        """Esegue il collector e restituisce il risultato grezzo."""
        raise NotImplementedError


__all__ = [
    "Collector",
    "CollectorBase",
    "EsecuzioneLiveNonDisponibile",
    "Risorsa",
    "RunContext",
]
