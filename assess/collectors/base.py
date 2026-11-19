"""Interfaccia dei collector e contesto di run.

Un collector dichiara **cosa gli serve** (``requires``) e **da che lato
guarda** (``scope``), ed espone un ``run(ctx)`` che restituisce un
``RawResult``. Il runner usa ``requires`` per decidere se puo' eseguirlo: un
collector che chiede ``ssh`` non parte se il run non ha un canale SSH, e il suo
check risulta *saltato* — non *superato*.

Tre responsabilita' separate
----------------------------

Un collector fa tre cose, e sono tenute distinte perche' due di esse si possono
testare **adesso**, senza target ne' VM:

* ``costruisci_comando(ctx)`` — costruisce il comando/le query reali. Pura,
  deterministica, testabile.
* ``parse(grezzo)`` — trasforma l'output grezzo del tool in un ``RawResult``.
  Pura, testabile su fixture.
* ``_esegui_live(ctx)`` — l'**unico** punto di I/O (subprocess, SSH, psycopg).
  E' l'unico stub: nello scaffold solleva ``EsecuzioneLiveNonDisponibile``.

``run`` le mette in fila: ``parse(_esegui_live(ctx))``. Cosi' la logica che
conta — costruire il comando giusto e interpretare l'output con onesta' — e'
implementata e coperta, e manca solo il filo che la collega al processo reale.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Protocol, runtime_checkable

from assess.config import ConfigScope
from assess.inventory.openapi_endpoints import Endpoint
from assess.model import EsitoCheck, RawResult, Scope, Source

#: Risorse che un collector puo' richiedere. Il runner le confronta con quelle
#: effettivamente disponibili nel contesto.
Risorsa = Literal["target", "ssh", "db"]


class EsecuzioneLiveNonDisponibile(NotImplementedError):
    """L'I/O live non e' disponibile in questo scaffold.

    E' sollevata **solo** da ``_esegui_live``: la costruzione del comando e il
    parsing sono implementati. Il runner la traduce in un check **saltato** con
    motivo esplicito, distinto da un check *fallito* (errore imprevisto) e da
    uno *saltato per requisiti non soddisfatti* (manca ssh/db/target). Tre modi
    diversi di non aver eseguito, tenuti distinti perche' dicono cose diverse."""


# --------------------------------------------------------------------------- #
# Costruttori di RawResult per i tre esiti canonici di un parse.
#
# Li usano tutti i parser, perche' la distinzione completato-a-zero / fallito
# e' l'invariante di onesta' e non va riscritta a mano in sei posti con sei
# sfumature diverse.
# --------------------------------------------------------------------------- #


def raw_completato(
    source: Source, comando: str, elementi: list[dict[str, Any]], nota: str = ""
) -> RawResult:
    """Check eseguito con risultati."""
    return RawResult(
        source=source, esito=EsitoCheck.COMPLETATO, comando=comando,
        elementi=elementi, nota=nota,
    )


def raw_vuoto(source: Source, comando: str, nota: str) -> RawResult:
    """Check eseguito a **zero** risultati: completato, nessun elemento, con la
    nota di controllo positivo. Non e' un fallimento, ed e' il punto in cui un
    esito negativo onesto si distingue da un errore mascherato da vuoto."""
    return RawResult(
        source=source, esito=EsitoCheck.COMPLETATO, comando=comando, nota=nota,
    )


def raw_fallito(source: Source, comando: str, nota: str) -> RawResult:
    """Check **fallito**: output malformato, sessione non valida, condizione
    imprevista. Esito esplicito, mai un falso vuoto."""
    return RawResult(
        source=source, esito=EsitoCheck.FALLITO, comando=comando, nota=nota,
    )


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

    Le sottoclassi dichiarano ``name``, ``source``, ``scope``, ``requires``,
    ``comando`` (documentazione leggibile) e implementano i tre metodi:
    ``costruisci_comando``, ``parse`` e ``_esegui_live``. ``run`` e' concreto e
    li orchestra.
    """

    name: str
    source: Source
    scope: Scope
    requires: frozenset[Risorsa] = frozenset()
    #: Il comando reale, come stringa leggibile. Finisce nel ``RawResult`` come
    #: documentazione ed evidenza di cosa il collector esegue.
    comando: str = ""

    @abstractmethod
    def costruisci_comando(self, ctx: RunContext) -> list[str]:
        """Costruisce il comando reale (argv) da eseguire. Puro e testabile."""

    @abstractmethod
    def parse(self, grezzo: str) -> RawResult:
        """Trasforma l'output grezzo del tool in un ``RawResult``.

        Deve gestire, con un esito esplicito per ciascuno: risultati presenti
        (``COMPLETATO`` con elementi), zero risultati (``COMPLETATO`` a zero,
        nota di controllo positivo), output malformato o condizione non valida
        (``FALLITO``, mai un falso vuoto)."""

    @abstractmethod
    def _esegui_live(self, ctx: RunContext) -> str:
        """UNICO punto di I/O: esegue il comando e restituisce l'output grezzo.

        Nello scaffold non e' implementato: solleva
        ``EsecuzioneLiveNonDisponibile``. E' l'unico filo che manca."""

    def run(self, ctx: RunContext) -> RawResult:
        """Esegue il collector: I/O live, poi parsing dell'output."""
        return self.parse(self._esegui_live(ctx))


__all__ = [
    "Collector",
    "CollectorBase",
    "EsecuzioneLiveNonDisponibile",
    "Risorsa",
    "RunContext",
    "raw_completato",
    "raw_fallito",
    "raw_vuoto",
]
