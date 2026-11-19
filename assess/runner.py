"""Runner: esegue i collector in modo indipendente e raccoglie i metadati.

Sequenza di un run:

1. **egress self-check** (scope guard). Se la rete non e' confinata, il run non
   parte affatto — e' la prima cosa, prima di qualunque collector.
2. **pin del target**: ogni collector riceve solo il target validato.
3. **collector, uno per uno e indipendenti**. Il fallimento o il salto di uno
   non ferma gli altri: diventa una voce nei metadati. Tre esiti distinti —
   *completato*, *saltato* (requisiti non soddisfatti, o implementazione live
   assente nello scaffold), *fallito* (errore imprevisto) — perche' dicono
   cose diverse e vanno mostrati, non fusi.
4. **normalizzazione** dei soli check completati in ``Finding``.
5. **metadati**: timestamp, versione tool, commit del pannello, versioni dei
   tool, elenco check {completati, saltati, falliti}, limitazioni note, hash
   della config di scope.

Onesta': un check che non e' stato eseguito non sparisce e non diventa verde.
Resta nei metadati con il suo motivo, e il report lo mostra in evidenza.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from assess import __version__
from assess.collectors.base import (
    Collector,
    EsecuzioneLiveNonDisponibile,
    RunContext,
)
from assess.config import ConfigScope
from assess.model import EsitoCheck, Finding, RawResult, Source
from assess.normalize import normalizza
from assess.scope import SENTINELLE_DEFAULT, Sonda, _sonda_socket, egress_self_check

#: Versioni pinnate attese dei tool (coerenti col Dockerfile). Nello scaffold i
#: tool non vengono eseguiti: sono le versioni che l'immagine installera', non
#: quelle osservate a runtime. La differenza e' dichiarata nelle limitazioni.
PIN_TOOL: dict[str, str] = {
    "nuclei": "3.3.7",
    "sqlmap": "1.8.11",
    "semgrep": "1.97.0",
    "pip-audit": "2.7.3",
}


@dataclass(slots=True)
class CheckEsito:
    """Esito di un collector nel run, per i metadati."""

    name: str
    source: Source
    esito: EsitoCheck
    comando: str
    nota: str = ""

    def to_json(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "source": self.source.value,
            "esito": self.esito.value,
            "comando": self.comando,
            "nota": self.nota,
        }


@dataclass(slots=True)
class MetadatiRun:
    """Metadati di un run (spec §7)."""

    timestamp: str
    tool_version: str
    commit_pannello: str | None
    versioni_tool: dict[str, str]
    scope_hash: str
    checks: list[CheckEsito] = field(default_factory=list)
    limitazioni: list[str] = field(default_factory=list)
    sentinelle_egress: list[str] = field(default_factory=list)

    def _per_esito(self, esito: EsitoCheck) -> list[str]:
        return [c.name for c in self.checks if c.esito is esito]

    def to_json(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "tool_version": self.tool_version,
            "commit_pannello": self.commit_pannello,
            "versioni_tool": self.versioni_tool,
            "scope_hash": self.scope_hash,
            "checks": {
                "completati": self._per_esito(EsitoCheck.COMPLETATO),
                "saltati": self._per_esito(EsitoCheck.SALTATO),
                "falliti": self._per_esito(EsitoCheck.FALLITO),
                "dettaglio": [c.to_json() for c in self.checks],
            },
            "limitazioni": self.limitazioni,
            "sentinelle_egress": self.sentinelle_egress,
        }


@dataclass(slots=True)
class Esecuzione:
    """Risultato completo di un run: metadati + finding + grezzi."""

    metadati: MetadatiRun
    findings: list[Finding]
    raws: list[RawResult]

    def to_json(self) -> dict[str, Any]:
        return {
            "meta": self.metadati.to_json(),
            "findings": [f.to_json() for f in self.findings],
        }


def hash_config(config: ConfigScope) -> str:
    """Hash deterministico della config di scope (senza segreti: non ce ne
    sono nel toml). Serializza i campi rilevanti in JSON ordinato e ne fa lo
    sha256, cosi' due run sullo stesso perimetro hanno lo stesso hash."""
    canonico = {
        "base_url": config.target.base_url,
        "allowlist": sorted(config.target.allowlist),
        "sentinelle": sorted(f"{h}:{p}" for h, p in config.egress.sentinelle),
        "db_dsn_env": config.db.dsn_env,
        "ssh": f"{config.ssh.user}@{config.ssh.host}:{config.ssh.port}",
    }
    grezzo = json.dumps(canonico, sort_keys=True, ensure_ascii=False)
    return "sha256:" + hashlib.sha256(grezzo.encode("utf-8")).hexdigest()


def _esegui_collector(coll: Collector, ctx: RunContext) -> tuple[CheckEsito, RawResult | None]:
    """Esegue un singolo collector, catturando tutto. Non solleva: qualunque
    esito e' una ``CheckEsito`` + eventualmente un ``RawResult``."""
    comando = getattr(coll, "comando", "")
    mancanti = ctx.risorse_mancanti(sorted(coll.requires))
    if mancanti:
        nota = "requisiti non soddisfatti: " + ", ".join(mancanti)
        return CheckEsito(coll.name, coll.source, EsitoCheck.SALTATO, comando, nota), None
    try:
        raw = coll.run(ctx)
    except EsecuzioneLiveNonDisponibile as exc:
        return (
            CheckEsito(coll.name, coll.source, EsitoCheck.SALTATO, comando, str(exc)),
            None,
        )
    except Exception as exc:  # noqa: BLE001 — un collector non deve abortire il run
        nota = f"{type(exc).__name__}: {exc}"
        return CheckEsito(coll.name, coll.source, EsitoCheck.FALLITO, comando, nota), None
    return (
        CheckEsito(coll.name, coll.source, raw.esito, comando, raw.nota),
        raw,
    )


def esegui_run(
    ctx: RunContext,
    collectors: Sequence[Collector],
    *,
    sonda_egress: Sonda = _sonda_socket,
    sentinelle: Iterable[tuple[str, int]] | None = None,
    salta_egress: bool = False,
    adesso: dt.datetime | None = None,
) -> Esecuzione:
    """Esegue un run completo. Solleva ``EgressAperto`` se il self-check fallisce
    (il run non parte). ``salta_egress`` e ``sonda_egress`` esistono per i test;
    in esercizio l'egress-check e' sempre attivo con la sonda reale."""
    sentinelle_run = tuple(sentinelle) if sentinelle is not None else ctx.config.egress.sentinelle or SENTINELLE_DEFAULT

    if not salta_egress:
        # Solleva EgressAperto se qualcosa risponde: il run non parte.
        egress_self_check(
            sentinelle_run, sonda=sonda_egress, timeout=ctx.config.egress.timeout_s
        )

    checks: list[CheckEsito] = []
    raws: list[RawResult] = []
    for coll in collectors:
        esito, raw = _esegui_collector(coll, ctx)
        checks.append(esito)
        if raw is not None:
            raws.append(raw)

    findings = normalizza(raws)

    limitazioni: list[str] = []
    for c in checks:
        if c.esito is EsitoCheck.SALTATO:
            limitazioni.append(f"{c.name}: saltato — {c.nota}")
        elif c.esito is EsitoCheck.FALLITO:
            limitazioni.append(f"{c.name}: FALLITO — {c.nota}")
    if not any(c.esito is EsitoCheck.COMPLETATO for c in checks):
        limitazioni.append(
            "Nessun collector eseguito dal vivo: scaffold indipendente dal "
            "target, l'esecuzione confinata richiede l'ambiente VM."
        )

    metadati = MetadatiRun(
        timestamp=(adesso or dt.datetime.now(dt.timezone.utc)).isoformat(),
        tool_version=__version__,
        commit_pannello=ctx.commit_pannello,
        versioni_tool=dict(PIN_TOOL),
        scope_hash=hash_config(ctx.config),
        checks=checks,
        limitazioni=limitazioni,
        sentinelle_egress=[f"{h}:{p}" for h, p in sentinelle_run],
    )
    return Esecuzione(metadati=metadati, findings=findings, raws=raws)


#: Ordine di esecuzione dei collector nel run, come mostrato dalla CLI (§9).
def collectors_standard() -> list[Collector]:
    """Istanzia i sei collector nell'ordine della spec."""
    from assess.collectors.external_nuclei import NucleiCollector
    from assess.collectors.external_sqlmap import SqlmapCollector
    from assess.collectors.internal_semgrep import SemgrepCollector
    from assess.collectors.internal_pipaudit import PipAuditCollector
    from assess.collectors.internal_db import DbCollector
    from assess.collectors.internal_system import SystemCollector

    return [
        NucleiCollector(),
        SqlmapCollector(),
        SemgrepCollector(),
        PipAuditCollector(),
        DbCollector(),
        SystemCollector(),
    ]


__all__ = [
    "CheckEsito",
    "Esecuzione",
    "MetadatiRun",
    "PIN_TOOL",
    "collectors_standard",
    "esegui_run",
    "hash_config",
]
