"""Collector interno: pip-audit sul ``requirements.txt`` recuperato.

L'input autorevole e' **``requirements.txt``** (il lock del repo, pin esatti),
preso dal sorgente esportato via ``source.export`` — non "requirements.lock",
che nel repo non esiste. Opzionalmente il ``pyproject.toml`` (anch'esso nel
pacchetto esportato) serve da confronto sulle dipendenze dirette, ma l'input su
cui pip-audit gira e' ``requirements.txt``.

Flusso live (come semgrep):

1. ``source.export`` → envelope SRC-01;
2. ``source_ingest`` → estrazione sicura (sha, cap, solo regolari, no traversal);
3. ``pip-audit --format json -r requirements.txt`` sul file estratto;
4. provenienza nei metadati; temp dir rimossa.

Export/integrita'/estrazione falliti (``IngestFallito``) → check **FALLITO**,
mai un falso "nessuna CVE". ``parse`` (JSON di pip-audit) e' implementato e
testato.
"""

from __future__ import annotations

import json
from pathlib import Path

from assess.collectors.base import (
    CollectorBase,
    EsecuzioneLiveNonDisponibile,
    RunContext,
    raw_completato,
    raw_fallito,
    raw_vuoto,
)
from assess.model import RawResult, Scope, Source

SORGENTE_ESTRATTO = "<sorgente-estratto>"


class PipAuditCollector(CollectorBase):
    name = "pip-audit"
    source = Source.PIP_AUDIT
    scope = Scope.INTERNAL
    requires = frozenset({"ssh"})
    comando = "source.export -> pip-audit --format json -r <sorgente>/requirements.txt"

    def comando_su(self, radice: Path) -> list[str]:
        """Comando pip-audit sul requirements.txt estratto."""
        return ["pip-audit", "--format", "json", "-r", str(radice / "requirements.txt")]

    def costruisci_comando(self, ctx: RunContext) -> list[str]:
        return self.comando_su(Path(SORGENTE_ESTRATTO))

    def parse(self, grezzo: str) -> RawResult:
        try:
            dati = json.loads(grezzo)
        except json.JSONDecodeError as exc:
            return raw_fallito(
                self.source, self.comando, f"output pip-audit non JSON: {exc}"
            )
        if isinstance(dati, dict) and "dependencies" in dati:
            dipendenze = dati["dependencies"]
        elif isinstance(dati, list):
            dipendenze = dati
        else:
            return raw_fallito(
                self.source, self.comando,
                "output pip-audit malformato: ne' {'dependencies': [...]} ne' lista.",
            )
        con_vuln = [d for d in dipendenze if d.get("vulns")]
        if con_vuln:
            return raw_completato(self.source, self.comando, con_vuln)
        return raw_vuoto(
            self.source, self.comando,
            f"nessuna CVE nota sulle {len(dipendenze)} dipendenze di requirements.txt "
            "(controllo positivo).",
        )

    def _esegui_live(self, ctx: RunContext) -> str:
        raise EsecuzioneLiveNonDisponibile(
            "pip-audit live non disponibile nello scaffold; flusso: source.export "
            "-> ingest sicuro -> " + " ".join(self.comando_su(Path(SORGENTE_ESTRATTO)))
        )


__all__ = ["PipAuditCollector", "SORGENTE_ESTRATTO"]
