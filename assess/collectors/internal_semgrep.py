"""Collector interno: semgrep sul sorgente recuperato via ``source.export``.

Il sorgente non si legge "da qualche parte": arriva dal target con un canale
autenticato e verificato. Il flusso live e':

1. ``ctx.ssh.esegui("source.export")`` → envelope SRC-01 (tar.gz + sha);
2. ``source_ingest.sorgente_da_envelope`` → estrazione **sicura** in una temp
   dir (sha verificato, cap, solo file regolari, niente traversal);
3. ``semgrep scan --json`` sulla ``backend/`` estratta;
4. la **provenienza** dell'ingest finisce nei metadati del run;
5. la temp dir viene rimossa.

Se export, integrita' o estrazione falliscono (``IngestFallito``), il check e'
**FALLITO** — mai un falso "pulito": un sorgente che non e' arrivato integro non
e' un sorgente senza problemi.

Nello scaffold ``_esegui_live`` e' l'unico stub. ``parse`` (output JSON di
semgrep) e' implementato e testato come prima.
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

#: Segnaposto del percorso: la radice reale e' la temp dir dell'ingest, nota
#: solo a runtime dopo ``source.export``.
SORGENTE_ESTRATTO = "<sorgente-estratto>"


class SemgrepCollector(CollectorBase):
    name = "semgrep"
    source = Source.SEMGREP
    scope = Scope.INTERNAL
    requires = frozenset({"ssh"})
    comando = (
        "source.export -> semgrep scan --json --no-git-ignore "
        "--config p/python --config p/owasp-top-ten <sorgente>/backend"
    )

    def comando_su(self, radice: Path) -> list[str]:
        """Comando semgrep sulla radice estratta (``radice/backend``)."""
        return [
            "semgrep", "scan", "--json", "--no-git-ignore",
            "--config", "p/python", "--config", "p/owasp-top-ten",
            str(radice / "backend"),
        ]

    def costruisci_comando(self, ctx: RunContext) -> list[str]:
        # Il percorso reale e' la temp dir dell'ingest, nota solo a runtime.
        return self.comando_su(Path(SORGENTE_ESTRATTO))

    def parse(self, grezzo: str) -> RawResult:
        try:
            dati = json.loads(grezzo)
        except json.JSONDecodeError as exc:
            return raw_fallito(
                self.source, self.comando, f"output semgrep non JSON: {exc}"
            )
        if not isinstance(dati, dict) or "results" not in dati:
            return raw_fallito(
                self.source, self.comando,
                "output semgrep malformato: manca il campo 'results'.",
            )
        results = dati.get("results") or []
        errors = dati.get("errors") or []
        if results:
            return raw_completato(self.source, self.comando, list(results))
        if errors:
            return raw_fallito(
                self.source, self.comando,
                f"semgrep non ha trovato nulla ma riporta {len(errors)} errori di "
                "scansione: scan non riuscito, non un sorgente pulito.",
            )
        return raw_vuoto(
            self.source, self.comando,
            "semgrep non ha trovato nulla sul sorgente, senza errori di "
            "scansione (controllo positivo).",
        )

    def _esegui_live(self, ctx: RunContext) -> str:
        # Live: source.export -> ingest sicuro -> semgrep sulla backend/ estratta,
        # con la provenienza nei metadati e IngestFallito -> check FALLITO.
        raise EsecuzioneLiveNonDisponibile(
            "semgrep live non disponibile nello scaffold; flusso: source.export "
            "-> ingest sicuro -> " + " ".join(self.comando_su(Path(SORGENTE_ESTRATTO)))
        )


__all__ = ["SemgrepCollector", "SORGENTE_ESTRATTO"]
