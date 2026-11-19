"""Collector interno: semgrep (analisi statica del sorgente).

Comando reale:

    semgrep scan --json --no-git-ignore \\
            --config p/python --config p/owasp-top-ten \\
            <repo>/backend

* Ruleset OWASP/Python **bundled** (offline).
* Sorgente ``backend/`` prelevato dalla macchina via SSH ristretto.
* Output JSON: ``results[]`` (``check_id``, ``path``, ``start.line``,
  ``extra.message``, ``extra.severity``, ``extra.metadata.cwe``) ed ``errors[]``.

``parse``: risultati presenti → ``COMPLETATO``; nessun risultato e nessun errore
→ ``COMPLETATO`` a zero (controllo positivo); nessun risultato ma con errori di
scansione → ``FALLITO`` (uno scan non riuscito non e' un "pulito"); JSON
malformato → ``FALLITO``.
"""

from __future__ import annotations

import json

from assess.collectors.base import (
    CollectorBase,
    EsecuzioneLiveNonDisponibile,
    RunContext,
    raw_completato,
    raw_fallito,
    raw_vuoto,
)
from assess.model import RawResult, Scope, Source


class SemgrepCollector(CollectorBase):
    name = "semgrep"
    source = Source.SEMGREP
    scope = Scope.INTERNAL
    requires = frozenset({"ssh"})
    comando = (
        "semgrep scan --json --no-git-ignore "
        "--config p/python --config p/owasp-top-ten backend/"
    )

    def costruisci_comando(self, ctx: RunContext) -> list[str]:
        sorgente = str(ctx.repo_root / "backend")
        return [
            "semgrep", "scan", "--json", "--no-git-ignore",
            "--config", "p/python", "--config", "p/owasp-top-ten",
            sorgente,
        ]

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
        raise EsecuzioneLiveNonDisponibile(
            "semgrep live non disponibile nello scaffold; comando: "
            + " ".join(self.costruisci_comando(ctx))
        )


__all__ = ["SemgrepCollector"]
