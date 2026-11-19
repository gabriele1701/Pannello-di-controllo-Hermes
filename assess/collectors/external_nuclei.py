"""Collector esterno: nuclei (template offline).

Comando reale:

    nuclei -silent -jsonl -no-color -disable-update-check \\
           -t templates_nuclei/ \\
           -H "Cookie: hermes_session=<cookie di sessione>" \\
           -u <base_url><path> ...   # un -u per endpoint dal contratto

* Template **offline** versionati in ``templates_nuclei/``, nessun auto-update
  durante lo scan (``-disable-update-check``).
* Cookie di sessione iniettato. Nel comando compare un **segnaposto**
  (``${ASSESS_SESSION}``), mai il valore: il filo che lo sostituisce col cookie
  reale e' l'I/O live (``_esegui_live``), e il segreto non finisce nei log.
* Gli URL sono costruiti dall'inventario di ``openapi.json``, non da una lista
  a mano.

L'output e' JSONL: una riga JSON per match, con ``template-id``, ``info``
(``name``, ``severity``, ``classification``), ``matched-at``.
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

#: Segnaposto del cookie nel comando. Lo sostituisce l'I/O live, non il testo.
SEGNAPOSTO_SESSIONE = "${ASSESS_SESSION}"


class NucleiCollector(CollectorBase):
    name = "nuclei"
    source = Source.NUCLEI
    scope = Scope.EXTERNAL
    requires = frozenset({"target"})
    comando = (
        "nuclei -silent -jsonl -no-color -disable-update-check -t templates_nuclei/ "
        '-H "Cookie: hermes_session=***" -u <base_url><path> ...'
    )

    def _url_da_scansionare(self, ctx: RunContext) -> list[str]:
        base = (ctx.base_url or "").rstrip("/")
        visti: list[str] = []
        for e in ctx.inventario:
            url = f"{base}{e.path}"
            if url not in visti:
                visti.append(url)
        return visti

    def costruisci_comando(self, ctx: RunContext) -> list[str]:
        argv = [
            "nuclei", "-silent", "-jsonl", "-no-color", "-disable-update-check",
            "-t", "templates_nuclei/",
            "-H", f"Cookie: hermes_session={SEGNAPOSTO_SESSIONE}",
        ]
        for url in self._url_da_scansionare(ctx):
            argv += ["-u", url]
        return argv

    def parse(self, grezzo: str) -> RawResult:
        righe = [r for r in grezzo.splitlines() if r.strip()]
        if not righe:
            return raw_vuoto(
                self.source, self.comando,
                "nuclei non ha prodotto match: nessuna segnalazione dai template "
                "offline sugli endpoint autorizzati (controllo positivo).",
            )
        elementi: list[dict] = []
        for riga in righe:
            try:
                oggetto = json.loads(riga)
            except json.JSONDecodeError as exc:
                return raw_fallito(
                    self.source, self.comando,
                    f"output nuclei malformato (riga non JSON): {exc}",
                )
            if not isinstance(oggetto, dict):
                return raw_fallito(
                    self.source, self.comando,
                    "output nuclei malformato: una riga non e' un oggetto JSON.",
                )
            elementi.append(oggetto)
        return raw_completato(self.source, self.comando, elementi)

    def _esegui_live(self, ctx: RunContext) -> str:
        raise EsecuzioneLiveNonDisponibile(
            "nuclei live non disponibile nello scaffold; comando: "
            + " ".join(self.costruisci_comando(ctx))
        )


__all__ = ["NucleiCollector", "SEGNAPOSTO_SESSIONE"]
