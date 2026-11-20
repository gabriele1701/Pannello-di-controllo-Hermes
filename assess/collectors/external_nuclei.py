"""Collector esterno: Nuclei con template locali e sessione autenticata.

Gli URL provengono esclusivamente dall'inventario OpenAPI del target validato.
I template sono versionati nel repository e copiati nell'immagine scanner:
nessun aggiornamento o download durante il run.
"""
from __future__ import annotations

import json
import shutil
import subprocess

from assess.collectors.base import (
    CollectorBase,
    RunContext,
    raw_completato,
    raw_fallito,
    raw_vuoto,
)
from assess.model import RawResult, Scope, Source


class NucleiCollector(CollectorBase):
    name = "nuclei"
    source = Source.NUCLEI
    scope = Scope.EXTERNAL
    requires = frozenset({"target"})
    timeout_s = 600
    comando = (
        "nuclei -silent -jsonl -no-color -disable-update-check "
        "-t templates_nuclei/ -H 'Cookie: hermes_session=***' "
        "-u <endpoint-openapi> ..."
    )

    def _url_da_scansionare(self, ctx: RunContext) -> list[str]:
        base = (ctx.base_url or "").rstrip("/")
        visti: list[str] = []
        for endpoint in ctx.inventario:
            url = f"{base}{endpoint.path}"
            if url not in visti:
                visti.append(url)
        return visti

    def costruisci_comando(self, ctx: RunContext) -> list[str]:
        argv = [
            "nuclei", "-silent", "-jsonl", "-no-color",
            "-disable-update-check", "-duc", "-disable-redirects",
            "-t", str(ctx.repo_root / "templates_nuclei"),
        ]
        if ctx.http:
            argv += ["-H", f"Cookie: hermes_session={ctx.http}"]
        for url in self._url_da_scansionare(ctx):
            argv += ["-u", url]
        return argv

    def parse(self, grezzo: str) -> RawResult:
        righe = [r for r in grezzo.splitlines() if r.strip()]
        if not righe:
            return raw_vuoto(
                self.source, self.comando,
                "Nessun match nei template locali sugli endpoint autorizzati. "
                "Esito limitato ai controlli effettivamente eseguiti.",
            )
        elementi: list[dict] = []
        for riga in righe:
            try:
                oggetto = json.loads(riga)
            except json.JSONDecodeError as exc:
                return raw_fallito(
                    self.source, self.comando,
                    f"output Nuclei malformato (riga non JSON): {exc}",
                )
            if not isinstance(oggetto, dict):
                return raw_fallito(
                    self.source, self.comando,
                    "output Nuclei malformato: una riga non e' un oggetto JSON.",
                )
            elementi.append(oggetto)
        return raw_completato(self.source, self.comando, elementi)

    def _esegui_live(self, ctx: RunContext) -> str:
        eseguibile = shutil.which("nuclei")
        if not eseguibile:
            raise RuntimeError("binario nuclei non trovato nel container scanner")
        templates = ctx.repo_root / "templates_nuclei"
        if not templates.is_dir() or not any(templates.rglob("*.yaml")):
            raise RuntimeError("directory templates_nuclei assente o senza template YAML")
        urls = self._url_da_scansionare(ctx)
        if not urls:
            raise RuntimeError("inventario OpenAPI vuoto: scansione non avviata")
        argv = self.costruisci_comando(ctx)
        argv[0] = eseguibile
        try:
            risultato = subprocess.run(
                argv, cwd=ctx.repo_root, capture_output=True, text=True,
                timeout=self.timeout_s, check=False,
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError(
                f"Nuclei ha superato il timeout di {self.timeout_s}s"
            ) from None
        except OSError as exc:
            raise RuntimeError(
                f"impossibile avviare Nuclei ({type(exc).__name__})"
            ) from None
        if risultato.returncode != 0:
            dettaglio = risultato.stderr.strip().splitlines()
            messaggio = dettaglio[-1][:300] if dettaglio else "errore senza dettagli"
            raise RuntimeError(
                f"Nuclei terminato con exit code {risultato.returncode}: {messaggio}"
            )
        return risultato.stdout


__all__ = ["NucleiCollector"]
