"""Collector interno: system — via il protocollo a verbi del wrapper SSH.

Non piu' comandi shell: il collector invia i **verbi** del contratto
(``PROTOCOL.md``) attraverso il wrapper client (``assess/wrappers/ssh.py``) e
interpreta gli **envelope** JSON che tornano. Le attestazioni sulle porte
vengono dai campi **strutturati** di ``data.listeners`` — niente regex su testo.

I tre verbi:

* ``system.listeners`` (SYS-02) e' il check portante: dai socket in ascolto
  ricava le attestazioni (attese ``app:8000`` e ``db:5432``, ogni altra porta e'
  una deviazione). Un ``status:"error"`` qui e' un check **FALLITO**, con
  l'``error.code`` nella nota — non un vuoto. ``ok`` con lista vuota e'
  ``COMPLETATO`` a zero sulle porte (controllo positivo).
* ``system.info`` (SYS-01) e ``system.processes`` (SYS-03) danno **attestazioni
  di contesto** (identita' host, numero di processi), non finding inventati.

``_esegui_live`` invia i tre verbi via il wrapper SSH e riunisce le righe
envelope grezze; il ``parse`` qui sotto resta l'unico a interpretarle. Senza un
canale SSH nel contesto (nessuna VM) il collector viene saltato dal runner.
"""

from __future__ import annotations

from assess.collectors.base import (
    CollectorBase,
    EsecuzioneLiveNonDisponibile,
    RunContext,
    raw_completato,
    raw_fallito,
)
from assess.model import RawResult, Scope, Source
from assess.wrappers.ssh import (
    Envelope,
    ProtocolloNonValido,
    TrasportoSshFallito,
    leggi_envelope,
)

#: Porte attese in ascolto: l'app e il database del compose.
PORTE_ATTESE = {8000: "app (uvicorn)", 5432: "db (postgres)"}

#: I verbi inviati, nell'ordine. Combaciano con l'allowlist del wrapper.
VERBI = ("system.info", "system.listeners", "system.processes")


class SystemCollector(CollectorBase):
    name = "system"
    source = Source.SYSTEM
    scope = Scope.INTERNAL
    requires = frozenset({"ssh"})
    comando = "ssh verbi: system.info ; system.listeners ; system.processes"

    def costruisci_comando(self, ctx: RunContext) -> list[str]:
        # Non comandi shell: i verbi logici del protocollo.
        return list(VERBI)

    # -- attestazioni per verbo -------------------------------------------- #

    def _attestazioni_porte(self, env: Envelope) -> list[dict]:
        att: list[dict] = []
        for voce in (env.data or {}).get("listeners", []):
            porta = voce.get("port")
            address = voce.get("address", "?")
            attesa = porta in PORTE_ATTESE
            att.append({
                "controllo": f"porta {porta} in ascolto",
                "bersaglio": f"{address}:{porta}",
                "atteso": "solo app:8000 e db:5432",
                "osservato": f"{address}:{porta} ({PORTE_ATTESE.get(porta, 'servizio inatteso')})",
                "conforme": attesa,
                "references": ["PROTOCOL.md SYS-02", "compose.assess.yaml"],
                "impact": 3,
                "probability": 3,
                "recommendation": (
                    "Nessuna azione." if attesa else
                    "Chiudere o non esporre questa porta: non e' app ne' db."
                ),
            })
        return att

    @staticmethod
    def _attestazione_info(env: Envelope) -> dict:
        d = env.data or {}
        osservato = (
            f"{d.get('os_pretty_name') or d.get('os')}, "
            f"kernel {d.get('kernel')}, python {d.get('python_version')}"
        )
        return {
            "controllo": "identita' dell'host (contesto)",
            "bersaglio": d.get("hostname", "?"),
            "atteso": "ambiente demo noto",
            "osservato": osservato,
            "conforme": True,
            "references": ["PROTOCOL.md SYS-01"],
            "impact": 1,
            "probability": 1,
            "recommendation": "Contesto, nessuna azione.",
        }

    @staticmethod
    def _attestazione_processi(env: Envelope) -> dict:
        d = env.data or {}
        return {
            "controllo": "processi visibili (contesto)",
            "bersaglio": "host",
            "atteso": "inventario di contesto",
            "osservato": f"{d.get('count', 0)} processi, visibilita' {d.get('visibility', '?')}",
            "conforme": True,
            "references": ["PROTOCOL.md SYS-03"],
            "impact": 1,
            "probability": 1,
            "recommendation": "Contesto, nessuna azione.",
        }

    def parse(self, grezzo: str) -> RawResult:
        per_check: dict[str, Envelope] = {}
        malformate = 0
        for riga in grezzo.splitlines():
            if not riga.strip():
                continue
            try:
                env = leggi_envelope(riga)
            except ProtocolloNonValido:
                malformate += 1
                continue
            per_check[env.check_id] = env

        if not per_check:
            return raw_fallito(
                self.source, self.comando,
                "nessun envelope valido nelle risposte del wrapper "
                f"({malformate} righe malformate).",
            )

        # SYS-02 e' il check portante: senza, o in errore, il collector fallisce.
        sys02 = per_check.get("SYS-02")
        if sys02 is None:
            return raw_fallito(
                self.source, self.comando,
                "nessuna risposta per system.listeners (SYS-02): check portante "
                "assente.",
            )
        if not sys02.ok:
            return raw_fallito(
                self.source, self.comando,
                f"system.listeners fallito: {sys02.codice_errore}.",
            )

        porte = self._attestazioni_porte(sys02)
        attestazioni = list(porte)

        # Contesto: info e processi. Un loro errore non fa fallire il collector,
        # ma non diventa un'attestazione conforme: resta nelle note.
        note: list[str] = []
        sys01 = per_check.get("SYS-01")
        if sys01 is not None:
            if sys01.ok:
                attestazioni.append(self._attestazione_info(sys01))
            else:
                note.append(f"system.info non disponibile: {sys01.codice_errore}")
        sys03 = per_check.get("SYS-03")
        if sys03 is not None:
            if sys03.ok:
                attestazioni.append(self._attestazione_processi(sys03))
            else:
                note.append(f"system.processes non disponibile: {sys03.codice_errore}")

        inattese = sum(1 for a in porte if not a["conforme"])
        if porte:
            nota = f"{len(porte)} porte in ascolto, {inattese} inattese."
        else:
            nota = "nessuna porta in ascolto osservata (controllo positivo)."
        if note:
            nota += " " + " ; ".join(note)
        return raw_completato(self.source, self.comando, attestazioni, nota)

    def _esegui_live(self, ctx: RunContext) -> str:
        """Invia i tre verbi via il wrapper SSH e riunisce le RIGHE envelope
        grezze con '\\n', nell'ordine dei verbi, cosi' che il ``parse`` esistente
        le consumi. Non interpreta qui gli envelope (niente logica duplicata).

        Se il trasporto di un verbo fallisce, quella riga semplicemente manca:
        ``parse`` gia' tratta SYS-02 assente/errore come FALLITO. Non si inventa
        un envelope per coprire il buco."""
        wrapper = ctx.ssh
        if wrapper is None:
            raise EsecuzioneLiveNonDisponibile("nessun canale SSH nel contesto")
        righe = []
        for verbo in VERBI:
            try:
                righe.append(wrapper.riga_grezza(verbo))
            except TrasportoSshFallito:
                continue  # riga mancante: la gestisce parse, non la si inventa
        return "\n".join(righe)


__all__ = ["SystemCollector", "PORTE_ATTESE", "VERBI"]
