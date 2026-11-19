"""Collector esterno: sqlmap (profilo non distruttivo).

Comando reale, una invocazione per endpoint iniettabile dal contratto:

    sqlmap -u "<base_url><path>" \\
           --cookie="hermes_session=<cookie>" \\
           --data="<campi del corpo>"   # per i metodi con body \\
           --batch --level=1 --risk=1 --technique=BEU \\
           --dbms=postgresql --flush-session

* **Profilo non distruttivo**: livello/rischio bassi, tecniche Boolean/Error/
  Union (``BEU``) — niente stacked queries o time-based che aprano la via a
  comandi OS o scritture.
* Endpoint e parametri da ``openapi.json`` (``parametri_iniettabili``).
* Cookie come segnaposto nel comando, mai il valore.

Interpretazione dell'output (``parse``), nell'ordine che conta:

1. **sessione non valida** (il server ha risposto con un redirect al login o un
   401/403): esito **esplicito** ``FALLITO``, controllato *per primo* perche'
   una sessione scaduta non deve diventare un falso "non iniettabile";
2. **iniezione trovata**: ``COMPLETATO`` con il finding;
3. **nessuna iniezione** ("do not appear to be injectable"): ``COMPLETATO`` a
   zero, con nota di controllo positivo;
4. **output non riconoscibile**: ``FALLITO``, mai un falso vuoto.

Il grezzo che ``parse`` riceve e' preceduto da una riga
``### endpoint: <metodo> <path>`` che l'I/O live antepone, cosi' il parser sa a
quale endpoint si riferisce il log (sqlmap non lo mette in forma stabile).
"""

from __future__ import annotations

import re

from assess.collectors.base import (
    CollectorBase,
    EsecuzioneLiveNonDisponibile,
    RunContext,
    raw_completato,
    raw_fallito,
    raw_vuoto,
)
from assess.inventory.openapi_endpoints import Endpoint
from assess.model import RawResult, Scope, Source

SEGNAPOSTO_SESSIONE = "${ASSESS_SESSION}"

#: Metodi che portano un corpo (sqlmap riceve --data).
_CON_CORPO = ("POST", "PUT", "PATCH")

_RE_ENDPOINT = re.compile(r"^###\s*endpoint:\s*(.+)$", re.MULTILINE)
_RE_PARAMETRO = re.compile(r"Parameter:\s*([^\s(]+)\s*\(([^)]+)\)")
_RE_TIPO = re.compile(r"Type:\s*(.+)")
_RE_PAYLOAD = re.compile(r"Payload:\s*(.+)")


class SqlmapCollector(CollectorBase):
    name = "sqlmap"
    source = Source.SQLMAP
    scope = Scope.EXTERNAL
    requires = frozenset({"target"})
    comando = (
        'sqlmap -u "<base_url><path>" --cookie="hermes_session=***" '
        "--batch --level=1 --risk=1 --technique=BEU --dbms=postgresql --flush-session"
    )

    def _comando_per(self, endpoint: Endpoint, ctx: RunContext) -> list[str]:
        base = (ctx.base_url or "").rstrip("/")
        argv = [
            "sqlmap", "-u", f"{base}{endpoint.path}",
            "--cookie", f"hermes_session={SEGNAPOSTO_SESSIONE}",
            "--batch", "--level=1", "--risk=1",
            "--technique=BEU", "--dbms=postgresql", "--flush-session",
        ]
        if endpoint.method in _CON_CORPO and endpoint.body_fields:
            dati = "&".join(f"{campo}=1" for campo in endpoint.body_fields)
            argv += ["--data", dati]
        return argv

    def _endpoint_iniettabili(self, ctx: RunContext) -> list[Endpoint]:
        return [e for e in ctx.inventario if e.parametri_iniettabili]

    def comandi(self, ctx: RunContext) -> list[list[str]]:
        """Un comando sqlmap per ciascun endpoint con parametri iniettabili."""
        return [self._comando_per(e, ctx) for e in self._endpoint_iniettabili(ctx)]

    def costruisci_comando(self, ctx: RunContext) -> list[str]:
        """Comando rappresentativo (il primo endpoint iniettabile). L'elenco
        completo e' in ``comandi``."""
        iniettabili = self._endpoint_iniettabili(ctx)
        if not iniettabili:
            return ["sqlmap", "--version"]  # niente da testare: comando innocuo
        return self._comando_per(iniettabili[0], ctx)

    @staticmethod
    def _endpoint_dal_log(grezzo: str) -> str:
        m = _RE_ENDPOINT.search(grezzo)
        return m.group(1).strip() if m else "endpoint sconosciuto"

    @staticmethod
    def _sessione_non_valida(grezzo: str) -> bool:
        low = grezzo.lower()
        if "error code (401" in low or "error code (403" in low:
            return True
        if ("redirect" in low or "redirected" in low) and "login" in low:
            return True
        if "session cookie" in low and "invalid" in low:
            return True
        return False

    def parse(self, grezzo: str) -> RawResult:
        endpoint = self._endpoint_dal_log(grezzo)
        low = grezzo.lower()

        # 1) Sessione non valida — per prima, per non mascherare un negativo.
        if self._sessione_non_valida(grezzo):
            return raw_fallito(
                self.source, self.comando,
                f"sessione non valida su {endpoint}: il target ha risposto con "
                "login/redirect o 401/403 — esito esplicito, non un 'negativo'.",
            )

        # 2) Iniezione trovata.
        if "injection point" in low or ("parameter:" in low and "type:" in low):
            elementi = []
            tipo_m = _RE_TIPO.search(grezzo)
            payload_m = _RE_PAYLOAD.search(grezzo)
            tipo = tipo_m.group(1).strip() if tipo_m else "sconosciuto"
            payload = payload_m.group(1).strip() if payload_m else ""
            for nome, metodo in _RE_PARAMETRO.findall(grezzo):
                elementi.append({
                    "endpoint": endpoint,
                    "parameter": nome,
                    "injectable": True,
                    "method": metodo,
                    "technique": tipo,
                    "payload": payload,
                    "dbms": "PostgreSQL",
                })
            if not elementi:
                elementi.append({
                    "endpoint": endpoint, "parameter": "sconosciuto",
                    "injectable": True, "technique": tipo, "payload": payload,
                })
            return raw_completato(self.source, self.comando, elementi)

        # 3) Nessuna iniezione.
        if "do not appear to be injectable" in low or "not injectable" in low:
            return raw_vuoto(
                self.source, self.comando,
                f"nessuna SQLi su {endpoint}: parametri non iniettabili "
                "(query parametrizzate SQLAlchemy) — controllo positivo.",
            )

        # 4) Non riconoscibile.
        return raw_fallito(
            self.source, self.comando,
            f"output sqlmap non riconosciuto su {endpoint}: ne' iniezione, ne' "
            "esito negativo esplicito.",
        )

    def _esegui_live(self, ctx: RunContext) -> str:
        raise EsecuzioneLiveNonDisponibile(
            "sqlmap live non disponibile nello scaffold; comandi: "
            + " ; ".join(" ".join(c) for c in self.comandi(ctx))
        )


__all__ = ["SqlmapCollector", "SEGNAPOSTO_SESSIONE"]
