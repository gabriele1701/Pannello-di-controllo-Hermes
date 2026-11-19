"""Normalizzazione: output grezzo dei tool → ``Finding`` canonici, con dedup.

Ogni fonte ha il suo formato nativo (il JSONL di nuclei, il JSON di semgrep,
l'albero ``dependencies`` di pip-audit) o un formato nostro per i wrapper
(sqlmap, postgres, system). I normalizzatori leggono quel formato e producono
``Finding`` con gli assi di rischio gia' assegnati; ``normalizza`` li raccoglie,
deduplica, ordina per rischio e assegna gli id ``VSPT-NNNN``.

Onesta' nella normalizzazione
-----------------------------

* Un esito **negativo** (sqlmap che non trova SQLi) **non** diventa un finding
  "superato": non produce un ``Finding`` affatto. Resta nel ``RawResult`` come
  nota di controllo positivo e nei metadati del run. Un report pieno di
  "niente trovato qui" trasformati in righe verdi sarebbe una bugia per
  accumulo.
* Un'**attestazione** (il DB conforme al modello a due ruoli, i permessi
  giusti) e' invece un finding deliberato a severita' minima: un controllo
  positivo che vogliamo *vedere*, con ``pentest_result = not_applicable`` e
  rischio 1 (verde). Dire "ho verificato e va bene" e' diverso da non dire
  niente.
* ``status`` e ``pentest_result`` riflettono cosa il tool fa davvero: semgrep
  e' statica (``not_applicable`` al pentest), pip-audit segnala CVE note non
  sfruttate (``not_run``), sqlmap confermato e' uno sfruttamento (``positive``).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from assess.model import (
    Category,
    EsitoCheck,
    Finding,
    PentestResult,
    RawResult,
    Scope,
    Source,
    Status,
    VerificationConfidence,
)

# --------------------------------------------------------------------------- #
# Mappe di appoggio
# --------------------------------------------------------------------------- #

#: Severita' testuale dei tool (nuclei, semgrep) -> impatto 1-5.
_IMPATTO_DA_SEVERITA: dict[str, int] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "moderate": 3,
    "low": 2,
    "warning": 2,
    "info": 1,
    "informational": 1,
    "error": 4,
}

#: CWE -> categoria del dominio. Fallback ``OTHER`` per cio' che non e' mappato:
#: meglio una categoria onesta e generica che una inventata.
_CATEGORIA_DA_CWE: dict[str, Category] = {
    "CWE-89": Category.INJECTION,
    "CWE-78": Category.INJECTION,
    "CWE-79": Category.INJECTION,
    "CWE-287": Category.AUTH,
    "CWE-306": Category.AUTH,
    "CWE-384": Category.AUTH,
    "CWE-862": Category.ACCESS_CONTROL,
    "CWE-863": Category.ACCESS_CONTROL,
    "CWE-200": Category.INFO_EXPOSURE,
    "CWE-327": Category.CRYPTO,
    "CWE-328": Category.CRYPTO,
}


def _impatto(severita: str, *, default: int = 3) -> int:
    return _IMPATTO_DA_SEVERITA.get(str(severita).strip().lower(), default)


def _norm_cwe(valore: Any) -> list[str]:
    """Normalizza un campo CWE eterogeneo (lista, stringa, con/senza prefisso)
    in una lista di ``CWE-<n>``."""
    if valore is None:
        return []
    voci = valore if isinstance(valore, (list, tuple)) else [valore]
    out: list[str] = []
    for v in voci:
        s = str(v).strip()
        if not s:
            continue
        if s.upper().startswith("CWE-"):
            out.append("CWE-" + s.split("-", 1)[1])
        elif s.isdigit():
            out.append(f"CWE-{s}")
        else:
            out.append(s)
    return out


def _categoria(cwe: list[str], default: Category = Category.OTHER) -> Category:
    for c in cwe:
        if c in _CATEGORIA_DA_CWE:
            return _CATEGORIA_DA_CWE[c]
    return default


# --------------------------------------------------------------------------- #
# Normalizzatori per fonte. Ognuno: dict grezzo -> lista di Finding (0..N).
# L'id resta vuoto: lo assegna ``normalizza`` dopo dedup e ordinamento.
# --------------------------------------------------------------------------- #


def _norm_nuclei(el: dict[str, Any]) -> list[Finding]:
    info = el.get("info", {})
    cwe = _norm_cwe(info.get("classification", {}).get("cwe-id"))
    riferimenti = [r for r in [el.get("template-id")] if r] + cwe
    return [
        Finding.nuovo(
            id="",
            title=info.get("name") or el.get("template-id", "match nuclei"),
            affected_element=el.get("matched-at", el.get("host", "?")),
            category=_categoria(cwe),
            source=Source.NUCLEI,
            evidence=f"template {el.get('template-id','?')} su {el.get('matched-at','?')}",
            status=Status.POTENTIAL,
            pentest_result=PentestResult.NOT_APPLICABLE,
            impact=_impatto(info.get("severity", "info")),
            probability=3,
            verification_confidence=VerificationConfidence.MEDIUM,
            recommendation="Verificare manualmente il match prima di trattarlo come confermato.",
            references=riferimenti,
        )
    ]


def _norm_sqlmap(el: dict[str, Any]) -> list[Finding]:
    # Un esito negativo NON e' un finding: lo salta. Finisce come nota di
    # controllo positivo nel RawResult, non come riga verde "superato".
    if not el.get("injectable", False):
        return []
    endpoint = el.get("endpoint", "?")
    parametro = el.get("parameter", "?")
    return [
        Finding.nuovo(
            id="",
            title=f"SQL injection su {parametro}",
            affected_element=f"{endpoint} (campo: {parametro})",
            category=Category.INJECTION,
            source=Source.SQLMAP,
            evidence=el.get("payload") or el.get("note") or "iniezione confermata da sqlmap",
            status=Status.CONFIRMED,
            pentest_result=PentestResult.POSITIVE,
            impact=5,
            probability=5,
            verification_confidence=VerificationConfidence.HIGH,
            recommendation="Usare query parametrizzate; non concatenare input nelle query.",
            references=["CWE-89", el.get("technique", "")],
        )
    ]


def _norm_semgrep(el: dict[str, Any]) -> list[Finding]:
    extra = el.get("extra", {})
    meta = extra.get("metadata", {})
    cwe = _norm_cwe(meta.get("cwe"))
    path = el.get("path", "?")
    riga = el.get("start", {}).get("line", "?")
    return [
        Finding.nuovo(
            id="",
            title=el.get("check_id", "match semgrep").split(".")[-1],
            affected_element=f"{path}:{riga}",
            category=_categoria(cwe),
            source=Source.SEMGREP,
            evidence=extra.get("message", "")[:400],
            # Analisi statica: il match nel codice e' certo, ma lo
            # sfruttamento non e' dimostrato -> confermato come presenza, non
            # applicabile come pentest.
            status=Status.CONFIRMED,
            pentest_result=PentestResult.NOT_APPLICABLE,
            impact=_impatto(extra.get("severity", "medium")),
            probability=3,
            verification_confidence=VerificationConfidence.MEDIUM,
            recommendation=meta.get("message", "") or "Rivedere il punto segnalato.",
            references=[el.get("check_id", "")] + cwe,
        )
    ]


def _norm_pipaudit(el: dict[str, Any]) -> list[Finding]:
    # Formato nativo: una dipendenza con 0..N vulnerabilita'. Ogni vuln e' un
    # finding separato; una dipendenza senza vuln non produce nulla.
    out: list[Finding] = []
    nome = el.get("name", "?")
    versione = el.get("version", "?")
    for vuln in el.get("vulns", []):
        fix = ", ".join(vuln.get("fix_versions", [])) or "nessuna versione corretta nota"
        out.append(
            Finding.nuovo(
                id="",
                title=f"{nome} {versione}: {vuln.get('id','CVE')}",
                affected_element=f"{nome}=={versione}",
                category=Category.DEPENDENCY,
                source=Source.PIP_AUDIT,
                evidence=(vuln.get("description") or "")[:400],
                status=Status.CONFIRMED,
                # CVE nota nella dipendenza, non sfruttata in questo run.
                pentest_result=PentestResult.NOT_RUN,
                impact=4,
                probability=3,
                verification_confidence=VerificationConfidence.HIGH,
                recommendation=f"Aggiornare a: {fix}.",
                references=[vuln.get("id", "")] + list(vuln.get("aliases", [])),
            )
        )
    return out


def _norm_attestazione(
    el: dict[str, Any], source: Source, categoria: Category
) -> list[Finding]:
    """Normalizzatore comune a postgres e system: distingue una deviazione (un
    finding vero) da un'attestazione conforme (controllo positivo verde)."""
    conforme = el.get("conforme", True)
    titolo = el.get("controllo") or el.get("attestazione", "controllo")
    atteso = el.get("atteso", "")
    osservato = el.get("osservato", "")
    bersaglio = el.get("bersaglio") or el.get("tabella") or el.get("dettaglio", "")
    evidenza = f"atteso: {atteso} · osservato: {osservato}".strip(" ·")
    if conforme:
        return [
            Finding.nuovo(
                id="",
                title=f"Attestazione: {titolo}",
                affected_element=str(bersaglio) or titolo,
                category=categoria,
                source=source,
                evidence=evidenza or "conforme al modello documentato",
                status=Status.CONFIRMED,
                pentest_result=PentestResult.NOT_APPLICABLE,
                impact=1,
                probability=1,
                verification_confidence=VerificationConfidence.HIGH,
                recommendation="Nessuna azione: il controllo e' rispettato.",
                references=list(el.get("references", [])),
            )
        ]
    return [
        Finding.nuovo(
            id="",
            title=f"Deviazione: {titolo}",
            affected_element=str(bersaglio) or titolo,
            category=categoria,
            source=source,
            evidence=evidenza or "difforme dal modello documentato",
            status=Status.CONFIRMED,
            pentest_result=PentestResult.NOT_APPLICABLE,
            impact=int(el.get("impact", 4)),
            probability=int(el.get("probability", 4)),
            verification_confidence=VerificationConfidence.HIGH,
            recommendation=el.get("recommendation", "Riportare la configurazione al modello documentato."),
            references=list(el.get("references", [])),
        )
    ]


def _norm_postgres(el: dict[str, Any]) -> list[Finding]:
    return _norm_attestazione(el, Source.POSTGRES, Category.CONFIG)


def _norm_system(el: dict[str, Any]) -> list[Finding]:
    return _norm_attestazione(el, Source.SYSTEM, Category.CONFIG)


_NORMALIZZATORI: dict[Source, Callable[[dict[str, Any]], list[Finding]]] = {
    Source.NUCLEI: _norm_nuclei,
    Source.SQLMAP: _norm_sqlmap,
    Source.SEMGREP: _norm_semgrep,
    Source.PIP_AUDIT: _norm_pipaudit,
    Source.POSTGRES: _norm_postgres,
    Source.SYSTEM: _norm_system,
}


# --------------------------------------------------------------------------- #
# Dedup e orchestrazione
# --------------------------------------------------------------------------- #


def _chiave(f: Finding) -> tuple[str, str, str]:
    """Identita' di deduplicazione: stessa fonte, stesso elemento colpito,
    stesso titolo = stesso finding."""
    return (f.source.value, f.affected_element, f.title)


def _dedup(trovati: list[Finding]) -> list[Finding]:
    """Rimuove i duplicati tenendo, a parita' di chiave, quello a rischio piu'
    alto. Due scansioni della stessa cosa non devono gonfiare il conteggio."""
    migliore: dict[tuple[str, str, str], Finding] = {}
    for f in trovati:
        k = _chiave(f)
        if k not in migliore or f.risk_score > migliore[k].risk_score:
            migliore[k] = f
    return list(migliore.values())


def normalizza(raws: list[RawResult]) -> list[Finding]:
    """Converte i ``RawResult`` completati in ``Finding`` canonici, dedotti,
    ordinati per rischio decrescente e numerati ``VSPT-NNNN``."""
    trovati: list[Finding] = []
    for raw in raws:
        if raw.esito is not EsitoCheck.COMPLETATO:
            continue
        norm = _NORMALIZZATORI.get(raw.source)
        if norm is None:
            continue
        for el in raw.elementi:
            trovati.extend(norm(el))

    dedotti = _dedup(trovati)
    dedotti.sort(key=lambda f: (-f.risk_score, f.source.value, f.affected_element, f.title))
    for i, f in enumerate(dedotti, start=1):
        f.id = f"VSPT-{i:04d}"
    return dedotti


__all__ = ["normalizza"]
