"""Documento JSON canonico del report e il suo schema (JSON Schema 2020-12).

Il documento ha tre parti: ``meta`` (i metadati del run), ``findings`` (le
righe canoniche) e ``riepilogo`` (conteggi derivati, per leggere il report a
colpo d'occhio e per verificare i criteri di accettazione — es. **≥ 2 fonti**).

Lo ``SCHEMA`` e' qui, accanto al documento che descrive, e i test lo usano per
validare i report veri: un contratto verificato con lo stesso strumento con cui
si valida, non un controllo scritto a mano piu' debole del contratto.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import TYPE_CHECKING, Any

from assess.model import Category, PentestResult, Scope, Source, Status, VerificationConfidence

if TYPE_CHECKING:
    from assess.runner import Esecuzione

#: Valori ammessi dei vocabolari, ricavati dagli enum per non duplicarli a mano.
_SEVERITA = ["verde", "giallo", "rosso"]
_BANDE = ["low", "medium", "high", "critical"]


def _enum_vals(enum_cls: type) -> list[str]:
    return [m.value for m in enum_cls]


#: Schema di un singolo finding (spec §7).
SCHEMA_FINDING: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "id", "title", "affected_element", "category", "source", "evidence",
        "status", "pentest_result", "impact", "probability", "risk_score",
        "severity", "banda", "verification_confidence", "scope",
        "recommendation", "references",
    ],
    "properties": {
        "id": {"type": "string", "pattern": r"^VSPT-\d{4}$"},
        "title": {"type": "string", "minLength": 1},
        "affected_element": {"type": "string", "minLength": 1},
        "category": {"type": "string", "enum": _enum_vals(Category)},
        "source": {"type": "string", "enum": _enum_vals(Source)},
        "evidence": {"type": "string"},
        "status": {"type": "string", "enum": _enum_vals(Status)},
        "pentest_result": {"type": "string", "enum": _enum_vals(PentestResult)},
        "impact": {"type": "integer", "minimum": 1, "maximum": 5},
        "probability": {"type": "integer", "minimum": 1, "maximum": 5},
        "risk_score": {"type": "integer", "minimum": 1, "maximum": 25},
        "severity": {"type": "string", "enum": _SEVERITA},
        "banda": {"type": "string", "enum": _BANDE},
        "verification_confidence": {
            "type": "string", "enum": _enum_vals(VerificationConfidence)
        },
        "scope": {"type": "string", "enum": _enum_vals(Scope)},
        "recommendation": {"type": "string"},
        "references": {"type": "array", "items": {"type": "string"}},
    },
}

#: Schema del documento completo.
SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "Report VSPT",
    "type": "object",
    "additionalProperties": False,
    "required": ["meta", "findings", "riepilogo"],
    "properties": {
        "meta": {
            "type": "object",
            "required": [
                "timestamp", "tool_version", "commit_pannello", "versioni_tool",
                "scope_hash", "checks", "limitazioni", "sentinelle_egress",
            ],
            "properties": {
                "timestamp": {"type": "string"},
                "tool_version": {"type": "string"},
                "commit_pannello": {"type": ["string", "null"]},
                "versioni_tool": {"type": "object"},
                "scope_hash": {"type": "string", "pattern": r"^sha256:[0-9a-f]{64}$"},
                "checks": {
                    "type": "object",
                    "required": ["completati", "saltati", "falliti", "dettaglio"],
                    "properties": {
                        "completati": {"type": "array", "items": {"type": "string"}},
                        "saltati": {"type": "array", "items": {"type": "string"}},
                        "falliti": {"type": "array", "items": {"type": "string"}},
                        "dettaglio": {"type": "array"},
                    },
                },
                "limitazioni": {"type": "array", "items": {"type": "string"}},
                "sentinelle_egress": {"type": "array", "items": {"type": "string"}},
            },
        },
        "findings": {"type": "array", "items": SCHEMA_FINDING},
        "riepilogo": {
            "type": "object",
            "required": ["totale", "per_severita", "per_fonte", "fonti_distinte"],
            "properties": {
                "totale": {"type": "integer", "minimum": 0},
                "per_severita": {"type": "object"},
                "per_fonte": {"type": "object"},
                "fonti_distinte": {"type": "integer", "minimum": 0},
            },
        },
    },
}


def _riepilogo(findings: list[dict[str, Any]]) -> dict[str, Any]:
    per_sev = Counter(f["severity"] for f in findings)
    per_fonte = Counter(f["source"] for f in findings)
    return {
        "totale": len(findings),
        "per_severita": {s: per_sev.get(s, 0) for s in _SEVERITA},
        "per_fonte": dict(sorted(per_fonte.items())),
        "fonti_distinte": len(per_fonte),
    }


def documento(esecuzione: Esecuzione) -> dict[str, Any]:
    """Costruisce il documento JSON canonico da un'esecuzione."""
    findings = [f.to_json() for f in esecuzione.findings]
    return {
        "meta": esecuzione.metadati.to_json(),
        "findings": findings,
        "riepilogo": _riepilogo(findings),
    }


def serializza(doc: dict[str, Any]) -> str:
    """JSON deterministico: indent 2, newline finale, utf-8 leggibile."""
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


def scrivi(doc: dict[str, Any], percorso: str | Path) -> Path:
    """Scrive il documento su file e restituisce il percorso."""
    p = Path(percorso)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(serializza(doc), encoding="utf-8")
    return p


def leggi(percorso: str | Path) -> dict[str, Any]:
    """Rilegge un documento JSON scritto in precedenza (per il sottocomando
    ``report``, che rigenera l'HTML dal JSON)."""
    return json.loads(Path(percorso).read_text(encoding="utf-8"))


__all__ = ["SCHEMA", "SCHEMA_FINDING", "documento", "leggi", "scrivi", "serializza"]
