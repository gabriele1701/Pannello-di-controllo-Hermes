"""Normalizzazione: dall'output grezzo ai Finding, con dedup e onesta'.

Si parte dalle fixture di output grezzo (formato nativo di ogni tool) e si
verifica che diventino Finding con gli assi giusti, che i duplicati collassino,
e — il punto che conta — che un esito negativo NON diventi un finding
"superato" e che un'attestazione conforme diventi un finding verde esplicito.
"""

from __future__ import annotations

from assess.model import (
    Category,
    EsitoCheck,
    PentestResult,
    RawResult,
    RiskTier,
    Source,
)
from assess.normalize import normalizza


def _raw(source: Source, elementi: list[dict]) -> RawResult:
    return RawResult(
        source=source, esito=EsitoCheck.COMPLETATO, comando="x", elementi=elementi
    )


def test_semgrep_grezzo_diventa_finding(carica_fixture):
    dati = carica_fixture("semgrep_raw.json")
    findings = normalizza([_raw(Source.SEMGREP, dati["results"])])
    assert len(findings) == 2
    # CWE-89 -> injection, CWE-327 -> crypto
    categorie = {f.category for f in findings}
    assert Category.INJECTION in categorie and Category.CRYPTO in categorie
    # La statica non e' un pentest: NOT_APPLICABLE, non NEGATIVE.
    assert all(f.pentest_result is PentestResult.NOT_APPLICABLE for f in findings)


def test_pipaudit_espande_solo_le_vulnerabilita(carica_fixture):
    dati = carica_fixture("pipaudit_raw.json")
    findings = normalizza([_raw(Source.PIP_AUDIT, dati["dependencies"])])
    # Due dipendenze, ma una senza vuln: un solo finding.
    assert len(findings) == 1
    f = findings[0]
    assert f.category is Category.DEPENDENCY
    assert "CVE-2025-0001" in f.references
    assert f.pentest_result is PentestResult.NOT_RUN  # CVE nota, non sfruttata


def test_sqlmap_negativo_non_produce_finding(carica_fixture):
    """Onesta': sqlmap che non trova SQLi non e' un finding 'superato'."""
    dati = carica_fixture("sqlmap_raw.json")
    findings = normalizza([_raw(Source.SQLMAP, dati)])
    assert findings == []


def test_sqlmap_positivo_e_confermato():
    elementi = [
        {"endpoint": "POST /api/x", "parameter": "q", "injectable": True,
         "technique": "B", "payload": "' OR 1=1--"}
    ]
    findings = normalizza([_raw(Source.SQLMAP, elementi)])
    assert len(findings) == 1
    f = findings[0]
    assert f.severity is RiskTier.ROSSO  # 5x5=25
    assert f.pentest_result is PentestResult.POSITIVE
    assert "CWE-89" in f.references


def test_postgres_attestazione_conforme_e_verde(carica_fixture):
    dati = carica_fixture("postgres_raw.json")
    findings = normalizza([_raw(Source.POSTGRES, dati)])
    assert len(findings) == 2
    assert all(f.severity is RiskTier.VERDE for f in findings)
    assert all(f.title.startswith("Attestazione") for f in findings)


def test_system_deviazione_e_rossa_conforme_verde(carica_fixture):
    dati = carica_fixture("system_raw.json")
    findings = normalizza([_raw(Source.SYSTEM, dati)])
    titoli = {f.title.split(":")[0]: f for f in findings}
    assert "Attestazione" in titoli  # permessi .env conformi
    assert "Deviazione" in titoli    # porta db esposta
    assert titoli["Attestazione"].severity is RiskTier.VERDE
    assert titoli["Deviazione"].severity is RiskTier.ROSSO  # 4x3=12


def test_dedup_collassa_i_duplicati():
    el = {"check_id": "dup", "path": "backend/x.py", "start": {"line": 1},
          "extra": {"message": "m", "severity": "ERROR", "metadata": {"cwe": ["CWE-89"]}}}
    findings = normalizza([_raw(Source.SEMGREP, [el, dict(el), dict(el)])])
    assert len(findings) == 1


def test_id_progressivi_e_ordine_per_rischio(carica_fixture):
    raws = [
        _raw(Source.SEMGREP, carica_fixture("semgrep_raw.json")["results"]),
        _raw(Source.PIP_AUDIT, carica_fixture("pipaudit_raw.json")["dependencies"]),
        _raw(Source.POSTGRES, carica_fixture("postgres_raw.json")),
    ]
    findings = normalizza(raws)
    # Id progressivi VSPT-0001.. nell'ordine finale.
    assert [f.id for f in findings] == [f"VSPT-{i:04d}" for i in range(1, len(findings) + 1)]
    # Ordinati per rischio decrescente.
    punteggi = [f.risk_score for f in findings]
    assert punteggi == sorted(punteggi, reverse=True)


def test_check_non_completato_ignorato():
    saltato = RawResult(source=Source.NUCLEI, esito=EsitoCheck.SALTATO, comando="x")
    assert normalizza([saltato]) == []
