"""Modello e rischio: il calcolo I×P e la severita' come banda nominale.

Il rischio e' il prodotto di due assi 1–5, e la severita' viene da li' come
banda *low/medium/high/critical* (non piu' ``RiskTier``: quello nel pannello e'
l'invasivita' di un tool, non la gravita' di una vulnerabilita'). Questi test
fissano i confini delle quattro bande e verificano che un finding non possa
essere costruito con un rischio o una severita' incoerenti con i suoi assi —
l'onesta' del modello non e' una convenzione, e' un invariante che solleva.
"""

from __future__ import annotations

import pytest

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
from assess.risk import rischio, severita_da_score


# --------------------------------------------------------------------------- #
# rischio = impatto × probabilita'
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "impatto,probabilita,atteso",
    [(1, 1, 1), (3, 2, 6), (4, 4, 16), (5, 5, 25), (5, 2, 10)],
)
def test_rischio_prodotto(impatto, probabilita, atteso):
    assert rischio(impatto, probabilita) == atteso


@pytest.mark.parametrize("valore", [0, 6, -1, 100])
def test_rischio_asse_fuori_scala_solleva(valore):
    with pytest.raises(ValueError):
        rischio(valore, 3)
    with pytest.raises(ValueError):
        rischio(3, valore)


def test_rischio_bool_rifiutato():
    # True varrebbe 1 in aritmetica: va rifiutato esplicitamente, non accettato
    # come se fosse un asse valido.
    with pytest.raises(TypeError):
        rischio(True, 3)


# --------------------------------------------------------------------------- #
# severita' (banda) dai confini
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "score,banda",
    [
        (1, "low"), (4, "low"),
        (5, "medium"), (9, "medium"),
        (10, "high"), (15, "high"),
        (16, "critical"), (25, "critical"),
    ],
)
def test_severity_confini(score, banda):
    assert severita_da_score(score) == banda


def test_severity_score_fuori_intervallo_solleva():
    with pytest.raises(ValueError):
        severita_da_score(0)
    with pytest.raises(ValueError):
        severita_da_score(26)


# --------------------------------------------------------------------------- #
# Finding: derivazione e coerenza
# --------------------------------------------------------------------------- #


def _finding(impatto=3, probabilita=2, **kw):
    base = dict(
        id="VSPT-0001", title="t", affected_element="POST /api/x",
        category=Category.INJECTION, source=Source.SQLMAP, evidence="e",
        status=Status.POTENTIAL, pentest_result=PentestResult.NEGATIVE,
        verification_confidence=VerificationConfidence.MEDIUM, recommendation="r",
    )
    base.update(kw)
    return Finding.nuovo(impact=impatto, probability=probabilita, **base)


def test_finding_nuovo_deriva_rischio_e_severita():
    f = _finding(impatto=4, probabilita=4)
    assert f.risk_score == 16
    assert f.severity == "critical"


def test_finding_scope_dedotto_dalla_fonte():
    # sqlmap e' esterno, semgrep e' interno: lo scope non va passato a mano.
    assert _finding(source=Source.SQLMAP).scope.value == "external"
    assert _finding(source=Source.SEMGREP).scope.value == "internal"


def test_finding_incoerente_rifiutato():
    # Costruzione diretta con un risk_score che non e' il prodotto degli assi.
    with pytest.raises(ValueError):
        Finding(
            id="VSPT-0001", title="t", affected_element="x",
            category=Category.CONFIG, source=Source.POSTGRES, evidence="e",
            status=Status.CONFIRMED, pentest_result=PentestResult.NOT_APPLICABLE,
            impact=2, probability=2, risk_score=99, severity="low",
            verification_confidence=VerificationConfidence.HIGH, recommendation="r",
            scope=Scope.INTERNAL,
        )


def test_finding_severita_incoerente_rifiutata():
    with pytest.raises(ValueError):
        Finding(
            id="VSPT-0001", title="t", affected_element="x",
            category=Category.CONFIG, source=Source.POSTGRES, evidence="e",
            status=Status.CONFIRMED, pentest_result=PentestResult.NOT_APPLICABLE,
            impact=5, probability=5, risk_score=25, severity="low",
            verification_confidence=VerificationConfidence.HIGH, recommendation="r",
            scope=Scope.INTERNAL,
        )


def test_finding_to_json_ha_i_campi_giusti():
    f = _finding()
    j = f.to_json()
    attesi = {
        "id", "title", "affected_element", "category", "source", "evidence",
        "status", "pentest_result", "impact", "probability", "risk_score",
        "severity", "verification_confidence", "scope",
        "recommendation", "references",
    }
    assert attesi <= set(j)
    # La severita' E' la banda: niente campo "banda" ridondante accanto.
    assert "banda" not in j
    assert j["severity"] in {"low", "medium", "high", "critical"}


# --------------------------------------------------------------------------- #
# RawResult: un check non completato non puo' portare risultati
# --------------------------------------------------------------------------- #


def test_rawresult_saltato_con_elementi_rifiutato():
    with pytest.raises(ValueError):
        RawResult(
            source=Source.NUCLEI, esito=EsitoCheck.SALTATO, comando="x",
            elementi=[{"template-id": "t"}],
        )


def test_rawresult_completato_a_zero_e_ammesso():
    # Un check eseguito che non trova nulla e' legittimo: zero elementi, nota.
    raw = RawResult(
        source=Source.SQLMAP, esito=EsitoCheck.COMPLETATO, comando="sqlmap",
        nota="nessuna SQLi nei test svolti",
    )
    assert raw.elementi == []
    assert raw.scope is Scope.EXTERNAL  # dedotto dalla fonte (sqlmap = esterno)
