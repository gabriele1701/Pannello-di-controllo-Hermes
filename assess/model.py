"""Modello dati dell'assessment: ``Finding``, i suoi vocabolari, ``RawResult``.

Un ``Finding`` e' una riga del report: una cosa osservata, con la sua
evidenza, il suo stato di verifica e il suo rischio calcolato. La severita'
**non** e' un campo libero: deriva dal punteggio di rischio (``risk.py``) ed
e' un ``RiskTier`` del repo, non un enum nuovo.

Invariante di onestita'
-----------------------

Il modello e' costruito perche' sia **impossibile** dichiarare superato un
controllo che non e' stato eseguito.

* Un check non eseguito non e' un ``Finding``: e' un ``RawResult`` con esito
  ``SALTATO`` o ``FALLITO``, che finisce nei metadati del run, non fra i
  risultati.
* ``PentestResult.NEGATIVE`` significa *non rilevato nei test svolti*, non
  *assente*. La distinzione e' nel docstring dell'enum, e ``NOT_RUN`` esiste
  apposta perche' "non provato" non venga scritto come "negativo".
* ``risk_score`` e ``severity`` non si passano a mano: li calcola
  ``Finding.nuovo`` da impatto e probabilita', e ``__post_init__`` rifiuta un
  oggetto incoerente. Un finding con un rischio scritto a mano diverso dal
  prodotto dei suoi assi sarebbe una bugia comoda.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from backend.models import RiskTier

from assess.risk import banda_nominale, rischio, severity_da_score


# --------------------------------------------------------------------------- #
# Vocabolari del finding
#
# `StrEnum` come in `backend/models.py`: il valore e' la stringa che finisce
# nel JSON, cosi' la serializzazione non ha bisogno di una tabella di
# traduzione che possa divergere dall'enum.
# --------------------------------------------------------------------------- #


class Status(StrEnum):
    """Stato di verifica di un finding.

    E' *quanto siamo sicuri che esista*, separato dall'esito del pentest
    (*cosa abbiamo ottenuto provandolo*). Un finding puo' essere ``CONFIRMED``
    da un tool statico senza che un pentest l'abbia sfruttato.
    """

    CONFIRMED = "confirmed"
    POTENTIAL = "potential"
    UNVERIFIED = "unverified"
    FALSE_POSITIVE = "false_positive"


class PentestResult(StrEnum):
    """Esito del tentativo di sfruttamento.

    ``NEGATIVE`` e ``NOT_RUN`` sono tenuti distinti di proposito: "provato,
    non sfruttabile nei test svolti" non e' "non provato". Confonderli
    trasformerebbe un controllo mancante in una rassicurazione.
    """

    #: Sfruttato con successo: la vulnerabilita' e' reale e dimostrata.
    POSITIVE = "positive"
    #: Provato e non rilevato NEI TEST SVOLTI. Non e' una prova d'assenza.
    NEGATIVE = "negative"
    #: Il controllo non si applica a questo elemento.
    NOT_APPLICABLE = "not_applicable"
    #: Non eseguito. Diverso da NEGATIVE: qui non abbiamo guardato.
    NOT_RUN = "not_run"


class Category(StrEnum):
    """Famiglia della debolezza. Vocabolario aperto ma chiuso qui dentro:
    un valore fuori lista fa fallire la costruzione, non scivola in testo."""

    INJECTION = "injection"
    AUTH = "auth"
    CONFIG = "config"
    DEPENDENCY = "dependency"
    CRYPTO = "crypto"
    INFO_EXPOSURE = "info-exposure"
    ACCESS_CONTROL = "access-control"
    OTHER = "other"


class Source(StrEnum):
    """Da quale strumento/fonte viene il finding. Serve anche a soddisfare il
    requisito della traccia delle **≥ 2 fonti** in modo verificabile: le fonti
    distinte presenti nel report si contano da questo campo."""

    NUCLEI = "nuclei"
    SQLMAP = "sqlmap"
    SEMGREP = "semgrep"
    PIP_AUDIT = "pip-audit"
    POSTGRES = "postgres"
    SYSTEM = "system"


class VerificationConfidence(StrEnum):
    """Confidenza nella verifica. Indipendente dal rischio: un finding ad
    alto rischio puo' avere confidenza bassa, ed e' un'informazione, non una
    contraddizione da nascondere."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Scope(StrEnum):
    """Lato da cui e' stato osservato: black-box (``EXTERNAL``) o
    introspezione autenticata (``INTERNAL``)."""

    EXTERNAL = "external"
    INTERNAL = "internal"


class EsitoCheck(StrEnum):
    """Esito di un collector nel run. Alimenta i metadati {completati,
    saltati, falliti}: e' il meccanismo con cui un controllo non eseguito
    resta visibile invece di sparire."""

    COMPLETATO = "completato"
    SALTATO = "saltato"
    FALLITO = "fallito"


#: Fonti considerate "interne" (richiedono accesso autenticato alla macchina
#: o al DB). Serve a derivare lo scope di default di un finding dalla fonte, e
#: a contare separatamente le fonti interne per i criteri di accettazione.
FONTI_INTERNE: frozenset[Source] = frozenset(
    {Source.SEMGREP, Source.PIP_AUDIT, Source.POSTGRES, Source.SYSTEM}
)


def scope_di(source: Source) -> Scope:
    """Scope implicito di una fonte. ``nuclei``/``sqlmap`` sono black-box
    (esterni), tutto il resto e' introspezione interna."""
    return Scope.INTERNAL if source in FONTI_INTERNE else Scope.EXTERNAL


# --------------------------------------------------------------------------- #
# Finding
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class Finding:
    """Una riga del report.

    Si costruisce con :meth:`nuovo`, che calcola ``risk_score`` e ``severity``
    dagli assi. Il costruttore diretto resta, ma ``__post_init__`` verifica la
    coerenza: non esiste un modo valido di avere un ``risk_score`` che non sia
    il prodotto dei suoi assi.
    """

    id: str
    title: str
    affected_element: str
    category: Category
    source: Source
    evidence: str
    status: Status
    pentest_result: PentestResult
    impact: int
    probability: int
    risk_score: int
    severity: RiskTier
    verification_confidence: VerificationConfidence
    scope: Scope
    recommendation: str
    references: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        atteso = rischio(self.impact, self.probability)
        if self.risk_score != atteso:
            raise ValueError(
                f"{self.id}: risk_score={self.risk_score} non e' impatto×"
                f"probabilita' ({self.impact}×{self.probability}={atteso})"
            )
        atteso_sev = severity_da_score(self.risk_score)
        if self.severity != atteso_sev:
            raise ValueError(
                f"{self.id}: severity={self.severity} non corrisponde al "
                f"punteggio {self.risk_score} (atteso {atteso_sev})"
            )

    @classmethod
    def nuovo(
        cls,
        *,
        id: str,
        title: str,
        affected_element: str,
        category: Category,
        source: Source,
        evidence: str,
        status: Status,
        pentest_result: PentestResult,
        impact: int,
        probability: int,
        verification_confidence: VerificationConfidence,
        recommendation: str,
        references: list[str] | None = None,
        scope: Scope | None = None,
    ) -> Finding:
        """Costruisce un finding derivando rischio e severita' dagli assi.

        ``scope`` si deduce dalla fonte se non dato: una fonte interna non
        puo' produrre un finding "esterno" per distrazione.
        """
        punteggio = rischio(impact, probability)
        return cls(
            id=id,
            title=title,
            affected_element=affected_element,
            category=category,
            source=source,
            evidence=evidence,
            status=status,
            pentest_result=pentest_result,
            impact=impact,
            probability=probability,
            risk_score=punteggio,
            severity=severity_da_score(punteggio),
            verification_confidence=verification_confidence,
            scope=scope if scope is not None else scope_di(source),
            recommendation=recommendation,
            references=list(references or []),
        )

    def to_json(self) -> dict[str, Any]:
        """Oggetto JSON canonico. Chiavi nell'ordine dello schema §7, enum
        come stringa, ``banda`` aggiunta per leggibilita' (descrittiva)."""
        return {
            "id": self.id,
            "title": self.title,
            "affected_element": self.affected_element,
            "category": self.category.value,
            "source": self.source.value,
            "evidence": self.evidence,
            "status": self.status.value,
            "pentest_result": self.pentest_result.value,
            "impact": self.impact,
            "probability": self.probability,
            "risk_score": self.risk_score,
            "severity": self.severity.value,
            "banda": banda_nominale(self.risk_score),
            "verification_confidence": self.verification_confidence.value,
            "scope": self.scope.value,
            "recommendation": self.recommendation,
            "references": list(self.references),
        }


# --------------------------------------------------------------------------- #
# RawResult
#
# L'uscita grezza di un collector, prima della normalizzazione. Porta anche
# l'esito del check (completato/saltato/fallito) e il comando reale, perche'
# un check saltato e il comando che AVREBBE eseguito sono informazione da
# mostrare, non da perdere.
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class RawResult:
    """Output grezzo di un collector."""

    source: Source
    esito: EsitoCheck
    #: Comando reale che il collector esegue (o eseguirebbe). Documentazione e
    #: evidenza insieme: compare nei metadati del run.
    comando: str
    #: Elementi grezzi da normalizzare. Vuoto per un check saltato/fallito, e
    #: anche per un check completato che non ha trovato nulla.
    elementi: list[dict[str, Any]] = field(default_factory=list)
    #: Nota: il motivo di un salto, l'errore di un fallimento, o la nota di
    #: controllo positivo di un check completato a zero finding.
    nota: str = ""
    scope: Scope | None = None

    def __post_init__(self) -> None:
        if self.scope is None:
            self.scope = scope_di(self.source)
        if self.esito is not EsitoCheck.COMPLETATO and self.elementi:
            raise ValueError(
                f"{self.source}: un check {self.esito.value} non puo' portare "
                "elementi — un controllo non riuscito non ha risultati"
            )


__all__ = [
    "Category",
    "EsitoCheck",
    "Finding",
    "FONTI_INTERNE",
    "PentestResult",
    "RawResult",
    "RiskTier",
    "Scope",
    "Source",
    "Status",
    "VerificationConfidence",
    "scope_di",
]
