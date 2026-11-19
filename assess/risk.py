"""Calcolo del rischio: impatto × probabilità → punteggio → severità.

Il rischio è il prodotto di due assi interi su scala 1–5, come chiede la
traccia. Il prodotto cade in 1–25, e da lì si ricava la severità come **banda
nominale** standard: *low / medium / high / critical*.

Perché una banda e non ``RiskTier``
-----------------------------------

Il pannello ha già un enum a colori, ``RiskTier`` (``verde``/``giallo``/
``rosso``), ma è l'asse dell'**invasività di un tool** — quanto è pericoloso
*eseguirlo* — non la **gravità di una vulnerabilità**. Sono due assi che il
pannello tiene separati di proposito: riusare ``RiskTier`` come severità di un
finding li fonderebbe, e per di più legherebbe l'assessor a ``backend``.

Quindi la severità qui è la sua scala propria, le quattro bande sul punteggio
di rischio — né ``RiskTier``, né un enum di dominio nuovo, né una dipendenza da
``backend``. A quattro livelli il confine *high* / *critical* a 16 torna a
contare, cosa che tre soli colori collassavano.

    punteggio   severità
    ---------   --------
    1 – 4       low
    5 – 9       medium
    10 – 15     high
    16 – 25     critical
"""

from __future__ import annotations

#: Estremi ammessi per impatto e probabilità. La scala 1–5 è quella della
#: traccia; 0 non è un rischio e 6 non esiste.
ASSE_MIN = 1
ASSE_MAX = 5

#: Le severità ammesse, dalla meno alla più grave. L'ordine è significativo.
SEVERITA: tuple[str, ...] = ("low", "medium", "high", "critical")

#: Confini (inclusi) di ciascuna banda sul punteggio 1–25. Scritti come
#: intervalli chiusi per leggerli come la tabella del docstring.
_BANDE: tuple[tuple[int, int, str], ...] = (
    (1, 4, "low"),
    (5, 9, "medium"),
    (10, 15, "high"),
    (16, 25, "critical"),
)


def _valida_asse(valore: int, nome: str) -> int:
    if not isinstance(valore, int) or isinstance(valore, bool):
        raise TypeError(f"{nome} deve essere un intero, non {type(valore).__name__}")
    if not (ASSE_MIN <= valore <= ASSE_MAX):
        raise ValueError(
            f"{nome} = {valore} fuori scala: ammessi {ASSE_MIN}–{ASSE_MAX}"
        )
    return valore


def rischio(impatto: int, probabilita: int) -> int:
    """Punteggio di rischio = impatto × probabilità.

    Entrambi gli assi sono validati su 1–5: un punteggio calcolato su un asse
    fuori scala sarebbe un numero senza significato, e passarlo oltre
    nasconderebbe l'errore invece di fermarlo.
    """
    i = _valida_asse(impatto, "impatto")
    p = _valida_asse(probabilita, "probabilita")
    return i * p


def severita_da_score(score: int) -> str:
    """Severità (banda nominale *low/medium/high/critical*) dal punteggio 1–25."""
    if not isinstance(score, int) or isinstance(score, bool):
        raise TypeError(f"score deve essere un intero, non {type(score).__name__}")
    for minimo, massimo, banda in _BANDE:
        if minimo <= score <= massimo:
            return banda
    raise ValueError(
        f"score = {score} fuori dall'intervallo 1–25; "
        "un punteggio valido è sempre il prodotto di due assi 1–5"
    )
