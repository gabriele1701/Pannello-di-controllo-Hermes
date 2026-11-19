"""Calcolo del rischio: impatto × probabilità → punteggio → severità.

Il rischio e' il prodotto di due assi interi su scala 1–5, come chiede la
traccia. Il prodotto cade in 1–25, e da li' si ricava la severita'.

Allineamento all'enum reale del repo
------------------------------------

La spec propone quattro bande nominali — *low / medium / high / critical* su
1–4 / 5–9 / 10–15 / 16–25 — ma ordina anche di **non introdurre un enum di
severita' nuovo** e di usare quello che il repo ha gia'. Il repo non ha un
enum ``Severity``: l'unico asse di rischio a colori e' ``RiskTier`` di
``backend.models`` (``verde`` < ``giallo`` < ``rosso``), gli stessi tre valori
di hermes-core. Sono **tre**, non quattro.

Allineare le quattro bande provvisorie ai tre colori reali significa far
collassare le due bande piu' alte sullo stesso colore: in una scala a tre,
``rosso`` *e'* il livello massimo, e deve contenere sia *high* sia *critical*.

    punteggio   banda nominale   RiskTier
    ---------   --------------   --------
    1 – 4       low              verde
    5 – 9       medium           giallo
    10 – 25     high / critical  rosso

La distinzione fine *high* vs *critical* non va persa per questo: resta nel
campo numerico ``risk_score`` del finding (10–15 vs 16–25) e nell'etichetta
``banda_nominale()``. Il colore e' l'enum del dominio; il numero porta il
dettaglio. Il confine giallo/rosso sta a 10 e non a 16 di proposito: in un
tool di sicurezza si arrotonda verso l'alto, non si declassa un *high* a
giallo.
"""

from __future__ import annotations

from backend.models import RiskTier

#: Estremi ammessi per impatto e probabilita'. La scala 1–5 e' quella della
#: traccia; 0 non e' un rischio e 6 non esiste.
ASSE_MIN = 1
ASSE_MAX = 5

#: Soglia inferiore (inclusa) di ciascun tier, sul punteggio 1–25.
#: Scritte come intervalli chiusi per leggerle come la tabella del docstring.
_SOGLIE: tuple[tuple[int, int, RiskTier], ...] = (
    (1, 4, RiskTier.VERDE),
    (5, 9, RiskTier.GIALLO),
    (10, 25, RiskTier.ROSSO),
)

#: Bande nominali della spec, tenute solo come etichetta descrittiva: non
#: sono un vocabolario del dominio (quello e' ``RiskTier``), servono a far
#: leggere nel report il dettaglio che i tre colori non distinguono.
_BANDE_NOMINALI: tuple[tuple[int, int, str], ...] = (
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
    """Punteggio di rischio = impatto × probabilita'.

    Entrambi gli assi sono validati su 1–5: un punteggio calcolato su un asse
    fuori scala sarebbe un numero senza significato, e passarlo oltre
    nasconderebbe l'errore invece di fermarlo.
    """
    i = _valida_asse(impatto, "impatto")
    p = _valida_asse(probabilita, "probabilita")
    return i * p


def severity_da_score(score: int) -> RiskTier:
    """Severita' (``RiskTier``) dal punteggio di rischio 1–25."""
    if not isinstance(score, int) or isinstance(score, bool):
        raise TypeError(f"score deve essere un intero, non {type(score).__name__}")
    for minimo, massimo, tier in _SOGLIE:
        if minimo <= score <= massimo:
            return tier
    raise ValueError(
        f"score = {score} fuori dall'intervallo 1–25; "
        "un punteggio valido e' sempre il prodotto di due assi 1–5"
    )


def banda_nominale(score: int) -> str:
    """Etichetta descrittiva *low/medium/high/critical* dal punteggio.

    Solo per il report: distingue *high* da *critical*, cosa che i tre colori
    di ``RiskTier`` non fanno. Non e' un valore di dominio e non va salvato
    come se lo fosse.
    """
    for minimo, massimo, nome in _BANDE_NOMINALI:
        if minimo <= score <= massimo:
            return nome
    raise ValueError(f"score = {score} fuori dall'intervallo 1–25")
