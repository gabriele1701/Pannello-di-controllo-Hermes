"""Traduzione degli errori del database in risposte HTTP.

Questa applicazione **non duplica** gli invarianti fra codice e database. I
vincoli vivono nel database — e' il punto dell'architettura — e le rotte si
limitano a tradurre il rifiuto che il database restituisce.

La differenza non e' stilistica. Un controllo applicativo che precede la
scrittura crea una finestra fra il controllo e la scrittura: due richieste
concorrenti possono passare entrambe il controllo e scrivere entrambe. Un
vincolo nel database non ha quella finestra, perche' il controllo *e'* la
scrittura.

Il codice SQLSTATE e' il contratto fra i due livelli:

===========  ===============================================  ====
SQLSTATE     Significato                                      HTTP
===========  ===============================================  ====
``HM409``    il tier non e' superiore a quello effettivo       409
``HM403``    tabella append-only                              403
``HM404``    riferimento a una riga inesistente               404
``HM422``    perimetro violato (alias fuori dalle reti)        422
===========  ===============================================  ====

LA FORMA DEL CORPO E' PARTE DEL CONTRATTO
-----------------------------------------

Tutte le risposte di errore applicative hanno la stessa forma::

    {"detail": {"messaggio": "...", "suggerimento": "..."}}

`ErroreApplicativo` e `RispostaErrore` la dichiarano, e `risposte()` la
mette nelle `responses` delle rotte, cosi' che finisca in `openapi.json`.

Non e' documentazione: e' la ragione per cui l'interfaccia puo' generare un
tipo invece di indovinare la forma a runtime. Finche' non era dichiarata,
`frontend/src/api/errori.ts` era l'unico punto dell'interfaccia che sapeva
qualcosa che il contratto non diceva -- cioe' un accordo verbale fra due
meta' che non si parlano.
"""

from __future__ import annotations

from typing import Any

from fastapi import HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.exc import DBAPIError

#: SQLSTATE applicativi -> codice HTTP.
_STATO_HTTP: dict[str, int] = {
    "HM409": status.HTTP_409_CONFLICT,
    "HM403": status.HTTP_403_FORBIDDEN,
    "HM404": status.HTTP_404_NOT_FOUND,
    "HM422": status.HTTP_422_UNPROCESSABLE_CONTENT,
}


def sqlstate_di(exc: BaseException) -> str | None:
    """Codice SQLSTATE di un'eccezione SQLAlchemy, se c'e'."""
    orig = getattr(exc, "orig", None)
    return getattr(orig, "sqlstate", None)


def _diagnostica(exc: DBAPIError) -> tuple[str, str | None]:
    """Messaggio e suggerimento che il database ha prodotto.

    I trigger scrivono messaggi destinati a essere letti dall'operatore, con
    un HINT che dice cosa fare. Riusarli invece di riscriverli in Python
    tiene una sola formulazione dell'invariante: se il vincolo cambia, il
    messaggio cambia con lui, e non resta indietro.
    """
    orig = getattr(exc, "orig", None)
    diag = getattr(orig, "diag", None)
    messaggio = getattr(diag, "message_primary", None) or "vincolo di integrita' violato"
    suggerimento = getattr(diag, "message_hint", None)
    return messaggio, suggerimento


def traduci_errore_db(exc: DBAPIError) -> HTTPException:
    """Trasforma un rifiuto del database nella risposta HTTP corrispondente.

    Un SQLSTATE non previsto diventa un 500: significa che il database ha
    rifiutato per una ragione che l'applicazione non conosce, e dire
    all'operatore «richiesta non valida» quando in realta' non si sa cosa sia
    successo sarebbe un'informazione falsa.
    """
    stato = _STATO_HTTP.get(sqlstate_di(exc) or "")
    messaggio, suggerimento = _diagnostica(exc)

    if stato is None:
        raise exc

    dettaglio: dict[str, str] = {"messaggio": messaggio}
    if suggerimento:
        dettaglio["suggerimento"] = suggerimento
    return HTTPException(status_code=stato, detail=dettaglio)


# --------------------------------------------------------------------------- #
# La forma dichiarata
# --------------------------------------------------------------------------- #


class ErroreApplicativo(BaseModel):
    """Il contenuto di `detail` in una risposta di errore applicativa."""

    messaggio: str = Field(
        description=(
            "Che cosa e' stato rifiutato, e perche'. Scritto per essere letto "
            "dall'operatore: va mostrato intero, non sostituito con un testo "
            "generico."
        ),
    )
    suggerimento: str | None = Field(
        default=None,
        description=(
            "Che cosa fare invece. Presente quando il rifiuto viene da un "
            "trigger che lo dichiara nel proprio HINT; assente altrimenti."
        ),
    )


class RispostaErrore(BaseModel):
    """Il corpo intero, `detail` compreso.

    FastAPI avvolge il `detail` di una `HTTPException` in un oggetto, quindi
    il corpo che arriva al client e' questo e non `ErroreApplicativo` da
    solo. Dichiarare il modello interno e chiamarlo contratto sarebbe
    dichiarare una forma che nessuna risposta ha.
    """

    detail: ErroreApplicativo


#: Riferimenti agli schemi dentro il documento OpenAPI.
#:
#: Scritti a mano perche' servono dentro un `anyOf`, e FastAPI costruisce un
#: `anyOf` solo da un'annotazione di tipo. `RispostaErrore` finisce fra i
#: componenti perche' qualche rotta lo usa come `model` -- il 401 dichiarato
#: sul router protetto, che vale per tutte -- e `HTTPValidationError` perche'
#: FastAPI lo genera da se' per ogni rotta con parametri validati.
#:
#: Sono due dipendenze implicite, e un riferimento che non risolve produce un
#: documento rotto senza lamentarsi. Per questo
#: `tests/test_contratto_errori.py` verifica che ogni `$ref` risolva.
_RIF_APPLICATIVO = {"$ref": "#/components/schemas/RispostaErrore"}
_RIF_VALIDAZIONE = {"$ref": "#/components/schemas/HTTPValidationError"}


def risposte(
    descrizioni: dict[int, str],
    *,
    validazione: str | None = None,
) -> dict[int | str, dict[str, Any]]:
    """Costruisce le `responses` di una rotta dai codici che produce davvero.

    Si dichiarano solo i codici che quella rotta puo' restituire. Un elenco
    uguale per tutte sarebbe piu' corto da scrivere e meno vero: direbbe
    all'interfaccia di gestire un 409 su una rotta che non lo produce mai, e
    tacerebbe quando una rotta ne guadagna uno.

    IL CASO DEL 422, che ha due forme.

    Quando una rotta ha parametri validati -- quasi tutte -- FastAPI dichiara
    da se' un 422 con lo schema di Pydantic. Se quella rotta puo' rifiutare
    *anche* per una ragione di dominio, allo stesso codice corrispondono due
    corpi diversi, e dichiararne uno solo sarebbe falso. I due casi si
    distinguono qui:

    - `422` fra le `descrizioni`: entrambe le forme sono possibili, e il
      contratto le dichiara come `anyOf`;
    - `validazione="..."`: solo quella di Pydantic. E' il caso di una rotta
      il cui rifiuto di dominio sta in un validator e non in un trigger.

    NON SI PASSA UNA DESCRIZIONE NUDA. `responses={422: {"description":
    "..."}}` non cambia il testo di cio' che FastAPI genera: **sostituisce
    l'intera voce**, schema compreso, e il risultato e' un 422 dichiarato
    senza alcuna forma. Due rotte di `scope.py` lo facevano, in buona fede,
    e il loro tentativo di documentare meglio il 422 aveva cancellato
    l'unica cosa che l'interfaccia poteva generare. Per questo `validazione`
    esiste come parametro invece che come convenzione: e' un errore che non
    si vede rileggendo il codice, solo rileggendo `openapi.json`.
    """
    if validazione is not None and status.HTTP_422_UNPROCESSABLE_CONTENT in descrizioni:
        raise ValueError(
            "Il 422 e' dichiarato due volte, una come forma applicativa e una "
            "come sola validazione. Sono alternative: se la rotta puo' "
            "rifiutare per entrambe le ragioni, va dichiarato solo fra le "
            "descrizioni, che produce l'anyOf."
        )

    costruite: dict[int | str, dict[str, Any]] = {}
    for codice, descrizione in sorted(descrizioni.items()):
        if codice == status.HTTP_422_UNPROCESSABLE_CONTENT:
            costruite[codice] = _con_schema(
                descrizione, {"anyOf": [_RIF_APPLICATIVO, _RIF_VALIDAZIONE]}
            )
        else:
            costruite[codice] = {
                "model": RispostaErrore,
                "description": descrizione,
            }

    if validazione is not None:
        costruite[status.HTTP_422_UNPROCESSABLE_CONTENT] = _con_schema(
            validazione, _RIF_VALIDAZIONE
        )

    return costruite


def _con_schema(descrizione: str, schema: dict[str, Any]) -> dict[str, Any]:
    """Voce di `responses` con descrizione e schema espliciti."""
    return {
        "description": descrizione,
        "content": {"application/json": {"schema": schema}},
    }
