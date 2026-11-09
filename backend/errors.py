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
"""

from __future__ import annotations

from fastapi import HTTPException, status
from sqlalchemy.exc import DBAPIError

#: SQLSTATE applicativi -> codice HTTP.
_STATO_HTTP: dict[str, int] = {
    "HM409": status.HTTP_409_CONFLICT,
    "HM403": status.HTTP_403_FORBIDDEN,
    "HM404": status.HTTP_404_NOT_FOUND,
    "HM422": status.HTTP_422_UNPROCESSABLE_ENTITY,
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
