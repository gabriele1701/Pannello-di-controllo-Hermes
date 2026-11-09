"""Vista del log d'audit. Sola lettura.

Questa applicazione **non e' la fonte di verita' del log**. La fonte e' un
file JSONL append-only con ``chattr +a`` sulla macchina del server MCP, dove
nemmeno il processo che lo scrive puo' riscriverlo. Questa tabella e' una
copia ricostruibile e scartabile, che esiste per poter interrogare e
correlare — cose che su un file di testo si fanno male.

La conseguenza e' il contenuto di questo modulo: **due rotte, entrambe
``GET``**. Nessun ``POST``, nessun ``PUT``, nessun ``PATCH``, nessun
``DELETE``. Non «non implementati ancora»: non devono esistere. Un pannello
che potesse scrivere nel log sarebbe un pannello che puo' riscrivere la
traccia di cio' che ha autorizzato, e la traccia e' il prodotto di tutto il
sistema.

Le righe arrivano dai dati seed in questa consegna, e dall'ingestione del
file JSONL dopo. In nessuno dei due casi passano da un'API.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.db import get_db
from backend.models import AuditEvent, CallOutcome, LogAction, OwnerAgent
from backend.schemas import CatenaEventi, Limite, PaginaEventi, Scarto
from backend.security import Operatore

router = APIRouter(prefix="/audit", tags=["log"])


@router.get("", response_model=PaginaEventi)
def elenca_eventi(
    operatore: Operatore,
    correlation_id: Annotated[uuid.UUID | None, Query()] = None,
    agent: Annotated[OwnerAgent | None, Query()] = None,
    tool_id: Annotated[str | None, Query(max_length=64)] = None,
    event_type: Annotated[LogAction | None, Query()] = None,
    outcome: Annotated[CallOutcome | None, Query()] = None,
    da: Annotated[dt.datetime | None, Query(description="Estremo iniziale, incluso.")] = None,
    a: Annotated[dt.datetime | None, Query(description="Estremo finale, escluso.")] = None,
    limite: Annotated[Limite, Query()] = 50,
    scarto: Annotated[Scarto, Query()] = 0,
    db: Session = Depends(get_db),
) -> dict:
    """Log filtrabile e paginato, dal piu' recente.

    Ogni filtro e' tipizzato: gli enum arrivano come enum, le date come date,
    ``tool_id`` come stringa con un tetto di lunghezza. Non esiste un
    parametro di ordinamento, ne' uno di ricerca libera: entrambi sarebbero
    un modo di far arrivare del testo del client dentro una clausola SQL.

    L'ordinamento e' fisso: ``occurred_at`` discendente, con ``id``
    discendente a parita'. Il secondo criterio non e' decorativo — piu'
    eventi della stessa catena possono avere lo stesso istante al
    microsecondo, e senza un criterio di spareggio la paginazione potrebbe
    restituire la stessa riga su due pagine e perderne un'altra.
    """
    condizioni = []
    if correlation_id is not None:
        condizioni.append(AuditEvent.correlation_id == correlation_id)
    if agent is not None:
        condizioni.append(AuditEvent.agent == agent)
    if tool_id is not None:
        condizioni.append(AuditEvent.tool_id == tool_id)
    if event_type is not None:
        condizioni.append(AuditEvent.event_type == event_type)
    if outcome is not None:
        condizioni.append(AuditEvent.outcome == outcome)
    if da is not None:
        condizioni.append(AuditEvent.occurred_at >= da)
    if a is not None:
        condizioni.append(AuditEvent.occurred_at < a)

    if da is not None and a is not None and da >= a:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "messaggio": (
                    "L'intervallo e' vuoto: l'estremo iniziale non precede "
                    "quello finale."
                )
            },
        )

    totale = db.scalar(
        select(func.count()).select_from(AuditEvent).where(*condizioni)
    ) or 0

    eventi = db.scalars(
        select(AuditEvent)
        .where(*condizioni)
        .order_by(AuditEvent.occurred_at.desc(), AuditEvent.id.desc())
        .limit(limite)
        .offset(scarto)
    ).all()

    return {
        "totale": totale,
        "limite": limite,
        "scarto": scarto,
        "eventi": list(eventi),
    }


@router.get("/{correlation_id}", response_model=CatenaEventi)
def catena(
    correlation_id: uuid.UUID,
    operatore: Operatore,
    db: Session = Depends(get_db),
) -> dict:
    """La catena completa di un ``correlation_id``, in ordine cronologico.

    Crescente, non decrescente come l'elenco: una catena si legge dall'inizio
    — l'agente invocato, le chiamate ai tool, il risultato — perche' e' una
    sequenza causale e non un elenco di righe recenti.

    Non e' paginata: una catena e' lunga quanto e' lunga, e troncarla
    nasconderebbe proprio il passo finale, che e' quello che dice com'e'
    andata.
    """
    eventi = db.scalars(
        select(AuditEvent)
        .where(AuditEvent.correlation_id == correlation_id)
        .order_by(AuditEvent.occurred_at.asc(), AuditEvent.id.asc())
    ).all()

    if not eventi:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"messaggio": f"Nessun evento con correlation_id {correlation_id}."},
        )

    return {"correlation_id": correlation_id, "eventi": list(eventi)}
