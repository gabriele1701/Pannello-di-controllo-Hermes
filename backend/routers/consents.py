"""Consensi per scope.

Un consenso autorizza un agente — o un singolo tool di quell'agente — ad
agire su uno scope del perimetro, fino a una scadenza. Serve ai tool di tier
`giallo`, la cui conferma e' una-tantum per scope, e ai tool con il flag dati
personali, qualunque sia il loro tier tecnico.

Due scelte di modellazione che vengono dal dominio:

* **La scadenza e' obbligatoria.** Un consenso che non scade non e' un
  consenso: e' una autorizzazione permanente con un altro nome. Il vincolo e'
  ``NOT NULL`` nel database, non una convenzione.
* **La revoca non cancella.** ``POST /{id}/revoke`` scrive ``revoked_at``, e
  la riga resta. Sapere che un consenso c'e' stato conta tanto quanto sapere
  che non vale piu': una `DELETE` cancellerebbe la seconda informazione
  insieme alla prima.

Lo **stato** — attivo, scaduto, revocato — non e' una colonna. E' derivato
dalle date al momento della lettura, perche' una colonna di stato andrebbe
aggiornata allo scadere e nessun processo la aggiornerebbe: un consenso
scaduto resterebbe marcato attivo.
"""

from __future__ import annotations

import datetime as dt
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.db import get_db
from backend.models import OwnerAgent, ScopeConsent, Tool
from backend.schemas import ConsensoRichiesta, ConsensoRisposta
from backend.security import Operatore

router = APIRouter(prefix="/consents", tags=["consensi"])

#: Stati su cui si puo' filtrare. Insieme chiuso: il filtro si traduce in una
#: condizione scritta qui, mai in un frammento ricevuto dal client.
StatoFiltro = Literal["attivo", "scaduto", "revocato"]


def _risposta(consenso: ScopeConsent, adesso: dt.datetime) -> dict:
    return {
        "id": consenso.id,
        "tool_id": consenso.tool_id,
        "tool_identificativo": consenso.tool.tool_id if consenso.tool else None,
        "agent": consenso.agent,
        "agente_etichetta": consenso.agent.etichetta,
        "scope": consenso.scope,
        "granted_by": consenso.granted_by,
        "granted_at": consenso.granted_at,
        "expires_at": consenso.expires_at,
        "revoked_at": consenso.revoked_at,
        "stato": consenso.stato(adesso),
    }


@router.get("", response_model=list[ConsensoRisposta])
def elenca_consensi(
    operatore: Operatore,
    agent: Annotated[OwnerAgent | None, Query(description="Filtra per agente.")] = None,
    stato: Annotated[
        StatoFiltro | None, Query(description="Filtra per stato calcolato.")
    ] = None,
    db: Session = Depends(get_db),
) -> list[dict]:
    """Elenco dei consensi, filtrabile per agente e per stato.

    Il filtro di stato si applica in SQL e non in Python: con molti consensi,
    filtrare dopo aver letto tutto significherebbe leggere tutto.
    """
    adesso = dt.datetime.now(tz=dt.UTC)
    stmt = select(ScopeConsent)

    if agent is not None:
        stmt = stmt.where(ScopeConsent.agent == agent)

    if stato == "revocato":
        stmt = stmt.where(ScopeConsent.revoked_at.is_not(None))
    elif stato == "scaduto":
        stmt = stmt.where(
            ScopeConsent.revoked_at.is_(None), ScopeConsent.expires_at <= adesso
        )
    elif stato == "attivo":
        stmt = stmt.where(
            ScopeConsent.revoked_at.is_(None), ScopeConsent.expires_at > adesso
        )

    stmt = stmt.order_by(ScopeConsent.granted_at.desc())
    return [_risposta(c, adesso) for c in db.scalars(stmt)]


@router.post("", response_model=ConsensoRisposta, status_code=status.HTTP_201_CREATED)
def concedi_consenso(
    richiesta: ConsensoRichiesta,
    operatore: Operatore,
    db: Session = Depends(get_db),
) -> dict:
    """Registra un consenso."""
    if richiesta.tool_id is not None:
        tool = db.get(Tool, richiesta.tool_id)
        if tool is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"messaggio": f"Nessun tool con id {richiesta.tool_id}."},
            )
        if tool.agent != richiesta.agent:
            # Un consenso che nomina un agente e un tool di un altro agente
            # non descrive niente di eseguibile: solo l'agente proprietario
            # puo' invocare quel tool.
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail={
                    "messaggio": (
                        f"Il tool '{tool.tool_id}' appartiene all'agente "
                        f"'{tool.agent}', non a '{richiesta.agent}'. Solo "
                        f"l'agente proprietario puo' invocare un tool."
                    )
                },
            )

    consenso = ScopeConsent(
        tool_id=richiesta.tool_id,
        agent=richiesta.agent,
        scope=richiesta.scope,
        # L'autore e' l'operatore della sessione, non un campo della richiesta.
        granted_by=operatore.username,
        expires_at=richiesta.expires_at,
    )
    db.add(consenso)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail={"messaggio": "Il consenso viola un vincolo di integrita'."},
        ) from exc
    db.refresh(consenso)
    return _risposta(consenso, dt.datetime.now(tz=dt.UTC))


@router.post("/{consenso_id}/revoke", response_model=ConsensoRisposta)
def revoca_consenso(
    consenso_id: int,
    operatore: Operatore,
    db: Session = Depends(get_db),
) -> dict:
    """Revoca un consenso. La riga resta, con ``revoked_at`` impostato."""
    consenso = db.get(ScopeConsent, consenso_id)
    if consenso is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"messaggio": f"Nessun consenso con id {consenso_id}."},
        )
    if consenso.revoked_at is not None:
        # Idempotente ma dichiarato: una seconda revoca non cambia la data
        # della prima, e sovrascriverla farebbe perdere quando e' avvenuta.
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "messaggio": (
                    f"Il consenso {consenso_id} e' gia' stato revocato il "
                    f"{consenso.revoked_at.isoformat()}."
                )
            },
        )

    consenso.revoked_at = dt.datetime.now(tz=dt.UTC)
    db.commit()
    db.refresh(consenso)
    return _risposta(consenso, dt.datetime.now(tz=dt.UTC))
