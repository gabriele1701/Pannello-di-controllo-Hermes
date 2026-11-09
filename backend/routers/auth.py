"""Autenticazione dell'operatore."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.config import Settings, get_settings
from backend.db import get_db
from backend.models import User
from backend.schemas import LoginRichiesta, OperatoreRisposta
from backend.security import (
    Operatore,
    apri_sessione,
    chiudi_sessione,
    cifra_password,
    verifica_password,
)

router = APIRouter(prefix="/auth", tags=["autenticazione"])

#: Hash di riferimento su cui verificare quando l'utente non esiste.
#:
#: Senza, il tempo di risposta direbbe se un nome utente esiste: con un utente
#: assente la rotta tornerebbe subito, con uno presente dopo la verifica
#: argon2, che e' lenta per costruzione. Verificare comunque contro un hash
#: finto rende i due casi indistinguibili nel tempo.
_HASH_FINTO = cifra_password("utente-inesistente-segnaposto")

_CREDENZIALI_ERRATE = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    # Un solo messaggio per entrambi i casi: dire «utente inesistente»
    # confermerebbe a chi prova quali nomi utente esistono.
    detail={"messaggio": "Credenziali non valide."},
)


@router.post("/login", response_model=OperatoreRisposta)
def login(
    richiesta: LoginRichiesta,
    response: Response,
    db: Session = Depends(get_db),
    impostazioni: Settings = Depends(get_settings),
) -> User:
    """Autentica l'operatore e apre la sessione."""
    utente = db.scalar(select(User).where(User.username == richiesta.username))

    if utente is None:
        verifica_password(_HASH_FINTO, richiesta.password)
        raise _CREDENZIALI_ERRATE

    if not verifica_password(utente.password_hash, richiesta.password):
        raise _CREDENZIALI_ERRATE

    apri_sessione(response, utente, impostazioni)
    return utente


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    response: Response,
    impostazioni: Settings = Depends(get_settings),
) -> None:
    """Chiude la sessione.

    Non richiede l'autenticazione: chiudere una sessione gia' scaduta o
    invalida deve riuscire comunque, altrimenti un cookie rotto resterebbe
    nel browser senza un modo di toglierlo.
    """
    chiudi_sessione(response, impostazioni)


@router.get("/me", response_model=OperatoreRisposta)
def me(operatore: Operatore) -> User:
    """L'operatore della sessione corrente."""
    return operatore
