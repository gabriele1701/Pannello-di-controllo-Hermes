"""Perimetro dei bersagli: reti autorizzate e alias dichiarati.

Due regole, entrambe applicate nel database e spiegate dall'applicazione:

* **Forma canonica.** `192.168.205.10/24` viene rifiutato. Il tipo `cidr` di
  PostgreSQL lo rifiuta da solo, ma il suo messaggio dice che il valore non e'
  valido senza dire perche'; la validazione Pydantic lo intercetta prima e
  spiega che quel valore verrebbe letto come l'intera `/24`, cioe' come 254
  indirizzi invece di uno.
* **Ogni alias dentro una rete dichiarata.** Applicata da due trigger, perche'
  ci sono due modi di violarla: inserire un alias fuori, oppure togliere la
  rete che lo conteneva.

Nessuna risoluzione DNS, da nessuna parte. Gli alias sono una tabella
dichiarata dall'operatore, non un'interrogazione: un nome risolto al momento
del controllo puo' puntare altrove al momento dell'esecuzione.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.orm import Session

from backend.db import get_db
from backend.errors import risposte, traduci_errore_db
from backend.models import ScopeAlias, ScopeNetwork
from backend.schemas import AliasRichiesta, AliasRisposta, ReteRichiesta, ReteRisposta
from backend.security import Operatore

router = APIRouter(prefix="/scope", tags=["perimetro"])


# --------------------------------------------------------------------------- #
# Reti
# --------------------------------------------------------------------------- #


@router.get("/networks", response_model=list[ReteRisposta])
def elenca_reti(operatore: Operatore, db: Session = Depends(get_db)) -> list[ScopeNetwork]:
    return list(db.scalars(select(ScopeNetwork).order_by(ScopeNetwork.cidr)))


@router.post(
    "/networks",
    response_model=ReteRisposta,
    status_code=status.HTTP_201_CREATED,
    responses=risposte(
        {409: "La rete e' gia' dichiarata nel perimetro."},
        # Il 422 di questa rotta ha una forma sola, quella di Pydantic: la
        # forma canonica della CIDR la verifica un validator di `schemas.py`,
        # non un trigger. Prima qui c'era `{422: {"description": ...}}`, che
        # sembrava cambiare il testo e invece cancellava lo schema.
        validazione="CIDR non in forma canonica, oppure campi mancanti.",
    ),
)
def aggiungi_rete(
    richiesta: ReteRichiesta,
    operatore: Operatore,
    db: Session = Depends(get_db),
) -> ScopeNetwork:
    """Dichiara una rete nel perimetro.

    La forma canonica e' gia' stata verificata da Pydantic, che ha anche
    normalizzato il valore. Il tipo `cidr` resta come vincolo di integrita'
    sotto: due livelli indipendenti, e quello che parla all'operatore e'
    quello che sa spiegare.
    """
    rete = ScopeNetwork(cidr=richiesta.cidr, label=richiesta.label)
    db.add(rete)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "messaggio": f"La rete '{richiesta.cidr}' e' gia' dichiarata nel perimetro."
            },
        ) from exc
    db.refresh(rete)
    return rete


@router.delete(
    "/networks/{rete_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    responses=risposte(
        {
            404: "Nessuna rete con quell'identificativo.",
            422: "Rimuovere la rete lascerebbe degli alias fuori perimetro.",
        }
    ),
)
def rimuovi_rete(
    rete_id: int,
    operatore: Operatore,
    db: Session = Depends(get_db),
) -> None:
    """Rimuove una rete dal perimetro.

    Rifiutata con 422 se qualche alias resterebbe fuori perimetro: lo
    verifica un trigger, non questo codice. Un perimetro che contenga un
    alias non contenuto da nessuna rete direbbe nello stesso momento che
    quell'indirizzo e' ammesso e che non lo e'.
    """
    rete = db.get(ScopeNetwork, rete_id)
    if rete is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"messaggio": f"Nessuna rete con id {rete_id}."},
        )
    db.delete(rete)
    try:
        db.commit()
    except DBAPIError as exc:
        db.rollback()
        raise traduci_errore_db(exc) from exc


# --------------------------------------------------------------------------- #
# Alias
# --------------------------------------------------------------------------- #


@router.get("/aliases", response_model=list[AliasRisposta])
def elenca_alias(operatore: Operatore, db: Session = Depends(get_db)) -> list[ScopeAlias]:
    return list(db.scalars(select(ScopeAlias).order_by(ScopeAlias.name)))


@router.post(
    "/aliases",
    response_model=AliasRisposta,
    status_code=status.HTTP_201_CREATED,
    responses=risposte(
        {
            409: "Un alias con quel nome esiste gia'.",
            422: "L'alias non cade in nessuna rete dichiarata del perimetro.",
        }
    ),
)
def aggiungi_alias(
    richiesta: AliasRichiesta,
    operatore: Operatore,
    db: Session = Depends(get_db),
) -> ScopeAlias:
    """Dichiara un alias.

    Il contenimento nelle reti del perimetro lo verifica il trigger
    ``scope_aliases_dentro_perimetro_trg``, che restituisce SQLSTATE
    ``HM422`` con l'elenco delle reti dichiarate nel suggerimento. Qui non
    viene riverificato: sarebbe la stessa regola scritta due volte, e due
    scritture divergono.
    """
    alias = ScopeAlias(name=richiesta.name, address=richiesta.address)
    db.add(alias)
    try:
        db.commit()
    except DBAPIError as exc:
        db.rollback()
        # Un nome duplicato e' un conflitto, non una violazione del perimetro:
        # IntegrityError senza uno dei nostri SQLSTATE applicativi.
        if isinstance(exc, IntegrityError) and _sqlstate(exc) == "23505":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"messaggio": f"L'alias '{richiesta.name}' esiste gia'."},
            ) from exc
        raise traduci_errore_db(exc) from exc
    db.refresh(alias)
    return alias


@router.delete(
    "/aliases/{alias_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    responses=risposte({404: "Nessun alias con quell'identificativo."}),
)
def rimuovi_alias(
    alias_id: int,
    operatore: Operatore,
    db: Session = Depends(get_db),
) -> None:
    """Rimuove un alias.

    Non c'e' vincolo che lo impedisca: togliere un alias restringe il
    perimetro, e restringere e' sempre ammesso. E' l'asimmetria del dominio —
    la stessa per cui un tier puo' salire e non scendere.
    """
    alias = db.get(ScopeAlias, alias_id)
    if alias is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"messaggio": f"Nessun alias con id {alias_id}."},
        )
    db.delete(alias)
    db.commit()


def _sqlstate(exc: BaseException) -> str | None:
    orig = getattr(exc, "orig", None)
    return getattr(orig, "sqlstate", None)
