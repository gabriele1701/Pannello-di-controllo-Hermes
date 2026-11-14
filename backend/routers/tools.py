"""Catalogo dei tool e innalzamento del tier.

E' la parte che dimostra il modello di sicurezza. Tre rotte, e nessuna di
piu':

* ``GET /tools`` — il catalogo, con il tier effettivo calcolato.
* ``GET /tools/{tool_id}`` — dettaglio e storico degli override.
* ``POST /tools/{tool_id}/overrides`` — innalzamento.

Quello che **non** c'e' e' significativo quanto quello che c'e':

* nessuna rotta che crei o modifichi un tool: li registra hermes-core
  all'avvio, e l'identita' ``(exec_path, exec_sha256, exec_args)`` e' di sola
  lettura per questa applicazione;
* nessun ``PUT``, ``PATCH`` o ``DELETE`` sugli override: la tabella e'
  append-only, e un'API di rimozione sarebbe un declassamento con
  un'interfaccia comoda — una volta che esiste, finisce per essere chiamata
  da qualcosa di automatico.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from backend.db import get_db
from backend.errors import risposte, traduci_errore_db
from backend.models import RiskTier, TierOverride, Tool, tool_effective_tier
from backend.schemas import (
    OverrideRichiesta,
    OverrideRisposta,
    ToolDettaglio,
    ToolRiepilogo,
)
from backend.security import Operatore

router = APIRouter(prefix="/tools", tags=["tool"])


def _riepilogo(tool: Tool, riga) -> dict:
    """Campi comuni fra catalogo e dettaglio."""
    return {
        "id": tool.id,
        "tool_id": tool.tool_id,
        "agent": tool.agent,
        "agente_etichetta": tool.agent.etichetta,
        "declared_tier": tool.declared_tier,
        "effective_tier": riga.effective_tier,
        # La divergenza fra dichiarato ed effettivo la calcola il server, non
        # l'interfaccia: e' la regola che l'interfaccia evidenzia, e tenerla
        # in un posto solo evita che due client la interpretino diversamente.
        "tier_innalzato": riga.effective_tier != tool.declared_tier,
        "personal_data": tool.personal_data,
        "requires_container": tool.requires_container,
        "target_kind": tool.target_kind,
        "bersaglio_etichetta": tool.target_kind.etichetta,
        "description": tool.description,
        "override_count": riga.override_count,
        "last_override_at": riga.last_override_at,
    }


def _override_risposta(o: TierOverride) -> dict:
    return {
        "id": o.id,
        "tier": o.tier,
        "reason": o.reason,
        "source": o.source,
        "source_descrizione": o.source.descrizione,
        "created_by": o.created_by,
        "created_at": o.created_at,
    }


@router.get("", response_model=list[ToolRiepilogo])
def elenca_tool(
    operatore: Operatore,
    db: Session = Depends(get_db),
) -> list[dict]:
    """Il catalogo, con il tier effettivo preso dalla vista del database.

    Il tier effettivo non viene ricalcolato in Python: lo legge dalla vista,
    che e' dove la regola `max(dichiarato, override)` e' definita. Due
    implementazioni della stessa regola sono due occasioni di scriverla
    diversamente.
    """
    vista = tool_effective_tier
    righe = db.execute(
        select(
            Tool,
            vista.c.effective_tier,
            vista.c.override_count,
            vista.c.last_override_at,
        )
        .join(vista, vista.c.tool_pk == Tool.id)
        # Ordine fisso: agente, poi identificativo. Non e' un parametro della
        # richiesta — una rotta che accetti un campo di ordinamento arbitrario
        # accetta un frammento di SQL.
        .order_by(Tool.agent, Tool.tool_id)
    ).all()
    return [_riepilogo(r[0], r) for r in righe]


def _cerca_tool(db: Session, tool_id: str) -> tuple[Tool, object]:
    vista = tool_effective_tier
    riga = db.execute(
        select(
            Tool,
            vista.c.effective_tier,
            vista.c.override_count,
            vista.c.last_override_at,
        )
        .join(vista, vista.c.tool_pk == Tool.id)
        .where(Tool.tool_id == tool_id)
    ).one_or_none()
    if riga is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"messaggio": f"Nessun tool registrato con identificativo '{tool_id}'."},
        )
    return riga[0], riga


@router.get(
    "/{tool_id}",
    response_model=ToolDettaglio,
    responses=risposte({404: "Nessun tool registrato con quell'identificativo."}),
)
def dettaglio_tool(
    tool_id: str,
    operatore: Operatore,
    db: Session = Depends(get_db),
) -> dict:
    """Dettaglio: identita', i due assi, storico degli override."""
    tool, riga = _cerca_tool(db, tool_id)
    effettivo = RiskTier(riga.effective_tier)
    return {
        **_riepilogo(tool, riga),
        "exec_path": tool.exec_path,
        "exec_sha256": tool.exec_sha256,
        "exec_args": list(tool.exec_args),
        "registered_at": tool.registered_at,
        "overrides": [_override_risposta(o) for o in tool.overrides],
        # Solo i tier superiori all'effettivo. Vuoto quando il tool e' gia' a
        # `rosso`: l'interfaccia non mostra allora nessuna azione, invece di
        # mostrarne una disabilitata. Un'opzione disabilitata insegna che
        # esiste un modo e che oggi non e' attivo.
        "tier_disponibili": list(effettivo.superiori()),
    }


@router.post(
    "/{tool_id}/overrides",
    response_model=OverrideRisposta,
    status_code=status.HTTP_201_CREATED,
    responses=risposte(
        {
            404: "Nessun tool registrato con quell'identificativo.",
            409: "Il tier richiesto non innalza il tier effettivo corrente.",
        }
    ),
)
def innalza_tier(
    tool_id: str,
    richiesta: OverrideRichiesta,
    operatore: Operatore,
    db: Session = Depends(get_db),
) -> dict:
    """Registra un innalzamento del tier.

    **Non c'e' un controllo di monotonia in questa funzione**, e l'assenza e'
    deliberata. Il vincolo e' un trigger del database: l'inserimento viene
    tentato e, se il tier non innalza, il database lo rifiuta con SQLSTATE
    ``HM409``, che qui diventa un 409.

    Due ragioni per farlo cosi' e non con un `if` prima dell'INSERT:

    1. **Non c'e' finestra.** Un controllo applicativo che precede la
       scrittura lascia uno spazio fra la lettura del tier corrente e
       l'inserimento: due richieste concorrenti possono leggere entrambe lo
       stesso valore e passare entrambe. Il trigger prende un lock sulla riga
       del tool, quindi la seconda richiesta attende e rilegge.
    2. **Non c'e' divergenza.** Con il controllo in due posti, uno dei due
       prima o poi cambia senza l'altro. Qui esiste una sola formulazione
       dell'invariante, e il criterio «rifiutato sia dall'API sia dal
       database» e' vero per costruzione invece che per disciplina.
    """
    tool, _ = _cerca_tool(db, tool_id)

    override = TierOverride(
        tool_id=tool.id,
        tier=richiesta.tier,
        reason=richiesta.reason.strip(),
        # L'autore e' l'operatore della sessione, non un campo della
        # richiesta: un client non deve poter dichiarare di essere qualcun
        # altro nello storico che serve a sapere chi ha fatto cosa.
        created_by=operatore.username,
    )
    db.add(override)
    try:
        db.commit()
    except DBAPIError as exc:
        db.rollback()
        raise traduci_errore_db(exc) from exc

    db.refresh(override)
    return _override_risposta(override)
