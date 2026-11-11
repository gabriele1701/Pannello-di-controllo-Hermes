"""Perimetro dei bersagli: reti, alias dichiarati, e prefissi di percorso.

DUE PERIMETRI, NON UNO
----------------------

Reti e alias dicono dove puo' arrivare un tool con bersaglio di rete.
`scope_paths` fa la stessa cosa per i file. Sono due perimetri distinti, e
l'interfaccia li mostra separati, perche' cio' che il pannello puo'
promettere sui due non e' la stessa cosa:

* di una rete verifica **l'appartenenza**: il tipo `cidr` e due trigger
  garantiscono che ogni alias cada in una rete dichiarata;
* di un percorso verifica solo **la forma del prefisso**. Che un bersaglio
  cada dentro il perimetro non e' verificabile qui: `/srv/analisi/x`, con `x`
  collegamento simbolico verso `/etc/shadow`, passa qualunque controllo di
  prefisso e apre un altro file. I collegamenti simbolici vivono nel
  filesystem del container, non in questo database.

Quel controllo tocca al gate di `hermes-core`, che risolve il percorso prima
di aprirlo e scrive nel log sia quello richiesto sia quello risolto. E' la
divisione che regge il progetto -- il pannello dichiara, il gate applica -- e
qui si vede che e' una scelta e non una mancanza: un controllo scritto in
questa applicazione sarebbe una promessa che nessuno puo' mantenere.

Due regole delle reti, entrambe applicate nel database e spiegate
dall'applicazione:

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
from backend.models import MAX_PREFISSO, ScopeAlias, ScopeNetwork, ScopePath
from backend.schemas import (
    AliasRichiesta,
    AliasRisposta,
    PercorsoRichiesta,
    PercorsoRisposta,
    ReteRichiesta,
    ReteRisposta,
)
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


# --------------------------------------------------------------------------- #
# Percorsi
# --------------------------------------------------------------------------- #

#: Nome del vincolo violato -> spiegazione per l'operatore.
#:
#: PostgreSQL, davanti a un `CHECK` violato, dice quale vincolo e' stato
#: infranto e niente altro: «new row for relation "scope_paths" violates
#: check constraint "scope_paths_prefix_senza_risalita"». E' l'informazione
#: giusta nella forma sbagliata -- nomina la regola a chi conosce lo schema,
#: non a chi sta compilando un campo.
#:
#: Da qui questa tabella. Non duplica le regole: le traduce. La regola resta
#: una sola, nel database, e vale anche per un `INSERT` fatto a mano; questo
#: dizionario esiste perche' chi usa l'interfaccia legga perche' il valore e'
#: stato rifiutato e cosa scrivere invece.
#:
#: I vincoli hanno un nome parlante proprio per questo: con un unico `CHECK`
#: che sommasse le sette regole, il messaggio direbbe «il prefisso non va
#: bene» e la traduzione sarebbe impossibile.
_SPIEGAZIONI: dict[str, tuple[str, str]] = {
    "scope_paths_prefix_assoluto": (
        "Il prefisso deve essere un percorso assoluto.",
        "Un percorso relativo non significa niente senza sapere qual e' la "
        "directory di lavoro del processo che lo usa, e quella cambia. "
        "Aggiungere la barra iniziale: '/srv/analisi', non 'srv/analisi'.",
    ),
    "scope_paths_prefix_non_radice": (
        "La radice '/' non e' un perimetro.",
        "Dichiarare l'intero filesystem equivale a rinunciare al perimetro, "
        "scrivendolo come se fosse una policy. Dichiarare la directory che "
        "contiene davvero i bersagli.",
    ),
    "scope_paths_prefix_senza_risalita": (
        "Il prefisso non puo' contenere '..'.",
        "Un percorso con '..' ha come antenato una directory diversa da "
        "quella che sembra: '/srv/analisi/..' autorizza '/srv'. Scrivere "
        "direttamente la directory che si intende autorizzare.",
    ),
    "scope_paths_prefix_senza_doppie_barre": (
        "Il prefisso non puo' contenere '//'.",
        "'/srv//analisi' e '/srv/analisi' sono lo stesso percorso per il "
        "sistema e due stringhe diverse per questa tabella: ammetterli "
        "vorrebbe dire dichiarare due volte lo stesso perimetro e crederlo "
        "dichiarato una.",
    ),
    "scope_paths_prefix_senza_barra_finale": (
        "Il prefisso non puo' terminare con '/'.",
        "'/srv/analisi/' e '/srv/analisi' direbbero la stessa cosa in due "
        "righe. Togliere la barra finale.",
    ),
    "scope_paths_prefix_senza_backslash": (
        "Il prefisso non puo' contenere il carattere '\\'.",
        "Su Linux il backslash non separa le directory: in un percorso fa "
        "parte del nome di un file, il che e' legale e quasi sempre un "
        "errore di trascrizione. Usare '/' come separatore.",
    ),
    "scope_paths_prefix_senza_spazi_esterni": (
        "Il prefisso non puo' iniziare o terminare con uno spazio.",
        "'/srv/analisi ' e '/srv/analisi' sono due percorsi diversi per il "
        "sistema e indistinguibili a occhio. Lo spazio non viene rimosso "
        "automaticamente: normalizzarlo significherebbe autorizzare un "
        "percorso che nessuno ha scritto.",
    ),
    "scope_paths_prefix_stampabile": (
        "Il prefisso contiene caratteri di controllo.",
        "Un percorso con caratteri non stampabili non e' trascrivibile in un "
        "file di policy ne' leggibile in una riga di log.",
    ),
    "scope_paths_prefix_lunghezza": (
        f"Il prefisso non puo' superare {MAX_PREFISSO} caratteri.",
        "Il limite viene dal gate: un bersaglio piu' lungo di "
        f"{MAX_PREFISSO} caratteri non entra nella riga di audit e viene "
        "rifiutato all'esecuzione. Un prefisso piu' lungo sarebbe un "
        "perimetro sotto il quale niente e' invocabile.",
    ),
    "scope_paths_label_non_vuota": (
        "L'etichetta non puo' essere vuota.",
        "Serve a chi leggera' il perimetro fra sei mesi: dice perche' quel "
        "percorso e' autorizzato.",
    ),
}


def _nome_vincolo(exc: BaseException) -> str | None:
    """Nome del vincolo violato, dalla diagnostica di PostgreSQL.

    Si legge da `diag.constraint_name` e non dal testo del messaggio: il
    testo cambia fra versioni e fra localizzazioni del server, il campo
    diagnostico no.
    """
    orig = getattr(exc, "orig", None)
    diag = getattr(orig, "diag", None)
    return getattr(diag, "constraint_name", None)


@router.get("/paths", response_model=list[PercorsoRisposta])
def elenca_percorsi(
    operatore: Operatore, db: Session = Depends(get_db)
) -> list[ScopePath]:
    return list(db.scalars(select(ScopePath).order_by(ScopePath.prefix)))


@router.post(
    "/paths",
    response_model=PercorsoRisposta,
    status_code=status.HTTP_201_CREATED,
    responses=risposte(
        {
            409: "Il prefisso e' gia' dichiarato nel perimetro.",
            422: "Il prefisso non e' in forma canonica.",
        }
    ),
)
def aggiungi_percorso(
    richiesta: PercorsoRichiesta,
    operatore: Operatore,
    db: Session = Depends(get_db),
) -> ScopePath:
    """Dichiara un prefisso di percorso nel perimetro.

    Il valore non viene validato qui prima dell'inserimento, e non e' una
    dimenticanza: le regole di forma sono `CHECK` del database, e ripeterle in
    Python vorrebbe dire tenerne due formulazioni destinate a divergere. Si
    tenta l'inserimento, e il rifiuto del database viene tradotto in una
    spiegazione.

    Lo stesso ragionamento degli override del tier, dove il controllo di
    monotonia e' un trigger e non un `if`: una sola formulazione
    dell'invariante, e il criterio «rifiutato sia dall'API sia dal database»
    vero per costruzione invece che per disciplina.
    """
    percorso = ScopePath(prefix=richiesta.prefix, label=richiesta.label)
    db.add(percorso)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        vincolo = _nome_vincolo(exc)

        # L'unico che non e' un problema di forma: il prefisso c'e' gia'.
        if vincolo == "scope_paths_prefix_key":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "messaggio": (
                        f"Il prefisso '{richiesta.prefix}' e' gia' dichiarato "
                        f"nel perimetro."
                    )
                },
            ) from exc

        spiegazione = _SPIEGAZIONI.get(vincolo or "")
        if spiegazione is None:
            # Un vincolo senza traduzione: si rilancia invece di inventare un
            # messaggio generico. Un «valore non valido» al posto della
            # spiegazione vera sarebbe una regressione silenziosa, e un 500
            # con l'eccezione intera nei log dice a chi mantiene il codice
            # che manca una voce in `_SPIEGAZIONI`.
            raise
        messaggio, suggerimento = spiegazione
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail={"messaggio": messaggio, "suggerimento": suggerimento},
        ) from exc

    db.refresh(percorso)
    return percorso


@router.delete(
    "/paths/{percorso_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    responses=risposte({404: "Nessun prefisso con quell'identificativo."}),
)
def rimuovi_percorso(
    percorso_id: int,
    operatore: Operatore,
    db: Session = Depends(get_db),
) -> None:
    """Rimuove un prefisso dal perimetro.

    Nessun vincolo lo impedisce, al contrario della rimozione di una rete:
    togliere un prefisso restringe il perimetro, e non lascia niente fuori
    perche' per i percorsi non esistono alias che vi puntino. E' la stessa
    asimmetria per cui un tier puo' salire e non scendere -- restringere e'
    sempre ammesso.
    """
    percorso = db.get(ScopePath, percorso_id)
    if percorso is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"messaggio": f"Nessun prefisso con id {percorso_id}."},
        )
    db.delete(percorso)
    db.commit()


def _sqlstate(exc: BaseException) -> str | None:
    orig = getattr(exc, "orig", None)
    return getattr(orig, "sqlstate", None)
