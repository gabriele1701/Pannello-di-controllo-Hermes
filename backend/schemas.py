"""Contratti di ingresso e di uscita delle rotte.

Ogni rotta valida l'ingresso con Pydantic. ``extra="forbid"`` su tutti i
modelli di ingresso: un payload con campi non previsti viene **rifiutato**,
non accettato ignorando l'ignoto. Un contratto permissivo e' una superficie
d'attacco, e qui e' anche un modo di sbagliare in silenzio — un campo scritto
male verrebbe buttato via e chi ha fatto la richiesta crederebbe di averlo
impostato.

I messaggi di errore spiegano **perche'** un valore e' rifiutato, non solo
che lo e'. Per il perimetro dei bersagli non e' cortesia: `192.168.205.10/24`
e' un errore che si commette credendo di aver dichiarato l'host, e un
messaggio che dica soltanto «valore non valido» lascia chi lo legge a
riscrivere lo stesso errore in un'altra forma.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import uuid
from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
)

from backend.models import (
    AuthorizedBy,
    CallOutcome,
    LogAction,
    OverrideSource,
    OwnerAgent,
    RiskTier,
    MAX_PREFISSO,
    TargetKind,
)

_INGRESSO = ConfigDict(extra="forbid", str_strip_whitespace=True)
_USCITA = ConfigDict(from_attributes=True)


# --------------------------------------------------------------------------- #
# Autenticazione
# --------------------------------------------------------------------------- #


class LoginRichiesta(BaseModel):
    model_config = _INGRESSO

    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=512)


class OperatoreRisposta(BaseModel):
    model_config = _USCITA

    id: int
    username: str
    created_at: dt.datetime


# --------------------------------------------------------------------------- #
# Tool
# --------------------------------------------------------------------------- #


class ToolRiepilogo(BaseModel):
    """Riga del catalogo.

    Porta **entrambi** i tier. L'interfaccia evidenzia la divergenza fra
    dichiarato ed effettivo: e' il segnale che un override e' attivo, e
    mostrare solo l'effettivo nasconderebbe che qualcuno e' intervenuto.
    """

    model_config = _USCITA

    id: int
    tool_id: str
    agent: OwnerAgent
    agente_etichetta: str
    declared_tier: RiskTier
    effective_tier: RiskTier
    #: Vero quando un override e' attivo. Lo calcola il server e non
    #: l'interfaccia, cosi' la regola sta in un posto solo.
    tier_innalzato: bool
    personal_data: bool
    requires_container: bool
    target_kind: TargetKind
    #: Etichetta leggibile del tipo di bersaglio. La calcola il server come
    #: `agente_etichetta`: e' un vocabolario del dominio, e due client che lo
    #: traducessero da se' prima o poi lo tradurrebbero diversamente.
    bersaglio_etichetta: str
    description: str
    override_count: int
    last_override_at: dt.datetime | None


class OverrideRisposta(BaseModel):
    """Riga dello storico degli innalzamenti."""

    model_config = _USCITA

    id: int
    tier: RiskTier
    reason: str
    source: OverrideSource
    source_descrizione: str
    created_by: str
    created_at: dt.datetime


class ToolDettaglio(ToolRiepilogo):
    """Dettaglio di un tool: identita', i due assi, storico degli override."""

    #: Identita' di cio' che viene eseguito: (percorso, SHA, argomenti fissi).
    #: Di sola lettura: li registra hermes-core all'avvio.
    exec_path: str
    exec_sha256: str
    exec_args: list[str]
    registered_at: dt.datetime
    overrides: list[OverrideRisposta]
    #: I tier che l'operatore puo' ancora scegliere: solo quelli superiori
    #: all'effettivo. Vuoto quando il tool e' gia' a `rosso`.
    tier_disponibili: list[RiskTier]


class OverrideRichiesta(BaseModel):
    """Innalzamento richiesto dall'operatore.

    Non c'e' un campo per abbassare, e non c'e' un campo `source`: un
    override creato da questa interfaccia e' per definizione registrato
    nello store, mentre `config` descrive una riga scritta nella
    configurazione versionata di hermes-core, che da qui non si tocca.
    """

    model_config = _INGRESSO

    tier: RiskTier
    #: Obbligatorio. Un innalzamento senza motivo e' illeggibile a distanza
    #: di mesi, che e' quando lo si rilegge.
    reason: str = Field(min_length=3, max_length=1024)

    @field_validator("reason")
    @classmethod
    def _motivo_non_vuoto(cls, v: str) -> str:
        if not v.strip():
            raise ValueError(
                "Il motivo e' obbligatorio: serve a chi rileggera' lo storico "
                "fra mesi per capire perche' questo tool sta dov'e'."
            )
        return v


# --------------------------------------------------------------------------- #
# Perimetro
# --------------------------------------------------------------------------- #


class ReteRisposta(BaseModel):
    model_config = _USCITA

    id: int
    cidr: str
    label: str


class ReteRichiesta(BaseModel):
    model_config = _INGRESSO

    cidr: str = Field(min_length=9, max_length=43)
    label: str = Field(min_length=1, max_length=128)

    @field_validator("cidr")
    @classmethod
    def _forma_canonica(cls, v: str) -> str:
        """Accetta solo l'indirizzo di rete, non un host con la maschera.

        `192.168.205.10/24` non viene rifiutato per pedanteria: Python e
        PostgreSQL lo leggerebbero come l'intera `192.168.205.0/24`, cioe'
        come un perimetro **piu' largo** di quello che chi scrive crede di
        dichiarare. Chi scrive quella riga pensa di aver autorizzato un host
        e ne ha autorizzati 254.
        """
        if "/" not in v:
            raise ValueError(
                f"'{v}' non ha la maschera di rete. Una rete del perimetro si "
                f"dichiara in notazione CIDR, per esempio '192.168.205.0/24'. "
                f"Per un singolo indirizzo la maschera e' /32."
            )
        try:
            rete = ipaddress.ip_network(v, strict=True)
        except ValueError:
            # strict=False dice se il valore e' comunque interpretabile, e
            # quindi quale rete l'operatore sta dichiarando per sbaglio.
            try:
                interpretata = ipaddress.ip_network(v, strict=False)
            except ValueError as err:
                raise ValueError(
                    f"'{v}' non e' una rete valida: {err}"
                ) from err
            raise ValueError(
                f"'{v}' non e' in forma canonica: ha dei bit a destra della "
                f"maschera, quindi non e' l'indirizzo di una rete ma un host "
                f"dentro una. Verrebbe interpretato come "
                f"'{interpretata}', cioe' {interpretata.num_addresses} "
                f"indirizzi invece di uno. Dichiarare "
                f"'{interpretata}' se si intende tutta la rete, oppure "
                f"'{v.split('/')[0]}/32' se si intende quel solo indirizzo."
            ) from None
        return str(rete)


class PercorsoRisposta(BaseModel):
    model_config = _USCITA

    id: int
    prefix: str
    label: str


class PercorsoRichiesta(BaseModel):
    """Prefisso di percorso da dichiarare nel perimetro.

    Deliberatamente senza validator di forma, al contrario di
    `ReteRichiesta`. Le otto regole sul prefisso sono `CHECK` nel database, e
    riscriverle qui vorrebbe dire tenerne due formulazioni: la rotta traduce
    il nome del vincolo violato in una spiegazione, cosi' la regola resta in
    un posto solo e vale anche per un `INSERT` fatto a mano in `psql`.

    DUE DEVIAZIONI DA `_INGRESSO`, entrambe trovate da un test che falliva.

    1. **Il prefisso non viene ripulito degli spazi.** `_INGRESSO` imposta
       `str_strip_whitespace=True`, che su questo campo faceva una cosa
       precisa e sbagliata: `/srv/analisi ` arrivava al database come
       `/srv/analisi`, cioe' l'API rispondeva 201 autorizzando un percorso
       **diverso** da quello digitato. Per il kernel sono due directory
       distinte, e quale delle due fosse intesa non lo sa l'applicazione.

       E' la stessa scelta di `hermes-core` sul bersaglio di un'invocazione:
       si rifiuta invece di normalizzare, perche' «normalizzare significa
       eseguire qualcosa di diverso da cio' che e' stato chiesto»
       (`mcp_server/scope.py`). Lo spazio resta, il database rifiuta, e la
       rotta spiega.

       L'etichetta invece viene ripulita: e' testo per chi legge, non un
       percorso, e uno spazio in piu' non cambia a cosa si riferisce.

    2. **Il tetto di lunghezza qui e' molto piu' alto di quello vero.**
       Con `max_length=MAX_PREFISSO`, Pydantic intercettava i prefissi troppo
       lunghi prima del database e rispondeva «String should have at most 256
       characters»: inglese, e muto sulla ragione. Il limite vero vale 256 e
       vive nel `CHECK`, insieme alla sua spiegazione -- che il gate rifiuta
       un bersaglio piu' lungo perche' non entrerebbe nella riga di audit.

       Il tetto che resta qui e' solo un argine contro un corpo
       patologico, non una regola del dominio.
    """

    model_config = ConfigDict(extra="forbid")

    #: Non ripulito: vedi il docstring.
    prefix: str = Field(min_length=1, max_length=8 * MAX_PREFISSO)
    label: Annotated[str, StringConstraints(strip_whitespace=True)] = Field(
        min_length=1, max_length=128
    )


class AliasRisposta(BaseModel):
    model_config = _USCITA

    id: int
    name: str
    address: str


class AliasRichiesta(BaseModel):
    model_config = _INGRESSO

    name: str = Field(min_length=2, max_length=64, pattern=r"^[a-z0-9]+([.-][a-z0-9]+)*$")
    address: str = Field(min_length=7, max_length=45)

    @field_validator("address")
    @classmethod
    def _indirizzo_non_nome(cls, v: str) -> str:
        """Un alias punta a un indirizzo, non a un altro nome.

        L'alias *e'* la risoluzione, non un secondo livello da risolvere. E
        qui non c'e' DNS, deliberatamente: un nome risolto al momento del
        controllo puo' puntare altrove al momento dell'esecuzione, puo'
        risolvere a piu' indirizzi, e dipende da un servizio che sta fuori dal
        perimetro che si sta dichiarando.
        """
        if "/" in v:
            raise ValueError(
                f"'{v}' ha una maschera di rete. Un alias punta a un singolo "
                f"indirizzo, non a una rete: le reti si dichiarano fra le reti "
                f"del perimetro."
            )
        try:
            ipaddress.ip_address(v)
        except ValueError as err:
            raise ValueError(
                f"'{v}' non e' un indirizzo IP. Un alias deve puntare a un "
                f"indirizzo: non viene risolto via DNS, perche' un nome "
                f"risolto al momento del controllo puo' puntare altrove al "
                f"momento dell'esecuzione."
            ) from err
        return v


# --------------------------------------------------------------------------- #
# Consensi
# --------------------------------------------------------------------------- #


class ConsensoRisposta(BaseModel):
    model_config = _USCITA

    id: int
    tool_id: int | None
    tool_identificativo: str | None
    agent: OwnerAgent
    agente_etichetta: str
    scope: str
    granted_by: str
    granted_at: dt.datetime
    expires_at: dt.datetime
    revoked_at: dt.datetime | None
    #: `attivo`, `scaduto` o `revocato`. Lo stato e' derivato dalle date e
    #: non memorizzato: una colonna di stato andrebbe aggiornata allo scadere,
    #: e nessuno la aggiornerebbe.
    stato: Literal["attivo", "scaduto", "revocato"]


class ConsensoRichiesta(BaseModel):
    model_config = _INGRESSO

    agent: OwnerAgent
    #: Assente = il consenso vale per l'agente intero, non per un solo tool.
    tool_id: int | None = None
    scope: str = Field(min_length=1, max_length=128)
    #: Obbligatorio: un consenso che non scade non e' un consenso, e' una
    #: autorizzazione permanente con un altro nome.
    expires_at: dt.datetime

    @field_validator("expires_at")
    @classmethod
    def _scadenza_futura(cls, v: dt.datetime) -> dt.datetime:
        if v.tzinfo is None:
            raise ValueError(
                "La scadenza deve indicare il fuso orario: un istante senza "
                "fuso non e' confrontabile con niente."
            )
        if v <= dt.datetime.now(tz=dt.UTC):
            raise ValueError(
                "La scadenza e' nel passato: il consenso nascerebbe gia' "
                "scaduto, e non autorizzerebbe niente."
            )
        return v


# --------------------------------------------------------------------------- #
# Log d'audit — sola lettura
# --------------------------------------------------------------------------- #


class EventoRisposta(BaseModel):
    model_config = _USCITA

    id: int
    correlation_id: uuid.UUID
    peer_correlation_id: str | None
    event_type: LogAction
    agent: OwnerAgent | None
    tool_id: str | None
    target: str | None
    tier_effective: RiskTier | None
    authorized_by: AuthorizedBy | None
    secret_name: str | None
    outcome: CallOutcome
    detail: str
    occurred_at: dt.datetime


class PaginaEventi(BaseModel):
    """Pagina del log.

    `totale` e' il numero di righe che soddisfano i filtri, non quelle
    restituite: senza, l'interfaccia non puo' dire quante pagine ci sono.
    """

    totale: int
    limite: int
    scarto: int
    eventi: list[EventoRisposta]


class CatenaEventi(BaseModel):
    """Catena completa di un `correlation_id`, in ordine cronologico."""

    correlation_id: uuid.UUID
    eventi: list[EventoRisposta]


#: Campi su cui il log si puo' ordinare.
#:
#: Un `Literal` e non una stringa libera: una rotta che accettasse un nome di
#: colonna arbitrario lo interpolerebbe in una clausola ORDER BY, cioe'
#: accetterebbe un frammento di SQL dal client. Qui l'insieme e' chiuso e il
#: valore si mappa su una colonna conosciuta, mai sul testo ricevuto.
OrdineEventi = Literal["occurred_at", "-occurred_at"]

#: Limite massimo di righe per pagina. Non e' una preferenza: senza tetto,
#: `limite=1000000` sarebbe una richiesta che esaurisce la memoria del server.
LIMITE_MASSIMO = 200

Limite = Annotated[int, Field(ge=1, le=LIMITE_MASSIMO)]
Scarto = Annotated[int, Field(ge=0)]
