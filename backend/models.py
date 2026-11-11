"""Modelli SQLAlchemy.

Mappano lo schema creato dalla migrazione. Non sono la fonte di verita' dello
schema: la migrazione lo e'. Questi modelli non vengono usati per creare le
tabelle (`create_all` non viene mai chiamato) perche' SQLAlchemy non sa
produrre i trigger e le funzioni che reggono gli invarianti, e uno schema in
cui parte dei vincoli e' dichiarata qui e parte nella migrazione e' uno schema
in cui non si sa cosa sia applicato davvero.

I vocabolari sono le stesse enumerazioni di hermes-core, ridichiarate come
``StrEnum`` Python: i valori combaciano, quindi un dato che arriva da quel
server non ha bisogno di rimappature.
"""

from __future__ import annotations

import datetime as dt
import uuid
from enum import StrEnum

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Enum as SAEnum,
    ForeignKey,
    Text,
    column,
    func,
    table,
)
from sqlalchemy.dialects.postgresql import ARRAY, CIDR, INET, UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import TypeDecorator

from backend.db import Base

# --------------------------------------------------------------------------- #
# Tipi di rete
#
# psycopg restituisce i tipi `cidr` e `inet` di PostgreSQL come oggetti
# `ipaddress.IPv4Network` / `IPv4Address`. Questi decoratori li espongono come
# stringhe al codice Python, lasciando al database il tipo vero.
#
# La direzione conta: il tipo nativo e' il VINCOLO — e' lui che rifiuta
# `192.168.205.10/24` — e non va sostituito con `text` per comodita' del
# livello applicativo. Si converte in uscita, non si rinuncia al vincolo.
# --------------------------------------------------------------------------- #


class CidrTesto(TypeDecorator):
    """`cidr` di PostgreSQL, esposto come stringa in forma canonica."""

    impl = CIDR
    cache_ok = True

    def process_result_value(self, value, dialect):  # noqa: ANN001, ANN201
        return None if value is None else str(value)


class InetTesto(TypeDecorator):
    """`inet` di PostgreSQL, esposto come stringa."""

    impl = INET
    cache_ok = True

    def process_result_value(self, value, dialect):  # noqa: ANN001, ANN201
        return None if value is None else str(value)


# --------------------------------------------------------------------------- #
# Vocabolari
# --------------------------------------------------------------------------- #


class RiskTier(StrEnum):
    """Asse tecnico del rischio. L'ordinamento e' significativo."""

    VERDE = "verde"
    GIALLO = "giallo"
    ROSSO = "rosso"

    @property
    def rank(self) -> int:
        return _RANGO_TIER[self]

    def superiori(self) -> tuple[RiskTier, ...]:
        """I tier strettamente superiori a questo.

        E' cio' che l'interfaccia offre nell'azione «Innalza tier»: solo
        questi. Il declassamento non viene offerto come azione disabilitata —
        non esiste come opzione, perche' un'opzione disabilitata insegna
        all'operatore che esiste un modo e che oggi non e' attivo.
        """
        return tuple(t for t in RiskTier if t.rank > self.rank)


_RANGO_TIER: dict[RiskTier, int] = {
    RiskTier.VERDE: 0,
    RiskTier.GIALLO: 1,
    RiskTier.ROSSO: 2,
}


class OwnerAgent(StrEnum):
    """Agente proprietario di un tool. Vocabolario chiuso."""

    ORCHESTRATOR = "orchestrator"
    ECHO_DUMMY = "echo_dummy"
    VULN_ASSESSMENT = "vuln_assessment"
    PENTEST_KALI = "pentest_kali"

    @property
    def etichetta(self) -> str:
        """Nome leggibile, per l'interfaccia in italiano."""
        return _ETICHETTE_AGENTE[self]


_ETICHETTE_AGENTE: dict[OwnerAgent, str] = {
    OwnerAgent.ORCHESTRATOR: "Orchestratore",
    OwnerAgent.ECHO_DUMMY: "Echo (dummy)",
    OwnerAgent.VULN_ASSESSMENT: "Vulnerability assessment",
    OwnerAgent.PENTEST_KALI: "Pentest (Kali)",
}


class TargetKind(StrEnum):
    """Che bersaglio accetta un tool, e quindi QUALE perimetro gli si applica.

    Non e' una descrizione: decide quale controllo viene applicato
    all'argomento prima dell'esecuzione, e in `hermes-core` c'e' un
    validatore per valore con un `match` esaustivo -- un valore senza il suo
    ramo fa fallire visibilmente, invece di scivolare in un ramo permissivo.
    La regola la', che vale anche qui: **nessun kind senza validatore**.

    `NONE` e' il default, e il default sta sul lato restrittivo: un tool che
    non dichiara un bersaglio non ne accetta uno.

    =========  ==========================  ==================================
    Valore     Bersaglio                   Perimetro
    =========  ==========================  ==================================
    `none`     nessuno                     nessuno
    `host`     indirizzo o rete            `scope_networks` / `scope_aliases`
    `path`     file o directory            `scope_paths`
    `process`  processo in esecuzione      **il container stesso**
    =========  ==========================  ==================================

    Per `process` non esiste una tabella di scope, e non e' una lacuna: un
    PID e' effimero e viene riciclato, quindi «il PID 4312 e' autorizzato»
    sarebbe falso qualche secondo dopo essere stato scritto. Il confine di
    isolamento *e'* il perimetro, e il vincolo `tools_bersaglio_isolato`
    impedisce di registrare un tool di questo tipo senza container.
    """

    NONE = "none"
    HOST = "host"
    PATH = "path"
    PROCESS = "process"

    @property
    def etichetta(self) -> str:
        """Nome leggibile, per l'interfaccia in italiano.

        Calcolata dal server come `OwnerAgent.etichetta`, e per la stessa
        ragione: e' un vocabolario del dominio, e tenerlo in un posto solo
        evita che due client traducano `process` in due modi diversi.
        """
        return _ETICHETTE_BERSAGLIO[self]


_ETICHETTE_BERSAGLIO: dict[TargetKind, str] = {
    TargetKind.NONE: "Nessun bersaglio",
    TargetKind.HOST: "Indirizzo o rete",
    TargetKind.PATH: "File o directory",
    TargetKind.PROCESS: "Processo in esecuzione",
}


class CallOutcome(StrEnum):
    """Esito di una invocazione.

    ``DENIED`` separato da ``ERROR``: un rifiuto deliberato della policy non
    e' un guasto. Contarli insieme confonderebbe «la macchina ha fallito» con
    «la policy ha detto no».
    """

    OK = "ok"
    ERROR = "error"
    DENIED = "denied"
    PENDING = "pending"


class AuthorizedBy(StrEnum):
    """Origine dell'autorizzazione di una invocazione."""

    POLICY = "policy"
    USER = "user"
    NONE = "none"


class LogAction(StrEnum):
    """Tipo di evento del log. Tutti quelli emessi da hermes-core."""

    AGENT_INVOKED = "agent_invoked"
    AGENT_RESULT = "agent_result"
    TOOL_REGISTERED = "tool_registered"
    TOOL_REGISTRATION_REJECTED = "tool_registration_rejected"
    TOOL_ALIAS_DETECTED = "tool_alias_detected"
    OVERRIDE_SET = "override_set"
    OVERRIDE_REJECTED = "override_rejected"
    OVERRIDE_STORE_LOADED = "override_store_loaded"
    OVERRIDE_NOT_PERSISTED = "override_not_persisted"
    CONCURRENCY_NOT_SHARED = "concurrency_not_shared"
    TOOL_CALL = "tool_call"
    SECRET_ACCESS = "secret_access"


class OverrideSource(StrEnum):
    """Da dove viene un override registrato, e quindi quanto dura."""

    #: Scritto in configurazione versionata: dura e si vede in review.
    CONFIG = "config"
    #: Registrato nello store append-only: dura oltre la connessione.
    PERSISTENT = "persistent"

    @property
    def descrizione(self) -> str:
        return _DESCRIZIONI_SOURCE[self]


_DESCRIZIONI_SOURCE: dict[OverrideSource, str] = {
    OverrideSource.CONFIG: "persistente, da configurazione versionata",
    OverrideSource.PERSISTENT: "persistente, registrato nello store",
}


# I tipi ENUM esistono gia' nel database, creati dalla migrazione.
# `create_type=False` impedisce a SQLAlchemy di tentare di ricrearli.
def _enum(enum_cls: type[StrEnum], nome: str) -> SAEnum:
    return SAEnum(
        enum_cls,
        name=nome,
        create_type=False,
        native_enum=True,
        values_callable=lambda e: [m.value for m in e],
    )


# --------------------------------------------------------------------------- #
# Tabelle
# --------------------------------------------------------------------------- #


class User(Base):
    """Operatore umano. Unico utente del pannello in questa consegna."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    username: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    #: Hash argon2id. Mai la password in chiaro.
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class Tool(Base):
    """Tool registrato presso il server MCP.

    I campi dell'identita' — ``exec_path``, ``exec_sha256``, ``exec_args`` —
    sono di sola lettura per questa applicazione: li registra hermes-core
    all'avvio. Non c'e' nessuna rotta che li crei o li modifichi.
    """

    __tablename__ = "tools"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    tool_id: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    agent: Mapped[OwnerAgent] = mapped_column(
        _enum(OwnerAgent, "owner_agent"), nullable=False
    )
    #: Pavimento immutabile. Nessun override lo abbassa.
    declared_tier: Mapped[RiskTier] = mapped_column(
        _enum(RiskTier, "tier"), nullable=False
    )
    #: Secondo asse, indipendente dal tier.
    personal_data: Mapped[bool] = mapped_column(Boolean, nullable=False)
    requires_container: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default="false"
    )
    target_kind: Mapped[TargetKind] = mapped_column(
        _enum(TargetKind, "target_kind"), nullable=False, server_default="none"
    )
    exec_path: Mapped[str] = mapped_column(Text, nullable=False)
    exec_sha256: Mapped[str] = mapped_column(Text, nullable=False)
    exec_args: Mapped[list[str]] = mapped_column(
        ARRAY(Text), nullable=False, server_default="{}"
    )
    description: Mapped[str] = mapped_column(Text, nullable=False)
    registered_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    overrides: Mapped[list[TierOverride]] = relationship(
        back_populates="tool",
        order_by="TierOverride.created_at",
        lazy="selectin",
    )


class TierOverride(Base):
    """Innalzamento registrato del tier di un tool.

    Append-only. Non esiste un metodo di modifica o di cancellazione in
    questa classe, e non esisterebbe comunque: i trigger del database li
    rifiutano. L'assenza di un'API di rimozione e' la scelta: una sarebbe un
    declassamento con un'interfaccia comoda, e una volta che esiste finisce
    per essere chiamata da qualcosa di automatico.
    """

    __tablename__ = "tier_overrides"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    tool_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("tools.id", ondelete="RESTRICT"), nullable=False
    )
    tier: Mapped[RiskTier] = mapped_column(_enum(RiskTier, "tier"), nullable=False)
    #: Obbligatorio: un innalzamento senza motivo e' illeggibile a distanza
    #: di mesi, che e' quando lo si rilegge.
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[OverrideSource] = mapped_column(
        _enum(OverrideSource, "override_source"),
        nullable=False,
        server_default="persistent",
    )
    created_by: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    tool: Mapped[Tool] = relationship(back_populates="overrides")


class ScopeNetwork(Base):
    """Rete autorizzata del perimetro, in forma canonica."""

    __tablename__ = "scope_networks"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    cidr: Mapped[str] = mapped_column(CidrTesto, nullable=False, unique=True)
    label: Mapped[str] = mapped_column(Text, nullable=False)


class ScopeAlias(Base):
    """Nome dichiarato per un indirizzo dentro il perimetro.

    Nessuna risoluzione DNS: l'alias *e'* la risoluzione. Un nome risolto al
    momento del controllo puo' puntare altrove al momento dell'esecuzione.
    """

    __tablename__ = "scope_aliases"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    name: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    address: Mapped[str] = mapped_column(InetTesto, nullable=False)


#: Lunghezza massima di un prefisso di percorso.
#:
#: Il numero viene da `hermes-core`, non da qui: il campo `target` di
#: un'invocazione e della riga di audit e' dichiarato `max_length=256`, e il
#: gate rifiuta qualunque bersaglio piu' lungo perche' «un bersaglio che non
#: entra nella riga di audit non e' registrabile, e un'esecuzione non
#: registrabile non si fa».
#:
#: Un prefisso piu' lungo di 256 potrebbe contenere solo bersagli che il gate
#: rifiuta sempre: sarebbe un perimetro sotto il quale niente e' invocabile.
MAX_PREFISSO = 256


class ScopePath(Base):
    """Prefisso di percorso autorizzato del perimetro.

    La forma canonica -- assoluto, senza `..`, senza doppie barre, senza
    barra finale -- la impongono i `CHECK` della migrazione 0004, una regola
    per vincolo. Qui non c'e' nessuna validazione che li duplichi: due
    formulazioni della stessa regola divergono, e quella che conta e' quella
    che vale anche per un `INSERT` fatto a mano.

    Che un bersaglio *cada dentro* uno di questi prefissi non lo verifica
    questa applicazione: richiede di risolvere i collegamenti simbolici nel
    filesystem su cui il tool girera', che non e' questo. Lo fa il gate di
    `hermes-core` al momento dell'esecuzione.
    """

    __tablename__ = "scope_paths"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    prefix: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    label: Mapped[str] = mapped_column(Text, nullable=False)


class ScopeConsent(Base):
    """Consenso dell'operatore per un agente su uno scope."""

    __tablename__ = "scope_consents"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    #: NULL = il consenso vale per l'agente intero, non per un solo tool.
    tool_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("tools.id", ondelete="RESTRICT"), nullable=True
    )
    agent: Mapped[OwnerAgent] = mapped_column(
        _enum(OwnerAgent, "owner_agent"), nullable=False
    )
    scope: Mapped[str] = mapped_column(Text, nullable=False)
    granted_by: Mapped[str] = mapped_column(Text, nullable=False)
    granted_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    #: Obbligatorio: un consenso che non scade non e' un consenso.
    expires_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    #: Revoca per annullamento, non cancellazione.
    revoked_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    tool: Mapped[Tool | None] = relationship(lazy="joined")

    def stato(self, adesso: dt.datetime) -> str:
        """Stato del consenso a un dato istante.

        L'ordine dei rami conta: una revoca prevale sulla scadenza, perche'
        «revocato» dice che qualcuno e' intervenuto e «scaduto» dice che e'
        passato il tempo, e all'operatore serve sapere quale dei due.
        """
        if self.revoked_at is not None:
            return "revocato"
        if self.expires_at <= adesso:
            return "scaduto"
        return "attivo"


class AuditEvent(Base):
    """Riga della vista del log d'audit.

    ``tool_id`` e' testo e non una chiave esterna: il log registra anche
    eventi che si riferiscono a tool NON registrati —
    ``tool_registration_rejected`` ne e' l'esempio — e una FK renderebbe
    quelle righe inseribili, cioe' renderebbe il log incapace di registrare
    i rifiuti.
    """

    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    correlation_id: Mapped[uuid.UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    peer_correlation_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    event_type: Mapped[LogAction] = mapped_column(
        _enum(LogAction, "log_action"), nullable=False
    )
    agent: Mapped[OwnerAgent | None] = mapped_column(
        _enum(OwnerAgent, "owner_agent"), nullable=True
    )
    tool_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    target: Mapped[str | None] = mapped_column(Text, nullable=True)
    tier_effective: Mapped[RiskTier | None] = mapped_column(
        _enum(RiskTier, "tier"), nullable=True
    )
    authorized_by: Mapped[AuthorizedBy | None] = mapped_column(
        _enum(AuthorizedBy, "authorized_by"), nullable=True
    )
    #: Il NOME del segreto consultato, mai il valore.
    secret_name: Mapped[str | None] = mapped_column(Text, nullable=True)
    outcome: Mapped[CallOutcome] = mapped_column(
        _enum(CallOutcome, "call_outcome"), nullable=False
    )
    detail: Mapped[str] = mapped_column(Text, nullable=False, server_default="")
    occurred_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


# --------------------------------------------------------------------------- #
# Vista del tier effettivo
#
# Dichiarata come `table()` e non come classe mappata: e' una vista di sola
# lettura, non ha chiave primaria e non va mai scritta. Un modello ORM
# completo suggerirebbe il contrario.
# --------------------------------------------------------------------------- #

tool_effective_tier = table(
    "tool_effective_tier",
    column("tool_pk", BigInteger),
    column("tool_id", Text),
    column("declared_tier", _enum(RiskTier, "tier")),
    column("effective_tier", _enum(RiskTier, "tier")),
    column("override_count", BigInteger),
    column("last_override_at", DateTime(timezone=True)),
)


__all__ = [
    "AuditEvent",
    "AuthorizedBy",
    "Base",
    "CallOutcome",
    "LogAction",
    "OverrideSource",
    "OwnerAgent",
    "RiskTier",
    "ScopeAlias",
    "ScopeConsent",
    "ScopeNetwork",
    "MAX_PREFISSO",
    "ScopePath",
    "TargetKind",
    "TierOverride",
    "Tool",
    "User",
    "tool_effective_tier",
]
