"""Popolamento iniziale del database.

Eseguito dall'entrypoint a ogni avvio, ma **attivo solo se il database e'
vuoto**: le righe di ``tier_overrides`` e ``audit_events`` non si possono
cancellare, quindi un seed che si rieseguisse le duplicherebbe senza modo di
ripulire. Il criterio di «vuoto» e' l'assenza dell'operatore, che e' la prima
riga che il seed scrive.

Per ripartire da zero si rimuove il volume del database::

    docker compose down -v && docker compose up --build

I dati non sono segnaposto. Servono a raccontare il dominio a chi apre
l'applicazione per la prima volta, quindi coprono tutte le combinazioni dei
due assi del rischio, includono due innalzamenti di tier con origini diverse,
e contengono catene di audit che finiscono in ``denied`` e in ``pending`` —
che sono i casi in cui si vede il gate fare il proprio lavoro. Una catena che
finisce in ``ok`` dimostra soltanto che il sistema esegue.

Gli indirizzi del perimetro sono quelli del laboratorio documentato in
hermes-core (``config/scope.example.toml``), cosi' i due repository
raccontano la stessa macchina.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import os
import sys
import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.db import privileged_session_factory
from backend.models import (
    AuditEvent,
    AuthorizedBy,
    CallOutcome,
    LogAction,
    OverrideSource,
    OwnerAgent,
    RiskTier,
    ScopeAlias,
    ScopeConsent,
    ScopeNetwork,
    ScopePath,
    TargetKind,
    TierOverride,
    Tool,
    User,
)
from backend.security import cifra_password

ADESSO = dt.datetime.now(tz=dt.UTC)


def _sha_segnaposto(tool_id: str) -> str:
    """SHA-256 ben formato e deterministico, derivato dall'identificativo.

    Non e' lo SHA di nessuno script reale: in esercizio lo registra
    hermes-core, che lo calcola sul file e lo verifica prima di ogni
    esecuzione. Qui serve un valore che rispetti il vincolo di formato
    (64 esadecimali minuscoli) e che resti lo stesso fra due seed, cosi' che
    una schermata di dettaglio non cambi a ogni ricostruzione.
    """
    return hashlib.sha256(f"segnaposto:{tool_id}".encode()).hexdigest()


# --------------------------------------------------------------------------- #
# Tool — tutte le combinazioni dei due assi
# --------------------------------------------------------------------------- #

TOOL = [
    # -- vuln_assessment --------------------------------------------------- #
    {
        "tool_id": "audit.lynis",
        "agent": OwnerAgent.VULN_ASSESSMENT,
        "declared_tier": RiskTier.VERDE,
        "personal_data": False,
        "requires_container": False,
        "target_kind": TargetKind.NONE,
        "exec_path": "agents/vuln_assessment/lynis_audit.py",
        "exec_args": ["--profile", "default"],
        "description": "Audit di configurazione della macchina locale. Sola lettura.",
    },
    {
        "tool_id": "audit.ssl-scan",
        "agent": OwnerAgent.VULN_ASSESSMENT,
        "declared_tier": RiskTier.VERDE,
        "personal_data": False,
        "requires_container": False,
        "target_kind": TargetKind.HOST,
        "exec_path": "agents/vuln_assessment/ssl_scan.py",
        "exec_args": [],
        "description": "Enumera cifrari e certificati di un servizio TLS. Nessuna scrittura.",
    },
    {
        # Verde CON dati personali: il caso che dimostra perche' i due assi
        # non si fondono. Tecnicamente passivo, ma indaga persone fisiche.
        "tool_id": "osint.breach-check",
        "agent": OwnerAgent.VULN_ASSESSMENT,
        "declared_tier": RiskTier.VERDE,
        "personal_data": True,
        "requires_container": False,
        "target_kind": TargetKind.NONE,
        "exec_path": "agents/vuln_assessment/breach_check.py",
        "exec_args": ["--no-cache"],
        "description": "Verifica se un indirizzo email compare in violazioni di dati note.",
    },
    {
        "tool_id": "recon.nmap-sweep",
        "agent": OwnerAgent.VULN_ASSESSMENT,
        "declared_tier": RiskTier.GIALLO,
        "personal_data": False,
        "requires_container": False,
        "target_kind": TargetKind.HOST,
        "exec_path": "agents/vuln_assessment/nmap_sweep.py",
        "exec_args": ["-sV", "--top-ports", "1000"],
        "description": "Scansione attiva di porte e servizi su uno scope autorizzato.",
    },
    {
        "tool_id": "scan.nikto",
        "agent": OwnerAgent.VULN_ASSESSMENT,
        "declared_tier": RiskTier.GIALLO,
        "personal_data": False,
        "requires_container": True,
        "target_kind": TargetKind.HOST,
        "exec_path": "agents/vuln_assessment/nikto.py",
        "exec_args": ["-Tuning", "123b"],
        "description": "Scansione di vulnerabilita' note di un server web. Attiva, non distruttiva.",
    },
    # -- pentest_kali ------------------------------------------------------- #
    {
        "tool_id": "osint.username-enum",
        "agent": OwnerAgent.PENTEST_KALI,
        "declared_tier": RiskTier.VERDE,
        "personal_data": True,
        "requires_container": False,
        "target_kind": TargetKind.NONE,
        "exec_path": "agents/pentest_kali/username_enum.py",
        "exec_args": [],
        "description": "Cerca un nome utente su servizi pubblici. Passivo, riguarda persone.",
    },
    {
        "tool_id": "exploit.msf-check",
        "agent": OwnerAgent.PENTEST_KALI,
        "declared_tier": RiskTier.ROSSO,
        "personal_data": False,
        "requires_container": True,
        "target_kind": TargetKind.HOST,
        "exec_path": "agents/pentest_kali/msf_check.py",
        "exec_args": ["--check-only"],
        "description": "Verifica la sfruttabilita' di una vulnerabilita'. Intrusiva.",
    },
    {
        "tool_id": "cred.hydra-spray",
        "agent": OwnerAgent.PENTEST_KALI,
        "declared_tier": RiskTier.ROSSO,
        "personal_data": True,
        "requires_container": True,
        "target_kind": TargetKind.HOST,
        "exec_path": "agents/pentest_kali/hydra_spray.py",
        "exec_args": ["--threads", "4"],
        "description": "Prova credenziali note contro un servizio. Intrusiva e riguarda persone.",
    },
    # -- bersagli che non sono host ----------------------------------------- #
    #
    # I due casi che la migrazione 0004 rende rappresentabili. Stanno nel seed
    # perche' un valore di enum che nessuna riga usa non si vede: chi apre
    # l'applicazione per la prima volta troverebbe un catalogo di soli
    # bersagli di rete e un perimetro di sole reti, e crederebbe che il
    # modello sia quello.
    #
    # Entrambi hanno `requires_container` vero, e non per scelta editoriale:
    # il vincolo `tools_bersaglio_isolato` non permette altro. Un tool che
    # punta a file o processi senza isolamento non e' registrabile.
    {
        "tool_id": "analisi.rea-decompile",
        "agent": OwnerAgent.PENTEST_KALI,
        "declared_tier": RiskTier.GIALLO,
        "personal_data": False,
        "requires_container": True,
        "target_kind": TargetKind.PATH,
        "exec_path": "agents/pentest_kali/rea_decompile.py",
        "exec_args": ["--no-network"],
        "description": (
            "Decompila un binario e ne riassume le funzioni. Statica, ma apre "
            "un file scelto a ogni invocazione."
        ),
    },
    {
        "tool_id": "analisi.frida-hook",
        "agent": OwnerAgent.PENTEST_KALI,
        "declared_tier": RiskTier.ROSSO,
        "personal_data": False,
        "requires_container": True,
        "target_kind": TargetKind.PROCESS,
        "exec_path": "agents/pentest_kali/frida_hook.py",
        "exec_args": ["--no-pause"],
        "description": (
            "Aggancia un processo in esecuzione e ne traccia le chiamate. "
            "Modifica il comportamento del programma agganciato."
        ),
    },
]

# --------------------------------------------------------------------------- #
# Innalzamenti di tier, con origini diverse
# --------------------------------------------------------------------------- #

OVERRIDE = [
    {
        "tool_id": "recon.nmap-sweep",
        "tier": RiskTier.ROSSO,
        "source": OverrideSource.PERSISTENT,
        "created_by": "operatore",
        "reason": (
            "Durante la verifica del 4 novembre la scansione ha fatto cadere il "
            "servizio di gestione dell'apparato a 192.168.205.1. Su questo "
            "perimetro non e' una azione non distruttiva: richiede conferma "
            "puntuale a ogni invocazione."
        ),
        "giorni_fa": 5,
    },
    {
        "tool_id": "audit.ssl-scan",
        "tier": RiskTier.GIALLO,
        "source": OverrideSource.CONFIG,
        "created_by": "config/hermes.toml",
        "reason": (
            "Innalzato in configurazione versionata: su alcuni servizi legacy "
            "l'enumerazione dei cifrari apre abbastanza connessioni da essere "
            "una azione attiva, non una lettura."
        ),
        "giorni_fa": 21,
    },
]


def _crea_tool(db: Session) -> dict[str, Tool]:
    creati: dict[str, Tool] = {}
    for i, spec in enumerate(TOOL):
        tool = Tool(
            **spec,
            exec_sha256=_sha_segnaposto(spec["tool_id"]),
            # Registrazioni distanziate nel tempo: in esercizio avvengono
            # all'avvio del server MCP, non tutte nello stesso istante.
            registered_at=ADESSO - dt.timedelta(days=30, minutes=-i * 7),
        )
        db.add(tool)
        creati[spec["tool_id"]] = tool
    db.flush()
    return creati


def _crea_override(db: Session, tool: dict[str, Tool]) -> None:
    """Inserisce gli innalzamenti in ordine crescente di tier.

    L'ordine conta: il trigger di monotonia rifiuta un override che non
    innalzi il tier effettivo corrente, quindi inserire prima il rosso e poi
    il giallo sullo stesso tool fallirebbe. Qui i due override sono su tool
    diversi, ma la regola e' quella che vale per chiunque scriva un seed.
    """
    for spec in OVERRIDE:
        db.add(
            TierOverride(
                tool_id=tool[spec["tool_id"]].id,
                tier=spec["tier"],
                reason=spec["reason"],
                source=spec["source"],
                created_by=spec["created_by"],
                created_at=ADESSO - dt.timedelta(days=spec["giorni_fa"]),
            )
        )
    db.flush()


def _crea_perimetro(db: Session) -> None:
    """I due perimetri: reti con alias, e prefissi di percorso.

    Sono due e non uno perche' le regole sono diverse, e il seed lo mostra
    invece di dirlo: di una rete il database verifica l'appartenenza, di un
    percorso soltanto la forma del prefisso.
    """
    db.add(ScopeNetwork(cidr="192.168.205.0/24", label="Laboratorio Hermes (VM su VMware)"))
    db.flush()
    # Gli alias dopo la rete: il trigger verifica il contenimento
    # all'inserimento, e con il perimetro ancora vuoto li rifiuterebbe.
    db.add(ScopeAlias(name="lab-web", address="192.168.205.20"))
    db.add(ScopeAlias(name="lab-kali", address="192.168.205.30"))
    db.flush()

    # Due prefissi e non uno: il secondo mostra che il perimetro dei percorsi
    # e' un elenco, e che la rimozione di una riga non tocca le altre. Nessun
    # alias, per i percorsi: ricordare `/srv/hermes/campioni` non e' il
    # problema che gli alias di rete risolvono.
    db.add(
        ScopePath(
            prefix="/srv/hermes/campioni",
            label="Binari e file da analizzare, copiati dall'operatore",
        )
    )
    db.add(
        ScopePath(
            prefix="/srv/hermes/esiti",
            label="Dove i tool di analisi scrivono i propri risultati",
        )
    )
    db.flush()


def _crea_consensi(db: Session, tool: dict[str, Tool]) -> None:
    """Due consensi, di cui uno scaduto.

    Lo scaduto non e' un difetto dei dati: e' il caso che mostra che lo stato
    e' derivato dalle date e non memorizzato, e che un consenso scaduto resta
    visibile invece di sparire.
    """
    db.add(
        ScopeConsent(
            tool_id=None,  # vale per l'agente intero
            agent=OwnerAgent.PENTEST_KALI,
            scope="192.168.205.0/24",
            granted_by="operatore",
            granted_at=ADESSO - dt.timedelta(days=2),
            expires_at=ADESSO + dt.timedelta(days=5),
        )
    )
    db.add(
        ScopeConsent(
            tool_id=tool["osint.breach-check"].id,
            agent=OwnerAgent.VULN_ASSESSMENT,
            scope="lab-web",
            granted_by="operatore",
            granted_at=ADESSO - dt.timedelta(days=12),
            expires_at=ADESSO - dt.timedelta(days=4),  # scaduto
        )
    )
    db.flush()


# --------------------------------------------------------------------------- #
# Log d'audit — sei catene
#
# Ogni catena e' una invocazione completa, legata da un `correlation_id`. Le
# righe seguono la struttura che hermes-core produce: `agent_invoked` apre,
# una riga `tool_call` per ciascuna invocazione, `agent_result` chiude.
#
# Le catene sono scelte per mostrare gli esiti che contano:
#   1. esecuzione passiva riuscita                       -> ok
#   2. scansione attiva su scope con consenso            -> ok
#   3. tool rosso senza conferma collegata               -> pending
#   4. bersaglio fuori perimetro                         -> denied
#   5. innalzamento di tier reattivo + rifiuto successivo -> denied
#   6. accesso a un segreto e guasto del tool            -> error
# --------------------------------------------------------------------------- #


class _Catena:
    """Accumulatore di eventi con un `correlation_id` e un orologio comuni."""

    def __init__(self, db: Session, agent: OwnerAgent, minuti_fa: int) -> None:
        self._db = db
        self._cid = uuid.uuid4()
        self._agent = agent
        self._t = ADESSO - dt.timedelta(minutes=minuti_fa)

    @property
    def correlation_id(self) -> uuid.UUID:
        return self._cid

    def evento(
        self,
        event_type: LogAction,
        outcome: CallOutcome,
        *,
        tool_id: str | None = None,
        target: str | None = None,
        tier_effective: RiskTier | None = None,
        authorized_by: AuthorizedBy | None = None,
        secret_name: str | None = None,
        detail: str = "",
        peer: str | None = None,
        secondi: int = 0,
    ) -> _Catena:
        """Aggiunge un evento e fa avanzare l'orologio della catena."""
        self._t += dt.timedelta(seconds=secondi or 2)
        self._db.add(
            AuditEvent(
                correlation_id=self._cid,
                peer_correlation_id=peer,
                event_type=event_type,
                agent=self._agent,
                tool_id=tool_id,
                target=target,
                tier_effective=tier_effective,
                authorized_by=authorized_by,
                secret_name=secret_name,
                outcome=outcome,
                detail=detail,
                occurred_at=self._t,
            )
        )
        return self


def _crea_audit(db: Session) -> None:
    A = OwnerAgent
    T = RiskTier
    O = CallOutcome
    L = LogAction
    AB = AuthorizedBy

    # -- registrazione dei tool all'avvio del server MCP ------------------- #
    # Non e' una catena di invocazione: e' cio' che hermes-core scrive quando
    # legge la propria configurazione. Un `correlation_id` per l'avvio.
    avvio = _Catena(db, A.VULN_ASSESSMENT, minuti_fa=60 * 26)
    for spec in TOOL:
        if spec["agent"] is A.VULN_ASSESSMENT:
            avvio.evento(
                L.TOOL_REGISTERED,
                O.OK,
                tool_id=spec["tool_id"],
                tier_effective=spec["declared_tier"],
                detail=f"registrato con tier dichiarato {spec['declared_tier']}",
                secondi=1,
            )
    avvio.evento(
        L.TOOL_REGISTRATION_REJECTED,
        O.DENIED,
        tool_id="recon.nmap-aggressive",
        detail=(
            "identita' (exec_path, exec_sha256, exec_args) uguale a "
            "recon.nmap-sweep ma tier dichiarato inferiore: rifiutata come "
            "alias abusivo"
        ),
    )
    avvio.evento(
        L.OVERRIDE_STORE_LOADED,
        O.OK,
        detail=(
            "istanza vuln_assessment: store degli override riletto da "
            "state_dir, 2 righe, 0 scartate"
        ),
    )

    avvio_pentest = _Catena(db, A.PENTEST_KALI, minuti_fa=60 * 26 - 5)
    for spec in TOOL:
        if spec["agent"] is A.PENTEST_KALI:
            avvio_pentest.evento(
                L.TOOL_REGISTERED,
                O.OK,
                tool_id=spec["tool_id"],
                tier_effective=spec["declared_tier"],
                detail=(
                    f"registrato con tier dichiarato {spec['declared_tier']}"
                    + (", richiede il container isolato" if spec["requires_container"] else "")
                ),
                secondi=1,
            )
    avvio_pentest.evento(
        L.OVERRIDE_NOT_PERSISTED,
        O.OK,
        detail=(
            "questa istanza non ha state_dir configurata: gli innalzamenti "
            "valgono per la connessione. Dichiarato nel campo override_scope "
            "delle risposte, non lasciato implicito"
        ),
    )
    avvio_pentest.evento(
        L.TOOL_ALIAS_DETECTED,
        O.DENIED,
        tool_id="exploit.msf-run",
        detail=(
            "stessa identita' di exploit.msf-check con exec_args diversi "
            "(--check-only rimosso) e tier dichiarato rosso: registrato come "
            "tool distinto, l'alias e' segnalato"
        ),
    )

    # -- 1. audit passivo locale, riuscito --------------------------------- #
    c1 = _Catena(db, A.VULN_ASSESSMENT, minuti_fa=60 * 20)
    c1.evento(
        L.AGENT_INVOKED, O.OK,
        detail="richiesto audit di configurazione della macchina locale",
        peer="claude-desktop-7f21",
    )
    c1.evento(
        L.TOOL_CALL, O.OK,
        tool_id="audit.lynis", tier_effective=T.VERDE, authorized_by=AB.POLICY,
        detail="tier verde senza dati personali: nessuna conferma richiesta",
        secondi=34,
    )
    c1.evento(
        L.AGENT_RESULT, O.OK,
        detail="audit completato: 3 findings informativi, 1 medio",
    )

    # -- 2. scansione attiva su scope con consenso ------------------------- #
    c2 = _Catena(db, A.VULN_ASSESSMENT, minuti_fa=60 * 15)
    c2.evento(L.AGENT_INVOKED, O.OK, detail="richiesta scansione del laboratorio")
    for host in (
        "192.168.205.20",
        "192.168.205.30",
        "192.168.205.1",
        "192.168.205.40",
        "192.168.205.41",
    ):
        c2.evento(
            L.TOOL_CALL, O.OK,
            tool_id="audit.ssl-scan", target=host,
            # Effettivo giallo, non verde: l'override da configurazione e'
            # applicato. E' il punto in cui il log mostra il tier effettivo e
            # non quello dichiarato.
            tier_effective=T.GIALLO, authorized_by=AB.USER,
            detail="consenso per scope 192.168.205.0/24 gia' a registro",
            secondi=18,
        )
    c2.evento(L.AGENT_RESULT, O.OK, detail="5 host analizzati, 2 con TLS 1.0 attivo")

    # -- 3. tool rosso: conferma non collegata -> pending ------------------ #
    # E' il caso che hermes-core documenta: una routine non presidiata non
    # viene rifiutata, esegue cio' che puo' e mette il rosso in attesa.
    c3 = _Catena(db, A.PENTEST_KALI, minuti_fa=60 * 9)
    c3.evento(L.AGENT_INVOKED, O.OK, detail="verifica di sfruttabilita' su lab-web")
    c3.evento(
        L.TOOL_CALL, O.OK,
        tool_id="osint.username-enum", tier_effective=T.VERDE, authorized_by=AB.USER,
        detail="tier verde ma dati personali: consenso dedicato a registro",
        secondi=12,
    )
    c3.evento(
        L.TOOL_CALL, O.OK,
        tool_id="audit.ssl-scan", target="lab-web",
        tier_effective=T.GIALLO, authorized_by=AB.USER,
        detail="ricognizione del servizio TLS prima della verifica intrusiva",
        secondi=15,
    )
    c3.evento(
        L.TOOL_CALL, O.PENDING,
        tool_id="exploit.msf-check", target="lab-web",
        tier_effective=T.ROSSO, authorized_by=AB.NONE,
        detail=(
            "tier rosso: conferma puntuale richiesta a ogni invocazione. "
            "Canale di conferma non collegato: richiesta in coda"
        ),
        secondi=3,
    )
    c3.evento(
        L.AGENT_RESULT, O.PENDING,
        detail=(
            "lavoro parziale consegnato: 1 invocazione eseguita, 1 in attesa "
            "di conferma dell'operatore"
        ),
    )

    # -- 4. bersaglio fuori perimetro -> denied ---------------------------- #
    c4 = _Catena(db, A.VULN_ASSESSMENT, minuti_fa=60 * 6)
    c4.evento(L.AGENT_INVOKED, O.OK, detail="richiesta scansione di 10.8.0.14")
    c4.evento(
        L.TOOL_CALL, O.DENIED,
        tool_id="recon.nmap-sweep", target="10.8.0.14",
        tier_effective=T.ROSSO, authorized_by=AB.NONE,
        detail=(
            "bersaglio fuori perimetro: 10.8.0.14 non cade in nessuna rete "
            "dichiarata (192.168.205.0/24)"
        ),
        secondi=1,
    )
    c4.evento(
        L.AGENT_RESULT, O.DENIED,
        detail="nessuna invocazione eseguita: il bersaglio non e' autorizzato",
    )

    # -- 5. innalzamento reattivo, poi rifiuto ----------------------------- #
    c5 = _Catena(db, A.VULN_ASSESSMENT, minuti_fa=60 * 5)
    c5.evento(
        L.OVERRIDE_SET, O.OK,
        tool_id="recon.nmap-sweep", tier_effective=T.ROSSO,
        detail=(
            "innalzato da giallo a rosso dopo la caduta del servizio di "
            "gestione a 192.168.205.1. Origine: store persistente"
        ),
    )
    c5.evento(
        L.OVERRIDE_REJECTED, O.DENIED,
        tool_id="recon.nmap-sweep", tier_effective=T.ROSSO,
        detail=(
            "richiesto abbassamento a giallo: rifiutato. Il tier puo' solo "
            "salire"
        ),
        secondi=90,
    )
    c5.evento(
        L.TOOL_CALL, O.DENIED,
        tool_id="recon.nmap-sweep", target="lab-kali",
        tier_effective=T.ROSSO, authorized_by=AB.NONE,
        detail=(
            "tier effettivo rosso dopo l'innalzamento: conferma puntuale "
            "richiesta, canale non collegato"
        ),
        secondi=240,
    )
    c5.evento(
        L.AGENT_RESULT, O.DENIED,
        detail="il tool resta non invocabile finche' la conferma non e' collegata",
    )

    # -- 6. accesso a un segreto e guasto del tool ------------------------- #
    c6 = _Catena(db, A.PENTEST_KALI, minuti_fa=60 * 2)
    c6.evento(L.AGENT_INVOKED, O.OK, detail="prova di credenziali note su lab-kali")
    c6.evento(
        L.SECRET_ACCESS, O.OK,
        secret_name="ssh/lab-kali",
        detail="segreto consultato dal vault. Registrato il nome, non il valore",
        secondi=1,
    )
    c6.evento(
        L.TOOL_CALL, O.ERROR,
        tool_id="cred.hydra-spray", target="lab-kali",
        tier_effective=T.ROSSO, authorized_by=AB.USER,
        detail=(
            "conferma puntuale ricevuta, esecuzione avviata, tool terminato "
            "con stato 2: servizio non raggiungibile sulla porta 22"
        ),
        secondi=47,
    )
    c6.evento(
        L.AGENT_RESULT, O.ERROR,
        detail="guasto del tool, non rifiuto della policy: l'invocazione era autorizzata",
    )

    # -- 7. limite di concorrenza e consenso scaduto ----------------------- #
    # Due rifiuti che non sono guasti: il primo perche' i posti di esecuzione
    # sono esauriti (un modello in ciclo che invoca senza fermarsi), il
    # secondo perche' il consenso per quello scope e' scaduto. Entrambi
    # `denied`, perche' entrambi sono decisioni e non malfunzionamenti.
    c7 = _Catena(db, A.VULN_ASSESSMENT, minuti_fa=55)
    c7.evento(L.AGENT_INVOKED, O.OK, detail="scansione web del laboratorio")
    c7.evento(
        L.TOOL_CALL, O.OK,
        tool_id="scan.nikto", target="lab-web",
        tier_effective=T.GIALLO, authorized_by=AB.USER,
        detail="eseguito nel container isolato, consenso per scope a registro",
        secondi=62,
    )
    c7.evento(
        L.TOOL_CALL, O.DENIED,
        tool_id="scan.nikto", target="192.168.205.40",
        tier_effective=T.GIALLO, authorized_by=AB.NONE,
        detail=(
            "posti di esecuzione esauriti (max_concurrent_tools = 2): "
            "invocazione rifiutata invece di accodata"
        ),
        secondi=1,
    )
    c7.evento(
        L.TOOL_CALL, O.DENIED,
        tool_id="osint.breach-check",
        tier_effective=T.VERDE, authorized_by=AB.NONE,
        detail=(
            "tier verde, ma il flag dati personali richiede una conferma "
            "dedicata e il consenso per lo scope 'lab-web' e' scaduto da 4 "
            "giorni"
        ),
        secondi=2,
    )
    c7.evento(
        L.AGENT_RESULT, O.DENIED,
        detail="1 invocazione eseguita, 2 rifiutate: posti esauriti e consenso scaduto",
    )

    db.flush()


# --------------------------------------------------------------------------- #
# Punto d'ingresso
# --------------------------------------------------------------------------- #


def _crea_operatore(db: Session) -> None:
    """Crea l'unico operatore, con la password presa dall'ambiente.

    Nessun default: una password predefinita in un pannello che decide i
    permessi degli agenti sarebbe la credenziale piu' prevedibile del
    sistema. Se la variabile manca, il seed si ferma e lo dice.
    """
    password = os.environ.get("HERMES_ADMIN_PASSWORD")
    username = os.environ.get("HERMES_ADMIN_USERNAME", "operatore")

    if not password:
        print(
            "[seed] HERMES_ADMIN_PASSWORD non impostata: nessun operatore "
            "creato, quindi non sarebbe possibile entrare. Copiare "
            ".env.example in .env e riempirla.",
            file=sys.stderr,
        )
        raise SystemExit(1)

    if password.startswith("sostituiscimi"):
        print(
            "[seed] HERMES_ADMIN_PASSWORD e' ancora il valore d'esempio di "
            ".env.example. Sostituirlo prima del primo avvio.",
            file=sys.stderr,
        )
        raise SystemExit(1)

    db.add(User(username=username, password_hash=cifra_password(password)))
    db.flush()
    print(f"[seed] operatore '{username}' creato")


def popola(db: Session, *, con_operatore: bool = True) -> None:
    """Scrive tutti i dati di esempio. Presuppone un database vuoto."""
    if con_operatore:
        _crea_operatore(db)
    tool = _crea_tool(db)
    _crea_override(db, tool)
    _crea_perimetro(db)
    _crea_consensi(db, tool)
    _crea_audit(db)
    db.commit()


def database_vuoto(db: Session) -> bool:
    """Se il seed deve girare.

    Il criterio e' l'assenza dell'operatore, che e' la prima riga che il seed
    scrive: se c'e', il seed e' gia' passato.
    """
    return (db.scalar(select(func.count()).select_from(User)) or 0) == 0


def main() -> None:
    # Sessione PRIVILEGIATA: il seed scrive su `tools`, `users` e
    # `audit_events`, che per il ruolo applicativo sono in sola lettura.
    db = privileged_session_factory()()
    try:
        if not database_vuoto(db):
            print("[seed] il database contiene gia' dei dati: niente da fare")
            return
        popola(db)
        conteggi = {
            "tool": db.scalar(select(func.count()).select_from(Tool)),
            "override": db.scalar(select(func.count()).select_from(TierOverride)),
            "reti": db.scalar(select(func.count()).select_from(ScopeNetwork)),
            "alias": db.scalar(select(func.count()).select_from(ScopeAlias)),
            "percorsi": db.scalar(select(func.count()).select_from(ScopePath)),
            "consensi": db.scalar(select(func.count()).select_from(ScopeConsent)),
            "eventi": db.scalar(select(func.count()).select_from(AuditEvent)),
            "catene": db.scalar(
                select(func.count(func.distinct(AuditEvent.correlation_id)))
            ),
        }
        print("[seed] popolato:", ", ".join(f"{k}={v}" for k, v in conteggi.items()))
    finally:
        db.close()


if __name__ == "__main__":
    main()
