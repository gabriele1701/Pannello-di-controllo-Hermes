"""Caricamento della configurazione di scope, fail-closed.

Il file ``scope.toml`` dichiara il perimetro del run: il target ammesso, gli
host in allowlist, le sentinelle dell'egress self-check, e i *riferimenti*
alle credenziali — mai le credenziali stesse. I segreti (password del target,
DSN del DB, chiave SSH) stanno in variabili d'ambiente o in file montati come
secret, e nel toml compare solo il **nome** della variabile.

Fail-closed, in tre punti
-------------------------

1. File assente o illeggibile → errore, non un default.
2. Un valore lasciato a ``DA_COMPILARE`` → errore. Il file di esempio e'
   volutamente non eseguibile: finche' l'operatore non lo compila, il tool
   rifiuta di partire invece di girare su un perimetro-segnaposto.
3. Un campo obbligatorio mancante → errore.

Non c'e' un ramo in cui una configurazione incompleta produca un perimetro
permissivo: ogni via d'uscita da un dato mancante e' un'eccezione.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

#: Segnaposto che l'operatore deve sostituire. La sua presenza in un campo
#: obbligatorio e' un errore: vedi il docstring del modulo.
SEGNAPOSTO = "DA_COMPILARE"


class ConfigIncompleta(Exception):
    """La configurazione non e' utilizzabile: manca un campo, o e' un
    segnaposto non compilato. Fail-closed: il tool non parte."""


@dataclass(frozen=True, slots=True)
class ConfigTarget:
    """Target HTTP e host ammessi. Nessun segreto qui."""

    base_url: str
    #: Host ammessi per il target. Il nome del target DEVE essere fra questi;
    #: qualunque altro host e' fuori perimetro (vedi ``scope.valida_target``).
    allowlist: tuple[str, ...]
    #: Nome della variabile d'ambiente che porta la password dell'operatore
    #: demo. Il valore non e' qui.
    password_env: str = "ASSESS_TARGET_PASSWORD"
    #: Utente operatore demo con cui fare login.
    operator_user: str = ""

    def password(self) -> str | None:
        """La password dell'operatore demo, risolta dalla variabile nominata in
        ``password_env``. ``None`` se non impostata (o vuota): il login HTTP e'
        **opzionale**. La sua assenza non e' un errore di caricamento — rende i
        collector esterni NOT_RUN, perche' il loro canale non c'e'."""
        return os.environ.get(self.password_env) or None

    def login_disponibile(self) -> bool:
        """Vero se c'e' abbastanza per un login HTTP: un utente operatore **e**
        la sua password nell'ambiente. Senza, il canale HTTP non si costruisce."""
        return bool(self.operator_user and self.password())


@dataclass(frozen=True, slots=True)
class ConfigDb:
    """Connessione DB in sola lettura. Il DSN vero arriva da env."""

    #: Nome della variabile d'ambiente che porta il DSN di ``hermes_assess``.
    dsn_env: str = "ASSESS_DB_DSN"

    def dsn(self) -> str | None:
        """Il DSN di ``hermes_assess``, risolto dalla variabile nominata in
        ``dsn_env``. ``None`` se non impostato: la connessione DB e'
        **opzionale** e la sua assenza rende il collector ``postgres`` NOT_RUN,
        non un errore di caricamento."""
        return os.environ.get(self.dsn_env) or None


@dataclass(frozen=True, slots=True)
class ConfigSsh:
    """Canale SSH ristretto verso l'host della VM. La restrizione vera sta sul
    server (``restrict`` + ``ForceCommand``), non qui: questo e' solo
    l'indirizzamento del canale."""

    host: str = ""
    user: str = "assess"
    port: int = 22
    #: Percorso DENTRO il container della chiave privata, montata come secret
    #: (es. /run/secrets/scanner_ed25519). Non e' la chiave: solo dove trovarla.
    key_path: str = ""
    #: Percorso DENTRO il container del file known_hosts che fissa l'identita'
    #: dell'host della VM (per StrictHostKeyChecking=yes). Nessun default che
    #: indovini: va dichiarato in scope.toml, o il trasporto SSH non parte.
    known_hosts_path: str = ""


@dataclass(frozen=True, slots=True)
class ConfigEgress:
    """Sentinelle esterne per il self-check. Raggiungerne anche una sola fa
    fallire il check (vedi ``scope.egress_self_check``)."""

    sentinelle: tuple[tuple[str, int], ...]
    timeout_s: float = 2.0


@dataclass(frozen=True, slots=True)
class ConfigScope:
    """Configurazione completa e validata di un run."""

    target: ConfigTarget
    egress: ConfigEgress
    db: ConfigDb = field(default_factory=ConfigDb)
    ssh: ConfigSsh = field(default_factory=ConfigSsh)
    #: Directory di output del report, relativa alla cwd se non assoluta.
    out_dir: str = "assess/out"


def _contiene_segnaposto(valore: object) -> bool:
    """Vero se un valore (anche dentro liste/dizionari annidati) contiene il
    segnaposto ``DA_COMPILARE``."""
    if isinstance(valore, str):
        return SEGNAPOSTO in valore
    if isinstance(valore, dict):
        return any(_contiene_segnaposto(v) for v in valore.values())
    if isinstance(valore, (list, tuple)):
        return any(_contiene_segnaposto(v) for v in valore)
    return False


def _sentinelle_da_toml(grezzo: object) -> tuple[tuple[str, int], ...]:
    """Converte la lista TOML ``[["1.1.1.1", 53], ...]`` in coppie (host, porta).

    Validazione stretta: una sentinella malformata e' un errore, perche' una
    sentinella che non viene provata e' una maglia aperta nella rete di
    sicurezza che non si vede."""
    if not isinstance(grezzo, list) or not grezzo:
        raise ConfigIncompleta(
            "egress.sentinelle: serve una lista non vuota di [host, porta]"
        )
    coppie: list[tuple[str, int]] = []
    for voce in grezzo:
        if (
            not isinstance(voce, (list, tuple))
            or len(voce) != 2
            or not isinstance(voce[0], str)
            or not isinstance(voce[1], int)
            or isinstance(voce[1], bool)
        ):
            raise ConfigIncompleta(
                f"egress.sentinelle: voce malformata {voce!r}, atteso [host, porta]"
            )
        coppie.append((voce[0], voce[1]))
    return tuple(coppie)


def _richiedi(sezione: dict, chiave: str, dove: str) -> object:
    if chiave not in sezione:
        raise ConfigIncompleta(f"{dove}.{chiave}: campo obbligatorio mancante")
    return sezione[chiave]


def carica(percorso: str | Path) -> ConfigScope:
    """Carica e valida ``scope.toml``. Solleva ``ConfigIncompleta`` se il
    perimetro non e' utilizzabile. Non ha un ramo che restituisca un
    perimetro di ripiego."""
    p = Path(percorso)
    if not p.is_file():
        raise ConfigIncompleta(f"configurazione non trovata: {p}")
    try:
        dati = tomllib.loads(p.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigIncompleta(f"configurazione illeggibile ({p}): {exc}") from exc

    if _contiene_segnaposto(dati):
        raise ConfigIncompleta(
            f"{p}: contiene ancora '{SEGNAPOSTO}'. Compila il file di scope "
            "prima di eseguire: il tool non parte su un perimetro-segnaposto."
        )

    target_raw = _richiedi(dati, "target", "<radice>")
    if not isinstance(target_raw, dict):
        raise ConfigIncompleta("target: deve essere una tabella [target]")
    base_url = _richiedi(target_raw, "base_url", "target")
    allowlist_raw = _richiedi(target_raw, "allowlist", "target")
    if (
        not isinstance(allowlist_raw, list)
        or not allowlist_raw
        or not all(isinstance(h, str) and h for h in allowlist_raw)
    ):
        raise ConfigIncompleta(
            "target.allowlist: serve una lista non vuota di host ammessi"
        )

    egress_raw = _richiedi(dati, "egress", "<radice>")
    if not isinstance(egress_raw, dict):
        raise ConfigIncompleta("egress: deve essere una tabella [egress]")
    sentinelle = _sentinelle_da_toml(_richiedi(egress_raw, "sentinelle", "egress"))

    target = ConfigTarget(
        base_url=str(base_url),
        allowlist=tuple(allowlist_raw),
        password_env=str(target_raw.get("password_env", "ASSESS_TARGET_PASSWORD")),
        operator_user=str(target_raw.get("operator_user", "")),
    )
    egress = ConfigEgress(
        sentinelle=sentinelle,
        timeout_s=float(egress_raw.get("timeout_s", 2.0)),
    )

    db_raw = dati.get("db", {})
    ssh_raw = dati.get("ssh", {})
    db = ConfigDb(dsn_env=str(db_raw.get("dsn_env", "ASSESS_DB_DSN")))
    ssh = ConfigSsh(
        host=str(ssh_raw.get("host", "")),
        user=str(ssh_raw.get("user", "assess")),
        port=int(ssh_raw.get("port", 22)),
        key_path=str(ssh_raw.get("key_path", "")),
        known_hosts_path=str(ssh_raw.get("known_hosts_path", "")),
    )
    # Fail-closed sul canale SSH: e' opzionale finche' non lo si usa (nessun
    # host -> il collector `system` resta NOT_RUN), ma un [ssh] a meta' e' un
    # errore. Se c'e' un host, servono chiave e known_hosts: un canale SSH senza
    # identita' dell'host fissata non si apre con StrictHostKeyChecking=yes, e un
    # "quasi configurato" che fallisce a runtime e' peggio di un rifiuto netto.
    if ssh.host and not (ssh.key_path and ssh.known_hosts_path):
        raise ConfigIncompleta(
            "ssh: con 'host' impostato servono anche 'key_path' e "
            "'known_hosts_path'. Per non usare l'SSH, lascia [ssh] senza 'host'."
        )
    out_dir = str(dati.get("out_dir", "assess/out"))

    return ConfigScope(target=target, egress=egress, db=db, ssh=ssh, out_dir=out_dir)


__all__ = [
    "ConfigDb",
    "ConfigEgress",
    "ConfigIncompleta",
    "ConfigScope",
    "ConfigSsh",
    "ConfigTarget",
    "SEGNAPOSTO",
    "carica",
]
