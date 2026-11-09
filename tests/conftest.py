"""Infrastruttura dei test.

I test girano contro un PostgreSQL **vero**, non contro SQLite in memoria.
Non e' una preferenza: gli invarianti di questo progetto sono trigger
plpgsql, tipi ENUM ordinati e tipi `cidr`/`inet`. SQLite non ha nessuna di
queste cose, quindi una suite su SQLite verificherebbe tutto tranne la parte
che conta.

Lo schema viene ricostruito una volta per sessione di test, applicando la
migrazione: quindi la suite verifica anche che la migrazione funzioni, che e'
il codice da cui dipende l'avvio a freddo.
"""

from __future__ import annotations

import datetime as dt
import os
import subprocess
import uuid
from collections.abc import Iterator

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.orm import Session, sessionmaker

from backend.config import get_settings

TEST_SECRET = "0" * 64


#: Password del ruolo applicativo durante i test.
#:
#: Su un cluster locale con autenticazione `trust` non serve, ma in CI il
#: collegamento e' TCP con scram, quindi il ruolo deve averne una.
PASSWORD_RUOLO_APP = os.environ.get("HERMES_APP_DB_PASSWORD", "ruolo-app-di-prova")


def _url_privilegiata() -> str:
    """URL del ruolo PROPRIETARIO delle tabelle.

    E' quella con cui girano le migrazioni, il seed e i test che verificano i
    trigger in SQL diretto.
    """
    url = (
        os.environ.get("TEST_DATABASE_URL")
        or os.environ.get("MIGRATIONS_DATABASE_URL")
        or os.environ.get("DATABASE_URL")
    )
    if not url:
        pytest.skip(
            "TEST_DATABASE_URL (o MIGRATIONS_DATABASE_URL, o DATABASE_URL) "
            "non impostata: i test richiedono un PostgreSQL raggiungibile"
        )
    return url


def _url_applicativa() -> str:
    """URL del ruolo `hermes_app`, derivata da quella privilegiata.

    Stesso host e stesso database, utente diverso: cosi' la suite non ha
    bisogno di una seconda variabile d'ambiente, e non c'e' modo che le due
    URL puntino per sbaglio a database diversi -- che renderebbe i test dei
    privilegi insensati senza che nessuno se ne accorga.
    """
    return str(
        make_url(_url_privilegiata()).set(
            username="hermes_app", password=PASSWORD_RUOLO_APP
        )
    )


@pytest.fixture(scope="session", autouse=True)
def _ambiente() -> Iterator[None]:
    """Variabili d'ambiente richieste dalla configurazione dell'app."""
    os.environ["MIGRATIONS_DATABASE_URL"] = _url_privilegiata()
    os.environ["HERMES_APP_DB_PASSWORD"] = PASSWORD_RUOLO_APP
    os.environ.setdefault("APP_SECRET_KEY", TEST_SECRET)
    os.environ.setdefault("APP_ENV", "development")
    yield


@pytest.fixture(scope="session")
def engine(_ambiente: None) -> Iterator[Engine]:
    """Schema ricostruito da zero, applicando le migrazioni.

    Restituisce il motore **privilegiato**: e' quello con cui i test
    preparano i dati, perche' `tools`, `users` e `audit_events` sono in sola
    lettura per il ruolo applicativo -- il che e' esattamente il punto della
    separazione dei ruoli.

    Imposta anche `DATABASE_URL` sul ruolo applicativo, quindi
    **l'applicazione sotto test gira con le concessioni minime**: i test delle
    API verificano allo stesso tempo il contratto HTTP e il fatto che quelle
    concessioni bastino. Se mancasse un GRANT, la suite lo scoprirebbe.
    """
    url = _url_privilegiata()
    eng = create_engine(url, future=True)
    with eng.begin() as conn:
        # DROP SCHEMA e non TRUNCATE: le tabelle append-only rifiutano
        # TRUNCATE e DELETE, che e' precisamente cio' che i test verificano.
        # Azzerare i dati passa quindi dallo smontaggio dello schema, come in
        # produzione passa dalla rimozione del volume.
        conn.execute(text("DROP SCHEMA public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))

    esito = subprocess.run(
        ["alembic", "upgrade", "head"],
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "MIGRATIONS_DATABASE_URL": url,
            "HERMES_APP_DB_PASSWORD": PASSWORD_RUOLO_APP,
        },
    )
    if esito.returncode != 0:
        pytest.fail(f"alembic upgrade head e' fallito:\n{esito.stderr}")

    # Da qui l'applicazione usa il ruolo applicativo, creato dalla 0002.
    os.environ["DATABASE_URL"] = _url_applicativa()
    get_settings.cache_clear()

    yield eng
    eng.dispose()


@pytest.fixture(scope="session")
def engine_app(engine: Engine) -> Iterator[Engine]:
    """Motore con il ruolo `hermes_app`, per i test sui privilegi."""
    eng = create_engine(_url_applicativa(), future=True)
    yield eng
    eng.dispose()


@pytest.fixture
def db(engine: Engine) -> Iterator[Session]:
    """Una sessione per test."""
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False, future=True)
    sessione = factory()
    try:
        yield sessione
    finally:
        sessione.rollback()
        sessione.close()


@pytest.fixture
def nuovo_tool(db: Session):
    """Crea un tool con `tool_id` univoco e ne restituisce la chiave primaria.

    Univoco perche' i test non possono ripulirsi a vicenda: `tier_overrides`
    e' append-only, quindi un tool riusato fra due test porterebbe gli
    override del primo nel secondo. Ogni test lavora sul proprio tool.
    """

    def _crea(
        *,
        declared_tier: str = "verde",
        personal_data: bool = False,
        agent: str = "vuln_assessment",
        target_kind: str = "none",
        tool_id: str | None = None,
    ) -> int:
        identificativo = tool_id or f"prova.t{uuid.uuid4().hex[:12]}"
        pk = db.execute(
            text(
                """
                INSERT INTO tools (tool_id, agent, declared_tier, personal_data,
                                   requires_container, target_kind, exec_path,
                                   exec_sha256, exec_args, description)
                VALUES (:tool_id, :agent, :tier, :pd, false, :tk,
                        'agents/prova/run.py',
                        '34b7aa6afc7f96e5c88ecfd8f4305a0739743bc5a1f7aa27ee2b63546518d3a8',
                        '{}', 'Tool di prova.')
                RETURNING id
                """
            ),
            {
                "tool_id": identificativo,
                "agent": agent,
                "tier": declared_tier,
                "pd": personal_data,
                "tk": target_kind,
            },
        ).scalar_one()
        db.commit()
        return pk

    return _crea


@pytest.fixture
def perimetro_pulito(db: Session) -> Iterator[None]:
    """Perimetro vuoto all'inizio e alla fine del test.

    `scope_networks` e `scope_aliases` non sono append-only — il perimetro si
    modifica, e' il suo scopo — quindi qui si puo' ripulire davvero.
    Gli alias prima delle reti: il trigger che vieta gli alias orfani
    rifiuterebbe l'ordine inverso.
    """
    db.execute(text("DELETE FROM scope_aliases"))
    db.execute(text("DELETE FROM scope_networks"))
    db.commit()
    yield
    db.rollback()
    db.execute(text("DELETE FROM scope_aliases"))
    db.execute(text("DELETE FROM scope_networks"))
    db.commit()


def sqlstate(exc: Exception) -> str | None:
    """Codice SQLSTATE di un'eccezione SQLAlchemy.

    I test controllano il CODICE e non il testo del messaggio: il testo e' per
    l'operatore e puo' essere riscritto, il codice e' il contratto fra
    database e applicazione.
    """
    orig = getattr(exc, "orig", None)
    return getattr(orig, "sqlstate", None)


def adesso() -> dt.datetime:
    return dt.datetime.now(tz=dt.UTC)


# --------------------------------------------------------------------------- #
# Client HTTP
# --------------------------------------------------------------------------- #

#: Password dell'operatore dei test. Non e' un segreto: e' un valore di prova
#: su un database di prova, e sta qui invece che in una variabile d'ambiente
#: perche' i test devono poterla usare per autenticarsi.
PASSWORD_PROVA = "password-di-prova-dei-test"


@pytest.fixture
def client(engine: Engine):
    """Client HTTP sull'applicazione.

    L'applicazione viene importata **dentro** la fixture e non in testa al
    modulo: la configurazione legge l'ambiente all'import, e a quel punto la
    fixture che lo imposta ha gia' girato. Un import in testa al file
    girerebbe in fase di raccolta dei test, prima.
    """
    from fastapi.testclient import TestClient

    from backend.main import crea_app

    with TestClient(crea_app()) as c:
        yield c


@pytest.fixture
def operatore(db: Session):
    """Crea l'operatore dei test, se non c'e' gia'."""
    from backend.models import User
    from backend.security import cifra_password

    esistente = db.query(User).filter(User.username == "operatore-test").one_or_none()
    if esistente is None:
        esistente = User(
            username="operatore-test", password_hash=cifra_password(PASSWORD_PROVA)
        )
        db.add(esistente)
        db.commit()
    return esistente


@pytest.fixture
def autenticato(client, operatore):
    """Client con una sessione aperta."""
    risposta = client.post(
        "/api/auth/login",
        json={"username": "operatore-test", "password": PASSWORD_PROVA},
    )
    assert risposta.status_code == 200, risposta.text
    return client


@pytest.fixture
def dati_esempio(db: Session, operatore):
    """Popola il database con i dati seed, se non ci sono gia'.

    Usa la stessa funzione dell'avvio, non una copia: cosi' i test verificano
    anche che il seed produca dati che rispettano i vincoli, che e' il codice
    da cui dipende `docker compose up` su una macchina pulita.
    """
    from backend.models import Tool
    from backend.seed import popola

    if db.query(Tool).count() == 0:
        popola(db, con_operatore=False)
    return db
