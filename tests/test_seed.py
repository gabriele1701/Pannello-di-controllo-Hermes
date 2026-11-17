"""I due percorsi del seed: bootstrap predefinito, dimostrativo esplicito.

Questi test eseguono **il comando vero** -- ``python -m backend.seed``, in un
processo a parte, con le variabili che gli passerebbe il compose -- su un
database creato apposta e vuoto. Non chiamano le funzioni del modulo, e la
ragione e' il difetto che devono prevenire: che i dati dimostrativi tornino
predefiniti. Quel difetto vivrebbe nel modo in cui opzione e variabile
d'ambiente arrivano a ``main``, cioe' esattamente nella parte che una chiamata
diretta salta.

Un database per test, e non quello condiviso della suite: ``tier_overrides`` e
``audit_events`` non si possono cancellare, quindi «il database e' vuoto» e'
una condizione che si puo' solo creare, non ripristinare. Sperare che un altro
test non abbia gia' popolato sarebbe sperare una proprieta' dell'ambiente.
"""

from __future__ import annotations

import os
import subprocess
import sys
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine, make_url

from backend.seed import OPZIONE_DEMO, VARIABILE_DEMO, dimostrativo_richiesto
from tests.conftest import PASSWORD_RUOLO_APP, _url_privilegiata

RADICE = Path(__file__).resolve().parent.parent
PASSWORD_OPERATORE = "una-password-solo-per-questo-test"

#: Le tabelle che il percorso dimostrativo popola, per nome SQL. Scritte qui e
#: non importate da ``backend.seed``: se il seed ne dimenticasse una nel
#: proprio elenco, un test che usa lo stesso elenco non se ne accorgerebbe.
TABELLE_DIMOSTRATIVE = (
    "tools",
    "tier_overrides",
    "scope_networks",
    "scope_aliases",
    "scope_paths",
    "scope_consents",
    "audit_events",
)


class BancaPulita:
    """Un database appena migrato, e il modo di lanciarci sopra il seed."""

    def __init__(self, url: str) -> None:
        self.url = url
        self.motore: Engine = create_engine(url, future=True)

    def seed(
        self, *argomenti: str, ambiente: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess:
        env = {
            k: v
            for k, v in os.environ.items()
            # Niente di cio' che la sessione di test ha impostato per
            # l'applicazione: il seed deve bastare a se stesso, e soprattutto
            # non deve ereditare una richiesta di dati dimostrativi.
            if k not in {VARIABILE_DEMO, "DATABASE_URL", "HERMES_ADMIN_USERNAME"}
        }
        env["MIGRATIONS_DATABASE_URL"] = self.url
        env["HERMES_ADMIN_PASSWORD"] = PASSWORD_OPERATORE
        env.update(ambiente or {})
        return subprocess.run(
            [sys.executable, "-m", "backend.seed", *argomenti],
            capture_output=True,
            text=True,
            cwd=RADICE,
            env=env,
            timeout=120,
            check=False,
        )

    def righe(self, tabella: str) -> int:
        with self.motore.connect() as conn:
            return conn.execute(text(f"SELECT count(*) FROM {tabella}")).scalar_one()

    @property
    def conteggi(self) -> dict[str, int]:
        return {t: self.righe(t) for t in TABELLE_DIMOSTRATIVE}

    @property
    def operatori(self) -> list[str]:
        with self.motore.connect() as conn:
            return list(conn.execute(text("SELECT username FROM users")).scalars())


@pytest.fixture
def banca(_ambiente: None) -> Iterator[BancaPulita]:
    base = make_url(_url_privilegiata())
    nome = f"hermes_seed_{uuid.uuid4().hex[:12]}"
    amministrazione = create_engine(base, isolation_level="AUTOCOMMIT", future=True)
    with amministrazione.connect() as conn:
        conn.execute(text(f'CREATE DATABASE "{nome}"'))

    url = base.set(database=nome).render_as_string(hide_password=False)
    migrazioni = subprocess.run(
        ["alembic", "upgrade", "head"],
        capture_output=True,
        text=True,
        cwd=RADICE,
        env={
            **os.environ,
            "MIGRATIONS_DATABASE_URL": url,
            "HERMES_APP_DB_PASSWORD": PASSWORD_RUOLO_APP,
        },
        check=False,
    )
    if migrazioni.returncode != 0:
        pytest.fail(f"alembic upgrade head e' fallito:\n{migrazioni.stderr}")

    banca = BancaPulita(url)
    try:
        yield banca
    finally:
        banca.motore.dispose()
        with amministrazione.connect() as conn:
            conn.execute(text(f'DROP DATABASE "{nome}" WITH (FORCE)'))
        amministrazione.dispose()


def _tutte_vuote(conteggi: dict[str, int]) -> bool:
    return all(n == 0 for n in conteggi.values())


# --------------------------------------------------------------------------- #
# Bootstrap: il percorso predefinito
# --------------------------------------------------------------------------- #


def test_un_installazione_pulita_crea_solo_l_operatore(banca: BancaPulita):
    """Il criterio di accettazione, alla lettera."""
    esito = banca.seed()
    assert esito.returncode == 0, esito.stderr
    assert banca.operatori == ["operatore"]
    assert banca.conteggi == dict.fromkeys(TABELLE_DIMOSTRATIVE, 0)
    assert "installazione pulita" in esito.stdout
    # E dice come avere i dati di esempio, a chi li cercava.
    assert OPZIONE_DEMO in esito.stdout


@pytest.mark.parametrize("valore", ["0", "false", "no", ""])
def test_la_variabile_a_zero_e_un_installazione_pulita(banca: BancaPulita, valore: str):
    esito = banca.seed(ambiente={VARIABILE_DEMO: valore})
    assert esito.returncode == 0, esito.stderr
    assert banca.operatori == ["operatore"]
    assert _tutte_vuote(banca.conteggi)


def test_il_bootstrap_rieseguito_non_tocca_niente(banca: BancaPulita):
    """L'entrypoint lo lancia a ogni avvio: il secondo non deve fare nulla."""
    assert banca.seed().returncode == 0
    secondo = banca.seed()
    assert secondo.returncode == 0, secondo.stderr
    assert banca.operatori == ["operatore"]
    assert _tutte_vuote(banca.conteggi)
    assert "bootstrap gia' eseguito" in secondo.stdout


def test_senza_password_il_bootstrap_si_ferma_e_non_scrive(banca: BancaPulita):
    esito = banca.seed(ambiente={"HERMES_ADMIN_PASSWORD": ""})
    assert esito.returncode == 1
    assert "HERMES_ADMIN_PASSWORD" in esito.stderr
    assert banca.operatori == []


# --------------------------------------------------------------------------- #
# Dimostrativo: il percorso esplicito
# --------------------------------------------------------------------------- #


def test_il_percorso_dimostrativo_ripopola_un_installazione_pulita(banca: BancaPulita):
    """L'ordine in cui lo incontra chi lo usa: prima pulita, poi chiesti.

    E' anche il caso che il vecchio criterio di «vuoto» avrebbe sbagliato:
    con l'operatore gia' creato il seed di prima non faceva niente.
    """
    assert banca.seed().returncode == 0
    assert _tutte_vuote(banca.conteggi)

    esito = banca.seed(OPZIONE_DEMO)
    assert esito.returncode == 0, esito.stderr
    conteggi = banca.conteggi
    assert all(n > 0 for n in conteggi.values()), conteggi
    assert banca.operatori == ["operatore"], "il dimostrativo non crea operatori"
    assert "DATI DIMOSTRATIVI" in esito.stdout
    assert "inventati" in esito.stdout


def test_la_variabile_a_uno_fa_bootstrap_e_dimostrativo_al_primo_avvio(
    banca: BancaPulita,
):
    esito = banca.seed(ambiente={VARIABILE_DEMO: "1"})
    assert esito.returncode == 0, esito.stderr
    assert banca.operatori == ["operatore"]
    assert all(n > 0 for n in banca.conteggi.values())


def test_il_dimostrativo_rieseguito_non_duplica(banca: BancaPulita):
    """Innalzamenti ed eventi d'audit non si cancellano: un doppio resterebbe."""
    assert banca.seed(OPZIONE_DEMO).returncode == 0
    prima = banca.conteggi

    secondo = banca.seed(OPZIONE_DEMO)
    assert secondo.returncode == 0, secondo.stderr
    assert banca.conteggi == prima
    assert "NON scritti" in secondo.stdout


def test_il_dimostrativo_non_si_mescola_a_dati_esistenti(banca: BancaPulita):
    """Una sola riga vera basta a fermarlo, e il messaggio dice quale.

    Qui la riga e' una rete dichiarata dall'operatore. Dati inventati accanto
    a dati veri non si distinguerebbero piu', in un pannello il cui prodotto
    e' la traccia.
    """
    assert banca.seed().returncode == 0
    with banca.motore.begin() as conn:
        conn.execute(
            text("INSERT INTO scope_networks (cidr, label) VALUES ('10.99.0.0/24', 'vera')")
        )

    esito = banca.seed(OPZIONE_DEMO)
    assert esito.returncode == 0, esito.stderr
    assert "NON scritti" in esito.stdout
    assert "reti (1)" in esito.stdout
    conteggi = banca.conteggi
    assert conteggi.pop("scope_networks") == 1
    assert _tutte_vuote(conteggi)


# --------------------------------------------------------------------------- #
# Cio' che non si capisce ferma, non vale «no»
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("valore", ["on", "demo", "2", "vero"])
def test_un_valore_non_riconosciuto_ferma_il_seed_prima_di_scrivere(
    banca: BancaPulita, valore: str
):
    """Chi scrive `HERMES_SEED_DEMO=on` voleva i dati.

    Un'installazione che parte vuota senza dire perche' e' un errore di
    battitura che si scopre davanti a chi doveva vederla. Si ferma prima di
    creare anche l'operatore: un avvio a meta' e' peggio di uno non iniziato.
    """
    esito = banca.seed(ambiente={VARIABILE_DEMO: valore})
    assert esito.returncode == 2
    assert VARIABILE_DEMO in esito.stderr
    assert banca.operatori == []


def test_un_argomento_ignoto_ferma_il_seed(banca: BancaPulita):
    esito = banca.seed("--demo")
    assert esito.returncode == 2
    assert OPZIONE_DEMO in esito.stderr
    assert banca.operatori == []


# --------------------------------------------------------------------------- #
# La decisione, da sola
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("argv", "ambiente", "atteso"),
    [
        ([], {}, False),
        ([], {VARIABILE_DEMO: "0"}, False),
        ([], {VARIABILE_DEMO: "1"}, True),
        ([], {VARIABILE_DEMO: " SI "}, True),
        ([], {VARIABILE_DEMO: "True"}, True),
        ([OPZIONE_DEMO], {}, True),
        # L'opzione esplicita vince su una variabile che dice di no: chi la
        # scrive a mano sta chiedendo esattamente quello.
        ([OPZIONE_DEMO], {VARIABILE_DEMO: "0"}, True),
    ],
)
def test_chi_chiede_il_dimostrativo(argv, ambiente, atteso):
    assert dimostrativo_richiesto(argv, ambiente) is atteso


def test_il_compose_non_chiede_il_dimostrativo_per_conto_suo():
    """Il default sta in tre posti, e devono dire tutti «no».

    Il compose, `.env.example` e il codice. Uno solo che dicesse «si'»
    basterebbe a far nascere ogni installazione con dati inventati.
    """
    compose = (RADICE / "compose.yaml").read_text(encoding="utf-8")
    assert f'{VARIABILE_DEMO}: "${{{VARIABILE_DEMO}:-0}}"' in compose

    esempio = (RADICE / ".env.example").read_text(encoding="utf-8")
    assegnazioni = [
        riga for riga in esempio.splitlines() if riga.startswith(f"{VARIABILE_DEMO}=")
    ]
    assert assegnazioni == [f"{VARIABILE_DEMO}=0"]


# --------------------------------------------------------------------------- #
# La migrazione 0005 e le righe che ci sono gia'
# --------------------------------------------------------------------------- #


def _alembic(url: str, *argomenti: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["alembic", *argomenti],
        capture_output=True,
        text=True,
        cwd=RADICE,
        env={
            **os.environ,
            "MIGRATIONS_DATABASE_URL": url,
            "HERMES_APP_DB_PASSWORD": PASSWORD_RUOLO_APP,
        },
        check=False,
    )


def test_la_0005_si_ferma_su_un_prefisso_non_montabile_e_dice_quale(
    banca: BancaPulita,
):
    """Una migrazione non cancella una riga di policy per conto dell'operatore.

    Sta in questo file perche' ha bisogno della stessa cosa dei test del
    seed: un database suo, da portare avanti e indietro fra due revisioni.

    Si torna alla 0004, si dichiara un prefisso che allora era lecito, e si
    risale. `ADD CONSTRAINT` da solo fallirebbe nominando il vincolo e non la
    riga; qui deve fallire nominando il prefisso, e lasciare la tabella
    com'era -- compresa la riga buona accanto.
    """
    assert _alembic(banca.url, "downgrade", "0004_perimetro_percorsi").returncode == 0
    with banca.motore.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO scope_paths (prefix, label) VALUES "
                "('/srv/dati condivisi', 'lecito fino alla 0004'), "
                "('/srv/buono', 'resta')"
            )
        )

    esito = _alembic(banca.url, "upgrade", "head")
    assert esito.returncode != 0
    assert "'/srv/dati condivisi'" in esito.stderr
    assert "/srv/buono" not in esito.stderr
    assert "Non vengono cancellati in automatico" in esito.stderr
    assert banca.righe("scope_paths") == 2

    # Tolto dall'operatore, la migrazione passa e il vincolo c'e'.
    with banca.motore.begin() as conn:
        conn.execute(text("DELETE FROM scope_paths WHERE prefix = '/srv/dati condivisi'"))
    assert _alembic(banca.url, "upgrade", "head").returncode == 0
    with pytest.raises(Exception, match="scope_paths_prefix_trascrivibile"):
        with banca.motore.begin() as conn:
            conn.execute(
                text("INSERT INTO scope_paths (prefix, label) VALUES ('/srv/a b', 'x')")
            )
    assert banca.righe("scope_paths") == 1


def test_i_prefissi_dimostrativi_sono_montabili(banca: BancaPulita):
    """I dati di esempio devono rispettare le regole che mostrano."""
    assert banca.seed(OPZIONE_DEMO).returncode == 0
    with banca.motore.connect() as conn:
        prefissi = list(conn.execute(text("SELECT prefix FROM scope_paths")).scalars())
    assert prefissi
    import re

    assert all(re.fullmatch(r"(/[A-Za-z0-9._-]+)+", p) for p in prefissi), prefissi
