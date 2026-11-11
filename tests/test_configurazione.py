"""Due configurazioni, due insiemi di requisiti.

`backend/config.py` tiene separata la configurazione di cio' che serve
richieste da quella di cio' che modifica lo schema. Questi test fissano
entrambe le meta' della separazione, perche' una sola non basta:

- migrazioni e seed devono poter girare **senza** i segreti
  dell'applicazione (era il difetto: `python -m backend.seed` pretendeva una
  chiave di firma del cookie per scrivere delle righe);
- l'applicazione deve continuare a pretenderli, tutti, all'avvio. Questo e'
  il criterio SPEC §11 «l'avvio fallisce senza .env», e allentarlo per
  comodita' del seed sarebbe stato uno scambio molto peggiore del problema.

Ogni caso gira in un sottoprocesso con l'ambiente SVUOTATO e in una
directory vuota. Non e' pignoleria: `Settings` legge anche `.env`, e su una
macchina di sviluppo quel file esiste e contiene proprio le variabili che
questi test vogliono assenti. In processo, con `monkeypatch`, il test
passerebbe o no a seconda di cosa ha in radice chi lo esegue.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

RADICE = Path(__file__).resolve().parent.parent

#: URL fittizie: questi test non si connettono a niente, guardano soltanto se
#: la configurazione si costruisce e con quale valore.
URL_PRIVILEGIATA = "postgresql+psycopg://proprietario:x@localhost:5432/hermes_panel"
URL_APPLICATIVA = "postgresql+psycopg://hermes_app:y@localhost:5432/hermes_panel"


def _esegui(codice: str, ambiente: dict[str, str], tmp_path: Path) -> str:
    """Esegue `codice` in un processo pulito e restituisce il suo stdout.

    L'ambiente contiene solo `PATH` e `PYTHONPATH`: `backend` e' importabile
    dalla radice del repository, ma la directory di lavoro e' vuota, quindi
    il `.env` della radice non viene letto. E' quello che rende il test
    indipendente dalla macchina su cui gira.

    Niente `-I`: la modalita' isolata implica `-E`, cioe' scarta proprio il
    `PYTHONPATH` che serve a trovare `backend`. L'isolamento qui lo da' la
    directory vuota.
    """
    esito = subprocess.run(
        [sys.executable, "-c", codice],
        capture_output=True,
        text=True,
        cwd=tmp_path,
        env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(RADICE), **ambiente},
    )
    assert esito.returncode == 0, (
        f"il sottoprocesso e' fallito (stato {esito.returncode}):\n{esito.stderr}"
    )
    return esito.stdout.strip()


# --------------------------------------------------------------------------- #
# Cio' che modifica lo schema
# --------------------------------------------------------------------------- #

_LEGGI_PRIVILEGIATA = """
from backend.config import ImpostazioniPrivilegiate
print(ImpostazioniPrivilegiate().url)
"""


def test_migrazioni_e_seed_non_pretendono_i_segreti_dell_applicazione(tmp_path):
    """Con la sola URL privilegiata, la configurazione del seed si costruisce.

    E' il difetto che questo test chiude: prima il seed passava da
    `Settings`, quindi non partiva senza `DATABASE_URL` e `APP_SECRET_KEY` --
    due valori che non usa. Chi lo eseguiva a mano doveva inventarseli, e un
    requisito che si soddisfa inventando un valore non verifica niente.
    """
    letta = _esegui(
        _LEGGI_PRIVILEGIATA,
        {"MIGRATIONS_DATABASE_URL": URL_PRIVILEGIATA},
        tmp_path,
    )
    assert letta == URL_PRIVILEGIATA


def test_la_privilegiata_ha_precedenza_sulla_url_applicativa(tmp_path):
    """Con entrambe impostate vince quella privilegiata.

    L'ordine non e' arbitrario. Invertirlo farebbe girare le migrazioni con
    il ruolo applicativo, che non possiede le tabelle: il guasto si
    presenterebbe come un errore sui permessi al primo CREATE, invece che
    come un errore di configurazione.
    """
    letta = _esegui(
        _LEGGI_PRIVILEGIATA,
        {
            "MIGRATIONS_DATABASE_URL": URL_PRIVILEGIATA,
            "DATABASE_URL": URL_APPLICATIVA,
        },
        tmp_path,
    )
    assert letta == URL_PRIVILEGIATA


def test_con_la_sola_url_applicativa_ripiega_su_quella(tmp_path):
    """Ripiego dichiarato: in sviluppo locale spesso esiste un solo ruolo.

    Non e' una configurazione valida in esercizio, ed e' il compose a
    renderla impossibile li': imposta le due URL distinte. Il ripiego vive
    per la macchina di chi sviluppa, dove un solo ruolo e' la norma.
    """
    letta = _esegui(_LEGGI_PRIVILEGIATA, {"DATABASE_URL": URL_APPLICATIVA}, tmp_path)
    assert letta == URL_APPLICATIVA


def test_senza_nessuna_url_il_messaggio_dice_cosa_esportare(tmp_path):
    """Un errore di configurazione deve dire come si corregge.

    «KeyError: MIGRATIONS_DATABASE_URL» dice cosa manca a chi conosce il
    codice. Il comando da eseguire lo dice a chiunque.
    """
    codice = """
from backend.config import ImpostazioniPrivilegiate
try:
    ImpostazioniPrivilegiate().url
except RuntimeError as e:
    print(str(e))
else:
    raise AssertionError("senza nessuna URL la configurazione si e' costruita")
"""
    messaggio = _esegui(codice, {}, tmp_path)
    assert "MIGRATIONS_DATABASE_URL" in messaggio
    assert "DATABASE_URL" in messaggio
    # Il comando, non solo il nome della variabile.
    assert "export MIGRATIONS_DATABASE_URL=" in messaggio


# --------------------------------------------------------------------------- #
# Cio' che serve richieste
#
# La separazione non deve essere diventata una scorciatoia per far partire
# l'applicazione senza segreti.
# --------------------------------------------------------------------------- #


def test_l_applicazione_pretende_ancora_tutti_i_suoi_segreti(tmp_path):
    """Con la sola URL privilegiata, `Settings` deve rifiutarsi di costruirsi.

    Criterio SPEC §11: senza `.env` l'avvio fallisce. La configurazione
    privilegiata ora si accontenta di poco, ma quella dell'applicazione no:
    le mancano l'URL del ruolo con cui servire e la chiave di firma del
    cookie, e un default per la seconda sarebbe una chiave nota a chi ha
    letto il repository.
    """
    codice = """
import json
from pydantic import ValidationError
from backend.config import Settings
try:
    Settings()
except ValidationError as e:
    print(json.dumps(sorted(str(r["loc"][0]) for r in e.errors())))
else:
    raise AssertionError("Settings si e' costruita senza segreti")
"""
    mancanti = json.loads(
        _esegui(codice, {"MIGRATIONS_DATABASE_URL": URL_PRIVILEGIATA}, tmp_path)
    )
    assert mancanti == ["APP_SECRET_KEY", "DATABASE_URL"]


def test_una_chiave_di_firma_corta_viene_rifiutata(tmp_path):
    """Il controllo sulla lunghezza non e' stato perso nella separazione.

    Una chiave di 8 caratteri si attacca a forza bruta fuori linea, e il
    risultato e' un cookie di sessione valido per l'unico account del
    pannello.
    """
    codice = """
from pydantic import ValidationError
from backend.config import Settings
try:
    Settings()
except ValidationError as e:
    print(str(e))
else:
    raise AssertionError("una chiave corta e' stata accettata")
"""
    messaggio = _esegui(
        codice,
        {"DATABASE_URL": URL_APPLICATIVA, "APP_SECRET_KEY": "corta"},
        tmp_path,
    )
    assert "32 caratteri" in messaggio
