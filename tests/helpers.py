"""Funzioni di supporto condivise fra i moduli di test.

Stanno qui e non in ``conftest.py`` perche' ``conftest`` e' un file con
semantica speciale per pytest -- viene caricato da lui, non importato da noi --
e importarlo direttamente funziona solo se la radice del repository e' su
``sys.path``. Con `python -m pytest` lo e' per effetto collaterale di `-m`,
con l'eseguibile `pytest` no: la suite collezionava in un modo e non
nell'altro, e la differenza si e' vista soltanto installando il pacchetto in
un venv pulito come fa l'integrazione continua.

Le *fixture* restano in ``conftest.py``, dove pytest le cerca. Qui c'e'
soltanto codice che si importa come qualunque altro modulo.
"""

from __future__ import annotations

import datetime as dt

#: Password dell'operatore nei test.
#:
#: Non e' un segreto: e' un valore di prova su un database di prova. Sta in
#: chiaro perche' i test devono poterla usare per autenticarsi.
PASSWORD_PROVA = "password-di-prova-dei-test"

#: Password del ruolo applicativo durante i test, se l'ambiente non ne da' una.
#:
#: Su un cluster locale con autenticazione `trust` non serve, ma in CI il
#: collegamento e' TCP con scram, quindi il ruolo deve averne una.
PASSWORD_RUOLO_APP_DEFAULT = "ruolo-app-di-prova"


def nome_vincolo(exc: BaseException) -> str | None:
    """Nome del vincolo violato, dalla diagnostica di PostgreSQL.

    Come `sqlstate`, si legge dal campo diagnostico e non dal testo del
    messaggio. Serve a verificare **quale** vincolo ha rifiutato una riga, non
    solo che qualcosa l'abbia rifiutata: con sette regole di forma sullo
    stesso campo, «e' stata rifiutata» non dice se e' stata rifiutata per la
    ragione giusta.
    """
    orig = getattr(exc, "orig", None)
    diag = getattr(orig, "diag", None)
    return getattr(diag, "constraint_name", None)


def sqlstate(exc: BaseException) -> str | None:
    """Codice SQLSTATE di un'eccezione SQLAlchemy.

    I test controllano il CODICE e non il testo del messaggio: il testo e' per
    l'operatore e puo' essere riscritto, il codice e' il contratto fra
    database e applicazione.
    """
    orig = getattr(exc, "orig", None)
    return getattr(orig, "sqlstate", None)


def adesso() -> dt.datetime:
    """Istante corrente, sempre con il fuso orario.

    Un istante senza fuso non e' confrontabile con le colonne `timestamptz`
    dello schema.
    """
    return dt.datetime.now(tz=dt.UTC)
