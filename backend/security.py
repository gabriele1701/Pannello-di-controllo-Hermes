"""Autenticazione dell'operatore e sessione.

Un solo utente umano, da browser. Nessuna API key, nessun token di servizio,
nessun meccanismo pensato per un client automatico — e' il vincolo
architetturale di questa applicazione: gli agenti LLM non devono poterla
raggiungere, perche' e' lei a decidere cosa gli agenti possono fare. Una
chiave di servizio esisterebbe per essere usata da un programma, e un
programma che puo' alzare i propri permessi e' il modello di sicurezza che
crolla.

Password con **argon2id**
-------------------------

``argon2-cffi`` con i parametri predefiniti della libreria, che sono quelli
raccomandati e non una scelta nostra. Argon2 e' resistente alla
parallelizzazione su GPU perche' richiede memoria, non solo cicli: e' la
proprieta' che distingue un hash moderno da uno SHA iterato.

Mai bcrypt con sale fisso, mai uno SHA nudo: uno SHA si calcola a miliardi
al secondo su hardware comune, quindi una password ordinaria si ritrova in
minuti partendo dal solo hash.

Sessione in cookie firmato
--------------------------

Il cookie contiene l'identita' dell'operatore, firmata con
``APP_SECRET_KEY``: il browser lo porta, non lo puo' falsificare. Non c'e'
una tabella delle sessioni perche' con un utente solo non servirebbe a
niente che non si ottenga ruotando la chiave, che invalida tutto in un colpo.

Attributi, e perche':

* ``HttpOnly`` — JavaScript non lo legge. Se una XSS entrasse nella pagina,
  non potrebbe esfiltrare la sessione.
* ``SameSite=Lax`` — il browser non invia il cookie su una richiesta POST
  che parte da un altro sito. E' la difesa CSRF di questa applicazione: senza
  cookie, una richiesta forgiata da un'altra origine arriva non autenticata.
  Le richieste di navigazione GET lo portano, ed e' voluto: servono a far
  funzionare i link.
* ``Secure`` in produzione — il cookie non parte su HTTP in chiaro. In
  sviluppo resta disattivo, altrimenti il browser non lo invierebbe mai su
  ``http://localhost`` e il login non funzionerebbe.
* scadenza — una sessione che non scade non e' una sessione.
"""

from __future__ import annotations

from typing import Annotated, Final

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from fastapi import Cookie, Depends, HTTPException, Response, status
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.config import Settings, get_settings
from backend.db import get_db
from backend.models import User

#: Nome del cookie di sessione.
NOME_COOKIE: Final = "hermes_session"

_hasher = PasswordHasher()


# --------------------------------------------------------------------------- #
# Password
# --------------------------------------------------------------------------- #


def cifra_password(password: str) -> str:
    """Hash argon2id della password."""
    return _hasher.hash(password)


def verifica_password(hash_memorizzato: str, password: str) -> bool:
    """Verifica una password contro il proprio hash.

    Restituisce ``False`` anche quando l'hash e' malformato: un hash illeggibile
    non autentica nessuno, e far propagare l'eccezione rivelerebbe al
    chiamante la differenza fra «password sbagliata» e «record rovinato».
    """
    try:
        return _hasher.verify(hash_memorizzato, password)
    except (VerifyMismatchError, InvalidHashError):
        return False


# --------------------------------------------------------------------------- #
# Sessione
# --------------------------------------------------------------------------- #


def _serializer(impostazioni: Settings) -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(
        impostazioni.secret_key.get_secret_value(),
        salt="hermes-panel-session",
    )


def apri_sessione(response: Response, utente: User, impostazioni: Settings) -> None:
    """Imposta il cookie di sessione sulla risposta."""
    token = _serializer(impostazioni).dumps(
        {"uid": utente.id, "username": utente.username}
    )
    response.set_cookie(
        key=NOME_COOKIE,
        value=token,
        max_age=impostazioni.session_max_age_seconds,
        httponly=True,
        samesite="lax",
        secure=impostazioni.cookie_secure,
        path="/",
    )


def chiudi_sessione(response: Response, impostazioni: Settings) -> None:
    """Rimuove il cookie di sessione.

    Gli attributi vanno ripetuti: un browser cancella il cookie solo se
    quelli della richiesta di cancellazione combaciano con quelli con cui era
    stato impostato.
    """
    response.delete_cookie(
        key=NOME_COOKIE,
        httponly=True,
        samesite="lax",
        secure=impostazioni.cookie_secure,
        path="/",
    )


_NON_AUTENTICATO = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail={"messaggio": "Sessione assente o scaduta. Occorre autenticarsi."},
)


def operatore_corrente(
    hermes_session: Annotated[str | None, Cookie()] = None,
    db: Session = Depends(get_db),
    impostazioni: Settings = Depends(get_settings),
) -> User:
    """Dipendenza di autenticazione: l'operatore della richiesta.

    Va applicata a **ogni** rotta tranne il login. Il default non e'
    l'accesso libero: una rotta che dimentica questa dipendenza e' una rotta
    aperta, quindi in ``main.py`` la dipendenza e' dichiarata sull'intero
    router delle API e non rotta per rotta.
    """
    if not hermes_session:
        raise _NON_AUTENTICATO

    try:
        dati = _serializer(impostazioni).loads(
            hermes_session, max_age=impostazioni.session_max_age_seconds
        )
    except SignatureExpired as err:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"messaggio": "Sessione scaduta. Occorre autenticarsi di nuovo."},
        ) from err
    except BadSignature as err:
        # Firma non valida: il cookie e' stato manomesso, o la chiave e' stata
        # ruotata. In entrambi i casi non autentica.
        raise _NON_AUTENTICATO from err

    if not isinstance(dati, dict) or "uid" not in dati:
        raise _NON_AUTENTICATO

    utente = db.get(User, dati["uid"])
    if utente is None:
        # Firma valida ma l'utente non c'e' piu': un cookie non deve
        # sopravvivere all'account che rappresenta.
        raise _NON_AUTENTICATO
    return utente


Operatore = Annotated[User, Depends(operatore_corrente)]
