"""Autenticazione e protezione delle rotte."""

from __future__ import annotations

import pytest

from tests.helpers import PASSWORD_PROVA

#: Ogni rotta protetta, con il metodo con cui si raggiunge.
#:
#: L'elenco e' esplicito e non derivato da `app.routes`: se una rotta nuova
#: non viene aggiunta qui, il test `test_elenco_rotte_protette_completo`
#: fallisce. Un elenco che si auto-popola non si accorgerebbe mai di una
#: rotta dimenticata, che e' l'unica cosa che questo test deve trovare.
ROTTE_PROTETTE = [
    ("GET", "/api/auth/me"),
    ("GET", "/api/tools"),
    ("GET", "/api/tools/audit.lynis"),
    ("POST", "/api/tools/audit.lynis/overrides"),
    ("GET", "/api/consents"),
    ("POST", "/api/consents"),
    ("POST", "/api/consents/1/revoke"),
    ("GET", "/api/scope/networks"),
    ("POST", "/api/scope/networks"),
    ("DELETE", "/api/scope/networks/1"),
    ("GET", "/api/scope/aliases"),
    ("POST", "/api/scope/aliases"),
    ("DELETE", "/api/scope/aliases/1"),
    ("GET", "/api/audit"),
    ("GET", "/api/audit/00000000-0000-0000-0000-000000000000"),
]


@pytest.mark.parametrize(("metodo", "percorso"), ROTTE_PROTETTE)
def test_rotta_senza_sessione_restituisce_401(client, metodo: str, percorso: str) -> None:
    """Nessuna rotta e' raggiungibile senza sessione.

    Il 401 arriva prima della validazione del corpo: una rotta che validasse
    prima di autenticare direbbe a chi non e' entrato quali campi si aspetta.
    """
    risposta = client.request(metodo, percorso, json={})
    assert risposta.status_code == 401, f"{metodo} {percorso} -> {risposta.status_code}"


def test_elenco_rotte_protette_completo(client) -> None:
    """Ogni rotta sotto /api, tranne le eccezioni dichiarate, e' nell'elenco.

    Cosi' una rotta aggiunta in futuro e non coperta dal test sopra fa
    fallire questo, invece di restare non verificata.
    """
    eccezioni = {
        ("POST", "/api/auth/login"),  # apre la sessione: non puo' richiederla
        ("POST", "/api/auth/logout"),  # deve riuscire anche su un cookie rotto
        ("GET", "/api/salute"),  # sonda per l'healthcheck del container
    }
    dichiarate = {(m, p) for m, p in ROTTE_PROTETTE}

    effettive: set[tuple[str, str]] = set()
    for rotta in client.app.routes:
        percorso = getattr(rotta, "path", "")
        if not percorso.startswith("/api") or percorso.startswith("/api/openapi"):
            continue
        if percorso in ("/api/docs", "/api/docs/oauth2-redirect"):
            continue
        for metodo in getattr(rotta, "methods", set()):
            if metodo in ("HEAD", "OPTIONS"):
                continue
            effettive.add((metodo, percorso))

    # Confronto per forma del percorso: l'elenco dichiarato usa valori
    # concreti, le rotte usano segnaposto.
    def forma(coppia: tuple[str, str]) -> tuple[str, int, str]:
        metodo, percorso = coppia
        pezzi = percorso.strip("/").split("/")
        return (metodo, len(pezzi), pezzi[1] if len(pezzi) > 1 else "")

    forme_dichiarate = {forma(c) for c in dichiarate} | {forma(c) for c in eccezioni}
    non_coperte = {c for c in effettive if forma(c) not in forme_dichiarate}
    assert not non_coperte, (
        f"rotte sotto /api non coperte dai test di autenticazione: {sorted(non_coperte)}"
    )


def test_login_riuscito_apre_la_sessione(client, operatore) -> None:
    risposta = client.post(
        "/api/auth/login",
        json={"username": "operatore-test", "password": PASSWORD_PROVA},
    )
    assert risposta.status_code == 200
    assert risposta.json()["username"] == "operatore-test"
    # Nessun hash nella risposta: il contratto di uscita non lo contiene.
    assert "password_hash" not in risposta.json()
    assert client.get("/api/auth/me").status_code == 200


def test_cookie_di_sessione_httponly_e_samesite_lax(client, operatore) -> None:
    """Gli attributi del cookie sono parte della consegna, non rifiniture.

    `HttpOnly` impedisce a una XSS di leggere la sessione; `SameSite=Lax`
    impedisce al browser di inviarla su una POST che parte da un altro sito,
    che e' la difesa CSRF di questa applicazione.
    """
    risposta = client.post(
        "/api/auth/login",
        json={"username": "operatore-test", "password": PASSWORD_PROVA},
    )
    intestazione = risposta.headers["set-cookie"].lower()
    assert "hermes_session=" in intestazione
    assert "httponly" in intestazione
    assert "samesite=lax" in intestazione
    # In sviluppo `Secure` resta disattivo, altrimenti il browser non
    # invierebbe mai il cookie su http://localhost.
    assert "secure" not in intestazione


def test_password_errata_rifiutata(client, operatore) -> None:
    risposta = client.post(
        "/api/auth/login",
        json={"username": "operatore-test", "password": "sbagliata"},
    )
    assert risposta.status_code == 401


def test_utente_inesistente_indistinguibile_da_password_errata(
    client, operatore
) -> None:
    """Il messaggio non deve dire quali nomi utente esistono."""
    assente = client.post(
        "/api/auth/login", json={"username": "nessuno", "password": "x"}
    )
    sbagliata = client.post(
        "/api/auth/login", json={"username": "operatore-test", "password": "x"}
    )
    assert assente.status_code == sbagliata.status_code == 401
    assert assente.json() == sbagliata.json()


def test_logout_chiude_la_sessione(autenticato) -> None:
    assert autenticato.get("/api/auth/me").status_code == 200
    assert autenticato.post("/api/auth/logout").status_code == 204
    assert autenticato.get("/api/auth/me").status_code == 401


def test_cookie_manomesso_rifiutato(autenticato) -> None:
    """Un cookie con la firma alterata non autentica."""
    autenticato.cookies.set("hermes_session", "valore-inventato.firma-finta")
    assert autenticato.get("/api/auth/me").status_code == 401


def test_campo_non_previsto_nel_login_rifiutato(client) -> None:
    """`extra="forbid"`: un payload con campi ignoti viene rifiutato.

    Un contratto permissivo butterebbe via il campo in silenzio, e chi ha
    fatto la richiesta crederebbe di averlo impostato.
    """
    risposta = client.post(
        "/api/auth/login",
        json={"username": "x", "password": "y", "ruolo": "amministratore"},
    )
    assert risposta.status_code == 422


def test_sonda_di_salute_non_rivela_nulla(client) -> None:
    risposta = client.get("/api/salute")
    assert risposta.status_code == 200
    assert risposta.json() == {"stato": "ok"}
