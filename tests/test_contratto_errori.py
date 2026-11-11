"""Le risposte di errore sono nel contratto, e il contratto dice il vero.

`openapi.json` e' l'unico documento che backend e interfaccia condividono, e
finche' non dichiarava le risposte di errore l'interfaccia doveva indovinarne
la forma a runtime. Dichiararle non basta pero' a renderle vere: una
`responses` e' una promessa scritta a mano accanto a una rotta, e niente
obbliga la rotta a mantenerla.

Questi test sono quell'obbligo, su quattro livelli:

1. ogni `$ref` del documento risolve (un riferimento rotto non si lamenta:
   produce un generatore di tipi che fallisce o, peggio, tace);
2. nessuna risposta di errore e' dichiarata senza schema;
3. i corpi di errore **veri**, ottenuti chiamando l'API, validano contro lo
   schema che il contratto dichiara per quel codice su quella rotta;
4. ogni rotta protetta dichiara il 401 che la sua dipendenza produce.

Il terzo e' quello che conta: gli altri verificano che il documento sia ben
formato, lui verifica che corrisponda al comportamento.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

import jsonschema
import pytest

# --------------------------------------------------------------------------- #
# Il documento
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def contratto(engine) -> dict[str, Any]:
    """Lo schema generato dall'applicazione.

    Generato e non letto da `openapi.json`: questi test verificano il
    comportamento del codice, mentre che il file committato corrisponda al
    codice lo verifica il lavoro `contratto` della CI. Due responsabilita'
    distinte in due posti distinti, invece che la stessa due volte.
    """
    from backend.main import crea_app

    return crea_app().openapi()


def _riferimenti(nodo: Any) -> list[str]:
    """Tutti i valori di `$ref` dentro un documento, a qualunque profondita'."""
    if isinstance(nodo, dict):
        trovati = [nodo["$ref"]] if isinstance(nodo.get("$ref"), str) else []
        for valore in nodo.values():
            trovati += _riferimenti(valore)
        return trovati
    if isinstance(nodo, list):
        return [r for voce in nodo for r in _riferimenti(voce)]
    return []


def _validatore(nodo: dict[str, Any], contratto: dict[str, Any]):
    """Validatore JSON Schema per un nodo che puo' contenere dei `$ref`.

    I riferimenti di OpenAPI puntano a `#/components/schemas/...`, che in un
    documento JSON Schema autonomo non esiste. Qui l'intero insieme dei
    componenti viene allegato sotto `$defs` e i riferimenti riscritti: e' una
    riscrittura testuale, non una reimplementazione della risoluzione.

    OpenAPI 3.1 usa JSON Schema 2020-12, quindi il dialetto e' quello.
    """
    documento = json.dumps(
        {"allOf": [nodo], "$defs": contratto["components"]["schemas"]}
    ).replace("#/components/schemas/", "#/$defs/")
    return jsonschema.Draft202012Validator(json.loads(documento))


def _schema_dichiarato(
    contratto: dict[str, Any], metodo: str, percorso: str, stato: int
) -> dict[str, Any]:
    """Lo schema che il contratto promette per quella risposta."""
    operazione = contratto["paths"][percorso][metodo.lower()]
    risposte = operazione["responses"]
    assert str(stato) in risposte, (
        f"{metodo} {percorso} ha risposto {stato}, ma il contratto non "
        f"dichiara quel codice: dichiara {sorted(risposte)}"
    )
    voce = risposte[str(stato)]
    assert "content" in voce, (
        f"{metodo} {percorso} dichiara il {stato} senza alcuno schema: "
        f"l'interfaccia non puo' generare un tipo da una descrizione"
    )
    return voce["content"]["application/json"]["schema"]


# --------------------------------------------------------------------------- #
# 1-2. Il documento e' ben formato
# --------------------------------------------------------------------------- #


def test_ogni_riferimento_dello_schema_risolve(contratto) -> None:
    """Un `$ref` che non risolve rende il documento inservibile in silenzio.

    Conta qui piu' che altrove: il 422 delle rotte con due forme di errore e'
    un `anyOf` di riferimenti scritti a mano in `backend/errors.py`, non
    dedotti da un'annotazione di tipo. Dipendono dal fatto che
    `RispostaErrore` e `HTTPValidationError` finiscano fra i componenti --
    il primo perche' il 401 del router protetto lo usa come modello, il
    secondo perche' FastAPI lo genera per le rotte con parametri validati.
    Se una di quelle due condizioni cadesse, il riferimento resterebbe li' a
    puntare al nulla.
    """
    disponibili = set(contratto["components"]["schemas"])
    mancanti = sorted(
        {
            r
            for r in _riferimenti(contratto)
            if r.startswith("#/components/schemas/")
            and r.removeprefix("#/components/schemas/") not in disponibili
        }
    )
    assert not mancanti, f"riferimenti che non risolvono: {mancanti}"


def test_nessuna_risposta_di_errore_e_dichiarata_senza_schema(contratto) -> None:
    """Dichiarare un errore senza forma e' peggio che non dichiararlo.

    E' un difetto che si e' verificato davvero: due rotte di `scope.py`
    passavano `responses={422: {"description": "..."}}` per migliorare il
    testo, e FastAPI non cambia il testo di cio' che genera -- sostituisce
    l'intera voce. Il risultato era un 422 dichiarato senza schema, cioe' un
    contratto che nominava un errore senza dire com'e' fatto, e nessuno se ne
    e' accorto perche' il codice sembrava giusto.
    """
    nude = [
        f"{metodo.upper()} {percorso} -> {stato}"
        for percorso, metodi in contratto["paths"].items()
        for metodo, operazione in metodi.items()
        for stato, voce in operazione.get("responses", {}).items()
        if stato.isdigit() and int(stato) >= 400 and "content" not in voce
    ]
    assert not nude, "risposte di errore dichiarate senza schema: " + ", ".join(nude)


def test_ogni_rotta_protetta_dichiara_il_401(contratto) -> None:
    """Il 401 si eredita dal router, e questo test verifica che sia arrivato.

    La dipendenza di autenticazione e' dichiarata su `api_protette`, quindi
    una rotta nuova nasce protetta. Il 401 e' dichiarato nello stesso punto e
    per la stessa ragione. Se qualcuno aggiungesse una rotta sotto `/api`
    fuori da quel router, questo test la nominerebbe.
    """
    #: Rotte che una sessione non la richiedono, e per cui il 401 sarebbe falso.
    #: `/salute` e' la sonda dell'healthcheck, `login` e `logout` aprono e
    #: chiudono la sessione.
    SENZA_SESSIONE = {
        ("get", "/api/salute"),
        ("post", "/api/auth/login"),  # il suo 401 e' «credenziali errate»
        ("post", "/api/auth/logout"),
    }
    senza_401 = sorted(
        f"{metodo.upper()} {percorso}"
        for percorso, metodi in contratto["paths"].items()
        for metodo in metodi
        if percorso.startswith("/api/")
        and (metodo, percorso) not in SENZA_SESSIONE
        and "401" not in contratto["paths"][percorso][metodo].get("responses", {})
    )
    assert not senza_401, f"rotte protette senza 401 dichiarato: {senza_401}"


# --------------------------------------------------------------------------- #
# 3. Il contratto corrisponde al comportamento
# --------------------------------------------------------------------------- #


def test_i_corpi_di_errore_reali_rispettano_lo_schema_dichiarato(
    autenticato, contratto, dati_esempio, nuovo_tool
) -> None:
    """Ogni errore che l'API produce davvero valida contro cio' che promette.

    I casi coprono le tre forme del corpo: quella applicativa con il solo
    `messaggio`, quella applicativa con il `suggerimento` di un trigger, e
    quella di Pydantic con la lista per campo. E coprono entrambi i 422: uno
    che nasce da un validator e uno che nasce da un trigger, che e' il punto
    in cui dichiarare una forma sola sarebbe stato falso.
    """
    # Perimetro noto, per i casi del perimetro.
    rete = autenticato.post(
        "/api/scope/networks",
        json={"cidr": "10.99.0.0/24", "label": "Rete del test di contratto"},
    )
    assert rete.status_code == 201, rete.text
    rete_id = rete.json()["id"]

    casi: list[tuple[str, str, str, dict | None, int]] = [
        # (descrizione, metodo, percorso del contratto, corpo, stato atteso)
        ("404 su un tool inesistente", "GET", "/api/tools/{tool_id}", None, 404),
        (
            "404 su un correlation_id inesistente",
            "GET",
            "/api/audit/{correlation_id}",
            None,
            404,
        ),
        ("404 su una rete inesistente", "DELETE", "/api/scope/networks/{rete_id}", None, 404),
        ("404 su un consenso inesistente", "POST", "/api/consents/{consenso_id}/revoke", None, 404),
        (
            "409 su una rete gia' dichiarata",
            "POST",
            "/api/scope/networks",
            {"cidr": "10.99.0.0/24", "label": "La stessa"},
            409,
        ),
        (
            "422 di Pydantic: CIDR con bit host",
            "POST",
            "/api/scope/networks",
            {"cidr": "10.99.0.10/24", "label": "Non canonica"},
            422,
        ),
        (
            "422 di un trigger: alias fuori perimetro",
            "POST",
            "/api/scope/aliases",
            {"name": "fuori-contratto", "address": "203.0.113.7"},
            422,
        ),
        ("422 applicativo: intervallo vuoto", "GET", "/api/audit", None, 422),
    ]

    # Gli URL concreti, uno per caso, nello stesso ordine.
    urls = [
        "/api/tools/non-esiste-questo-tool",
        f"/api/audit/{uuid.uuid4()}",
        "/api/scope/networks/99999999",
        "/api/consents/99999999/revoke",
        "/api/scope/networks",
        "/api/scope/networks",
        "/api/scope/aliases",
        "/api/audit?da=2026-01-02T00:00:00Z&a=2026-01-01T00:00:00Z",
    ]

    problemi: list[str] = []
    for (descrizione, metodo, percorso, corpo, atteso), url in zip(casi, urls, strict=True):
        risposta = autenticato.request(metodo, url, json=corpo)
        if risposta.status_code != atteso:
            problemi.append(
                f"{descrizione}: atteso {atteso}, ottenuto "
                f"{risposta.status_code} ({risposta.text[:120]})"
            )
            continue
        schema = _schema_dichiarato(contratto, metodo, percorso, atteso)
        errori = sorted(
            _validatore(schema, contratto).iter_errors(risposta.json()),
            key=lambda e: list(e.path),
        )
        if errori:
            problemi.append(
                f"{descrizione}: il corpo non valida contro lo schema "
                f"dichiarato ({errori[0].message}); corpo: {risposta.text[:200]}"
            )

    # Il 401, con un client nuovo.
    #
    # Non la fixture `client`: `autenticato` restituisce quello stesso oggetto
    # dopo averci aperto una sessione, quindi riusarlo qui vorrebbe dire
    # chiedere una rotta protetta da autenticati e chiamarlo 401. Il primo
    # tentativo rispondeva 200, ed e' il test che se n'e' accorto.
    from fastapi.testclient import TestClient

    from backend.main import crea_app

    with TestClient(crea_app()) as anonimo:
        senza_sessione = anonimo.get("/api/tools")
    if senza_sessione.status_code != 401:
        problemi.append(f"401: ottenuto {senza_sessione.status_code}")
    else:
        schema = _schema_dichiarato(contratto, "GET", "/api/tools", 401)
        errori = list(_validatore(schema, contratto).iter_errors(senza_sessione.json()))
        if errori:
            problemi.append(f"401: {errori[0].message}")

    # Il 409 della monotonia del tier, che e' il caso con il `suggerimento`.
    #
    # Su un tool proprio e non su uno dei dati di esempio: `tier_overrides` e'
    # append-only, quindi un innalzamento scritto qui resterebbe addosso al
    # tool per tutti i test successivi.
    identificativo = f"prova.contratto{uuid.uuid4().hex[:10]}"
    nuovo_tool(tool_id=identificativo, declared_tier="verde")
    innalzamento = autenticato.post(
        f"/api/tools/{identificativo}/overrides",
        json={"tier": "rosso", "reason": "Innalzamento per il test di contratto."},
    )
    assert innalzamento.status_code == 201, innalzamento.text
    declassamento = autenticato.post(
        f"/api/tools/{identificativo}/overrides",
        json={"tier": "giallo", "reason": "Declassamento, che deve essere rifiutato."},
    )
    if declassamento.status_code != 409:
        problemi.append(f"409 del tier: ottenuto {declassamento.status_code}")
    else:
        schema = _schema_dichiarato(
            contratto, "POST", "/api/tools/{tool_id}/overrides", 409
        )
        errori = list(_validatore(schema, contratto).iter_errors(declassamento.json()))
        if errori:
            problemi.append(f"409 del tier: {errori[0].message}")
        # Il campo che esiste per i trigger: il contratto lo dichiara
        # opzionale, e qui deve esserci davvero, altrimenti sarebbe
        # dichiarato per niente.
        if "suggerimento" not in declassamento.json().get("detail", {}):
            problemi.append(
                "409 del tier: manca il `suggerimento`, cioe' l'HINT del "
                "trigger non arriva al client e il campo e' dichiarato a vuoto"
            )

    assert not problemi, "\n  - " + "\n  - ".join(problemi)


# --------------------------------------------------------------------------- #
# Il costruttore delle responses
# --------------------------------------------------------------------------- #


def test_risposte_rifiuta_il_422_dichiarato_in_due_modi() -> None:
    """Le due forme del 422 sono alternative, non sommabili.

    Dichiararlo come applicativo e come sola validazione nella stessa
    chiamata e' una contraddizione, e la seconda sovrascriverebbe la prima in
    silenzio: il contratto perderebbe la forma applicativa senza dirlo.
    """
    from backend.errors import risposte

    with pytest.raises(ValueError, match="dichiarato due volte"):
        risposte({422: "entrambe le forme"}, validazione="solo Pydantic")
