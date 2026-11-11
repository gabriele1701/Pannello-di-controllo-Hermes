"""Perimetro dei bersagli, dalle API.

Due criteri di accettazione espliciti vivono qui:

* `192.168.205.10/24` viene rifiutato **con un messaggio che spiega il
  perche'**;
* un alias fuori dalle reti dichiarate viene rifiutato.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.usefixtures("perimetro_pulito")


def _messaggio(risposta) -> str:
    """Tutto il testo dell'errore, in minuscolo, da qualunque forma arrivi.

    Pydantic restituisce una lista di errori sotto `detail`, i nostri trigger
    un dizionario. Il test guarda il contenuto, non la struttura.
    """
    return str(risposta.json()).lower()


# --------------------------------------------------------------------------- #
# Forma canonica dei CIDR
# --------------------------------------------------------------------------- #


def test_rete_in_forma_canonica_accettata(autenticato) -> None:
    risposta = autenticato.post(
        "/api/scope/networks",
        json={"cidr": "192.168.205.0/24", "label": "Laboratorio"},
    )
    assert risposta.status_code == 201, risposta.text
    assert risposta.json()["cidr"] == "192.168.205.0/24"


def test_cidr_con_bit_host_rifiutata_con_spiegazione(autenticato) -> None:
    """Il criterio dice «con un messaggio che spiega il perche'».

    Un messaggio che dica solo «valore non valido» lascia chi lo legge a
    riscrivere lo stesso errore in un'altra forma: non sa se il problema sia
    la maschera, l'indirizzo o la sintassi.
    """
    risposta = autenticato.post(
        "/api/scope/networks",
        json={"cidr": "192.168.205.10/24", "label": "Sbagliata"},
    )
    assert risposta.status_code == 422
    testo = _messaggio(risposta)

    # Dice CHE COSA non va: ci sono bit a destra della maschera.
    assert "bit a destra" in testo
    # Dice COME verrebbe interpretato, cioe' qual e' il danno.
    assert "192.168.205.0/24" in testo
    # Dice QUANTO e' piu' largo del previsto.
    assert "256" in testo or "254" in testo
    # Dice COSA FARE, nelle due letture possibili dell'intenzione.
    assert "/32" in testo


def test_indirizzo_senza_maschera_rifiutato_con_spiegazione(autenticato) -> None:
    risposta = autenticato.post(
        "/api/scope/networks", json={"cidr": "192.168.205.0", "label": "Senza maschera"}
    )
    assert risposta.status_code == 422
    assert "/32" in _messaggio(risposta)


@pytest.mark.parametrize(
    "cidr",
    ["non-un-cidr", "999.1.1.0/24", "192.168.205.0/33", "192.168.205.0/-1"],
)
def test_cidr_malformata_rifiutata(autenticato, cidr: str) -> None:
    risposta = autenticato.post(
        "/api/scope/networks", json={"cidr": cidr, "label": "x"}
    )
    assert risposta.status_code == 422


def test_rete_duplicata_rifiutata_con_409(autenticato) -> None:
    corpo = {"cidr": "192.168.205.0/24", "label": "Laboratorio"}
    assert autenticato.post("/api/scope/networks", json=corpo).status_code == 201
    risposta = autenticato.post("/api/scope/networks", json=corpo)
    assert risposta.status_code == 409


# --------------------------------------------------------------------------- #
# Alias
# --------------------------------------------------------------------------- #


def test_alias_dentro_il_perimetro_accettato(autenticato) -> None:
    autenticato.post(
        "/api/scope/networks", json={"cidr": "192.168.205.0/24", "label": "Lab"}
    )
    risposta = autenticato.post(
        "/api/scope/aliases", json={"name": "lab-web", "address": "192.168.205.20"}
    )
    assert risposta.status_code == 201, risposta.text


def test_alias_fuori_dal_perimetro_rifiutato_con_spiegazione(autenticato) -> None:
    """Criterio di accettazione esplicito.

    Il rifiuto viene dal trigger, e il suo suggerimento elenca le reti
    dichiarate: chi legge sa subito perche' quell'indirizzo non va bene.
    """
    autenticato.post(
        "/api/scope/networks", json={"cidr": "192.168.205.0/24", "label": "Lab"}
    )
    risposta = autenticato.post(
        "/api/scope/aliases", json={"name": "fuori", "address": "10.0.0.5"}
    )
    assert risposta.status_code == 422, risposta.text
    testo = _messaggio(risposta)
    assert "non cade in nessuna rete" in testo
    # Elenca le reti dichiarate, cosi' l'operatore vede il perimetro reale.
    assert "192.168.205.0/24" in testo


def test_alias_con_perimetro_vuoto_rifiutato(autenticato) -> None:
    """Un perimetro vuoto non vale «tutto ammesso»."""
    risposta = autenticato.post(
        "/api/scope/aliases", json={"name": "orfano", "address": "10.0.0.5"}
    )
    assert risposta.status_code == 422


def test_alias_verso_un_nome_rifiutato(autenticato) -> None:
    """Un alias punta a un indirizzo, non a un altro nome.

    E non viene risolto via DNS: un nome risolto al momento del controllo
    puo' puntare altrove al momento dell'esecuzione.
    """
    autenticato.post(
        "/api/scope/networks", json={"cidr": "192.168.205.0/24", "label": "Lab"}
    )
    risposta = autenticato.post(
        "/api/scope/aliases", json={"name": "web", "address": "lab-web.local"}
    )
    assert risposta.status_code == 422
    assert "dns" in _messaggio(risposta)


def test_alias_con_maschera_rifiutato(autenticato) -> None:
    autenticato.post(
        "/api/scope/networks", json={"cidr": "192.168.205.0/24", "label": "Lab"}
    )
    risposta = autenticato.post(
        "/api/scope/aliases", json={"name": "rete", "address": "192.168.205.0/24"}
    )
    assert risposta.status_code == 422
    assert "maschera" in _messaggio(risposta)


def test_alias_duplicato_rifiutato_con_409(autenticato) -> None:
    autenticato.post(
        "/api/scope/networks", json={"cidr": "192.168.205.0/24", "label": "Lab"}
    )
    corpo = {"name": "lab-web", "address": "192.168.205.20"}
    assert autenticato.post("/api/scope/aliases", json=corpo).status_code == 201
    assert autenticato.post("/api/scope/aliases", json=corpo).status_code == 409


# --------------------------------------------------------------------------- #
# Rimozione
# --------------------------------------------------------------------------- #


def test_rimozione_rete_con_alias_dipendenti_rifiutata(autenticato) -> None:
    """Il secondo modo di far uscire un alias dal perimetro.

    Coprire solo l'inserimento lascerebbe questa via aperta, ed e' la piu'
    facile da imboccare per sbaglio.
    """
    rete = autenticato.post(
        "/api/scope/networks", json={"cidr": "192.168.205.0/24", "label": "Lab"}
    ).json()
    autenticato.post(
        "/api/scope/aliases", json={"name": "lab-web", "address": "192.168.205.20"}
    )

    risposta = autenticato.delete(f"/api/scope/networks/{rete['id']}")
    assert risposta.status_code == 422, risposta.text
    assert "lab-web" in _messaggio(risposta)

    # La rete e' ancora al suo posto.
    assert len(autenticato.get("/api/scope/networks").json()) == 1


def test_rimozione_alias_poi_rete_accettata(autenticato) -> None:
    """Restringere il perimetro e' sempre ammesso, nell'ordine giusto."""
    rete = autenticato.post(
        "/api/scope/networks", json={"cidr": "192.168.205.0/24", "label": "Lab"}
    ).json()
    alias = autenticato.post(
        "/api/scope/aliases", json={"name": "lab-web", "address": "192.168.205.20"}
    ).json()

    assert autenticato.delete(f"/api/scope/aliases/{alias['id']}").status_code == 204
    assert autenticato.delete(f"/api/scope/networks/{rete['id']}").status_code == 204
    assert autenticato.get("/api/scope/networks").json() == []


def test_rimozione_di_cio_che_non_esiste_404(autenticato) -> None:
    assert autenticato.delete("/api/scope/networks/999999").status_code == 404
    assert autenticato.delete("/api/scope/aliases/999999").status_code == 404


# --------------------------------------------------------------------------- #
# Perimetro dei percorsi
#
# Le tre rotte sono speculari a quelle delle reti, ma la verifica di un
# prefisso non e' speculare a quella di una CIDR: il database ha sette
# vincoli con un nome parlante, e la rotta traduce il nome in una
# spiegazione. Questi test guardano la traduzione, cioe' cio' che
# l'operatore legge.
# --------------------------------------------------------------------------- #


def test_prefisso_canonico_accettato(autenticato) -> None:
    risposta = autenticato.post(
        "/api/scope/paths",
        json={"prefix": "/srv/hermes/campioni", "label": "Campioni da analizzare"},
    )
    assert risposta.status_code == 201, risposta.text
    corpo = risposta.json()
    assert corpo["prefix"] == "/srv/hermes/campioni"
    assert corpo["id"] > 0


def test_elenco_ordinato_per_prefisso(autenticato) -> None:
    for prefisso in ("/srv/c", "/srv/a", "/srv/b"):
        assert (
            autenticato.post(
                "/api/scope/paths", json={"prefix": prefisso, "label": "x"}
            ).status_code
            == 201
        )
    elenco = autenticato.get("/api/scope/paths")
    assert elenco.status_code == 200
    assert [v["prefix"] for v in elenco.json()] == ["/srv/a", "/srv/b", "/srv/c"]


@pytest.mark.parametrize(
    ("prefisso", "attesi"),
    [
        pytest.param("srv/analisi", ("assoluto", "barra iniziale"), id="relativo"),
        pytest.param("/", ("non e' un perimetro", "rinunciare"), id="radice"),
        pytest.param(
            "/srv/analisi/../etc", ("'..'", "antenato"), id="risalita"
        ),
        pytest.param("/srv//analisi", ("'//'", "due volte"), id="doppia-barra"),
        pytest.param(
            "/srv/analisi/", ("terminare con '/'", "due righe"), id="barra-finale"
        ),
        pytest.param("/srv/ana\\lisi", ("backslash", "separatore"), id="backslash"),
        pytest.param(
            "/srv/analisi ",
            ("spazio", "non viene rimosso"),
            id="spazio-finale",
        ),
        pytest.param(
            "/" + "a" * 299, ("256", "riga di audit"), id="troppo-lungo"
        ),
    ],
)
def test_prefisso_non_canonico_rifiutato_con_spiegazione(
    autenticato, prefisso: str, attesi: tuple[str, ...]
) -> None:
    """Il criterio §6 dice «rifiutato con una spiegazione».

    Non basta il 422: un «valore non valido» lascia chi lo legge a riscrivere
    lo stesso errore in un'altra forma. Ogni caso qui verifica che il
    messaggio dica **che cosa** non va, e il suggerimento **cosa fare
    invece**.
    """
    risposta = autenticato.post(
        "/api/scope/paths", json={"prefix": prefisso, "label": "Prova"}
    )
    assert risposta.status_code == 422, risposta.text
    dettaglio = risposta.json()["detail"]
    assert "messaggio" in dettaglio
    assert "suggerimento" in dettaglio, "la spiegazione non dice cosa fare"
    testo = _messaggio(risposta)
    for atteso in attesi:
        assert atteso.lower() in testo, f"manca {atteso!r} in: {testo}"


def test_prefisso_duplicato_rifiutato_con_409(autenticato) -> None:
    """Un duplicato non e' un problema di forma: e' un conflitto di stato."""
    primo = {"prefix": "/srv/unico", "label": "Primo"}
    assert autenticato.post("/api/scope/paths", json=primo).status_code == 201
    risposta = autenticato.post(
        "/api/scope/paths", json={"prefix": "/srv/unico", "label": "Secondo"}
    )
    assert risposta.status_code == 409
    assert "/srv/unico" in _messaggio(risposta)


def test_prefisso_vuoto_rifiutato_da_pydantic(autenticato) -> None:
    """Il 422 ha due forme, e questa e' quella di Pydantic.

    Una stringa vuota non arriva al database: la intercetta `min_length`. Il
    corpo e' quindi la lista per campo, non l'oggetto con `messaggio`, ed e'
    il motivo per cui il contratto dichiara il 422 di questa rotta come
    `anyOf` fra le due forme.
    """
    risposta = autenticato.post(
        "/api/scope/paths", json={"prefix": "", "label": "Prova"}
    )
    assert risposta.status_code == 422
    assert isinstance(risposta.json()["detail"], list)


def test_rimozione_di_un_prefisso(autenticato) -> None:
    creato = autenticato.post(
        "/api/scope/paths", json={"prefix": "/srv/da-togliere", "label": "Prova"}
    )
    assert creato.status_code == 201
    identificativo = creato.json()["id"]

    assert autenticato.delete(f"/api/scope/paths/{identificativo}").status_code == 204
    assert autenticato.get("/api/scope/paths").json() == []

    # La seconda rimozione non trova niente, e lo dice.
    seconda = autenticato.delete(f"/api/scope/paths/{identificativo}")
    assert seconda.status_code == 404
    assert str(identificativo) in _messaggio(seconda)


def test_rimuovere_un_prefisso_non_tocca_gli_altri(autenticato) -> None:
    """Togliere un prefisso restringe il perimetro e non lascia niente fuori.

    Al contrario della rimozione di una rete, che un trigger rifiuta se
    qualche alias resterebbe orfano. Per i percorsi non esistono alias, e
    questo test fissa l'asimmetria invece di lasciarla implicita.
    """
    identificativi = []
    for prefisso in ("/srv/resta", "/srv/va-via"):
        risposta = autenticato.post(
            "/api/scope/paths", json={"prefix": prefisso, "label": "x"}
        )
        assert risposta.status_code == 201
        identificativi.append(risposta.json()["id"])

    assert autenticato.delete(f"/api/scope/paths/{identificativi[1]}").status_code == 204
    assert [v["prefix"] for v in autenticato.get("/api/scope/paths").json()] == [
        "/srv/resta"
    ]


def test_i_percorsi_richiedono_una_sessione(client) -> None:
    """Il perimetro non si legge ne' si modifica senza autenticazione."""
    assert client.get("/api/scope/paths").status_code == 401
    assert (
        client.post("/api/scope/paths", json={"prefix": "/srv/x", "label": "y"}).status_code
        == 401
    )
    assert client.delete("/api/scope/paths/1").status_code == 401


def test_il_prefisso_non_viene_normalizzato(autenticato) -> None:
    """Uno spazio finale viene RIFIUTATO, non rimosso.

    Test con un nome proprio perche' e' una scelta che si puo' disfare per
    distrazione: basta rimettere `str_strip_whitespace=True` sul modello
    d'ingresso e il campo torna a essere ripulito, l'API risponde 201, e
    autorizza un percorso diverso da quello digitato. E' successo, e questo
    test e' cio' che se n'e' accorto.

    Per il kernel `/srv/analisi ` e `/srv/analisi` sono due directory
    distinte, e quale delle due fosse intesa non lo sa l'applicazione. La
    regola e' la stessa che `hermes-core` applica al bersaglio di
    un'invocazione: normalizzare significa autorizzare qualcosa di diverso da
    cio' che e' stato chiesto.
    """
    risposta = autenticato.post(
        "/api/scope/paths", json={"prefix": "/srv/analisi ", "label": "Con spazio"}
    )
    assert risposta.status_code == 422, (
        f"lo spazio finale e' stato accettato: la risposta e' {risposta.text}"
    )
    assert autenticato.get("/api/scope/paths").json() == []


def test_l_etichetta_invece_viene_ripulita(autenticato) -> None:
    """L'altra meta' della scelta sopra.

    L'etichetta e' testo per chi legge, non un percorso: uno spazio in piu'
    non cambia a cosa si riferisce, e ripulirlo non autorizza niente di
    diverso.
    """
    risposta = autenticato.post(
        "/api/scope/paths", json={"prefix": "/srv/x", "label": "  Con spazi  "}
    )
    assert risposta.status_code == 201, risposta.text
    assert risposta.json()["label"] == "Con spazi"
