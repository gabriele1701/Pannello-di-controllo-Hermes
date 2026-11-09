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
