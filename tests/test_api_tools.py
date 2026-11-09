"""Catalogo, dettaglio e innalzamento del tier, dalle API.

E' la meta' applicativa del criterio «rifiutato sia dall'API sia dal
database». L'altra meta' sta in ``test_db_constraints.py``, che fa le stesse
prove in SQL diretto.
"""

from __future__ import annotations

import pytest


def test_catalogo_porta_entrambi_i_tier(autenticato, dati_esempio) -> None:
    """Il catalogo mostra dichiarato ed effettivo, non solo l'effettivo.

    Mostrare il solo effettivo nasconderebbe che qualcuno e' intervenuto, che
    e' precisamente l'informazione per cui esiste la colonna.
    """
    risposta = autenticato.get("/api/tools")
    assert risposta.status_code == 200
    catalogo = risposta.json()
    assert len(catalogo) == 8

    per_id = {t["tool_id"]: t for t in catalogo}

    # nmap-sweep: dichiarato giallo, innalzato a rosso dal seed.
    nmap = per_id["recon.nmap-sweep"]
    assert nmap["declared_tier"] == "giallo"
    assert nmap["effective_tier"] == "rosso"
    assert nmap["tier_innalzato"] is True

    # lynis: nessun override, i due tier combaciano.
    lynis = per_id["audit.lynis"]
    assert lynis["declared_tier"] == lynis["effective_tier"] == "verde"
    assert lynis["tier_innalzato"] is False


def test_catalogo_copre_tutte_le_combinazioni_dei_due_assi(
    autenticato, dati_esempio
) -> None:
    """I due assi sono indipendenti, e i dati lo mostrano.

    Il caso che conta e' il verde CON dati personali: se i due assi fossero
    fusi in un unico valore, quel tool non sarebbe rappresentabile.
    """
    catalogo = autenticato.get("/api/tools").json()
    combinazioni = {(t["declared_tier"], t["personal_data"]) for t in catalogo}
    assert ("verde", False) in combinazioni
    assert ("verde", True) in combinazioni, "manca il verde con dati personali"
    assert ("giallo", False) in combinazioni
    assert any(tier == "rosso" for tier, _ in combinazioni)


def test_dettaglio_mostra_identita_e_storico(autenticato, dati_esempio) -> None:
    risposta = autenticato.get("/api/tools/recon.nmap-sweep")
    assert risposta.status_code == 200
    dettaglio = risposta.json()

    # Identita' di cio' che viene eseguito.
    assert dettaglio["exec_path"].endswith("nmap_sweep.py")
    assert len(dettaglio["exec_sha256"]) == 64
    assert dettaglio["exec_args"] == ["-sV", "--top-ports", "1000"]

    # Storico con motivo e autore: senza, un innalzamento e' illeggibile.
    assert len(dettaglio["overrides"]) == 1
    override = dettaglio["overrides"][0]
    assert override["tier"] == "rosso"
    assert override["created_by"] == "operatore"
    assert len(override["reason"]) > 20
    assert override["source"] == "persistent"
    assert override["source_descrizione"]


def test_dettaglio_offre_solo_i_tier_superiori(autenticato, dati_esempio) -> None:
    """L'azione «Innalza tier» non offre il declassamento, nemmeno disattivato.

    Un'opzione disabilitata insegnerebbe all'operatore che esiste un modo e
    che oggi non e' attivo. Qui i tier inferiori non compaiono nell'elenco.
    """
    # audit.lynis e' a verde: puo' salire a giallo o rosso.
    lynis = autenticato.get("/api/tools/audit.lynis").json()
    assert lynis["tier_disponibili"] == ["giallo", "rosso"]

    # ssl-scan e' effettivo giallo (override da configurazione): solo rosso.
    ssl = autenticato.get("/api/tools/audit.ssl-scan").json()
    assert ssl["effective_tier"] == "giallo"
    assert ssl["tier_disponibili"] == ["rosso"]

    # msf-check e' a rosso: nessuna azione possibile, elenco vuoto.
    msf = autenticato.get("/api/tools/exploit.msf-check").json()
    assert msf["tier_disponibili"] == []


def test_tool_inesistente_404(autenticato, dati_esempio) -> None:
    risposta = autenticato.get("/api/tools/non.esiste")
    assert risposta.status_code == 404
    assert "non.esiste" in risposta.json()["detail"]["messaggio"]


def test_innalzamento_accettato(autenticato, dati_esempio) -> None:
    risposta = autenticato.post(
        "/api/tools/audit.lynis/overrides",
        json={"tier": "rosso", "reason": "Verifica del comportamento su un host di produzione."},
    )
    assert risposta.status_code == 201, risposta.text
    corpo = risposta.json()
    assert corpo["tier"] == "rosso"
    # L'autore e' l'operatore della sessione, non un campo della richiesta.
    assert corpo["created_by"] == "operatore-test"
    assert corpo["source"] == "persistent"

    # Il catalogo riflette subito l'innalzamento.
    catalogo = {t["tool_id"]: t for t in autenticato.get("/api/tools").json()}
    assert catalogo["audit.lynis"]["effective_tier"] == "rosso"
    assert catalogo["audit.lynis"]["tier_innalzato"] is True


def test_declassamento_rifiutato_con_409(autenticato, dati_esempio) -> None:
    """Il criterio di accettazione centrale, dal lato API.

    nmap-sweep e' a rosso: un override a giallo non lo innalza.
    """
    risposta = autenticato.post(
        "/api/tools/recon.nmap-sweep/overrides",
        json={"tier": "giallo", "reason": "Vorrei riportarlo a giallo."},
    )
    assert risposta.status_code == 409, risposta.text
    dettaglio = risposta.json()["detail"]
    # Il messaggio spiega perche', e viene dal trigger: una sola formulazione
    # dell'invariante, non una copia in Python che puo' divergere.
    assert "solo salire" in dettaglio["messaggio"]
    assert "rosso" in dettaglio["suggerimento"]


def test_override_pari_al_corrente_rifiutato_con_409(autenticato, dati_esempio) -> None:
    risposta = autenticato.post(
        "/api/tools/recon.nmap-sweep/overrides",
        json={"tier": "rosso", "reason": "Confermo il rosso."},
    )
    assert risposta.status_code == 409


def test_innalzamento_senza_motivo_rifiutato(autenticato, dati_esempio) -> None:
    """Il motivo e' obbligatorio: senza, lo storico non si rilegge."""
    assert (
        autenticato.post(
            "/api/tools/audit.lynis/overrides", json={"tier": "giallo"}
        ).status_code
        == 422
    )
    assert (
        autenticato.post(
            "/api/tools/audit.lynis/overrides",
            json={"tier": "giallo", "reason": "   "},
        ).status_code
        == 422
    )


def test_tier_inventato_rifiutato(autenticato, dati_esempio) -> None:
    risposta = autenticato.post(
        "/api/tools/audit.lynis/overrides",
        json={"tier": "arancione", "reason": "Un tier di mia invenzione."},
    )
    assert risposta.status_code == 422


def test_autore_non_falsificabile(autenticato, dati_esempio) -> None:
    """`created_by` non e' un campo della richiesta.

    Se lo fosse, un client potrebbe dichiarare di essere qualcun altro nello
    storico che serve esattamente a sapere chi ha fatto cosa.
    """
    risposta = autenticato.post(
        "/api/tools/osint.username-enum/overrides",
        json={
            "tier": "giallo",
            "reason": "Innalzamento con autore falsificato.",
            "created_by": "qualcun-altro",
        },
    )
    assert risposta.status_code == 422


@pytest.mark.parametrize("metodo", ["PUT", "PATCH", "DELETE"])
def test_nessuna_modifica_degli_override(autenticato, dati_esempio, metodo: str) -> None:
    """Non esistono rotte di modifica o cancellazione degli override.

    Un'API di rimozione sarebbe un declassamento con un'interfaccia comoda, e
    una volta che esiste finisce per essere chiamata da qualcosa di
    automatico.
    """
    risposta = autenticato.request(
        metodo, "/api/tools/recon.nmap-sweep/overrides/1", json={}
    )
    assert risposta.status_code in (404, 405), risposta.status_code


@pytest.mark.parametrize("metodo", ["POST", "PUT", "PATCH", "DELETE"])
def test_nessuna_rotta_crea_o_modifica_un_tool(
    autenticato, dati_esempio, metodo: str
) -> None:
    """I tool li registra hermes-core: l'identita' e' di sola lettura qui."""
    risposta = autenticato.request(metodo, "/api/tools", json={})
    assert risposta.status_code == 405, risposta.status_code
