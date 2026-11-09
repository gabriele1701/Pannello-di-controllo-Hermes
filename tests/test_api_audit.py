"""Vista del log d'audit, dalle API.

Il criterio di accettazione dice «nessuna rotta permette di scrivere nel
log». Non e' una funzionalita' mancante: il log e' una vista di un file
JSONL append-only che vive sulla macchina del server MCP, e un pannello che
potesse scriverci sarebbe un pannello capace di riscrivere la traccia di
cio' che ha autorizzato.
"""

from __future__ import annotations

import datetime as dt

import pytest


def test_elenco_paginato_dal_piu_recente(autenticato, dati_esempio) -> None:
    risposta = autenticato.get("/api/audit", params={"limite": 10})
    assert risposta.status_code == 200
    pagina = risposta.json()

    assert pagina["limite"] == 10
    assert pagina["scarto"] == 0
    assert len(pagina["eventi"]) == 10
    # `totale` conta le righe che soddisfano i filtri, non quelle restituite:
    # senza, l'interfaccia non puo' dire quante pagine ci sono.
    assert pagina["totale"] >= 40

    istanti = [e["occurred_at"] for e in pagina["eventi"]]
    assert istanti == sorted(istanti, reverse=True)


def test_paginazione_senza_sovrapposizioni(autenticato, dati_esempio) -> None:
    """Pagine disgiunte.

    L'ordinamento ha `id` come criterio di spareggio: senza, piu' eventi
    della stessa catena con lo stesso istante potrebbero comparire su due
    pagine, perdendone altri.
    """
    prima = autenticato.get("/api/audit", params={"limite": 20, "scarto": 0}).json()
    seconda = autenticato.get("/api/audit", params={"limite": 20, "scarto": 20}).json()
    id_prima = {e["id"] for e in prima["eventi"]}
    id_seconda = {e["id"] for e in seconda["eventi"]}
    assert not (id_prima & id_seconda)


def test_limite_oltre_il_tetto_rifiutato(autenticato, dati_esempio) -> None:
    """Senza tetto, `limite=1000000` esaurirebbe la memoria del server."""
    assert autenticato.get("/api/audit", params={"limite": 10_000}).status_code == 422
    assert autenticato.get("/api/audit", params={"limite": 0}).status_code == 422
    assert autenticato.get("/api/audit", params={"scarto": -1}).status_code == 422


@pytest.mark.parametrize(
    ("parametro", "valore"),
    [
        ("agent", "vuln_assessment"),
        ("outcome", "denied"),
        ("event_type", "tool_call"),
        ("tool_id", "recon.nmap-sweep"),
    ],
)
def test_filtri(autenticato, dati_esempio, parametro: str, valore: str) -> None:
    risposta = autenticato.get(
        "/api/audit", params={parametro: valore, "limite": 200}
    )
    assert risposta.status_code == 200
    eventi = risposta.json()["eventi"]
    assert eventi, f"nessun evento per {parametro}={valore}"
    assert all(e[parametro] == valore for e in eventi)


def test_filtro_con_valore_fuori_vocabolario_rifiutato(autenticato, dati_esempio) -> None:
    """I filtri sono tipizzati: non arriva testo libero dentro una query."""
    assert autenticato.get("/api/audit", params={"outcome": "boh"}).status_code == 422
    assert autenticato.get("/api/audit", params={"agent": "x"}).status_code == 422
    assert (
        autenticato.get("/api/audit", params={"event_type": "qualsiasi"}).status_code
        == 422
    )


def test_nessun_parametro_di_ordinamento(autenticato, dati_esempio) -> None:
    """Un campo di ordinamento libero sarebbe testo del client in una ORDER BY.

    FastAPI ignora i parametri non dichiarati, quindi la prova e' che il
    risultato non cambi: l'ordinamento resta quello fisso.
    """
    base = autenticato.get("/api/audit", params={"limite": 5}).json()
    con_ordine = autenticato.get(
        "/api/audit",
        params={"limite": 5, "order_by": "detail", "sort": "asc"},
    ).json()
    assert [e["id"] for e in base["eventi"]] == [e["id"] for e in con_ordine["eventi"]]


def test_filtro_temporale(autenticato, dati_esempio) -> None:
    adesso = dt.datetime.now(tz=dt.UTC)
    recenti = autenticato.get(
        "/api/audit",
        params={"da": (adesso - dt.timedelta(hours=3)).isoformat(), "limite": 200},
    ).json()
    tutti = autenticato.get("/api/audit", params={"limite": 200}).json()
    assert recenti["totale"] < tutti["totale"]
    assert recenti["totale"] > 0


def test_intervallo_vuoto_rifiutato(autenticato, dati_esempio) -> None:
    adesso = dt.datetime.now(tz=dt.UTC)
    risposta = autenticato.get(
        "/api/audit",
        params={
            "da": adesso.isoformat(),
            "a": (adesso - dt.timedelta(days=1)).isoformat(),
        },
    )
    assert risposta.status_code == 422
    assert "intervallo" in str(risposta.json()).lower()


def test_catena_in_ordine_cronologico(autenticato, dati_esempio) -> None:
    """Una catena si legge dall'inizio: e' una sequenza causale.

    L'elenco va dal piu' recente, la catena dal primo evento: l'agente
    invocato, le chiamate ai tool, il risultato.
    """
    pagina = autenticato.get("/api/audit", params={"limite": 200}).json()
    cid = pagina["eventi"][0]["correlation_id"]

    risposta = autenticato.get(f"/api/audit/{cid}")
    assert risposta.status_code == 200
    catena = risposta.json()
    assert catena["correlation_id"] == cid
    assert len(catena["eventi"]) >= 1

    istanti = [e["occurred_at"] for e in catena["eventi"]]
    assert istanti == sorted(istanti)
    assert all(e["correlation_id"] == cid for e in catena["eventi"])


def test_catena_con_esito_denied_presente(autenticato, dati_esempio) -> None:
    """I dati di esempio devono contenere una catena che finisce in `denied`.

    E' il caso che mostra il gate fare il proprio lavoro: una catena che
    finisce in `ok` dimostra soltanto che il sistema esegue.
    """
    eventi = autenticato.get("/api/audit", params={"limite": 200}).json()["eventi"]
    per_catena: dict[str, list[dict]] = {}
    for evento in eventi:
        per_catena.setdefault(evento["correlation_id"], []).append(evento)

    esiti_finali = set()
    for righe in per_catena.values():
        ultima = max(righe, key=lambda e: (e["occurred_at"], e["id"]))
        esiti_finali.add(ultima["outcome"])

    assert "denied" in esiti_finali
    assert "pending" in esiti_finali


def test_log_mostra_il_tier_effettivo(autenticato, dati_esempio) -> None:
    """Il log registra il tier applicato, non quello dichiarato.

    ssl-scan e' dichiarato verde e innalzato a giallo: le sue righe di
    invocazione portano `giallo`. Ignorare l'override significherebbe
    registrare conferme piu' lasse di quelle richieste.
    """
    eventi = autenticato.get(
        "/api/audit",
        params={"tool_id": "audit.ssl-scan", "event_type": "tool_call", "limite": 200},
    ).json()["eventi"]
    assert eventi
    assert all(e["tier_effective"] == "giallo" for e in eventi)


def test_nessun_valore_di_segreto_nel_log(autenticato, dati_esempio) -> None:
    """Il log registra il NOME del segreto consultato, mai il valore."""
    eventi = autenticato.get(
        "/api/audit", params={"event_type": "secret_access", "limite": 200}
    ).json()["eventi"]
    assert eventi
    for evento in eventi:
        assert evento["secret_name"]
        campi = set(evento.keys())
        assert not {"secret_value", "value", "password", "token"} & campi


def test_catena_inesistente_404(autenticato, dati_esempio) -> None:
    risposta = autenticato.get("/api/audit/00000000-0000-0000-0000-000000000000")
    assert risposta.status_code == 404


def test_correlation_id_malformato_rifiutato(autenticato, dati_esempio) -> None:
    assert autenticato.get("/api/audit/non-un-uuid").status_code == 422


@pytest.mark.parametrize("metodo", ["POST", "PUT", "PATCH", "DELETE"])
def test_nessuna_scrittura_sul_log(autenticato, dati_esempio, metodo: str) -> None:
    """Criterio di accettazione esplicito: nessuna rotta scrive nel log."""
    risposta = autenticato.request(metodo, "/api/audit", json={})
    assert risposta.status_code == 405, risposta.status_code


@pytest.mark.parametrize("metodo", ["POST", "PUT", "PATCH", "DELETE"])
def test_nessuna_scrittura_su_una_catena(autenticato, dati_esempio, metodo: str) -> None:
    pagina = autenticato.get("/api/audit", params={"limite": 1}).json()
    cid = pagina["eventi"][0]["correlation_id"]
    risposta = autenticato.request(metodo, f"/api/audit/{cid}", json={})
    assert risposta.status_code == 405, risposta.status_code
