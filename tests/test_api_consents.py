"""Consensi per scope, dalle API."""

from __future__ import annotations

import datetime as dt


def _fra(giorni: int) -> str:
    return (dt.datetime.now(tz=dt.UTC) + dt.timedelta(days=giorni)).isoformat()


def test_elenco_mostra_stato_derivato(autenticato, dati_esempio) -> None:
    """Lo stato non e' una colonna: e' calcolato dalle date alla lettura.

    Una colonna di stato andrebbe aggiornata allo scadere, e nessun processo
    la aggiornerebbe: un consenso scaduto resterebbe marcato attivo.
    """
    consensi = autenticato.get("/api/consents").json()
    stati = {c["stato"] for c in consensi}
    assert "attivo" in stati
    assert "scaduto" in stati, "i dati di esempio devono contenere uno scaduto"


def test_filtro_per_stato(autenticato, dati_esempio) -> None:
    attivi = autenticato.get("/api/consents", params={"stato": "attivo"}).json()
    scaduti = autenticato.get("/api/consents", params={"stato": "scaduto"}).json()
    assert all(c["stato"] == "attivo" for c in attivi)
    assert all(c["stato"] == "scaduto" for c in scaduti)
    assert len(attivi) >= 1
    assert len(scaduti) >= 1


def test_filtro_per_agente(autenticato, dati_esempio) -> None:
    risposta = autenticato.get("/api/consents", params={"agent": "pentest_kali"})
    assert risposta.status_code == 200
    assert all(c["agent"] == "pentest_kali" for c in risposta.json())


def test_filtro_con_agente_inventato_rifiutato(autenticato, dati_esempio) -> None:
    """Il vocabolario degli agenti e' chiuso anche nei filtri."""
    risposta = autenticato.get("/api/consents", params={"agent": "agente_inventato"})
    assert risposta.status_code == 422


def test_consenso_per_agente_intero(autenticato, dati_esempio) -> None:
    risposta = autenticato.post(
        "/api/consents",
        json={
            "agent": "pentest_kali",
            "scope": "192.168.205.0/24",
            "expires_at": _fra(7),
        },
    )
    assert risposta.status_code == 201, risposta.text
    corpo = risposta.json()
    assert corpo["tool_id"] is None  # vale per l'agente intero
    assert corpo["stato"] == "attivo"
    # L'autore e' l'operatore della sessione, non un campo della richiesta.
    assert corpo["granted_by"] == "operatore-test"


def test_consenso_senza_scadenza_rifiutato(autenticato, dati_esempio) -> None:
    """Un consenso che non scade non e' un consenso."""
    risposta = autenticato.post(
        "/api/consents",
        json={"agent": "pentest_kali", "scope": "192.168.205.0/24"},
    )
    assert risposta.status_code == 422


def test_consenso_con_scadenza_passata_rifiutato(autenticato, dati_esempio) -> None:
    """Nascerebbe gia' scaduto, cioe' non autorizzerebbe niente."""
    risposta = autenticato.post(
        "/api/consents",
        json={
            "agent": "pentest_kali",
            "scope": "192.168.205.0/24",
            "expires_at": _fra(-1),
        },
    )
    assert risposta.status_code == 422
    assert "passato" in str(risposta.json()).lower()


def test_consenso_con_scadenza_senza_fuso_rifiutato(autenticato, dati_esempio) -> None:
    """Un istante senza fuso non e' confrontabile con niente."""
    risposta = autenticato.post(
        "/api/consents",
        json={
            "agent": "pentest_kali",
            "scope": "192.168.205.0/24",
            "expires_at": "2030-01-01T10:00:00",
        },
    )
    assert risposta.status_code == 422
    assert "fuso" in str(risposta.json()).lower()


def test_consenso_su_tool_di_un_altro_agente_rifiutato(autenticato, dati_esempio) -> None:
    """Solo l'agente proprietario puo' invocare un tool.

    Un consenso che nomini un agente e un tool di un altro non descrive
    niente di eseguibile.
    """
    tool = autenticato.get("/api/tools/audit.lynis").json()  # vuln_assessment
    risposta = autenticato.post(
        "/api/consents",
        json={
            "agent": "pentest_kali",
            "tool_id": tool["id"],
            "scope": "lab-web",
            "expires_at": _fra(3),
        },
    )
    assert risposta.status_code == 422
    assert "appartiene" in str(risposta.json()).lower()


def test_consenso_su_tool_inesistente_404(autenticato, dati_esempio) -> None:
    risposta = autenticato.post(
        "/api/consents",
        json={
            "agent": "pentest_kali",
            "tool_id": 999999,
            "scope": "lab-web",
            "expires_at": _fra(3),
        },
    )
    assert risposta.status_code == 404


def test_revoca_annulla_senza_cancellare(autenticato, dati_esempio) -> None:
    """La riga resta, con `revoked_at` impostato.

    Sapere che un consenso c'e' stato conta tanto quanto sapere che non vale
    piu': una DELETE cancellerebbe la seconda informazione insieme alla prima.
    """
    creato = autenticato.post(
        "/api/consents",
        json={"agent": "pentest_kali", "scope": "lab-kali", "expires_at": _fra(4)},
    ).json()

    risposta = autenticato.post(f"/api/consents/{creato['id']}/revoke")
    assert risposta.status_code == 200
    revocato = risposta.json()
    assert revocato["stato"] == "revocato"
    assert revocato["revoked_at"] is not None

    # La riga e' ancora nell'elenco, non e' sparita.
    elenco = autenticato.get("/api/consents").json()
    assert any(c["id"] == creato["id"] for c in elenco)


def test_revoca_ripetuta_rifiutata(autenticato, dati_esempio) -> None:
    """Sovrascrivere la data farebbe perdere quando la revoca e' avvenuta."""
    creato = autenticato.post(
        "/api/consents",
        json={"agent": "vuln_assessment", "scope": "lab-web", "expires_at": _fra(4)},
    ).json()
    assert autenticato.post(f"/api/consents/{creato['id']}/revoke").status_code == 200
    risposta = autenticato.post(f"/api/consents/{creato['id']}/revoke")
    assert risposta.status_code == 409


def test_revoca_di_cio_che_non_esiste_404(autenticato, dati_esempio) -> None:
    assert autenticato.post("/api/consents/999999/revoke").status_code == 404


def test_nessuna_cancellazione_dei_consensi(autenticato, dati_esempio) -> None:
    """La revoca e' l'unico modo di annullare: non c'e' DELETE."""
    risposta = autenticato.request("DELETE", "/api/consents/1")
    assert risposta.status_code in (404, 405)
