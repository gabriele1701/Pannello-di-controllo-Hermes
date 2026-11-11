#!/usr/bin/env python3
"""Verifica lo stack avviato, via HTTP, come lo verificherebbe una persona.

Gira nella CI dopo `docker compose up`, e si puo' eseguire a mano contro
un'istanza locale:

    python3 .github/scripts/verifica_stack.py --base http://127.0.0.1:8000 \\
        --utente operatore --password "$HERMES_ADMIN_PASSWORD"

Sta in un file e non dentro il workflow perche' le verifiche dentro un blocco
YAML diventano illeggibili al terzo livello di quoting -- e perche' un file si
prova in locale prima di spingerlo, mentre un passo di workflow si prova
soltanto facendo girare la CI.

Solo libreria standard: nessuna dipendenza da installare prima di poter
verificare.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from http.cookiejar import CookieJar
from typing import Any

#: Esiti attesi nel log dei dati di esempio. `denied` e `pending` sono i casi
#: che mostrano il gate fare il proprio lavoro: una catena che finisce in `ok`
#: dimostra soltanto che il sistema esegue.
ESITI_ATTESI = ("ok", "denied", "pending", "error")

#: Intervallo richiesto dallo SPEC §9 per il numero di eventi di audit.
EVENTI_MIN, EVENTI_MAX = 40, 60

_errori: list[str] = []


def _ok(messaggio: str) -> None:
    print(f"  ok    {messaggio}")


def _ko(messaggio: str) -> None:
    print(f"  FALLITO {messaggio}")
    _errori.append(messaggio)


class Client:
    """Client HTTP minimo con i cookie, per tenere la sessione."""

    def __init__(self, base: str) -> None:
        self.base = base.rstrip("/")
        self.cookies = CookieJar()
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cookies)
        )

    def chiama(
        self,
        percorso: str,
        *,
        metodo: str = "GET",
        corpo: dict[str, Any] | None = None,
        con_sessione: bool = True,
    ) -> tuple[int, Any]:
        dati = json.dumps(corpo).encode() if corpo is not None else None
        richiesta = urllib.request.Request(
            f"{self.base}{percorso}", data=dati, method=metodo
        )
        if dati is not None:
            richiesta.add_header("Content-Type", "application/json")

        apri = self._opener.open if con_sessione else urllib.request.urlopen
        try:
            with apri(richiesta, timeout=15) as risposta:
                testo = risposta.read().decode()
                return risposta.status, json.loads(testo) if testo else None
        except urllib.error.HTTPError as err:
            testo = err.read().decode()
            try:
                return err.code, json.loads(testo) if testo else None
            except json.JSONDecodeError:
                return err.code, testo


def verifica_login(client: Client, utente: str, password: str) -> bool:
    stato, corpo = client.chiama(
        "/api/auth/login",
        metodo="POST",
        corpo={"username": utente, "password": password},
    )
    if stato != 200:
        _ko(f"login: atteso 200, ricevuto {stato} ({corpo})")
        return False
    _ok(f"login come '{corpo.get('username')}'")

    cookie = {c.name for c in client.cookies}
    if "hermes_session" not in cookie:
        _ko(f"nessun cookie di sessione: {cookie}")
        return False
    _ok("cookie di sessione presente")
    return True


def verifica_catalogo(client: Client) -> None:
    stato, catalogo = client.chiama("/api/tools")
    if stato != 200:
        _ko(f"catalogo: atteso 200, ricevuto {stato}")
        return

    if len(catalogo) < 6:
        _ko(f"catalogo con {len(catalogo)} tool: lo SPEC §9 ne chiede 6-8")
    else:
        _ok(f"catalogo popolato: {len(catalogo)} tool")

    # I due assi del rischio devono essere tutti rappresentati, compreso il
    # verde CON dati personali, che e' il caso per cui non si possono fondere.
    combinazioni = {(t["declared_tier"], t["personal_data"]) for t in catalogo}
    for atteso, descrizione in (
        (("verde", False), "verde senza dati personali"),
        (("verde", True), "verde CON dati personali"),
        (("giallo", False), "giallo"),
    ):
        if atteso in combinazioni:
            _ok(f"presente il caso {descrizione}")
        else:
            _ko(f"manca il caso {descrizione}")
    if any(tier == "rosso" for tier, _ in combinazioni):
        _ok("presente il caso rosso")
    else:
        _ko("manca il caso rosso")

    # La divergenza fra tier dichiarato ed effettivo deve essere visibile: e'
    # il segnale che un override e' attivo.
    innalzati = [t for t in catalogo if t["tier_innalzato"]]
    if not innalzati:
        _ko("nessun tool con tier innalzato: i dati non mostrano la divergenza")
    else:
        for t in innalzati:
            _ok(
                f"divergenza visibile su {t['tool_id']}: "
                f"{t['declared_tier']} -> {t['effective_tier']}"
            )


def verifica_log(client: Client) -> None:
    stato, pagina = client.chiama("/api/audit?limite=200")
    if stato != 200:
        _ko(f"log: atteso 200, ricevuto {stato}")
        return

    totale = pagina["totale"]
    if EVENTI_MIN <= totale <= EVENTI_MAX:
        _ok(f"log con {totale} eventi (atteso {EVENTI_MIN}-{EVENTI_MAX})")
    else:
        _ko(f"log con {totale} eventi, fuori da {EVENTI_MIN}-{EVENTI_MAX}")

    esiti = {e["outcome"] for e in pagina["eventi"]}
    for atteso in ESITI_ATTESI:
        if atteso in esiti:
            _ok(f"esito '{atteso}' presente nel log")
        else:
            _ko(f"esito '{atteso}' assente dal log")

    # Una catena deve essere ricostruibile e in ordine cronologico.
    cid = pagina["eventi"][0]["correlation_id"]
    stato, catena = client.chiama(f"/api/audit/{cid}")
    if stato != 200:
        _ko(f"catena {cid}: atteso 200, ricevuto {stato}")
        return
    istanti = [e["occurred_at"] for e in catena["eventi"]]
    if istanti == sorted(istanti):
        _ok(f"catena di {len(istanti)} eventi in ordine cronologico")
    else:
        _ko("catena non in ordine cronologico")


def verifica_criteri(client: Client) -> None:
    """I criteri di accettazione dello SPEC §11, contro lo stack vero."""
    casi = [
        (
            "declassamento del tier rifiutato",
            409,
            "/api/tools/recon.nmap-sweep/overrides",
            "POST",
            {"tier": "giallo", "reason": "provo ad abbassarlo"},
        ),
        (
            "CIDR non canonica rifiutata",
            422,
            "/api/scope/networks",
            "POST",
            {"cidr": "192.168.205.10/24", "label": "sbagliata"},
        ),
        (
            "alias fuori perimetro rifiutato",
            422,
            "/api/scope/aliases",
            "POST",
            {"name": "fuori", "address": "10.0.0.5"},
        ),
        ("scrittura nel log impossibile", 405, "/api/audit", "POST", {}),
        ("modifica del log impossibile", 405, "/api/audit", "PATCH", {}),
        ("cancellazione del log impossibile", 405, "/api/audit", "DELETE", {}),
        (
            "creazione di un tool impossibile",
            405,
            "/api/tools",
            "POST",
            {"tool_id": "x.y"},
        ),
    ]
    for descrizione, atteso, percorso, metodo, corpo in casi:
        stato, risposta = client.chiama(percorso, metodo=metodo, corpo=corpo)
        if stato == atteso:
            _ok(f"{descrizione} ({stato})")
        else:
            _ko(f"{descrizione}: atteso {atteso}, ricevuto {stato} ({risposta})")

    # Il messaggio sulla CIDR deve spiegare il perche', non solo rifiutare.
    _, risposta = client.chiama(
        "/api/scope/networks",
        metodo="POST",
        corpo={"cidr": "192.168.205.10/24", "label": "sbagliata"},
    )
    testo = json.dumps(risposta, ensure_ascii=False).lower()
    for frammento, cosa in (
        ("bit a destra", "dice cosa non va"),
        ("192.168.205.0/24", "dice come verrebbe interpretata"),
        ("/32", "dice cosa fare invece"),
    ):
        if frammento in testo:
            _ok(f"il messaggio sulla CIDR {cosa}")
        else:
            _ko(f"il messaggio sulla CIDR non {cosa}")


def verifica_perimetro_percorsi(client: Client) -> None:
    """Il perimetro dei percorsi, contro lo stack vero.

    Esiste per una ragione specifica, oltre a verificare le tre rotte:
    `scope_paths` nasce con la migrazione 0004, e la 0002 non ha
    `ALTER DEFAULT PRIVILEGES`. Se le due righe di `GRANT` mancassero,
    lo schema sarebbe valido, la suite di pytest passerebbe -- gira con lo
    stesso ruolo ma su un database costruito dalle stesse migrazioni -- e
    `GET /api/scope/paths` risponderebbe 500 solo nello stack dispiegato.
    Qui quel caso diventa un lavoro rosso.
    """
    stato, percorsi = client.chiama("/api/scope/paths")
    if stato != 200:
        _ko(f"elenco dei percorsi: atteso 200, ricevuto {stato} ({percorsi})")
        return
    if isinstance(percorsi, list) and percorsi:
        _ok(f"perimetro dei percorsi popolato: {len(percorsi)} prefissi")
    else:
        _ko("perimetro dei percorsi vuoto: il seed non ha scritto nessun prefisso")

    # Scrittura e rimozione: le concessioni INSERT e DELETE sulla tabella
    # nuova, piu' la sequenza del bigserial.
    stato, creato = client.chiama(
        "/api/scope/paths",
        metodo="POST",
        corpo={"prefix": "/srv/verifica-a-freddo", "label": "Scritto dal verificatore"},
    )
    if stato == 201:
        _ok("prefisso dichiarato (201)")
        stato, _ = client.chiama(
            f"/api/scope/paths/{creato['id']}", metodo="DELETE"
        )
        if stato == 204:
            _ok("prefisso rimosso (204)")
        else:
            _ko(f"rimozione del prefisso: atteso 204, ricevuto {stato}")
    else:
        _ko(f"dichiarazione di un prefisso: atteso 201, ricevuto {stato} ({creato})")

    # Il rifiuto, e la sua spiegazione. I vincoli sono nel database e la
    # rotta traduce il nome del vincolo violato: se la traduzione mancasse,
    # qui arriverebbe un 500 invece di un 422.
    casi = [
        ("prefisso relativo", {"prefix": "srv/analisi", "label": "x"}, "assoluto"),
        ("risalita nel prefisso", {"prefix": "/srv/../etc", "label": "x"}, "'..'"),
        ("la radice come perimetro", {"prefix": "/", "label": "x"}, "perimetro"),
    ]
    for descrizione, corpo, frammento in casi:
        stato, risposta = client.chiama(
            "/api/scope/paths", metodo="POST", corpo=corpo
        )
        testo = json.dumps(risposta, ensure_ascii=False).lower()
        if stato != 422:
            _ko(f"{descrizione}: atteso 422, ricevuto {stato} ({risposta})")
        elif frammento not in testo:
            _ko(f"{descrizione}: rifiutato senza spiegazione ({testo[:120]})")
        elif "suggerimento" not in testo:
            _ko(f"{descrizione}: la spiegazione non dice cosa fare")
        else:
            _ok(f"{descrizione} rifiutato con una spiegazione (422)")

    # Uno spazio finale va RIFIUTATO, non rimosso: un 201 qui vorrebbe dire
    # che lo stack autorizza un percorso diverso da quello richiesto.
    stato, risposta = client.chiama(
        "/api/scope/paths",
        metodo="POST",
        corpo={"prefix": "/srv/con-spazio ", "label": "x"},
    )
    if stato == 422:
        _ok("spazio finale rifiutato invece che rimosso (422)")
    else:
        _ko(
            f"spazio finale: atteso 422, ricevuto {stato} -- lo stack "
            f"normalizza il prefisso e autorizza un percorso diverso"
        )


def verifica_bersagli_estesi(client: Client) -> None:
    """Il catalogo mostra i bersagli che non sono host.

    Senza una riga che li usi, i due valori nuovi dell'enum sarebbero
    rappresentabili e invisibili: chi apre l'applicazione troverebbe un
    catalogo di soli bersagli di rete e crederebbe che il modello sia quello.
    """
    stato, catalogo = client.chiama("/api/tools")
    if stato != 200:
        _ko(f"catalogo: atteso 200, ricevuto {stato}")
        return

    per_tipo = {t["target_kind"]: t for t in catalogo}
    for tipo in ("path", "process"):
        tool = per_tipo.get(tipo)
        if tool is None:
            _ko(f"nessun tool con target_kind '{tipo}' nel catalogo")
            continue
        if not tool.get("requires_container"):
            _ko(
                f"il tool '{tool['tool_id']}' ha target_kind '{tipo}' senza "
                f"requires_container: il vincolo tools_bersaglio_isolato non "
                f"e' applicato"
            )
        elif not tool.get("bersaglio_etichetta"):
            _ko(f"il tool '{tool['tool_id']}' non porta l'etichetta del bersaglio")
        else:
            _ok(
                f"bersaglio '{tipo}' nel catalogo, isolato, etichettato "
                f"«{tool['bersaglio_etichetta']}»"
            )


def verifica_senza_sessione(base: str) -> None:
    """Nessuna rotta protetta risponde senza sessione."""
    anonimo = Client(base)
    for percorso in (
        "/api/tools",
        "/api/audit",
        "/api/consents",
        "/api/scope/networks",
        "/api/scope/paths",
    ):
        stato, _ = anonimo.chiama(percorso, con_sessione=False)
        if stato == 401:
            _ok(f"{percorso} senza sessione: 401")
        else:
            _ko(f"{percorso} senza sessione: atteso 401, ricevuto {stato}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default="http://127.0.0.1:8000")
    parser.add_argument("--utente", default="operatore")
    parser.add_argument("--password", required=True)
    argomenti = parser.parse_args()

    client = Client(argomenti.base)

    print("== sessione ==")
    if not verifica_login(client, argomenti.utente, argomenti.password):
        print("\nlogin fallito: le verifiche successive non hanno senso", file=sys.stderr)
        return 1

    print("== catalogo e dati di esempio ==")
    verifica_catalogo(client)
    print("== log d'audit ==")
    verifica_log(client)
    print("== criteri di accettazione (SPEC §11) ==")
    verifica_criteri(client)
    print("== perimetro dei percorsi ==")
    verifica_perimetro_percorsi(client)
    print("== bersagli che non sono host ==")
    verifica_bersagli_estesi(client)
    print("== rotte protette ==")
    verifica_senza_sessione(argomenti.base)

    print()
    if _errori:
        print(f"{len(_errori)} verifiche fallite:", file=sys.stderr)
        for errore in _errori:
            print(f"  - {errore}", file=sys.stderr)
        return 1
    print("tutte le verifiche sono passate")
    return 0


if __name__ == "__main__":
    sys.exit(main())
