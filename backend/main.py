"""Applicazione FastAPI: API sotto ``/api``, interfaccia compilata sul resto.

Un solo processo serve entrambe. Costa uno stage di build in piu'
nell'immagine e risparmia un container, un reverse proxy e la configurazione
CORS che servirebbe con due origini — e una configurazione CORS e' una cosa
che si sbaglia.

Il vincolo architetturale
-------------------------

Gli agenti LLM non devono poter raggiungere questa applicazione. E' lei a
decidere cosa gli agenti possono fare: se un agente — o una prompt injection
nel suo contesto — ne raggiungesse le API, alzerebbe i propri permessi, e
l'intero modello di sicurezza cadrebbe.

Non c'e' un modo di garantirlo dentro il codice di un'applicazione web, e
quindi non si finge che ci sia. Quello che si fa e' togliere le cose che
servirebbero a un client automatico, perche' un'interfaccia che nessun
programma puo' usare comodamente e' un'interfaccia che nessun programma
finisce per usare:

* **nessuna API key, nessun token di servizio.** L'unica autenticazione e' un
  cookie di sessione ottenuto con una password. Un agente non ha una password
  da digitare, e una credenziale di servizio esisterebbe per essere usata da
  un programma.
* **nessun endpoint MCP, nessuna rotta per il consumo automatico.** Le rotte
  servono le sei schermate, e nient'altro.
* **la porta e' pubblicata su 127.0.0.1** nel compose, non su `0.0.0.0`: il
  pannello non e' raggiungibile dalla rete, e il server MCP gira altrove.
* **lo schema OpenAPI e la documentazione interattiva esistono solo in
  sviluppo.** Uno schema leggibile da una macchina e' la cosa che rende
  un'API comoda da usare per un programma; in produzione non c'e'.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, FastAPI
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.requests import Request
from starlette.responses import Response

from backend.config import get_settings
from backend.routers import audit, auth, consents, scope, tools
from backend.security import operatore_corrente

#: Directory del build di Vite, copiata nell'immagine dallo stage `frontend`.
DIR_STATICI = Path(__file__).resolve().parent / "static"


def crea_app() -> FastAPI:
    impostazioni = get_settings()
    in_sviluppo = impostazioni.app_env == "development"

    app = FastAPI(
        title="Pannello di controllo Hermes",
        description=(
            "Registro dello stato della toolbox di sicurezza Hermes: tier dei "
            "tool, innalzamenti, consensi per scope, perimetro dei bersagli e "
            "vista del log d'audit. Un solo utente: l'operatore umano."
        ),
        version="0.1.0",
        # Solo in sviluppo: in produzione non viene esposto nessuno schema
        # leggibile da una macchina.
        openapi_url="/api/openapi.json" if in_sviluppo else None,
        docs_url="/api/docs" if in_sviluppo else None,
        redoc_url=None,
    )

    # ---------------------------------------------------------------------- #
    # API
    #
    # La dipendenza di autenticazione e' dichiarata sul router, non rotta per
    # rotta. Cosi' il default e' «protetta»: una rotta nuova e' autenticata
    # perche' sta qui dentro, non perche' chi l'ha scritta si e' ricordato di
    # aggiungere il decoratore. Dimenticare una riga non apre un buco.
    # ---------------------------------------------------------------------- #
    api_protette = APIRouter(
        prefix="/api",
        dependencies=[Depends(operatore_corrente)],
    )
    api_protette.include_router(tools.router)
    api_protette.include_router(consents.router)
    api_protette.include_router(scope.router)
    api_protette.include_router(audit.router)

    # Il login e il logout non possono richiedere una sessione: sono le rotte
    # che la aprono e la chiudono. `/auth/me` la richiede, ed e' dichiarata
    # con la propria dipendenza dentro il modulo.
    api_pubbliche = APIRouter(prefix="/api")
    api_pubbliche.include_router(auth.router)

    app.include_router(api_pubbliche)
    app.include_router(api_protette)

    @app.get("/api/salute", tags=["servizio"])
    def salute() -> dict[str, str]:
        """Sonda di vitalita'. Non dice niente sullo stato interno.

        Non e' autenticata, perche' serve a un healthcheck. Per la stessa
        ragione non riporta la versione dello schema, il numero di tool o
        altri dettagli: una sonda deve dire se il processo risponde, non
        descrivere il sistema a chi non e' entrato.
        """
        return {"stato": "ok"}

    # ---------------------------------------------------------------------- #
    # Interfaccia
    # ---------------------------------------------------------------------- #
    if DIR_STATICI.is_dir():
        app.mount(
            "/assets",
            StaticFiles(directory=DIR_STATICI / "assets", check_dir=False),
            name="assets",
        )

        @app.get("/{percorso:path}", include_in_schema=False)
        def spa(percorso: str) -> Response:
            """Serve il build di Vite, con fallback su ``index.html``.

            Il fallback e' cio' che fa funzionare i percorsi del router lato
            client: un ricaricamento su `/tool/audit.lynis` arriva al server
            come una richiesta per un file che non esiste, e deve restituire
            la pagina perche' il router JavaScript possa leggere il percorso.

            Il fallback **non** copre `/api`: una rotta API inesistente deve
            restituire un 404 JSON, non la pagina HTML. Un client che chiede
            `/api/qualcosa` e riceve dell'HTML con stato 200 non ha modo di
            accorgersi dell'errore.
            """
            if percorso.startswith("api/"):
                return JSONResponse(
                    {"detail": {"messaggio": "Rotta API inesistente."}},
                    status_code=404,
                )

            candidato = (DIR_STATICI / percorso).resolve()
            # Il confronto con la directory dei file statici e' obbligatorio:
            # senza, un percorso con '..' servirebbe qualunque file leggibile
            # dal processo. Starlette normalizza molti casi, ma qui il
            # percorso lo stiamo manipolando noi, quindi il controllo e'
            # nostro.
            if (
                percorso
                and candidato.is_file()
                and candidato.is_relative_to(DIR_STATICI)
            ):
                return FileResponse(candidato)
            return FileResponse(DIR_STATICI / "index.html")

    else:

        @app.get("/", include_in_schema=False)
        def interfaccia_assente(request: Request) -> JSONResponse:
            """Risposta quando il build dell'interfaccia non c'e'.

            Succede eseguendo uvicorn direttamente in sviluppo, senza aver
            compilato il frontend. Dirlo esplicitamente evita di cercare la
            causa in un 404 generico.
            """
            return JSONResponse(
                {
                    "messaggio": (
                        "Il build dell'interfaccia non e' presente in "
                        "backend/static. In sviluppo l'interfaccia gira a "
                        "parte: cd frontend && npm run dev. Le API sono "
                        "attive sotto /api."
                    )
                },
                status_code=503,
            )

    return app


app = crea_app()
