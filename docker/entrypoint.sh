#!/bin/sh
# Avvio dell'applicazione: migrazioni, poi seed se il database e' vuoto, poi
# il server. In questo ordine, e fermandosi al primo errore.
#
# `set -e` non e' decorativo: se le migrazioni falliscono, avviare il server
# comunque significherebbe servire un'applicazione su uno schema che non
# conosce, cioe' errori a runtime invece di un errore all'avvio.
set -eu

# L'URL delle migrazioni, con il ruolo PROPRIETARIO delle tabelle.
#
# Il ciclo di attesa sotto usa questa e non DATABASE_URL, e non e' un
# dettaglio: il ruolo applicativo `hermes_app` viene creato DALLA migrazione
# 0002, quindi prima che le migrazioni girino non esiste ancora. Aspettare
# che risponda sarebbe aspettare per sempre.
MIGRATIONS_DATABASE_URL="${MIGRATIONS_DATABASE_URL:-$DATABASE_URL}"
export MIGRATIONS_DATABASE_URL

echo "[entrypoint] attendo il database..."
# Il compose ha un healthcheck su db e un depends_on: service_healthy, quindi
# qui il database di norma risponde gia'. Questo ciclo copre il caso in cui
# l'immagine venga avviata senza compose, e costa un secondo quando non serve.
#
# La connessione di prova passa da SQLAlchemy e non da psycopg con l'URL
# grezzo. Non e' un dettaglio: prima questo ciclo faceva
#
#     psycopg.connect(URL.replace('+psycopg', ''))
#
# cioe' dava a libpq una stringa costruita per SQLAlchemy. Le due sintassi
# NON sono la stessa cosa: libpq segue RFC 3986 alla lettera, quindi una
# password che contenga `/` -- e `openssl rand -base64`, che e' il comando
# suggerito dal README, ne produce una nel 40% dei casi -- chiude l'authority
# in anticipo e il resto dell'URL diventa spazzatura. L'errore che ne usciva
# era «Servname not supported for ai_socktype», che non nomina ne' la
# password ne' l'URL, e il container restava in ciclo di riavvio dicendo che
# il database non risponde -- indicando il componente sbagliato.
#
# SQLAlchemy interpreta l'URL da se' e passa i parametri separati al driver,
# quindi una password con caratteri speciali arriva intera. Ed e' la stessa
# libreria che useranno alembic e l'applicazione subito dopo: se qui si
# connette, si connettono anche loro.
i=0
until python - <<'PROVA' 2>/dev/null
import os
from sqlalchemy import create_engine, text

motore = create_engine(
    os.environ["MIGRATIONS_DATABASE_URL"],
    connect_args={"connect_timeout": 2},
    pool_pre_ping=False,
)
with motore.connect() as connessione:
    connessione.execute(text("SELECT 1"))
PROVA
do
    i=$((i + 1))
    if [ "$i" -ge 30 ]; then
        echo "[entrypoint] il database non risponde dopo 30 tentativi." >&2
        echo "[entrypoint] errore dell'ultimo tentativo:" >&2
        # L'errore vero, non piu' ingoiato da 2>/dev/null. Nasconderlo
        # trasformava una diagnosi di due secondi in un timeout senza
        # informazioni.
        python - >&2 <<'DIAGNOSI' || true
import os
from sqlalchemy import create_engine, text

try:
    motore = create_engine(
        os.environ["MIGRATIONS_DATABASE_URL"],
        connect_args={"connect_timeout": 2},
        pool_pre_ping=False,
    )
    with motore.connect() as connessione:
        connessione.execute(text("SELECT 1"))
except Exception as errore:
    print(f"  {type(errore).__name__}: {errore}")
DIAGNOSI
        exit 1
    fi
    sleep 1
done
echo "[entrypoint] database raggiungibile"

# Migrazioni e seed girano con il ruolo proprietario. La migrazione 0002 crea
# `hermes_app` e gli assegna le concessioni minime.
echo "[entrypoint] applico le migrazioni (ruolo proprietario)..."
alembic upgrade head

echo "[entrypoint] seed, se il database e' vuoto (ruolo proprietario)..."
python -m backend.seed

# Da qui in poi il processo e' l'applicazione, e usa DATABASE_URL, cioe'
# `hermes_app`: un ruolo che non possiede le tabelle e non puo' disabilitarne
# i trigger. Il server non vede mai l'URL privilegiata nella propria
# configurazione... se non nell'ambiente, che e' un limite noto e scritto nel
# README: toglierla richiederebbe due container, e per una consegna con un
# solo operatore non vale la complessita'.
echo "[entrypoint] avvio dell'applicazione come ruolo applicativo: $*"
exec "$@"
