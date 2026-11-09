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
i=0
until python -c "
import os, sys
import psycopg
try:
    psycopg.connect(os.environ['MIGRATIONS_DATABASE_URL'].replace('+psycopg', ''), connect_timeout=2).close()
except Exception as err:
    print(err, file=sys.stderr)
    sys.exit(1)
" 2>/dev/null; do
    i=$((i + 1))
    if [ "$i" -ge 30 ]; then
        echo "[entrypoint] il database non risponde dopo 30 tentativi" >&2
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
