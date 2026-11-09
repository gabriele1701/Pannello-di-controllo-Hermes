#!/bin/sh
# Avvio dell'applicazione: migrazioni, poi seed se il database e' vuoto, poi
# il server. In questo ordine, e fermandosi al primo errore.
#
# `set -e` non e' decorativo: se le migrazioni falliscono, avviare il server
# comunque significherebbe servire un'applicazione su uno schema che non
# conosce, cioe' errori a runtime invece di un errore all'avvio.
set -eu

echo "[entrypoint] attendo il database..."
# Il compose ha un healthcheck su db e un depends_on: service_healthy, quindi
# qui il database di norma risponde gia'. Questo ciclo copre il caso in cui
# l'immagine venga avviata senza compose, e costa un secondo quando non serve.
i=0
until python -c "
import os, sys
import psycopg
try:
    psycopg.connect(os.environ['DATABASE_URL'].replace('+psycopg', ''), connect_timeout=2).close()
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

echo "[entrypoint] applico le migrazioni..."
alembic upgrade head

echo "[entrypoint] seed (solo se il database e' vuoto)..."
python -m backend.seed

echo "[entrypoint] avvio: $*"
exec "$@"
