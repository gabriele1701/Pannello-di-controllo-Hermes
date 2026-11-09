# Immagine dell'applicazione: un solo container serve API e interfaccia.
#
# Il build di Vite viene copiato dentro l'immagine Python e servito da FastAPI
# come file statici. Costa uno stage di build in piu' e risparmia un container,
# un reverse proxy e la configurazione CORS che servirebbe con due origini.

# --------------------------------------------------------------------------- #
# Stage 1 — build dell'interfaccia
# --------------------------------------------------------------------------- #
FROM node:22-alpine AS frontend

WORKDIR /build

# package.json e lockfile prima del resto: cambiano raramente, quindi il
# layer delle dipendenze resta in cache quando cambia solo il codice.
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm ci --no-audit --no-fund 2>/dev/null || npm install --no-audit --no-fund

COPY frontend/ ./
RUN npm run build

# --------------------------------------------------------------------------- #
# Stage 2 — runtime
# --------------------------------------------------------------------------- #
FROM python:3.12-slim AS runtime

# PYTHONDONTWRITEBYTECODE: niente .pyc in un filesystem che non li riusa.
# PYTHONUNBUFFERED: i log arrivano a `docker compose logs` subito, non a blocchi.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Utente di servizio, creato prima dell'installazione.
#
# Il container NON gira come root. Un processo che non ha bisogno di root non
# deve averlo: se l'applicazione viene compromessa, l'attaccante eredita i
# privilegi del processo, e qui ereditera' quelli di un utente che non puo'
# scrivere nemmeno il proprio codice.
RUN groupadd --system --gid 1001 hermes \
 && useradd --system --uid 1001 --gid hermes --no-create-home \
            --home-dir /app --shell /usr/sbin/nologin hermes

WORKDIR /app

# Dipendenze Python separate dal codice, per la stessa ragione di cache.
COPY pyproject.toml ./
RUN pip install --no-cache-dir . \
 && pip install --no-cache-dir "psycopg[binary]==3.2.3"

COPY alembic.ini ./
COPY migrations/ ./migrations/
COPY backend/ ./backend/
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/entrypoint.sh

# L'interfaccia compilata, dallo stage precedente.
COPY --from=frontend /build/dist/ ./backend/static/

# Il codice e' di root e in sola lettura per l'utente di servizio: il processo
# non puo' modificare i propri file. E' la stessa scelta di hermes-core, dove
# il repo e' in sola lettura per l'utente del servizio.
RUN chown -R root:root /app && chmod -R u=rwX,go=rX /app

USER hermes

EXPOSE 8000

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
