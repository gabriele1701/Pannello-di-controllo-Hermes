# Immagine dello scanner VSPT — BOZZA (si rifinisce con l'ambiente VM).
#
# Si spedisce QUESTO Dockerfile, non un'immagine pre-costruita: l'utente
# costruisce, e il build installa i tool da upstream a versioni PINNATE.
# Nessun codice di terze parti vive nel repo.
#
# Pin = riproducibilita'. Una versione non pinnata rende l'immagine di oggi
# diversa da quella di domani sullo stesso commit, ed e' esattamente cio' che
# un assessment non deve avere: i risultati non sarebbero confrontabili.

# --------------------------------------------------------------------------- #
# Stage 1 — nuclei, compilato da upstream a versione pinnata
#
# `go install ...@vX.Y.Z` pinna il modulo e ne verifica i checksum tramite il
# go.sum del modulo e il checksum database: niente SHA di release hardcodato
# qui, e nessun binario opaco scaricato da un URL.
# --------------------------------------------------------------------------- #
FROM golang:1.23-bookworm AS nuclei-build

ARG NUCLEI_VERSION=v3.3.7
ENV GOFLAGS=-trimpath CGO_ENABLED=0
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@${NUCLEI_VERSION}
# Il binario finisce in /go/bin/nuclei.

# --------------------------------------------------------------------------- #
# Stage 2 — runtime dello scanner
# --------------------------------------------------------------------------- #
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONPATH=/opt/pannello

# Versioni PINNATE dei tool installati da pip. Allineate a runner.PIN_TOOL:
# se cambiano qui, cambiano la' (e i metadati del report lo dichiarano).
ARG SQLMAP_VERSION=1.8.11
ARG SEMGREP_VERSION=1.97.0
ARG PIP_AUDIT_VERSION=2.7.3

# Dipendenze di sistema minime: git serve a sqlmap/semgrep per alcune regole,
# openssh-client al collector SSH. Nessun pacchetto superfluo.
RUN apt-get update \
 && apt-get install -y --no-install-recommends git openssh-client ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Utente di servizio non privilegiato: lo scanner non gira come root. Se un
# tool viene sfruttato, eredita privilegi minimi. Stessa scelta del pannello.
RUN groupadd --system --gid 1002 assess \
 && useradd --system --uid 1002 --gid assess --create-home \
            --home-dir /home/assess --shell /usr/sbin/nologin assess

# nuclei dallo stage di build.
COPY --from=nuclei-build /go/bin/nuclei /usr/local/bin/nuclei

# I tool Python, pinnati da upstream (PyPI).
RUN pip install --no-cache-dir \
      "sqlmap==${SQLMAP_VERSION}" \
      "semgrep==${SEMGREP_VERSION}" \
      "pip-audit==${PIP_AUDIT_VERSION}"

WORKDIR /opt/pannello

# assess NON dipende dal pannello a runtime: la severita' e' una banda calcolata
# in casa (risk.py), non piu' RiskTier di backend.models, e il resto dello
# scaffold usa solo la standard library. Quindi niente COPY di backend/ e
# nessuna pip install di requirements.txt del pannello. (L'implementazione live
# del collector DB aggiungera' qui psycopg quando servira', venerdi'.)
#
# Il codice: assess/ e openapi.json (per l'inventario). NON si installa come
# pacchetto: PYTHONPATH punta qui.
COPY assess/ ./assess/
COPY openapi.json ./openapi.json

# Comando `vspt` come wrapper su `python -m assess`. Il console_script
# "proprio" vivrebbe in pyproject [project.scripts], ma quello e' fuori dal
# perimetro di questo scaffold: il wrapper da' lo stesso comando senza
# toccarlo.
RUN printf '#!/bin/sh\nexec python -m assess "$@"\n' > /usr/local/bin/vspt \
 && chmod 0755 /usr/local/bin/vspt

# Codice in sola lettura per l'utente di servizio.
RUN chown -R root:root /opt/pannello && chmod -R u=rwX,go=rX /opt/pannello

USER assess

# Nessun ENTRYPOINT che esegua scansioni al boot: l'immagine e' un ambiente,
# il run lo lancia l'operatore. Un default che partisse da solo scansionerebbe
# senza che nessuno l'abbia chiesto.
ENTRYPOINT ["vspt"]
CMD ["--help"]
