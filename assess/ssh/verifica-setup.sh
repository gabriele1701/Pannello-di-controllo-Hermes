#!/usr/bin/env bash
#
# verifica-setup.sh — ACCETTAZIONE del setup SSH/secret del VSPT, DA ESEGUIRE
# SULLA VM. NON e' in CI e NON e' nel percorso di esecuzione del tool: tocca
# docker, ssh reale e utenti della VM. Stampa PASS/FAIL per controllo ed esce
# non-zero se almeno uno fallisce.
#
# Nessun segreto viene stampato: la leggibilita' si prova con `test -r`, mai con
# `cat`.
#
# Criterio del controllo 3: un utente ORDINARIO — non root, non in gid 1002,
# non nei gruppi docker/sudo/wheel — non deve poter leggere la chiave. Un utente
# privilegiato la leggerebbe per i suoi privilegi e renderebbe il test
# inconcludente, quindi lo script lo rifiuta prima di provare la lettura.
#
# Uso:
#   assess/ssh/verifica-setup.sh [UTENTE_DI_PROVA]
# oppure via variabili d'ambiente (override dei default):
#   VSPT_TEST_USER=<utente non privilegiato> assess/ssh/verifica-setup.sh
#
set -uo pipefail

# --- parametri (override via ambiente) ------------------------------------- #
COMPOSE_FILES=${VSPT_COMPOSE_FILES:-"-f compose.yaml -f assess/compose.assess.yaml"}
PROFILO=${VSPT_PROFILE:-assess}
SCANNER=${VSPT_SCANNER_SERVICE:-scanner}

# Percorsi DENTRO il container (montati dal compose).
KEY_CT=${VSPT_KEY_PATH:-/run/secrets/scanner_ed25519}
KH_CT=${VSPT_KNOWN_HOSTS_PATH:-/run/secrets/known_hosts}
# Percorso della chiave SULL'HOST della VM (per il controllo 3).
KEY_HOST=${VSPT_KEY_ON_HOST:-/etc/hermes-vspt/secrets/scanner_ed25519}

# Utente non privilegiato della VM che NON deve leggere la chiave (controllo 3).
UTENTE_PROVA=${VSPT_TEST_USER:-${1:-}}

# Destinazione SSH usata dai controlli 5 e 6 (dal container verso l'host VM).
SSH_USER=${VSPT_SSH_USER:-assess}
SSH_HOST=${VSPT_SSH_HOST:-host.docker.internal}

DC="docker compose ${COMPOSE_FILES} --profile ${PROFILO}"
OPZIONI_SSH=(-i "$KEY_CT" -o BatchMode=yes -o IdentitiesOnly=yes \
             -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=${KH_CT}" \
             -o ConnectTimeout=10)

falliti=0
pass() { echo "PASS - $1"; }
fail() { echo "FAIL - $1"; falliti=$((falliti + 1)); }

echo "== Accettazione setup SSH/secret VSPT =="
echo "   compose: ${DC}   servizio: ${SCANNER}"
echo

# --- 1) UID/GID del container = 1002:1002 ---------------------------------- #
id_out=$(${DC} run --rm --entrypoint id "${SCANNER}" 2>/dev/null)
if grep -q "uid=1002" <<<"$id_out" && grep -q "gid=1002" <<<"$id_out"; then
    pass "1) il container gira come uid=1002 gid=1002"
else
    fail "1) uid/gid del container non 1002:1002 (osservato: ${id_out:-vuoto})"
fi

# --- 2) assess (container) legge la chiave --------------------------------- #
if ${DC} run --rm --entrypoint sh "${SCANNER}" -c "test -r ${KEY_CT}" >/dev/null 2>&1; then
    pass "2) il container legge la chiave (${KEY_CT})"
else
    fail "2) il container NON legge la chiave (${KEY_CT})"
fi

# --- 3) un utente ORDINARIO NON legge la chiave sull'host ------------------ #
# Il controllo ha senso solo se l'utente di prova e' davvero non privilegiato:
# un root, o un utente in gid 1002 o nei gruppi docker/sudo/wheel, leggerebbe la
# chiave per i suoi privilegi, non per un difetto dei permessi -> il test sarebbe
# inconcludente. Si valida PRIMA del test di lettura.
if [ -z "${UTENTE_PROVA}" ]; then
    fail "3) nessun utente di prova indicato: crea un utente NON privilegiato \
(es. 'sudo useradd -m provavspt') e rilancia con VSPT_TEST_USER=provavspt"
elif ! id "${UTENTE_PROVA}" >/dev/null 2>&1; then
    fail "3) l'utente di prova '${UTENTE_PROVA}' non esiste: crealo non \
privilegiato e rilancia"
elif [ "$(id -u "${UTENTE_PROVA}")" -eq 0 ]; then
    fail "3) controllo inconcludente: l'utente di prova '${UTENTE_PROVA}' e' root \
(uid 0): usane uno ordinario"
else
    gruppi_nomi=$(id -nG "${UTENTE_PROVA}" 2>/dev/null)
    gruppi_num=$(id -G "${UTENTE_PROVA}" 2>/dev/null)
    privilegio=""
    for g in docker sudo wheel; do
        if grep -qw "${g}" <<<"${gruppi_nomi}"; then privilegio="gruppo ${g}"; break; fi
    done
    if [ -z "${privilegio}" ] && grep -qw 1002 <<<"${gruppi_num}"; then
        privilegio="gid 1002"
    fi
    if [ -n "${privilegio}" ]; then
        fail "3) controllo inconcludente: l'utente di prova e' privilegiato \
(${privilegio}): usane uno ordinario"
    elif sudo -u "${UTENTE_PROVA}" test -r "${KEY_HOST}" 2>/dev/null; then
        fail "3) '${UTENTE_PROVA}' PUO' leggere la chiave ${KEY_HOST} (non deve)"
    else
        pass "3) '${UTENTE_PROVA}' (ordinario) non puo' leggere la chiave sull'host"
    fi
fi

# --- 4) il container NON puo' modificare chiave/known_hosts (mount RO) ------ #
if ${DC} run --rm --entrypoint sh "${SCANNER}" -c "echo x >> ${KEY_CT}" >/dev/null 2>&1; then
    fail "4a) la chiave e' SCRIVIBILE dal container (dev'essere read-only)"
else
    pass "4a) la chiave e' read-only nel container"
fi
if ${DC} run --rm --entrypoint sh "${SCANNER}" -c "echo x >> ${KH_CT}" >/dev/null 2>&1; then
    fail "4b) known_hosts e' SCRIVIBILE dal container (dev'essere read-only)"
else
    pass "4b) known_hosts e' read-only nel container"
fi

# --- 5) SSH con hardening: system.info -> envelope status ok --------------- #
env5=$(${DC} run --rm --entrypoint ssh "${SCANNER}" \
        "${OPZIONI_SSH[@]}" "${SSH_USER}@${SSH_HOST}" system.info 2>/dev/null \
        | head -n1)
if grep -q '"status":"ok"' <<<"$env5"; then
    pass "5) ssh (BatchMode + StrictHostKeyChecking) system.info -> status ok"
else
    fail "5) system.info non ha dato status ok (osservato: ${env5:-vuoto})"
fi

# --- 6) comando non autorizzato rifiutato dal wrapper (exit 126) ----------- #
env6=$(${DC} run --rm --entrypoint ssh "${SCANNER}" \
        "${OPZIONI_SSH[@]}" "${SSH_USER}@${SSH_HOST}" "system.processes; id" 2>/dev/null)
rc6=$?
if grep -q "COMMAND_NOT_ALLOWED" <<<"$env6" && [ "$rc6" -eq 126 ]; then
    pass "6) 'system.processes; id' rifiutato: COMMAND_NOT_ALLOWED, exit 126"
else
    fail "6) comando non autorizzato non rifiutato come atteso (exit ${rc6}, \
osservato: $(head -n1 <<<"$env6"))"
fi

echo
if [ "${falliti}" -eq 0 ]; then
    echo "RISULTATO: tutti i controlli PASSATI."
    exit 0
fi
echo "RISULTATO: ${falliti} controllo/i FALLITO/I."
exit 1
