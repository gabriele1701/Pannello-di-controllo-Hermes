#!/usr/bin/env bash
#
# applica-nftables.sh — applica (idempotente) le regole di egress dello scanner
# VSPT sull'HOST della VM. NON gira in CI e NON e' nel percorso del tool: tocca
# il forward path dell'host, quindi va eseguito a mano, da root, sulla VM.
#
# Legge la SUBNET della rete `uscita` e l'IP di host:22 da variabili d'ambiente
# (o da argomenti). NON inventa indirizzi: se mancano o sono malformati, esce
# senza toccare nulla (fail-closed).
#
# Uso:
#   VSPT_SUBNET_USCITA=10.77.42.0/24 VSPT_HOST_SSH=10.0.2.2 \
#     sudo -E assess/net/applica-nftables.sh
# oppure, per argomenti:
#   sudo assess/net/applica-nftables.sh 10.77.42.0/24 10.0.2.2
#
# VSPT_SUBNET_USCITA e' LA STESSA variabile che alimenta la rete `uscita` nel
# compose (ipam.subnet): rete e filtro restano d'accordo per costruzione.
#
set -euo pipefail

qui="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NFT_FILE="${qui}/nftables-assess.nft"

SUBNET="${VSPT_SUBNET_USCITA:-${1:-}}"
HOST_SSH="${VSPT_HOST_SSH:-${2:-}}"

errore() { echo "applica-nftables: $*" >&2; exit 2; }

[[ -n "$SUBNET"   ]] || errore "manca VSPT_SUBNET_USCITA (CIDR della rete 'uscita', es. 10.77.42.0/24)"
[[ -n "$HOST_SSH" ]] || errore "manca VSPT_HOST_SSH (IPv4 di host:22 raggiungibile dai container)"
[[ "$SUBNET"   =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$ ]] || errore "SUBNET non e' un CIDR IPv4: $SUBNET"
[[ "$HOST_SSH" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]           || errore "HOST_SSH non e' un IPv4: $HOST_SSH"
[[ -r "$NFT_FILE" ]] || errore "regole non leggibili: $NFT_FILE"

# I define, anteposti al file parametrico. Lo script e' l'unico a conoscere i
# valori concreti; il file di regole resta senza indirizzi.
intestazione="define SUBNET_USCITA = ${SUBNET}
define HOST_SSH = ${HOST_SSH}
"

# Controllo di sintassi PRIMA di toccare lo stato (fail-closed): se le regole
# non passano `nft -c`, non si applica niente.
if ! printf '%s' "$intestazione" | cat - "$NFT_FILE" | nft -c -f - 2>/tmp/assess-nft-check.err; then
    echo "--- nft -c ---" >&2; cat /tmp/assess-nft-check.err >&2
    errore "le regole non superano il controllo di sintassi (nft -c)"
fi

# Idempotente: se la tabella esiste gia', la si rimuove e riapplica, cosi' una
# riesecuzione converge sempre allo stesso stato invece di accumulare regole.
if nft list table ip assess_egress >/dev/null 2>&1; then
    nft delete table ip assess_egress
fi
printf '%s' "$intestazione" | cat - "$NFT_FILE" | nft -f -

echo "applica-nftables: attiva 'ip assess_egress' — saddr ${SUBNET} -> solo host:22 (${HOST_SSH}) + DNS + established; DROP il resto."
