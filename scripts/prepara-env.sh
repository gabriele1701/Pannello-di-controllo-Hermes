#!/usr/bin/env bash
#
# Prepara il file `.env` con i segreti obbligatori, generati qui.
#
#     ./scripts/prepara-env.sh
#
# Esiste perche' il passo precedente era: copiare `.env.example`, eseguire
# `openssl rand -hex 32` tre volte, e incollare ogni risultato accanto alla
# variabile giusta. Quattro valori da riportare a mano in un file di
# configurazione sono quattro occasioni di incollarne uno nella riga
# sbagliata, e il guasto che ne segue — l'applicazione che non si connette al
# database — non dice che la causa e' un copia-incolla.
#
# I tre segreti del sistema sono generati e non scelti: nessuno deve
# ricordarseli. L'unico valore che una persona dovra' digitare e' la password
# dell'operatore, che lo script stampa alla fine, una volta sola.
#
# Esadecimale e non base64: due di queste password finiscono dentro un URL di
# connessione, e `openssl rand -base64` produce una `/` nel 40% dei casi. A
# parita' di byte generati l'entropia e' la stessa.

set -euo pipefail

RADICE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODELLO="$RADICE/.env.example"
DESTINAZIONE="$RADICE/.env"

forza=0
password_operatore=""

while [ $# -gt 0 ]; do
  case "$1" in
    --forza)
      forza=1
      shift
      ;;
    --password-operatore)
      password_operatore="${2:-}"
      if [ -z "$password_operatore" ]; then
        echo "--password-operatore richiede un valore" >&2
        exit 2
      fi
      shift 2
      ;;
    -h | --help)
      sed -n '2,24p' "${BASH_SOURCE[0]}" | sed 's/^#\s\?//'
      exit 0
      ;;
    *)
      echo "Opzione sconosciuta: $1" >&2
      echo "Uso: $0 [--forza] [--password-operatore VALORE]" >&2
      exit 2
      ;;
  esac
done

command -v openssl >/dev/null 2>&1 || {
  echo "Serve openssl per generare i segreti. Su Debian/Ubuntu: apt install openssl" >&2
  exit 1
}

[ -f "$MODELLO" ] || {
  echo "Manca $MODELLO: eseguire lo script dalla radice del repository." >&2
  exit 1
}

# Rifiuta di sovrascrivere un .env esistente.
#
# Non e' prudenza generica: le password del database sono scritte dentro il
# volume di PostgreSQL al primo avvio. Rigenerarle lascia un volume che
# contiene i ruoli vecchi e un .env che ne dichiara di nuovi, cioe'
# un'applicazione che non si connette piu' e un motivo non ovvio.
if [ -e "$DESTINAZIONE" ] && [ "$forza" -eq 0 ]; then
  cat >&2 <<FINE
$DESTINAZIONE esiste gia': non viene toccato.

Le password che contiene sono quelle con cui il volume del database e' stato
creato. Rigenerarle senza rimuovere il volume lascia l'applicazione incapace
di connettersi.

Per ricominciare davvero da zero:

    docker compose down -v
    rm .env
    ./scripts/prepara-env.sh

Per sovrascrivere comunque (il file attuale viene salvato in .env.precedente):

    ./scripts/prepara-env.sh --forza
FINE
  exit 1
fi

if [ -e "$DESTINAZIONE" ]; then
  cp "$DESTINAZIONE" "$RADICE/.env.precedente"
  chmod 600 "$RADICE/.env.precedente"
  echo "Il .env precedente e' stato salvato in .env.precedente"
fi

proprietario="$(openssl rand -hex 32)"
applicativo="$(openssl rand -hex 32)"
chiave="$(openssl rand -hex 32)"

# Dodici byte, cioe' ventiquattro caratteri: questa password si copia a mano
# nel modulo di accesso, a differenza delle altre tre che nessuno digita mai.
if [ -z "$password_operatore" ]; then
  password_operatore="$(openssl rand -hex 12)"
  generata="si"
else
  generata="no"
fi

# Il file nasce accanto alla destinazione e viene rinominato solo dopo i
# controlli: `.env` o e' completo o non esiste.
#
# Prima la scrittura andava diretta su `.env`, e la guardia sui segnaposto
# qui sotto usciva con stato 1 lasciando a terra un file incompleto. La
# seconda esecuzione trovava quel file, rifiutava di toccarlo e indirizzava
# verso `docker compose down -v && rm .env`, cioe' verso un problema diverso
# da quello vero -- con il problema vero ormai scomparso dallo schermo.
PARZIALE="$DESTINAZIONE.parziale"
trap 'rm -f "$PARZIALE"' EXIT

# Creato vuoto e GIA' a 600, prima che ci finisca dentro un segreto: la
# redirezione sotto riusa questo file e ne conserva i permessi. Scrivere
# prima e restringere dopo lascia una finestra, breve ma vera, in cui
# quattro segreti sono leggibili da tutti gli utenti della macchina.
rm -f "$PARZIALE"
(
  umask 077
  : > "$PARZIALE"
)

# La sostituzione legge riga per riga invece di usare `sed`: una password
# scelta da chi esegue lo script puo' contenere `&`, `/` o `\`, che in uno
# script di sed hanno un significato. Qui il valore non viene mai
# interpretato.
while IFS= read -r riga || [ -n "$riga" ]; do
  case "$riga" in
    POSTGRES_PASSWORD=*) printf '%s\n' "POSTGRES_PASSWORD=$proprietario" ;;
    HERMES_APP_DB_PASSWORD=*) printf '%s\n' "HERMES_APP_DB_PASSWORD=$applicativo" ;;
    APP_SECRET_KEY=*) printf '%s\n' "APP_SECRET_KEY=$chiave" ;;
    HERMES_ADMIN_PASSWORD=*) printf '%s\n' "HERMES_ADMIN_PASSWORD=$password_operatore" ;;
    *) printf '%s\n' "$riga" ;;
  esac
done < "$MODELLO" > "$PARZIALE"

# Controprova. Se `.env.example` guadagnasse un quinto segnaposto senza che
# questo script lo sappia, il file resterebbe incompleto e l'avvio
# fallirebbe piu' tardi, con un errore che non nomina questo passaggio.
#
# Il controllo guarda SOLO le righe di assegnazione: `.env.example` e' anche
# documentazione, e un commento che nomini il segnaposto per spiegarlo non e'
# un segnaposto da riempire. Senza l'ancoraggio, scrivere quella parola in un
# commento fermava lo script.
SEGNAPOSTO='^[A-Za-z_][A-Za-z0-9_]*=.*sostituiscimi'
if grep -qE "$SEGNAPOSTO" "$PARZIALE"; then
  echo >&2
  echo "Il modello ha dei segnaposto che questo script non sa riempire:" >&2
  grep -nE "$SEGNAPOSTO" "$PARZIALE" >&2
  echo >&2
  echo ".env NON e' stato scritto: non resta a terra un file incompleto che" >&2
  echo "alla prossima esecuzione faccia sembrare il problema un altro." >&2
  echo >&2
  echo "Aggiungere queste variabili a scripts/prepara-env.sh." >&2
  exit 1
fi

# Rinomina nello stesso filesystem: da qui in avanti `.env` esiste ed e'
# completo. I permessi arrivano dal file parziale; il chmod e' la garanzia
# scritta, non un rimedio.
mv "$PARZIALE" "$DESTINAZIONE"
chmod 600 "$DESTINAZIONE"

utente="$(grep -E '^HERMES_ADMIN_USERNAME=' "$DESTINAZIONE" | cut -d= -f2-)"

cat <<FINE

.env creato, con permessi 600.

  Le tre password del sistema sono state generate e non servono a nessuno:
  le leggono solo il database e l'applicazione.

  Credenziali per entrare nel pannello:

      utente    ${utente:-operatore}
      password  $password_operatore
FINE

if [ "$generata" = "si" ]; then
  cat <<'FINE'

  Questa password e' stata generata adesso ed e' scritta in .env. Da li' la
  si rilegge in qualunque momento; dopo il primo avvio il database ne
  conserva soltanto l'hash argon2.
FINE
fi

cat <<'FINE'

Avvio:

    docker compose up --build

FINE
