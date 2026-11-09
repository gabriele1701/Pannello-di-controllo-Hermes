#!/bin/sh
# Verifica che il database rifiuti a mano cio' che l'API rifiuta via HTTP.
#
# E' la seconda meta' del criterio §11: «rifiutato sia dall'API sia dal
# database se la query viene eseguita a mano». Qui le query si eseguono a
# mano, con una console aperta sul database, come la aprirebbe chi valuta.
#
# Due gruppi di verifiche, con due ruoli diversi:
#
#   A. con il ruolo PROPRIETARIO -- i trigger rifiutano anche chi possiede le
#      tabelle: declassamento, UPDATE/DELETE/TRUNCATE sulle tabelle
#      append-only, CIDR non canonica, alias fuori perimetro;
#   B. con il ruolo APPLICATIVO -- cio' che il proprietario potrebbe fare e
#      lui no: disabilitare i trigger, rimuoverli, cambiare
#      session_replication_role, scrivere nel log.
#
# Il gruppo B e' il motivo per cui i due ruoli esistono. Senza di esso
# l'affermazione «i vincoli sono nel database» descriverebbe dove stanno
# scritti, non chi puo' togliterli.
#
# Uso, contro uno stack avviato con docker compose:
#
#     ./.github/scripts/verifica_database.sh
#
# Uso contro un PostgreSQL locale, senza container:
#
#     PSQL_CMD="psql -h /tmp -p 5433" \
#     PGDATABASE=hermes_panel UTENTE_PROPRIETARIO=hermes UTENTE_APP=hermes_app \
#       ./.github/scripts/verifica_database.sh

set -eu

# Come si invoca psql. Il default parla al container `db` del compose; si
# sovrascrive per girare contro un server locale.
PSQL_CMD="${PSQL_CMD:-docker compose exec -T db psql}"

# Le credenziali arrivano da .env, se c'e'. Non si stampano mai.
if [ -f .env ]; then
    # shellcheck disable=SC1091
    . ./.env
fi

PGDATABASE="${PGDATABASE:-${POSTGRES_DB:-hermes_panel}}"
UTENTE_PROPRIETARIO="${UTENTE_PROPRIETARIO:-${POSTGRES_USER:-hermes}}"
UTENTE_APP="${UTENTE_APP:-hermes_app}"

FALLITE=0

# Esegue una istruzione e pretende che FALLISCA, stampando il messaggio di
# errore che il database ha prodotto. Il messaggio conta: i trigger di questo
# progetto scrivono per essere letti da un operatore.
deve_fallire() {
    ETICHETTA="$1"
    UTENTE="$2"
    PASSWORD="$3"
    SQL="$4"

    printf '  %-46s ' "$ETICHETTA"
    if PGPASSWORD="$PASSWORD" $PSQL_CMD -U "$UTENTE" -d "$PGDATABASE" \
         -v ON_ERROR_STOP=1 -c "$SQL" > /tmp/verifica_sql.out 2>&1; then
        echo "NON HA FALLITO <-- problema"
        sed 's/^/      /' /tmp/verifica_sql.out
        FALLITE=$((FALLITE + 1))
        return
    fi
    grep -oE 'ERROR:.*' /tmp/verifica_sql.out | head -1 | cut -c1-110
}

# Esegue una istruzione e pretende che RIESCA. Serve come controprova: senza,
# una verifica potrebbe passare perche' il database e' rotto o vuoto, non
# perche' il vincolo funziona.
deve_riuscire() {
    ETICHETTA="$1"
    UTENTE="$2"
    PASSWORD="$3"
    SQL="$4"

    printf '  %-46s ' "$ETICHETTA"
    if PGPASSWORD="$PASSWORD" $PSQL_CMD -U "$UTENTE" -d "$PGDATABASE" \
         -tA -v ON_ERROR_STOP=1 -c "$SQL" > /tmp/verifica_sql.out 2>&1; then
        tr -d '\n' < /tmp/verifica_sql.out | cut -c1-60; echo
    else
        echo "FALLITA <-- problema"
        sed 's/^/      /' /tmp/verifica_sql.out
        FALLITE=$((FALLITE + 1))
    fi
}

PW_PROPRIETARIO="${POSTGRES_PASSWORD:-}"
PW_APP="${HERMES_APP_DB_PASSWORD:-}"

echo "== controprove: lo schema c'e' e i dati di esempio sono stati scritti =="
deve_riuscire "numero di tool registrati" "$UTENTE_PROPRIETARIO" "$PW_PROPRIETARIO" \
    "SELECT count(*) FROM tools"
deve_riuscire "tier effettivo di recon.nmap-sweep" "$UTENTE_PROPRIETARIO" "$PW_PROPRIETARIO" \
    "SELECT effective_tier FROM tool_effective_tier WHERE tool_id='recon.nmap-sweep'"
deve_riuscire "trigger attivi sulle tabelle del dominio" "$UTENTE_PROPRIETARIO" "$PW_PROPRIETARIO" \
    "SELECT count(*) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE NOT t.tgisinternal AND t.tgenabled='O'"

echo
echo "== A. i trigger rifiutano anche il PROPRIETARIO delle tabelle =="
deve_fallire "declassamento del tier" "$UTENTE_PROPRIETARIO" "$PW_PROPRIETARIO" \
    "INSERT INTO tier_overrides (tool_id,tier,reason,created_by) SELECT id,'giallo','provo ad abbassarlo','manuale' FROM tools WHERE tool_id='recon.nmap-sweep'"
deve_fallire "override pari al tier corrente" "$UTENTE_PROPRIETARIO" "$PW_PROPRIETARIO" \
    "INSERT INTO tier_overrides (tool_id,tier,reason,created_by) SELECT id,'rosso','confermo','manuale' FROM tools WHERE tool_id='recon.nmap-sweep'"
deve_fallire "UPDATE su tier_overrides" "$UTENTE_PROPRIETARIO" "$PW_PROPRIETARIO" \
    "UPDATE tier_overrides SET tier='verde'"
deve_fallire "DELETE su tier_overrides" "$UTENTE_PROPRIETARIO" "$PW_PROPRIETARIO" \
    "DELETE FROM tier_overrides"
deve_fallire "TRUNCATE su tier_overrides" "$UTENTE_PROPRIETARIO" "$PW_PROPRIETARIO" \
    "TRUNCATE tier_overrides"
deve_fallire "UPDATE sul log" "$UTENTE_PROPRIETARIO" "$PW_PROPRIETARIO" \
    "UPDATE audit_events SET detail='manomesso'"
deve_fallire "DELETE sul log" "$UTENTE_PROPRIETARIO" "$PW_PROPRIETARIO" \
    "DELETE FROM audit_events"
deve_fallire "TRUNCATE sul log" "$UTENTE_PROPRIETARIO" "$PW_PROPRIETARIO" \
    "TRUNCATE audit_events"
deve_fallire "CIDR con bit host (192.168.205.10/24)" "$UTENTE_PROPRIETARIO" "$PW_PROPRIETARIO" \
    "INSERT INTO scope_networks (cidr,label) VALUES ('192.168.205.10/24','sbagliata')"
deve_fallire "alias fuori dalle reti dichiarate" "$UTENTE_PROPRIETARIO" "$PW_PROPRIETARIO" \
    "INSERT INTO scope_aliases (name,address) VALUES ('fuori','10.0.0.5')"
deve_fallire "rimozione rete con alias dipendenti" "$UTENTE_PROPRIETARIO" "$PW_PROPRIETARIO" \
    "DELETE FROM scope_networks WHERE cidr='192.168.205.0/24'"

echo
echo "== B. il ruolo APPLICATIVO non arriva nemmeno al trigger =="
deve_riuscire "chi e' il ruolo applicativo" "$UTENTE_APP" "$PW_APP" \
    "SELECT current_user || ', superuser=' || rolsuper FROM pg_roles WHERE rolname=current_user"
deve_fallire "DISABLE TRIGGER su tier_overrides" "$UTENTE_APP" "$PW_APP" \
    "ALTER TABLE tier_overrides DISABLE TRIGGER ALL"
deve_fallire "DISABLE TRIGGER sul log" "$UTENTE_APP" "$PW_APP" \
    "ALTER TABLE audit_events DISABLE TRIGGER ALL"
deve_fallire "SET session_replication_role = replica" "$UTENTE_APP" "$PW_APP" \
    "SET session_replication_role = 'replica'"
deve_fallire "DROP TRIGGER della monotonia" "$UTENTE_APP" "$PW_APP" \
    "DROP TRIGGER tier_overrides_monotonia_trg ON tier_overrides"
deve_fallire "CREATE OR REPLACE della funzione" "$UTENTE_APP" "$PW_APP" \
    "CREATE OR REPLACE FUNCTION tier_overrides_monotonia() RETURNS trigger LANGUAGE plpgsql AS \$f\$ BEGIN RETURN NEW; END; \$f\$"
deve_fallire "DROP del vincolo sul motivo" "$UTENTE_APP" "$PW_APP" \
    "ALTER TABLE tier_overrides DROP CONSTRAINT tier_overrides_reason_non_vuoto"
deve_fallire "DROP TABLE sul log" "$UTENTE_APP" "$PW_APP" \
    "DROP TABLE audit_events"
deve_fallire "INSERT nel log" "$UTENTE_APP" "$PW_APP" \
    "INSERT INTO audit_events (correlation_id,event_type,outcome) VALUES (gen_random_uuid(),'tool_call','ok')"
deve_fallire "UPDATE del tier dichiarato di un tool" "$UTENTE_APP" "$PW_APP" \
    "UPDATE tools SET declared_tier='verde'"
deve_fallire "INSERT di un tool" "$UTENTE_APP" "$PW_APP" \
    "INSERT INTO tools (tool_id,agent,declared_tier,personal_data,exec_path,exec_sha256,description) VALUES ('x.y','pentest_kali','verde',false,'a.py','0000000000000000000000000000000000000000000000000000000000000000','x')"
deve_fallire "UPDATE della password di un operatore" "$UTENTE_APP" "$PW_APP" \
    "UPDATE users SET password_hash='\$argon2id\$finto'"
deve_fallire "prolungare la scadenza di un consenso" "$UTENTE_APP" "$PW_APP" \
    "UPDATE scope_consents SET expires_at = now() + interval '10 years'"
deve_fallire "CREATE TABLE nello schema public" "$UTENTE_APP" "$PW_APP" \
    "CREATE TABLE scappatoia (x int)"
deve_fallire "lettura di alembic_version" "$UTENTE_APP" "$PW_APP" \
    "SELECT * FROM alembic_version"
deve_fallire "declassamento (il trigger, quando ci arriva)" "$UTENTE_APP" "$PW_APP" \
    "INSERT INTO tier_overrides (tool_id,tier,reason,created_by) SELECT id,'giallo','provo ad abbassarlo','app' FROM tools WHERE tool_id='recon.nmap-sweep'"

echo
if [ "$FALLITE" -gt 0 ]; then
    echo "$FALLITE verifiche non si sono comportate come devono" >&2
    exit 1
fi
echo "tutte le verifiche sul database si sono comportate come devono"
