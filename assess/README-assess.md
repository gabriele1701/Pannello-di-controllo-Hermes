# VSPT — assessor della web application del Pannello Hermes

Tool CLI (`vspt`) che valuta la sicurezza della webapp del pannello **e**
dell'ambiente che la ospita, e produce un report unico con finding
normalizzati e rischio = impatto × probabilità.

> Cugino, non fratello, di `hermes-core/bin/hermes-assess`. Quello verifica le
> difese del *server MCP*; questo valuta la *web application* del pannello.

Questo documento confluirà nel README principale alla consegna.

---

## Stato

Implementato e testato **senza VM né target**:

- **modello** (`model.py`) e **rischio** (`risk.py`) — il finding canonico e il
  calcolo I×P;
- **scope guard** (`scope.py`) — egress self-check fail-closed e pin del target;
- **config** (`config.py`) — loader `scope.toml` fail-closed;
- **parse layer dei collector** (`collectors/`) — per ciascuno, costruzione del
  comando e trasformazione output-grezzo → `RawResult`, implementati e coperti.
  L'**unico** stub è `_esegui_live` (I/O subprocess/SSH/psycopg), isolato;
- **normalizzazione** (`normalize.py`) — `RawResult` → finding, con dedup;
- **report** (`report/`) — JSON canonico con schema, HTML dai soli dati JSON;
- **inventario** (`inventory/`) — endpoint e parametri da `openapi.json`;
- **protocollo SSH a verbi** (`ssh/PROTOCOL.md`, `wrappers/ssh.py`) — il client
  parla il contratto del wrapper `vspt-ssh-wrapper` (fonte di verità sulla VM),
  ora con `source.export`;
- **recupero sorgente** (`source_ingest.py`) — ingest sicuro del `tar.gz`
  esportato (sha, cap, filter data, provenienza) per semgrep/pip-audit;
- **trasporto SSH live del collector `system`** (`wrappers/ssh.py`,
  `collectors/internal_system.py`, `cli.py`) — il primo collector che va dal
  vivo: la CLI costruisce il canale SSH dalla config e lo passa al collector;
- **config di rete per il primo test** (`net/nftables-assess.nft`,
  `net/applica-nftables.sh`, `compose.assess.yaml`) — override con bind mount
  dei secret, subnet fissa per la rete `uscita`, e regole nft **host-side** per
  subnet; **scritte, da applicare sulla VM**;
- **runner + CLI** — orchestrazione, metadati, output sequenziale, selezione
  `--only <collector>` per eseguire un sottoinsieme;
- **test** (`tests/`) — parser di tutti i collector (zero/malformato/condizione
  non valida), contratto SSH (client + wrapper come subprocess), scope, modello,
  normalize, report.

Resta per la messa in opera (**sulla VM**):

- **primo test live: `system`** — il codice è pronto (`--only system`); sulla VM
  si preparano chiave/known_hosts, l'utente `assess` col `ForceCommand`, e si
  applicano le nft host-side (`net/applica-nftables.sh`). Procedura e checkpoint
  nella sezione *«Primo test live del collector `system`»*;
- collegare gli altri `_esegui_live` al processo reale (HTTP/psycopg/sorgente);
- applicare la migrazione `0006` e creare `hermes_assess`;
- e2e confinato contro l'istanza demo.

## Esecuzione

Da clone, senza installare nulla nel pannello:

```bash
python -m assess --help
python -m assess run --config assess/scope.toml
python -m assess report assess/out/report.json      # rigenera l'HTML dal JSON
```

Dentro l'immagine dello scanner il comando è `vspt` (wrapper su `python -m
assess`). Il console_script "proprio" vivrebbe in `pyproject [project.scripts]`,
ma è fuori dal perimetro di questo scaffold: il wrapper dà lo stesso comando
senza toccare il packaging del pannello.

Sottocomandi: `run` (esegue e produce il report), `report` (rigenera l'HTML dal
JSON), `update-feeds` (aggiornamento template/CVE — **separato**, esce in rete,
non necessario a un run confinato).

`run` accetta `--only <collector>…` per eseguire un **sottoinsieme**: `vspt run
--only system` esegue solo `system`; gli altri non vengono nemmeno tentati. Un
nome sconosciuto e' un errore (fail-closed), non un run silenziosamente ridotto.

## Configurazione: `scope.toml`

Copia l'esempio e compila i `DA_COMPILARE`:

```bash
cp assess/scope.example.toml assess/scope.toml
# poi compila operator_user, ssh.host, ssh.key_path
```

Il loader è **fail-closed**: file assente, un solo `DA_COMPILARE` residuo, o un
campo obbligatorio mancante → il tool non parte. Un perimetro-segnaposto non è
un perimetro.

**I segreti non stanno nel file.** Nel `scope.toml` c'è solo il *nome* della
variabile d'ambiente che li porta:

| Segreto | Variabile | Note |
|---|---|---|
| Password operatore demo | `ASSESS_TARGET_PASSWORD` | login HTTP |
| DSN di `hermes_assess` | `ASSESS_DB_DSN` | DB in sola lettura |
| Chiave SSH | file montato come secret (`ssh.key_path`) | mai nel repo |

Il report redige qualunque valore sensibile.

> **TODO (valori dalla VM):**
> - `ssh.host` ← **IP/hostname della VM** (o `host.docker.internal`) — serve per
>   il primo test `system`;
> - `VSPT_SUBNET_USCITA` ← una **/24 non usata** per la rete `uscita`, e
>   `VSPT_HOST_SSH` ← l'**IP di host:22** dai container, per `applica-nftables.sh`;
> - *(per gli step successivi, non per il test `system`)* `ASSESS_DB_DSN` ←
>   **DSN di `hermes_assess`** (il ruolo lo crea la migrazione `0006`), e
>   `ASSESS_TARGET_PASSWORD` ← password dell'operatore demo (`HERMES_SEED_DEMO=1`).
>   Assenti, i collector HTTP/DB restano NOT_RUN.

## Topologia e confinamento (Opzione B)

Lo scanner gira in un container su una rete docker **`internal: true`** che
raggiunge solo `app` e `db` per nome di servizio; l'unica eccezione è `host:22`
(SSH all'host della VM), concessa esplicitamente. "Esterno" è il **metodo**
black-box (HTTP, nessun accesso al sorgente), non la distanza di rete.

Il confinamento è a due livelli, e **quello che conta è la rete**:

1. **Enforcement (autorevole): la rete.** `internal: true` confina `app` e `db`
   (nessuna uscita) e lo scanner li raggiunge lì, per nome di servizio. Ma
   `internal` **da solo non regge l'eccezione SSH**: una rete internal-only non
   ha gateway, quindi non può raggiungere `host:22` e il collector `system` non
   partirebbe mai. Perciò lo scanner sta anche su una seconda rete *con* gateway
   (`uscita`), con **subnet fissa** (`ipam`, da `VSPT_SUBNET_USCITA`), ristretta
   dalle regole **`net/nftables-assess.nft`** applicate **host-side** nel forward
   path: dalla subnet `uscita` si concede SOLO `host:22` ed
   `established/related`, e si fa `drop` del resto. Non si autorizza DNS generico:
   per il primo test `system` non serve traffico DNS in uscita. Il filtro è **per subnet**, non per IP
   per-container (che cambiano a ogni `up`): la stessa `VSPT_SUBNET_USCITA`
   alimenta compose e nft, così rete e filtro concordano. La garanzia è "gateway
   sorvegliato", non "nessun gateway". (Config **scritta, da applicare sulla
   VM** con `net/applica-nftables.sh`.)
2. **Tripwire (nel codice):** l'egress self-check prova sentinelle esterne
   (`1.1.1.1:53`, `8.8.8.8:443`, …) e, se *anche una sola* risponde, **rifiuta
   di partire** (uscita non-zero). Non dimostra che ogni uscita sia chiusa:
   coglie una rete mal configurata (regole nft non applicate) e fallisce in
   sicurezza.

**I servizi da attaccare alla rete dello scanner:** `app` e `db` devono stare
anche sulla rete `interna` dello scanner (si aggiunge `interna` ai loro
`networks` nell'override, o la si dichiara condivisa). Lo scanner li raggiunge
per nome di servizio (`app:8000`, `db:5432`), non via porta pubblicata.

**Non distruttivo, regola dura:** il tool non esegue mai comandi che modificano
dati o stato. Il DB è letto in sola lettura. `docker compose down -v` cancella
i volumi: è una procedura **manuale** dell'operatore, solo sull'istanza demo
sacrificabile, **mai** un passo del tool.

## Canali autenticati (minimo privilegio)

| Canale | Credenziale | Privilegio | Uso |
|---|---|---|---|
| HTTP `app:8000` | cookie di sessione (login operatore demo) | utente operatore | scan esterno + PT |
| SQL `db:5432` | ruolo `hermes_assess` | **SELECT-only** | ruoli/grant/config |
| SSH host VM `:22` | chiave, utente `assess` | **ristretto lato server** | processi/porte/sorgente |

- **`hermes_assess`**: ruolo nuovo, migrazione `0006`, `SELECT` sulle tabelle +
  lettura `pg_catalog`/`information_schema`. Non si riusa `hermes_app` (non è
  read-only). La migrazione è **scritta ma non applicata**: si applica venerdì.
- **SSH — un protocollo a verbi, la restrizione sta sul server.** Non comandi
  shell: il client (`wrappers/ssh.py`) invia un **verbo logico**
  (`system.info`, `system.listeners`, `system.processes`, `source.export`) e
  riceve **un envelope JSON** su una riga. Il controllo di sicurezza è il
  ForceCommand `assess/ssh/vspt-ssh-wrapper` sulla VM: `sshd` lo invoca per ogni
  connessione, legge `$SSH_ORIGINAL_COMMAND` come stringa-verbo esatta (mai
  shell), la confronta con l'allowlist dei verbi e risponde. `system.processes;
  id` non è il verbo `system.processes`: è un'altra stringa, e viene negata con
  `COMMAND_NOT_ALLOWED` (exit 126). Il contratto completo è in
  **`assess/ssh/PROTOCOL.md`**.
- **Recupero del sorgente — `source.export` + ingest sicuro.** `semgrep` e
  `pip-audit` non leggono un sorgente "qualsiasi": lo ottengono dal target col
  verbo `source.export`, che impacchetta in `tar.gz` **solo** i `*.py` di
  `backend/` e i manifest `requirements.txt`/`pyproject.toml` (allowlist di
  contenuto; percorsi fissi lato server; symlink, `static/`, `.pyc` esclusi;
  cap su file/byte/tempo). Il client (`source_ingest.py`) **non si fida**
  dell'archivio: verifica `archive_sha256`, estrae in una temp dir con
  `tarfile` `filter="data"` applicando cap cumulativi e rifiutando i membri non
  regolari (niente path traversal, niente symlink, niente decompression bomb),
  registra la **provenienza** (sha, per-file, target, timestamp) nei metadati e
  pulisce la temp dir. Se export, integrità o estrazione falliscono, i due
  check sono **FALLITO/NOT_RUN**, mai un falso "pulito".

### SSH ristretto: installazione (sulla VM, venerdì)

`assess/ssh/vspt-ssh-wrapper` nel repo resta la **fonte unica**: va tenuto
byte-identico a quello sulla VM. Questo giro aggiunge il verbo `source.export`,
quindi il wrapper **va reinstallato sulla VM** (stesso file, non una copia
divergente) perché il nuovo verbo sia servito. Installazione:

```bash
# 1) utente non privilegiato, nessun sudo
sudo useradd --system --create-home --shell /usr/sbin/nologin assess

# 2) il wrapper raggiungibile sulla VM (es. /opt/pannello/assess/ssh/) e python3

# 3) in ~assess/.ssh/authorized_keys, la chiave con restrict + ForceCommand:
restrict,command="/opt/pannello/assess/ssh/vspt-ssh-wrapper" ssh-ed25519 AAAA... assess
```

`restrict` toglie port/agent/X11-forwarding, pty e user-rc; `command="…"`
(ForceCommand della chiave) impone il wrapper a ogni connessione, qualunque
cosa il client chieda. Il wrapper risponde solo ai verbi dell'allowlist, in
sola lettura e senza privilegi; ogni altra stringa è negata. Il client-side non
c'entra con questa garanzia: è `sshd` ad applicarla.

## Primo test live del collector `system` (sulla VM)

Il primo collector che va dal vivo è `system`, via SSH. Gli altri (HTTP, DB,
sorgente) restano per gli step successivi: qui si abilita **solo** `system`, con
`--only`, e il resto resta NOT_RUN per scelta, non per errore.

**Cosa prepara l'operatore sulla VM (non è compito del tool):** la chiave
`scanner_ed25519` e il `known_hosts` in `/etc/hermes-vspt/secrets/`, l'utente
`assess` con `restrict` + `ForceCommand` (vedi sopra), e le regole nft host-side.

**Messa in opera:**

```bash
# 1) scope.toml: compila [ssh].host (e operator_user con l'utente demo reale).
#    ASSESS_TARGET_PASSWORD / ASSESS_DB_DSN NON servono: i collector HTTP/DB
#    resteranno NOT_RUN.
cp assess/scope.example.toml assess/scope.toml && $EDITOR assess/scope.toml

# 2) scegli una /24 non usata per la rete `uscita` e applica le nft host-side
#    (la stessa subnet alimenta compose e nft). HOST_SSH = IP host:22 dai container.
export VSPT_SUBNET_USCITA=10.77.42.0/24
sudo -E VSPT_HOST_SSH=10.0.2.2 assess/net/applica-nftables.sh

# 3) esegui SOLO il collector system (lo scanner non esce verso Internet):
VSPT_SUBNET_USCITA=$VSPT_SUBNET_USCITA \
  docker compose -f compose.yaml -f assess/compose.assess.yaml --profile assess \
  run --rm scanner run --config /scope/scope.toml --only system
```

**Checkpoint (cosa guardare, in ordine):**

1. **Egress self-check passa** → il run parte. Se *fallisce*, le nft non sono
   applicate (o la subnet non combacia): è la tripwire che fa il suo lavoro, non
   un falso positivo. Applica/riapplica `applica-nftables.sh` e riprova.
2. **`system` COMPLETATO** nel report, con le attestazioni sulle porte in
   ascolto (attese `app:8000`, `db:5432`; ogni altra è segnalata).
3. **Gli altri collector NOT_RUN** con motivo esplicito (`--only system`): nel
   report risultano saltati, non superati.
4. **Nessuna uscita verso Internet**: il contatore del `drop` nelle nft
   (`nft list table ip assess_egress`) resta a zero per traffico legittimo e
   sale solo se qualcosa tenta un'uscita non prevista.

**Regole nft host-side — applicazione e caveat.** `net/applica-nftables.sh` è
idempotente: legge `VSPT_SUBNET_USCITA` e `VSPT_HOST_SSH`, controlla la sintassi
(`nft -c`) prima di toccare lo stato, rimuove ed riapplica la tabella
`ip assess_egress`. Il filtro è **per subnet** e vive nel **forward path**
dell'host. *Caveat Docker 29 (backend nftables):* Docker gestisce catene proprie;
questa tabella è separata, con hook forward a priorità negativa (gira prima) e
`drop` terminale (vince). Un restart del demone o un `docker network` può
ricreare le reti: se la subnet di `uscita` cambia, **riapplica**. L'SSH verso
l'host passa spesso per l'INPUT (destinazione = gateway), non per il forward: in
quel caso la regola `host:22` è innocua e ciò che conta resta il `drop`
dell'uscita verso Internet.

## Il report

Due file in `out/`:

- `report.json` — documento canonico: `meta` (timestamp, commit del pannello,
  versioni tool, check {completati, saltati, falliti}, limitazioni, hash della
  config di scope), `findings` (schema §7), `riepilogo` (conteggi, fonti
  distinte). Valida contro `report/json_report.SCHEMA` (JSON Schema 2020-12).
- `report.html` — vista dei **soli** dati JSON (nessuna rivalutazione), template
  autoconsistente, nessun asset remoto, si apre offline.

**Onestà, in evidenza.** Un controllo non eseguito o fallito non è mai
presentato come superato: i check saltati/falliti e i limiti sono mostrati in
cima al report, non in nota. `pentest_result: negative` significa *non rilevato
nei test svolti*, non *assente*.

### Severità: la banda derivata dal `risk_score`

La `severity` di un finding è la **banda nominale** standard
*low/medium/high/critical*, derivata dal `risk_score`:

| `risk_score` | `severity` |
|---|---|
| 1–4 | low |
| 5–9 | medium |
| 10–15 | high |
| 16–25 | critical |

Non è `RiskTier` (`verde`/`giallo`/`rosso`): nel pannello quello è l'asse
dell'**invasività di un tool** — quanto è pericoloso *eseguirlo* — non la
**gravità di una vulnerabilità**, e il pannello tiene i due assi separati di
proposito. Riusarlo li fonderebbe, e legherebbe l'assessor a `backend`. Non è
nemmeno un enum nuovo: è la scala a quattro livelli calcolata in casa
(`risk.py`), per cui il confine *high* / *critical* a 16 torna a contare.

La `severity` **non** è mai un input libero: `Finding` la deriva sempre dal
`risk_score` e rifiuta un oggetto incoerente. Non esiste un campo `banda`
separato — la severity *è* la banda.

Di conseguenza lo scaffold non dipende da `backend` a runtime: usa solo la
standard library.

## Test

```bash
python -m pytest assess/tests/ -q
```

167 test su fixture (`tests/fixtures/`): nessuna rete, nessun target reale.
Coprono i parser di tutti i collector (risultati, zero, malformato, condizione
non valida), il contratto SSH (client + `vspt-ssh-wrapper` invocato come
subprocess) e il trasporto SSH live con `subprocess` **mockato** (argv di
hardening, guasti, `_esegui_live`), `source.export` e l'**ingest sicuro**
(archivio benigno estratto; path traversal, symlink, hardlink, bomb/oversize,
troppi file, sha mismatch tutti rifiutati), le **credenziali opzionali** e il
fail-closed su `[ssh]`, la selezione `--only` e l'onestà del NOT_RUN, lo scope
guard, il modello, la normalizzazione e il report. Un test verifica anche che
l'override `compose.assess.yaml` sia valido (`docker compose config`) e si salta
da solo dove docker non c'è. Richiedono `jsonschema` (già in `pyproject [dev]`).

La CI del pannello esegue `tests/` (la suite del backend), non `assess/tests/`:
quest'ultima si lancia a mano col comando sopra.

## Immagine e licenze

Si spedisce il `Dockerfile`, non un'immagine pre-costruita: il build installa
nuclei/sqlmap/semgrep/pip-audit da upstream a versioni pinnate (vedi
`LICENSES/NOTICE.md`). `compose.assess.yaml` è un **override** del compose del
pannello: mette lo scanner su `interna` (con `app`/`db`) e `uscita` (solo
`host:22`), monta i secret read-only e richiede `VSPT_SUBNET_USCITA` (la subnet
fissa della rete `uscita`, la stessa delle nft). Lo scanner **non** parte da
solo (`profiles: assess`, nessuna scansione al boot): lo si lancia col
sottocomando `run`.

```bash
VSPT_SUBNET_USCITA=10.77.42.0/24 \
  docker compose -f compose.yaml -f assess/compose.assess.yaml --profile assess \
  run --rm scanner run --config /scope/scope.toml --only system
```
