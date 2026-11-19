# VSPT — assessor della web application del Pannello Hermes

Tool CLI (`vspt`) che valuta la sicurezza della webapp del pannello **e**
dell'ambiente che la ospita, e produce un report unico con finding
normalizzati e rischio = impatto × probabilità.

> Cugino, non fratello, di `hermes-core/bin/hermes-assess`. Quello verifica le
> difese del *server MCP*; questo valuta la *web application* del pannello.

Questo documento confluirà nel README principale alla consegna.

---

## Stato: scaffold indipendente dal target

C'è, e gira senza VM né rete:

- **modello** (`model.py`) e **rischio** (`risk.py`) — il finding canonico e il
  calcolo I×P;
- **scope guard** (`scope.py`) — egress self-check fail-closed e pin del target;
- **config** (`config.py`) — loader `scope.toml` fail-closed;
- **normalizzazione** (`normalize.py`) — output grezzo → finding, con dedup;
- **report** (`report/`) — JSON canonico con schema, HTML dai soli dati JSON;
- **inventario** (`inventory/`) — endpoint e parametri da `openapi.json`;
- **runner + CLI** — orchestrazione, metadati, output sequenziale;
- **collector** (`collectors/`) — i sei, come **stub**: interfaccia completa e
  comando reale documentato, nessuna esecuzione live;
- **test** (`tests/`) — 63 test su fixture.

Arriva con l'ambiente VM (venerdì): l'esecuzione live dei sei collector contro
l'istanza demo, l'applicazione della migrazione `0006` (ruolo `hermes_assess`),
il validatore `ForceCommand` lato server, l'e2e confinato.

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

## Topologia e confinamento (Opzione B)

Lo scanner gira in un container su una rete docker **`internal: true`** che
raggiunge solo `app` e `db` per nome di servizio; l'unica eccezione è `host:22`
(SSH all'host della VM), concessa esplicitamente. "Esterno" è il **metodo**
black-box (HTTP, nessun accesso al sorgente), non la distanza di rete.

Il confinamento è a due livelli, e **quello che conta è la rete**:

1. **Enforcement (autorevole):** la regola di rete `internal: true`. Ogni
   uscita non prevista è bloccata al confine.
2. **Tripwire (nel codice):** l'egress self-check prova sentinelle esterne
   (`1.1.1.1:53`, `8.8.8.8:443`, …) e, se *anche una sola* risponde, **rifiuta
   di partire** (uscita non-zero). Non dimostra che ogni uscita sia chiusa:
   coglie una rete mal configurata e fallisce in sicurezza.

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
- **SSH — la restrizione sta sul server, non nel wrapper Python.** Il
  `wrappers/ssh.py` decide solo *cosa il tool invia*; non impedisce a chi ha la
  chiave di aprire una shell. Il minimo privilegio reale è:
  account `assess` non privilegiato, `restrict` in `authorized_keys`, e un
  `ForceCommand` validatore che confronta `$SSH_ORIGINAL_COMMAND` con
  un'allowlist di comandi read-only. L'allowlist vive sul server, applicata da
  `sshd`.

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

63 test su fixture di output grezzo (`tests/fixtures/`): nessuna rete, nessun
target. Richiedono `jsonschema` (già in `pyproject [dev]`).

## Immagine e licenze

Si spedisce il `Dockerfile`, non un'immagine pre-costruita: il build installa
nuclei/sqlmap/semgrep/pip-audit da upstream a versioni pinnate (vedi
`LICENSES/NOTICE.md`). `compose.assess.yaml` definisce il servizio scanner su
rete `internal: true`, da usare come override del compose del pannello:

```bash
docker compose -f compose.yaml -f assess/compose.assess.yaml --profile assess up scanner
```
