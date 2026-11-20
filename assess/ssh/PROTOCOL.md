# Protocollo SSH dell'assessor VSPT — contratto condiviso

Questo e' il contratto fra il **client** (`assess/wrappers/ssh.py`, dentro il
collector `system`) e il **server** (`assess/ssh/vspt-ssh-wrapper`, il
ForceCommand sulla VM). Come `openapi.json` per l'HTTP: una fonte di verita'
sola, a cui le due parti si allineano. Il wrapper sulla VM e' la fonte di
verita'; questo documento e il client la seguono.

## Trasporto

- **Un comando SSH per richiesta.** Il client apre una connessione SSH e invia
  **un** verbo; il server risponde e la connessione si chiude.
- `SSH_ORIGINAL_COMMAND` e' la **stringa-verbo esatta** (es. `system.listeners`).
  Il ForceCommand la confronta per uguaglianza con l'allowlist e la dispatcha:
  **non e' mai interpretata come shell**. `system.processes; id` non e' il verbo
  `system.processes` — e' un'altra stringa, e viene negata.
- La risposta e' **una riga** di JSON compatto (`separators=(",",":")`,
  `ensure_ascii=True`), terminata da `\n`.

## Verbi

| Verbo               | check_id | Cosa raccoglie                         |
|---------------------|----------|----------------------------------------|
| `system.info`       | SYS-01   | identita' host/OS/kernel/python        |
| `system.listeners`  | SYS-02   | socket TCP in ascolto                  |
| `system.processes`  | SYS-03   | metadati dei processi                  |
| `source.export`     | SRC-01   | sorgente autorizzato come tar.gz       |

Qualunque altra stringa → errore `COMMAND_NOT_ALLOWED` (vedi *Exit*).

`source.export` e' **secco**: nessun parametro dal client. I percorsi sono fissi
lato server — `<root>/backend` (solo `*.py`), `<root>/requirements.txt`,
`<root>/pyproject.toml`, con `root` = `/opt/pannello` — e il client non li
sceglie. E' una **allowlist di contenuto**: entrano solo i `*.py` regolari sotto
`backend/` (esclusi `static/`, `__pycache__`, `.git`) e i due manifest; symlink
e file speciali non entrano, e il target non viene mai scritto.

## Envelope di risposta

```json
{"protocol_version":1,"check_id":"SYS-02","status":"ok","data":{...},"error":null}
```

- `protocol_version`: sempre `1`. Il client che legge un valore diverso rifiuta
  la risposta.
- `check_id`: `SYS-01` | `SYS-02` | `SYS-03`, oppure `UNKNOWN` per un verbo non
  ammesso.
- `status`: `"ok"` | `"error"`.
- `ok` → `data` = l'oggetto del check, `error` = `null`.
- `error` → `data` = `null`, `error` = `{"code":"..."}`.

## Exit code

| Exit | Significato                                        |
|------|----------------------------------------------------|
| 0    | `ok`                                               |
| 1    | `error` (il verbo e' ammesso ma il check e' fallito) |
| 126  | `denied` — verbo non ammesso (`COMMAND_NOT_ALLOWED`) o non implementato (`COMMAND_NOT_IMPLEMENTED`) |

## Shape di `data`

**SYS-01 — `system.info`**

```json
{"hostname":"...","os":"...","os_version":"...","os_pretty_name":"...",
 "kernel":"...","architecture":"...","python_version":"..."}
```

I campi `os`/`os_version`/`os_pretty_name` vengono letti da `/etc/os-release`
(campi `ID`/`VERSION_ID`/`PRETTY_NAME`, **senza** sourcing del file) e possono
essere `null` se assenti.

**SYS-02 — `system.listeners`**

```json
{"listeners":[{"protocol":"tcp","state":"LISTEN","address":"0.0.0.0","port":8000,"process":null}],
 "count":1,"process_visibility":"limited","limitations":["..."]}
```

`process` e' `null`: l'utente `assess`, non privilegiato, non vede il processo
proprietario del socket (per questo `process_visibility` = `"limited"`). Gli
indirizzi IPv6 (`[::]:22`) sono normalizzati ad `address`/`port`.

**SYS-03 — `system.processes`**

```json
{"processes":[{"pid":1,"ppid":0,"user":"root","state":"Ss","command":"init"}],
 "count":1,"visibility":"system_wide","limitations":["..."]}
```

**SRC-01 — `source.export`**

```json
{"format":"tar.gz",
 "archive_b64":"<base64 del tar.gz>",
 "archive_sha256":"<sha256 esadecimale dell'archivio>",
 "byte_size":12345,
 "file_count":42,
 "files":[{"path":"backend/main.py","sha256":"...","size":1024}],
 "exported_paths":["backend/ (*.py)","requirements.txt","pyproject.toml"],
 "target_id":"<hostname>",
 "timestamp":"<UTC ISO 8601>"}
```

`archive_b64` e' il tar.gz dell'intero export; `archive_sha256` ne e' lo sha256
(il client lo riverifica dopo la decodifica, e un mismatch e' un export
fallito); `files[].sha256` e' l'hash del singolo file prima dell'archiviazione.
L'export ha dei cap — al massimo ~2000 file / 10 MB complessivi e un timeout —
che tengono la memoria **bounded**; oltre il limite nessun archivio viene
prodotto (`EXPORT_LIMIT_EXCEEDED`).

## Error code

| check  | code                                                        |
|--------|-------------------------------------------------------------|
| —      | `COMMAND_NOT_ALLOWED`, `COMMAND_NOT_IMPLEMENTED` (denied)    |
| SYS-01 | `SYSTEM_INFO_UNAVAILABLE`                                    |
| SYS-02 | `LISTENER_COMMAND_FAILED`, `LISTENER_COMMAND_TIMEOUT`, `LISTENER_COMMAND_UNAVAILABLE` |
| SYS-03 | `PROCESS_COMMAND_FAILED`, `PROCESS_COMMAND_TIMEOUT`, `PROCESS_COMMAND_UNAVAILABLE` |
| SRC-01 | `EXPORT_LIMIT_EXCEEDED` (oltre i cap file/byte/tempo), `EXPORT_UNAVAILABLE` |

## Onesta' lato client

Un `status:"error"` su un verbo e' un **check fallito**, con il suo `error.code`
nella nota — **non** un risultato vuoto. Un `status:"ok"` con lista vuota e' un
controllo positivo (nessun listener/processo inatteso osservato nei test
svolti), distinto da un errore.
