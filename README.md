# Pannello di controllo Hermes

Pannello di controllo di **Hermes**, una toolbox di sicurezza multi-agente.

Hermes è composto da due parti. [`hermes-core`](https://github.com/gabriele1701/hermes-core)
è un server MCP che espone strumenti di sicurezza ad agenti LLM, con un *gate*
che decide se ogni invocazione può procedere. Il gate applica una policy;
**questa applicazione è dove quella policy viene decisa, consultata e
conservata.**

| | Questa applicazione | `hermes-core` |
|---|---|---|
| Ruolo | Registro dello stato | Esecuzione e applicazione |
| Gestisce | Tier dei tool, innalzamenti, consensi per scope, perimetro dei bersagli, vista del log | Invocazione dei tool, gate, scrittura del log |

## Gli agenti non devono poter raggiungere questa applicazione

È il vincolo architetturale da cui dipendono tutti gli altri. Questa
applicazione decide cosa gli agenti LLM possono fare: se un agente — o una
*prompt injection* nel suo contesto — ne raggiungesse le API, alzerebbe i
propri permessi, e l'intero modello di sicurezza non proteggerebbe più niente.

Non esiste un modo di garantirlo dentro il codice di un'applicazione web, e
quindi non si finge che ci sia. Quello che si fa è togliere tutto ciò che
serve a un client automatico, perché un'interfaccia che nessun programma può
usare comodamente è un'interfaccia che nessun programma finisce per usare:

- **nessuna API key, nessun token di servizio.** L'unica autenticazione è un
  cookie di sessione ottenuto digitando una password. Un agente non ha una
  password da digitare, e una credenziale di servizio esisterebbe per essere
  usata da un programma;
- **nessun endpoint MCP, nessuna rotta per il consumo automatico;**
- **la porta è pubblicata su `127.0.0.1`**, non su `0.0.0.0`: il pannello non
  è raggiungibile dalla rete, e il server MCP gira altrove;
- **lo schema OpenAPI e la documentazione interattiva esistono solo in
  sviluppo.** Uno schema leggibile da una macchina è esattamente la cosa che
  rende un'API comoda da usare per un programma.

L'unico utente è l'operatore umano, da browser.

---

## Avvio

Serve `docker` con il plugin `compose`. Niente altro: Python, Node e
PostgreSQL stanno nei container.

```bash
git clone https://github.com/gabriele1701/Pannello-di-controllo-Hermes
cd Pannello-di-controllo-Hermes
cp .env.example .env
```

Poi riempire i quattro valori obbligatori in `.env`:

```bash
# password del ruolo proprietario del database
openssl rand -hex 32

# password del ruolo con cui gira l'applicazione (sono due ruoli distinti,
# vedi «Due ruoli di database» più sotto)
openssl rand -hex 32

# chiave di firma del cookie di sessione
openssl rand -hex 32
```

Esadecimale e non base64: queste password finiscono dentro un URL di
connessione, e `openssl rand -base64` produce una `/` nel 40% dei casi — un
carattere che in un URL chiude la parte delle credenziali. L'esadecimale non
ha caratteri speciali e, a parità di byte generati, ha la stessa entropia.

e scegliere la password dell'operatore (`HERMES_ADMIN_PASSWORD`). Infine:

```bash
docker compose up --build
```

L'applicazione risponde su <http://127.0.0.1:8000> e si entra con
`HERMES_ADMIN_USERNAME` / `HERMES_ADMIN_PASSWORD`. Il primo avvio applica le
migrazioni e popola il database con i dati di esempio; i successivi non lo
rifanno.

**Senza `.env` l'avvio fallisce,** e lo fa dicendo quale variabile manca.
Nessun segreto ha un default funzionante nel `compose`: un default che
funziona è un default che resta, e una password di database che resta è una
password nota a chiunque abbia letto il repository.

Per ripartire da zero:

```bash
docker compose down -v && docker compose up --build
```

Il `-v` non è opzionale: il reset passa dalla rimozione del volume, perché le
tabelle degli innalzamenti e del log non ammettono `DELETE` — vedi sotto.

---

## Le quattro decisioni che reggono il progetto

### 1. I due assi del rischio restano separati

Ogni tool porta **due metadati indipendenti**, che non vengono mai fusi in un
unico valore.

L'**asse tecnico** è l'impatto dell'azione sul sistema bersaglio:

| Tier | Significato | Conferma richiesta |
|---|---|---|
| `verde` | Passiva, sola lettura, nessun impatto | Nessuna |
| `giallo` | Attiva non distruttiva su scope già autorizzato | Una tantum per scope |
| `rosso` | Intrusiva o distruttiva | Puntuale, a ogni invocazione |

L'**asse dei dati personali** è un booleano: un tool che indaga persone
fisiche — indirizzi email, nomi utente, violazioni di dati, numeri di
telefono — richiede una conferma dedicata **anche quando il suo tier tecnico
è `verde`**.

Il caso che spiega perché non si possono fondere è `osint.breach-check`, nei
dati di esempio: verifica se un indirizzo email compare in violazioni di dati
note. Tecnicamente è una lettura e non tocca niente, quindi è `verde`. Ma
eseguirlo rende l'operatore titolare del trattamento di un dato personale, e
quella è una conferma che va chiesta per una ragione diversa.

Se i due assi fossero collassati in un solo valore — diciamo portando quel
tool a `giallo` — l'operatore vedrebbe la richiesta di conferma ma non
saprebbe *perché* gli viene chiesta. E il *perché* è l'unica informazione che
gli serve per decidere: è diverso rispondere a «questa azione può rompere
qualcosa» e a «questa azione riguarda una persona».

Per la stessa ragione il tier non è un campo che il tool possa dichiarare
assieme alla propria cadenza di conferma: la cadenza la **deriva** il server
dai due assi. Se il tool potesse dichiararla, potrebbe assegnarsene una più
lassa del proprio rischio.

### 2. Il tier può solo salire, mai scendere

```
tier_effettivo = max(tier_dichiarato, override più alto registrato)
```

con l'ordinamento `verde < giallo < rosso`.

È l'invariante centrale del sistema. **Non è un limite dell'implementazione:
è una scelta, e togliere il declassamento costa qualcosa che si è deciso di
pagare.**

Un declassamento sarebbe un modo di disattivare i controlli di sicurezza. Se
un tool viene portato a `rosso` dopo un incidente, da quel momento richiede
una conferma puntuale a ogni invocazione; se esistesse un modo di riportarlo a
`giallo`, quel modo verrebbe usato — e prima o poi verrebbe usato da qualcosa
di automatico, che è precisamente lo scenario per cui i tier esistono. Un
override amplia ciò che l'operatore autorizza, mai ciò che il sistema può
fare senza di lui.

Il prezzo è reale e va detto: un modello in ciclo, o spinto da una
*prompt injection*, può bloccare la toolbox chiedendo **più** severità, che è
l'unica direzione che nessun controllo impedisce. Si accetta perché è un
attacco alla disponibilità e non all'integrità: il risultato è una toolbox
ferma, non una che esegue azioni rischiose con i controlli allentati. Fra i
due, il primo si recupera in un minuto da chi ha accesso alla macchina.

Conseguenze visibili nel prodotto:

- l'azione «Innalza tier» offre **solo** i tier superiori a quello effettivo;
  i tier inferiori non compaiono come opzioni disabilitate, perché un'opzione
  disabilitata insegna che esiste un modo e che oggi non è attivo;
- un tool già a `rosso` non mostra nessuna azione, non un pulsante spento;
- il motivo dell'innalzamento è obbligatorio e non vuoto. Un innalzamento
  senza motivo è illeggibile a distanza di mesi, che è quando lo si rilegge;
- non esiste nessuna rotta che modifichi o cancelli un override. Un'API di
  rimozione sarebbe un declassamento con un'interfaccia comoda.

### 3. Il vincolo sta nel database, non nel codice

La monotonia del tier e l'append-only sono **vincoli di integrità di
PostgreSQL**: funzioni `plpgsql` e trigger, in
[`migrations/versions/0001_fondamenta.py`](migrations/versions/0001_fondamenta.py).
Non sono controlli applicativi.

La ragione è il perimetro del problema. Se l'invariante vivesse solo nel
codice Python, basterebbe un'altra via d'accesso al database per aggirarlo:
una console `psql`, uno script di manutenzione, un bug in una rotta scritta
l'anno prossimo. **Un'applicazione si aggira, un vincolo di integrità no.**

#### Due ruoli di database, e perché ne servono due

La frase sopra, da sola, sarebbe più forte del vero — e nella prima versione
di questo progetto lo era. In PostgreSQL **il proprietario di una tabella può
disabilitarne i trigger**:

```sql
ALTER TABLE tier_overrides DISABLE TRIGGER ALL;
-- da qui un override a `verde` passa
```

Gli invarianti di questo progetto *sono* trigger. Finché l'applicazione si
connetteva con il ruolo che possiede le tabelle, quel comando era a
disposizione del codice applicativo, e quindi di qualunque suo difetto. «Il
vincolo è nel database» descriveva dove stava *scritto* il vincolo, non chi
poteva *toglierlo*. C'è anche una seconda via, più corta:

```sql
SET session_replication_role = replica;  -- i trigger non scattano più
```

che richiede il superutente.

Da qui la separazione in due ruoli, con due URL distinte:

| | `MIGRATIONS_DATABASE_URL` | `DATABASE_URL` |
|---|---|---|
| Ruolo | proprietario (`POSTGRES_USER`) | `hermes_app` |
| Chi lo usa | `alembic upgrade head` e il seed, all'avvio | l'applicazione in esercizio |
| Possiede le tabelle | sì | **no** |
| Può disabilitare un trigger | sì — è il suo compito cambiare lo schema | **no** |

Che il ruolo delle migrazioni possa cambiare tutto non è un difetto: una
migrazione serve esattamente a questo. Il punto è che il **processo che
risponde alle richieste HTTP** non ci arriva.

Le concessioni di `hermes_app` sono scritte per tabella nella migrazione
`0002`, e quella tabella di concessioni *è* una dichiarazione del dominio:

| Tabella | SELECT | INSERT | UPDATE | DELETE |
|---|---|---|---|---|
| `users` | ✔ | | | |
| `tools` | ✔ | | | |
| `tier_overrides` | ✔ | ✔ | | |
| `audit_events` | ✔ | | | |
| `scope_networks` | ✔ | ✔ | | ✔ |
| `scope_aliases` | ✔ | ✔ | | ✔ |
| `scope_consents` | ✔ | ✔ | solo `revoked_at` | |
| `alembic_version` | | | | |

Tre righe di quella tabella sono affermazioni che prima erano solo convenzioni
del codice:

- **`tools` in sola lettura.** Lo SPEC dice che l'identità di un tool è di
  sola lettura per questa applicazione, perché la registra `hermes-core`.
  Prima lo garantiva l'assenza di una rotta; ora l'assenza del privilegio —
  una garanzia che non dipende da chi scriverà la prossima rotta.
- **`audit_events` senza `INSERT`.** «Nessuna rotta permette di scrivere nel
  log» diventa «nessuna scrittura nel log è possibile da questa connessione»,
  che è un'affermazione diversa e più forte.
- **`scope_consents` con `UPDATE` su una sola colonna.** L'applicazione può
  revocare un consenso e non può cambiargli scope, agente o scadenza: un
  consenso non si riscrive, si revoca.

E `alembic_version` non è raggiungibile: l'applicazione non può mentire su
quale versione dello schema sta girando.

#### Il lock del trigger, e perché ha cambiato forma

Un effetto collaterale che vale la pena raccontare, perché mostra come un
vincolo tiri l'altro. Il trigger di monotonia prendeva `SELECT ... FOR UPDATE`
sulla riga di `tools` per serializzare due innalzamenti concorrenti. Con un
ruolo in sola lettura su `tools` non funziona più: in PostgreSQL **ogni**
clausola di blocco di riga — `FOR UPDATE`, `FOR SHARE`, `FOR KEY SHARE` —
richiede più del privilegio `SELECT`.

Le alternative erano tre: concedere `UPDATE` su `tools`, che butterebbe via la
sola lettura appena guadagnata; rendere la funzione `SECURITY DEFINER`, che
mette un'escalation di privilegi dentro il percorso di applicazione del
vincolo; oppure un **advisory lock di transazione**, che non richiede
privilegi su nessuna tabella.

Si è scelta la terza, e non come ripiego: il lock sulla riga di `tools` era un
*sostituto* della cosa che si voleva davvero serializzare, cioè la catena di
override di un tool. `pg_advisory_xact_lock` la nomina direttamente.

Il codice dell'API non duplica il controllo: tenta l'inserimento e traduce il
rifiuto del database. Due conseguenze, entrambe volute:

1. **Non c'è finestra di concorrenza.** Un `if` prima dell'`INSERT` lascerebbe
   uno spazio fra la lettura del tier corrente e la scrittura: due richieste
   contemporanee potrebbero leggere entrambe lo stesso valore e passare
   entrambe. Il trigger prende un lock sulla riga del tool, quindi la seconda
   richiesta attende e rilegge — ed è verificato da un test con due
   transazioni concorrenti.
2. **Non c'è divergenza.** Con il controllo in due posti, uno dei due prima o
   poi cambia senza l'altro. Qui esiste una sola formulazione
   dell'invariante, e il criterio «rifiutato sia dall'API sia dal database» è
   vero per costruzione invece che per disciplina.

Si verifica a mano, con una console aperta sul database:

```bash
docker compose exec db psql -U hermes -d hermes_panel
```

```sql
-- recon.nmap-sweep è a `rosso` nei dati di esempio
INSERT INTO tier_overrides (tool_id, tier, reason, created_by)
SELECT id, 'giallo', 'provo ad abbassarlo', 'manuale' FROM tools
WHERE tool_id = 'recon.nmap-sweep';
-- ERRORE: il tier puo' solo salire: recon.nmap-sweep ha tier effettivo
--         rosso, un override a giallo non lo innalza

UPDATE tier_overrides SET tier = 'verde';
-- ERRORE: tier_overrides e' append-only: UPDATE non e' consentito

DELETE FROM audit_events;
-- ERRORE: audit_events e' append-only: DELETE non e' consentito

TRUNCATE audit_events;
-- ERRORE: audit_events e' append-only: TRUNCATE non e' consentito
```

Il `TRUNCATE` ha un trigger suo: non passa dai trigger di riga, quindi
senza un trigger di statement «append-only» sarebbe vero solo per le
operazioni che qualcuno si è ricordato di coprire.

E con il ruolo applicativo, che è quello con cui gira il processo che risponde
alle richieste:

```bash
docker compose exec -e PGPASSWORD="$HERMES_APP_DB_PASSWORD" db   psql -U hermes_app -d hermes_panel
```

```sql
ALTER TABLE tier_overrides DISABLE TRIGGER ALL;
-- ERRORE: must be owner of table tier_overrides

SET session_replication_role = 'replica';
-- ERRORE: permission denied to set parameter "session_replication_role"

INSERT INTO audit_events (correlation_id, event_type, outcome)
VALUES (gen_random_uuid(), 'tool_call', 'ok');
-- ERRORE: permission denied for table audit_events
```

Tutte queste verifiche, insieme, sono in uno script che si esegue da solo:

```bash
./.github/scripts/verifica_database.sh
```

Un dettaglio che vale la pena notare: `tier` è un `ENUM` nativo di PostgreSQL,
e in un `ENUM` l'ordine di dichiarazione **è** l'ordinamento del tipo. Quindi
`verde < giallo < rosso` vale in SQL, `max()` e `GREATEST()` funzionano
direttamente sul tier, e l'invariante si scrive come un confronto — senza
colonne di rango parallele da tenere sincronizzate.

### 4. Il log è una vista, non la fonte di verità

La fonte di verità del log d'audit è un **file JSONL append-only con
`chattr +a`** sulla macchina del server MCP. `chattr +a` richiede i privilegi
di root per essere messo o tolto, e impedisce troncamenti e riscritture a
qualunque processo non privilegiato — incluso `hermes-core` stesso, che non
gira da root. La difesa non sta nel formato del file: sta fuori dal processo
che lo scrive.

La tabella `audit_events` di questo pannello è una **copia ricostruibile e
scartabile**. Esiste per poter interrogare, filtrare e correlare — cose che su
un file di testo si fanno male — non per custodire.

La conseguenza è quello che il pannello **non** ha: nessuna rotta di
scrittura, modifica o cancellazione sul log. Solo `GET`. Non «non implementate
ancora»: non devono esistere. Un pannello che potesse scrivere nel log sarebbe
un pannello capace di riscrivere la traccia di ciò che ha autorizzato, e la
traccia è il prodotto di tutto il sistema.

Nota pratica: in questa consegna il log è popolato dai dati di esempio.
L'ingestione del file JSONL reale arriva dopo, e per questo il vocabolario
degli eventi è **quello completo di `hermes-core`** — tutti e dodici i tipi,
`peer_correlation_id` e `authorized_by` compresi — e non un sottoinsieme
semplificato: un modello dati più povero renderebbe l'ingestione una
riscrittura.

Per la stessa ragione `audit_events.tool_id` è testo e non una chiave esterna.
Il log registra anche eventi che si riferiscono a tool **non** registrati:
`tool_registration_rejected` ne è l'esempio, perché registra proprio un tool
che non è stato accettato. Una chiave esterna renderebbe quelle righe
inseribili, cioè renderebbe il log incapace di registrare i rifiuti.

---

## Il perimetro dei bersagli

Una lista di reti autorizzate e di alias dichiarati. Tre regole, tutte
applicate nel database e tutte spiegate dall'interfaccia.

**La forma canonica è obbligatoria.** `192.168.205.10/24` viene rifiutato:

```
'192.168.205.10/24' non e' in forma canonica: ha dei bit a destra della
maschera, quindi non e' l'indirizzo di una rete ma un host dentro una.
Verrebbe interpretato come '192.168.205.0/24', cioe' 256 indirizzi invece
di uno. Dichiarare '192.168.205.0/24' se si intende tutta la rete, oppure
'192.168.205.10/32' se si intende quel solo indirizzo.
```

Il messaggio spiega il *perché* perché è un errore che si commette credendo
di aver dichiarato un host: chi lo scrive pensa di aver autorizzato un
indirizzo e ne ha autorizzati 254. Un messaggio che dicesse solo «valore non
valido» lascerebbe chi lo legge a riscrivere lo stesso errore in un'altra
forma.

**Ogni alias deve cadere dentro una rete dichiarata.** Il vincolo è applicato
in due punti, perché ci sono due modi di violarlo: inserire un alias fuori
perimetro, oppure rimuovere la rete che ne conteneva uno. Coprire solo il
primo lascerebbe il secondo come via d'uscita, ed è la più facile da
imboccare per sbaglio.

**Nessuna risoluzione DNS, da nessuna parte.** Gli alias sono una tabella
dichiarata dall'operatore, non un'interrogazione. Un nome risolto al momento
del controllo può puntare altrove al momento dell'esecuzione, può risolvere a
più indirizzi, e dipende da un servizio che sta fuori dal perimetro che si sta
dichiarando. L'alias *è* la risoluzione.

## I consensi

Un consenso autorizza un agente — o un singolo tool di quell'agente — ad
agire su uno scope, fino a una scadenza.

**La scadenza è obbligatoria,** con un `NOT NULL` nel database: un consenso
che non scade non è un consenso, è un'autorizzazione permanente con un altro
nome.

**La revoca non cancella.** `POST /api/consents/{id}/revoke` scrive
`revoked_at` e la riga resta. Sapere che un consenso c'è stato conta tanto
quanto sapere che non vale più: una `DELETE` cancellerebbe la seconda
informazione insieme alla prima.

Lo stato — attivo, scaduto, revocato — **non è una colonna**: è derivato dalle
date alla lettura. Una colonna di stato andrebbe aggiornata allo scadere, e
nessun processo la aggiornerebbe: un consenso scaduto resterebbe marcato
attivo, che è il modo in cui un controllo decade in silenzio.

---

## Stack e struttura

- **Backend**: Python 3.12, FastAPI, SQLAlchemy 2, Alembic
- **Frontend**: React + Vite + TypeScript, CSS scritto a mano
- **Database**: PostgreSQL 16, in container
- **Orchestrazione**: `docker compose`, due servizi (`app`, `db`)

Il build di Vite è servito da FastAPI come file statici: un container in meno,
nessun reverse proxy, e nessuna configurazione CORS da gestire — che è una
cosa che si sbaglia.

```
backend/
  config.py        configurazione dall'ambiente, nessun default per i segreti
  db.py            motore e sessioni
  models.py        modelli e vocabolari, allineati a hermes-core
  schemas.py       contratti di ingresso e uscita, con i messaggi che spiegano
  security.py      argon2, sessione in cookie firmato
  errors.py        traduzione SQLSTATE -> HTTP
  seed.py          dati di esempio
  main.py          applicazione, montaggio della SPA
  routers/         auth, tools, consents, scope, audit
openapi.json       il contratto fra backend e frontend: si rigenera,
                   non si modifica a mano
requirements.txt   il lock: anche le versioni transitive, da cui
                   installa l'immagine
migrations/        schema, vincoli, trigger, ruoli e concessioni
frontend/          interfaccia
scripts/           strumenti di sviluppo (esportazione del contratto)
.github/
  workflows/ci.yml contratto, suite, build dell'immagine, avvio a freddo
  scripts/         le verifiche, eseguibili anche a mano
tests/             175 test: vincoli in SQL diretto, privilegi dei ruoli,
                   contratti delle API
```

## Il contratto fra backend e frontend

[`openapi.json`](openapi.json) **è il contratto fra backend e interfaccia. Si
rigenera, non si modifica a mano:**

```bash
python3 scripts/esporta_openapi.py
```

Lo script importa l'applicazione e chiama `app.openapi()` — nessun server da
avviare, nessuna connessione al database. Scrive con le chiavi ordinate e
l'indentazione fissa, quindi due rigenerazioni dello stesso codice producono
byte identici e la diff mostra soltanto i cambiamenti veri.

Esiste come file versionato e non solo come schema servito dall'applicazione
perché backend e interfaccia vengono scritti in momenti diversi, e questo
documento è il punto in cui si incontrano. Finché vive solo in memoria del
processo è una convenzione: chi scrive il frontend lo legge una volta e poi se
lo ricorda, e quando il backend cambia una risposta nessuno se ne accorge
finché qualcosa non si rompe nel browser. Versionato, un cambiamento del
contratto compare nella diff di una pull request.

La CI verifica che il file committato corrisponda al codice delle rotte
(`python3 scripts/esporta_openapi.py --check`), e il messaggio di errore
contiene il comando per rigenerarlo.

## Sicurezza dell'applicazione

- **Password con argon2id** (`argon2-cffi`, parametri predefiniti della
  libreria, che sono quelli raccomandati). Argon2 richiede memoria e non solo
  cicli, quindi resiste alla parallelizzazione su GPU: è la proprietà che lo
  distingue da uno SHA iterato, che si calcola a miliardi al secondo su
  hardware comune. Un `CHECK` nel database rifiuta un `password_hash` che non
  inizi per `$argon2`, così una password in chiaro non può finire in quella
  colonna per una svista in uno script.
- **Sessione in cookie `HttpOnly`, `SameSite=Lax`, `Secure` in produzione.**
  `HttpOnly` impedisce a una XSS di leggere la sessione; `SameSite=Lax`
  impedisce al browser di inviarla su una POST che parte da un altro sito, ed
  è la difesa CSRF di questa applicazione.
- **Il login non rivela quali nomi utente esistono**: il messaggio è lo stesso
  nei due casi, e la verifica gira contro un hash di riferimento anche quando
  l'utente non c'è, perché altrimenti il tempo di risposta lo direbbe.
- **La dipendenza di autenticazione è dichiarata sul router, non rotta per
  rotta.** Così il default è «protetta»: una rotta nuova è autenticata perché
  sta lì, non perché chi l'ha scritta si è ricordato del decoratore.
  Dimenticare una riga non apre un buco — e un test verifica che ogni rotta
  sotto `/api` sia nell'elenco di quelle coperte.
- **Validazione Pydantic su ogni rotta, con `extra="forbid"`:** un payload con
  campi non previsti viene rifiutato, non accettato ignorando l'ignoto.
- **Nessun parametro di ordinamento o di ricerca libera.** Sarebbero un modo
  di far arrivare testo del client dentro una clausola SQL. I filtri del log
  sono tipizzati uno per uno, e la paginazione ha un tetto: senza,
  `limite=1000000` sarebbe una richiesta che esaurisce la memoria del server.
- **Due ruoli di database.** L'applicazione in esercizio si connette con
  `hermes_app`, che non possiede le tabelle e quindi non può disabilitarne i
  trigger, non è superutente e quindi non può cambiare
  `session_replication_role`, e non ha `CREATE` sullo schema e quindi non può
  costruirsi scappatoie. Le concessioni sono minime e scritte per tabella.
- **Il container dell'app non gira come root,** ha il filesystem in sola
  lettura, `no-new-privileges` e tutte le capability rimosse. Il codice è di
  root e il processo non può riscrivere i propri file.
- **Il database non pubblica nessuna porta:** è raggiungibile solo dalla rete
  interna del compose.
- **`created_by` e `granted_by` vengono dalla sessione, non dalla richiesta.**
  Se fossero campi del payload, un client potrebbe dichiarare di essere
  qualcun altro nello storico che serve esattamente a sapere chi ha fatto cosa.

---

## Sviluppo

Serve un PostgreSQL 16 raggiungibile.

```bash
# ruolo proprietario: migrazioni e seed
export MIGRATIONS_DATABASE_URL="postgresql+psycopg://hermes:...@localhost:5432/hermes_panel"
export HERMES_APP_DB_PASSWORD="una-password-di-sviluppo"
export APP_SECRET_KEY="$(openssl rand -hex 32)"
export HERMES_ADMIN_PASSWORD="una-password-di-sviluppo"

pip install -e '.[dev]'
alembic upgrade head        # crea anche il ruolo hermes_app
python -m backend.seed

# ruolo applicativo: il server
export DATABASE_URL="postgresql+psycopg://hermes_app:una-password-di-sviluppo@localhost:5432/hermes_panel"
uvicorn backend.main:app --reload
```

Se `MIGRATIONS_DATABASE_URL` non è impostata, migrazioni e seed ricadono su
`DATABASE_URL`. È una comodità per lo sviluppo locale, dove spesso esiste un
solo ruolo — **non** una configurazione valida in esercizio: il `compose`
imposta le due URL distinte e rende obbligatoria la password del ruolo
applicativo, quindi il ripiego non si verifica in un dispiegamento.

L'interfaccia, in un altro terminale:

```bash
cd frontend && npm install && npm run dev
```

Vite serve su `:5173` e inoltra `/api` a uvicorn.

### Dopo aver cambiato una rotta

```bash
python3 scripts/esporta_openapi.py
```

e committare `openapi.json` insieme al cambiamento: è il contratto, e la CI
rifiuta un disallineamento fra il file e il codice.

### Test

```bash
# il ruolo proprietario: la suite crea lo schema e poi punta l'applicazione
# sul ruolo hermes_app da sola
export TEST_DATABASE_URL="postgresql+psycopg://hermes:...@localhost:5432/hermes_panel"
export HERMES_APP_DB_PASSWORD="una-password-di-sviluppo"
pytest
```

I test girano contro un **PostgreSQL vero**, non contro SQLite in memoria, e
non è una preferenza: gli invarianti di questo progetto sono trigger
`plpgsql`, tipi `ENUM` ordinati e tipi `cidr`/`inet`. SQLite non ha nessuna di
queste cose, quindi una suite su SQLite verificherebbe tutto tranne la parte
che conta.

Lo schema viene ricostruito applicando la migrazione, quindi la suite verifica
anche il codice da cui dipende l'avvio a freddo.

`tests/test_db_constraints.py` interroga il database **in SQL diretto**, senza
passare dall'API: è la metà del criterio che chiede che un declassamento sia
rifiutato anche eseguendo la query a mano. Gira con il ruolo proprietario,
quindi prova che i trigger rifiutano anche chi possiede le tabelle.

`tests/test_privilegi_ruolo.py` prova la separazione dei ruoli: che
`hermes_app` non possa disabilitare un trigger, rimuoverlo, sostituirne la
funzione, cambiare `session_replication_role`, scrivere nel log o modificare un
tool — e, come controprova, che le concessioni gli bastino per fare il proprio
lavoro.

La prova più larga però è un'altra: **l'intera suite delle API gira con il
ruolo `hermes_app`**, perché la fixture che prepara lo schema punta
l'applicazione su quel ruolo. Se mancasse una concessione, i test delle API lo
troverebbero.

---

## Integrazione continua

`.github/workflows/ci.yml` gira a ogni push, con quattro lavori:

1. **`contratto`** — `openapi.json` corrisponde al codice delle rotte. Nessun
   database e nessun Docker, quindi è il più veloce a dire che qualcosa non
   torna.
2. **`suite`** — i 175 test su un PostgreSQL 16 di servizio, con
   l'applicazione che gira come `hermes_app`.
3. **`immagine`** — `docker compose build --no-cache`, più la verifica che la
   `compose` sia YAML valido, che l'avvio *fallisca* senza i segreti, e che il
   container non giri come root.
4. **`freddo`** — l'avvio vero dello stack da un `.env` scritto come lo
   scriverebbe una persona seguendo questo README, poi tutte le verifiche
   contro lo stack in piedi.

L'ultimo lavoro è quello che conta di più, perché è il criterio §11 numero uno: *il
primo* criterio di accettazione non si verifica scrivendo codice, si verifica
eseguendolo su una macchina pulita. Le verifiche stanno in due script
eseguibili anche a mano, e non dentro i passi del workflow — un file si prova
in locale prima di spingerlo, un passo di workflow si prova soltanto facendo
girare la CI:

```bash
python3 .github/scripts/verifica_stack.py   --base http://127.0.0.1:8000 --utente operatore --password "$HERMES_ADMIN_PASSWORD"
```

```bash
./.github/scripts/verifica_database.sh
```

Il primo verifica via HTTP i dati di esempio, la copertura dei due assi del
rischio, la divergenza fra tier dichiarato ed effettivo, il log con tutti e
quattro gli esiti, e i criteri §11. Il secondo apre due console sul database —
una per ruolo — e verifica che i trigger rifiutino anche il proprietario, e che
il ruolo applicativo non arrivi nemmeno al trigger.

---

## Fuori dal perimetro di questa consegna

- la connessione reale a `hermes-core`;
- l'ingestione live del file di log JSONL;
- il flusso di conferma (*elicitation* MCP);
- multi-utente, ruoli, organizzazioni.

Il **modello dati** però è quello vero, non una versione semplificata: i
vocabolari sono gli stessi di `hermes-core`
([`mcp_server/contracts.py`](https://github.com/gabriele1701/hermes-core/blob/main/mcp_server/contracts.py)
e [`mcp_server/audit.py`](https://github.com/gabriele1701/hermes-core/blob/main/mcp_server/audit.py)),
valore per valore, così l'integrazione non comporta rimappature.

Due note sulle differenze di nome, per chi confronta i due repository:

- qui la colonna si chiama `declared_tier`, in `hermes-core` il campo è
  `ToolSpec.default_tier`. Lo stesso dato: il pavimento dichiarato
  all'integrazione, che nessun override abbassa;
- `tier_overrides.source` distingue le due origini persistenti di un
  innalzamento che `hermes-core` tiene separate (`OverrideScope`): `config`
  per un `override_tier` scritto nella configurazione versionata, che si vede
  in *review*, e `persistent` per una riga dello store append-only, scritta
  reagendo a un evento.
