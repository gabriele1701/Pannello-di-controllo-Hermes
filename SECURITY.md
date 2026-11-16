# Politica di sicurezza

Questo file dice **come segnalare una vulnerabilità** e cosa aspettarsi dopo.
Il modello di minaccia — da cosa il pannello si difende e da cosa no — non
sta qui: è nel [README](README.md), alle sezioni *Gli agenti non devono poter
raggiungere questa applicazione* e *Sicurezza dell'applicazione*.

## Cos'è questo progetto

Il pannello di controllo di Hermes è l'applicazione in cui si decide cosa gli
agenti LLM di [`hermes-core`](https://github.com/gabriele1701/hermes-core)
possono fare: tier dei tool, innalzamenti, consensi, perimetro dei bersagli.

È un progetto didattico, sviluppato da una persona sola. Non c'è un'azienda
dietro, non c'è un reperibile, non c'è un contratto di servizio. Le righe che
seguono dicono cosa aspettarsi davvero: una politica che promette più di
quanto può mantenere è peggio di nessuna politica.

## Versioni supportate

Solo `main`. Non esistono rami di manutenzione né rilasci precedenti da
correggere.

## Come segnalare

**Non aprire una issue pubblica** per una vulnerabilità: una issue è leggibile
da chiunque prima che esista una correzione.

Il canale è uno solo, la **segnalazione privata di GitHub**: nella scheda
*Security* di questo repository, *Report a vulnerability*. Resta accanto al
codice, non espone nessun indirizzo, e la discussione è visibile solo a chi
segnala e a chi mantiene il progetto.

Se quel pulsante non compare, la segnalazione privata non è attiva su questo
repository. In quel caso apri una issue che dica **soltanto** che hai una
segnalazione di sicurezza da fare, senza nessun dettaglio: verrà aperto il
canale privato e la issue chiusa.

### Cosa è utile includere

Più di tutto, **come riprodurlo**. Una vulnerabilità descritta e non
riproducibile costa più tempo a chi la riceve che a chi la segnala.

- il commit su cui l'hai vista;
- i passi per riprodurla, o un proof-of-concept;
- cosa ottiene chi la sfrutta — in particolare se permette di **abbassare un
  tier**, di **modificare o cancellare** una riga degli innalzamenti o del
  log d'audit, o di raggiungere le API **senza una sessione**: sono le tre
  cose che il progetto esiste per impedire;
- la configurazione rilevante, **senza segreti**. Il contenuto di `.env` non
  serve mai.

### Cosa aspettarsi

- **Presa in carico entro 7 giorni.** Se dopo una settimana non hai ricevuto
  risposta, insisti sulla stessa segnalazione: è più probabile una notifica
  persa che un silenzio voluto.
- **Correzione**: dipende dalla gravità e dal tempo disponibile. Riceverai
  una risposta onesta su cosa si intende fare e quando, anche quando la
  risposta è «non adesso».
- **Divulgazione concordata.** Si chiede un tempo ragionevole per correggere
  prima della pubblicazione, e il credito è tuo se lo vuoi.

## Cosa non è una vulnerabilità di questo progetto

Per non far perdere tempo a chi segnala:

- **Il pannello raggiungibile dalla rete** perché qualcuno ha cambiato la
  porta pubblicata da `127.0.0.1` a `0.0.0.0`. È una configurazione che il
  progetto sconsiglia esplicitamente, non un difetto del codice.
- **I dati di esempio del seed.** Sono inventati: i tool, gli indirizzi e
  gli eventi che contengono non descrivono nessun sistema reale.
- **Ciò che il README elenca come fuori dal perimetro della consegna**: sono
  limiti dichiarati, non scoperte. Se però trovi un modo di *sfruttarne* uno,
  quello sì è una segnalazione.

Un difetto in `hermes-core` — il gate, il wrapper dei tool, il log d'audit
sul server — va segnalato in quel repository, che ha la propria politica.
