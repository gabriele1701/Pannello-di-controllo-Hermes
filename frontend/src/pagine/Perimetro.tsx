/** Perimetro dei bersagli: reti autorizzate e alias dichiarati.
 *
 * E' la schermata dove due criteri di accettazione diventano visibili, e
 * dipendono entrambi da una cosa sola: **il messaggio del backend arriva a
 * schermo intero**. `192.168.205.10/24` non viene rifiutato per pedanteria —
 * verrebbe letto come l'intera `/24`, cioe' 256 indirizzi invece di uno — e
 * chi scrive quella riga crede di aver autorizzato un host. Un'interfaccia
 * che rispondesse «valore non valido» lascerebbe riscrivere lo stesso errore
 * in un'altra forma.
 *
 * Quei testi nascono in due posti diversi e arrivano in due forme diverse:
 * dai validator Pydantic, per campo, e dai trigger del database, come
 * messaggio piu' suggerimento. `api/errori.ts` le riduce entrambe, e qui si
 * mostrano senza riformularle.
 *
 * Quello che questa pagina NON fa: calcolare dentro quale rete cade un alias.
 * Sarebbe comodo da mostrare in tabella, e sarebbe una seconda
 * implementazione della regola di appartenenza — con IPv6 e maschere non
 * banali, una seconda implementazione che diverge. Il vincolo vive nel
 * database; qui si dice che esiste, non lo si ricalcola.
 */

import { useCallback, useEffect, useState, type FormEvent } from 'react'

import { ErroreApi, richiedi } from '../api/client'
import type { Problema } from '../api/errori'
import { erroriDi } from '../api/errori'
import type { Alias, Rete } from '../api/tipi'
import { Caricamento, Errore, Vuoto } from '../componenti/Stati'
import { useRisorsa } from '../hook/useRisorsa'

export function Perimetro() {
  const caricaReti = useCallback(
    (segnale: AbortSignal) => richiedi<Rete[]>('/api/scope/networks', { segnale }),
    [],
  )
  const caricaAlias = useCallback(
    (segnale: AbortSignal) => richiedi<Alias[]>('/api/scope/aliases', { segnale }),
    [],
  )
  const reti = useRisorsa(caricaReti)
  const alias = useRisorsa(caricaAlias)
  const [versione, setVersione] = useState(0)

  // Le due risorse si ricaricano insieme: rimuovere una rete puo' essere
  // rifiutato per via degli alias, e aggiungerne una puo' rendere
  // dichiarabile un alias che prima era fuori perimetro.
  function ricaricaTutto() {
    reti.ricarica()
    alias.ricarica()
    // Alza la versione, che azzera i rifiuti rimasti sulle righe. Un
    // messaggio di rifiuto descrive lo stato di un istante: «rimuovere
    // questa rete lascerebbe fuori lab-kali e lab-web» smette di essere
    // vero appena quegli alias vengono rimossi, e un testo falso che resta
    // a schermo e' peggio di nessun testo.
    setVersione((n) => n + 1)
  }

  return (
    <section className="perimetro">
      <h1 className="pagina__titolo">Perimetro dei bersagli</h1>
      <p className="riepilogo">
        Le reti su cui gli agenti sono autorizzati ad agire, e gli alias dichiarati
        dall&rsquo;operatore. Nessuna risoluzione DNS: un nome risolto al momento del
        controllo può puntare altrove al momento dell&rsquo;esecuzione.
      </p>

      <SezioneReti risorsa={reti} dopoModifica={ricaricaTutto} versione={versione} />
      <SezioneAlias risorsa={alias} dopoModifica={ricaricaTutto} versione={versione} />
    </section>
  )
}

/* ------------------------------------------------------------------ */
/* Reti                                                                */
/* ------------------------------------------------------------------ */

function SezioneReti({
  risorsa,
  dopoModifica,
  versione,
}: {
  risorsa: ReturnType<typeof useRisorsa<Rete[]>>
  dopoModifica: () => void
  versione: number
}) {
  const [cidr, setCidr] = useState('')
  const [etichetta, setEtichetta] = useState('')
  const [problema, setProblema] = useState<Problema | null>(null)
  const [invio, setInvio] = useState(false)

  async function aggiungi(evento: FormEvent) {
    evento.preventDefault()
    setInvio(true)
    setProblema(null)
    try {
      await richiedi<Rete>('/api/scope/networks', {
        metodo: 'POST',
        corpo: { cidr, label: etichetta },
      })
      setCidr('')
      setEtichetta('')
      dopoModifica()
    } catch (errore: unknown) {
      setProblema(problemaDi(errore, 'Impossibile dichiarare la rete.'))
    } finally {
      setInvio(false)
    }
  }

  return (
    <article className="riquadro">
      <h2 className="sezione__titolo">
        Reti autorizzate{' '}
        {risorsa.dati && <span className="sezione__conteggio">{risorsa.dati.length}</span>}
      </h2>
      <p className="sezione__nota">
        Solo in forma canonica, cioè l&rsquo;indirizzo di rete. Un host con la maschera
        di una rete verrebbe letto come la rete intera: un perimetro più largo di
        quello che chi scrive crede di dichiarare.
      </p>

      {risorsa.caricamento && <Caricamento cosa="delle reti" />}
      {risorsa.problema && <Errore problema={risorsa.problema} riprova={risorsa.ricarica} />}

      {risorsa.dati &&
        (risorsa.dati.length === 0 ? (
          <Vuoto>
            Nessuna rete dichiarata. Finché il perimetro è vuoto, nessun alias può
            essere dichiarato.
          </Vuoto>
        ) : (
          <table className="tabella">
            <thead>
              <tr>
                <th scope="col">Rete</th>
                <th scope="col">Etichetta</th>
                <th scope="col" className="tabella__azioni">
                  <span className="solo-lettori">Azioni</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {risorsa.dati.map((rete) => (
                <RigaRimovibile
                  key={rete.id}
                  percorso={`/api/scope/networks/${rete.id}`}
                  nome={rete.cidr}
                  dopoModifica={dopoModifica}
                  versione={versione}
                >
                  <td className="mono">{rete.cidr}</td>
                  <td className="tabella__tenue">{rete.label}</td>
                </RigaRimovibile>
              ))}
            </tbody>
          </table>
        ))}

      <form className="modulo-inline" onSubmit={(e) => void aggiungi(e)}>
        <label className="campo campo--inline">
          <span className="campo__etichetta">Rete in CIDR</span>
          <input
            className="campo__ingresso mono"
            name="cidr"
            required
            placeholder="192.168.205.0/24"
            value={cidr}
            onChange={(e) => setCidr(e.target.value)}
            aria-invalid={erroriDi(problema, 'cidr').length > 0}
          />
        </label>

        <label className="campo campo--inline">
          <span className="campo__etichetta">Etichetta</span>
          <input
            className="campo__ingresso"
            name="label"
            required
            placeholder="Laboratorio"
            value={etichetta}
            onChange={(e) => setEtichetta(e.target.value)}
          />
        </label>

        <button type="submit" className="bottone" disabled={invio}>
          {invio ? 'Verifica…' : 'Dichiara la rete'}
        </button>
      </form>

      {problema && <Errore problema={problema} />}
    </article>
  )
}

/* ------------------------------------------------------------------ */
/* Alias                                                               */
/* ------------------------------------------------------------------ */

function SezioneAlias({
  risorsa,
  dopoModifica,
  versione,
}: {
  risorsa: ReturnType<typeof useRisorsa<Alias[]>>
  dopoModifica: () => void
  versione: number
}) {
  const [nome, setNome] = useState('')
  const [indirizzo, setIndirizzo] = useState('')
  const [problema, setProblema] = useState<Problema | null>(null)
  const [invio, setInvio] = useState(false)

  async function aggiungi(evento: FormEvent) {
    evento.preventDefault()
    setInvio(true)
    setProblema(null)
    try {
      await richiedi<Alias>('/api/scope/aliases', {
        metodo: 'POST',
        corpo: { name: nome, address: indirizzo },
      })
      setNome('')
      setIndirizzo('')
      dopoModifica()
    } catch (errore: unknown) {
      setProblema(problemaDi(errore, "Impossibile dichiarare l'alias."))
    } finally {
      setInvio(false)
    }
  }

  return (
    <article className="riquadro">
      <h2 className="sezione__titolo">
        Alias dichiarati{' '}
        {risorsa.dati && <span className="sezione__conteggio">{risorsa.dati.length}</span>}
      </h2>
      <p className="sezione__nota">
        Ogni alias deve cadere dentro una delle reti qui sopra: lo impone un vincolo
        del database, non questa pagina. Un alias è una tabella dichiarata
        dall&rsquo;operatore, non un&rsquo;interrogazione DNS.
      </p>

      {risorsa.caricamento && <Caricamento cosa="degli alias" />}
      {risorsa.problema && <Errore problema={risorsa.problema} riprova={risorsa.ricarica} />}

      {risorsa.dati &&
        (risorsa.dati.length === 0 ? (
          <Vuoto>Nessun alias dichiarato.</Vuoto>
        ) : (
          <table className="tabella">
            <thead>
              <tr>
                <th scope="col">Nome</th>
                <th scope="col">Indirizzo</th>
                <th scope="col" className="tabella__azioni">
                  <span className="solo-lettori">Azioni</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {risorsa.dati.map((alias) => (
                <RigaRimovibile
                  key={alias.id}
                  percorso={`/api/scope/aliases/${alias.id}`}
                  nome={alias.name}
                  dopoModifica={dopoModifica}
                  versione={versione}
                >
                  <td className="mono">{alias.name}</td>
                  <td className="mono tabella__tenue">{alias.address}</td>
                </RigaRimovibile>
              ))}
            </tbody>
          </table>
        ))}

      <form className="modulo-inline" onSubmit={(e) => void aggiungi(e)}>
        <label className="campo campo--inline">
          <span className="campo__etichetta">Nome</span>
          <input
            className="campo__ingresso mono"
            name="name"
            required
            placeholder="lab-web"
            value={nome}
            onChange={(e) => setNome(e.target.value)}
            aria-invalid={erroriDi(problema, 'name').length > 0}
          />
          {/* Il messaggio del backend per questo campo è l'espressione
              regolare nuda, che è il solo caso in cui il testo non è scritto
              per chi legge. Questo aiuto non lo sostituisce: lo affianca. */}
          <span className="campo__aiuto">minuscole, cifre, punti e trattini</span>
        </label>

        <label className="campo campo--inline">
          <span className="campo__etichetta">Indirizzo</span>
          <input
            className="campo__ingresso mono"
            name="address"
            required
            placeholder="192.168.205.20"
            value={indirizzo}
            onChange={(e) => setIndirizzo(e.target.value)}
            aria-invalid={erroriDi(problema, 'address').length > 0}
          />
          <span className="campo__aiuto">un solo indirizzo, senza maschera</span>
        </label>

        <button type="submit" className="bottone" disabled={invio}>
          {invio ? 'Verifica…' : "Dichiara l'alias"}
        </button>
      </form>

      {problema && <Errore problema={problema} />}
    </article>
  )
}

/* ------------------------------------------------------------------ */
/* Rimozione                                                           */
/* ------------------------------------------------------------------ */

/** Riga con la rimozione in due tempi.
 *
 * Due tempi e non un dialogo: togliere una riga dal perimetro si annulla
 * ridichiarandola, quindi non merita il peso di una finestra modale — che e'
 * riservata all'innalzamento del tier, che invece non si annulla.
 *
 * Il rifiuto viene mostrato sotto la riga, non in cima alla pagina: quando il
 * database dice che rimuovere questa rete lascerebbe degli alias fuori
 * perimetro, il messaggio deve stare accanto alla rete che lo ha provocato.
 */
function RigaRimovibile({
  percorso,
  nome,
  dopoModifica,
  versione,
  children,
}: {
  percorso: string
  nome: string
  dopoModifica: () => void
  versione: number
  children: React.ReactNode
}) {
  const [conferma, setConferma] = useState(false)
  const [problema, setProblema] = useState<Problema | null>(null)
  const [invio, setInvio] = useState(false)

  // React riusa questo componente fra una ricarica e l'altra, perche' la
  // chiave e' l'id della riga. Senza questo, un rifiuto letto una volta
  // resterebbe a schermo mentre i dati che lo rendevano vero cambiano.
  useEffect(() => setProblema(null), [versione])

  async function rimuovi() {
    setInvio(true)
    setProblema(null)
    try {
      await richiedi<void>(percorso, { metodo: 'DELETE' })
      setConferma(false)
      dopoModifica()
    } catch (errore: unknown) {
      setProblema(problemaDi(errore, 'Rimozione non riuscita.'))
      setConferma(false)
    } finally {
      setInvio(false)
    }
  }

  return (
    <>
      <tr>
        {children}
        <td className="tabella__azioni">
          {conferma ? (
            <span className="conferma">
              <button
                type="button"
                className="bottone bottone--pericolo"
                onClick={() => void rimuovi()}
                disabled={invio}
              >
                {invio ? 'Rimozione…' : `Rimuovi ${nome}`}
              </button>
              <button
                type="button"
                className="bottone bottone--tenue"
                onClick={() => setConferma(false)}
                disabled={invio}
              >
                Annulla
              </button>
            </span>
          ) : (
            <button
              type="button"
              className="bottone bottone--tenue"
              onClick={() => {
                setProblema(null)
                setConferma(true)
              }}
            >
              Rimuovi
            </button>
          )}
        </td>
      </tr>
      {problema && (
        <tr className="riga-errore">
          <td colSpan={3}>
            <Errore problema={problema} />
          </td>
        </tr>
      )}
    </>
  )
}

function problemaDi(errore: unknown, ripiego: string): Problema {
  if (errore instanceof ErroreApi) return errore.problema
  return {
    stato: 0,
    messaggio: errore instanceof Error ? errore.message : ripiego,
    campi: [],
  }
}
