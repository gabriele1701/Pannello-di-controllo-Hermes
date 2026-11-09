/** Stato della sessione dell'operatore.
 *
 * Un solo utente umano, nessuna API key: il backend lo dichiara e
 * l'interfaccia non ha ruoli, permessi o profili da gestire. Qui si sa solo
 * se c'e' una sessione, di chi, e cosa fare quando scade.
 *
 * Tre fasi, e la prima non e' «fuori»
 * -----------------------------------
 *
 * All'avvio il cookie c'e' o non c'e', e non lo si sa prima di aver chiesto
 * a `/api/auth/me`. Trattare quell'istante come «non autenticato» farebbe
 * comparire la pagina di login per una frazione di secondo a ogni
 * ricaricamento, anche a sessione valida. `verifica` e' quella frazione, resa
 * esplicita.
 */

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react'

import { alLaSessioneScaduta, richiedi } from '../api/client'
import type { Credenziali, Operatore } from '../api/tipi'

export type Sessione =
  | { fase: 'verifica' }
  | { fase: 'dentro'; operatore: Operatore }
  | { fase: 'fuori' }

interface Contesto {
  sessione: Sessione
  /** Autentica. Rilancia l'errore: la pagina di login lo mostra. */
  entra: (credenziali: Credenziali) => Promise<void>
  esci: () => Promise<void>
}

const ContestoSessione = createContext<Contesto | null>(null)

export function FornitoreSessione({ children }: { children: ReactNode }) {
  const [sessione, setSessione] = useState<Sessione>({ fase: 'verifica' })

  // Chi c'e', se c'e' qualcuno. `notificaSessioneScaduta: false` perche' un
  // 401 qui e' la risposta normale a «non sono autenticato», non la scadenza
  // di una sessione che era aperta.
  useEffect(() => {
    const controllo = new AbortController()
    richiedi<Operatore>('/api/auth/me', {
      segnale: controllo.signal,
      notificaSessioneScaduta: false,
    })
      .then((operatore) => setSessione({ fase: 'dentro', operatore }))
      .catch((errore: unknown) => {
        if (errore instanceof DOMException && errore.name === 'AbortError') return
        setSessione({ fase: 'fuori' })
      })
    return () => controllo.abort()
  }, [])

  // Il 401 che arriva da una chiamata qualsiasi mentre si lavora: la sessione
  // e' morta sotto i piedi. Qui si registra una volta sola, e il rimbalzo
  // alla pagina di accesso lo fa `RichiedeSessione` perche' la fase cambia.
  useEffect(() => alLaSessioneScaduta(() => setSessione({ fase: 'fuori' })), [])

  const entra = useCallback(async (credenziali: Credenziali) => {
    const operatore = await richiedi<Operatore>('/api/auth/login', {
      metodo: 'POST',
      corpo: credenziali,
      // Un 401 qui significa «credenziali sbagliate»: va mostrato sotto il
      // modulo, non trattato come una sessione scaduta.
      notificaSessioneScaduta: false,
    })
    setSessione({ fase: 'dentro', operatore })
  }, [])

  const esci = useCallback(async () => {
    try {
      await richiedi<void>('/api/auth/logout', { metodo: 'POST' })
    } catch {
      // Deliberatamente ingoiato. Il logout non richiede autenticazione e
      // deve riuscire comunque: lasciare l'operatore «dentro» perche' il
      // server non ha risposto sarebbe il peggiore dei due esiti, e il
      // cookie scade da se'.
    }
    setSessione({ fase: 'fuori' })
  }, [])

  const valore = useMemo<Contesto>(
    () => ({ sessione, entra, esci }),
    [sessione, entra, esci],
  )

  return <ContestoSessione.Provider value={valore}>{children}</ContestoSessione.Provider>
}

export function useSessione(): Contesto {
  const contesto = useContext(ContestoSessione)
  if (!contesto) {
    throw new Error('useSessione richiede <FornitoreSessione> piu’ in alto nell’albero.')
  }
  return contesto
}
