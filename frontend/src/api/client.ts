/** Chiamate all'API.
 *
 * Origine unica. In sviluppo Vite gira su :5173 e inoltra `/api` a uvicorn;
 * in produzione FastAPI serve il build dalla stessa origine. In entrambi i
 * casi il percorso e' relativo, quindi non c'e' una base da configurare e
 * CORS non entra mai in gioco.
 *
 * `credentials: 'same-origin'` e non `'include'`: il cookie di sessione
 * serve solo a questa origine, e `include` lo manderebbe anche altrove se
 * un giorno qualcuno puntasse una chiamata fuori.
 *
 * Il 401 non e' un errore come gli altri
 * --------------------------------------
 *
 * Il cookie ha una scadenza, quindi una sessione muore mentre la pagina e'
 * aperta: la richiesta successiva torna 401 e la schermata resterebbe la',
 * vuota o a meta'. Qui il 401 diventa un tipo di errore a se'
 * (`ErroreSessione`) e viene notificato a un gestore unico, che la shell
 * registra per riportare al login conservando la rotta corrente.
 *
 * Un gestore registrato e non un `window.location.href = ...`: il secondo
 * ricaricherebbe tutta l'applicazione e perderebbe il punto in cui
 * l'operatore stava lavorando, che e' esattamente cio' che si vuole
 * conservare.
 */

import { interpretaProblema, type Problema } from './errori'

/** Una risposta di errore dell'API, gia' interpretata. */
export class ErroreApi extends Error {
  readonly problema: Problema

  constructor(problema: Problema) {
    super(problema.messaggio)
    this.name = 'ErroreApi'
    this.problema = problema
  }
}

/** 401: sessione assente, scaduta o con firma non valida. */
export class ErroreSessione extends ErroreApi {
  constructor(problema: Problema) {
    super(problema)
    this.name = 'ErroreSessione'
  }
}

/** La richiesta non e' nemmeno partita, o la risposta non e' arrivata. */
export class ErroreRete extends Error {
  constructor(causa: unknown) {
    super(
      'Nessuna risposta dal server. Verificare che l’applicazione sia in esecuzione.',
    )
    this.name = 'ErroreRete'
    this.cause = causa
  }
}

type Gestore = () => void

let gestoreSessioneScaduta: Gestore | null = null

/** Registra chi viene avvisato quando una chiamata torna 401.
 *
 * Restituisce la funzione per disiscriversi, cosi' l'effetto che lo registra
 * puo' pulirlo e non restano gestori di componenti smontati.
 */
export function alLaSessioneScaduta(gestore: Gestore): () => void {
  gestoreSessioneScaduta = gestore
  return () => {
    if (gestoreSessioneScaduta === gestore) gestoreSessioneScaduta = null
  }
}

export interface OpzioniRichiesta {
  metodo?: 'GET' | 'POST' | 'DELETE'
  /** Corpo JSON. Serializzato qui: le pagine passano oggetti, non stringhe. */
  corpo?: unknown
  /** Parametri di query. Le voci `undefined` e `''` non vengono inviate. */
  parametri?: Record<string, string | number | undefined>
  segnale?: AbortSignal
  /**
   * Se `false`, un 401 non avvisa il gestore globale.
   *
   * Serve al login: li' un 401 significa «password sbagliata», non «sessione
   * scaduta», e un rimbalzo alla pagina su cui l'operatore gia' si trova
   * cancellerebbe il messaggio di errore invece di mostrarlo.
   */
  notificaSessioneScaduta?: boolean
}

function conParametri(percorso: string, parametri?: OpzioniRichiesta['parametri']): string {
  if (!parametri) return percorso
  const query = new URLSearchParams()
  for (const [chiave, valore] of Object.entries(parametri)) {
    if (valore === undefined || valore === '') continue
    query.set(chiave, String(valore))
  }
  const stringa = query.toString()
  return stringa ? `${percorso}?${stringa}` : percorso
}

/** Esegue una chiamata e restituisce il corpo decodificato.
 *
 * `T` va indicato dal chiamante prendendolo da `./tipi`, che viene da
 * `openapi.json`. Non c'e' validazione del corpo a runtime: il contratto e'
 * verificato in CI (`scripts/esporta_openapi.py --check`), quindi
 * ricontrollarlo nel browser verificherebbe due volte la stessa cosa.
 */
export async function richiedi<T>(
  percorso: string,
  opzioni: OpzioniRichiesta = {},
): Promise<T> {
  const { metodo = 'GET', corpo, parametri, segnale } = opzioni
  const notifica = opzioni.notificaSessioneScaduta ?? true

  const intestazioni: Record<string, string> = { Accept: 'application/json' }
  if (corpo !== undefined) intestazioni['Content-Type'] = 'application/json'

  let risposta: Response
  try {
    const init: RequestInit = {
      method: metodo,
      headers: intestazioni,
      credentials: 'same-origin',
    }
    if (corpo !== undefined) init.body = JSON.stringify(corpo)
    if (segnale) init.signal = segnale
    risposta = await fetch(conParametri(percorso, parametri), init)
  } catch (causa) {
    // Un fetch interrotto deliberatamente non e' un guasto: lo rilancia
    // tale e quale, cosi' chi ha annullato lo riconosce e non lo mostra.
    if (causa instanceof DOMException && causa.name === 'AbortError') throw causa
    throw new ErroreRete(causa)
  }

  if (!risposta.ok) {
    const problema = interpretaProblema(risposta.status, await corpoJson(risposta))
    if (risposta.status === 401) {
      if (notifica) gestoreSessioneScaduta?.()
      throw new ErroreSessione(problema)
    }
    throw new ErroreApi(problema)
  }

  // 204 e corpo vuoto: `logout` e le due `DELETE` del perimetro non
  // restituiscono niente, e `response.json()` su un corpo vuoto solleva.
  if (risposta.status === 204) return undefined as T
  return (await corpoJson(risposta)) as T
}

/** Corpo JSON, o `null` se la risposta non ne ha uno leggibile.
 *
 * Un errore del server puo' arrivare come pagina HTML o come corpo vuoto:
 * in quel caso `interpretaProblema` ricade sul messaggio generico del codice
 * HTTP, che e' sempre meglio di un'eccezione di parsing.
 */
async function corpoJson(risposta: Response): Promise<unknown> {
  try {
    return await risposta.json()
  } catch {
    return null
  }
}
