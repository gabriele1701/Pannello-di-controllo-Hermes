/** Lettura dei corpi di errore dell'API.
 *
 * Il contratto dichiara le forme
 * ----------------------------------
 *
 * `openapi.json` ha due schemi per questo: `RispostaErrore`, cioe' il corpo
 * intero, e `ErroreApplicativo`, cioe' il contenuto del suo `detail` —
 * `messaggio` obbligatorio, `suggerimento` quando il rifiuto viene da un
 * trigger che lo dichiara nel proprio HINT. I tipi qui sotto vengono da li',
 * non sono scritti a mano, e il 403 non e' piu' fra i casi attesi perche'
 * nessuna rotta lo produce.
 *
 * Perche' le forme si riconoscono ancora a runtime
 * ------------------------------------------------
 *
 * Non e' diffidenza verso il backend: un tipo TypeScript descrive cosa
 * *dovrebbe* arrivare, non valida cosa arriva. Restano tre casi in cui il
 * corpo non ha la forma dichiarata, e nessuno dei tre e' un difetto:
 *
 * 1. **Il 422 e' un `anyOf` di due schemi** — `RispostaErrore` e
 *    `HTTPValidationError` — su alias, rimozione di una rete e consensi. E'
 *    il contratto stesso a dire che le forme sono due, quindi distinguerle
 *    qui e' leggere il contratto, non aggirarlo.
 * 2. **`backend/main.py` risponde `{"detail": {"messaggio": ...}}` sul
 *    fallback SPA** per una rotta `/api` inesistente, con
 *    `include_in_schema=False`: una forma reale che il contratto non
 *    descrive, deliberatamente.
 * 3. **Un 500, o una risposta del proxy**, non hanno nessuna forma
 *    dichiarata: un corpo vuoto o una pagina HTML sono possibili, e un
 *    accesso non protetto solleverebbe mentre si sta gia' gestendo un
 *    errore.
 *
 * I messaggi vanno a schermo interi
 * ---------------------------------
 *
 * Quelli del perimetro nascono nei validator di `backend/schemas.py` e nei
 * trigger: spiegano *perche'* `192.168.205.10/24` e' rifiutato, ed e'
 * l'unica parte utile. Sostituirli con «valore non valido» lascerebbe
 * riscrivere lo stesso errore in un'altra forma.
 *
 * Le tre forme che arrivano:
 *
 *   applicativa   {"detail": {"messaggio": "...", "suggerimento": "..."}}
 *   Pydantic      {"detail": [{"loc": ["body","cidr"], "msg": "...", ...}]}
 *   FastAPI nuda  {"detail": "testo"}
 */

import type { components } from './schema'

/** Il contenuto di `detail` in una risposta di errore applicativa. */
export type ErroreApplicativo = components['schemas']['ErroreApplicativo']

/** Un errore dell'API gia' ridotto a cio' che si mostra. */
export interface Problema {
  /** Codice HTTP. Serve alle pagine per distinguere 404 da 409. */
  stato: number
  /** Frase principale, sempre presente. */
  messaggio: string
  /** L'HINT del database, quando c'e'. Dice cosa fare, non cosa e' successo. */
  suggerimento?: string
  /** Errori di validazione per campo, quando il rifiuto viene da Pydantic. */
  campi: ProblemaCampo[]
}

export interface ProblemaCampo {
  /** Nome del campo, dall'ultimo segmento di `loc`. Vuoto se non deducibile. */
  campo: string
  messaggio: string
}

/** Messaggi di ripiego, per quando il corpo non porta un `messaggio`.
 *
 * Niente 403: dopo la revisione del contratto nessuna rotta lo produce. Le
 * tabelle append-only sono protette da trigger, ma non esiste una rotta che
 * tenti di scriverci, quindi quel rifiuto non puo' arrivare fin qui.
 */
const GENERICI: Record<number, string> = {
  400: 'Richiesta non valida.',
  404: 'Risorsa inesistente.',
  409: 'La richiesta è in conflitto con lo stato attuale.',
  422: 'Il valore inviato non è accettabile.',
  500: 'Errore interno del server.',
}

/** Riconosce `ErroreApplicativo`, o restituisce null se non e' quello.
 *
 * Il controllo e' su `messaggio`, l'unico campo che il contratto dichiara
 * obbligatorio: un `detail` che non lo ha non e' questa forma, qualunque
 * altra cosa contenga.
 */
function comeErroreApplicativo(detail: unknown): ErroreApplicativo | null {
  const o = oggetto(detail)
  const messaggio = testo(o?.['messaggio'])
  if (!messaggio) return null
  const suggerimento = testo(o?.['suggerimento'])
  return suggerimento ? { messaggio, suggerimento } : { messaggio }
}

function oggetto(v: unknown): Record<string, unknown> | null {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
    ? (v as Record<string, unknown>)
    : null
}

function testo(v: unknown): string | undefined {
  return typeof v === 'string' && v.trim() !== '' ? v : undefined
}

/** Ultimo segmento di `loc` utile come nome di campo.
 *
 * `loc` e' tipo `["body", "cidr"]` o `["query", "limite"]`: il primo elemento
 * dice da dove viene il valore, l'ultimo quale campo e'. Un `loc` di un solo
 * elemento (`["body"]`, quando l'intero corpo e' malformato) non nomina
 * nessun campo, e allora e' giusto non inventarne uno.
 */
function nomeCampo(loc: unknown): string {
  if (!Array.isArray(loc) || loc.length < 2) return ''
  const ultimo = loc[loc.length - 1]
  return typeof ultimo === 'string' ? ultimo : ''
}

/** Toglie il prefisso che Pydantic antepone ai messaggi dei validator.
 *
 * Un `ValueError` sollevato in un validator esce come «Value error, » seguito
 * dal testo vero. Quel prefisso e' un dettaglio dell'implementazione del
 * backend, non una parola scritta per chi legge: i messaggi del perimetro
 * cominciano a spiegare dopo di lui.
 *
 * Toglierlo non e' riscrivere il messaggio — il testo resta quello del
 * backend, intero. E' togliere l'involucro.
 */
function senzaPrefissoPydantic(messaggio: string): string {
  const prefissi = ['Value error, ', 'Assertion failed, ']
  for (const prefisso of prefissi) {
    if (messaggio.startsWith(prefisso)) return messaggio.slice(prefisso.length)
  }
  return messaggio
}

function daPydantic(detail: unknown[]): ProblemaCampo[] {
  const campi: ProblemaCampo[] = []
  for (const voce of detail) {
    const o = oggetto(voce)
    const messaggio = testo(o?.['msg'])
    if (messaggio) {
      campi.push({
        campo: nomeCampo(o?.['loc']),
        messaggio: senzaPrefissoPydantic(messaggio),
      })
    }
  }
  return campi
}

/** Riduce un corpo di errore alla forma che le pagine mostrano. */
export function interpretaProblema(stato: number, corpo: unknown): Problema {
  const generico = GENERICI[stato] ?? `La richiesta è fallita (HTTP ${stato}).`
  const detail = oggetto(corpo)?.['detail']

  // Forma applicativa: `RispostaErrore`, il corpo che il contratto dichiara
  // per 401, 404, 409 e per meta' dei 422.
  const applicativo = comeErroreApplicativo(detail)
  if (applicativo) {
    const suggerimento = testo(applicativo.suggerimento)
    return suggerimento
      ? { stato, messaggio: applicativo.messaggio, suggerimento, campi: [] }
      : { stato, messaggio: applicativo.messaggio, campi: [] }
  }

  // Forma Pydantic: un errore per campo.
  if (Array.isArray(detail)) {
    const campi = daPydantic(detail)
    if (campi.length > 0) {
      // La frase principale e' il primo messaggio quando ce n'e' uno solo:
      // ripetere «valore non valido» sopra a un testo che spiega il perche'
      // aggiungerebbe rumore davanti all'unica riga che serve leggere.
      const primo = campi[0]
      return {
        stato,
        messaggio: campi.length === 1 && primo ? primo.messaggio : generico,
        campi,
      }
    }
  }

  // `{"detail": "testo"}`, la forma nuda di FastAPI.
  const nudo = testo(detail)
  return { stato, messaggio: nudo ?? generico, campi: [] }
}

/** Errori di validazione di un campo preciso, per mostrarli accanto a lui. */
export function erroriDi(problema: Problema | null, campo: string): string[] {
  if (!problema) return []
  return problema.campi.filter((c) => c.campo === campo).map((c) => c.messaggio)
}
