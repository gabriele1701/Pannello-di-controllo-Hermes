/** Lettura dei corpi di errore dell'API.
 *
 * DEBITO NOTO, dichiarato invece che nascosto
 * -------------------------------------------
 *
 * `openapi.json` tipizza le risposte di successo e il 422 di Pydantic
 * (`HTTPValidationError`), ma **non** le risposte di errore applicative:
 * 401, 403, 404 e i 409 che `backend/errors.py` produce traducendo gli
 * SQLSTATE dei trigger restituiscono `{"detail": {"messaggio", "suggerimento"}}`
 * senza che quella forma compaia in nessuna `responses` del contratto.
 *
 * Qui dunque il generatore non aiuta, e questo e' l'unico punto
 * dell'interfaccia che sa qualcosa che `openapi.json` non dice. Per non
 * fingere che sia tipizzato, il corpo si legge in modo difensivo: si
 * riconosce la forma a runtime e si ricade su un messaggio generico quando
 * non e' nessuna delle due. Nessun cast, nessuna interfaccia scritta a mano
 * spacciata per contratto.
 *
 * Il modo di chiuderlo e' nel backend, non qui: un modello `ErroreApplicativo`
 * dichiarato nelle `responses` delle rotte che lo producono, e
 * `scripts/esporta_openapi.py` rigenerato. Finche' non c'e', vale questo file.
 *
 * Le due forme
 * ------------
 *
 *   applicativa   {"detail": {"messaggio": "...", "suggerimento": "..."}}
 *   Pydantic      {"detail": [{"loc": ["body","cidr"], "msg": "...", ...}]}
 *   FastAPI nuda  {"detail": "testo"}
 *
 * La distinzione conta: i messaggi che spiegano *perche'* `192.168.205.10/24`
 * viene rifiutato nascono nei validator di `backend/schemas.py`, quindi
 * arrivano nella forma Pydantic, mentre quelli dei trigger del perimetro
 * arrivano nella forma applicativa con il `suggerimento`. Entrambi vanno a
 * schermo interi: sono scritti per essere letti dall'operatore, e
 * sostituirli con «valore non valido» butterebbe via l'unica parte utile.
 */

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

const GENERICI: Record<number, string> = {
  400: 'Richiesta non valida.',
  403: 'Operazione non permessa.',
  404: 'Risorsa inesistente.',
  409: 'La richiesta è in conflitto con lo stato attuale.',
  422: 'Il valore inviato non è accettabile.',
  500: 'Errore interno del server.',
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

  // Forma applicativa: l'oggetto dei trigger e delle HTTPException del backend.
  const applicativo = oggetto(detail)
  const messaggio = testo(applicativo?.['messaggio'])
  if (messaggio) {
    const suggerimento = testo(applicativo?.['suggerimento'])
    return suggerimento
      ? { stato, messaggio, suggerimento, campi: [] }
      : { stato, messaggio, campi: [] }
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
