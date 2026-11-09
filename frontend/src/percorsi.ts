/** Le rotte dell'interfaccia, in un posto solo.
 *
 * Scritte come costanti e non come stringhe sparse: una rotta rinominata in
 * un punto e dimenticata in un altro produce un link che porta alla pagina
 * «non trovata», e nessuno se ne accorge finche' non ci clicca sopra.
 */

export const ROTTE = {
  accesso: '/accesso',
  catalogo: '/',
  tool: (toolId: string) => `/tool/${encodeURIComponent(toolId)}`,
  perimetro: '/perimetro',
  consensi: '/consensi',
  log: '/log',
  catena: (correlationId: string) => `/log/${encodeURIComponent(correlationId)}`,
} as const

/** Le voci della barra di navigazione, nell'ordine in cui compaiono. */
export const NAVIGAZIONE = [
  { a: ROTTE.catalogo, etichetta: 'Catalogo tool', esatta: true },
  { a: ROTTE.perimetro, etichetta: 'Perimetro', esatta: false },
  { a: ROTTE.consensi, etichetta: 'Consensi', esatta: false },
  { a: ROTTE.log, etichetta: 'Log', esatta: false },
] as const

/** Convalida una destinazione interna presa da uno stato di navigazione.
 *
 * Dopo il login si torna alla pagina da cui si era stati rimbalzati, e quella
 * destinazione arriva da `location.state`. E' un valore che non abbiamo
 * scritto noi al momento in cui lo leggiamo, quindi va trattato come tale:
 * passarlo a `navigate()` cosi' com'e' sarebbe un open redirect, cioe' un
 * modo di far atterrare l'operatore su un sito altrui subito dopo che ha
 * digitato la password — il momento in cui una pagina di login falsa funziona
 * meglio.
 *
 * Passano solo i percorsi assoluti di questa origine. `//altro.example` e
 * `/\altro.example` sono scartati perche' il browser li legge come host, non
 * come percorsi: sono la forma con cui il controllo «inizia per /» si aggira.
 */
export function percorsoInterno(valore: unknown): string | null {
  if (typeof valore !== 'string' || valore === '') return null
  if (!valore.startsWith('/')) return null
  if (valore.startsWith('//') || valore.startsWith('/\\')) return null
  return valore
}
