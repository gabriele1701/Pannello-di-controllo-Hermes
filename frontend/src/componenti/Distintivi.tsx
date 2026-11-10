/** I segni con cui si leggono i due assi del rischio.
 *
 * Stanno in un file solo perche' la regola che conta e' che restino
 * **distinti**: il tier tecnico dice ogni quanto si chiede conferma, i dati
 * personali dicono perche' la si chiede. Fonderli in un unico indicatore
 * — un pallino piu' scuro, un tier «verde+» — perderebbe la ragione, che e'
 * l'informazione da mostrare all'operatore. `osint.breach-check` e' verde e
 * riguarda persone fisiche: un indicatore solo non potrebbe dirlo.
 *
 * Perche' i colori dei due assi non si somigliano: la scala del tier e'
 * verde/giallo/rosso, il badge dei dati personali e' viola. Un asse
 * booleano colorato con i colori di una scala a tre si leggerebbe come un
 * quarto livello della scala.
 */

import type { Tier } from '../api/tipi'

/** Pastiglia con il nome del tier. */
export function PastigliaTier({ tier, tenue = false }: { tier: Tier; tenue?: boolean }) {
  return (
    <span className={`pastiglia pastiglia--${tier}${tenue ? ' pastiglia--tenue' : ''}`}>
      {tier}
    </span>
  )
}

/** I due tier di un tool, e la loro divergenza quando c'e'.
 *
 * Divergenti, si mostrano **entrambi**: il dichiarato tenue, l'effettivo
 * pieno. Mostrare solo l'effettivo nasconderebbe che qualcuno e'
 * intervenuto, che e' l'unica cosa che questa colonna deve far notare.
 */
export function CellaTier({
  dichiarato,
  effettivo,
  innalzato,
}: {
  dichiarato: Tier
  effettivo: Tier
  innalzato: boolean
}) {
  if (!innalzato) return <PastigliaTier tier={effettivo} />

  return (
    <span className="divergenza">
      <PastigliaTier tier={dichiarato} tenue />
      <span className="divergenza__segno" aria-label="innalzato a">
        →
      </span>
      <PastigliaTier tier={effettivo} />
    </span>
  )
}

/** Fascia di classificazione: la barra verticale sul bordo della riga.
 *
 * Due meta': sopra il tier dichiarato, sotto l'effettivo. Quando coincidono
 * si vede una barra sola, e quando non coincidono si vede il salto — prima
 * di aver letto una parola. E' il segnale che un override e' attivo.
 */
export function Fascia({ dichiarato, effettivo }: { dichiarato: Tier; effettivo: Tier }) {
  return (
    <span className="fascia" aria-hidden="true">
      <span className={`fascia__meta fascia__meta--${dichiarato}`} />
      <span className={`fascia__meta fascia__meta--${effettivo}`} />
    </span>
  )
}

/** Il secondo asse. Booleano: o riguarda persone fisiche, o non le riguarda. */
export function BadgeDatiPersonali() {
  return (
    <span className="badge-dati" title="Richiede una conferma dedicata, qualunque sia il tier tecnico">
      Dati personali
    </span>
  )
}
