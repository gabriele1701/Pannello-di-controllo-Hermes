/** I tre stati che ogni schermata deve saper mostrare.
 *
 * Stanno qui e non dentro le pagine perche' siano gli stessi ovunque: un
 * errore che in una schermata e' un riquadro rosso e in un'altra una riga
 * grigia insegna a non fidarsi di nessuna delle due.
 */

import type { ReactNode } from 'react'

import type { Problema } from '../api/errori'

export function Caricamento({ cosa }: { cosa: string }) {
  return (
    <div className="stato stato--attesa" role="status" aria-live="polite">
      <span className="stato__indicatore" aria-hidden="true" />
      <span>Caricamento {cosa}…</span>
    </div>
  )
}

/** Un errore dell'API, con il testo che il backend ha scritto.
 *
 * `messaggio` e `suggerimento` vanno a schermo interi. Quelli del perimetro
 * sono scritti dai validator e dai trigger per essere letti dall'operatore:
 * spiegano *perche'* un valore e' rifiutato, ed e' l'unica parte che serve.
 */
export function Errore({
  problema,
  riprova,
}: {
  problema: Problema
  riprova?: () => void
}) {
  const altri = problema.campi.filter((c) => c.messaggio !== problema.messaggio)

  return (
    <div className="stato stato--errore" role="alert">
      <p className="stato__titolo">{problema.messaggio}</p>

      {problema.suggerimento && (
        <p className="stato__suggerimento">
          <span className="stato__etichetta">Suggerimento</span>
          {problema.suggerimento}
        </p>
      )}

      {altri.length > 0 && (
        <ul className="stato__campi">
          {altri.map((c, indice) => (
            <li key={`${c.campo}-${indice}`}>
              {c.campo && <code>{c.campo}</code>} {c.messaggio}
            </li>
          ))}
        </ul>
      )}

      {riprova && (
        <button type="button" className="bottone bottone--tenue" onClick={riprova}>
          Riprova
        </button>
      )}
    </div>
  )
}

/** Nessun dato, ma nessun guasto: va detto, non lasciato indovinare. */
export function Vuoto({ children }: { children: ReactNode }) {
  return <p className="stato stato--vuoto">{children}</p>
}
