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

/** Un elenco vuoto che spiega perche' lo e' e cosa lo riempira'.
 *
 * Un'installazione pulita nasce con il solo operatore: catalogo, log,
 * perimetro e consensi sono vuoti, e una tabella bianca senza spiegazione
 * sembra un guasto. Tre righe, sempre nello stesso ordine: cosa manca,
 * perche', e da dove arrivera'.
 *
 * Sta qui, accanto a `Vuoto`, perche' i due non vanno confusi: `Vuoto` e' per
 * «i filtri non trovano niente», dove non c'e' niente da spiegare; questo e'
 * per «qui non c'e' ancora mai stato niente».
 */
export function VuotoSpiegato({
  titolo,
  children,
  dimostrativo = false,
}: {
  titolo: string
  children: ReactNode
  /** Se i dati di questa schermata arrivano anche dal percorso dimostrativo. */
  dimostrativo?: boolean
}) {
  return (
    <div className="stato stato--vuoto stato--spiegato">
      <p className="stato__titolo">{titolo}</p>
      <p className="stato__perche">{children}</p>
      {dimostrativo && (
        <p className="stato__perche">
          Per vedere il pannello con dati di esempio, su un database ancora vuoto:{' '}
          <code>docker compose exec app python -m backend.seed --dimostrativo</code>. Sono
          dati inventati, e innalzamenti ed eventi d&rsquo;audit non si possono poi
          cancellare: non su un&rsquo;installazione che riceverà dati veri.
        </p>
      )}
    </div>
  )
}
