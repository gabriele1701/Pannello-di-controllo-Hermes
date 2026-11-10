/** Dialogo per innalzare il tier di un tool.
 *
 * Perche' un dialogo e non un modulo in fondo alla pagina: l'innalzamento
 * **non e' reversibile**. Il tier non scende mai e la tabella degli override
 * non ammette UPDATE ne' DELETE — e' un trigger del database, non una scelta
 * dell'interfaccia. Un'azione che non si annulla merita un gesto deliberato e
 * un riepilogo che nomina il tool, i due tier e cosa cambia.
 *
 * `<dialog>` nativo e non un overlay fatto a mano: porta con se' il
 * confinamento del fuoco da tastiera, la chiusura con Esc e l'inerzia del
 * resto della pagina. Riscriverle sarebbe tre volte il codice e una volta
 * peggio.
 *
 * I tier offerti sono **solo** `tier_disponibili`, che il backend calcola. Non
 * c'e' un elenco completo con le voci basse disabilitate: un'opzione
 * disabilitata insegna che esiste un modo e che oggi non e' attivo, mentre il
 * declassamento non e' disattivato, non esiste. Quando l'array e' vuoto —
 * tool gia' a `rosso` — questo dialogo non viene nemmeno costruito.
 */

import { useEffect, useRef, useState, type FormEvent } from 'react'

import { ErroreApi, richiedi } from '../api/client'
import type { Problema } from '../api/errori'
import type { Override, Tier } from '../api/tipi'
import { PastigliaTier } from './Distintivi'
import { Errore } from './Stati'

/** Cosa comanda ciascun tier, in termini di conferme richieste. */
const CONFERMA_RICHIESTA: Record<Tier, string> = {
  verde: 'nessuna conferma',
  giallo: 'una conferma una tantum per ogni scope',
  rosso: 'una conferma puntuale a ogni invocazione',
}

export function DialogoInnalzamento({
  toolId,
  effettivo,
  disponibili,
  aperto,
  chiudi,
  fatto,
}: {
  toolId: string
  effettivo: Tier
  disponibili: Tier[]
  aperto: boolean
  chiudi: () => void
  fatto: (override: Override) => void
}) {
  const riferimento = useRef<HTMLDialogElement>(null)
  const primo = disponibili[0]
  const [tier, setTier] = useState<Tier | undefined>(primo)
  const [motivo, setMotivo] = useState('')
  const [problema, setProblema] = useState<Problema | null>(null)
  const [invio, setInvio] = useState(false)

  // `showModal()` e non l'attributo `open`: solo il primo rende il dialogo
  // davvero modale, con il fuoco confinato e il resto della pagina inerte.
  useEffect(() => {
    const elemento = riferimento.current
    if (!elemento) return
    if (aperto && !elemento.open) {
      setTier(primo)
      setMotivo('')
      setProblema(null)
      elemento.showModal()
    } else if (!aperto && elemento.open) {
      elemento.close()
    }
  }, [aperto, primo])

  async function invia(evento: FormEvent) {
    evento.preventDefault()
    if (!tier) return
    setInvio(true)
    setProblema(null)
    try {
      const creato = await richiedi<Override>(
        `/api/tools/${encodeURIComponent(toolId)}/overrides`,
        { metodo: 'POST', corpo: { tier, reason: motivo } },
      )
      fatto(creato)
    } catch (errore: unknown) {
      // Il 409 arriva dal trigger del database, non da un controllo in
      // Python: significa che il tier richiesto non innalza piu' quello
      // effettivo, perche' nel frattempo e' cambiato. Il messaggio e' scritto
      // dal database per essere letto, quindi va mostrato com'e'.
      setProblema(
        errore instanceof ErroreApi
          ? errore.problema
          : {
              stato: 0,
              messaggio:
                errore instanceof Error ? errore.message : 'Innalzamento non riuscito.',
              campi: [],
            },
      )
    } finally {
      setInvio(false)
    }
  }

  const motivoValido = motivo.trim().length >= 3

  return (
    <dialog
      className="dialogo"
      ref={riferimento}
      // Esc e il clic sullo sfondo chiudono il dialogo da soli: questo tiene
      // allineato lo stato di React a quello dell'elemento.
      onClose={chiudi}
      aria-labelledby="titolo-innalzamento"
    >
      <form className="dialogo__corpo" onSubmit={(e) => void invia(e)}>
        <h2 className="dialogo__titolo" id="titolo-innalzamento">
          Innalza il tier di <code>{toolId}</code>
        </h2>

        <p className="dialogo__riepilogo">
          Tier effettivo oggi: <PastigliaTier tier={effettivo} tenue />{' '}
          <span className="dialogo__nota">({CONFERMA_RICHIESTA[effettivo]})</span>
        </p>

        <fieldset className="scelta-tier">
          <legend className="campo__etichetta">Nuovo tier</legend>
          {disponibili.map((valore) => (
            <label key={valore} className="scelta-tier__voce">
              <input
                type="radio"
                name="tier"
                value={valore}
                checked={tier === valore}
                onChange={() => setTier(valore)}
              />
              <PastigliaTier tier={valore} />
              <span className="dialogo__nota">{CONFERMA_RICHIESTA[valore]}</span>
            </label>
          ))}
        </fieldset>

        <label className="campo">
          <span className="campo__etichetta">
            Motivo <span className="campo__obbligatorio">obbligatorio</span>
          </span>
          <textarea
            className="campo__ingresso"
            name="reason"
            rows={4}
            required
            minLength={3}
            value={motivo}
            onChange={(e) => setMotivo(e.target.value)}
            placeholder="Cosa e' successo, e perche' questo tool deve stare piu' in alto"
          />
          <span className="campo__aiuto">
            Lo leggerà chi rivedrà lo storico fra mesi, quando nessuno
            ricorderà il contesto.
          </span>
        </label>

        <p className="avviso-irreversibile">
          L’innalzamento non è reversibile: il tier può solo
          salire, e lo storico non ammette modifiche né cancellazioni. Il
          vincolo sta nel database, non in questa pagina.
        </p>

        {problema && <Errore problema={problema} />}

        <div className="dialogo__azioni">
          <button
            type="button"
            className="bottone"
            onClick={chiudi}
            disabled={invio}
          >
            Annulla
          </button>
          <button
            type="submit"
            className="bottone bottone--pericolo"
            disabled={invio || !tier || !motivoValido}
          >
            {invio ? 'Registrazione…' : `Innalza a ${tier ?? ''}`}
          </button>
        </div>
      </form>
    </dialog>
  )
}
