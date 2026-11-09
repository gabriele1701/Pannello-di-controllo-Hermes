/** Pagina di accesso.
 *
 * Un solo operatore umano. Il messaggio di errore e' quello che manda il
 * backend, ed e' lo stesso per utente inesistente e password sbagliata:
 * distinguerli direbbe a chi prova quali nomi utente esistono. Qui non va
 * «migliorato» rendendolo piu' specifico.
 */

import { useState, type FormEvent } from 'react'
import { Navigate, useLocation } from 'react-router-dom'

import { ErroreApi } from '../api/client'
import type { Problema } from '../api/errori'
import { Errore } from '../componenti/Stati'
import { percorsoInterno, ROTTE } from '../percorsi'
import { useSessione } from '../auth/sessione'

export function Accesso() {
  const { sessione, entra } = useSessione()
  const posizione = useLocation()

  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [problema, setProblema] = useState<Problema | null>(null)
  const [invio, setInvio] = useState(false)

  // La pagina da cui si e' stati rimbalzati, se c'era. Convalidata: vedi
  // `percorsoInterno`, che e' dove sta la ragione.
  const stato = posizione.state as { da?: unknown } | null
  const destinazione = percorsoInterno(stato?.da) ?? ROTTE.catalogo

  if (sessione.fase === 'dentro') return <Navigate to={destinazione} replace />

  async function invia(evento: FormEvent) {
    evento.preventDefault()
    setInvio(true)
    setProblema(null)
    try {
      await entra({ username, password })
      // Nessuna navigazione esplicita: la fase della sessione cambia e il
      // `Navigate` qui sopra porta a destinazione. Un `navigate()` in piu'
      // sarebbe una seconda strada per lo stesso esito, da tenere allineata.
    } catch (errore: unknown) {
      setProblema(
        errore instanceof ErroreApi
          ? errore.problema
          : {
              stato: 0,
              messaggio:
                errore instanceof Error ? errore.message : 'Accesso non riuscito.',
              campi: [],
            },
      )
      setPassword('')
    } finally {
      setInvio(false)
    }
  }

  return (
    <div className="accesso">
      <form className="riquadro accesso__modulo" onSubmit={(e) => void invia(e)}>
        <h1 className="accesso__titolo">
          <span className="accesso__marchio">Hermes</span>
          Pannello di controllo
        </h1>
        <p className="accesso__nota">
          Accesso riservato all&rsquo;operatore. Questa applicazione decide cosa gli
          agenti possono fare: non espone nessuna credenziale di servizio e
          nessuna rotta pensata per un client automatico.
        </p>

        <label className="campo">
          <span className="campo__etichetta">Nome utente</span>
          <input
            className="campo__ingresso"
            name="username"
            autoComplete="username"
            autoFocus
            required
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
        </label>

        <label className="campo">
          <span className="campo__etichetta">Password</span>
          <input
            className="campo__ingresso"
            type="password"
            name="password"
            autoComplete="current-password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </label>

        {problema && <Errore problema={problema} />}

        <button type="submit" className="bottone bottone--primario" disabled={invio}>
          {invio ? 'Verifica in corso…' : 'Entra'}
        </button>
      </form>
    </div>
  )
}
