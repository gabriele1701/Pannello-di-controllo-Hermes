/** Intelaiatura: intestazione, navigazione, area della pagina.
 *
 * L'identita' dell'operatore e l'uscita stanno nell'intestazione e non in un
 * menu: con un utente solo, nascondere l'unica azione di sessione dietro un
 * clic non semplifica niente.
 */

import { NavLink, Outlet } from 'react-router-dom'

import { NAVIGAZIONE } from '../percorsi'
import { useSessione } from '../auth/sessione'

export function Shell() {
  const { sessione, esci } = useSessione()
  const operatore = sessione.fase === 'dentro' ? sessione.operatore : null

  return (
    <div className="telaio">
      <header className="testata">
        <div className="testata__identita">
          <span className="testata__marchio">Hermes</span>
          <span className="testata__sottotitolo">Pannello di controllo</span>
        </div>

        <nav className="navigazione" aria-label="Sezioni">
          {NAVIGAZIONE.map((voce) => (
            <NavLink
              key={voce.a}
              to={voce.a}
              end={voce.esatta}
              className={({ isActive }) =>
                isActive ? 'navigazione__voce navigazione__voce--attiva' : 'navigazione__voce'
              }
            >
              {voce.etichetta}
            </NavLink>
          ))}
        </nav>

        <div className="testata__sessione">
          {operatore && <span className="testata__operatore">{operatore.username}</span>}
          <button type="button" className="bottone bottone--tenue" onClick={() => void esci()}>
            Esci
          </button>
        </div>
      </header>

      <main className="pagina">
        <Outlet />
      </main>

      <footer className="pie">
        Registro dello stato della toolbox. L’esecuzione e l’applicazione della
        policy stanno in <code>hermes-core</code>.
      </footer>
    </div>
  )
}
