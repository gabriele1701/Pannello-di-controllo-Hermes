/** Composizione dell'applicazione: fornitore di sessione, rotte, shell.
 *
 * Le rotte protette stanno tutte dentro `RichiedeSessione`, che e' l'unico
 * punto in cui si decide chi entra: una schermata nuova e' protetta perche'
 * sta li' dentro, non perche' chi l'ha scritta ci ha pensato.
 *
 * Il percorso profondo funziona per via del fallback SPA di `backend/main.py`:
 * un ricaricamento su `/tool/audit.lynis` arriva al server come un file che
 * non esiste e riceve `index.html`, cosi' il router legge il percorso.
 */

import { BrowserRouter, Route, Routes } from 'react-router-dom'

import { FornitoreSessione } from './auth/sessione'
import { RichiedeSessione } from './auth/RichiedeSessione'
import { Shell } from './componenti/Shell'
import { Accesso } from './pagine/Accesso'
import { Catalogo } from './pagine/Catalogo'
import { InCostruzione } from './pagine/InCostruzione'
import { NonTrovata } from './pagine/NonTrovata'
import { ROTTE } from './percorsi'

export function App() {
  return (
    <BrowserRouter>
      <FornitoreSessione>
        <Routes>
          <Route path={ROTTE.accesso} element={<Accesso />} />

          <Route element={<RichiedeSessione />}>
            <Route element={<Shell />}>
              <Route index element={<Catalogo />} />
              <Route
                path="tool/:toolId"
                element={
                  <InCostruzione
                    titolo="Dettaglio tool"
                    descrizione="Identità dell’eseguibile, i due assi del rischio, storico degli innalzamenti e azione «Innalza tier»."
                  />
                }
              />
              <Route
                path="perimetro"
                element={
                  <InCostruzione
                    titolo="Perimetro"
                    descrizione="Reti autorizzate e alias dichiarati, con i messaggi di rifiuto del backend."
                  />
                }
              />
              <Route
                path="consensi"
                element={
                  <InCostruzione
                    titolo="Consensi"
                    descrizione="Consensi per scope con stato attivo, scaduto o revocato."
                  />
                }
              />
              <Route
                path="log"
                element={
                  <InCostruzione
                    titolo="Log d’audit"
                    descrizione="Vista filtrabile del log, e la catena completa di un correlation_id."
                  />
                }
              />
              <Route path="*" element={<NonTrovata />} />
            </Route>
          </Route>
        </Routes>
      </FornitoreSessione>
    </BrowserRouter>
  )
}
