/** Protezione delle rotte: senza sessione non si entra.
 *
 * Il controllo sta qui e non in ogni pagina, per la stessa ragione per cui
 * nel backend la dipendenza di autenticazione e' dichiarata sul router e non
 * rotta per rotta: il default dev'essere «protetta». Una pagina nuova e'
 * protetta perche' sta dentro questo elemento, non perche' chi l'ha scritta
 * si e' ricordato di aggiungere un controllo.
 *
 * Questo non e' un controllo di sicurezza. Nasconde delle schermate, non dei
 * dati: i dati li protegge il cookie, verificato dal server a ogni chiamata.
 * Un browser con gli strumenti di sviluppo aperti puo' far comparire
 * qualunque pagina di questa applicazione, e vedrebbe tabelle vuote.
 */

import { Navigate, Outlet, useLocation } from 'react-router-dom'

import { Caricamento } from '../componenti/Stati'
import { ROTTE } from '../percorsi'
import { useSessione } from './sessione'

export function RichiedeSessione() {
  const { sessione } = useSessione()
  const posizione = useLocation()

  if (sessione.fase === 'verifica') {
    return (
      <div className="pagina pagina--centrata">
        <Caricamento cosa="della sessione" />
      </div>
    )
  }

  if (sessione.fase === 'fuori') {
    // `replace`: la pagina da cui si e' stati rimbalzati non deve restare
    // nella cronologia, altrimenti il tasto «indietro» dopo il login
    // riporterebbe alla pagina di accesso.
    //
    // La destinazione viene conservata nello stato e non nella query string:
    // una `?da=` e' un valore che chiunque puo' scrivere in un link da
    // mandare a qualcun altro. Convalidata comunque in `percorsoInterno`,
    // perche' «viene da noi» e' un'assunzione, e le assunzioni invecchiano.
    return (
      <Navigate
        to={ROTTE.accesso}
        replace
        state={{ da: `${posizione.pathname}${posizione.search}` }}
      />
    )
  }

  return <Outlet />
}
