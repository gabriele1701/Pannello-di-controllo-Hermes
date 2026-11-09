import { Link } from 'react-router-dom'

import { ROTTE } from '../percorsi'

export function NonTrovata() {
  return (
    <section>
      <h1 className="pagina__titolo">Pagina inesistente</h1>
      <p className="stato stato--vuoto">
        Questo indirizzo non corrisponde a nessuna schermata.{' '}
        <Link to={ROTTE.catalogo}>Torna al catalogo</Link>.
      </p>
    </section>
  )
}
