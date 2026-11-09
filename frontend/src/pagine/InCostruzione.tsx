/** Segnaposto delle schermate non ancora costruite.
 *
 * Dice quale schermata sara' e cosa mostrera', invece di una pagina vuota:
 * una sezione raggiungibile ma muta si legge come un guasto.
 */

export function InCostruzione({ titolo, descrizione }: { titolo: string; descrizione: string }) {
  return (
    <section>
      <h1 className="pagina__titolo">{titolo}</h1>
      <p className="stato stato--vuoto">{descrizione}</p>
    </section>
  )
}
