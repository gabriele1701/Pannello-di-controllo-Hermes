// Scheletro dell'interfaccia. Le schermate arrivano nella fase successiva:
// catalogo tool, dettaglio con innalzamento del tier, perimetro, consensi, log.
export function App() {
  return (
    <main className="shell">
      <h1>Pannello di controllo Hermes</h1>
      <p>
        Registro dello stato della toolbox di sicurezza: tier dei tool,
        innalzamenti, consensi per scope, perimetro dei bersagli e vista del
        log d&apos;audit.
      </p>
      <p className="nota">
        Interfaccia in costruzione. Le API sono attive sotto <code>/api</code>.
      </p>
    </main>
  )
}
