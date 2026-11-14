/** Catalogo dei tool.
 *
 * La schermata che dimostra il meccanismo: ogni riga porta i due assi del
 * rischio, separati, e la divergenza fra tier dichiarato ed effettivo e'
 * resa visibile prima di essere letta, dalla fascia di classificazione sul
 * bordo sinistro.
 *
 * Il tier effettivo **non viene calcolato qui**. Lo manda il backend, che lo
 * legge dalla vista dove la regola `max(dichiarato, override)` e' definita
 * una volta sola. Due implementazioni della stessa regola sono due occasioni
 * di scriverla diversamente, e la seconda sarebbe questa.
 *
 * I filtri sono nel browser e non nell'API, e non e' una scorciatoia: la
 * rotta `/api/tools` non ha parametri di filtro, e l'ordinamento e' fisso,
 * deliberatamente — una rotta che accettasse un campo di ordinamento
 * arbitrario accetterebbe un frammento di SQL. Con otto tool il filtro
 * client-side non costa niente e non allarga la superficie dell'API.
 */

import { useCallback, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'

import { richiedi } from '../api/client'
import type { Tier, ToolRiepilogo } from '../api/tipi'
import { TIER_CRESCENTI } from '../api/tipi'
import { BadgeDatiPersonali, CellaTier, Fascia } from '../componenti/Distintivi'
import { Caricamento, Errore, Vuoto } from '../componenti/Stati'
import { useRisorsa } from '../hook/useRisorsa'
import { ROTTE } from '../percorsi'

interface Filtri {
  testo: string
  agente: string
  tier: '' | Tier
  soloDatiPersonali: boolean
  soloInnalzati: boolean
}

const FILTRI_VUOTI: Filtri = {
  testo: '',
  agente: '',
  tier: '',
  soloDatiPersonali: false,
  soloInnalzati: false,
}

export function Catalogo() {
  const carica = useCallback(
    (segnale: AbortSignal) => richiedi<ToolRiepilogo[]>('/api/tools', { segnale }),
    [],
  )
  const { dati, problema, caricamento, ricarica } = useRisorsa(carica)
  const [filtri, setFiltri] = useState<Filtri>(FILTRI_VUOTI)

  const tool = useMemo(() => dati ?? [], [dati])

  // Gli agenti che compaiono davvero, non il vocabolario intero: un filtro
  // che offre un agente senza tool restituisce sempre una tabella vuota.
  const agenti = useMemo(() => {
    const visti = new Map<string, string>()
    for (const t of tool) visti.set(t.agent, t.agente_etichetta)
    return [...visti].sort((a, b) => a[1].localeCompare(b[1], 'it'))
  }, [tool])

  const visibili = useMemo(() => {
    const cercato = filtri.testo.trim().toLowerCase()
    return tool.filter((t) => {
      if (filtri.agente && t.agent !== filtri.agente) return false
      if (filtri.tier && t.effective_tier !== filtri.tier) return false
      if (filtri.soloDatiPersonali && !t.personal_data) return false
      if (filtri.soloInnalzati && !t.tier_innalzato) return false
      if (!cercato) return true
      return (
        t.tool_id.toLowerCase().includes(cercato) ||
        t.description.toLowerCase().includes(cercato)
      )
    })
  }, [tool, filtri])

  const innalzati = tool.filter((t) => t.tier_innalzato).length
  const conDatiPersonali = tool.filter((t) => t.personal_data).length
  const filtroAttivo =
    filtri.testo !== '' ||
    filtri.agente !== '' ||
    filtri.tier !== '' ||
    filtri.soloDatiPersonali ||
    filtri.soloInnalzati

  function aggiorna(parziale: Partial<Filtri>) {
    setFiltri((precedenti) => ({ ...precedenti, ...parziale }))
  }

  return (
    <section>
      <h1 className="pagina__titolo">Catalogo tool</h1>

      {caricamento && <Caricamento cosa="del catalogo" />}
      {problema && <Errore problema={problema} riprova={ricarica} />}

      {!caricamento && !problema && (
        <>
          <p className="riepilogo">
            {tool.length} tool registrati da <code>hermes-core</code>.{' '}
            {innalzati > 0 && (
              <>
                <strong>{innalzati}</strong> con il tier innalzato oltre quello dichiarato
                {conDatiPersonali > 0 && ', '}
              </>
            )}
            {conDatiPersonali > 0 && (
              <>
                <strong>{conDatiPersonali}</strong> che riguardano persone fisiche
              </>
            )}
            .
          </p>

          <form className="filtri" onSubmit={(e) => e.preventDefault()} role="search">
            <label className="campo campo--inline">
              <span className="campo__etichetta">Cerca</span>
              <input
                className="campo__ingresso"
                type="search"
                placeholder="identificativo o descrizione"
                value={filtri.testo}
                onChange={(e) => aggiorna({ testo: e.target.value })}
              />
            </label>

            <label className="campo campo--inline">
              <span className="campo__etichetta">Agente</span>
              <select
                className="campo__ingresso"
                value={filtri.agente}
                onChange={(e) => aggiorna({ agente: e.target.value })}
              >
                <option value="">tutti</option>
                {agenti.map(([valore, etichetta]) => (
                  <option key={valore} value={valore}>
                    {etichetta}
                  </option>
                ))}
              </select>
            </label>

            <label className="campo campo--inline">
              <span className="campo__etichetta">Tier effettivo</span>
              <select
                className="campo__ingresso"
                value={filtri.tier}
                onChange={(e) => aggiorna({ tier: e.target.value as '' | Tier })}
              >
                <option value="">tutti</option>
                {TIER_CRESCENTI.map((t) => (
                  <option key={t} value={t}>
                    {t}
                  </option>
                ))}
              </select>
            </label>

            <label className="interruttore">
              <input
                type="checkbox"
                checked={filtri.soloDatiPersonali}
                onChange={(e) => aggiorna({ soloDatiPersonali: e.target.checked })}
              />
              Solo dati personali
            </label>

            <label className="interruttore">
              <input
                type="checkbox"
                checked={filtri.soloInnalzati}
                onChange={(e) => aggiorna({ soloInnalzati: e.target.checked })}
              />
              Solo tier innalzati
            </label>

            {filtroAttivo && (
              <button
                type="button"
                className="bottone bottone--tenue"
                onClick={() => setFiltri(FILTRI_VUOTI)}
              >
                Azzera i filtri
              </button>
            )}
          </form>

          {tool.length === 0 && (
            <Vuoto>
              Nessun tool registrato. Il catalogo lo popola <code>hermes-core</code> all’avvio: questa applicazione lo mostra, non lo crea.
            </Vuoto>
          )}

          {tool.length > 0 && visibili.length === 0 && (
            <Vuoto>Nessun tool corrisponde ai filtri.</Vuoto>
          )}

          {visibili.length > 0 && <TabellaTool tool={visibili} />}
        </>
      )}
    </section>
  )
}

function TabellaTool({ tool }: { tool: ToolRiepilogo[] }) {
  return (
    <table className="tabella tabella--catalogo">
      <thead>
        <tr>
          <th scope="col" className="tabella__fascia">
            <span className="solo-lettori">Classificazione</span>
          </th>
          <th scope="col">Tool</th>
          <th scope="col">Agente</th>
          <th scope="col">Bersaglio</th>
          <th scope="col">Tier dichiarato ed effettivo</th>
          <th scope="col">Innalzamenti</th>
        </tr>
      </thead>
      <tbody>
        {tool.map((t) => (
          <tr key={t.id} className={t.tier_innalzato ? 'riga riga--innalzata' : 'riga'}>
            <td className="tabella__fascia">
              <Fascia dichiarato={t.declared_tier} effettivo={t.effective_tier} />
            </td>

            <td>
              <span className="tool__intestazione">
                {/* Il link porta il nome: e' cio' che si clicca, e funziona
                    anche da tastiera e con l'apertura in una scheda nuova. */}
                <Link className="tool__identificativo mono" to={ROTTE.tool(t.tool_id)}>
                  {t.tool_id}
                </Link>
                {t.personal_data && <BadgeDatiPersonali />}
              </span>
              <span className="tool__descrizione">{t.description}</span>
            </td>

            <td className="tabella__tenue">{t.agente_etichetta}</td>

            {/* L'etichetta viene dal backend, dove sta il resto del
                vocabolario del dominio: `bersaglio_etichetta` e non una
                mappa scritta qui, che sarebbe una seconda traduzione da
                tenere allineata.

                L'isolamento non e' un terzo badge colorato. La riga porta
                gia' due vocabolari visivi -- la scala del tier e il viola
                dei dati personali -- e un terzo segno competerebbe con la
                divergenza dei tier, che e' il motivo per cui questa tabella
                esiste. Sta qui sotto, come riga minore, dove si legge
                insieme al bersaglio a cui si riferisce. */}
            <td className="tabella__tenue">
              {t.bersaglio_etichetta}
              {t.requires_container && (
                <span className="bersaglio__isolamento">in container isolato</span>
              )}
            </td>

            <td>
              <CellaTier
                dichiarato={t.declared_tier}
                effettivo={t.effective_tier}
                innalzato={t.tier_innalzato}
              />
            </td>

            <td className="tabella__tenue">
              {t.override_count === 0 ? (
                <span className="assente">nessuno</span>
              ) : (
                <>
                  {t.override_count}
                  {t.last_override_at && (
                    <span className="tool__ultimo">
                      , ultimo il {dataBreve(t.last_override_at)}
                    </span>
                  )}
                </>
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

function dataBreve(istante: string): string {
  return new Date(istante).toLocaleDateString('it-IT', {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
  })
}
