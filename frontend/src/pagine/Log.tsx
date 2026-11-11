/** Vista del log d'audit.
 *
 * **Questa applicazione non è la fonte di verità del log.** Il log vero è un
 * file JSONL append-only con `chattr +a` sulla macchina del server MCP;
 * quella nel database è una copia ricostruibile e scartabile. Di conseguenza
 * qui non esiste nessuna azione: niente modifica, niente cancellazione,
 * niente inserimento. Si legge e si filtra, e basta — non perché sia comodo,
 * ma perché una vista che potesse scrivere non sarebbe più una vista.
 *
 * I filtri vivono nella query string invece che nello stato del componente:
 * un log filtrato è una cosa che si manda a qualcuno, e un ricaricamento non
 * deve perdere il punto in cui si stava guardando.
 *
 * L'ordinamento non è scegliibile, ed è una scelta del backend: una rotta che
 * accettasse un campo di ordinamento arbitrario accetterebbe un frammento di
 * SQL. Qui non si finge che manchi qualcosa.
 */

import { useCallback } from 'react'
import { Link, useSearchParams } from 'react-router-dom'

import { richiedi } from '../api/client'
import type { Esito, PaginaEventi, TipoEvento } from '../api/tipi'
import { BadgeEsito } from '../componenti/Distintivi'
import { Caricamento, Errore, Vuoto } from '../componenti/Stati'
import { useRisorsa } from '../hook/useRisorsa'
import { ROTTE } from '../percorsi'

/** Quanti eventi per pagina. Il backend ne ammette al massimo 200. */
const PER_PAGINA = 25

const ESITI: Esito[] = ['ok', 'denied', 'error', 'pending']

/** I tipi di evento, nell'ordine in cui compaiono in una catena.
 *
 * Elencati qui perché servono a riempire un menu, e il contratto li dà come
 * enum: l'ordine è l'unica cosa che aggiungiamo, e non è una regola di
 * dominio — è la sequenza tipica di una invocazione, che rende il menu
 * leggibile invece che alfabetico.
 */
const TIPI: TipoEvento[] = [
  'agent_invoked',
  'tool_call',
  'agent_result',
  'secret_access',
  'tool_registered',
  'tool_registration_rejected',
  'tool_alias_detected',
  'override_set',
  'override_rejected',
  'override_store_loaded',
  'override_not_persisted',
  'concurrency_not_shared',
]

export function Log() {
  const [parametri, setParametri] = useSearchParams()

  const agente = parametri.get('agent') ?? ''
  const toolId = parametri.get('tool_id') ?? ''
  const tipo = parametri.get('event_type') ?? ''
  const esito = parametri.get('outcome') ?? ''
  const da = parametri.get('da') ?? ''
  const a = parametri.get('a') ?? ''
  const scarto = Number(parametri.get('scarto') ?? '0')

  const carica = useCallback(
    (segnale: AbortSignal) =>
      richiedi<PaginaEventi>('/api/audit', {
        segnale,
        parametri: {
          agent: agente || undefined,
          tool_id: toolId || undefined,
          event_type: tipo || undefined,
          outcome: esito || undefined,
          // `datetime-local` non porta il fuso: lo aggiunge il browser.
          da: da ? new Date(da).toISOString() : undefined,
          a: a ? new Date(a).toISOString() : undefined,
          limite: PER_PAGINA,
          scarto,
        },
      }),
    [agente, toolId, tipo, esito, da, a, scarto],
  )
  const pagina = useRisorsa(carica)

  /** Cambia un filtro e riparte dalla prima pagina.
   *
   * Lo scarto va azzerato: restare alla terza pagina di un elenco che è
   * appena diventato un altro elenco mostra il vuoto e sembra un guasto.
   */
  function filtra(chiave: string, valore: string) {
    // Un filtro che non cambia non deve rifare la query. Senza questo
    // controllo, uscire dal campo «Tool» senza averlo toccato scrive di
    // nuovo gli stessi parametri: `useSearchParams` restituisce comunque un
    // oggetto nuovo, `carica` cambia identita' e la pagina si ricarica,
    // sfarfallando sullo stato di caricamento per nulla.
    if ((parametri.get(chiave) ?? '') === valore) return

    const prossimi = new URLSearchParams(parametri)
    if (valore) prossimi.set(chiave, valore)
    else prossimi.delete(chiave)
    prossimi.delete('scarto')
    setParametri(prossimi)
  }

  function vaiA(nuovoScarto: number) {
    const prossimi = new URLSearchParams(parametri)
    if (nuovoScarto > 0) prossimi.set('scarto', String(nuovoScarto))
    else prossimi.delete('scarto')
    setParametri(prossimi)
  }

  const filtroAttivo = Boolean(agente || toolId || tipo || esito || da || a)
  const dati = pagina.dati
  const eventi = dati?.eventi ?? []
  const totale = dati?.totale ?? 0
  const primo = totale === 0 ? 0 : scarto + 1
  const ultimo = Math.min(scarto + PER_PAGINA, totale)

  return (
    <section className="log">
      <h1 className="pagina__titolo">Log d&rsquo;audit</h1>
      <p className="riepilogo">
        Una vista, non la fonte di verità: il log vero è un file append-only sulla
        macchina del server MCP, e questa è una copia ricostruibile. Nessuna rotta di
        questa applicazione può scriverci.
      </p>

      <form className="filtri" onSubmit={(e) => e.preventDefault()}>
        <label className="campo campo--inline">
          <span className="campo__etichetta">Esito</span>
          <select
            className="campo__ingresso"
            value={esito}
            onChange={(e) => filtra('outcome', e.target.value)}
          >
            <option value="">tutti</option>
            {ESITI.map((v) => (
              <option key={v} value={v}>
                {v}
              </option>
            ))}
          </select>
        </label>

        <label className="campo campo--inline">
          <span className="campo__etichetta">Tipo di evento</span>
          <select
            className="campo__ingresso"
            value={tipo}
            onChange={(e) => filtra('event_type', e.target.value)}
          >
            <option value="">tutti</option>
            {TIPI.map((v) => (
              <option key={v} value={v}>
                {v}
              </option>
            ))}
          </select>
        </label>

        <label className="campo campo--inline">
          <span className="campo__etichetta">Tool</span>
          <input
            className="campo__ingresso mono"
            type="search"
            placeholder="audit.lynis"
            defaultValue={toolId}
            onBlur={(e) => filtra('tool_id', e.target.value.trim())}
            onKeyDown={(e) => {
              if (e.key === 'Enter') {
                e.preventDefault()
                filtra('tool_id', e.currentTarget.value.trim())
              }
            }}
          />
          <span className="campo__aiuto">identificativo esatto</span>
        </label>

        <label className="campo campo--inline">
          <span className="campo__etichetta">Dal</span>
          <input
            className="campo__ingresso"
            type="datetime-local"
            value={da}
            onChange={(e) => filtra('da', e.target.value)}
          />
        </label>

        <label className="campo campo--inline">
          <span className="campo__etichetta">Al</span>
          <input
            className="campo__ingresso"
            type="datetime-local"
            value={a}
            onChange={(e) => filtra('a', e.target.value)}
          />
        </label>

        {filtroAttivo && (
          <button
            type="button"
            className="bottone bottone--tenue"
            onClick={() => setParametri(new URLSearchParams())}
          >
            Azzera i filtri
          </button>
        )}
      </form>

      {pagina.caricamento && <Caricamento cosa="del log" />}
      {pagina.problema && <Errore problema={pagina.problema} riprova={pagina.ricarica} />}

      {!pagina.caricamento && !pagina.problema && (
        <>
          {eventi.length === 0 ? (
            <Vuoto>
              {filtroAttivo
                ? 'Nessun evento corrisponde ai filtri.'
                : 'Il log è vuoto.'}
            </Vuoto>
          ) : (
            <>
              <p className="riepilogo">
                Eventi da <strong>{primo}</strong> a <strong>{ultimo}</strong> di{' '}
                <strong>{totale}</strong>, dal più recente. Una riga apre la catena
                completa di quella invocazione.
              </p>

              <table className="tabella tabella--log">
                <thead>
                  <tr>
                    <th scope="col">Quando</th>
                    <th scope="col">Esito</th>
                    <th scope="col">Evento</th>
                    <th scope="col">Agente</th>
                    <th scope="col">Tool</th>
                    <th scope="col">Dettaglio</th>
                  </tr>
                </thead>
                <tbody>
                  {eventi.map((e) => (
                    <tr key={e.id}>
                      <td className="tabella__tenue">{istante(e.occurred_at)}</td>
                      <td>
                        <BadgeEsito esito={e.outcome} />
                      </td>
                      <td>
                        {/* Il link è sul tipo di evento e non sulla riga
                            intera: una riga cliccabile non si raggiunge da
                            tastiera e non si apre in una scheda nuova. */}
                        <Link className="mono" to={ROTTE.catena(e.correlation_id)}>
                          {e.event_type}
                        </Link>
                      </td>
                      <td className="tabella__tenue">{e.agent ?? '—'}</td>
                      <td className="mono tabella__tenue">{e.tool_id ?? '—'}</td>
                      <td className="evento__dettaglio">{e.detail}</td>
                    </tr>
                  ))}
                </tbody>
              </table>

              <div className="paginazione">
                <button
                  type="button"
                  className="bottone"
                  disabled={scarto === 0}
                  onClick={() => vaiA(Math.max(0, scarto - PER_PAGINA))}
                >
                  Più recenti
                </button>
                <button
                  type="button"
                  className="bottone"
                  disabled={ultimo >= totale}
                  onClick={() => vaiA(scarto + PER_PAGINA)}
                >
                  Più vecchi
                </button>
              </div>
            </>
          )}
        </>
      )}
    </section>
  )
}

function istante(valore: string): string {
  return new Date(valore).toLocaleString('it-IT', {
    day: '2-digit',
    month: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}
