/** Consensi per scope.
 *
 * Un consenso autorizza un agente — o un suo tool preciso — ad agire su un
 * ambito del perimetro, fino a una scadenza. **La scadenza e' obbligatoria**:
 * un consenso che non scade non e' un consenso, e' un'autorizzazione
 * permanente con un altro nome. Il backend lo impone, questa pagina non
 * offre il modo di aggirarlo.
 *
 * Lo stato — attivo, scaduto, revocato — arriva calcolato dal backend e non
 * viene ricalcolato qui. E' derivato dalle date e non memorizzato, perche'
 * una colonna di stato andrebbe aggiornata allo scadere e nessuno la
 * aggiornerebbe.
 *
 * I filtri sono del server, non del browser: `/api/consents` li espone, e il
 * backend li applica in SQL perche' con molti consensi filtrare dopo aver
 * letto tutto significherebbe leggere tutto. E' l'opposto del catalogo, dove
 * la rotta non ha filtri e gli otto tool si filtrano in pagina — in entrambi
 * i casi si segue quello che la rotta offre, invece di inventare.
 *
 * La revoca non cancella: segna una data. Un consenso revocato resta nello
 * storico, perche' sapere che e' esistito ed e' stato ritirato e' diverso da
 * non trovarne traccia.
 */

import { useCallback, useEffect, useMemo, useState, type FormEvent } from 'react'

import { ErroreApi, richiedi } from '../api/client'
import type { Problema } from '../api/errori'
import { erroriDi } from '../api/errori'
import type { Alias, Consenso, Rete, StatoConsenso, ToolRiepilogo } from '../api/tipi'
import { BadgeStato } from '../componenti/Distintivi'
import { Caricamento, Errore, Vuoto } from '../componenti/Stati'
import { useRisorsa } from '../hook/useRisorsa'

const STATI: StatoConsenso[] = ['attivo', 'scaduto', 'revocato']

export function Consensi() {
  const [agente, setAgente] = useState('')
  const [stato, setStato] = useState<'' | StatoConsenso>('')
  const [versione, setVersione] = useState(0)

  // I filtri entrano nella chiamata, quindi `carica` cambia identita' quando
  // cambiano: e' il modo in cui `useRisorsa` riparte.
  const caricaConsensi = useCallback(
    (segnale: AbortSignal) =>
      richiedi<Consenso[]>('/api/consents', {
        segnale,
        parametri: { agent: agente || undefined, stato: stato || undefined },
      }),
    [agente, stato],
  )
  const consensi = useRisorsa(caricaConsensi)

  // Il catalogo serve due volte: per gli agenti con le loro etichette
  // leggibili, e per i tool fra cui scegliere. E' l'unica fonte a runtime di
  // entrambi, quindi non si scrive a mano un secondo vocabolario.
  const caricaTool = useCallback(
    (segnale: AbortSignal) => richiedi<ToolRiepilogo[]>('/api/tools', { segnale }),
    [],
  )
  const tool = useRisorsa(caricaTool)

  const agenti = useMemo(() => {
    const visti = new Map<string, string>()
    for (const t of tool.dati ?? []) visti.set(t.agent, t.agente_etichetta)
    return [...visti].sort((a, b) => a[1].localeCompare(b[1], 'it'))
  }, [tool.dati])

  function ricarica() {
    consensi.ricarica()
    setVersione((n) => n + 1)
  }

  const righe = consensi.dati ?? []
  const attivi = righe.filter((c) => c.stato === 'attivo').length

  return (
    <section className="consensi">
      <h1 className="pagina__titolo">Consensi per scope</h1>
      <p className="riepilogo">
        Un consenso autorizza un agente, o un suo tool preciso, ad agire su un ambito
        del perimetro fino a una scadenza. La scadenza è obbligatoria: un consenso che
        non scade non è un consenso.
      </p>

      <form className="filtri" onSubmit={(e) => e.preventDefault()}>
        <label className="campo campo--inline">
          <span className="campo__etichetta">Agente</span>
          <select
            className="campo__ingresso"
            value={agente}
            onChange={(e) => setAgente(e.target.value)}
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
          <span className="campo__etichetta">Stato</span>
          <select
            className="campo__ingresso"
            value={stato}
            onChange={(e) => setStato(e.target.value as '' | StatoConsenso)}
          >
            <option value="">tutti</option>
            {STATI.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </label>

        {(agente || stato) && (
          <button
            type="button"
            className="bottone bottone--tenue"
            onClick={() => {
              setAgente('')
              setStato('')
            }}
          >
            Azzera i filtri
          </button>
        )}
      </form>

      <article className="riquadro">
        <h2 className="sezione__titolo">
          Consensi{' '}
          {!consensi.caricamento && (
            <span className="sezione__conteggio">{righe.length}</span>
          )}
        </h2>
        <p className="sezione__nota">
          La revoca non cancella la riga: ne segna la data. Un consenso ritirato resta
          visibile, perché sapere che è esistito è diverso dal non trovarne traccia.
          {attivi > 0 && ` Di questi, ${attivi} ${attivi === 1 ? 'è attivo' : 'sono attivi'}.`}
        </p>

        {consensi.caricamento && <Caricamento cosa="dei consensi" />}
        {consensi.problema && (
          <Errore problema={consensi.problema} riprova={consensi.ricarica} />
        )}

        {!consensi.caricamento &&
          !consensi.problema &&
          (righe.length === 0 ? (
            <Vuoto>
              {agente || stato
                ? 'Nessun consenso corrisponde ai filtri.'
                : 'Nessun consenso registrato.'}
            </Vuoto>
          ) : (
            <table className="tabella">
              <thead>
                <tr>
                  <th scope="col">Stato</th>
                  <th scope="col">Agente</th>
                  <th scope="col">Ambito</th>
                  <th scope="col">Scope</th>
                  <th scope="col">Concesso</th>
                  <th scope="col">Scadenza</th>
                  <th scope="col" className="tabella__azioni">
                    <span className="solo-lettori">Azioni</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {righe.map((c) => (
                  <RigaConsenso
                    key={c.id}
                    consenso={c}
                    versione={versione}
                    dopoModifica={ricarica}
                  />
                ))}
              </tbody>
            </table>
          ))}
      </article>

      <ModuloConsenso
        agenti={agenti}
        tool={tool.dati ?? []}
        dopoCreazione={ricarica}
      />
    </section>
  )
}

/* ------------------------------------------------------------------ */

function RigaConsenso({
  consenso,
  versione,
  dopoModifica,
}: {
  consenso: Consenso
  versione: number
  dopoModifica: () => void
}) {
  const [conferma, setConferma] = useState(false)
  const [problema, setProblema] = useState<Problema | null>(null)
  const [invio, setInvio] = useState(false)

  useEffect(() => setProblema(null), [versione])

  async function revoca() {
    setInvio(true)
    setProblema(null)
    try {
      await richiedi<Consenso>(`/api/consents/${consenso.id}/revoke`, { metodo: 'POST' })
      setConferma(false)
      dopoModifica()
    } catch (errore: unknown) {
      setProblema(
        errore instanceof ErroreApi
          ? errore.problema
          : {
              stato: 0,
              messaggio: errore instanceof Error ? errore.message : 'Revoca non riuscita.',
              campi: [],
            },
      )
      setConferma(false)
    } finally {
      setInvio(false)
    }
  }

  return (
    <>
      <tr className={consenso.stato === 'attivo' ? '' : 'riga--spenta'}>
        <td>
          <BadgeStato stato={consenso.stato} />
        </td>
        <td className="tabella__tenue">{consenso.agente_etichetta}</td>
        <td>
          {consenso.tool_identificativo ? (
            <span className="mono">{consenso.tool_identificativo}</span>
          ) : (
            <span className="ambito-agente">tutto l&rsquo;agente</span>
          )}
        </td>
        <td className="mono tabella__tenue">{consenso.scope}</td>
        <td className="tabella__tenue">
          {data(consenso.granted_at)}
          <span className="tool__ultimo"> da {consenso.granted_by}</span>
        </td>
        <td className="tabella__tenue">
          {data(consenso.expires_at)}
          {consenso.revoked_at && (
            <span className="tool__ultimo"> revocato il {data(consenso.revoked_at)}</span>
          )}
        </td>
        <td className="tabella__azioni">
          {/* La revoca esiste solo per ciò che è ancora attivo: revocare un
              consenso scaduto non cambia niente, e offrirlo suggerirebbe che
              serva a qualcosa. Il backend rifiuta comunque una seconda
              revoca, e quel rifiuto resta mostrato se ci si arriva. */}
          {consenso.stato !== 'attivo' ? (
            <span className="assente">&mdash;</span>
          ) : conferma ? (
            <span className="conferma">
              <button
                type="button"
                className="bottone bottone--pericolo"
                onClick={() => void revoca()}
                disabled={invio}
              >
                {invio ? 'Revoca…' : 'Conferma la revoca'}
              </button>
              <button
                type="button"
                className="bottone bottone--tenue"
                onClick={() => setConferma(false)}
                disabled={invio}
              >
                Annulla
              </button>
            </span>
          ) : (
            <button
              type="button"
              className="bottone bottone--tenue"
              onClick={() => setConferma(true)}
            >
              Revoca
            </button>
          )}
        </td>
      </tr>
      {problema && (
        <tr className="riga-errore">
          <td colSpan={7}>
            <Errore problema={problema} />
          </td>
        </tr>
      )}
    </>
  )
}

/* ------------------------------------------------------------------ */

function ModuloConsenso({
  agenti,
  tool,
  dopoCreazione,
}: {
  agenti: [string, string][]
  tool: ToolRiepilogo[]
  dopoCreazione: () => void
}) {
  const [agente, setAgente] = useState('')
  const [toolId, setToolId] = useState('')
  const [scope, setScope] = useState('')
  const [scadenza, setScadenza] = useState('')
  const [problema, setProblema] = useState<Problema | null>(null)
  const [invio, setInvio] = useState(false)

  // Gli ambiti suggeriti sono le reti e gli alias del perimetro. Un
  // suggerimento e non un vincolo: il backend accetta testo libero, e
  // restringere qui inventerebbe una regola che il contratto non ha.
  const caricaReti = useCallback(
    (segnale: AbortSignal) => richiedi<Rete[]>('/api/scope/networks', { segnale }),
    [],
  )
  const caricaAlias = useCallback(
    (segnale: AbortSignal) => richiedi<Alias[]>('/api/scope/aliases', { segnale }),
    [],
  )
  const reti = useRisorsa(caricaReti)
  const alias = useRisorsa(caricaAlias)
  const ambiti = [
    ...(reti.dati ?? []).map((r) => r.cidr),
    ...(alias.dati ?? []).map((a) => a.name),
  ]

  // Solo i tool dell'agente scelto: il backend rifiuta un tool di un altro
  // agente, e offrirlo qui vorrebbe dire costruire una richiesta che si sa
  // gia' rifiutata.
  const toolDellAgente = tool.filter((t) => t.agent === agente)

  async function crea(evento: FormEvent) {
    evento.preventDefault()
    setInvio(true)
    setProblema(null)
    try {
      await richiedi<Consenso>('/api/consents', {
        metodo: 'POST',
        corpo: {
          agent: agente,
          // `datetime-local` non porta il fuso: lo aggiunge il browser
          // interpretando il valore come ora locale. Il backend rifiuta un
          // istante senza fuso, perche' non sarebbe confrontabile con niente.
          expires_at: new Date(scadenza).toISOString(),
          scope,
          ...(toolId ? { tool_id: Number(toolId) } : {}),
        },
      })
      setScope('')
      setScadenza('')
      setToolId('')
      dopoCreazione()
    } catch (errore: unknown) {
      setProblema(
        errore instanceof ErroreApi
          ? errore.problema
          : {
              stato: 0,
              messaggio:
                errore instanceof Error ? errore.message : 'Consenso non registrato.',
              campi: [],
            },
      )
    } finally {
      setInvio(false)
    }
  }

  return (
    <article className="riquadro">
      <h2 className="sezione__titolo">Concedi un consenso</h2>
      <p className="sezione__nota">
        Senza indicare un tool, il consenso vale per l&rsquo;agente intero.
      </p>

      <form className="modulo-inline" onSubmit={(e) => void crea(e)}>
        <label className="campo campo--inline">
          <span className="campo__etichetta">Agente</span>
          <select
            className="campo__ingresso"
            name="agent"
            required
            value={agente}
            onChange={(e) => {
              setAgente(e.target.value)
              // Il tool scelto apparteneva all'agente di prima.
              setToolId('')
            }}
          >
            <option value="">scegli</option>
            {agenti.map(([valore, etichetta]) => (
              <option key={valore} value={valore}>
                {etichetta}
              </option>
            ))}
          </select>
        </label>

        <label className="campo campo--inline">
          <span className="campo__etichetta">Tool</span>
          <select
            className="campo__ingresso"
            name="tool_id"
            value={toolId}
            disabled={!agente}
            onChange={(e) => setToolId(e.target.value)}
          >
            <option value="">tutto l&rsquo;agente</option>
            {toolDellAgente.map((t) => (
              <option key={t.id} value={t.id}>
                {t.tool_id}
              </option>
            ))}
          </select>
          <span className="campo__aiuto">
            {agente ? 'solo i tool di questo agente' : 'scegli prima un agente'}
          </span>
        </label>

        <label className="campo campo--inline">
          <span className="campo__etichetta">Scope</span>
          <input
            className="campo__ingresso mono"
            name="scope"
            required
            list="ambiti-perimetro"
            placeholder="192.168.205.0/24"
            value={scope}
            onChange={(e) => setScope(e.target.value)}
            aria-invalid={erroriDi(problema, 'scope').length > 0}
          />
          <datalist id="ambiti-perimetro">
            {ambiti.map((a) => (
              <option key={a} value={a} />
            ))}
          </datalist>
          <span className="campo__aiuto">una rete o un alias del perimetro</span>
        </label>

        <label className="campo campo--inline">
          <span className="campo__etichetta">Scade il</span>
          <input
            className="campo__ingresso"
            type="datetime-local"
            name="expires_at"
            required
            value={scadenza}
            onChange={(e) => setScadenza(e.target.value)}
            aria-invalid={erroriDi(problema, 'expires_at').length > 0}
          />
          <span className="campo__aiuto">{descriviScadenza(scadenza)}</span>
        </label>

        <button type="submit" className="bottone" disabled={invio}>
          {invio ? 'Registrazione…' : 'Concedi'}
        </button>
      </form>

      {problema && <Errore problema={problema} />}
    </article>
  )
}

function data(valore: string): string {
  return new Date(valore).toLocaleDateString('it-IT', {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
  })
}

/** Rilegge in italiano la scadenza scelta nel campo.
 *
 * Il formato che un `datetime-local` mostra lo decide la lingua del browser,
 * non questa pagina: su un browser in inglese compare `mm/dd/yyyy`, e chi
 * scrive 03/12 puo' credere di aver indicato il 3 dicembre mentre ha
 * indicato il 12 marzo. Qui sotto la data scelta viene riscritta per esteso,
 * con il giorno della settimana: qualunque formato mostri il campo,
 * l'interpretazione e' leggibile prima di premere «Concedi».
 */
function descriviScadenza(valore: string): string {
  if (!valore) return 'obbligatoria'
  const istante = new Date(valore)
  if (Number.isNaN(istante.getTime())) return 'data non leggibile'

  const quando = istante.toLocaleString('it-IT', {
    weekday: 'long',
    day: 'numeric',
    month: 'long',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })

  const giorni = Math.round((istante.getTime() - Date.now()) / 86_400_000)
  if (giorni < 0) return `${quando} — nel passato`
  if (giorni === 0) return `${quando} — oggi`
  if (giorni === 1) return `${quando} — fra un giorno`
  return `${quando} — fra ${giorni} giorni`
}
