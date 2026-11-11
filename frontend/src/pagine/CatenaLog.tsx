/** La catena completa di un `correlation_id`, in ordine cronologico.
 *
 * E' la schermata che mostra il gate al lavoro. Una riga del log da sola dice
 * che qualcosa e' stato rifiutato; la catena dice da dove veniva
 * l'invocazione, cosa e' stato chiesto, con quale tier effettivo, chi ha
 * autorizzato, e come e' finita.
 *
 * In ordine cronologico crescente, al contrario dell'elenco che e' dal piu'
 * recente: un elenco si scorre per trovare, una catena si legge per capire,
 * e una storia si legge dall'inizio.
 */

import { useCallback } from 'react'
import { Link, useParams } from 'react-router-dom'

import { richiedi } from '../api/client'
import type { CatenaEventi, Evento } from '../api/tipi'
import { BadgeEsito, PastigliaTier } from '../componenti/Distintivi'
import { Caricamento, Errore } from '../componenti/Stati'
import { useRisorsa } from '../hook/useRisorsa'
import { ROTTE } from '../percorsi'

/** Chi ha autorizzato, detto in italiano. */
const AUTORIZZATO_DA: Record<string, string> = {
  policy: 'dalla policy, senza chiedere',
  user: "dall'operatore, con una conferma",
  none: 'da nessuno',
}

export function CatenaLog() {
  const { correlationId = '' } = useParams()

  const carica = useCallback(
    (segnale: AbortSignal) =>
      richiedi<CatenaEventi>(`/api/audit/${encodeURIComponent(correlationId)}`, {
        segnale,
      }),
    [correlationId],
  )
  const { dati, problema, caricamento, ricarica } = useRisorsa(carica)

  return (
    <section className="catena">
      <Link className="indietro" to={ROTTE.log}>
        Torna al log
      </Link>

      <header>
        <h1 className="pagina__titolo">Catena dell&rsquo;invocazione</h1>
        <p className="riepilogo">
          <span className="mono">{correlationId}</span>
        </p>
      </header>

      {caricamento && <Caricamento cosa="della catena" />}
      {problema && <Errore problema={problema} riprova={ricarica} />}

      {dati && (
        <>
          <p className="riepilogo">
            {dati.eventi.length}{' '}
            {dati.eventi.length === 1 ? 'evento' : 'eventi'}, dal primo all&rsquo;ultimo.
            Gli esiti diversi da <code>ok</code> sono il gate che fa il proprio lavoro.
          </p>

          <ol className="catena__elenco">
            {dati.eventi.map((evento, indice) => (
              <VoceCatena key={evento.id} evento={evento} numero={indice + 1} />
            ))}
          </ol>
        </>
      )}
    </section>
  )
}

function VoceCatena({ evento, numero }: { evento: Evento; numero: number }) {
  return (
    <li className={`voce voce--${evento.outcome}`}>
      <div className="voce__barra" aria-hidden="true">
        <span className="voce__numero">{numero}</span>
      </div>

      <div className="voce__corpo">
        <div className="voce__intestazione">
          <span className="mono voce__tipo">{evento.event_type}</span>
          <BadgeEsito esito={evento.outcome} />
          <span className="voce__istante">{istante(evento.occurred_at)}</span>
        </div>

        <p className="voce__dettaglio">{evento.detail}</p>

        <dl className="voce__dati">
          {evento.agent && (
            <>
              <dt>Agente</dt>
              <dd>{evento.agent}</dd>
            </>
          )}
          {evento.tool_id && (
            <>
              <dt>Tool</dt>
              <dd className="mono">{evento.tool_id}</dd>
            </>
          )}
          {evento.target && (
            <>
              <dt>Bersaglio</dt>
              <dd className="mono">{evento.target}</dd>
            </>
          )}
          {evento.tier_effective && (
            <>
              <dt>Tier effettivo</dt>
              <dd>
                <PastigliaTier tier={evento.tier_effective} />
              </dd>
            </>
          )}
          {evento.authorized_by && (
            <>
              <dt>Autorizzato</dt>
              <dd>{AUTORIZZATO_DA[evento.authorized_by] ?? evento.authorized_by}</dd>
            </>
          )}
          {evento.secret_name && (
            <>
              <dt>Segreto letto</dt>
              {/* Il nome, mai il valore: il log registra che un segreto e'
                  stato letto, non quale sia. */}
              <dd className="mono">{evento.secret_name}</dd>
            </>
          )}
          {evento.peer_correlation_id && (
            <>
              <dt>Catena collegata</dt>
              <dd className="mono">{evento.peer_correlation_id}</dd>
            </>
          )}
        </dl>
      </div>
    </li>
  )
}

function istante(valore: string): string {
  return new Date(valore).toLocaleString('it-IT', {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}
