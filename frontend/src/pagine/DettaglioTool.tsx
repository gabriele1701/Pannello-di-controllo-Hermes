/** Dettaglio di un tool.
 *
 * Tre cose, in quest'ordine: i due assi del rischio, l'identita' di cio' che
 * viene eseguito, lo storico degli innalzamenti.
 *
 * I due assi stanno in due riquadri affiancati e non in una riga sola, e
 * ciascuno dice **cosa comanda**: il tier tecnico decide ogni quanto si chiede
 * conferma, i dati personali dicono perche' la si chiede. Collassarli in un
 * indicatore unico perderebbe la ragione, che e' l'informazione utile
 * all'operatore nel momento in cui deve decidere.
 *
 * L'azione «Innalza tier» esiste solo se `tier_disponibili` non e' vuoto.
 * Niente bottone disabilitato per un tool gia' a `rosso`: un comando
 * disattivato insegna che esiste un modo e che oggi non e' attivo, mentre qui
 * il declassamento non e' disattivato, non esiste.
 */

import { useCallback, useState } from 'react'
import { Link, useParams } from 'react-router-dom'

import { richiedi } from '../api/client'
import type { Tier, ToolDettaglio } from '../api/tipi'
import { DialogoInnalzamento } from '../componenti/DialogoInnalzamento'
import { BadgeDatiPersonali, CellaTier, PastigliaTier } from '../componenti/Distintivi'
import { Caricamento, Errore } from '../componenti/Stati'
import { useRisorsa } from '../hook/useRisorsa'
import { ROTTE } from '../percorsi'

const CONFERMA_RICHIESTA: Record<Tier, string> = {
  verde: 'Passiva, sola lettura, nessun impatto sul bersaglio. Non richiede conferma.',
  giallo:
    'Attiva ma non distruttiva, su uno scope già autorizzato. Richiede una conferma una tantum per ogni scope.',
  rosso:
    'Intrusiva o distruttiva. Richiede una conferma puntuale a ogni invocazione.',
}

export function DettaglioTool() {
  const { toolId = '' } = useParams()
  const [dialogoAperto, setDialogoAperto] = useState(false)

  const carica = useCallback(
    (segnale: AbortSignal) =>
      richiedi<ToolDettaglio>(`/api/tools/${encodeURIComponent(toolId)}`, { segnale }),
    [toolId],
  )
  const { dati, problema, caricamento, ricarica } = useRisorsa(carica)

  if (caricamento) {
    return (
      <section>
        <Indietro />
        <Caricamento cosa="del tool" />
      </section>
    )
  }

  if (problema || !dati) {
    return (
      <section>
        <Indietro />
        <Errore
          problema={problema ?? { stato: 0, messaggio: 'Tool non disponibile.', campi: [] }}
          riprova={ricarica}
        />
      </section>
    )
  }

  const tool = dati
  const innalzabile = tool.tier_disponibili.length > 0

  return (
    <section className="dettaglio">
      <Indietro />

      <header className="dettaglio__testata">
        <h1 className="dettaglio__titolo mono">{tool.tool_id}</h1>
        <p className="dettaglio__descrizione">{tool.description}</p>
        <p className="dettaglio__agente">
          Agente proprietario: <strong>{tool.agente_etichetta}</strong>. Solo lui può invocare questo tool.
        </p>
      </header>

      {/* I due assi. Separati di proposito: vedi il commento in testa. */}
      <div className="assi">
        <article className={`riquadro asse asse--${tool.effective_tier}`}>
          <h2 className="asse__titolo">Asse tecnico</h2>
          <p className="asse__sottotitolo">Quanto spesso si chiede conferma</p>

          <div className="asse__valore">
            <CellaTier
              dichiarato={tool.declared_tier}
              effettivo={tool.effective_tier}
              innalzato={tool.tier_innalzato}
            />
          </div>

          <p className="asse__spiegazione">{CONFERMA_RICHIESTA[tool.effective_tier]}</p>

          {tool.tier_innalzato && (
            <p className="asse__nota">
              Il tier dichiarato da <code>hermes-core</code> è{' '}
              <PastigliaTier tier={tool.declared_tier} tenue />, ma un innalzamento
              registrato lo porta a <PastigliaTier tier={tool.effective_tier} />. Vale
              il più alto dei due.
            </p>
          )}

          {innalzabile ? (
            <button
              type="button"
              className="bottone bottone--pericolo"
              onClick={() => setDialogoAperto(true)}
            >
              Innalza tier
            </button>
          ) : (
            <p className="asse__nota asse__nota--chiusa">
              Questo tool è già al livello più alto: non c’è niente da innalzare. Il tier non può scendere.
            </p>
          )}
        </article>

        <article className={`riquadro asse ${tool.personal_data ? 'asse--dati' : ''}`}>
          <h2 className="asse__titolo">Dati personali</h2>
          <p className="asse__sottotitolo">Perché si chiede conferma</p>

          <div className="asse__valore">
            {tool.personal_data ? (
              <BadgeDatiPersonali />
            ) : (
              <span className="assente">non riguarda persone fisiche</span>
            )}
          </div>

          <p className="asse__spiegazione">
            {tool.personal_data
              ? 'Questo tool indaga persone fisiche: indirizzi, nomi utente, violazioni di dati. Richiede una conferma dedicata anche quando il tier tecnico è verde.'
              : 'Questo tool non indaga persone fisiche. Le conferme dipendono soltanto dal tier tecnico.'}
          </p>

          <p className="asse__nota">
            I due assi restano separati: questo dice <em>perché</em> si chiede
            conferma, il tier dice <em>quanto spesso</em>. Fonderli perderebbe la
            ragione.
          </p>
        </article>
      </div>

      <article className="riquadro identita">
        <h2 className="sezione__titolo">Identità dell’eseguibile</h2>
        <p className="sezione__nota">
          Di sola lettura: li registra <code>hermes-core</code> all’avvio. Questa
          applicazione li mostra, non li crea né li modifica.
        </p>

        <dl className="elenco-dati">
          <dt>Percorso</dt>
          <dd className="mono">{tool.exec_path}</dd>

          <dt>SHA-256</dt>
          <dd className="mono elenco-dati__sha">{tool.exec_sha256}</dd>

          <dt>Argomenti fissi</dt>
          <dd>
            {tool.exec_args.length === 0 ? (
              <span className="assente">nessuno</span>
            ) : (
              <span className="mono">{tool.exec_args.join(' ')}</span>
            )}
          </dd>

          <dt>Bersaglio</dt>
          <dd>
            {tool.target_kind === 'none'
              ? 'nessuno: non agisce su un host della rete'
              : 'un host, che deve cadere dentro il perimetro dichiarato'}
          </dd>

          <dt>Esecuzione</dt>
          <dd>{tool.requires_container ? 'in container dedicato' : 'sulla macchina del server'}</dd>

          <dt>Registrato il</dt>
          <dd>{istante(tool.registered_at)}</dd>
        </dl>
      </article>

      <article className="riquadro">
        <h2 className="sezione__titolo">
          Storico degli innalzamenti{' '}
          <span className="sezione__conteggio">{tool.overrides.length}</span>
        </h2>
        <p className="sezione__nota">
          Append-only: nessuna riga può essere modificata o cancellata, nemmeno
          da chi possiede le tabelle. Il vincolo è un trigger del database.
        </p>

        {tool.overrides.length === 0 ? (
          <p className="stato stato--vuoto">
            Nessun innalzamento. Il tier effettivo coincide con quello dichiarato da{' '}
            <code>hermes-core</code>.
          </p>
        ) : (
          <table className="tabella">
            <thead>
              <tr>
                <th scope="col">Tier</th>
                <th scope="col">Motivo</th>
                <th scope="col">Autore</th>
                <th scope="col">Provenienza</th>
                <th scope="col">Quando</th>
              </tr>
            </thead>
            <tbody>
              {tool.overrides.map((o) => (
                <tr key={o.id}>
                  <td>
                    <PastigliaTier tier={o.tier} />
                  </td>
                  <td className="override__motivo">{o.reason}</td>
                  <td className="tabella__tenue">{o.created_by}</td>
                  <td className="tabella__tenue">{o.source_descrizione}</td>
                  <td className="tabella__tenue">{istante(o.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </article>

      {innalzabile && (
        <DialogoInnalzamento
          toolId={tool.tool_id}
          effettivo={tool.effective_tier}
          disponibili={tool.tier_disponibili}
          aperto={dialogoAperto}
          chiudi={() => setDialogoAperto(false)}
          fatto={() => {
            setDialogoAperto(false)
            // Si ricarica invece di aggiornare lo stato locale: il tier
            // effettivo e i tier ancora disponibili li calcola il backend, e
            // ricostruirli qui sarebbe una seconda implementazione della
            // stessa regola.
            ricarica()
          }}
        />
      )}
    </section>
  )
}

function Indietro() {
  return (
    <Link className="indietro" to={ROTTE.catalogo}>
      Torna al catalogo
    </Link>
  )
}

function istante(valore: string): string {
  return new Date(valore).toLocaleString('it-IT', {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })
}
