/** Alias comodi sui tipi generati da `openapi.json`.
 *
 * Questo file non *definisce* niente: rinomina. Ogni tipo qui sotto e' una
 * voce di `schema.d.ts`, che e' generato da `../../openapi.json` con
 * `npm run genera-tipi` e non va modificato a mano.
 *
 * Esiste perche' `components['schemas']['ToolRiepilogo']` scritto venti volte
 * nelle pagine e' illeggibile, e perche' se un giorno il backend rinominasse
 * uno schema il punto da correggere sarebbe uno solo.
 */

import type { components } from './schema'

type S = components['schemas']

// Vocabolari del dominio. Sono enum nel backend, quindi qui sono unioni di
// stringhe letterali: un valore fuori dall'insieme non compila.
export type Tier = S['RiskTier']
export type Agente = S['OwnerAgent']
export type Esito = S['CallOutcome']
export type TipoEvento = S['LogAction']
export type ProvenienzaOverride = S['OverrideSource']
export type GenereBersaglio = S['TargetKind']
export type AutorizzatoDa = S['AuthorizedBy']

// Autenticazione
export type Operatore = S['OperatoreRisposta']
export type Credenziali = S['LoginRichiesta']

// Tool
export type ToolRiepilogo = S['ToolRiepilogo']
export type ToolDettaglio = S['ToolDettaglio']
export type Override = S['OverrideRisposta']
export type OverrideRichiesta = S['OverrideRichiesta']

// Perimetro
export type Rete = S['ReteRisposta']
export type ReteRichiesta = S['ReteRichiesta']
export type Alias = S['AliasRisposta']
export type AliasRichiesta = S['AliasRichiesta']
export type Percorso = S['PercorsoRisposta']
export type PercorsoRichiesta = S['PercorsoRichiesta']

// Consensi
export type Consenso = S['ConsensoRisposta']
export type ConsensoRichiesta = S['ConsensoRichiesta']
export type StatoConsenso = Consenso['stato']

// Log
export type Evento = S['EventoRisposta']
export type PaginaEventi = S['PaginaEventi']
export type CatenaEventi = S['CatenaEventi']

/** I tre tier in ordine crescente.
 *
 * L'ordine e' significativo e lo dichiara il backend (`RiskTier`,
 * «L'ordinamento e' significativo»). Qui serve solo a mettere in fila le
 * opzioni di un menu: il *calcolo* di quali tier siano ammessi non si fa
 * mai qui, arriva da `tier_disponibili`.
 */
export const TIER_CRESCENTI = ['verde', 'giallo', 'rosso'] as const satisfies readonly Tier[]
