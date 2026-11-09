/** Caricamento di una risorsa dall'API, con i suoi tre stati.
 *
 * Gli stati di caricamento e di errore non sono una rifinitura: una pagina
 * bianca per due secondi si legge come un'applicazione rotta. Averli in un
 * hook unico fa si' che ogni schermata li abbia per costruzione, invece che
 * per disciplina di chi la scrive.
 *
 * Due dettagli che evitano guasti silenziosi:
 *
 * * **AbortController.** Uscendo da una pagina prima che la risposta arrivi,
 *   la richiesta viene annullata: senza, la risposta tornerebbe a un
 *   componente smontato, e una navigazione veloce fra due tool potrebbe far
 *   vincere la risposta piu' lenta, mostrando il tool sbagliato.
 * * **Il 401 non diventa un errore della pagina.** Se ne occupa la shell
 *   riportando al login; mostrarlo anche qui come messaggio rosso sarebbe un
 *   errore che sparisce da solo mentre l'operatore lo legge.
 */

import { useCallback, useEffect, useState } from 'react'

import { ErroreApi, ErroreSessione } from '../api/client'
import type { Problema } from '../api/errori'

export interface Risorsa<T> {
  dati: T | null
  problema: Problema | null
  caricamento: boolean
  /** Ricarica. Utile dopo una scrittura, e nel bottone «Riprova». */
  ricarica: () => void
}

/**
 * @param carica Funzione che esegue la chiamata. **Va memoizzata** dal
 *   chiamante con `useCallback`, altrimenti cambia identita' a ogni render e
 *   la richiesta riparte all'infinito.
 */
export function useRisorsa<T>(carica: (segnale: AbortSignal) => Promise<T>): Risorsa<T> {
  const [dati, setDati] = useState<T | null>(null)
  const [problema, setProblema] = useState<Problema | null>(null)
  const [caricamento, setCaricamento] = useState(true)
  const [tentativo, setTentativo] = useState(0)

  const ricarica = useCallback(() => setTentativo((n) => n + 1), [])

  useEffect(() => {
    const controllo = new AbortController()
    let vivo = true

    setCaricamento(true)
    setProblema(null)

    carica(controllo.signal)
      .then((risultato) => {
        if (!vivo) return
        setDati(risultato)
        setCaricamento(false)
      })
      .catch((errore: unknown) => {
        if (!vivo) return
        if (errore instanceof DOMException && errore.name === 'AbortError') return
        // Il rimbalzo al login lo fa la shell: qui la pagina resta in
        // caricamento finche' sparisce, invece di lampeggiare un errore.
        if (errore instanceof ErroreSessione) return
        setProblema(
          errore instanceof ErroreApi
            ? errore.problema
            : { stato: 0, messaggio: messaggioDi(errore), campi: [] },
        )
        setCaricamento(false)
      })

    return () => {
      vivo = false
      controllo.abort()
    }
  }, [carica, tentativo])

  return { dati, problema, caricamento, ricarica }
}

function messaggioDi(errore: unknown): string {
  return errore instanceof Error ? errore.message : 'Errore imprevisto.'
}
