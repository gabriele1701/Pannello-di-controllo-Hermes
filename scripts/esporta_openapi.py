#!/usr/bin/env python3
"""Esporta lo schema OpenAPI dell'applicazione in `openapi.json`.

`openapi.json` e' il **contratto fra backend e frontend**, e questo script
e' l'unico modo in cui viene scritto. Non si modifica a mano: si cambia il
codice delle rotte e si rigenera.

    python3 scripts/esporta_openapi.py           # rigenera il file
    python3 scripts/esporta_openapi.py --check   # verifica che sia allineato

Perche' un file versionato e non lo schema servito dall'applicazione
---------------------------------------------------------------------

Backend e interfaccia vengono sviluppati in momenti diversi, e il punto in
cui si incontrano e' questo documento. Finche' vive solo in memoria del
processo, e' una convenzione: chi scrive il frontend lo legge una volta e
poi se lo ricorda, e quando il backend cambia una risposta nessuno se ne
accorge finche' qualcosa non si rompe nel browser.

Versionato, invece, un cambiamento del contratto compare nella diff di una
pull request, e una modifica non voluta si vede prima di essere spedita.
La CI verifica che il file committato corrisponda al codice.

Nessun server da avviare
------------------------

Lo script importa l'applicazione e chiama `app.openapi()`. Non apre
connessioni al database -- il motore SQLAlchemy si costruisce alla prima
query, non all'import -- quindi le variabili d'ambiente sotto sono valori
fittizi, imposti qui per due ragioni: perche' la configurazione li pretende
all'avvio, e perche' l'output non deve dipendere dal `.env` di chi esegue
lo script.

Byte identici a parita' di codice
---------------------------------

`sort_keys=True`, indentazione fissa e newline finale: due rigenerazioni
dello stesso codice producono lo stesso file, byte per byte, e la diff
mostra soltanto i cambiamenti veri. Senza l'ordinamento delle chiavi, il
file cambierebbe a ogni rigenerazione per via dell'ordine dei dizionari, e
la diff diventerebbe illeggibile proprio quando serve leggerla.

Verificato che lo schema NON dipenda dall'ambiente: le quattro combinazioni
di `APP_ENV` (development, production) e presenza del build del frontend
producono lo stesso documento, perche' le rotte che cambiano fra quei casi
sono tutte dichiarate `include_in_schema=False`.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

#: Radice del repository, da cui si risolve il percorso del contratto.
RADICE = Path(__file__).resolve().parent.parent

#: Il contratto. In radice e non in una sottodirectory: e' un artefatto che
#: chi apre il repository deve vedere senza cercarlo.
CONTRATTO = RADICE / "openapi.json"

#: Il comando che rigenera il file. Definito qui e usato nei messaggi di
#: errore, cosi' chi incontra il fallimento fra due settimane legge il
#: comando invece di andarselo a cercare.
COMANDO = "python3 scripts/esporta_openapi.py"

#: Valori fittizi: servono solo a soddisfare la configurazione all'import.
#: Imposti e non letti dall'ambiente, perche' lo schema non deve cambiare a
#: seconda di chi lo genera.
AMBIENTE_FITTIZIO = {
    "DATABASE_URL": "postgresql+psycopg://esportazione:schema@localhost:5432/schema",
    "MIGRATIONS_DATABASE_URL": "postgresql+psycopg://esportazione:schema@localhost:5432/schema",
    "APP_SECRET_KEY": "0" * 64,
    "APP_ENV": "development",
}


def genera() -> str:
    """Costruisce l'applicazione e restituisce lo schema serializzato."""
    # Prima dell'import: `backend.main` costruisce l'applicazione a livello
    # di modulo, e la configurazione viene letta in quel momento.
    os.environ.update(AMBIENTE_FITTIZIO)

    sys.path.insert(0, str(RADICE))
    from backend.main import crea_app

    schema = crea_app().openapi()

    # ensure_ascii=False: le descrizioni sono in italiano e contengono
    # lettere accentate. Scritte come caratteri veri invece che come
    # sequenze \uXXXX, la diff resta leggibile.
    return json.dumps(schema, sort_keys=True, indent=2, ensure_ascii=False) + "\n"


def scrivi(contenuto: str) -> None:
    # newline="\n" esplicito: su Windows il default tradurrebbe in CRLF, e
    # il file committato differirebbe da quello generato in CI per i soli
    # fine riga -- un fallimento vero per una ragione falsa.
    CONTRATTO.write_text(contenuto, encoding="utf-8", newline="\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help=(
            "Non scrive: verifica che openapi.json corrisponda al codice ed "
            "esce con stato 1 se differisce."
        ),
    )
    argomenti = parser.parse_args()

    atteso = genera()

    if not argomenti.check:
        scrivi(atteso)
        percorsi = len(json.loads(atteso)["paths"])
        print(f"{CONTRATTO.relative_to(RADICE)} scritto: {percorsi} percorsi")
        return 0

    if not CONTRATTO.exists():
        print(
            f"{CONTRATTO.relative_to(RADICE)} non esiste.\n"
            f"\n"
            f"  Generarlo con:  {COMANDO}\n",
            file=sys.stderr,
        )
        return 1

    attuale = CONTRATTO.read_text(encoding="utf-8")
    if attuale == atteso:
        percorsi = len(json.loads(atteso)["paths"])
        print(f"openapi.json allineato al codice: {percorsi} percorsi")
        return 0

    import difflib

    differenze = list(
        difflib.unified_diff(
            attuale.splitlines(keepends=True),
            atteso.splitlines(keepends=True),
            fromfile="openapi.json (committato)",
            tofile="openapi.json (generato dal codice)",
            n=2,
        )
    )
    print(
        "openapi.json NON corrisponde al codice delle rotte.\n"
        "\n"
        "E' il contratto fra backend e frontend: va rigenerato e committato\n"
        "insieme al cambiamento delle rotte, non modificato a mano.\n"
        "\n"
        f"  Rigeneralo con:  {COMANDO}\n"
        f"  poi committa:    git add openapi.json\n"
        "\n"
        f"Differenze ({len(differenze)} righe di diff):\n",
        file=sys.stderr,
    )
    # Un tetto alle righe stampate: una diff di diecimila righe nel log di
    # una CI non si legge, e il comando per riprodurla e' gia' scritto sopra.
    for riga in differenze[:200]:
        print(riga.rstrip("\n"), file=sys.stderr)
    if len(differenze) > 200:
        print(f"... e altre {len(differenze) - 200} righe", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
