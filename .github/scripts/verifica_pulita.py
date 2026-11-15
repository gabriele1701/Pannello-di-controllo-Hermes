#!/usr/bin/env python3
"""Verifica che un'installazione pulita sia davvero pulita.

Gira nella CI subito dopo `docker compose up`, PRIMA del percorso
dimostrativo, e si puo' eseguire a mano:

    python3 .github/scripts/verifica_pulita.py --base http://127.0.0.1:8000 \\
        --utente operatore --password "$HERMES_ADMIN_PASSWORD"

Il percorso predefinito del seed crea l'operatore e nient'altro. Qui si
verifica la seconda meta' della frase: che si entri, e che ogni elenco sia
vuoto. Senza questa verifica i dati dimostrativi potrebbero tornare
predefiniti -- un flag invertito, un default cambiato -- e la CI resterebbe
verde, perche' `verifica_stack.py` li pretende e li troverebbe.

Usa il client di `verifica_stack.py`, non una copia: stesso login, stesso
cookie, un solo posto in cui il protocollo e' scritto.
"""

from __future__ import annotations

import argparse
import sys

import verifica_stack as stack

#: Ogni elenco che un'installazione pulita deve mostrare vuoto, con la rotta
#: e il modo di contarne le righe. `tools` e `audit` li popola `hermes-core`,
#: gli altri li dichiara l'operatore: nessuno dei due e' ancora passato.
ELENCHI = (
    ("catalogo dei tool", "/api/tools", len),
    ("log d'audit", "/api/audit?limite=200", lambda pagina: pagina["totale"]),
    ("reti del perimetro", "/api/scope/networks", len),
    ("alias del perimetro", "/api/scope/aliases", len),
    ("percorsi del perimetro", "/api/scope/paths", len),
    ("consensi", "/api/consents", len),
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default="http://127.0.0.1:8000")
    parser.add_argument("--utente", default="operatore")
    parser.add_argument("--password", required=True)
    argomenti = parser.parse_args()

    client = stack.Client(argomenti.base)

    print("== l'operatore c'e' ==")
    if not stack.verifica_login(client, argomenti.utente, argomenti.password):
        print(
            "\nlogin fallito: il percorso predefinito deve creare l'operatore",
            file=sys.stderr,
        )
        return 1

    print("== e nient'altro ==")
    for nome, rotta, conta in ELENCHI:
        stato, corpo = client.chiama(rotta)
        if stato != 200:
            stack._ko(f"{nome}: atteso 200, ricevuto {stato}")
            continue
        quante = conta(corpo)
        if quante:
            stack._ko(
                f"{nome}: {quante} righe su un'installazione pulita. I dati "
                f"dimostrativi non devono arrivare senza essere chiesti."
            )
        else:
            stack._ok(f"{nome}: vuoto")

    print()
    if stack._errori:
        print(f"{len(stack._errori)} verifiche fallite:", file=sys.stderr)
        for errore in stack._errori:
            print(f"  - {errore}", file=sys.stderr)
        return 1
    print("installazione pulita: solo l'operatore")
    return 0


if __name__ == "__main__":
    sys.exit(main())
