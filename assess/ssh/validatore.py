"""Validatore ForceCommand lato server — l'allowlist che pinna gli argomenti.

Questo e' il controllo di sicurezza vero del canale SSH (il wrapper client-side
in ``assess/wrappers/ssh.py`` non lo e'). ``sshd`` invoca questo validatore come
``ForceCommand`` e gli passa, in ``$SSH_ORIGINAL_COMMAND``, il comando che il
client vorrebbe eseguire. Il validatore lo confronta con un'allowlist che
**pinna gli argomenti**, non solo il verbo, ed esegue solo i consentiti —
altrimenti esce non-zero senza output.

Regole:

* quattro comandi diagnostici **fissi**, ammessi solo identici (argv pinnato):
  ``ss -tlnp``, ``ps aux``,
  ``systemctl list-units --type=service --state=running``,
  ``docker ps --format '{{.Names}} {{.Status}} {{.Ports}}'``;
* ``cat <percorso>`` ammesso **solo** se il percorso e' sotto la radice
  sorgente consentita (``/opt/pannello``) e non contiene ``..``;
* ``ls -la <dir>`` ammesso **solo** se la directory e' sotto la stessa radice e
  non contiene ``..``.

Tutto il resto e' negato. La logica (``comando_consentito``) e' separata
dall'esecuzione (``main`` → ``os.execvp``) cosi' si testa senza eseguire nulla.

Installazione: vedi ``assess/README-assess.md``. Scritto, **non installato**.
"""

from __future__ import annotations

import os
import shlex
import sys

#: Radice sotto cui ``cat`` e ``ls`` sono ammessi. Il codice del pannello sta
#: qui dentro nell'immagine; niente fuori e' leggibile per questa via.
RADICE_SORGENTE = "/opt/pannello"

#: Comandi fissi ammessi, come argv gia' scomposto: il confronto e' sull'intero
#: vettore, cosi' nessun argomento in piu' passa.
COMANDI_FISSI: tuple[tuple[str, ...], ...] = (
    ("ss", "-tlnp"),
    ("ps", "aux"),
    ("systemctl", "list-units", "--type=service", "--state=running"),
    ("docker", "ps", "--format", "{{.Names}} {{.Status}} {{.Ports}}"),
)


def _sotto_radice(percorso: str, radice: str) -> bool:
    """Vero se ``percorso`` e' ``radice`` o sta sotto di essa, senza risalite.

    Il controllo su ``..`` e' sui segmenti grezzi, prima di ``normpath``: cosi'
    un ``..`` viene rifiutato esplicitamente invece di essere "risolto" in un
    percorso che per caso ricade dentro. Poi ``normpath`` + confronto del
    prefisso chiude i casi residui (es. ``/opt/pannelloX``)."""
    if ".." in percorso.split("/"):
        return False
    if not percorso.startswith("/"):
        return False  # solo percorsi assoluti
    norm = os.path.normpath(percorso)
    radice_norm = os.path.normpath(radice)
    return norm == radice_norm or norm.startswith(radice_norm + "/")


def comando_consentito(
    original: str | None, radice: str = RADICE_SORGENTE
) -> list[str] | None:
    """Restituisce l'argv da eseguire se il comando e' ammesso, altrimenti
    ``None``. Pura: non esegue niente."""
    testo = (original or "").strip()
    if not testo:
        return None
    try:
        argv = shlex.split(testo)
    except ValueError:
        return None  # virgolette non bilanciate: rifiuto
    if not argv:
        return None

    if tuple(argv) in COMANDI_FISSI:
        return argv

    if argv[0] == "cat" and len(argv) == 2:
        return argv if _sotto_radice(argv[1], radice) else None

    if argv[:2] == ["ls", "-la"] and len(argv) == 3:
        return argv if _sotto_radice(argv[2], radice) else None

    return None


def main(argv: list[str] | None = None) -> int:
    """Entry point del ForceCommand. Legge ``$SSH_ORIGINAL_COMMAND``, valida ed
    esegue il comando consentito (``os.execvp``, che sostituisce il processo).
    Su comando non consentito esce con codice 1 e nessun output."""
    original = os.environ.get("SSH_ORIGINAL_COMMAND", "")
    consentito = comando_consentito(original)
    if consentito is None:
        return 1  # negato, nessun output
    os.execvp(consentito[0], consentito)  # non ritorna se riesce
    return 127  # raggiunto solo se execvp fallisce


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())


__all__ = ["COMANDI_FISSI", "RADICE_SORGENTE", "comando_consentito", "main"]
