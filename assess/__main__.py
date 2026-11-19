"""Entrypoint: ``python -m assess``.

Il comando ``vspt`` e' un wrapper su questo (vedi il Dockerfile). Si tiene qui
l'avvio del package cosi' il tool e' eseguibile da clone senza dipendere da un
console_script registrato nel packaging del pannello.
"""

from __future__ import annotations

import sys

from assess.cli import main

if __name__ == "__main__":
    sys.exit(main())
