"""VSPT — assessor della web application del pannello Hermes.

Tool CLI (comando ``vspt``) che valuta la sicurezza della webapp del pannello
e dell'ambiente che la ospita, e produce un report unico con finding
normalizzati e rischio = impatto × probabilita'.

Cugino, non fratello, di ``hermes-core/bin/hermes-assess``: quello verifica le
difese del server MCP, questo valuta la web application. Vedi
``assess/README-assess.md``.

Questo package e' lo **scaffold indipendente dal target**: modello, rischio,
scope guard, normalizzazione, report, CLI, interfaccia dei collector e parser
dell'inventario. I collector qui sono stub con l'interfaccia completa ma senza
esecuzione live; il collegamento al target reale e l'esecuzione confinata
arrivano con l'ambiente VM.
"""

from __future__ import annotations

#: Versione del tool, finisce nei metadati di ogni run.
__version__ = "0.1.0-scaffold"
