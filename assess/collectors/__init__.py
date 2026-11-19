"""Collector dell'assessment.

Ogni collector incapsula uno strumento (nuclei, sqlmap, semgrep, pip-audit) o
una fonte (postgres, system) e produce un ``RawResult`` grezzo che
``normalize`` converte in ``Finding``. Sono **indipendenti**: il fallimento di
uno e' un check fallito nei metadati, non l'aborto del run.

In questo scaffold i collector sono **stub**: interfaccia completa (nome,
scope, risorse richieste, comando reale documentato) ma nessuna esecuzione
live. Il collegamento al target reale arriva con l'ambiente VM.
"""
