"""`--only`: eseguire un sottoinsieme di collector, e l'onesta' del NOT_RUN.

`vspt run --only system` esegue SOLO `system`; gli altri non vengono nemmeno
istanziati nel run (non sono "saltati": non sono stati chiesti). E un collector
il cui canale manca (http/db/ssh None) risulta NOT_RUN esplicito, mai un finto
esito. Nessuna rete: si lavora sul runner, non sull'I/O.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from assess.cli import costruisci_parser, filtra_collectors
from assess.collectors.base import RunContext
from assess.config import ConfigEgress, ConfigScope, ConfigSsh, ConfigTarget
from assess.model import EsitoCheck
from assess.runner import collectors_standard, esegui_run


def _cfg() -> ConfigScope:
    return ConfigScope(
        target=ConfigTarget(base_url="http://app:8000", allowlist=("app",)),
        egress=ConfigEgress(sentinelle=(("1.1.1.1", 53),)),
        ssh=ConfigSsh(),  # nessun host -> nessun canale
    )


# --- selezione --only ------------------------------------------------------ #


def test_only_system_tiene_solo_system():
    scelti = filtra_collectors(collectors_standard(), ["system"])
    assert [c.name for c in scelti] == ["system"]


def test_only_mantiene_ordine_standard():
    scelti = filtra_collectors(collectors_standard(), ["postgres", "nuclei"])
    # L'ordine e' quello standard del run, non quello degli argomenti.
    assert [c.name for c in scelti] == ["nuclei", "postgres"]


def test_only_nome_sconosciuto_e_errore():
    with pytest.raises(ValueError):
        filtra_collectors(collectors_standard(), ["sistema"])  # refuso


def test_parser_accetta_only():
    args = costruisci_parser().parse_args(["run", "--only", "system"])
    assert args.only == ["system"]


def test_parser_senza_only_e_none():
    args = costruisci_parser().parse_args(["run"])
    assert args.only is None


# --- end-to-end: --only system non tenta gli altri ------------------------- #


def test_run_only_system_non_istanzia_gli_altri():
    ctx = RunContext(config=_cfg(), repo_root=Path("."), ssh=None)
    collectors = filtra_collectors(collectors_standard(), ["system"])
    esec = esegui_run(ctx, collectors, salta_egress=True)
    nomi = [c.name for c in esec.metadati.checks]
    assert nomi == ["system"]  # SOLO system e' nei metadati
    system = esec.metadati.checks[0]
    assert system.esito is EsitoCheck.SALTATO  # NOT_RUN: nessun canale SSH
    assert "ssh" in system.nota


# --- onesta': canali assenti -> NOT_RUN, mai un finto esito ---------------- #


def test_collector_senza_canale_sono_not_run():
    # http=None, db=None, ssh=None: nessun collector ha il suo canale.
    ctx = RunContext(config=_cfg(), repo_root=Path("."), http=None, db=None, ssh=None)
    esec = esegui_run(ctx, collectors_standard(), salta_egress=True)
    per_nome = {c.name: c.esito for c in esec.metadati.checks}
    # Tutti e sei saltati per requisiti non soddisfatti.
    assert set(per_nome) == {"nuclei", "sqlmap", "semgrep", "pip-audit", "postgres", "system"}
    assert all(e is EsitoCheck.SALTATO for e in per_nome.values())
    # Nessun finto COMPLETATO, nessun FALLITO imprevisto.
    assert not any(e is EsitoCheck.COMPLETATO for e in per_nome.values())
    assert not any(e is EsitoCheck.FALLITO for e in per_nome.values())
