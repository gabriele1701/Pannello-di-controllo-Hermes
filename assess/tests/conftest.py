"""Fixture comuni ai test dello scaffold VSPT.

I test girano su **fixture di output grezzo** in ``fixtures/``: nessuna rete,
nessun target, nessuna VM. Verificano la logica indipendente dal target —
scope guard, modello, normalizzazione, report — che e' tutto cio' che lo
scaffold contiene.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES


@pytest.fixture
def carica_fixture():
    def _carica(nome: str) -> Any:
        return json.loads((FIXTURES / nome).read_text(encoding="utf-8"))

    return _carica
