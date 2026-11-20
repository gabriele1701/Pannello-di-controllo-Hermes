"""Parse layer dei collector: output grezzo -> RawResult, su fixture realistiche.

E' il lavoro che si puo' testare adesso, senza VM ne' target: la costruzione
del comando e l'interpretazione dell'output. L'unico punto non coperto e'
``_esegui_live`` (l'I/O), che resta uno stub isolato e qui si verifica solo che
sollevi ``EsecuzioneLiveNonDisponibile``.

Per ogni collector: risultati presenti, zero risultati (controllo positivo),
output malformato (FALLITO, non un falso vuoto) e — dove ha senso — condizione
non valida (sessione scaduta, scan con errori) con esito esplicito.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from assess.collectors.base import (
    EsecuzioneLiveNonDisponibile,
    RunContext,
)
from assess.collectors.external_nuclei import NucleiCollector
from assess.collectors.external_sqlmap import SqlmapCollector
from assess.collectors.internal_db import DbCollector
from assess.collectors.internal_pipaudit import PipAuditCollector
from assess.collectors.internal_semgrep import SemgrepCollector
from assess.collectors.internal_system import SystemCollector
from assess.config import ConfigEgress, ConfigScope, ConfigTarget
from assess.inventory.openapi_endpoints import inventario_da_file
from assess.model import EsitoCheck, Source
from assess.normalize import normalizza

RADICE = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).parent / "fixtures"


def _testo(nome: str) -> str:
    return (FIXTURES / nome).read_text(encoding="utf-8")


def _ctx() -> RunContext:
    cfg = ConfigScope(
        target=ConfigTarget(base_url="http://app:8000", allowlist=("app",)),
        egress=ConfigEgress(sentinelle=(("1.1.1.1", 53),)),
    )
    inv = inventario_da_file(RADICE / "openapi.json")
    return RunContext(
        config=cfg, repo_root=RADICE, target="app",
        base_url="http://app:8000", inventario=inv,
    )


# --------------------------------------------------------------------------- #
# nuclei
# --------------------------------------------------------------------------- #


def test_nuclei_comando_usa_gli_url_del_contratto():
    argv = NucleiCollector().costruisci_comando(_ctx())
    assert argv[0] == "nuclei"
    assert "-jsonl" in argv and "-disable-update-check" in argv
    url = [argv[i + 1] for i, a in enumerate(argv) if a == "-u"]
    assert "http://app:8000/api/scope/networks" in url
    # Il cookie viene aggiunto solo quando il contesto ha una sessione.
    assert not any("hermes_session=" in a for a in argv)
    ctx = _ctx()
    ctx.http = "cookie-di-test"
    argv_auth = NucleiCollector().costruisci_comando(ctx)
    assert "Cookie: hermes_session=cookie-di-test" in argv_auth


def test_nuclei_parse_match():
    raw = NucleiCollector().parse(_testo("nuclei.jsonl"))
    assert raw.esito is EsitoCheck.COMPLETATO
    assert len(raw.elementi) == 2


def test_nuclei_parse_zero():
    raw = NucleiCollector().parse("   \n  ")
    assert raw.esito is EsitoCheck.COMPLETATO
    assert raw.elementi == [] and raw.nota


def test_nuclei_parse_malformato_e_fallito():
    raw = NucleiCollector().parse('{"template-id": "x"}\n{non-json')
    assert raw.esito is EsitoCheck.FALLITO


# --------------------------------------------------------------------------- #
# sqlmap
# --------------------------------------------------------------------------- #


def test_sqlmap_comando_profilo_non_distruttivo():
    argv = SqlmapCollector().costruisci_comando(_ctx())
    assert "--technique=BEU" in argv and "--risk=1" in argv and "--level=1" in argv
    assert "--batch" in argv
    # nessuna tecnica che tocchi dati/OS
    assert "--os-shell" not in argv and "--dump" not in argv


def test_sqlmap_un_comando_per_endpoint_iniettabile():
    comandi = SqlmapCollector().comandi(_ctx())
    assert comandi, "ci sono endpoint iniettabili nel contratto"
    assert all(c[0] == "sqlmap" for c in comandi)


def test_sqlmap_parse_iniezione():
    raw = SqlmapCollector().parse(_testo("sqlmap_iniezione.txt"))
    assert raw.esito is EsitoCheck.COMPLETATO
    assert raw.elementi and raw.elementi[0]["injectable"] is True
    assert raw.elementi[0]["parameter"] == "cidr"


def test_sqlmap_parse_pulito_e_zero():
    raw = SqlmapCollector().parse(_testo("sqlmap_pulito.txt"))
    assert raw.esito is EsitoCheck.COMPLETATO and raw.elementi == []
    assert "controllo positivo" in raw.nota


def test_sqlmap_sessione_scaduta_e_fallito_non_negativo():
    raw = SqlmapCollector().parse(_testo("sqlmap_sessione.txt"))
    assert raw.esito is EsitoCheck.FALLITO
    assert "sessione non valida" in raw.nota


def test_sqlmap_parse_non_riconosciuto_e_fallito():
    raw = SqlmapCollector().parse("### endpoint: GET /api/x\nqualcosa di inatteso")
    assert raw.esito is EsitoCheck.FALLITO


# --------------------------------------------------------------------------- #
# semgrep
# --------------------------------------------------------------------------- #


def test_semgrep_comando_punta_a_backend():
    argv = SemgrepCollector().costruisci_comando(_ctx())
    assert argv[0] == "semgrep" and "--json" in argv
    assert argv[-1].endswith("backend")


def test_semgrep_parse_match():
    raw = SemgrepCollector().parse(_testo("semgrep.json"))
    assert raw.esito is EsitoCheck.COMPLETATO and len(raw.elementi) == 1


def test_semgrep_parse_pulito_e_zero():
    raw = SemgrepCollector().parse(_testo("semgrep_pulito.json"))
    assert raw.esito is EsitoCheck.COMPLETATO and raw.elementi == []


def test_semgrep_errori_di_scansione_sono_fallito():
    raw = SemgrepCollector().parse(_testo("semgrep_errori.json"))
    assert raw.esito is EsitoCheck.FALLITO


def test_semgrep_malformato_e_fallito():
    assert SemgrepCollector().parse("non json").esito is EsitoCheck.FALLITO


# --------------------------------------------------------------------------- #
# pip-audit
# --------------------------------------------------------------------------- #


def test_pipaudit_comando_usa_requirements():
    argv = PipAuditCollector().costruisci_comando(_ctx())
    assert argv[0] == "pip-audit" and argv[-1].endswith("requirements.txt")


def test_pipaudit_parse_con_vulnerabilita():
    raw = PipAuditCollector().parse(_testo("pipaudit.json"))
    assert raw.esito is EsitoCheck.COMPLETATO and len(raw.elementi) == 1


def test_pipaudit_parse_pulito_e_zero():
    raw = PipAuditCollector().parse(_testo("pipaudit_pulito.json"))
    assert raw.esito is EsitoCheck.COMPLETATO and raw.elementi == []


def test_pipaudit_malformato_e_fallito():
    assert PipAuditCollector().parse("42").esito is EsitoCheck.FALLITO


# --------------------------------------------------------------------------- #
# postgres
# --------------------------------------------------------------------------- #


def test_postgres_modello_conforme():
    raw = DbCollector().parse(_testo("postgres.json"))
    assert raw.esito is EsitoCheck.COMPLETATO
    assert raw.elementi and all(a["conforme"] for a in raw.elementi)


def test_postgres_deviazioni_segnalate():
    raw = DbCollector().parse(_testo("postgres_deviazione.json"))
    assert raw.esito is EsitoCheck.COMPLETATO
    nonconf = [a for a in raw.elementi if not a["conforme"]]
    assert len(nonconf) >= 3  # audit INSERT, consents UPDATE tabella, assess DELETE, replica


def test_postgres_malformato_e_fallito():
    assert DbCollector().parse("{").esito is EsitoCheck.FALLITO


def test_postgres_senza_ruolo_app_e_fallito():
    raw = DbCollector().parse('{"roles": [], "table_grants": []}')
    assert raw.esito is EsitoCheck.FALLITO


# Il collector system e' basato sul protocollo a verbi del wrapper SSH: i suoi
# test (parsing degli envelope, wrapper come subprocess) stanno in
# test_ssh_contract.py.


# --------------------------------------------------------------------------- #
# L'unico stub: _esegui_live
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "collector",
    [NucleiCollector, SqlmapCollector, SemgrepCollector, PipAuditCollector,
     DbCollector, SystemCollector],
)
def test_esegui_live_e_l_unico_stub(collector):
    with pytest.raises(EsecuzioneLiveNonDisponibile):
        collector()._esegui_live(_ctx())


# --------------------------------------------------------------------------- #
# parse -> normalize end-to-end
# --------------------------------------------------------------------------- #


def test_sqlmap_iniezione_normalizza_in_finding_critico():
    raw = SqlmapCollector().parse(_testo("sqlmap_iniezione.txt"))
    findings = normalizza([raw])
    assert len(findings) == 1
    assert findings[0].severity == "critical" and findings[0].source is Source.SQLMAP


def test_postgres_deviazione_normalizza_in_finding():
    raw = DbCollector().parse(_testo("postgres_deviazione.json"))
    findings = normalizza([raw])
    # le attestazioni conformi diventano finding verdi (low), le deviazioni no
    assert any(f.title.startswith("Deviazione") for f in findings)
