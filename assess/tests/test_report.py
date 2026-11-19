"""Report: il JSON valida contro il suo schema, l'HTML nasce dallo stesso JSON.

Due garanzie. La prima: ogni documento prodotto rispetta lo schema 2020-12
dichiarato in ``json_report.SCHEMA`` — il contratto del report verificato con
lo stesso strumento con cui lo si valida. La seconda: l'HTML e' una funzione
pura del JSON, cioe' rigenerarlo dal JSON salvato da' lo stesso risultato, e
non introduce nulla che il JSON non dica.
"""

from __future__ import annotations

from jsonschema import Draft202012Validator

from assess.collectors.base import RunContext
from assess.config import ConfigEgress, ConfigScope, ConfigTarget
from assess.model import EsitoCheck, RawResult, Source
from assess.report import html_report, json_report
from assess.runner import collectors_standard, esegui_run


def _config() -> ConfigScope:
    return ConfigScope(
        target=ConfigTarget(base_url="http://app:8000", allowlist=("app",)),
        egress=ConfigEgress(sentinelle=(("1.1.1.1", 53),)),
    )


def _esecuzione_con_findings(carica_fixture):
    """Un'esecuzione con finding veri, iniettati come collector completati."""

    class _Finto:
        def __init__(self, source, elementi):
            self.name = source.value
            self.source = source
            self.requires = frozenset()
            self.comando = "fixture"
            self._elementi = elementi

        def run(self, ctx):
            return RawResult(
                source=self.source, esito=EsitoCheck.COMPLETATO,
                comando=self.comando, elementi=self._elementi,
            )

    ctx = RunContext(config=_config(), repo_root=".", target="app",
                     base_url="http://app:8000", commit_pannello="deadbee")
    collectors = [
        _Finto(Source.SEMGREP, carica_fixture("semgrep_raw.json")["results"]),
        _Finto(Source.PIP_AUDIT, carica_fixture("pipaudit_raw.json")["dependencies"]),
        _Finto(Source.POSTGRES, carica_fixture("postgres_raw.json")),
        _Finto(Source.SYSTEM, carica_fixture("system_raw.json")),
    ]
    return esegui_run(ctx, collectors, salta_egress=True)


def test_schema_e_valido_di_per_se():
    """Lo schema stesso dev'essere un JSON Schema 2020-12 ben formato."""
    Draft202012Validator.check_schema(json_report.SCHEMA)


def test_documento_con_findings_valida_contro_schema(carica_fixture):
    ex = _esecuzione_con_findings(carica_fixture)
    doc = json_report.documento(ex)
    Draft202012Validator(json_report.SCHEMA).validate(doc)
    assert doc["riepilogo"]["totale"] == len(doc["findings"]) > 0


def test_severity_e_la_banda_nel_json(carica_fixture):
    """La severity nel JSON e' la banda low/medium/high/critical, e non esiste
    piu' un campo 'banda' separato (la severity E' la banda)."""
    ex = _esecuzione_con_findings(carica_fixture)
    doc = json_report.documento(ex)
    bande = {"low", "medium", "high", "critical"}
    assert doc["findings"], "servono finding per il test"
    for f in doc["findings"]:
        assert f["severity"] in bande
        assert "banda" not in f
    # Il riepilogo conta per banda, non per colore.
    assert set(doc["riepilogo"]["per_severita"]) == bande


def test_documento_scaffold_vuoto_valida(carica_fixture):
    """Anche il run tutto-saltato (nessun finding) e' un documento valido, con
    i limiti registrati: un report onesto di 'non ho potuto eseguire' deve
    comunque rispettare il contratto."""
    ctx = RunContext(config=_config(), repo_root=".", http=None, ssh=None, db=None)
    ex = esegui_run(ctx, collectors_standard(), salta_egress=True)
    doc = json_report.documento(ex)
    Draft202012Validator(json_report.SCHEMA).validate(doc)
    assert doc["findings"] == []
    assert len(doc["meta"]["checks"]["saltati"]) == 6
    assert doc["meta"]["limitazioni"]  # i limiti ci sono


def test_html_si_genera_dal_json(carica_fixture):
    ex = _esecuzione_con_findings(carica_fixture)
    doc = json_report.documento(ex)
    html = html_report.render(doc)
    assert html.lstrip().lower().startswith("<!doctype html>")
    # L'HTML riporta un id di finding preso dal JSON, non inventato.
    assert doc["findings"][0]["id"] in html
    # Nessun asset remoto.
    assert "http://" not in html.split("</head>")[0].replace("app:8000", "")
    assert "src=" not in html and "<link" not in html


def test_html_deterministico_round_trip(tmp_path, carica_fixture):
    ex = _esecuzione_con_findings(carica_fixture)
    doc = json_report.documento(ex)
    pj = json_report.scrivi(doc, tmp_path / "report.json")
    # Rigenerato dal JSON riletto == generato dal doc in memoria.
    doc_riletto = json_report.leggi(pj)
    assert html_report.render(doc_riletto) == html_report.render(doc)


def test_html_mostra_i_limiti_in_evidenza(carica_fixture):
    ctx = RunContext(config=_config(), repo_root=".", http=None, ssh=None, db=None)
    ex = esegui_run(ctx, collectors_standard(), salta_egress=True)
    html = html_report.render(json_report.documento(ex))
    assert "Limiti del run" in html
    assert "non" in html and "superato" in html  # il testo di onesta'


def test_json_serializzazione_deterministica(carica_fixture):
    ex = _esecuzione_con_findings(carica_fixture)
    doc = json_report.documento(ex)
    assert json_report.serializza(doc) == json_report.serializza(doc)
    assert json_report.serializza(doc).endswith("\n")
