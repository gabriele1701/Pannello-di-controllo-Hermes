"""Trasporto SSH live del collector `system` — senza connessione reale.

La connessione vera la prova Gabriele sulla VM; qui si verifica, con
``subprocess`` mockato: la costruzione dell'argv con le opzioni di hardening, la
gestione dei guasti (nessun envelope / timeout -> errore chiaro, mai un finto
esito), e che ``_esegui_live`` riunisca le tre righe per il ``parse`` esistente.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

import assess.wrappers.ssh as sshmod
from assess.collectors.base import RunContext
from assess.collectors.internal_system import SystemCollector, VERBI
from assess.config import ConfigEgress, ConfigScope, ConfigSsh, ConfigTarget
from assess.model import EsitoCheck
from assess.wrappers.ssh import TrasportoSshFallito, WrapperSsh

FIXTURES = Path(__file__).parent / "fixtures"


def _wrapper() -> WrapperSsh:
    return WrapperSsh(ConfigSsh(
        host="vm.local", user="assess",
        key_path="/run/secrets/scanner_ed25519",
        known_hosts_path="/run/secrets/known_hosts",
    ))


class _Completed:
    def __init__(self, stdout="", stderr="", returncode=0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


def _mock_run(monkeypatch, risultato=None, eccezione=None):
    def finto(argv, **kw):
        if eccezione is not None:
            raise eccezione
        return risultato
    monkeypatch.setattr(sshmod.subprocess, "run", finto)


# --------------------------------------------------------------------------- #
# Costruzione argv: opzioni di hardening, verbo come singolo argomento
# --------------------------------------------------------------------------- #


def test_argv_ha_le_opzioni_di_hardening():
    argv = _wrapper()._argv("system.info")
    assert argv[0] == "ssh"
    # chiave dedicata
    assert "-i" in argv and "/run/secrets/scanner_ed25519" in argv
    # opzioni di sicurezza
    testo = " ".join(argv)
    for opt in (
        "BatchMode=yes", "IdentitiesOnly=yes", "StrictHostKeyChecking=yes",
        "UserKnownHostsFile=/run/secrets/known_hosts", "ConnectTimeout=10",
    ):
        assert opt in testo, opt
    # destinazione e verbo come ULTIMO singolo argomento (niente shell)
    assert "assess@vm.local" in argv
    assert argv[-1] == "system.info"


def test_verbo_e_un_singolo_argv():
    # Un "verbo" con metacaratteri resta un unico elemento: nessuna injection.
    argv = _wrapper()._argv("system.processes; id")
    assert argv[-1] == "system.processes; id"
    assert argv.count("system.processes; id") == 1


# --------------------------------------------------------------------------- #
# _invia: successo e guasti
# --------------------------------------------------------------------------- #


def test_invia_ritorna_la_prima_riga_non_vuota(monkeypatch):
    envelope = '{"protocol_version":1,"check_id":"SYS-01","status":"ok","data":{},"error":null}'
    _mock_run(monkeypatch, _Completed(stdout=f"\n{envelope}\nrumore\n"))
    assert _wrapper()._invia("system.info") == envelope


def test_invia_stdout_vuoto_e_fallito(monkeypatch):
    _mock_run(monkeypatch, _Completed(stdout="", stderr="connection refused", returncode=255))
    with pytest.raises(TrasportoSshFallito):
        _wrapper()._invia("system.info")


def test_invia_nonzero_ma_con_envelope_ritorna_la_riga(monkeypatch):
    # Il wrapper puo' rispondere con un envelope di errore ed exit non-zero
    # (es. COMMAND_NOT_ALLOWED, exit 126): il trasporto NON fallisce, e' il
    # parser a giudicare l'envelope.
    envelope = '{"protocol_version":1,"check_id":"UNKNOWN","status":"error","data":null,"error":{"code":"COMMAND_NOT_ALLOWED"}}'
    _mock_run(monkeypatch, _Completed(stdout=envelope + "\n", returncode=126))
    assert _wrapper()._invia("system.info") == envelope


def test_invia_timeout_e_fallito(monkeypatch):
    _mock_run(monkeypatch, eccezione=subprocess.TimeoutExpired(cmd="ssh", timeout=30))
    with pytest.raises(TrasportoSshFallito):
        _wrapper()._invia("system.listeners")


def test_invia_ssh_assente_e_fallito(monkeypatch):
    _mock_run(monkeypatch, eccezione=FileNotFoundError("ssh"))
    with pytest.raises(TrasportoSshFallito):
        _wrapper()._invia("system.info")


# --------------------------------------------------------------------------- #
# _esegui_live: riunisce le tre righe per il parse esistente
# --------------------------------------------------------------------------- #


class _WrapperFinto:
    """Un wrapper che restituisce righe envelope prese dalle fixture; alcuni
    verbi possono fallire il trasporto."""

    def __init__(self, mappa, falliscono=()):
        self._mappa = mappa
        self._falliscono = set(falliscono)

    def riga_grezza(self, verbo):
        if verbo in self._falliscono:
            raise TrasportoSshFallito(f"trasporto fallito per {verbo}")
        return (FIXTURES / self._mappa[verbo]).read_text(encoding="utf-8").strip()


def _ctx(wrapper) -> RunContext:
    cfg = ConfigScope(
        target=ConfigTarget(base_url="http://app:8000", allowlist=("app",)),
        egress=ConfigEgress(sentinelle=(("1.1.1.1", 53),)),
    )
    return RunContext(config=cfg, repo_root=Path("."), ssh=wrapper)


_MAPPA = {
    "system.info": "sys01_ok.json",
    "system.listeners": "sys02_ok.json",
    "system.processes": "sys03_ok.json",
}


def test_esegui_live_tre_verbi_poi_parse():
    raw = SystemCollector().run(_ctx(_WrapperFinto(_MAPPA)))
    assert raw.esito is EsitoCheck.COMPLETATO
    porte = [a for a in raw.elementi if a["controllo"].startswith("porta")]
    assert len(porte) == 3 and any(not a["conforme"] for a in porte)  # 6379 inattesa


def test_esegui_live_unisce_le_righe_nell_ordine_dei_verbi():
    grezzo = SystemCollector()._esegui_live(_ctx(_WrapperFinto(_MAPPA)))
    righe = grezzo.splitlines()
    assert len(righe) == 3
    import json
    assert [json.loads(r)["check_id"] for r in righe] == ["SYS-01", "SYS-02", "SYS-03"]


def test_esegui_live_listeners_trasporto_fallito_e_check_fallito():
    # SYS-02 non arriva: la riga manca, e parse (gia' testato) -> FALLITO.
    wrapper = _WrapperFinto(_MAPPA, falliscono=["system.listeners"])
    raw = SystemCollector().run(_ctx(wrapper))
    assert raw.esito is EsitoCheck.FALLITO


def test_esegui_live_tutti_falliscono_e_check_fallito():
    wrapper = _WrapperFinto(_MAPPA, falliscono=VERBI)
    raw = SystemCollector().run(_ctx(wrapper))
    assert raw.esito is EsitoCheck.FALLITO
