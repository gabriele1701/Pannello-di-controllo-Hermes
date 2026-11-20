"""Contratto SSH: client, collector e wrapper, allineati a PROTOCOL.md.

Tre livelli, tutti senza VM:

* **client** (`assess/wrappers/ssh.py`): parsing e validazione dell'envelope;
* **collector** (`internal_system`): dai tre envelope alle attestazioni;
* **wrapper** (`assess/ssh/vspt-ssh-wrapper`): invocato come **subprocess** con
  `SSH_ORIGINAL_COMMAND`, non importato — è lo stesso modo in cui `sshd` lo usa.

Il wrapper è la fonte di verità: questi test verificano che il repo (client +
collector) parli il suo stesso contratto.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from assess.collectors.internal_system import SystemCollector
from assess.config import ConfigSsh
from assess.model import EsitoCheck, Source
from assess.normalize import normalizza
from assess.wrappers.ssh import (
    Envelope,
    ProtocolloNonValido,
    WrapperSsh,
    leggi_envelope,
)

RADICE = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).parent / "fixtures"
WRAPPER = RADICE / "assess" / "ssh" / "vspt-ssh-wrapper"


def _riga(nome: str) -> str:
    return (FIXTURES / nome).read_text(encoding="utf-8").strip()


# --------------------------------------------------------------------------- #
# Client: parsing e validazione dell'envelope
# --------------------------------------------------------------------------- #


def test_client_envelope_ok():
    env = leggi_envelope(_riga("sys01_ok.json"))
    assert isinstance(env, Envelope)
    assert env.ok and env.check_id == "SYS-01"
    assert env.data["python_version"] and env.error is None


def test_client_envelope_error():
    env = leggi_envelope(_riga("sys02_error.json"))
    assert not env.ok and env.status == "error"
    assert env.codice_errore == "LISTENER_COMMAND_FAILED" and env.data is None


def test_client_protocol_version_sbagliata_rifiutata():
    with pytest.raises(ProtocolloNonValido):
        leggi_envelope('{"protocol_version":2,"check_id":"SYS-01","status":"ok","data":{},"error":null}')


def test_client_malformato_rifiutato():
    with pytest.raises(ProtocolloNonValido):
        leggi_envelope("non json")


@pytest.mark.parametrize(
    "riga",
    [
        '{"protocol_version":1,"check_id":"SYS-01","status":"boh","data":{},"error":null}',
        '{"protocol_version":1,"status":"ok","data":{},"error":null}',  # no check_id
        '[1,2,3]',
    ],
)
def test_client_envelope_invalidi_rifiutati(riga):
    with pytest.raises(ProtocolloNonValido):
        leggi_envelope(riga)


def test_client_esegui_verbo_non_ammesso():
    w = WrapperSsh(ConfigSsh(host="vm", user="assess"))
    with pytest.raises(ValueError):
        w.esegui("rm -rf /")


def test_client_esegui_passa_dal_trasporto(monkeypatch):
    # Il trasporto live e' ora implementato (vedi test_ssh_live). Qui basta che
    # esegui() di un verbo ammesso arrivi al trasporto: con subprocess mockato
    # (nessun I/O reale) l'envelope torna e viene parsato.
    import assess.wrappers.ssh as sshmod

    envelope = '{"protocol_version":1,"check_id":"SYS-02","status":"ok","data":{"listeners":[],"count":0,"process_visibility":"limited","limitations":[]},"error":null}'

    class _C:
        stdout = envelope + "\n"
        stderr = ""
        returncode = 0

    monkeypatch.setattr(sshmod.subprocess, "run", lambda *a, **k: _C())
    w = WrapperSsh(ConfigSsh(
        host="vm", user="assess",
        key_path="/run/secrets/k", known_hosts_path="/run/secrets/kh",
    ))
    env = w.esegui("system.listeners")
    assert env.ok and env.check_id == "SYS-02"


# --------------------------------------------------------------------------- #
# Collector: dai tre envelope alle attestazioni
# --------------------------------------------------------------------------- #


def _tre_verbi(sys02_fixture: str) -> str:
    return "\n".join([
        _riga("sys01_ok.json"), _riga(sys02_fixture), _riga("sys03_ok.json")
    ])


def test_collector_tre_verbi_ok():
    raw = SystemCollector().parse(_tre_verbi("sys02_ok.json"))
    assert raw.esito is EsitoCheck.COMPLETATO
    porte = [a for a in raw.elementi if a["controllo"].startswith("porta")]
    inattese = [a for a in porte if not a["conforme"]]
    assert len(porte) == 3 and len(inattese) == 1 and "6379" in inattese[0]["bersaglio"]
    # contesto da SYS-01 e SYS-03
    assert any("identita'" in a["controllo"] for a in raw.elementi)
    assert any("processi" in a["controllo"] for a in raw.elementi)


def test_collector_listeners_error_e_fallito():
    raw = SystemCollector().parse(_tre_verbi("sys02_error.json"))
    assert raw.esito is EsitoCheck.FALLITO
    assert "LISTENER_COMMAND_FAILED" in raw.nota


def test_collector_listeners_vuoto_e_completato_a_zero():
    raw = SystemCollector().parse(_tre_verbi("sys02_vuoto.json"))
    assert raw.esito is EsitoCheck.COMPLETATO
    porte = [a for a in raw.elementi if a["controllo"].startswith("porta")]
    assert porte == []
    assert "controllo positivo" in raw.nota


def test_collector_solo_listeners_vuoto_senza_contesto():
    raw = SystemCollector().parse(_riga("sys02_vuoto.json"))
    assert raw.esito is EsitoCheck.COMPLETATO and raw.elementi == []


def test_collector_envelope_malformato_e_fallito():
    assert SystemCollector().parse("non e' un envelope").esito is EsitoCheck.FALLITO


def test_collector_deviazione_normalizza_in_finding():
    raw = SystemCollector().parse(_tre_verbi("sys02_ok.json"))
    findings = normalizza([raw])
    assert any(f.title.startswith("Deviazione") and f.source is Source.SYSTEM for f in findings)


# --------------------------------------------------------------------------- #
# Wrapper come subprocess (non importato): è come lo invoca sshd
# --------------------------------------------------------------------------- #


def _invoca(verbo: str) -> tuple[dict, int]:
    out = subprocess.run(
        [sys.executable, str(WRAPPER)],
        env={**__import__("os").environ, "SSH_ORIGINAL_COMMAND": verbo},
        capture_output=True, text=True, timeout=20, check=False,
    )
    riga = out.stdout.strip().splitlines()[0]
    return json.loads(riga), out.returncode


@pytest.mark.parametrize(
    "verbo,check_id",
    [("system.info", "SYS-01"), ("system.listeners", "SYS-02"),
     ("system.processes", "SYS-03")],
)
def test_wrapper_verbi_ammessi(verbo, check_id):
    env, code = _invoca(verbo)
    assert env["protocol_version"] == 1
    assert env["check_id"] == check_id
    assert env["status"] in ("ok", "error")
    # exit coerente con lo status: ok->0, error->1
    assert code == (0 if env["status"] == "ok" else 1)


@pytest.mark.parametrize("verbo", ["pippo", "system.processes; id", "cat /etc/shadow", ""])
def test_wrapper_verbi_negati(verbo):
    env, code = _invoca(verbo)
    assert code == 126
    assert env["status"] == "error"
    assert env["error"]["code"] == "COMMAND_NOT_ALLOWED"
