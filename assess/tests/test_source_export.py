"""Verbo source.export del wrapper, invocato come subprocess (come sshd).

Allowlist di contenuto, integrità dell'archivio, cap, e il giro completo
export → client → ingest sicuro. Il wrapper gira con ``VSPT_SOURCE_ROOT`` su una
radice finta (configurazione del server, non input del client).
"""

from __future__ import annotations

import base64
import hashlib
import importlib.machinery
import importlib.util
import io
import json
import os
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

from assess.config import ConfigSsh
from assess.source_ingest import sorgente_da_envelope
from assess.wrappers.ssh import Envelope, VERBI, WrapperSsh, leggi_envelope

RADICE = Path(__file__).resolve().parents[2]
WRAPPER = RADICE / "assess" / "ssh" / "vspt-ssh-wrapper"


def _carica_wrapper():
    """Carica vspt-ssh-wrapper (senza estensione .py) come modulo, per i test
    unitari che devono simulare errori di I/O che da root non si riproducono."""
    loader = importlib.machinery.SourceFileLoader("vspt_wrapper", str(WRAPPER))
    spec = importlib.util.spec_from_loader("vspt_wrapper", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


@pytest.fixture
def sorgente_finto(tmp_path: Path) -> Path:
    """Una radice /opt/pannello finta: backend con py + roba da escludere."""
    (tmp_path / "backend" / "routers").mkdir(parents=True)
    (tmp_path / "backend" / "static").mkdir()
    (tmp_path / "backend" / "__pycache__").mkdir()
    (tmp_path / "backend" / "main.py").write_text("x = 1\n")
    (tmp_path / "backend" / "routers" / "scope.py").write_text("y = 2\n")
    (tmp_path / "backend" / "__pycache__" / "main.pyc").write_text("cache\n")
    (tmp_path / "backend" / "static" / "app.py").write_text("junk\n")  # py ma sotto static
    (tmp_path / "requirements.txt").write_text("fastapi==1\n")
    (tmp_path / "pyproject.toml").write_text("[project]\n")
    (tmp_path / "secret.txt").write_text("SEGRETO\n")  # fuori allowlist
    # symlink malevolo dentro backend
    try:
        (tmp_path / "backend" / "evil.py").symlink_to("/etc/passwd")
    except OSError:
        pass
    return tmp_path


def _export(root: Path, **env_extra) -> tuple[dict, int]:
    env = {**os.environ, "SSH_ORIGINAL_COMMAND": "source.export",
           "VSPT_SOURCE_ROOT": str(root)}
    env.update(env_extra)
    out = subprocess.run(
        [sys.executable, str(WRAPPER)],
        env=env, capture_output=True, text=True, timeout=30, check=False,
    )
    return json.loads(out.stdout.strip().splitlines()[0]), out.returncode


def test_export_allowlist_solo_py_backend_e_manifest(sorgente_finto):
    env, code = _export(sorgente_finto)
    assert code == 0 and env["status"] == "ok" and env["check_id"] == "SRC-01"
    paths = {f["path"] for f in env["data"]["files"]}
    assert paths == {
        "backend/main.py", "backend/routers/scope.py",
        "requirements.txt", "pyproject.toml",
    }
    # esclusi: static/, __pycache__/.pyc, symlink, fuori allowlist
    assert not any("static" in p or ".pyc" in p or "evil" in p or "secret" in p
                   for p in paths)


def test_export_integrita_archivio(sorgente_finto):
    env, _ = _export(sorgente_finto)
    d = env["data"]
    arc = base64.b64decode(d["archive_b64"])
    assert hashlib.sha256(arc).hexdigest() == d["archive_sha256"]
    assert len(arc) == d["byte_size"]
    assert d["file_count"] == len(d["files"])
    tar = tarfile.open(fileobj=io.BytesIO(arc))
    assert all(m.isreg() for m in tar.getmembers())  # solo file regolari
    assert d["format"] == "tar.gz" and d["target_id"] and d["timestamp"]


def test_export_cap_byte_supera(sorgente_finto):
    env, code = _export(sorgente_finto, VSPT_MAX_TOTAL_BYTES="5")
    assert code == 1 and env["status"] == "error"
    assert env["error"]["code"] == "EXPORT_LIMIT_EXCEEDED"


def test_export_cap_file_supera(sorgente_finto):
    env, code = _export(sorgente_finto, VSPT_MAX_FILES="1")
    assert code == 1 and env["error"]["code"] == "EXPORT_LIMIT_EXCEEDED"


def test_export_poi_ingest_end_to_end(sorgente_finto):
    env_dict, _ = _export(sorgente_finto)
    envelope = leggi_envelope(json.dumps(env_dict))
    with sorgente_da_envelope(envelope) as s:
        estratti = sorted(
            p.relative_to(s.percorso).as_posix()
            for p in s.percorso.rglob("*") if p.is_file()
        )
        assert estratti == [
            "backend/main.py", "backend/routers/scope.py",
            "pyproject.toml", "requirements.txt",
        ]
        assert (s.percorso / "backend" / "main.py").read_text() == "x = 1\n"
        assert s.provenienza.esito == "ok"
        assert s.provenienza.file_count == 4


# --------------------------------------------------------------------------- #
# FIX 1 — il client ammette il verbo source.export
# --------------------------------------------------------------------------- #


def test_fix1_client_ammette_source_export(monkeypatch):
    # NON deve sollevare ValueError ("verbo non ammesso"): il verbo e' in VERBI
    # e la chiamata arriva al trasporto. Con subprocess mockato (nessun I/O
    # reale) l'envelope torna e viene parsato: nessun ValueError.
    import assess.wrappers.ssh as sshmod

    envelope = '{"protocol_version":1,"check_id":"SRC-01","status":"error","data":null,"error":{"code":"EXPORT_READ_ERROR"}}'

    class _C:
        stdout = envelope + "\n"
        stderr = ""
        returncode = 1

    monkeypatch.setattr(sshmod.subprocess, "run", lambda *a, **k: _C())
    w = WrapperSsh(ConfigSsh(
        host="vm", user="assess",
        key_path="/run/secrets/k", known_hosts_path="/run/secrets/kh",
    ))
    assert isinstance(w.esegui("source.export"), Envelope)
    assert "source.export" in VERBI


# --------------------------------------------------------------------------- #
# FIX 2 — un file oltre il cap non viene caricato intero
# --------------------------------------------------------------------------- #


def test_fix2_file_oltre_cap_e_limite(sorgente_finto):
    (sorgente_finto / "backend" / "grande.py").write_bytes(b"A" * 200_000)
    env, code = _export(sorgente_finto, VSPT_MAX_TOTAL_BYTES="1000")
    assert code == 1 and env["status"] == "error"
    assert env["error"]["code"] == "EXPORT_LIMIT_EXCEEDED"


def test_fix2_non_carica_il_file_intero(tmp_path, monkeypatch, capsys):
    """Coglie il bounded: un file enorme viene letto al massimo per (residuo+1)
    byte, mai intero. Senza il fix, read() sarebbe chiamato senza limite."""
    import builtins

    w = _carica_wrapper()
    (tmp_path / "backend").mkdir()
    (tmp_path / "backend" / "grande.py").write_bytes(b"A" * 5_000_000)
    monkeypatch.setattr(w, "SOURCE_ROOT", str(tmp_path))
    monkeypatch.setattr(w, "MAX_TOTAL_BYTES", 1000)

    letture: list[int] = []
    apri_reale = builtins.open

    class _Spia:
        def __init__(self, handle):
            self._handle = handle

        def read(self, n=-1):
            letture.append(n)
            return self._handle.read(n)

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            self._handle.close()

    def apri_spia(percorso, *a, **k):
        reale = apri_reale(percorso, *a, **k)
        return _Spia(reale) if str(percorso).endswith("grande.py") else reale

    monkeypatch.setattr(builtins, "open", apri_spia)
    codice = w.source_export()
    monkeypatch.setattr(builtins, "open", apri_reale)

    envelope = json.loads(capsys.readouterr().out.strip())
    assert codice == w.EXIT_ERROR
    assert envelope["error"]["code"] == "EXPORT_LIMIT_EXCEEDED"
    # Letto una sola volta, con un limite = residuo+1 = 1001, MAI read(-1).
    assert letture == [1001]


# --------------------------------------------------------------------------- #
# FIX 3 — un export incompleto non si dichiara ok (test unitari, no root bypass)
# --------------------------------------------------------------------------- #


def test_fix3_file_selezionato_illeggibile_e_export_fallito(tmp_path, monkeypatch, capsys):
    w = _carica_wrapper()
    (tmp_path / "backend").mkdir()
    (tmp_path / "backend" / "main.py").write_text("x = 1\n")
    monkeypatch.setattr(w, "SOURCE_ROOT", str(tmp_path))
    originale = w.os.lstat

    def lstat_che_nega(percorso, *a, **k):
        if str(percorso).endswith("main.py"):
            raise PermissionError("permesso negato")
        return originale(percorso, *a, **k)

    monkeypatch.setattr(w.os, "lstat", lstat_che_nega)
    codice = w.source_export()
    envelope = json.loads(capsys.readouterr().out.strip())
    assert codice == w.EXIT_ERROR
    assert envelope["status"] == "error"
    assert envelope["error"]["code"] == "EXPORT_READ_ERROR"


def test_fix3_errore_scansione_directory_propaga(tmp_path, monkeypatch):
    w = _carica_wrapper()

    def walk_con_errore(top, followlinks=True, onerror=None):
        if onerror is not None:
            onerror(PermissionError("scansione negata"))
        return iter([])

    monkeypatch.setattr(w.os, "walk", walk_con_errore)
    with pytest.raises(PermissionError):
        list(w.iter_source_files(str(tmp_path), lambda: False))


def test_fix3_symlink_saltato_export_ok(sorgente_finto):
    # Controprova: un symlink NON e' un guasto, si salta e l'export resta ok.
    env, code = _export(sorgente_finto)
    assert code == 0 and env["status"] == "ok"
    assert not any("evil" in f["path"] for f in env["data"]["files"])
