"""Verbo source.export del wrapper, invocato come subprocess (come sshd).

Allowlist di contenuto, integrità dell'archivio, cap, e il giro completo
export → client → ingest sicuro. Il wrapper gira con ``VSPT_SOURCE_ROOT`` su una
radice finta (configurazione del server, non input del client).
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

from assess.source_ingest import sorgente_da_envelope
from assess.wrappers.ssh import leggi_envelope

RADICE = Path(__file__).resolve().parents[2]
WRAPPER = RADICE / "assess" / "ssh" / "vspt-ssh-wrapper"


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
