"""Ingest sicuro del sorgente: esercita il guasto, non solo l'assenza.

Un archivio benigno viene estratto e la provenienza registrata; un archivio
ostile — path traversal, symlink malevolo, decompression bomb/oversize, troppi
file, sha256 non combaciante — viene **rifiutato** con un codice esplicito, e la
temp dir viene sempre rimossa.
"""

from __future__ import annotations

import base64
import hashlib
import io
import tarfile

import pytest

from assess.source_ingest import IngestFallito, sorgente_da_envelope
from assess.wrappers.ssh import Envelope


def _envelope(archivio: bytes, **override) -> Envelope:
    data = {
        "format": "tar.gz",
        "archive_b64": base64.b64encode(archivio).decode("ascii"),
        "archive_sha256": hashlib.sha256(archivio).hexdigest(),
        "byte_size": len(archivio),
        "file_count": 0,
        "files": [],
        "exported_paths": ["backend/ (*.py)", "requirements.txt"],
        "target_id": "vm",
        "timestamp": "2026-11-20T00:00:00+00:00",
    }
    data.update(override)
    return Envelope(1, "SRC-01", "ok", data, None)


def _tar(membri: list[tuple[tarfile.TarInfo, bytes | None]]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for info, blob in membri:
            tar.addfile(info, io.BytesIO(blob) if blob is not None else None)
    return buf.getvalue()


def _reg(name: str, data: bytes = b"x = 1\n") -> tuple[tarfile.TarInfo, bytes]:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.type = tarfile.REGTYPE
    return info, data


# --------------------------------------------------------------------------- #
# Benigno
# --------------------------------------------------------------------------- #


def test_archivio_benigno_estratto_e_provenienza():
    arc = _tar([_reg("backend/main.py"), _reg("requirements.txt", b"fastapi==1\n")])
    env = _envelope(
        arc, file_count=2,
        files=[{"path": "backend/main.py", "sha256": "a", "size": 6}],
    )
    with sorgente_da_envelope(env) as s:
        estratti = sorted(
            p.relative_to(s.percorso).as_posix()
            for p in s.percorso.rglob("*") if p.is_file()
        )
        assert estratti == ["backend/main.py", "requirements.txt"]
        assert s.provenienza.esito == "ok"
        assert s.provenienza.target_id == "vm"
        assert s.provenienza.archive_sha256 == env.data["archive_sha256"]
        assert s.provenienza.file_count == 2
        assert s.provenienza.to_json()["exported_paths"]
        temp = s.percorso
    # pulizia a fine uso
    assert not temp.exists()


# --------------------------------------------------------------------------- #
# Guasti rifiutati
# --------------------------------------------------------------------------- #


def test_path_traversal_rifiutato():
    arc = _tar([_reg("../evil.py")])
    with pytest.raises(IngestFallito) as exc:
        with sorgente_da_envelope(_envelope(arc)):
            pass
    assert exc.value.code in ("ESTRAZIONE_RIFIUTATA", "MEMBRO_NON_REGOLARE")


def test_symlink_malevolo_rifiutato():
    info = tarfile.TarInfo("link.py")
    info.type = tarfile.SYMTYPE
    info.linkname = "/etc/passwd"
    arc = _tar([(info, None)])
    with pytest.raises(IngestFallito) as exc:
        with sorgente_da_envelope(_envelope(arc)):
            pass
    assert exc.value.code == "MEMBRO_NON_REGOLARE"


def test_hardlink_rifiutato():
    info = tarfile.TarInfo("hard.py")
    info.type = tarfile.LNKTYPE
    info.linkname = "backend/main.py"
    arc = _tar([_reg("backend/main.py"), (info, None)])
    with pytest.raises(IngestFallito):
        with sorgente_da_envelope(_envelope(arc)):
            pass


def test_oversize_bomb_rifiutato():
    arc = _tar([_reg("backend/big.py", b"A" * 5000)])
    with pytest.raises(IngestFallito) as exc:
        with sorgente_da_envelope(_envelope(arc), max_total_bytes=1000):
            pass
    assert exc.value.code == "TROPPI_BYTE"


def test_troppi_file_rifiutato():
    arc = _tar([_reg(f"backend/f{i}.py") for i in range(5)])
    with pytest.raises(IngestFallito) as exc:
        with sorgente_da_envelope(_envelope(arc), max_files=3):
            pass
    assert exc.value.code == "TROPPI_FILE"


def test_sha256_non_combaciante_e_export_fallito():
    arc = _tar([_reg("backend/main.py")])
    with pytest.raises(IngestFallito) as exc:
        with sorgente_da_envelope(_envelope(arc, archive_sha256="deadbeef")):
            pass
    assert exc.value.code == "ARCHIVE_SHA256_MISMATCH"


def test_base64_non_valido_rifiutato():
    env = Envelope(1, "SRC-01", "ok",
                   {"archive_b64": "non-base64!!", "archive_sha256": "x"}, None)
    with pytest.raises(IngestFallito) as exc:
        with sorgente_da_envelope(env):
            pass
    assert exc.value.code == "ARCHIVE_DECODE_FAILED"


def test_envelope_error_e_ingest_fallito():
    env = Envelope(1, "SRC-01", "error", None, {"code": "EXPORT_LIMIT_EXCEEDED"})
    with pytest.raises(IngestFallito) as exc:
        with sorgente_da_envelope(env):
            pass
    assert exc.value.code == "EXPORT_LIMIT_EXCEEDED"


def test_temp_dir_rimossa_anche_su_guasto():
    # Anche quando l'estrazione fallisce, non resta spazzatura in /tmp.
    import glob
    import tempfile
    prima = set(glob.glob(f"{tempfile.gettempdir()}/vspt-src-*"))
    arc = _tar([_reg("../evil.py")])
    with pytest.raises(IngestFallito):
        with sorgente_da_envelope(_envelope(arc)):
            pass
    dopo = set(glob.glob(f"{tempfile.gettempdir()}/vspt-src-*"))
    assert dopo <= prima  # nessuna nuova temp dir rimasta
