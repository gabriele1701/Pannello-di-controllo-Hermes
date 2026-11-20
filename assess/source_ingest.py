"""Ingest sicuro del sorgente esportato via ``source.export`` (SRC-01).

Il wrapper sulla VM e' la fonte di verita', ma il client **non si fida**
dell'archivio che riceve: lo tratta come dato ostile finche' non ha superato
ogni guardia. In ordine:

1. l'envelope deve essere ``status: ok`` e ``protocol_version == 1``;
2. ``archive_b64`` si decodifica; lo sha256 dell'archivio deve combaciare con
   ``archive_sha256`` — un mismatch e' un **export fallito**, non un sorgente da
   scansionare;
3. l'estrazione avviene in una ``mkdtemp`` dedicata, con ``tarfile`` e
   ``filter="data"`` (niente path assoluti, niente ``..``), applicando cap
   cumulativi su conteggio e byte **durante** l'estrazione (ferma una
   decompression bomb) e rifiutando ogni membro non regolare (symlink, device,
   hardlink);
4. la temp dir viene rimossa a fine uso (context manager);
5. la **provenienza** (timestamp, target_id, percorsi, sha dell'archivio e per
   file, esito) e' registrata per i metadati del run.

Se una qualunque guardia scatta, si solleva ``IngestFallito``: il chiamante lo
traduce in check NOT_RUN/FALLITO, **mai** in un falso "pulito".
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import io
import shutil
import tarfile
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from assess.wrappers.ssh import Envelope

#: Cap di sicurezza lato client (indipendenti da quelli del server: il client
#: non si fida del fatto che il server li abbia rispettati).
MAX_FILES = 2000
MAX_TOTAL_BYTES = 10 * 1024 * 1024


class IngestFallito(Exception):
    """L'ingest e' fallito a una delle guardie. ``code`` nomina quale."""

    def __init__(self, messaggio: str, code: str) -> None:
        super().__init__(messaggio)
        self.code = code


@dataclass(slots=True)
class Provenienza:
    """Da dove viene il sorgente scansionato, per i metadati del run."""

    esito: str
    archive_sha256: str
    target_id: str | None
    timestamp: str | None
    exported_paths: list[str] = field(default_factory=list)
    file_count: int = 0
    files: list[dict[str, Any]] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return {
            "esito": self.esito,
            "archive_sha256": self.archive_sha256,
            "target_id": self.target_id,
            "timestamp": self.timestamp,
            "exported_paths": list(self.exported_paths),
            "file_count": self.file_count,
            "files": list(self.files),
        }


@dataclass(slots=True)
class SorgenteEstratto:
    percorso: Path
    provenienza: Provenienza


def _verifica_archivio(env: Envelope) -> bytes:
    """Guardie 1-2: envelope ok, decodifica, sha256. Restituisce i byte."""
    if not env.ok:
        raise IngestFallito(
            f"source.export non riuscito: {env.codice_errore}",
            env.codice_errore or "EXPORT_ERROR",
        )
    if env.protocol_version != 1:
        raise IngestFallito("protocol_version inattesa", "PROTOCOL_MISMATCH")
    data = env.data or {}
    atteso = data.get("archive_sha256")
    b64 = data.get("archive_b64")
    if not isinstance(b64, str) or not isinstance(atteso, str):
        raise IngestFallito("envelope SRC-01 senza archivio", "ARCHIVE_MANCANTE")
    try:
        archivio = base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise IngestFallito(f"base64 non valido: {exc}", "ARCHIVE_DECODE_FAILED") from exc
    if hashlib.sha256(archivio).hexdigest() != atteso:
        raise IngestFallito(
            "archive_sha256 non combacia: export trattato come fallito",
            "ARCHIVE_SHA256_MISMATCH",
        )
    return archivio


def _estrai_sicuro(
    archivio: bytes, dest: Path, *, max_files: int, max_total_bytes: int
) -> None:
    """Guardia 3: estrazione con filter='data', cap cumulativi, solo regolari."""
    try:
        tar = tarfile.open(fileobj=io.BytesIO(archivio), mode="r:gz")
    except tarfile.TarError as exc:
        raise IngestFallito(f"archivio illeggibile: {exc}", "ARCHIVE_ILLEGGIBILE") from exc
    with tar:
        conteggio = 0
        totale = 0
        for membro in tar:
            if membro.isdir():
                continue  # le directory le crea l'estrazione dei file
            if not membro.isreg():
                raise IngestFallito(
                    f"membro non regolare rifiutato: {membro.name} ({membro.type!r})",
                    "MEMBRO_NON_REGOLARE",
                )
            conteggio += 1
            if conteggio > max_files:
                raise IngestFallito("troppi file nell'archivio", "TROPPI_FILE")
            totale += max(membro.size, 0)
            if totale > max_total_bytes:
                raise IngestFallito(
                    "archivio oltre il cap di byte (possibile bomb)", "TROPPI_BYTE"
                )
            try:
                tar.extract(membro, dest, filter="data")
            except (tarfile.TarError, OSError) as exc:
                # Il data filter rifiuta traversal/path assoluti/link pericolosi.
                raise IngestFallito(
                    f"estrazione rifiutata per {membro.name}: {exc}", "ESTRAZIONE_RIFIUTATA"
                ) from exc


@contextmanager
def sorgente_da_envelope(
    env: Envelope,
    *,
    max_files: int = MAX_FILES,
    max_total_bytes: int = MAX_TOTAL_BYTES,
) -> Iterator[SorgenteEstratto]:
    """Estrae in sicurezza il sorgente da un envelope SRC-01 e lo espone come
    directory temporanea, rimossa all'uscita. Solleva ``IngestFallito`` se una
    guardia scatta."""
    archivio = _verifica_archivio(env)
    data = env.data or {}
    tmp = Path(tempfile.mkdtemp(prefix="vspt-src-"))
    try:
        _estrai_sicuro(
            archivio, tmp, max_files=max_files, max_total_bytes=max_total_bytes
        )
        provenienza = Provenienza(
            esito="ok",
            archive_sha256=data.get("archive_sha256", ""),
            target_id=data.get("target_id"),
            timestamp=data.get("timestamp"),
            exported_paths=list(data.get("exported_paths", [])),
            file_count=int(data.get("file_count", 0)),
            files=list(data.get("files", [])),
        )
        yield SorgenteEstratto(percorso=tmp, provenienza=provenienza)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


__all__ = [
    "IngestFallito",
    "MAX_FILES",
    "MAX_TOTAL_BYTES",
    "Provenienza",
    "SorgenteEstratto",
    "sorgente_da_envelope",
]
