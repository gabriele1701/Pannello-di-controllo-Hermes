"""L'override `compose.assess.yaml` e' uno YAML valido e si fonde col compose
del pannello.

Non e' un test di rete: ``docker compose config`` risolve e valida il modello
senza avviare nulla. Gira in LOCALE (la CI del pannello esegue ``tests/``, non
``assess/tests/``) e si salta da solo dove docker/compose non ci sono.

Due cose che il test fissa:
  * l'override e' strutturalmente valido (merge di reti, bind mount, ipam);
  * ASSESS_TARGET_PASSWORD e ASSESS_DB_DSN sono OPZIONALI: il config risolve
    anche quando NON sono nell'ambiente (erano `:?` obbligatorie, ora `:-`).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]


def _docker_compose_c_e() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        r = subprocess.run(
            ["docker", "compose", "version"],
            capture_output=True, timeout=20, check=False,
        )
        return r.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


pytestmark = pytest.mark.skipif(
    not _docker_compose_c_e(),
    reason="docker compose non disponibile: verifica dell'override solo in locale",
)


def _config(env_extra: dict[str, str]) -> subprocess.CompletedProcess:
    # Le variabili obbligatorie del compose del pannello (`:?`) vanno comunque
    # soddisfatte per risolvere il modello: valori fittizi, non segreti.
    env = {
        "PATH": os.environ.get("PATH", ""),
        "POSTGRES_PASSWORD": "x",
        "HERMES_APP_DB_PASSWORD": "x",
        "APP_SECRET_KEY": "x",
        "HERMES_ADMIN_PASSWORD": "x",
        **env_extra,
    }
    return subprocess.run(
        ["docker", "compose", "-f", "compose.yaml",
         "-f", "assess/compose.assess.yaml", "--profile", "assess",
         "config", "--format", "json"],
        cwd=REPO, env=env, capture_output=True, text=True, timeout=120, check=False,
    )


def test_override_valido_e_creds_opzionali():
    # Di proposito NON si impostano ASSESS_TARGET_PASSWORD ne' ASSESS_DB_DSN:
    # se fossero ancora `:?` obbligatorie, `config` fallirebbe qui.
    r = _config({"VSPT_SUBNET_USCITA": "10.77.42.0/24"})
    assert r.returncode == 0, r.stderr

    doc = json.loads(r.stdout)
    scanner = doc["services"]["scanner"]

    # Creds opzionali risolte a stringa vuota (non un errore).
    assert scanner["environment"]["ASSESS_TARGET_PASSWORD"] == ""
    assert scanner["environment"]["ASSESS_DB_DSN"] == ""

    # I due segreti sono bind mount READ-ONLY verso /run/secrets.
    mnt = {m["target"]: m for m in scanner["volumes"]}
    for t in ("/run/secrets/scanner_ed25519", "/run/secrets/known_hosts"):
        assert mnt[t]["read_only"] is True

    # Lo scanner e' su interna + uscita; la subnet di uscita e' quella fissata.
    assert set(scanner["networks"]) == {"interna", "uscita"}
    reti = doc["networks"]
    assert reti["interna"]["internal"] is True
    assert reti["uscita"]["ipam"]["config"][0]["subnet"] == "10.77.42.0/24"

    # app e db raggiungibili dallo scanner: anche loro su `interna`.
    assert "interna" in doc["services"]["app"]["networks"]
    assert "interna" in doc["services"]["db"]["networks"]


def test_subnet_uscita_obbligatoria():
    # Senza VSPT_SUBNET_USCITA (var `:?`) il config fallisce: fail-closed, una
    # /24 non scelta non e' una /24.
    r = _config({})
    assert r.returncode != 0
    assert "VSPT_SUBNET_USCITA" in (r.stderr + r.stdout)
