"""Credenziali HTTP/DB opzionali, e fail-closed sul canale SSH.

Per il PRIMO test live (solo `system`) l'operatore non deve essere costretto a
compilare login HTTP e DSN del DB: assenti, i relativi collector restano
NOT_RUN, non un errore di caricamento. Il caricamento resta invece fail-closed
sui campi che servono davvero — qui, un ``[ssh]`` dichiarato a meta'.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from assess import config

_BASE = """\
[target]
base_url = "http://app:8000"
allowlist = ["app"]
operator_user = "demo"

[egress]
sentinelle = [["1.1.1.1", 53]]
"""


def _scrivi(tmp_path: Path, testo: str) -> Path:
    p = tmp_path / "scope.toml"
    p.write_text(testo, encoding="utf-8")
    return p


# --- credenziali opzionali ------------------------------------------------- #


def test_carica_senza_credenziali(tmp_path, monkeypatch):
    monkeypatch.delenv("ASSESS_TARGET_PASSWORD", raising=False)
    monkeypatch.delenv("ASSESS_DB_DSN", raising=False)
    cfg = config.carica(_scrivi(tmp_path, _BASE))
    # Carica senza errori, e le credenziali risultano assenti.
    assert cfg.target.password() is None
    assert cfg.target.login_disponibile() is False
    assert cfg.db.dsn() is None


def test_password_e_dsn_risolti_da_env(tmp_path, monkeypatch):
    monkeypatch.setenv("ASSESS_TARGET_PASSWORD", "segreta")
    monkeypatch.setenv("ASSESS_DB_DSN", "postgresql://hermes_assess@db/hermes_panel")
    cfg = config.carica(_scrivi(tmp_path, _BASE))
    assert cfg.target.password() == "segreta"
    assert cfg.target.login_disponibile() is True        # utente demo + password
    assert cfg.db.dsn().startswith("postgresql://")


def test_login_non_disponibile_senza_utente(tmp_path, monkeypatch):
    monkeypatch.setenv("ASSESS_TARGET_PASSWORD", "segreta")
    senza_utente = _BASE.replace('operator_user = "demo"', 'operator_user = ""')
    cfg = config.carica(_scrivi(tmp_path, senza_utente))
    # Password c'e', ma senza operator_user il login HTTP non si costruisce.
    assert cfg.target.login_disponibile() is False


# --- fail-closed sul canale SSH -------------------------------------------- #


def test_ssh_assente_carica(tmp_path):
    cfg = config.carica(_scrivi(tmp_path, _BASE))
    assert cfg.ssh.host == ""  # nessun [ssh]: canale non usato, non un errore


def test_ssh_host_senza_known_hosts_e_errore(tmp_path):
    testo = _BASE + '\n[ssh]\nhost = "vm.local"\nkey_path = "/run/secrets/k"\n'
    with pytest.raises(config.ConfigIncompleta):
        config.carica(_scrivi(tmp_path, testo))


def test_ssh_host_senza_chiave_e_errore(tmp_path):
    testo = _BASE + '\n[ssh]\nhost = "vm.local"\nknown_hosts_path = "/run/secrets/kh"\n'
    with pytest.raises(config.ConfigIncompleta):
        config.carica(_scrivi(tmp_path, testo))


def test_ssh_completo_carica(tmp_path):
    testo = (
        _BASE
        + '\n[ssh]\nhost = "vm.local"\n'
        + 'key_path = "/run/secrets/k"\nknown_hosts_path = "/run/secrets/kh"\n'
    )
    cfg = config.carica(_scrivi(tmp_path, testo))
    assert cfg.ssh.host == "vm.local"
    assert cfg.ssh.key_path and cfg.ssh.known_hosts_path
