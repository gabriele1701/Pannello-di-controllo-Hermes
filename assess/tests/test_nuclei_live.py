"""Test del login HTTP e dell'I/O live Nuclei, senza rete reale."""
from __future__ import annotations

from email.message import Message
from pathlib import Path
from unittest.mock import Mock

import pytest

from assess.config import ConfigTarget
from assess.collectors.external_nuclei import NucleiCollector
from assess.collectors.base import RunContext
from assess.config import ConfigEgress, ConfigScope
from assess.inventory.openapi_endpoints import inventario_da_file
from assess.wrappers.http_session import SessioneHttpError, apri_sessione


class _Response:
    status = 200

    def __init__(self, cookie: str):
        self.headers = Message()
        self.headers["Set-Cookie"] = cookie

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self, _):
        return b'{"username":"operatore"}'


def test_login_http_estrae_solo_cookie(monkeypatch):
    import assess.wrappers.http_session as modulo

    chiamate = []

    def fake_open(request, timeout):
        chiamate.append((request, timeout))
        return _Response("hermes_session=abc.def; HttpOnly; Path=/; SameSite=Lax")

    monkeypatch.setattr(modulo.urllib.request, "build_opener", lambda *a: Mock(open=fake_open))
    cfg = ConfigTarget(
        base_url="http://app:8000", allowlist=("app",),
        operator_user="operatore", password_env="TEST_ASSESS_PASSWORD",
    )
    monkeypatch.setenv("TEST_ASSESS_PASSWORD", "password-di-test")
    assert apri_sessione(cfg) == "abc.def"
    request, timeout = chiamate[0]
    assert request.full_url == "http://app:8000/api/auth/login"
    assert request.get_method() == "POST"
    assert timeout == 10
    assert b'"username": "operatore"' in request.data
    assert b'"password": "password-di-test"' in request.data


def test_login_http_senza_password_non_apre_connessione(monkeypatch):
    cfg = ConfigTarget(
        base_url="http://app:8000", allowlist=("app",),
        operator_user="operatore", password_env="TEST_ASSESS_PASSWORD",
    )
    monkeypatch.delenv("TEST_ASSESS_PASSWORD", raising=False)
    assert apri_sessione(cfg) is None


def test_login_http_rifiutato_non_rivela_credenziali(monkeypatch):
    import assess.wrappers.http_session as modulo
    from urllib.error import HTTPError

    def fake_open(*_args, **_kwargs):
        raise HTTPError("http://app:8000/api/auth/login", 401, "Unauthorized", {}, None)

    monkeypatch.setattr(modulo.urllib.request, "build_opener", lambda *a: Mock(open=fake_open))
    cfg = ConfigTarget(
        base_url="http://app:8000", allowlist=("app",),
        operator_user="operatore", password_env="TEST_ASSESS_PASSWORD",
    )
    monkeypatch.setenv("TEST_ASSESS_PASSWORD", "segreto")
    with pytest.raises(SessioneHttpError, match="status 401") as errore:
        apri_sessione(cfg)
    assert "segreto" not in str(errore.value)


def _ctx() -> RunContext:
    root = Path(__file__).resolve().parents[2]
    cfg = ConfigScope(
        target=ConfigTarget(base_url="http://app:8000", allowlist=("app",)),
        egress=ConfigEgress(sentinelle=(("1.1.1.1", 53),)),
    )
    return RunContext(
        config=cfg, repo_root=root, target="app", base_url="http://app:8000",
        inventario=inventario_da_file(root / "openapi.json"), http="cookie.test",
    )


def test_nuclei_live_esegue_solo_template_locali(monkeypatch):
    import assess.collectors.external_nuclei as modulo

    chiamata = {}

    def fake_run(argv, **kwargs):
        chiamata["argv"] = argv
        chiamata["kwargs"] = kwargs
        return Mock(returncode=0, stdout='{"template-id":"fixture"}\n', stderr="")

    monkeypatch.setattr(modulo.shutil, "which", lambda _: "/usr/local/bin/nuclei")
    monkeypatch.setattr(modulo.subprocess, "run", fake_run)
    ctx = _ctx()
    raw = NucleiCollector().run(ctx)
    assert raw.esito.value == "completato"
    assert raw.elementi[0]["template-id"] == "fixture"
    argv = chiamata["argv"]
    assert "-disable-update-check" in argv and "-duc" in argv
    assert "-t" in argv and str(ctx.repo_root / "templates_nuclei") in argv
    assert "Cookie: hermes_session=cookie.test" in argv
    assert chiamata["kwargs"].get("shell", False) is False
    assert chiamata["kwargs"]["timeout"] == 600
    assert chiamata["kwargs"]["cwd"] == ctx.repo_root
