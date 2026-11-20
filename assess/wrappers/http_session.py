"""Login HTTP dell'operatore per i collector black-box.

Usa solo la standard library. Il target e' gia' stato validato dalla scope
allowlist; redirect disabilitati e proxy ambientali ignorati per non lasciare
che una credenziale venga inviata a un'origine diversa.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from http.cookies import SimpleCookie
from urllib.parse import urlsplit

from assess.config import ConfigTarget


class SessioneHttpError(RuntimeError):
    """Login fallito o risposta non valida: il cookie non viene mai esposto."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def apri_sessione(target: ConfigTarget) -> str | None:
    """Esegue POST /api/auth/login e restituisce il cookie hermes_session.

    Se le credenziali non sono configurate restituisce None: il collector
    esterno verra' saltato dai requisiti del RunContext.
    """
    password = target.password()
    if not target.operator_user or not password:
        return None

    parsed = urlsplit(target.base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise SessioneHttpError("base_url non valida per il login HTTP")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise SessioneHttpError("base_url contiene componenti non ammesse")

    url = target.base_url.rstrip("/") + "/api/auth/login"
    payload = json.dumps(
        {"username": target.operator_user, "password": password}
    ).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), _NoRedirect()
    )
    try:
        with opener.open(request, timeout=10) as response:
            if response.status != 200:
                raise SessioneHttpError(
                    f"login HTTP rifiutato (status {response.status})"
                )
            # La risposta e' piccola; non serve leggere altro.
            response.read(65536)
            intestazioni = response.headers.get_all("Set-Cookie") or []
    except urllib.error.HTTPError as exc:
        raise SessioneHttpError(
            f"login HTTP rifiutato (status {exc.code})"
        ) from None
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise SessioneHttpError(
            f"target non raggiungibile durante il login ({type(exc).__name__})"
        ) from None

    cookie = SimpleCookie()
    try:
        for intestazione in intestazioni:
            cookie.load(intestazione)
    except Exception:
        raise SessioneHttpError("header Set-Cookie non valido") from None
    morsetto = cookie.get("hermes_session")
    if morsetto is None or not morsetto.value:
        raise SessioneHttpError("login senza cookie hermes_session")
    return morsetto.value


__all__ = ["SessioneHttpError", "apri_sessione"]
