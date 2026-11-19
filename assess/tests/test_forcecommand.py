"""Validatore ForceCommand: l'allowlist che pinna gli argomenti.

Si testa la logica pura (``comando_consentito``) e l'entry point ``main`` con
l'``os.execvp`` mockato — nessun comando viene davvero eseguito, nessuna VM.
"""

from __future__ import annotations

import pytest

from assess.ssh import validatore
from assess.ssh.validatore import comando_consentito


# --------------------------------------------------------------------------- #
# cat: pinnato sotto la radice sorgente, senza risalite
# --------------------------------------------------------------------------- #


def test_cat_shadow_negato():
    assert comando_consentito("cat /etc/shadow") is None


def test_cat_sorgente_ammesso():
    assert comando_consentito("cat /opt/pannello/backend/main.py") == [
        "cat", "/opt/pannello/backend/main.py",
    ]


def test_cat_risalita_negata():
    assert comando_consentito("cat /opt/pannello/../etc/shadow") is None


def test_cat_prefisso_simile_negato():
    # /opt/pannelloX non e' sotto /opt/pannello
    assert comando_consentito("cat /opt/pannelloX/segreto") is None


def test_cat_relativo_negato():
    assert comando_consentito("cat backend/main.py") is None


def test_cat_senza_argomento_negato():
    assert comando_consentito("cat") is None
    assert comando_consentito("cat a b") is None


# --------------------------------------------------------------------------- #
# ls -la: solo directory consentite
# --------------------------------------------------------------------------- #


def test_ls_sorgente_ammesso():
    assert comando_consentito("ls -la /opt/pannello/backend") == [
        "ls", "-la", "/opt/pannello/backend",
    ]


def test_ls_fuori_radice_negato():
    assert comando_consentito("ls -la /etc") is None


def test_ls_risalita_negata():
    assert comando_consentito("ls -la /opt/pannello/../..") is None


# --------------------------------------------------------------------------- #
# comandi fissi: argv pinnato per intero
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "comando",
    [
        "ss -tlnp",
        "ps aux",
        "systemctl list-units --type=service --state=running",
        "docker ps --format '{{.Names}} {{.Status}} {{.Ports}}'",
    ],
)
def test_comandi_fissi_ammessi(comando):
    assert comando_consentito(comando) is not None


def test_comando_fisso_con_argomento_extra_negato():
    # Il pinning e' sull'intero argv: un argomento in piu' non passa.
    assert comando_consentito("ss -tlnp -p") is None
    assert comando_consentito("ps aux --forest") is None


def test_comando_fisso_con_opzione_cambiata_negato():
    assert comando_consentito("ss -tanp") is None


# --------------------------------------------------------------------------- #
# vario: non in lista, vuoto, injection
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "comando",
    ["", "   ", "rm -rf /", "bash", "cat /opt/pannello/x; rm -rf /",
     "ss -tlnp && cat /etc/shadow", "nc -l 4444", "python3 -c 'import os'"],
)
def test_non_in_lista_negato(comando):
    assert comando_consentito(comando) is None


def test_virgolette_non_bilanciate_negato():
    assert comando_consentito('cat "/opt/pannello/x') is None


# --------------------------------------------------------------------------- #
# main: con execvp mockato (nessuna esecuzione reale)
# --------------------------------------------------------------------------- #


def test_main_esegue_comando_consentito(monkeypatch):
    chiamato = {}

    def finta_execvp(file, args):
        chiamato["file"] = file
        chiamato["args"] = args

    monkeypatch.setattr(validatore.os, "execvp", finta_execvp)
    monkeypatch.setenv("SSH_ORIGINAL_COMMAND", "ss -tlnp")
    # execvp mockata non sostituisce il processo: main prosegue fino a return 127
    assert validatore.main() == 127
    assert chiamato == {"file": "ss", "args": ["ss", "-tlnp"]}


def test_main_nega_comando_non_consentito(monkeypatch):
    def non_chiamare(file, args):  # pragma: no cover
        raise AssertionError("execvp non deve essere chiamata su comando negato")

    monkeypatch.setattr(validatore.os, "execvp", non_chiamare)
    monkeypatch.setenv("SSH_ORIGINAL_COMMAND", "cat /etc/shadow")
    assert validatore.main() == 1
