"""Wiring del trasporto SSH nella CLI (FIX 1), senza SSH reale.

Con una config che ha ``[ssh]`` il RunContext riceve un ``WrapperSsh``; senza,
riceve ``None`` e il collector ``system`` resta NOT_RUN per requisito non
soddisfatto — mai un finto esito.
"""

from __future__ import annotations

from pathlib import Path

from assess.cli import canale_ssh
from assess.collectors.base import RunContext
from assess.config import ConfigEgress, ConfigScope, ConfigSsh, ConfigTarget
from assess.model import EsitoCheck
from assess.runner import collectors_standard, esegui_run
from assess.wrappers.ssh import WrapperSsh


def _cfg(ssh: ConfigSsh) -> ConfigScope:
    return ConfigScope(
        target=ConfigTarget(base_url="http://app:8000", allowlist=("app",)),
        egress=ConfigEgress(sentinelle=(("1.1.1.1", 53),)),
        ssh=ssh,
    )


def test_canale_ssh_con_config_e_un_wrapper():
    cfg = _cfg(ConfigSsh(
        host="vm.local", user="assess",
        key_path="/run/secrets/k", known_hosts_path="/run/secrets/kh",
    ))
    assert isinstance(canale_ssh(cfg), WrapperSsh)


def test_canale_ssh_senza_config_e_none():
    # [ssh] assente -> ConfigSsh con host vuoto -> nessun canale.
    assert canale_ssh(_cfg(ConfigSsh())) is None


def test_system_not_run_senza_canale_ssh():
    ctx = RunContext(config=_cfg(ConfigSsh()), repo_root=Path("."),
                     ssh=canale_ssh(_cfg(ConfigSsh())))
    esecuzione = esegui_run(ctx, collectors_standard(), salta_egress=True)
    system = next(c for c in esecuzione.metadati.checks if c.name == "system")
    assert system.esito is EsitoCheck.SALTATO
    assert "ssh" in system.nota  # requisito non soddisfatto, non un esito


def test_system_tentato_con_canale_ssh():
    # Con un canale configurato il collector NON e' piu' saltato per requisito:
    # viene tentato (e qui, senza _invia reale, fallisce il trasporto -> FALLITO,
    # non un finto 'pulito').
    cfg = _cfg(ConfigSsh(
        host="vm.local", key_path="/run/secrets/k",
        known_hosts_path="/run/secrets/kh",
    ))
    ctx = RunContext(config=cfg, repo_root=Path("."), ssh=canale_ssh(cfg))

    class _SshCheFallisce:
        def riga_grezza(self, verbo):
            from assess.wrappers.ssh import TrasportoSshFallito
            raise TrasportoSshFallito("niente rete nei test")

    ctx.ssh = _SshCheFallisce()
    esecuzione = esegui_run(ctx, collectors_standard(), salta_egress=True)
    system = next(c for c in esecuzione.metadati.checks if c.name == "system")
    assert system.esito is EsitoCheck.FALLITO
