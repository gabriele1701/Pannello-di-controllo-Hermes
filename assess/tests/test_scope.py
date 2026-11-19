"""Scope guard: l'egress bloccato fa partire, l'egress aperto fa rifiutare.

E' il test del fail-closed. La sonda e' iniettata, cosi' il comportamento si
verifica senza toccare la rete: una sonda che non raggiunge niente simula una
rete confinata, una che raggiunge una sentinella simula una rete bucata. Il
secondo caso DEVE far rifiutare il run — e' tutto il punto del controllo.

Qui si verifica anche il loader fail-closed: un file con un ``DA_COMPILARE``
residuo non e' una configurazione, e il tool non deve partirci.
"""

from __future__ import annotations

import pytest

from assess import config, scope


# --------------------------------------------------------------------------- #
# Egress self-check
# --------------------------------------------------------------------------- #


def test_egress_bloccato_fa_partire():
    """Nessuna sentinella raggiungibile → il check passa e non solleva."""
    sonda_chiusa = lambda h, p, t: False  # noqa: E731
    raggiungibili = scope.egress_self_check(
        [("1.1.1.1", 53), ("8.8.8.8", 443)], sonda=sonda_chiusa
    )
    assert raggiungibili == []


def test_egress_aperto_fa_rifiutare():
    """Anche UNA sola sentinella raggiungibile → EgressAperto (fail-closed)."""
    sonda_aperta = lambda h, p, t: (h, p) == ("8.8.8.8", 443)  # noqa: E731
    with pytest.raises(scope.EgressAperto) as exc:
        scope.egress_self_check([("1.1.1.1", 53), ("8.8.8.8", 443)], sonda=sonda_aperta)
    assert "8.8.8.8:443" in str(exc.value)


def test_egress_tutte_aperte_le_elenca_tutte():
    sonda_tutto = lambda h, p, t: True  # noqa: E731
    with pytest.raises(scope.EgressAperto) as exc:
        scope.egress_self_check([("1.1.1.1", 53), ("8.8.8.8", 443)], sonda=sonda_tutto)
    testo = str(exc.value)
    assert "1.1.1.1:53" in testo and "8.8.8.8:443" in testo


# --------------------------------------------------------------------------- #
# Validazione del target (pin, senza DNS esterno)
# --------------------------------------------------------------------------- #


def test_target_in_allowlist_e_ammesso():
    assert scope.valida_target("http://app:8000", ["app"]) == "app"


@pytest.mark.parametrize(
    "url",
    [
        "http://1.2.3.4:8000",          # IP pubblico
        "http://evil.example.com/",     # nome esterno non in allowlist
        "https://app.evil.com",         # sottodominio non in allowlist
        "ftp://app",                    # schema non http(s)
    ],
)
def test_target_fuori_perimetro_rifiutato(url):
    with pytest.raises(scope.TargetFuoriPerimetro):
        scope.valida_target(url, ["app"])


def test_target_ip_privato_ammesso_solo_se_in_allowlist():
    # In allowlist esplicita: ammesso.
    assert scope.valida_target("http://127.0.0.1:8000", ["127.0.0.1"]) == "127.0.0.1"
    # Non in allowlist: rifiutato, anche se privato.
    with pytest.raises(scope.TargetFuoriPerimetro):
        scope.valida_target("http://127.0.0.1:8000", ["app"])


# --------------------------------------------------------------------------- #
# Loader fail-closed
# --------------------------------------------------------------------------- #


def test_esempio_con_segnaposto_e_rifiutato():
    """scope.example.toml contiene DA_COMPILARE: il loader deve rifiutarlo."""
    percorso = scope.__file__.replace("scope.py", "scope.example.toml")
    with pytest.raises(config.ConfigIncompleta) as exc:
        config.carica(percorso)
    assert config.SEGNAPOSTO in str(exc.value)


def test_config_compilata_valida(tmp_path):
    toml = tmp_path / "scope.toml"
    toml.write_text(
        "[target]\n"
        'base_url = "http://app:8000"\n'
        'allowlist = ["app"]\n'
        'operator_user = "demo"\n'
        "[egress]\n"
        'sentinelle = [["1.1.1.1", 53]]\n',
        encoding="utf-8",
    )
    cfg = config.carica(toml)
    assert cfg.target.base_url == "http://app:8000"
    assert cfg.target.allowlist == ("app",)
    assert cfg.egress.sentinelle == (("1.1.1.1", 53),)


def test_config_file_assente_e_rifiutata(tmp_path):
    with pytest.raises(config.ConfigIncompleta):
        config.carica(tmp_path / "non-esiste.toml")


def test_config_sentinella_malformata_e_rifiutata(tmp_path):
    toml = tmp_path / "scope.toml"
    toml.write_text(
        "[target]\n"
        'base_url = "http://app:8000"\n'
        'allowlist = ["app"]\n'
        "[egress]\n"
        'sentinelle = ["1.1.1.1"]\n',  # manca la porta
        encoding="utf-8",
    )
    with pytest.raises(config.ConfigIncompleta):
        config.carica(toml)


def test_config_campo_obbligatorio_mancante(tmp_path):
    toml = tmp_path / "scope.toml"
    toml.write_text(
        "[target]\n"
        'base_url = "http://app:8000"\n'  # manca allowlist
        "[egress]\n"
        'sentinelle = [["1.1.1.1", 53]]\n',
        encoding="utf-8",
    )
    with pytest.raises(config.ConfigIncompleta):
        config.carica(toml)
