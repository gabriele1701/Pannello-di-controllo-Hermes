"""CLI del VSPT: ``run``, ``report``, ``update-feeds``.

Output sequenziale (spec §9): per ogni controllo una riga
``comando → cosa fa → esito``, nell'ordine in cui vengono eseguiti, cosi' chi
guarda vede il run procedere e capisce cosa e' stato fatto e cosa no.

In questo scaffold un ``run`` non ha canali verso il target (niente sessione
HTTP, niente SSH, niente DB: non c'e' una VM), quindi tutti i collector
risultano **saltati** — ed e' la verita', non un difetto da nascondere. Il
report che ne esce e' onesto: nessun finding, limiti in evidenza, e la ragione
scritta. Il collegamento live arriva con l'ambiente VM.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from assess import __version__, config, scope
from assess.collectors.base import RunContext
from assess.inventory.openapi_endpoints import inventario_da_file
from assess.report import html_report, json_report
from assess.runner import collectors_standard, esegui_run
from assess.wrappers.ssh import WrapperSsh
from assess.wrappers.http_session import SessioneHttpError, apri_sessione
from assess.scope import egress_self_check

#: Una riga di "cosa fa", per l'output sequenziale. Chiave = name del collector.
_DESCRIZIONE = {
    "nuclei": "scan a template offline sugli endpoint autorizzati",
    "sqlmap": "SQLi mirata sugli endpoint da openapi.json (profilo non distruttivo)",
    "semgrep": "analisi statica su backend/",
    "pip-audit": "CVE note sulle dipendenze",
    "postgres": "ruoli e grant via hermes_assess (SELECT-only)",
    "system": "porte, processi, servizi, permessi (SSH ristretto)",
}


def _commit_pannello(repo_root: Path) -> str | None:
    try:
        out = subprocess.run(
            ["git", "-C", str(repo_root), "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=5, check=False,
        )
        return out.stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


def _trova_openapi(repo_root: Path) -> Path | None:
    p = repo_root / "openapi.json"
    return p if p.is_file() else None


def filtra_collectors(collectors, nomi):
    """Restringe i collector ai soli ``nomi``, mantenendo l'ordine standard.

    Un nome sconosciuto e' un **errore** (fail-closed): se l'operatore chiede
    ``--only sistema`` per un refuso, e' meglio fermarsi che eseguire di nascosto
    un sottoinsieme diverso da quello voluto. I collector esclusi non vengono
    nemmeno istanziati nel run: non sono "saltati", semplicemente non chiesti."""
    noti = {c.name for c in collectors}
    sconosciuti = [n for n in nomi if n not in noti]
    if sconosciuti:
        raise ValueError(
            "collector sconosciuti: " + ", ".join(sconosciuti)
            + " — disponibili: " + ", ".join(c.name for c in collectors)
        )
    scelti = set(nomi)
    return [c for c in collectors if c.name in scelti]


def canale_ssh(cfg: config.ConfigScope) -> WrapperSsh | None:
    """Il wrapper SSH se la config lo definisce (sezione [ssh] con un host),
    altrimenti None.

    Senza un canale configurato il collector ``system`` (``requires={"ssh"}``)
    resta NOT_RUN per requisito non soddisfatto: mai un finto esito, e nemmeno
    un tentativo di connessione verso un host vuoto."""
    if cfg.ssh is not None and cfg.ssh.host:
        return WrapperSsh(cfg.ssh)
    return None


def comando_run(args: argparse.Namespace) -> int:
    repo_root = Path(args.repo_root).resolve()
    try:
        cfg = config.carica(args.config)
    except config.ConfigIncompleta as exc:
        print(f"configurazione non valida: {exc}", file=sys.stderr)
        return 2

    try:
        target = scope.valida_target(cfg.target.base_url, cfg.target.allowlist)
    except scope.TargetFuoriPerimetro as exc:
        print(f"target fuori perimetro: {exc}", file=sys.stderr)
        return 2

    openapi = _trova_openapi(repo_root)
    inventario = inventario_da_file(openapi) if openapi else []

    collectors = collectors_standard()
    if args.only:
        try:
            collectors = filtra_collectors(collectors, args.only)
        except ValueError as exc:
            print(f"selezione collector non valida: {exc}", file=sys.stderr)
            return 2

    ctx = RunContext(
        config=cfg,
        repo_root=repo_root,
        target=target,
        base_url=cfg.target.base_url,
        inventario=inventario,
        http=None,  # valorizzato solo dopo il self-check di rete
        ssh=canale_ssh(cfg),  # il trasporto SSH live, se la config lo definisce
        db=None,     # nessuna connessione DB (fuori da questo step)
        commit_pannello=_commit_pannello(repo_root),
    )

    print(f"vspt {__version__} — target pinnato: {target} ({cfg.target.base_url})")
    print("egress self-check…", file=sys.stderr)
    try:
        egress_self_check(
            cfg.egress.sentinelle, timeout=cfg.egress.timeout_s
        )
    except scope.EgressAperto as exc:
        print(f"RUN NON AVVIATO — {exc}", file=sys.stderr)
        return 2

    # Il controllo di confinamento precede qualunque richiesta HTTP, incluso
    # il login. Il cookie resta in memoria e non viene mai scritto nel report.
    if any(c.name in {"nuclei", "sqlmap"} for c in collectors):
        try:
            ctx.http = apri_sessione(cfg.target)
        except SessioneHttpError as exc:
            print(f"login HTTP non riuscito: {exc}", file=sys.stderr)
            return 2

    esecuzione = esegui_run(ctx, collectors, salta_egress=True)

    totale = len(esecuzione.metadati.checks)
    for i, c in enumerate(esecuzione.metadati.checks, start=1):
        descrizione = _DESCRIZIONE.get(c.name, "")
        nota = f" ({c.nota})" if c.nota else ""
        print(f"[{i}/{totale}] {c.name:9}— {descrizione:55} … {c.esito.value}{nota}")

    doc = json_report.documento(esecuzione)
    out_dir = Path(args.out_dir or cfg.out_dir)
    pj = json_report.scrivi(doc, out_dir / "report.json")
    ph = html_report.scrivi(doc, out_dir / "report.html")
    print(f"→ report: {pj}, {ph}")
    return 0


def comando_report(args: argparse.Namespace) -> int:
    """Rigenera l'HTML dal JSON gia' prodotto, senza rieseguire niente."""
    try:
        doc = json_report.leggi(args.json)
    except OSError as exc:
        print(f"impossibile leggere {args.json}: {exc}", file=sys.stderr)
        return 2
    ph = html_report.scrivi(doc, args.out or Path(args.json).with_suffix(".html"))
    print(f"→ HTML: {ph}")
    return 0


def comando_update_feeds(_args: argparse.Namespace) -> int:
    """Documentato e separato: NON necessario all'esecuzione confinata.

    L'aggiornamento dei template nuclei e del DB di pip-audit e' uno step a
    parte, esplicito, che esce in rete — percio' non fa parte di un ``run``
    confinato. Qui e' solo documentato."""
    print(
        "update-feeds e' uno step separato ed esplicito, NON parte di un run "
        "confinato (esce in rete). Aggiornerebbe:\n"
        "  - i template offline in templates_nuclei/ (nuclei -update-templates)\n"
        "  - il DB di pip-audit (pip-audit scarica gli advisory)\n"
        "Il run confinato usa solo cio' che e' gia' locale."
    )
    return 0


def costruisci_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vspt",
        description="Assessor della web application del Pannello Hermes.",
    )
    parser.add_argument("--version", action="version", version=f"vspt {__version__}")
    sub = parser.add_subparsers(dest="comando", required=True)

    p_run = sub.add_parser("run", help="esegue l'assessment e produce il report")
    p_run.add_argument("--config", default="scope.toml", help="file di scope (toml)")
    p_run.add_argument("--out-dir", default=None, help="directory di output del report")
    p_run.add_argument("--repo-root", default=".", help="radice del repo del pannello")
    p_run.add_argument(
        "--only", nargs="+", metavar="NAME", default=None,
        help="esegue SOLO i collector indicati (es. --only system); gli altri "
             "non vengono nemmeno tentati. Un nome sconosciuto e' un errore.",
    )
    p_run.set_defaults(func=comando_run)

    p_rep = sub.add_parser("report", help="rigenera l'HTML dal JSON esistente")
    p_rep.add_argument("json", help="percorso di report.json")
    p_rep.add_argument("--out", default=None, help="percorso dell'HTML da scrivere")
    p_rep.set_defaults(func=comando_report)

    p_upd = sub.add_parser(
        "update-feeds", help="(separato) aggiorna template/CVE — esce in rete"
    )
    p_upd.set_defaults(func=comando_update_feeds)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = costruisci_parser()
    args = parser.parse_args(argv)
    return args.func(args)


__all__ = ["costruisci_parser", "main"]
