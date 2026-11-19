"""Rende l'HTML del report **dai soli dati JSON**.

Nessuna logica di valutazione: ``render`` riceve il documento (lo stesso dict
che ``json_report`` produce e scrive) e lo trasforma in pagina. Se il JSON
cambia, cambia l'HTML; se l'HTML dicesse qualcosa che il JSON non dice, sarebbe
un bug — percio' non calcola niente, formatta e basta.

Template autoconsistente: CSS inline, nessun asset remoto. Si apre con un
doppio clic, anche offline.
"""

from __future__ import annotations

import html
from pathlib import Path
from string import Template
from typing import Any

_TEMPLATE = Path(__file__).parent / "templates" / "report.html"

#: Mappa severita' (banda low/medium/high/critical) -> classe CSS di colore.
#: Il template ha tre colori; high e critical condividono il rosso, ma la
#: severita' testuale nella pill li distingue (e' il dato, non il colore).
_CLASSE_SEV = {
    "low": "verde",
    "medium": "giallo",
    "high": "rosso",
    "critical": "rosso",
}
#: Ordine di gravita' decrescente, per i conteggi del riepilogo.
_SEV_ORDINE = ("critical", "high", "medium", "low")
#: Esito del check -> classe CSS, per leggere a colpo d'occhio cosa non e' andato.
_CLASSE_ESITO = {"completato": "verde", "saltato": "giallo", "fallito": "rosso"}


def _e(valore: Any) -> str:
    """Escape HTML di qualunque valore. Tutto cio' che viene dai dati passa di
    qui: un'evidenza che contiene ``<script>`` non deve diventare markup."""
    return html.escape(str(valore), quote=True)


def _avviso_limiti(meta: dict[str, Any]) -> str:
    """Blocco in EVIDENZA di cio' che non e' stato eseguito. In cima, non in
    nota: e' l'invariante di onesta' del report."""
    checks = meta.get("checks", {})
    saltati = checks.get("saltati", [])
    falliti = checks.get("falliti", [])
    limitazioni = meta.get("limitazioni", [])
    if not (saltati or falliti or limitazioni):
        return ""
    righe = "".join(f"<li>{_e(x)}</li>" for x in limitazioni)
    cappello = []
    if falliti:
        cappello.append(f"<strong>{len(falliti)}</strong> falliti")
    if saltati:
        cappello.append(f"<strong>{len(saltati)}</strong> saltati")
    riassunto = ", ".join(cappello) or "limiti noti"
    return (
        '<div class="avviso">'
        "<h2>Limiti del run — da leggere prima</h2>"
        f"<p>Controlli non completati ({riassunto}). "
        "Un controllo non eseguito <strong>non</strong> e' un controllo superato: "
        "quanto segue non copre cio' che e' elencato qui.</p>"
        f"<ul>{righe}</ul></div>"
    )


def _meta_righe(meta: dict[str, Any]) -> str:
    coppie = [
        ("Generato", meta.get("timestamp", "")),
        ("Versione tool", meta.get("tool_version", "")),
        ("Commit pannello", meta.get("commit_pannello") or "—"),
        ("Hash scope", meta.get("scope_hash", "")),
        ("Sentinelle egress", ", ".join(meta.get("sentinelle_egress", []))),
        ("Versioni tool attese", ", ".join(f"{k} {v}" for k, v in meta.get("versioni_tool", {}).items())),
    ]
    return "".join(f"<dt>{_e(k)}</dt><dd>{_e(v)}</dd>" for k, v in coppie)


def _tabella_checks(meta: dict[str, Any]) -> str:
    dettaglio = meta.get("checks", {}).get("dettaglio", [])
    if not dettaglio:
        return '<tr><td colspan="4" class="vuoto">Nessun controllo registrato.</td></tr>'
    righe = []
    for c in dettaglio:
        cls = _CLASSE_ESITO.get(c.get("esito", ""), "giallo")
        righe.append(
            "<tr>"
            f"<td>{_e(c.get('name',''))}</td>"
            f"<td>{_e(c.get('source',''))}</td>"
            f'<td><span class="pill {cls}">{_e(c.get("esito",""))}</span></td>'
            f'<td class="ev">{_e(c.get("nota",""))}</td>'
            "</tr>"
        )
    return "".join(righe)


def _conteggi(riepilogo: dict[str, Any]) -> str:
    per_sev = riepilogo.get("per_severita", {})
    box = []
    for sev in _SEV_ORDINE:
        cls = _CLASSE_SEV[sev]
        box.append(
            f'<div class="box {cls}"><span class="num">{_e(per_sev.get(sev,0))}</span>{_e(sev)}</div>'
        )
    return "".join(box)


def _tabella_findings(findings: list[dict[str, Any]]) -> str:
    if not findings:
        return '<tr><td colspan="5" class="vuoto">Nessun finding. Vedi i limiti del run qui sopra: assenza di finding non e\' assenza di rischio.</td></tr>'
    righe = []
    for f in findings:
        cls = _CLASSE_SEV.get(f.get("severity", ""), "giallo")
        rif = ", ".join(r for r in f.get("references", []) if r)
        righe.append(
            '<tr class="finding">'
            f"<td>{_e(f.get('id',''))}</td>"
            f'<td><span class="pill {cls}">{_e(f.get("severity",""))}</span></td>'
            f"<td><strong>{_e(f.get('title',''))}</strong><br>"
            f'<code>{_e(f.get("affected_element",""))}</code><br>'
            f'<span class="ev">{_e(f.get("evidence",""))}</span><br>'
            f'<span class="ev">Raccomandazione: {_e(f.get("recommendation",""))}</span>'
            + (f'<br><span class="ev mono">{_e(rif)}</span>' if rif else "")
            + "</td>"
            f"<td>{_e(f.get('status',''))}<br><span class=\"muto\">{_e(f.get('pentest_result',''))}</span></td>"
            f"<td>{_e(f.get('risk_score',''))} "
            f'<span class="muto">({_e(f.get("impact",""))}×{_e(f.get("probability",""))})</span></td>'
            "</tr>"
        )
    return "".join(righe)


def render(doc: dict[str, Any]) -> str:
    """Rende il documento JSON in una pagina HTML autoconsistente."""
    meta = doc.get("meta", {})
    riepilogo = doc.get("riepilogo", {})
    findings = doc.get("findings", [])
    modello = Template(_TEMPLATE.read_text(encoding="utf-8"))
    return modello.safe_substitute(
        titolo="Report VSPT — assessment del Pannello Hermes",
        sottotitolo=_e(f"Generato {meta.get('timestamp','')} · commit {meta.get('commit_pannello') or '—'}"),
        avviso_limiti=_avviso_limiti(meta),
        meta_righe=_meta_righe(meta),
        tabella_checks=_tabella_checks(meta),
        conteggi=_conteggi(riepilogo),
        fonti_distinte=_e(riepilogo.get("fonti_distinte", 0)),
        totale=_e(riepilogo.get("totale", 0)),
        tabella_findings=_tabella_findings(findings),
    )


def scrivi(doc: dict[str, Any], percorso: str | Path) -> Path:
    """Rende e scrive l'HTML su file."""
    p = Path(percorso)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(render(doc), encoding="utf-8")
    return p


__all__ = ["render", "scrivi"]
