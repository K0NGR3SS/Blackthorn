"""
WAFPierce Exporters

Turn scan results into portable artifacts:

  * SARIF 2.1.0  -> CI/CD ingestion (GitHub code scanning, etc.)
  * Nuclei       -> reproducible YAML templates for confirmed findings
  * HTML         -> standalone, styled report for humans

All exporters are stdlib-only (no PyYAML dependency) and never raise on bad data.
"""
import json
import html
import datetime
from typing import List, Dict, Any

from . import __version__

_SEV_TO_SARIF = {
    'CRITICAL': 'error', 'HIGH': 'error', 'MEDIUM': 'warning',
    'LOW': 'note', 'INFO': 'note',
}
_SEV_RANK = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
_SEV_COLOR = {
    'CRITICAL': '#b00020', 'HIGH': '#e65100', 'MEDIUM': '#f9a825',
    'LOW': '#1565c0', 'INFO': '#607d8b',
}


def _rule_id(result: Dict[str, Any]) -> str:
    cat = (result.get('category') or 'finding').lower().replace(' ', '_')
    tech = (result.get('technique') or 'unknown').split(':')[0].strip().lower()
    tech = ''.join(ch if ch.isalnum() else '_' for ch in tech)[:40]
    return f"wafpierce.{cat}.{tech}"


# --------------------------------------------------------------------- SARIF
def to_sarif(target: str, results: List[Dict[str, Any]]) -> str:
    rules = {}
    sarif_results = []
    for r in results:
        rid = _rule_id(r)
        if rid not in rules:
            rules[rid] = {
                'id': rid,
                'name': r.get('technique', rid),
                'shortDescription': {'text': r.get('technique', rid)},
                'defaultConfiguration': {'level': _SEV_TO_SARIF.get(r.get('severity', 'INFO'), 'note')},
                'properties': {'category': r.get('category', ''), 'security-severity':
                               {'CRITICAL': '9.5', 'HIGH': '8.0', 'MEDIUM': '5.0',
                                'LOW': '3.0', 'INFO': '0.0'}.get(r.get('severity', 'INFO'), '0.0')},
            }
        uri = target.rstrip('/') + (r.get('path') or '/')
        sarif_results.append({
            'ruleId': rid,
            'level': _SEV_TO_SARIF.get(r.get('severity', 'INFO'), 'note'),
            'message': {'text': f"{r.get('technique', '')}: {r.get('reason', '')}"},
            'locations': [{
                'physicalLocation': {'artifactLocation': {'uri': uri}}
            }],
            'properties': {
                'severity': r.get('severity', 'INFO'),
                'bypass': bool(r.get('bypass')),
                'status': r.get('status'),
            },
        })
    doc = {
        '$schema': 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
        'version': '2.1.0',
        'runs': [{
            'tool': {'driver': {
                'name': 'WAFPierce',
                'informationUri': 'https://github.com/K0NGR3SS/WAFPierce',
                'version': __version__,
                'rules': list(rules.values()),
            }},
            'results': sarif_results,
        }],
    }
    return json.dumps(doc, indent=2)


# --------------------------------------------------------------------- Nuclei
def _yaml_escape(s: str) -> str:
    return '"' + str(s).replace('\\', '\\\\').replace('"', '\\"') + '"'


def to_nuclei(target: str, results: List[Dict[str, Any]]) -> str:
    """Generate Nuclei templates for confirmed (bypass) findings, '---'-separated."""
    docs = []
    for r in results:
        if not r.get('bypass'):
            continue
        rid = _rule_id(r).replace('.', '-')
        path = r.get('path') or '/'
        method = r.get('method', 'GET')
        sev = (r.get('severity') or 'info').lower()
        status = r.get('status') or 200
        doc = (
            f"id: {rid}\n"
            f"info:\n"
            f"  name: {_yaml_escape(r.get('technique', 'WAFPierce finding'))}\n"
            f"  author: wafpierce\n"
            f"  severity: {sev}\n"
            f"  description: {_yaml_escape(r.get('reason', ''))}\n"
            f"  tags: wafpierce,{(r.get('category') or 'misc').lower()}\n"
            f"http:\n"
            f"  - method: {method}\n"
            f"    path:\n"
            f"      - {_yaml_escape('{{BaseURL}}' + path)}\n"
            f"    matchers-condition: and\n"
            f"    matchers:\n"
            f"      - type: status\n"
            f"        status:\n"
            f"          - {status}\n"
        )
        docs.append(doc)
    if not docs:
        return "# No confirmed (bypass) findings to export as Nuclei templates.\n"
    return "\n---\n".join(docs)


# ----------------------------------------------------------------------- HTML
def to_html(target: str, results: List[Dict[str, Any]]) -> str:
    ts = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    counts = {s: 0 for s in _SEV_RANK}
    for r in results:
        counts[r.get('severity', 'INFO')] = counts.get(r.get('severity', 'INFO'), 0) + 1
    ordered = sorted(results, key=lambda r: _SEV_RANK.get(r.get('severity', 'INFO'), 5))

    rows = []
    for r in ordered:
        sev = r.get('severity', 'INFO')
        color = _SEV_COLOR.get(sev, '#607d8b')
        triage = r.get('ai_triage') or {}
        fp = ' <span style="color:#b00020">(AI: likely FP)</span>' if triage.get('false_positive') else ''
        conf = r.get('confidence')
        conf_badge = (
            f" <span class='conf conf-{html.escape(str(conf))}'>{html.escape(str(conf))}"
            f"{' ' + html.escape(str(r['confirmations'])) if r.get('confirmations') else ''}</span>"
            if conf else ''
        )
        fp = fp + conf_badge
        curl = r.get('curl')
        oob = r.get('oob') or {}
        repro_parts = []
        if oob:
            proof = (f"protocol: {oob.get('protocol','?')}\nsource: {oob.get('source','?')}\n"
                     f"id: {oob.get('full_id','')}\n\n{oob.get('raw','')}")
            repro_parts.append(
                f"<details open><summary>OOB proof</summary><pre class='repro'>{html.escape(proof)}</pre></details>"
            )
        if curl:
            repro_parts.append(
                f"<details><summary>curl</summary><pre class='repro'>{html.escape(str(curl))}</pre></details>"
            )
        repro = ''.join(repro_parts) if repro_parts else '<span class="muted">—</span>'
        rows.append(
            f"<tr>"
            f"<td><span style='background:{color};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px'>{html.escape(sev)}</span></td>"
            f"<td>{html.escape(str(r.get('technique', '')))}{fp}</td>"
            f"<td>{html.escape(str(r.get('category', '')))}</td>"
            f"<td>{html.escape(str(r.get('status', '')))}</td>"
            f"<td>{html.escape(str(r.get('reason', '')))}</td>"
            f"<td><code>{html.escape(str(r.get('path', '')))}</code></td>"
            f"<td>{repro}</td>"
            f"</tr>"
        )
    summary = " ".join(
        f"<span style='background:{_SEV_COLOR[s]};color:#fff;padding:4px 10px;border-radius:4px;margin-right:6px'>{s}: {counts.get(s,0)}</span>"
        for s in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
    )
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>WAFPierce Report — {html.escape(target)}</title>
<style>
 body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:#0f1115;color:#e6e6e6}}
 header{{background:#161a22;padding:24px 32px;border-bottom:1px solid #262b36}}
 h1{{margin:0;font-size:22px}} .sub{{color:#9aa4b2;font-size:13px;margin-top:6px}}
 .wrap{{padding:24px 32px}}
 table{{width:100%;border-collapse:collapse;font-size:13px}}
 th,td{{text-align:left;padding:9px 10px;border-bottom:1px solid #232936;vertical-align:top}}
 th{{color:#9aa4b2;text-transform:uppercase;font-size:11px;letter-spacing:.04em}}
 tr:hover td{{background:#161a22}} code{{color:#7fd1ff}}
 .summary{{margin:18px 0}}
 .muted{{color:#5b6472}}
 .conf{{font-size:11px;padding:1px 6px;border-radius:3px;margin-left:4px}}
 .conf-high{{background:#1b3a2b;color:#5bd98a}} .conf-medium{{background:#3a341b;color:#e6c84b}}
 .conf-low{{background:#3a1b1b;color:#e67a7a}} .conf-single{{background:#26303a;color:#9ac4e6}}
 details summary{{cursor:pointer;color:#7fd1ff;font-size:12px}}
 pre.repro{{white-space:pre-wrap;word-break:break-all;background:#0b0d11;border:1px solid #232936;border-radius:6px;padding:8px;margin:6px 0 0;font-size:12px;color:#cfe8ff}}
</style></head>
<body>
 <header>
  <h1>WAFPierce Security Report</h1>
  <div class="sub">Target: {html.escape(target)} &nbsp;•&nbsp; Generated: {ts} &nbsp;•&nbsp; {len(results)} findings</div>
 </header>
 <div class="wrap">
  <div class="summary">{summary}</div>
  <table>
   <thead><tr><th>Severity</th><th>Technique</th><th>Category</th><th>Status</th><th>Reason</th><th>Path</th><th>Reproduce</th></tr></thead>
   <tbody>
   {''.join(rows) if rows else '<tr><td colspan=7>No findings.</td></tr>'}
   </tbody>
  </table>
 </div>
</body></html>"""


def to_pdf(target: str, results: List[Dict[str, Any]], path: str) -> bool:
    """Render a findings PDF to ``path`` using reportlab. Returns False if
    reportlab is unavailable (caller can fall back to HTML)."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                        Table, TableStyle)
    except Exception:
        logger.warning("reportlab not installed; cannot export PDF")
        return False

    styles = getSampleStyleSheet()
    small = ParagraphStyle('small', parent=styles['BodyText'], fontSize=7, leading=9)
    ts = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    ordered = sorted(results, key=lambda r: _SEV_RANK.get(r.get('severity', 'INFO'), 5))

    doc = SimpleDocTemplate(path, pagesize=A4, title=f"WAFPierce — {target}")
    story = [Paragraph("WAFPierce Security Report", styles['Title']),
             Paragraph(f"Target: {target} &nbsp; • &nbsp; Generated: {ts} &nbsp; • &nbsp; "
                       f"{len(results)} findings", styles['Normal']),
             Spacer(1, 6 * mm)]

    rows = [['Severity', 'CVSS', 'Technique', 'Status', 'Reason']]
    for r in ordered:
        rows.append([
            r.get('severity', 'INFO'),
            str(r.get('cvss_score', '')),
            Paragraph(html.escape(str(r.get('technique', '')))[:80], small),
            str(r.get('status', '')),
            Paragraph(html.escape(str(r.get('reason', '')))[:160], small),
        ])
    table = Table(rows, colWidths=[22 * mm, 14 * mm, 50 * mm, 16 * mm, 70 * mm],
                  repeatRows=1)
    style = [('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#161a22')),
             ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
             ('FONTSIZE', (0, 0), (-1, -1), 7),
             ('GRID', (0, 0), (-1, -1), 0.25, colors.HexColor('#cccccc')),
             ('VALIGN', (0, 0), (-1, -1), 'TOP')]
    sev_color = {'CRITICAL': '#b71c1c', 'HIGH': '#e65100', 'MEDIUM': '#f9a825',
                 'LOW': '#1565c0', 'INFO': '#607d8b'}
    for i, r in enumerate(ordered, start=1):
        style.append(('TEXTCOLOR', (0, i), (0, i),
                      colors.HexColor(sev_color.get(r.get('severity', 'INFO'), '#607d8b'))))
    table.setStyle(TableStyle(style))
    story.append(table)
    doc.build(story)
    return True


def export(results: List[Dict[str, Any]], target: str, fmt: str, path: str = None) -> str:
    """Render results to ``fmt`` ('sarif'|'nuclei'|'html'|'json'|'pdf'); optionally write to ``path``."""
    fmt = (fmt or 'json').lower()
    if fmt == 'pdf':
        if not path:
            raise ValueError("PDF export requires an output path")
        if to_pdf(target, results, path):
            return path
        # Fall back to an HTML file alongside the requested path.
        html_path = path.rsplit('.', 1)[0] + '.html'
        content = to_html(target, results)
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(content)
        logger.warning(f"PDF unavailable; wrote HTML to {html_path}")
        return html_path
    if fmt == 'sarif':
        content = to_sarif(target, results)
    elif fmt == 'nuclei':
        content = to_nuclei(target, results)
    elif fmt == 'html':
        content = to_html(target, results)
    else:
        content = json.dumps(results, indent=2, default=str)
    if path:
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)
    return content
