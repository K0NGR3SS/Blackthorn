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
                'version': '1.5',
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
        rows.append(
            f"<tr>"
            f"<td><span style='background:{color};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px'>{html.escape(sev)}</span></td>"
            f"<td>{html.escape(str(r.get('technique', '')))}{fp}</td>"
            f"<td>{html.escape(str(r.get('category', '')))}</td>"
            f"<td>{html.escape(str(r.get('status', '')))}</td>"
            f"<td>{html.escape(str(r.get('reason', '')))}</td>"
            f"<td><code>{html.escape(str(r.get('path', '')))}</code></td>"
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
</style></head>
<body>
 <header>
  <h1>WAFPierce Security Report</h1>
  <div class="sub">Target: {html.escape(target)} &nbsp;•&nbsp; Generated: {ts} &nbsp;•&nbsp; {len(results)} findings</div>
 </header>
 <div class="wrap">
  <div class="summary">{summary}</div>
  <table>
   <thead><tr><th>Severity</th><th>Technique</th><th>Category</th><th>Status</th><th>Reason</th><th>Path</th></tr></thead>
   <tbody>
   {''.join(rows) if rows else '<tr><td colspan=6>No findings.</td></tr>'}
   </tbody>
  </table>
 </div>
</body></html>"""


def export(results: List[Dict[str, Any]], target: str, fmt: str, path: str = None) -> str:
    """Render results to ``fmt`` ('sarif'|'nuclei'|'html'|'json'); optionally write to ``path``."""
    fmt = (fmt or 'json').lower()
    if fmt == 'sarif':
        content = to_sarif(target, results)
    elif fmt == 'nuclei':
        content = to_nuclei(target, results)
    elif fmt == 'html':
        content = to_html(target, results)
    else:
        content = json.dumps(results, indent=2)
    if path:
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)
    return content
