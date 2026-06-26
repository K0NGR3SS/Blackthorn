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
import logging
import datetime
from typing import List, Dict, Any

from . import __version__

logger = logging.getLogger(__name__)

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
        cat = str(r.get('category', ''))
        triage = r.get('ai_triage') or {}
        fp = ' <span style="color:#ff6b6b">(AI: likely FP)</span>' if triage.get('false_positive') else ''
        conf = r.get('confidence')
        conf_badge = (
            f" <span class='conf conf-{html.escape(str(conf))}'>{html.escape(str(conf))}"
            f"{' ' + html.escape(str(r['confirmations'])) if r.get('confirmations') else ''}</span>"
            if conf else ''
        )
        # CVSS badge with the vector + CWE as a hover tooltip.
        cvss = r.get('cvss_score')
        cvss_badge = ''
        if cvss not in (None, ''):
            tip = str(r.get('cvss_vector') or '')
            cwe = str(r.get('cwe') or r.get('cwe_id') or '')
            if cwe:
                tip = (tip + '  ' + (cwe if str(cwe).upper().startswith('CWE') else f'CWE-{cwe}')).strip()
            cvss_badge = (f" <span class='cvss' title='{html.escape(tip)}'>CVSS "
                          f"{html.escape(str(cvss))}</span>")
        tech_extra = fp + conf_badge + cvss_badge
        curl = r.get('curl')
        oob = r.get('oob') or {}
        repro_parts = []
        if oob:
            proof = (f"protocol: {oob.get('protocol','?')}\nsource: {oob.get('source','?')}\n"
                     f"id: {oob.get('full_id','')}\n\n{oob.get('raw','')}")
            repro_parts.append(
                f"<details open><summary>OOB proof</summary>"
                f"<div class='reprobox'><pre class='repro'>{html.escape(proof)}</pre></div></details>"
            )
        if curl:
            repro_parts.append(
                f"<details><summary>curl</summary><div class='reprobox'>"
                f"<button class='copy' onclick='copyRepro(this)'>copy</button>"
                f"<pre class='repro'>{html.escape(str(curl))}</pre></div></details>"
            )
        repro = ''.join(repro_parts) if repro_parts else '<span class="muted">—</span>'
        rows.append(
            f"<tr class='finding' data-sev='{html.escape(sev)}' data-cat='{html.escape(cat)}'>"
            f"<td><span style='background:{color};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px'>{html.escape(sev)}</span></td>"
            f"<td>{html.escape(str(r.get('technique', '')))}{tech_extra}</td>"
            f"<td>{html.escape(cat)}</td>"
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

    # --- Executive summary inputs -------------------------------------------
    bypasses = sum(1 for r in results if r.get('bypass'))
    detected = []
    for r in results:
        if r.get('category') in ('WAF_DETECTION', 'CDN_DETECTION'):
            label = r.get('technique') or r.get('reason') or ''
            if label and label not in detected:
                detected.append(str(label))
    detected_str = ', '.join(detected[:6]) if detected else 'none identified'
    cat_counts: Dict[str, int] = {}
    for r in results:
        cat_counts[str(r.get('category', ''))] = cat_counts.get(str(r.get('category', '')), 0) + 1
    top_cats = sorted(cat_counts.items(), key=lambda kv: -kv[1])[:5]
    top_cats_str = ', '.join(f"{c or '—'} ({n})" for c, n in top_cats) or '—'

    # Category filter <option>s
    cat_options = ''.join(f"<option value='{html.escape(c)}'>{html.escape(c)}</option>"
                          for c in sorted(cat_counts) if c)

    # Severity filter buttons
    sev_buttons = "<button data-sev='ALL' class='active' onclick=\"setSev('ALL',this)\">All</button>" + ''.join(
        f"<button data-sev='{s}' onclick=\"setSev('{s}',this)\">{s.title()} {counts.get(s,0)}</button>"
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
 .exec{{background:#161a22;border:1px solid #262b36;border-radius:10px;padding:16px 20px;margin:0 0 18px}}
 .exec h2{{margin:0 0 10px;font-size:13px;text-transform:uppercase;letter-spacing:.06em;color:#9aa4b2}}
 .exec .grid{{display:flex;flex-wrap:wrap;gap:22px;font-size:13px}}
 .exec .k{{color:#9aa4b2}} .exec .v{{font-weight:600}}
 table{{width:100%;border-collapse:collapse;font-size:13px}}
 th,td{{text-align:left;padding:9px 10px;border-bottom:1px solid #232936;vertical-align:top}}
 th{{color:#9aa4b2;text-transform:uppercase;font-size:11px;letter-spacing:.04em}}
 tr:hover td{{background:#161a22}} code{{color:#7fd1ff}}
 .summary{{margin:18px 0}}
 .toolbar{{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin:14px 0}}
 .toolbar input,.toolbar select{{background:#0b0d11;border:1px solid #2a3140;color:#e6e6e6;border-radius:6px;padding:7px 10px;font-size:13px}}
 .toolbar input{{min-width:240px}}
 .sevfilters button{{background:#0b0d11;border:1px solid #2a3140;color:#cfd6e0;border-radius:6px;padding:6px 10px;font-size:12px;cursor:pointer;margin-right:4px}}
 .sevfilters button.active{{background:#1f2530;border-color:#3a4658;color:#fff}}
 .muted{{color:#5b6472}}
 .conf{{font-size:11px;padding:1px 6px;border-radius:3px;margin-left:4px}}
 .conf-high{{background:#1b3a2b;color:#5bd98a}} .conf-medium{{background:#3a341b;color:#e6c84b}}
 .conf-low{{background:#3a1b1b;color:#e67a7a}} .conf-single{{background:#26303a;color:#9ac4e6}}
 .cvss{{font-size:11px;padding:1px 6px;border-radius:3px;margin-left:4px;background:#2a2350;color:#c7bdff;cursor:help}}
 details summary{{cursor:pointer;color:#7fd1ff;font-size:12px}}
 .reprobox{{position:relative}}
 .copy{{position:absolute;top:8px;right:8px;background:#1f2530;border:1px solid #3a4658;color:#cfd6e0;border-radius:5px;font-size:11px;padding:2px 8px;cursor:pointer}}
 .copy:hover{{background:#28303d}}
 pre.repro{{white-space:pre-wrap;word-break:break-all;background:#0b0d11;border:1px solid #232936;border-radius:6px;padding:8px;margin:6px 0 0;font-size:12px;color:#cfe8ff}}
</style></head>
<body>
 <header>
  <h1>WAFPierce Security Report</h1>
  <div class="sub">Target: {html.escape(target)} &nbsp;•&nbsp; Generated: {ts} &nbsp;•&nbsp; <span id="count">{len(results)}</span> shown</div>
 </header>
 <div class="wrap">
  <div class="exec">
   <h2>Executive summary</h2>
   <div class="grid">
    <div><span class="k">Total findings:</span> <span class="v">{len(results)}</span></div>
    <div><span class="k">Confirmed bypasses:</span> <span class="v">{bypasses}</span></div>
    <div><span class="k">Critical / High:</span> <span class="v">{counts.get('CRITICAL',0)} / {counts.get('HIGH',0)}</span></div>
    <div><span class="k">WAF / CDN:</span> <span class="v">{html.escape(detected_str)}</span></div>
    <div><span class="k">Top categories:</span> <span class="v">{html.escape(top_cats_str)}</span></div>
   </div>
  </div>
  <div class="summary">{summary}</div>
  <div class="toolbar">
   <input id="q" placeholder="Search findings…" oninput="applyFilters()">
   <select id="catf" onchange="applyFilters()"><option value="">All categories</option>{cat_options}</select>
   <span class="sevfilters">{sev_buttons}</span>
  </div>
  <table>
   <thead><tr><th>Severity</th><th>Technique</th><th>Category</th><th>Status</th><th>Reason</th><th>Path</th><th>Reproduce</th></tr></thead>
   <tbody>
   {''.join(rows) if rows else '<tr><td colspan=7>No findings.</td></tr>'}
   </tbody>
  </table>
 </div>
 <script>
  let sevFilter='ALL';
  function setSev(s,btn){{sevFilter=s;document.querySelectorAll('.sevfilters button').forEach(b=>b.classList.remove('active'));btn.classList.add('active');applyFilters();}}
  function applyFilters(){{
    const q=(document.getElementById('q').value||'').toLowerCase();
    const cat=document.getElementById('catf').value;
    let shown=0;
    document.querySelectorAll('tr.finding').forEach(tr=>{{
      const okSev=sevFilter==='ALL'||tr.dataset.sev===sevFilter;
      const okCat=!cat||tr.dataset.cat===cat;
      const okQ=!q||tr.textContent.toLowerCase().includes(q);
      const show=okSev&&okCat&&okQ; tr.style.display=show?'':'none'; if(show)shown++;
    }});
    document.getElementById('count').textContent=shown;
  }}
  function copyRepro(btn){{
    const pre=btn.parentElement.querySelector('pre');
    navigator.clipboard.writeText(pre.innerText).then(()=>{{const t=btn.textContent;btn.textContent='copied';setTimeout(()=>btn.textContent=t,1200);}});
  }}
 </script>
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


# ---------------------------------------------------------------------- JUnit
# Severity at or above this rank is reported as a JUnit test *failure* so CI
# surfaces it; everything else is a passing (informational) testcase.
# (_SEV_RANK is defined once near the top of the module.)
_JUNIT_FAIL_AT = _SEV_RANK['MEDIUM']


def _is_failure(r: Dict[str, Any]) -> bool:
    sev = (r.get('severity') or 'INFO').upper()
    return bool(r.get('bypass')) or _SEV_RANK.get(sev, 4) <= _JUNIT_FAIL_AT


def to_junit(target: str, results: List[Dict[str, Any]]) -> str:
    """JUnit XML so CI shows findings as test failures (grouped by category)."""
    from xml.sax.saxutils import escape, quoteattr

    by_cat: Dict[str, List[Dict[str, Any]]] = {}
    for r in results:
        by_cat.setdefault(r.get('category') or 'UNCATEGORIZED', []).append(r)

    total = len(results)
    total_fail = sum(1 for r in results if _is_failure(r))
    lines = ['<?xml version="1.0" encoding="utf-8"?>']
    lines.append(f'<testsuites name="WAFPierce" tests="{total}" '
                 f'failures="{total_fail}" errors="0">')
    for cat, items in by_cat.items():
        fails = sum(1 for r in items if _is_failure(r))
        lines.append(f'  <testsuite name={quoteattr(cat)} tests="{len(items)}" '
                     f'failures="{fails}">')
        for r in items:
            name = r.get('technique', 'finding')
            sev = (r.get('severity') or 'INFO').upper()
            lines.append(f'    <testcase classname={quoteattr(cat)} '
                         f'name={quoteattr(name)}>')
            if _is_failure(r):
                msg = f"[{sev}] {r.get('reason', '')}".strip()
                detail = []
                for k in ('reason', 'status', 'confidence', 'path', 'cvss_score', 'curl'):
                    if r.get(k) not in (None, ''):
                        detail.append(f"{k}: {r.get(k)}")
                lines.append(f'      <failure message={quoteattr(msg[:300])} '
                             f'type={quoteattr(sev)}>{escape(chr(10).join(detail))}</failure>')
            lines.append('    </testcase>')
        lines.append('  </testsuite>')
    lines.append('</testsuites>')
    return '\n'.join(lines)


# ------------------------------------------------------------------------ CSV
def to_csv(target: str, results: List[Dict[str, Any]]) -> str:
    """Flat CSV for spreadsheet triage."""
    import csv
    import io

    cols = ['severity', 'category', 'technique', 'bypass', 'confidence',
            'status', 'cvss_score', 'cwe', 'path', 'reason']
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator='\n')
    w.writerow(cols)
    # Most-severe first for readability.
    ordered = sorted(results, key=lambda r: _SEV_RANK.get((r.get('severity') or 'INFO').upper(), 4))
    for r in ordered:
        w.writerow([
            r.get('severity', ''), r.get('category', ''), r.get('technique', ''),
            'yes' if r.get('bypass') else 'no', r.get('confidence', ''),
            r.get('status', ''), r.get('cvss_score', ''), r.get('cwe', ''),
            r.get('path', ''), (r.get('reason', '') or '').replace('\n', ' '),
        ])
    return buf.getvalue()


# ----------------------------------------------------------------- Prometheus
def to_prometheus(target: str, results: List[Dict[str, Any]]) -> str:
    """OpenMetrics/Prometheus text exposition for monitor-mode textfile collector."""
    def esc(v: str) -> str:
        return str(v).replace('\\', '\\\\').replace('"', '\\"')

    counts = {s: 0 for s in _SEV_RANK}
    for r in results:
        sev = (r.get('severity') or 'INFO').upper()
        counts[sev] = counts.get(sev, 0) + 1
    bypasses = sum(1 for r in results if r.get('bypass'))
    t = esc(target)
    lines = [
        '# HELP wafpierce_findings_total Findings from the last scan, by severity.',
        '# TYPE wafpierce_findings_total gauge',
    ]
    for s in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
        lines.append(f'wafpierce_findings_total{{target="{t}",severity="{s}"}} {counts.get(s, 0)}')
    lines += [
        '# HELP wafpierce_bypasses_total Confirmed bypasses from the last scan.',
        '# TYPE wafpierce_bypasses_total gauge',
        f'wafpierce_bypasses_total{{target="{t}"}} {bypasses}',
        '# HELP wafpierce_findings All findings, total.',
        '# TYPE wafpierce_findings gauge',
        f'wafpierce_findings{{target="{t}"}} {len(results)}',
    ]
    return '\n'.join(lines) + '\n'


# ------------------------------------------------------------- HAR (Burp/ZAP)
def to_har(target: str, results: List[Dict[str, Any]]) -> str:
    """HAR 1.2 log of the findings' requests — importable by Burp and ZAP."""
    base = target.rstrip('/')
    entries = []
    for r in results:
        method = str(r.get('method') or 'GET').upper()
        url = base + (r.get('path') or '/')
        entries.append({
            'startedDateTime': datetime.datetime.now().isoformat(),
            'time': 0,
            'request': {
                'method': method, 'url': url, 'httpVersion': 'HTTP/1.1',
                'headers': [], 'queryString': [], 'cookies': [], 'headersSize': -1,
                'bodySize': -1,
            },
            'response': {
                'status': int(r.get('status') or 0), 'statusText': '',
                'httpVersion': 'HTTP/1.1', 'headers': [], 'cookies': [],
                'content': {'size': 0, 'mimeType': 'text/html'},
                'redirectURL': '', 'headersSize': -1, 'bodySize': -1,
            },
            'cache': {},
            'timings': {'send': 0, 'wait': 0, 'receive': 0},
            'comment': f"{r.get('severity', 'INFO')} | {r.get('technique', '')} | {r.get('reason', '')}",
        })
    doc = {'log': {
        'version': '1.2',
        'creator': {'name': 'WAFPierce', 'version': __version__},
        'entries': entries,
    }}
    return json.dumps(doc, indent=2, default=str)


# ------------------------------------------------------------------ diff report
def _finding_key(r: Dict[str, Any]):
    """Stable identity for a finding across two scans of the same target."""
    return (str(r.get('technique', '')), str(r.get('category', '')), str(r.get('path', '')))


def diff_results(old: List[Dict[str, Any]], new: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Compare two result sets. Returns dict with 'new', 'resolved', 'unchanged'."""
    old_keys = {_finding_key(r) for r in old}
    new_keys = {_finding_key(r) for r in new}
    return {
        'new': [r for r in new if _finding_key(r) not in old_keys],
        'resolved': [r for r in old if _finding_key(r) not in new_keys],
        'unchanged': [r for r in new if _finding_key(r) in old_keys],
    }


def to_html_diff(target: str, old: List[Dict[str, Any]], new: List[Dict[str, Any]]) -> str:
    """Standalone HTML diff of two scans, highlighting NEW and RESOLVED findings."""
    ts = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    d = diff_results(old, new)

    def _table(items, kind):
        if not items:
            return f"<p class='muted'>No {kind} findings.</p>"
        body = ''.join(
            f"<tr><td><span style='background:{_SEV_COLOR.get(r.get('severity','INFO'),'#607d8b')};"
            f"color:#fff;padding:2px 8px;border-radius:4px;font-size:12px'>"
            f"{html.escape(str(r.get('severity','INFO')))}</span></td>"
            f"<td>{html.escape(str(r.get('technique','')))}</td>"
            f"<td>{html.escape(str(r.get('category','')))}</td>"
            f"<td><code>{html.escape(str(r.get('path','')))}</code></td>"
            f"<td>{html.escape(str(r.get('reason','')))}</td></tr>"
            for r in sorted(items, key=lambda x: _SEV_RANK.get(x.get('severity', 'INFO'), 5))
        )
        return (f"<table><thead><tr><th>Severity</th><th>Technique</th><th>Category</th>"
                f"<th>Path</th><th>Reason</th></tr></thead><tbody>{body}</tbody></table>")

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>WAFPierce Diff — {html.escape(target)}</title>
<style>
 body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:#0f1115;color:#e6e6e6}}
 header{{background:#161a22;padding:24px 32px;border-bottom:1px solid #262b36}}
 h1{{margin:0;font-size:22px}} h2{{font-size:15px;margin:26px 0 8px}}
 .sub{{color:#9aa4b2;font-size:13px;margin-top:6px}} .wrap{{padding:24px 32px}}
 table{{width:100%;border-collapse:collapse;font-size:13px}}
 th,td{{text-align:left;padding:8px 10px;border-bottom:1px solid #232936}}
 th{{color:#9aa4b2;text-transform:uppercase;font-size:11px}} code{{color:#7fd1ff}}
 .muted{{color:#5b6472}} .new{{color:#ff7b7b}} .res{{color:#5bd98a}}
 .pill{{padding:4px 10px;border-radius:4px;margin-right:8px;font-weight:600}}
</style></head>
<body><header><h1>WAFPierce Scan Diff</h1>
 <div class="sub">Target: {html.escape(target)} &nbsp;•&nbsp; {ts} &nbsp;•&nbsp;
  <span class="pill" style="background:#3a1b1b;color:#ff7b7b">+{len(d['new'])} new</span>
  <span class="pill" style="background:#1b3a2b;color:#5bd98a">-{len(d['resolved'])} resolved</span>
  <span class="pill" style="background:#26303a;color:#9ac4e6">{len(d['unchanged'])} unchanged</span>
 </div></header>
 <div class="wrap">
  <h2 class="new">🔺 New findings ({len(d['new'])})</h2>{_table(d['new'], 'new')}
  <h2 class="res">✓ Resolved findings ({len(d['resolved'])})</h2>{_table(d['resolved'], 'resolved')}
 </div>
</body></html>"""


def export(results: List[Dict[str, Any]], target: str, fmt: str, path: str = None) -> str:
    """Render results to ``fmt`` ('sarif'|'nuclei'|'html'|'json'|'pdf'|'junit'|'csv');
    optionally write to ``path``."""
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
    elif fmt == 'junit':
        content = to_junit(target, results)
    elif fmt == 'csv':
        content = to_csv(target, results)
    elif fmt in ('prometheus', 'metrics', 'openmetrics'):
        content = to_prometheus(target, results)
    elif fmt == 'har':
        content = to_har(target, results)
    else:
        content = json.dumps(results, indent=2, default=str)
    if path:
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)
    return content
