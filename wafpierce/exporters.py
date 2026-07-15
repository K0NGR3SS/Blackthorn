"""
Blackthorn exporters

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
from urllib.parse import parse_qsl, urljoin, urlsplit

from . import __version__
from .branding import PRODUCT_NAME

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

_CANDIDATE_VERIFICATIONS = {'candidate', 'suspected', 'unconfirmed'}
_OBSERVATION_VERIFICATIONS = {'not_detected', 'informational', 'error'}


def result_state(result: Dict[str, Any]) -> str:
    """Return the canonical presentation state for a result.

    ``bypass`` historically meant both "interesting response" and "verified
    vulnerability".  New records carry explicit state, which must take
    precedence; the boolean is retained only as a legacy fallback.
    """
    result = result if isinstance(result, dict) else {}
    verification = str(
        result.get('verification_status') or result.get('verification') or ''
    ).strip().lower()
    kind = str(result.get('kind') or '').strip().lower()

    if kind in ('observation', 'coverage'):
        return 'observation'
    if verification in _CANDIDATE_VERIFICATIONS or kind == 'suspected':
        return 'candidate'
    if verification in _OBSERVATION_VERIFICATIONS:
        return 'observation'
    if verification in ('confirmed', 'verified') or kind == 'finding':
        return 'confirmed'
    return 'confirmed' if bool(result.get('bypass')) else 'observation'


def is_confirmed_result(result: Dict[str, Any]) -> bool:
    """Whether a record carries confirmed/verified finding semantics."""
    return result_state(result) == 'confirmed'


def _json_safe(value: Any) -> Any:
    """Return a JSON-serializable copy without discarding structured proof."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, bytes):
        return value.decode('utf-8', errors='replace')
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(v) for v in value]
    return str(value)


def _as_mapping(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return dict(value)
    if isinstance(value, (list, tuple)):
        out = {}
        for item in value:
            if isinstance(item, dict) and item.get('name') is not None:
                out[str(item['name'])] = item.get('value', '')
        return out
    return {}


def _request_data(target: str, result: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize canonical and legacy request fields for every exporter."""
    nested = result.get('request') if isinstance(result.get('request'), dict) else {}
    if nested.get('available') is False:
        return {
            'available': False,
            'note': str(nested.get('note') or 'Exact request was not recorded'),
            'method': '', 'url': '', 'path': '', 'headers': {}, 'body': None,
        }
    method = str(nested.get('method') or result.get('method') or 'GET').upper()
    raw_path = nested.get('path') or result.get('path')
    path = str(raw_path or '/')
    explicit_url = nested.get('url') or result.get('url') or result.get('request_url')
    if explicit_url:
        url = str(explicit_url)
        if not raw_path:
            parsed = urlsplit(url)
            path = parsed.path or '/'
            if parsed.query:
                path += '?' + parsed.query
    elif path.startswith(('http://', 'https://')):
        url = path
    else:
        url = urljoin(target.rstrip('/') + '/', path)
    headers_value = nested.get('headers')
    if headers_value is None:
        headers_value = result.get('request_headers')
    if headers_value is None:
        headers_value = result.get('headers')
    headers = _as_mapping(headers_value)
    if 'body' in nested:
        body = nested.get('body')
    elif 'request_body' in result:
        body = result.get('request_body')
    else:
        body = result.get('data')
    return {
        'available': True, 'method': method, 'url': url, 'path': path,
        'headers': headers, 'body': _json_safe(body),
    }


def _response_data(result: Dict[str, Any]) -> Dict[str, Any]:
    nested = result.get('response') if isinstance(result.get('response'), dict) else {}
    status = nested.get('status')
    if status is None:
        status = result.get('status')
    if status is None:
        status = result.get('response_code')
    size = nested.get('size')
    if size is None:
        size = result.get('size')
    return {
        **_json_safe(nested),
        'status': status,
        'size': size,
        'headers': _as_mapping(nested.get('headers')),
    }


def _cwe_id(result: Dict[str, Any]) -> str:
    """Canonical CWE label; external parsers use ``cwe_id``, older data ``cwe``."""
    value = result.get('cwe_id') or result.get('cwe') or ''
    if isinstance(value, (list, tuple)):
        value = value[0] if value else ''
    text = str(value).strip()
    if text and text.isdigit():
        return f'CWE-{text}'
    return text


def _evidence_items(result: Dict[str, Any]) -> List[Any]:
    evidence = result.get('evidence')
    if evidence in (None, '', [], {}):
        return []
    if isinstance(evidence, (list, tuple)):
        return [_json_safe(item) for item in evidence]
    return [_json_safe(evidence)]


def _remediation(result: Dict[str, Any]) -> Any:
    return (result.get('remediation') or result.get('recommendation') or
            result.get('solution') or '')


def _compact(value: Any, limit: int = 4000) -> str:
    if value in (None, '', [], {}):
        return ''
    if isinstance(value, (dict, list, tuple)):
        text = json.dumps(_json_safe(value), ensure_ascii=False, separators=(',', ':'))
    else:
        text = str(value)
    return text if len(text) <= limit else text[:limit] + '…'


def _prepared_results(results: List[Dict[str, Any]], redact: bool) -> List[Dict[str, Any]]:
    """Deep-copy findings and scrub credentials before rendering by default."""
    items = list(results or [])
    if not redact:
        return items
    try:
        from .redaction import redact_findings
        return redact_findings(items)
    except Exception as exc:
        # Fail closed: keep non-sensitive triage metadata but omit arbitrary
        # request/response text when the sanitizer cannot process a finding.
        logger.warning(f"Finding redaction failed; detailed proof omitted: {exc}")
        safe = []
        for item in items:
            if not isinstance(item, dict):
                continue
            safe.append({
                'severity': item.get('severity', 'INFO'),
                'category': item.get('category', ''),
                'technique': item.get('technique', 'finding'),
                'bypass': bool(item.get('bypass')),
                'confidence': item.get('confidence', ''),
                'verification_status': item.get('verification_status', ''),
                'status': item.get('status'),
                'cvss_score': item.get('cvss_score', ''),
                'cwe_id': item.get('cwe_id') or item.get('cwe') or '',
                'path': item.get('path', '/'),
                'reason': 'Detailed evidence omitted because redaction failed.',
            })
        return safe


def _prepared_target(target: str, redact: bool) -> str:
    text = str(target or '')
    if not redact:
        return text
    try:
        from .redaction import redact_text
        return redact_text(text)
    except Exception:
        return '<redacted-target>'


def _rule_id(result: Dict[str, Any]) -> str:
    cat = str(result.get('category') or 'finding').lower().replace(' ', '_')
    tech = str(result.get('technique') or 'unknown').split(':')[0].strip().lower()
    tech = ''.join(ch if ch.isalnum() else '_' for ch in tech)[:40]
    return f"blackthorn.{cat}.{tech}"


# --------------------------------------------------------------------- SARIF
def to_sarif(target: str, results: List[Dict[str, Any]], *, redact: bool = True) -> str:
    results = _prepared_results(results, redact)
    target = _prepared_target(target, redact)
    rules = {}
    sarif_results = []
    for r in results:
        rid = _rule_id(r)
        severity = str(r.get('severity') or 'INFO').upper()
        cwe = _cwe_id(r)
        if rid not in rules:
            rule = {
                'id': rid,
                'name': r.get('technique', rid),
                'shortDescription': {'text': r.get('technique', rid)},
                'defaultConfiguration': {'level': _SEV_TO_SARIF.get(severity, 'note')},
                'properties': {
                    'category': r.get('category', ''),
                    'security-severity': str(
                        r.get('cvss_score') or
                        {'CRITICAL': '9.5', 'HIGH': '8.0', 'MEDIUM': '5.0',
                         'LOW': '3.0', 'INFO': '0.0'}.get(severity, '0.0')
                    ),
                    **({'tags': [cwe], 'cwe_id': cwe} if cwe else {}),
                },
            }
            remediation = _remediation(r)
            if remediation:
                rule['fullDescription'] = {'text': _compact(remediation, 2000)}
            ref = str(r.get('reference_url') or '')
            if ref.startswith(('https://', 'http://')):
                rule['helpUri'] = ref
            rules[rid] = rule
        request = _request_data(target, r)
        response = _response_data(r)
        evidence = _evidence_items(r)
        reason = str(r.get('reason') or '')
        message = f"{r.get('technique', '')}: {reason}".strip(': ')
        finding = {
            'ruleId': rid,
            'level': _SEV_TO_SARIF.get(severity, 'note'),
            'message': {'text': message},
            'properties': {
                'severity': severity,
                'bypass': bool(r.get('bypass')),
                'kind': r.get('kind'),
                'verification_status': r.get('verification_status') or r.get('verification'),
                'confidence': r.get('confidence'),
                'confirmations': r.get('confirmations'),
                'status': response.get('status'),
                'request': request,
                'response': response,
                'baseline': _json_safe(r.get('baseline') or {}),
                'comparison': _json_safe(r.get('comparison') or {}),
                'evidence': evidence,
                'payload': _json_safe(r.get('payload')),
                'insertion_point': _json_safe(r.get('insertion_point')),
                'remediation': _json_safe(_remediation(r)),
                **({'cwe_id': cwe} if cwe else {}),
            },
        }
        if request.get('available') and request.get('url'):
            finding['locations'] = [{
                'physicalLocation': {'artifactLocation': {'uri': request['url']}}
            }]
        fingerprint = r.get('fingerprint') or r.get('finding_id')
        if fingerprint:
            finding['partialFingerprints'] = {'blackthorn/v1': str(fingerprint)}
        sarif_results.append(finding)
    doc = {
        '$schema': 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
        'version': '2.1.0',
        'runs': [{
            'tool': {'driver': {
                'name': PRODUCT_NAME,
                'version': __version__,
                'rules': list(rules.values()),
            }},
            'results': sarif_results,
        }],
    }
    return json.dumps(_json_safe(doc), indent=2)


# --------------------------------------------------------------------- Nuclei
def _yaml_escape(s: str) -> str:
    # JSON double-quoted strings are valid YAML scalars and safely encode newlines.
    return json.dumps(str(s), ensure_ascii=False)


def to_nuclei(target: str, results: List[Dict[str, Any]], *, redact: bool = True) -> str:
    """Generate evidence-aware Nuclei templates for confirmed findings."""
    results = _prepared_results(results, redact)
    target = _prepared_target(target, redact)
    docs = []
    for r in results:
        if not r.get('bypass'):
            continue
        if not is_confirmed_result(r):
            continue
        verification = str(r.get('verification_status') or r.get('verification') or '').lower()
        rid = _rule_id(r).replace('.', '-')
        request = _request_data(target, r)
        # A template without the exact request invents coverage and can report a
        # false positive against ``/``. Keep the finding in human/SARIF exports,
        # but do not pretend it is replayable as Nuclei.
        if not request.get('available') or not request.get('url'):
            continue
        response = _response_data(r)
        method = request['method']
        path = request['path'] or '/'
        if path.startswith(('http://', 'https://')):
            parsed = urlsplit(path)
            path = parsed.path or '/'
            if parsed.query:
                path += '?' + parsed.query
        sev = str(r.get('severity') or 'info').lower()
        if sev not in ('critical', 'high', 'medium', 'low', 'info', 'unknown'):
            sev = 'info'
        category = ''.join(
            ch if ch.isalnum() or ch in '-_' else '-'
            for ch in str(r.get('category') or 'misc').lower()
        ).strip('-') or 'misc'
        cwe = _cwe_id(r)

        lines = [
            f"id: {rid}",
            "info:",
            f"  name: {_yaml_escape(r.get('technique', 'Blackthorn finding'))}",
            "  author: blackthorn",
            f"  severity: {sev}",
            f"  description: {_yaml_escape(r.get('reason', ''))}",
            f"  tags: blackthorn,{category}",
        ]
        if cwe or r.get('cvss_score') not in (None, '', 0, 0.0):
            lines.append("  classification:")
            if cwe:
                lines.append(f"    cwe-id: {_yaml_escape(cwe)}")
            if r.get('cvss_score') not in (None, ''):
                lines.append(f"    cvss-score: {_yaml_escape(r.get('cvss_score'))}")
        lines.extend([
            "  metadata:",
            f"    blackthorn-verification: {_yaml_escape(verification or 'legacy-confirmed')}",
            f"    blackthorn-confidence: {_yaml_escape(r.get('confidence') or '')}",
            "http:",
            f"  - method: {method}",
            "    path:",
            f"      - {_yaml_escape('{{BaseURL}}' + path)}",
            "    redirects: false",
        ])
        if request['headers']:
            lines.append("    headers:")
            for name, value in request['headers'].items():
                lines.append(f"      {_yaml_escape(name)}: {_yaml_escape(value)}")
        if request['body'] not in (None, '', b''):
            body = request['body']
            if isinstance(body, (dict, list)):
                body = json.dumps(body, ensure_ascii=False, separators=(',', ':'))
            lines.append(f"    body: {_yaml_escape(body)}")

        body_signals = []
        header_signals = []
        for item in _evidence_items(r):
            if not isinstance(item, dict):
                continue
            matched = str(item.get('matched') or '').strip()
            signal = str(item.get('type') or item.get('signal') or '').lower()
            if not matched or len(matched) > 300:
                continue
            if signal in {
                'execution_marker', 'response_signature', 'unencoded_reflection',
                'resource_signature', 'kubernetes_api_signature',
                'provider_unclaimed_fingerprint',
            }:
                if matched not in body_signals:
                    body_signals.append(matched)
            elif signal in {
                'response_header_injection', 'external_redirect', 'redirect_changed',
            }:
                header_match = matched
                if signal == 'response_header_injection' and ':' in header_match:
                    # Header-name casing is transport-dependent; the randomized
                    # injected value is the stable proof token.
                    header_match = header_match.split(':', 1)[1].strip()
                if header_match and header_match not in header_signals:
                    header_signals.append(header_match)

        # Differential/state-transition and browser/OOB proof cannot be reduced
        # to one safe HTTP matcher. A status-only template would match ordinary
        # successful traffic, so omit it instead of shipping a misleading check.
        if not body_signals and not header_signals:
            continue

        lines.extend(["    matchers-condition: and", "    matchers:"])
        try:
            status = int(response.get('status') or 0)
        except (TypeError, ValueError):
            status = 0
        if status:
            lines.extend([
                "      - type: status", "        status:", f"          - {status}",
            ])
        for part, signals in (('body', body_signals), ('header', header_signals)):
            if not signals:
                continue
            lines.extend([
                "      - type: word",
                f"        part: {part}",
                "        condition: or",
                "        words:",
            ])
            lines.extend(f"          - {_yaml_escape(value)}" for value in signals[:5])
        docs.append('\n'.join(lines) + '\n')
    if not docs:
        return "# No confirmed (bypass) findings to export as Nuclei templates.\n"
    return "\n---\n".join(docs)


def _html_value(value: Any, limit: int = 5000) -> str:
    if value in (None, '', [], {}):
        return ''
    if isinstance(value, (dict, list, tuple)):
        text = json.dumps(_json_safe(value), indent=2, ensure_ascii=False)
    else:
        text = str(value)
    if len(text) > limit:
        text = text[:limit] + '\n… (truncated)'
    return html.escape(text, quote=True)


def _html_finding_proof(target: str, result: Dict[str, Any]) -> str:
    """Expandable, fully escaped request/response proof for the HTML report."""
    request = _request_data(str(result.get('target') or target), result)
    response = _response_data(result)
    baseline = result.get('baseline') if isinstance(result.get('baseline'), dict) else {}
    comparison = result.get('comparison') if isinstance(result.get('comparison'), dict) else {}
    evidence = _evidence_items(result)

    verification = result.get('verification_status') or result.get('verification') or ''
    confidence = result.get('confidence') or ''
    meta = []
    for label, value in (
        ('Verification', verification), ('Confidence', confidence),
        ('Confirmations', result.get('confirmations')), ('Finding type', result.get('kind')),
        ('CWE', _cwe_id(result)),
    ):
        if value not in (None, ''):
            meta.append(f"<dt>{label}</dt><dd>{_html_value(value, 500)}</dd>")

    sections = []
    if meta:
        sections.append("<dl class='proofmeta'>" + ''.join(meta) + "</dl>")
    if request.get('available'):
        request_view = {
            'method': request['method'], 'url': request['url'], 'path': request['path'],
            'headers': request['headers'], 'body': request['body'],
        }
        sections.append(
            "<h4>Request</h4><pre class='proofpre'>" + _html_value(request_view) + "</pre>"
        )
    else:
        sections.append(
            "<h4>Request</h4><div class='remediation'>Exact request unavailable: "
            + _html_value(request.get('note') or 'not recorded') + "</div>"
        )
    if result.get('payload') not in (None, '') or result.get('insertion_point'):
        payload_view = {
            'insertion_point': _json_safe(result.get('insertion_point')),
            'payload': _json_safe(result.get('payload')),
        }
        sections.append(
            "<h4>Payload</h4><pre class='proofpre'>" + _html_value(payload_view) + "</pre>"
        )
    if evidence:
        sections.append(
            "<h4>Evidence</h4><pre class='proofpre'>" + _html_value(evidence) + "</pre>"
        )
    if response and any(value not in (None, '', {}, []) for value in response.values()):
        sections.append(
            "<h4>Observed response</h4><pre class='proofpre'>" + _html_value(response) + "</pre>"
        )
    if baseline:
        sections.append(
            "<h4>Matched baseline</h4><pre class='proofpre'>" + _html_value(baseline) + "</pre>"
        )
    if comparison:
        sections.append(
            "<h4>Comparison</h4><pre class='proofpre'>" + _html_value(comparison) + "</pre>"
        )
    remediation = _remediation(result)
    if remediation:
        sections.append(
            "<h4>Remediation</h4><div class='remediation'>" + _html_value(remediation) + "</div>"
        )
    return (
        "<details class='proof'><summary>Proof &amp; request</summary>"
        + ''.join(sections) + "</details>"
    )


# ----------------------------------------------------------------------- HTML
def to_html(target: str, results: List[Dict[str, Any]], *, redact: bool = True) -> str:
    results = _prepared_results(results, redact)
    target = _prepared_target(target, redact)
    ts = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    counts = {s: 0 for s in _SEV_RANK}
    for r in results:
        counts[r.get('severity', 'INFO')] = counts.get(r.get('severity', 'INFO'), 0) + 1
    ordered = sorted(results, key=lambda r: _SEV_RANK.get(r.get('severity', 'INFO'), 5))

    rows = []
    for r in ordered:
        sev = str(r.get('severity') or 'INFO').upper()
        color = _SEV_COLOR.get(sev, '#607d8b')
        cat = str(r.get('category', ''))
        triage = r.get('ai_triage') or {}
        fp = ' <span style="color:#ff6b6b">(AI: likely FP)</span>' if triage.get('false_positive') else ''
        conf = r.get('confidence')
        conf_class = ''.join(ch if ch.isalnum() or ch in '-_' else '-'
                             for ch in str(conf or '').lower())
        conf_badge = (
            f" <span class='conf conf-{conf_class}'>{html.escape(str(conf))}"
            f"{' ' + html.escape(str(r['confirmations'])) if r.get('confirmations') else ''}</span>"
            if conf else ''
        )
        verification = r.get('verification_status') or r.get('verification')
        verification_badge = (
            f" <span class='verify'>{html.escape(str(verification))}</span>"
            if verification else ''
        )
        # CVSS badge with the vector + CWE as a hover tooltip.
        cvss = r.get('cvss_score')
        cvss_badge = ''
        if cvss not in (None, ''):
            tip = str(r.get('cvss_vector') or '')
            cwe = _cwe_id(r)
            if cwe:
                tip = (tip + '  ' + (cwe if str(cwe).upper().startswith('CWE') else f'CWE-{cwe}')).strip()
            cvss_badge = (f" <span class='cvss' title='{html.escape(tip)}'>CVSS "
                          f"{html.escape(str(cvss))}</span>")
        tech_extra = fp + conf_badge + verification_badge + cvss_badge
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
        repro_parts.append(_html_finding_proof(target, r))
        repro = ''.join(repro_parts) if repro_parts else '<span class="muted">—</span>'
        request = _request_data(str(r.get('target') or target), r)
        response = _response_data(r)
        rows.append(
            f"<tr class='finding' data-sev='{html.escape(sev)}' data-cat='{html.escape(cat)}'>"
            f"<td><span style='background:{color};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px'>{html.escape(sev)}</span></td>"
            f"<td>{html.escape(str(r.get('technique', '')))}{tech_extra}</td>"
            f"<td>{html.escape(cat)}</td>"
            f"<td>{html.escape(str(response.get('status') if response.get('status') is not None else ''))}</td>"
            f"<td>{html.escape(str(r.get('reason', '')))}</td>"
            f"<td><code>{html.escape(str(request.get('path', '')))}</code></td>"
            f"<td>{repro}</td>"
            f"</tr>"
        )
    summary = " ".join(
        f"<span style='background:{_SEV_COLOR[s]};color:#fff;padding:4px 10px;border-radius:4px;margin-right:6px'>{s}: {counts.get(s,0)}</span>"
        for s in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
    )

    # --- Executive summary inputs -------------------------------------------
    confirmed = sum(1 for r in results if result_state(r) == 'confirmed')
    candidates = sum(1 for r in results if result_state(r) == 'candidate')
    observations = sum(1 for r in results if result_state(r) == 'observation')
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
<title>Blackthorn Report — {html.escape(target)}</title>
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
 .verify{{font-size:11px;padding:1px 6px;border-radius:3px;margin-left:4px;background:#213042;color:#9fd0ff}}
 .cvss{{font-size:11px;padding:1px 6px;border-radius:3px;margin-left:4px;background:#2a2350;color:#c7bdff;cursor:help}}
 details summary{{cursor:pointer;color:#7fd1ff;font-size:12px}}
 .reprobox{{position:relative}}
 .copy{{position:absolute;top:8px;right:8px;background:#1f2530;border:1px solid #3a4658;color:#cfd6e0;border-radius:5px;font-size:11px;padding:2px 8px;cursor:pointer}}
 .copy:hover{{background:#28303d}}
 pre.repro{{white-space:pre-wrap;word-break:break-all;background:#0b0d11;border:1px solid #232936;border-radius:6px;padding:8px;margin:6px 0 0;font-size:12px;color:#cfe8ff}}
 details.proof{{margin-top:6px;min-width:260px;max-width:620px}}
 details.proof h4{{margin:10px 0 4px;color:#9aa4b2;font-size:11px;text-transform:uppercase}}
 .proofpre{{white-space:pre-wrap;word-break:break-all;background:#0b0d11;border:1px solid #232936;border-radius:6px;padding:8px;margin:4px 0;font-size:11px;color:#cfe8ff;max-height:240px;overflow:auto}}
 .proofmeta{{display:grid;grid-template-columns:max-content 1fr;gap:3px 10px;margin:8px 0;font-size:11px}}
 .proofmeta dt{{color:#9aa4b2}} .proofmeta dd{{margin:0}} .remediation{{white-space:pre-wrap;color:#cfd6e0;font-size:12px}}
</style></head>
<body>
 <header>
  <h1>Blackthorn Threat Hunting &amp; Web Security Report</h1>
  <div class="sub">Target: {html.escape(target)} &nbsp;•&nbsp; Generated: {ts} &nbsp;•&nbsp; <span id="count">{len(results)}</span> shown</div>
 </header>
 <div class="wrap">
  <div class="exec">
   <h2>Executive summary</h2>
   <div class="grid">
    <div><span class="k">Total results:</span> <span class="v">{len(results)}</span></div>
    <div><span class="k">Confirmed findings:</span> <span class="v">{confirmed}</span></div>
    <div><span class="k">Candidates to verify:</span> <span class="v">{candidates}</span></div>
    <div><span class="k">Observations:</span> <span class="v">{observations}</span></div>
    <div><span class="k">Critical / High:</span> <span class="v">{counts.get('CRITICAL',0)} / {counts.get('HIGH',0)}</span></div>
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


def to_pdf(target: str, results: List[Dict[str, Any]], path: str, *, redact: bool = True) -> bool:
    """Render a findings PDF to ``path`` using reportlab. Returns False if
    reportlab is unavailable (caller can fall back to HTML)."""
    results = _prepared_results(results, redact)
    target = _prepared_target(target, redact)
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

    doc = SimpleDocTemplate(path, pagesize=A4, title=f"Blackthorn — {target}")
    story = [Paragraph("Blackthorn Web Security Report", styles['Title']),
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
    return is_confirmed_result(r) and _SEV_RANK.get(sev, 4) <= _JUNIT_FAIL_AT


def to_junit(target: str, results: List[Dict[str, Any]], *, redact: bool = True) -> str:
    """JUnit XML so CI shows findings as test failures (grouped by category)."""
    results = _prepared_results(results, redact)
    target = _prepared_target(target, redact)
    from xml.sax.saxutils import escape, quoteattr

    by_cat: Dict[str, List[Dict[str, Any]]] = {}
    for r in results:
        by_cat.setdefault(r.get('category') or 'UNCATEGORIZED', []).append(r)

    total = len(results)
    total_fail = sum(1 for r in results if _is_failure(r))
    lines = ['<?xml version="1.0" encoding="utf-8"?>']
    lines.append(f'<testsuites name="Blackthorn" tests="{total}" '
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
def to_csv(target: str, results: List[Dict[str, Any]], *, redact: bool = True) -> str:
    """Flat CSV for spreadsheet triage, including proof and comparison fields."""
    results = _prepared_results(results, redact)
    target = _prepared_target(target, redact)
    import csv
    import io

    # Keep the original columns first for downstream compatibility, then append
    # evidence-aware fields from the canonical finding schema.
    cols = [
        'severity', 'category', 'technique', 'bypass', 'confidence',
        'status', 'cvss_score', 'cwe', 'path', 'reason',
        'finding_id', 'kind', 'verification_status', 'confirmations',
        'method', 'url', 'insertion_point', 'payload', 'evidence',
        'baseline_status', 'baseline_size', 'response_size',
        'similarity', 'size_delta', 'remediation',
    ]
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator='\n')
    w.writerow(cols)
    # Most-severe first for readability.
    ordered = sorted(results, key=lambda r: _SEV_RANK.get((r.get('severity') or 'INFO').upper(), 4))
    for r in ordered:
        request = _request_data(target, r)
        response = _response_data(r)
        baseline = r.get('baseline') if isinstance(r.get('baseline'), dict) else {}
        comparison = r.get('comparison') if isinstance(r.get('comparison'), dict) else {}
        w.writerow([
            r.get('severity', ''), r.get('category', ''), r.get('technique', ''),
            'yes' if r.get('bypass') else 'no', r.get('confidence', ''),
            response.get('status', ''), r.get('cvss_score', ''), _cwe_id(r),
            request.get('path', ''), str(r.get('reason') or '').replace('\n', ' '),
            r.get('finding_id') or r.get('fingerprint') or '', r.get('kind', ''),
            r.get('verification_status') or r.get('verification') or '',
            r.get('confirmations', ''), request.get('method', ''), request.get('url', ''),
            _compact(r.get('insertion_point')), _compact(r.get('payload')),
            _compact(_evidence_items(r)), baseline.get('status', ''),
            baseline.get('size', ''), response.get('size', ''),
            comparison.get('similarity', ''), comparison.get('size_delta', ''),
            _compact(_remediation(r)),
        ])
    return buf.getvalue()


# ----------------------------------------------------------------- Prometheus
def to_prometheus(target: str, results: List[Dict[str, Any]], *, redact: bool = True) -> str:
    """OpenMetrics/Prometheus text exposition for monitor-mode textfile collector."""
    results = _prepared_results(results, redact)
    target = _prepared_target(target, redact)
    def esc(v: str) -> str:
        return str(v).replace('\\', '\\\\').replace('"', '\\"')

    confirmed_results = [r for r in results if result_state(r) == 'confirmed']
    candidate_results = [r for r in results if result_state(r) == 'candidate']
    observation_results = [r for r in results if result_state(r) == 'observation']
    counts = {s: 0 for s in _SEV_RANK}
    for r in confirmed_results:
        sev = (r.get('severity') or 'INFO').upper()
        counts[sev] = counts.get(sev, 0) + 1
    bypasses = sum(1 for r in confirmed_results if r.get('bypass'))
    t = esc(target)
    lines = [
        '# HELP blackthorn_findings_total Confirmed findings from the last scan, by severity.',
        '# TYPE blackthorn_findings_total gauge',
    ]
    for s in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
        lines.append(f'blackthorn_findings_total{{target="{t}",severity="{s}"}} {counts.get(s, 0)}')
    lines += [
        '# HELP blackthorn_bypasses_total Confirmed bypasses from the last scan.',
        '# TYPE blackthorn_bypasses_total gauge',
        f'blackthorn_bypasses_total{{target="{t}"}} {bypasses}',
        '# HELP blackthorn_findings Confirmed findings, total.',
        '# TYPE blackthorn_findings gauge',
        f'blackthorn_findings{{target="{t}"}} {len(confirmed_results)}',
        '# HELP blackthorn_candidates_total Unverified candidates from the last scan.',
        '# TYPE blackthorn_candidates_total gauge',
        f'blackthorn_candidates_total{{target="{t}"}} {len(candidate_results)}',
        '# HELP blackthorn_observations_total Informational observations from the last scan.',
        '# TYPE blackthorn_observations_total gauge',
        f'blackthorn_observations_total{{target="{t}"}} {len(observation_results)}',
    ]
    return '\n'.join(lines) + '\n'


# ------------------------------------------------------------- HAR (Burp/ZAP)
def to_har(target: str, results: List[Dict[str, Any]], *, redact: bool = True) -> str:
    """HAR 1.2 requests/responses with Blackthorn proof metadata preserved."""
    results = _prepared_results(results, redact)
    target = _prepared_target(target, redact)
    entries = []
    for r in results:
        request = _request_data(target, r)
        if not request.get('available'):
            continue
        response = _response_data(r)
        parsed = urlsplit(request['url'])
        request_headers = [
            {'name': str(name), 'value': str(value)}
            for name, value in request['headers'].items()
        ]
        response_headers = [
            {'name': str(name), 'value': str(value)}
            for name, value in _as_mapping(response.get('headers')).items()
        ]
        body = request.get('body')
        if isinstance(body, (dict, list)):
            body_text = json.dumps(body, ensure_ascii=False, separators=(',', ':'))
        elif body is None:
            body_text = ''
        else:
            body_text = str(body)
        content_type = str(
            next((value for name, value in request['headers'].items()
                  if str(name).lower() == 'content-type'), '')
        )
        response_text = response.get('excerpt')
        if response_text is None:
            response_text = response.get('text') or ''
        try:
            response_status = int(response.get('status') or 0)
        except (TypeError, ValueError):
            response_status = 0
        try:
            response_size = int(response.get('size') or len(str(response_text).encode('utf-8')))
        except (TypeError, ValueError):
            response_size = len(str(response_text).encode('utf-8'))

        har_request = {
            'method': request['method'], 'url': request['url'], 'httpVersion': 'HTTP/1.1',
            'headers': request_headers,
            'queryString': [
                {'name': name, 'value': value}
                for name, value in parse_qsl(parsed.query, keep_blank_values=True)
            ],
            'cookies': [], 'headersSize': -1,
            'bodySize': len(body_text.encode('utf-8')) if body_text else 0,
        }
        if body_text:
            har_request['postData'] = {
                'mimeType': content_type or 'application/octet-stream',
                'text': body_text,
            }

        entries.append({
            'startedDateTime': str(r.get('started_at') or r.get('timestamp') or
                                   datetime.datetime.now(datetime.timezone.utc).isoformat()),
            'time': 0,
            'request': har_request,
            'response': {
                'status': response_status, 'statusText': '',
                'httpVersion': 'HTTP/1.1', 'headers': response_headers, 'cookies': [],
                'content': {
                    'size': response_size,
                    'mimeType': str(response.get('content_type') or 'application/octet-stream'),
                    **({'text': str(response_text)} if response_text not in (None, '') else {}),
                },
                'redirectURL': str(response.get('location') or ''),
                'headersSize': -1, 'bodySize': response_size,
            },
            'cache': {},
            'timings': {'send': 0, 'wait': 0, 'receive': 0},
            'comment': f"{r.get('severity', 'INFO')} | {r.get('technique', '')} | {r.get('reason', '')}",
            '_blackthorn': {
                'finding_id': r.get('finding_id') or r.get('fingerprint'),
                'severity': r.get('severity', 'INFO'),
                'category': r.get('category', ''),
                'kind': r.get('kind'),
                'verification_status': r.get('verification_status') or r.get('verification'),
                'confidence': r.get('confidence'),
                'cwe_id': _cwe_id(r),
                'payload': _json_safe(r.get('payload')),
                'insertion_point': _json_safe(r.get('insertion_point')),
                'evidence': _evidence_items(r),
                'baseline': _json_safe(r.get('baseline') or {}),
                'comparison': _json_safe(r.get('comparison') or {}),
                'remediation': _json_safe(_remediation(r)),
            },
        })
    doc = {'log': {
        'version': '1.2',
        'creator': {'name': PRODUCT_NAME, 'version': __version__},
        'entries': entries,
    }}
    return json.dumps(_json_safe(doc), indent=2)


# ------------------------------------------------------------------ diff report
def _finding_key(r: Dict[str, Any]):
    """Stable identity for a finding across two scans of the same target."""
    stable_id = r.get('fingerprint') or r.get('finding_id')
    if stable_id:
        return ('id', str(stable_id))
    insertion = r.get('insertion_point') if isinstance(r.get('insertion_point'), dict) else {}
    request = r.get('request') if isinstance(r.get('request'), dict) else {}
    raw_path = str(request.get('path') or r.get('path') or '')
    identity_path = urlsplit(raw_path).path or raw_path
    return (
        'legacy', str(r.get('technique', '')), str(r.get('category', '')),
        str(request.get('method') or r.get('method') or 'GET').upper(),
        identity_path,
        str(insertion.get('type') or ''), str(insertion.get('name') or ''),
    )


def _finding_state_signature(r: Dict[str, Any]) -> Dict[str, Any]:
    evidence_types = sorted({
        str(item.get('type') or item.get('signal') or '')
        for item in _evidence_items(r) if isinstance(item, dict)
    })
    return {
        'state': result_state(r),
        'verification_status': str(
            r.get('verification_status') or r.get('verification') or ''
        ).lower(),
        'kind': str(r.get('kind') or '').lower(),
        'severity': str(r.get('severity') or 'INFO').upper(),
        'confidence': str(r.get('confidence') or '').lower(),
        'bypass': bool(r.get('bypass')),
        'detector_id': str(r.get('detector_id') or ''),
        'evidence_types': evidence_types,
    }


def diff_results(old: List[Dict[str, Any]], new: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Compare result sets, including proof/verification state transitions."""
    old_by_key = {_finding_key(r): r for r in old}
    new_by_key = {_finding_key(r): r for r in new}
    old_keys = set(old_by_key)
    new_keys = set(new_by_key)
    shared = old_keys & new_keys
    changed = []
    unchanged = []
    for key in shared:
        before = old_by_key[key]
        after = new_by_key[key]
        before_state = _finding_state_signature(before)
        after_state = _finding_state_signature(after)
        if before_state == after_state:
            unchanged.append(after)
            continue
        changes = {
            name: {'from': before_state[name], 'to': after_state[name]}
            for name in before_state
            if before_state[name] != after_state[name]
        }
        changed.append({'before': before, 'after': after, 'changes': changes})
    return {
        'new': [r for r in new if _finding_key(r) not in old_keys],
        'resolved': [r for r in old if _finding_key(r) not in new_keys],
        'changed': changed,
        'unchanged': unchanged,
    }


def to_html_diff(target: str, old: List[Dict[str, Any]], new: List[Dict[str, Any]],
                 *, redact: bool = True) -> str:
    """Standalone HTML diff of two scans, highlighting NEW and RESOLVED findings."""
    old = _prepared_results(old, redact)
    new = _prepared_results(new, redact)
    target = _prepared_target(target, redact)
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

    def _changed_table(items):
        if not items:
            return "<p class='muted'>No changed findings.</p>"
        body = ''.join(
            f"<tr><td>{html.escape(str(item['after'].get('technique', '')))}</td>"
            f"<td><code>{html.escape(str(item['after'].get('path', '')))}</code></td>"
            f"<td><pre>{html.escape(json.dumps(item.get('changes') or {}, indent=2))}</pre></td></tr>"
            for item in items
        )
        return ("<table><thead><tr><th>Technique</th><th>Path</th><th>State changes</th>"
                f"</tr></thead><tbody>{body}</tbody></table>")

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Blackthorn Diff — {html.escape(target)}</title>
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
<body><header><h1>Blackthorn Scan Diff</h1>
 <div class="sub">Target: {html.escape(target)} &nbsp;•&nbsp; {ts} &nbsp;•&nbsp;
  <span class="pill" style="background:#3a1b1b;color:#ff7b7b">+{len(d['new'])} new</span>
  <span class="pill" style="background:#1b3a2b;color:#5bd98a">-{len(d['resolved'])} resolved</span>
  <span class="pill" style="background:#3a341b;color:#e6c84b">~{len(d['changed'])} changed</span>
  <span class="pill" style="background:#26303a;color:#9ac4e6">{len(d['unchanged'])} unchanged</span>
 </div></header>
 <div class="wrap">
  <h2 class="new">🔺 New findings ({len(d['new'])})</h2>{_table(d['new'], 'new')}
  <h2 class="res">✓ Resolved findings ({len(d['resolved'])})</h2>{_table(d['resolved'], 'resolved')}
  <h2>↕ Changed findings ({len(d['changed'])})</h2>{_changed_table(d['changed'])}
 </div>
</body></html>"""


def export(results: List[Dict[str, Any]], target: str, fmt: str, path: str = None,
           *, redact: bool = True) -> str:
    """Render results to ``fmt`` ('sarif'|'nuclei'|'html'|'json'|'pdf'|'junit'|'csv');
    optionally write to ``path``. Credentials are redacted from a deep copy by
    default; pass ``redact=False`` only for an explicitly private artifact."""
    results = _prepared_results(results, redact)
    target = _prepared_target(target, redact)
    fmt = (fmt or 'json').lower()
    if fmt == 'pdf':
        if not path:
            raise ValueError("PDF export requires an output path")
        if to_pdf(target, results, path, redact=False):
            return path
        # Fall back to an HTML file alongside the requested path.
        html_path = path.rsplit('.', 1)[0] + '.html'
        content = to_html(target, results, redact=False)
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(content)
        logger.warning(f"PDF unavailable; wrote HTML to {html_path}")
        return html_path
    if fmt == 'sarif':
        content = to_sarif(target, results, redact=False)
    elif fmt == 'nuclei':
        content = to_nuclei(target, results, redact=False)
    elif fmt == 'html':
        content = to_html(target, results, redact=False)
    elif fmt == 'junit':
        content = to_junit(target, results, redact=False)
    elif fmt == 'csv':
        content = to_csv(target, results, redact=False)
    elif fmt in ('prometheus', 'metrics', 'openmetrics'):
        content = to_prometheus(target, results, redact=False)
    elif fmt == 'har':
        content = to_har(target, results, redact=False)
    else:
        content = json.dumps(results, indent=2, default=str)
    if path:
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)
    return content
