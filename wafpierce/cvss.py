"""
CVSS v3.1 scoring for findings.

The engine emits qualitative severities (CRITICAL/HIGH/...). Reports and CI
gates often want a numeric CVSS base score and vector. This maps a finding to a
representative score/vector by severity, refined per finding category, and
attaches a CWE id where one is well-known. It is intentionally conservative:
these are baseline estimates for triage, not a substitute for manual scoring.
"""
from typing import Any, Dict, Optional, Tuple

# Representative base scores + vectors per qualitative severity.
_SEVERITY = {
    'CRITICAL': (9.8, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'),
    'HIGH':     (7.5, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'),
    'MEDIUM':   (5.3, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'),
    'LOW':      (3.1, 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N'),
    'INFO':     (0.0, ''),
}

# Category/technique substring -> (CWE id, optional severity floor override).
# Matched case-insensitively against category then technique.
_CWE = [
    ('sqli', 'CWE-89'), ('sql', 'CWE-89'),
    ('xss', 'CWE-79'), ('ssrf', 'CWE-918'), ('xxe', 'CWE-611'),
    ('command', 'CWE-77'), ('rce', 'CWE-94'), ('ssti', 'CWE-1336'),
    ('traversal', 'CWE-22'), ('lfi', 'CWE-22'),
    ('idor', 'CWE-639'), ('cors', 'CWE-942'), ('redirect', 'CWE-601'),
    ('csrf', 'CWE-352'), ('crlf', 'CWE-93'), ('deserial', 'CWE-502'),
    ('jwt', 'CWE-347'), ('saml', 'CWE-347'),
    ('smuggl', 'CWE-444'), ('desync', 'CWE-444'),
    ('cache', 'CWE-525'), ('clickjack', 'CWE-1021'),
    ('header', 'CWE-693'), ('cookie', 'CWE-614'),
    ('disclosure', 'CWE-200'), ('secret', 'CWE-200'), ('api key', 'CWE-200'),
    ('csp', 'CWE-693'), ('log4shell', 'CWE-917'), ('jndi', 'CWE-917'),
    ('prototype', 'CWE-1321'), ('open redirect', 'CWE-601'),
    ('llm', 'CWE-1427'), ('prompt injection', 'CWE-1427'),
    ('oob', 'CWE-918'),
]


def cwe_for(result: Dict[str, Any]) -> Optional[str]:
    hay = f"{result.get('category','')} {result.get('technique','')}".lower()
    for needle, cwe in _CWE:
        if needle in hay:
            return cwe
    return None


def score(result: Dict[str, Any]) -> Tuple[float, str, Optional[str]]:
    """Return (base_score, vector, cwe) for a finding."""
    sev = str(result.get('severity', 'INFO')).upper()
    base, vector = _SEVERITY.get(sev, _SEVERITY['INFO'])
    # OOB-confirmed blind RCE/SSRF deserves the full critical vector.
    if result.get('category') == 'OOB' and sev == 'CRITICAL':
        base, vector = 9.8, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
    return base, vector, cwe_for(result)


def annotate(results) -> None:
    """In-place: attach cvss_score / cvss_vector / cwe_id to findings missing them."""
    for r in results:
        if not isinstance(r, dict):
            continue
        if r.get('cvss_score'):
            continue
        base, vector, cwe = score(r)
        r['cvss_score'] = base
        if vector:
            r['cvss_vector'] = vector
        if cwe and not r.get('cwe_id'):
            r['cwe_id'] = cwe
