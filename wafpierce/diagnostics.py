"""Runtime diagnostics: version reporting and a `doctor` preflight check.

Centralizes the "is this optional component actually installed?" logic so the
CLI can answer the perennial *"why doesn't --impersonate / --export-format pdf
work?"* question without the user having to read a stack trace.
"""
from __future__ import annotations

import os
import platform
import sys
from typing import List, Optional, Tuple

from . import __version__
from .branding import CLI_NAME, PRODUCT_NAME


# (import_name, friendly_label, what it powers, pip install hint)
# `pip` is None for components that ship with the core requirements.
OPTIONAL_COMPONENTS: List[Tuple[str, str, str, Optional[str]]] = [
    ('curl_cffi', 'curl_cffi', 'Browser TLS (JA3/JA4)+HTTP/2 impersonation (--impersonate)', 'pip install curl_cffi'),
    ('httpx', 'httpx', 'HTTP/2 smuggling + single-packet race tests', 'pip install "httpx[http2]"'),
    ('h2', 'h2 (httpx[http2])', 'HTTP/2 wire protocol for httpx', 'pip install "httpx[http2]"'),
    ('reportlab', 'reportlab', 'PDF report export (--export-format pdf)', 'pip install reportlab'),
    ('cryptography', 'cryptography', 'SSL/TLS cert analysis + Interactsh OOB crypto', 'pip install cryptography'),
    ('playwright', 'playwright', 'Headless-browser tests: DOM XSS / CSPT', 'pip install playwright && python -m playwright install chromium'),
    ('anthropic', 'anthropic', 'AI triage / AI report (--ai-triage / --ai-report)', 'pip install anthropic'),
    ('PySide6', 'PySide6', 'Desktop GUI (blackthorn gui / run_gui.py)', 'pip install PySide6'),
    ('pymetasploit3', 'pymetasploit3', 'Metasploit RPC integration (blackthorn msf)', 'pip install pymetasploit3'),
]


def _module_version(mod_name: str) -> Optional[str]:
    """Best-effort version string for an installed module."""
    try:
        from importlib import metadata as _md
    except Exception:  # pragma: no cover - py<3.8
        _md = None
    # Distribution name often differs from import name; try a few.
    dist_candidates = {
        'PySide6': 'PySide6',
        'curl_cffi': 'curl_cffi',
        'h2': 'h2',
    }
    if _md is not None:
        for cand in {mod_name, dist_candidates.get(mod_name, mod_name)}:
            try:
                return _md.version(cand)
            except Exception:
                continue
    try:
        mod = __import__(mod_name)
        return getattr(mod, '__version__', None)
    except Exception:
        return None


def check_component(import_name: str) -> Tuple[bool, Optional[str]]:
    """Return (available, version_or_None) without importing heavy side effects."""
    try:
        import importlib.util
        spec = importlib.util.find_spec(import_name)
    except Exception:
        spec = None
    if spec is None:
        return False, None
    return True, _module_version(import_name)


def component_report() -> List[dict]:
    """Structured availability report for every optional component."""
    report = []
    for import_name, label, purpose, pip_hint in OPTIONAL_COMPONENTS:
        available, version = check_component(import_name)
        report.append({
            'import_name': import_name,
            'label': label,
            'purpose': purpose,
            'pip': pip_hint,
            'available': available,
            'version': version,
        })
    return report


def _marks(no_color: bool) -> Tuple[str, str]:
    """(ok_mark, bad_mark) — unicode when the terminal can take it."""
    if no_color:
        return '[+]', '[-]'
    enc = (getattr(sys.stdout, 'encoding', None) or 'ascii').lower()
    try:
        '✓✗'.encode(enc)
        return '✓', '✗'
    except (UnicodeEncodeError, LookupError):
        return '[+]', '[-]'


def print_version(no_color: bool = False, stream=None) -> None:
    """Print version + which optional components are actually importable."""
    out = stream or sys.stdout
    ok, bad = _marks(no_color)
    print(f"{PRODUCT_NAME} {__version__}", file=out)
    print(f"Python {platform.python_version()} on {sys.platform}", file=out)
    print("", file=out)
    print("Optional components:", file=out)
    for c in component_report():
        if c['available']:
            ver = c['version'] or '?'
            print(f"  {ok} {c['label']:<20} {ver:<10} {c['purpose']}", file=out)
        else:
            hint = f"  ->  {c['pip']}" if c['pip'] else ""
            print(f"  {bad} {c['label']:<20} {'(missing)':<10} {c['purpose']}{hint}", file=out)


def _check_network_egress(timeout: float = 5.0) -> Tuple[bool, str]:
    try:
        import urllib.request
        req = urllib.request.Request('https://example.com', method='HEAD',
                                     headers={'User-Agent': f'{PRODUCT_NAME}-doctor'})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return True, f"reachable (HTTP {resp.status})"
    except Exception as e:
        return False, f"no egress to https://example.com ({type(e).__name__})"


def _check_config_dir() -> Tuple[bool, str]:
    try:
        from .config import ensure_config_dir
        d = ensure_config_dir()
        probe = os.path.join(d, '.doctor_write_test')
        with open(probe, 'w', encoding='utf-8') as f:
            f.write('ok')
        os.remove(probe)
        return True, d
    except Exception as e:
        from .config import get_config_dir
        return False, f"{get_config_dir()} not writable ({type(e).__name__})"


def _check_oob() -> Tuple[bool, str]:
    """OOB confirmation readiness (best-effort, no network spray)."""
    try:
        from .oob import build_oob  # noqa: F401
    except Exception as e:
        return False, f"oob module import failed ({type(e).__name__})"
    crypto_ok, _ = check_component('cryptography')
    if not crypto_ok:
        return False, "cryptography missing -> Interactsh OOB unavailable"
    return True, "Interactsh + self-hosted listener available"


def _check_recon_tools() -> List[Tuple[str, bool, str]]:
    """(label, available, hint) for each required external recon binary."""
    from .recon import REQUIRED_TOOLS, _which
    rows = []
    for binary, label, _stage, hint in REQUIRED_TOOLS:
        path = _which(binary)
        rows.append((label, path is not None, path or hint))
    return rows


def _check_metasploit() -> Tuple[bool, str]:
    """Is pymetasploit3 importable? (RPC reachability needs creds, so skip it.)"""
    avail, ver = check_component('pymetasploit3')
    if avail:
        return True, f"pymetasploit3 {ver or ''} (start msfrpcd + set RPC creds to use)"
    return False, "pymetasploit3 missing -> pip install pymetasploit3"


def run_doctor(no_color: bool = False, check_network: bool = True) -> int:
    """Green/red preflight checklist. Returns a process exit code (0 = all core OK)."""
    no_color = no_color or bool(os.environ.get('NO_COLOR'))
    ok, bad = _marks(no_color)
    print(f"{PRODUCT_NAME} {__version__} - doctor\n")

    core_ok = True

    # 1. Python version
    py_ok = sys.version_info >= (3, 8)
    print(f"  {ok if py_ok else bad} Python {platform.python_version()} "
          f"({'>= 3.8' if py_ok else 'NEEDS >= 3.8'})")
    core_ok = core_ok and py_ok

    # 2. Core importable deps
    print("\n  Core dependencies:")
    for name in ('requests', 'urllib3', 'cryptography', 'httpx'):
        avail, ver = check_component(name)
        print(f"    {ok if avail else bad} {name:<16} {ver or ('(missing)' if not avail else '')}")
        if name in ('requests', 'urllib3') and not avail:
            core_ok = False

    # 3. Optional components
    print("\n  Optional components:")
    for c in component_report():
        mark = ok if c['available'] else bad
        ver = c['version'] or ('(missing)' if not c['available'] else '')
        line = f"    {mark} {c['label']:<20} {ver:<10} {c['purpose']}"
        if not c['available'] and c['pip']:
            line += f"   ->  {c['pip']}"
        print(line)

    # 4. Config dir writable
    cfg_ok, cfg_msg = _check_config_dir()
    print(f"\n  {ok if cfg_ok else bad} Config dir: {cfg_msg}")
    core_ok = core_ok and cfg_ok

    # 5. OOB readiness
    oob_ok, oob_msg = _check_oob()
    print(f"  {ok if oob_ok else bad} OOB: {oob_msg}")

    # 5b. Recon external tools (required for the recon subcommand)
    print(f"\n  Recon tools (required for `{CLI_NAME} recon`):")
    recon_rows = _check_recon_tools()
    for label, avail, info in recon_rows:
        mark = ok if avail else bad
        suffix = info if avail else f"(missing)  ->  {info}"
        print(f"    {mark} {label:<12} {suffix}")
    recon_ready = all(a for _l, a, _i in recon_rows)
    print(f"    {ok if recon_ready else bad} recon "
          f"{'ready' if recon_ready else 'NOT ready - install the tools above'}")

    # 5c. Metasploit integration
    msf_ok, msf_msg = _check_metasploit()
    print(f"\n  {ok if msf_ok else bad} Metasploit: {msf_msg}")

    # 6. Network egress (best-effort, opt-out)
    if check_network:
        net_ok, net_msg = _check_network_egress()
        print(f"  {ok if net_ok else bad} Network: {net_msg}")

    print()
    if core_ok:
        print(f"  {ok} Core checks passed.")
        return 0
    print(f"  {bad} One or more core checks FAILED — see above.")
    return 1
