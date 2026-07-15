"""Auto-installer for the external recon tools.

Recon shells out to subfinder / amass / dnsx / httpx / nmap and refuses to run
unless they are on PATH (see :mod:`wafpierce.recon`). This module downloads
prebuilt binaries into a managed directory under the WAFPierce config dir and
puts that directory on PATH, so the user can get recon-ready without installing
Go or a package manager.

Sources:
  * subfinder / dnsx / httpx  -> ProjectDiscovery GitHub release zips
  * amass                     -> OWASP amass GitHub release zips
  * nmap                      -> the official Windows portable .zip (Windows
                                 only; elsewhere we point at the package manager)

Everything is best-effort and per-tool: :func:`download_all` never raises, it
returns a ``{tool: (status, detail)}`` map so the caller can report what worked.
"""
from __future__ import annotations

import os
import re
import json
import shutil
import ssl
import stat
import tarfile
import tempfile
import platform
import zipfile
import urllib.request
from typing import Callable, Dict, List, Optional, Tuple

from .config import ensure_config_dir

# Binary name -> (github "owner/repo", binary basename inside the archive).
GITHUB_TOOLS: Dict[str, Tuple[str, str]] = {
    # Required recon tools
    'subfinder': ('projectdiscovery/subfinder', 'subfinder'),
    'dnsx': ('projectdiscovery/dnsx', 'dnsx'),
    'httpx': ('projectdiscovery/httpx', 'httpx'),
    'amass': ('owasp-amass/amass', 'amass'),
    # Optional tools that add richer recon stages
    'tlsx': ('projectdiscovery/tlsx', 'tlsx'),
    'katana': ('projectdiscovery/katana', 'katana'),
    'nuclei': ('projectdiscovery/nuclei', 'nuclei'),
    'naabu': ('projectdiscovery/naabu', 'naabu'),
    'gau': ('lc/gau', 'gau'),
    'dalfox': ('hahwul/dalfox', 'dalfox'),
    # Standalone pentest sections
    'ffuf': ('ffuf/ffuf', 'ffuf'),                       # content discovery / fuzzing
    'feroxbuster': ('epi052/feroxbuster', 'feroxbuster'),  # recursive content discovery
    'gobuster': ('OJ/gobuster', 'gobuster'),             # dir/dns/vhost brute
    'trufflehog': ('trufflesecurity/trufflehog', 'trufflehog'),  # secret scanning
    'gitleaks': ('gitleaks/gitleaks', 'gitleaks'),       # secret scanning (repos)
    'interactsh-client': ('projectdiscovery/interactsh', 'interactsh-client'),  # OOB callbacks
    's3scanner': ('sa7mon/S3Scanner', 's3scanner'),      # open cloud buckets
}

# nmap stopped shipping a portable win32 .zip after 7.92 (newer releases are
# installer-only), so the newest drop-in binary is 7.92. Used as a fallback if
# the live /dist/ listing can't be scraped.
_NMAP_FALLBACK_ZIP = 'https://nmap.org/dist/nmap-7.92-win32.zip'

# NB: do NOT use a bare 'win' token for Windows — it is a substring of 'darwin',
# which made macOS assets match as Windows (WinError 216 at runtime). Goreleaser
# and ProjectDiscovery both name Windows assets with the full word 'windows'.
_OS_TOKENS = {
    'windows': ('windows',),
    'linux': ('linux',),
    'darwin': ('macos', 'darwin', 'osx'),
}
_ARCH_TOKENS = {
    'amd64': ('amd64', 'x86_64', 'x64'),
    'arm64': ('arm64', 'aarch64'),
    '386': ('386', 'i386'),
}

_Logger = Callable[[str], None]


def _noop(_m: str) -> None:
    pass


# --------------------------------------------------------------------------- #
# Paths / PATH wiring
# --------------------------------------------------------------------------- #
def tools_dir() -> str:
    """Managed directory where downloaded tool binaries live (created)."""
    d = os.path.join(ensure_config_dir(), 'tools')
    try:
        os.makedirs(d, exist_ok=True)
    except OSError:
        pass
    return d


def ensure_tools_on_path() -> str:
    """Prepend the managed tools dir (and its nmap subdir) to PATH, idempotently.

    Returns the tools dir. Safe to call repeatedly and at import time — both the
    GUI process and the recon subprocess call this so ``shutil.which`` resolves
    freshly downloaded binaries without a restart.
    """
    d = tools_dir()
    extra = [d]
    nmapd = os.path.join(d, 'nmap')
    if os.path.isdir(nmapd):
        extra.append(nmapd)
    cur = os.environ.get('PATH', '')
    parts = cur.split(os.pathsep) if cur else []
    new = [p for p in extra if p not in parts]
    if new:
        os.environ['PATH'] = os.pathsep.join(new + parts) if parts else os.pathsep.join(new)
    return d


# --------------------------------------------------------------------------- #
# Download helpers
# --------------------------------------------------------------------------- #
def _ctx() -> ssl.SSLContext:
    try:
        return ssl.create_default_context()
    except Exception:
        return ssl.create_default_context()


def _platform() -> Tuple[str, str]:
    sysname = platform.system().lower()
    if 'windows' in sysname:
        sysname = 'windows'
    elif 'darwin' in sysname or 'mac' in sysname:
        sysname = 'darwin'
    else:
        sysname = 'linux'
    arch = platform.machine().lower()
    if arch in ('x86_64', 'amd64', 'x64'):
        arch = 'amd64'
    elif arch in ('aarch64', 'arm64'):
        arch = 'arm64'
    elif arch in ('i386', 'i686', 'x86'):
        arch = '386'
    return sysname, arch


def _fetch_bytes(url: str, timeout: float = 60.0,
                 progress: Optional[Callable[[int, int], None]] = None) -> bytes:
    req = urllib.request.Request(url, headers={'User-Agent': 'Blackthorn-installer'})
    with urllib.request.urlopen(req, timeout=timeout, context=_ctx()) as r:
        total = int(r.headers.get('Content-Length') or 0)
        chunks = []
        got = 0
        while True:
            chunk = r.read(65536)
            if not chunk:
                break
            chunks.append(chunk)
            got += len(chunk)
            if progress:
                progress(got, total)
        return b''.join(chunks)


def _fetch_text(url: str, timeout: float = 30.0) -> str:
    req = urllib.request.Request(
        url, headers={'User-Agent': 'Blackthorn-installer',
                      'Accept': 'application/vnd.github+json'})
    with urllib.request.urlopen(req, timeout=timeout, context=_ctx()) as r:
        return r.read().decode('utf-8', 'replace')


def _gh_latest_assets(repo: str) -> Tuple[List[dict], str]:
    data = json.loads(_fetch_text(f'https://api.github.com/repos/{repo}/releases/latest'))
    return data.get('assets', []) or [], data.get('tag_name', '') or ''


def _pick_asset(assets: List[dict], sysname: str, arch: str) -> Optional[dict]:
    os_toks = _OS_TOKENS.get(sysname, (sysname,))
    arch_toks = _ARCH_TOKENS.get(arch, (arch,))
    candidates = []
    for a in assets:
        name = (a.get('name') or '').lower()
        if not (name.endswith('.zip') or name.endswith('.tar.gz') or name.endswith('.tgz')):
            continue
        if any(t in name for t in ('checksum', 'sha256', '.sig', '.pem')):
            continue
        if not any(t in name for t in os_toks):
            continue
        if not any(t in name for t in arch_toks):
            continue
        candidates.append(a)
    if not candidates:
        return None
    # Prefer the shortest name (avoids "-extended"/variant builds when present).
    candidates.sort(key=lambda a: len(a.get('name') or ''))
    return candidates[0]


def _extract_member(archive_path: str, binary: str, dest: str) -> str:
    """Extract the file named ``binary`` (with/without .exe) from a zip/tar to
    ``dest`` (a file path) and mark it executable. Returns ``dest``."""
    wanted = {binary.lower(), f'{binary.lower()}.exe'}
    tmpd = tempfile.mkdtemp(prefix='wp_tool_')
    try:
        if archive_path.endswith(('.tar.gz', '.tgz')):
            with tarfile.open(archive_path, 'r:*') as tf:
                tf.extractall(tmpd)
        else:
            with zipfile.ZipFile(archive_path) as zf:
                zf.extractall(tmpd)
        found = None
        for root, _dirs, files in os.walk(tmpd):
            for fn in files:
                if fn.lower() in wanted:
                    found = os.path.join(root, fn)
                    break
            if found:
                break
        if not found:
            raise RuntimeError(f'binary "{binary}" not found inside archive')
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        shutil.copy2(found, dest)
        try:
            st = os.stat(dest)
            os.chmod(dest, st.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        except OSError:
            pass
        return dest
    finally:
        shutil.rmtree(tmpd, ignore_errors=True)


def _install_github_tool(repo: str, binary: str, log: _Logger) -> str:
    sysname, arch = _platform()
    assets, tag = _gh_latest_assets(repo)
    asset = _pick_asset(assets, sysname, arch)
    if asset is None:
        raise RuntimeError(f'no prebuilt {binary} for {sysname}/{arch} in {repo} {tag}')
    name = asset.get('name')
    url = asset.get('browser_download_url')
    log(f'  fetching {name} ({tag}) …')
    blob = _fetch_bytes(url, progress=_mk_progress(log, name))
    tmp = os.path.join(tempfile.gettempdir(), name)
    with open(tmp, 'wb') as f:
        f.write(blob)
    try:
        ext = '.exe' if sysname == 'windows' else ''
        dest = os.path.join(tools_dir(), binary + ext)
        log('  extracting …')
        return _extract_member(tmp, binary, dest)
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass


def _nmap_windows_zip_url() -> str:
    """Newest portable win32 .zip that actually exists in nmap's dist listing.

    nmap removed the portable zip from the download page after 7.92 (newer
    releases ship only a setup.exe installer), so we read the live /dist/ index
    and pick the highest version whose -win32.zip is really published.
    """
    try:
        html = _fetch_text('https://nmap.org/dist/')
        versions = re.findall(r'nmap-([\d.]+)-win32\.zip', html)
        if versions:
            def _key(v: str):
                return tuple(int(x) for x in v.split('.') if x.isdigit())
            best = max(set(versions), key=_key)
            return f'https://nmap.org/dist/nmap-{best}-win32.zip'
    except Exception:
        pass
    return _NMAP_FALLBACK_ZIP


def _install_nmap(log: _Logger) -> str:
    sysname, _arch = _platform()
    if sysname != 'windows':
        raise RuntimeError(
            'auto-download is Windows-only for nmap; install via your package '
            'manager (apt install nmap / brew install nmap / snap install nmap)')
    url = _nmap_windows_zip_url()
    name = url.rsplit('/', 1)[-1]
    log(f'  fetching {name} …')
    blob = _fetch_bytes(url, progress=_mk_progress(log, name))
    tmp = os.path.join(tempfile.gettempdir(), name)
    with open(tmp, 'wb') as f:
        f.write(blob)
    tmpd = tempfile.mkdtemp(prefix='wp_nmap_')
    try:
        with zipfile.ZipFile(tmp) as zf:
            zf.extractall(tmpd)
        exe = None
        for root, _dirs, files in os.walk(tmpd):
            for fn in files:
                if fn.lower() == 'nmap.exe':
                    exe = os.path.join(root, fn)
                    break
            if exe:
                break
        if not exe:
            raise RuntimeError('nmap.exe not found inside archive')
        # nmap needs its data files (nmap-services, nse scripts) next to the exe,
        # so copy the whole portable folder into tools/nmap/.
        srcdir = os.path.dirname(exe)
        dest = os.path.join(tools_dir(), 'nmap')
        if os.path.isdir(dest):
            shutil.rmtree(dest, ignore_errors=True)
        log('  extracting nmap (portable) …')
        shutil.copytree(srcdir, dest)
        log('  note: SYN scans need Npcap (https://npcap.com); connect scans work without it')
        return os.path.join(dest, 'nmap.exe')
    finally:
        shutil.rmtree(tmpd, ignore_errors=True)
        try:
            os.remove(tmp)
        except OSError:
            pass


def _mk_progress(log: _Logger, name: str) -> Callable[[int, int], None]:
    state = {'last': -1}

    def _p(got: int, total: int) -> None:
        if not total:
            return
        pct = int(got * 100 / total)
        if pct >= state['last'] + 20:   # log every ~20%
            state['last'] = pct
            log(f'    {name}: {pct}%')
    return _p


# --------------------------------------------------------------------------- #
# sqlmap (a Python project, not a single binary)
# --------------------------------------------------------------------------- #
def sqlmap_dir() -> str:
    return os.path.join(tools_dir(), 'sqlmap')


def sqlmap_script() -> Optional[str]:
    """Path to sqlmap.py if installed, else None."""
    p = os.path.join(sqlmap_dir(), 'sqlmap.py')
    return p if os.path.exists(p) else None


def _install_sqlmap(log: _Logger) -> str:
    url = 'https://github.com/sqlmapproject/sqlmap/archive/refs/heads/master.zip'
    log('  fetching sqlmap (master.zip) …')
    blob = _fetch_bytes(url, progress=_mk_progress(log, 'sqlmap'))
    tmp = os.path.join(tempfile.gettempdir(), 'wp_sqlmap_master.zip')
    with open(tmp, 'wb') as f:
        f.write(blob)
    tmpd = tempfile.mkdtemp(prefix='wp_sqlmap_')
    try:
        with zipfile.ZipFile(tmp) as zf:
            zf.extractall(tmpd)
        src = None
        for root, _dirs, files in os.walk(tmpd):
            if 'sqlmap.py' in files:
                src = root
                break
        if not src:
            raise RuntimeError('sqlmap.py not found in archive')
        dest = sqlmap_dir()
        if os.path.isdir(dest):
            shutil.rmtree(dest, ignore_errors=True)
        log('  extracting sqlmap …')
        shutil.copytree(src, dest)
        return os.path.join(dest, 'sqlmap.py')
    finally:
        shutil.rmtree(tmpd, ignore_errors=True)
        try:
            os.remove(tmp)
        except OSError:
            pass


# --------------------------------------------------------------------------- #
# pip-installed Python tools (ghauri, commix-as-module, …) kept isolated
# --------------------------------------------------------------------------- #
def pylibs_dir() -> str:
    d = os.path.join(tools_dir(), 'pylibs')
    try:
        os.makedirs(d, exist_ok=True)
    except OSError:
        pass
    return d


# Python tools pip-installed (from a GitHub zip URL when not on PyPI) into an
# isolated dir so deps come along.
#   name -> (pip_spec, top_package_to_verify, entry_code_for_python_-c)
PIP_URL_TOOLS = {
    'ghauri': ('https://github.com/r0oth3x49/ghauri/archive/refs/heads/master.zip',
               'ghauri', 'from ghauri.scripts.ghauri import main; main()'),
}


def _install_pip_url(name: str, log: _Logger) -> str:
    import sys
    import subprocess
    spec, package, _entry = PIP_URL_TOOLS[name]
    dest = pylibs_dir()
    log(f'  pip install {name} (from GitHub, resolving deps) … this can take a minute')
    r = subprocess.run([sys.executable, '-m', 'pip', 'install', '--upgrade',
                        '--target', dest, spec],
                       capture_output=True, text=True, timeout=600)
    if r.returncode != 0:
        tail = (r.stderr or r.stdout or 'pip failed').strip().splitlines()
        raise RuntimeError(tail[-1][:200] if tail else 'pip failed')
    if not os.path.isdir(os.path.join(dest, package)):
        raise RuntimeError(f'{package} not found after install')
    return os.path.join(dest, package)


def python_tool_cmd(name: str):
    """argv prefix + env to run a pip/script python tool, or (None, None).
    Args appended after the returned prefix become the tool's sys.argv."""
    import sys
    if name in PIP_URL_TOOLS:
        return [sys.executable, '-c', PIP_URL_TOOLS[name][2]], {'PYTHONPATH': pylibs_dir()}
    if name == 'sqlmap' and sqlmap_script():
        return [sys.executable, sqlmap_script()], {}
    if name in SCRIPT_REPO_TOOLS and script_repo_path(name):
        return [sys.executable, script_repo_path(name)], {}
    return None, None


# Python tools that are a repo with a top-level runnable script (like sqlmap).
#   name -> (zip_url, script_filename)
SCRIPT_REPO_TOOLS = {
    'commix': ('https://github.com/commixproject/commix/archive/refs/heads/master.zip', 'commix.py'),
}


def script_repo_path(name: str) -> Optional[str]:
    p = os.path.join(tools_dir(), name, SCRIPT_REPO_TOOLS[name][1])
    return p if os.path.exists(p) else None


def _install_script_repo(name: str, log: _Logger) -> str:
    url, script = SCRIPT_REPO_TOOLS[name]
    log(f'  fetching {name} ({url.rsplit("/", 1)[-1]}) …')
    blob = _fetch_bytes(url, progress=_mk_progress(log, name))
    tmp = os.path.join(tempfile.gettempdir(), f'wp_{name}_repo.zip')
    with open(tmp, 'wb') as f:
        f.write(blob)
    tmpd = tempfile.mkdtemp(prefix=f'wp_{name}_')
    try:
        with zipfile.ZipFile(tmp) as zf:
            zf.extractall(tmpd)
        src = None
        for root, _dirs, files in os.walk(tmpd):
            if script in files:
                src = root
                break
        if not src:
            raise RuntimeError(f'{script} not found in {name} archive')
        dest = os.path.join(tools_dir(), name)
        if os.path.isdir(dest):
            shutil.rmtree(dest, ignore_errors=True)
        log(f'  extracting {name} …')
        shutil.copytree(src, dest)
        return os.path.join(dest, script)
    finally:
        shutil.rmtree(tmpd, ignore_errors=True)
        try:
            os.remove(tmp)
        except OSError:
            pass


def is_installed(name: str) -> bool:
    """Whether a tool is available (handles sqlmap + pip/script-tool layouts)."""
    if name == 'sqlmap':
        return sqlmap_script() is not None
    if name in PIP_URL_TOOLS:
        return os.path.isdir(os.path.join(pylibs_dir(), PIP_URL_TOOLS[name][1]))
    if name in SCRIPT_REPO_TOOLS:
        return script_repo_path(name) is not None
    return shutil.which(name) is not None


# --------------------------------------------------------------------------- #
# Built-in wordlist for ffuf content discovery
# --------------------------------------------------------------------------- #
_COMMON_WORDS = (
    "admin administrator login logout signin signup register dashboard panel "
    "api api/v1 api/v2 graphql rest swagger swagger-ui openapi docs doc "
    "robots.txt sitemap.xml .htaccess .htpasswd .git .git/config .gitignore "
    ".env env config config.php config.json configuration settings setup install "
    "backup backups bak old new test testing dev development staging prod "
    "uploads upload files file images img assets static media downloads download "
    "css js scripts include includes lib libs vendor node_modules tmp temp cache "
    "logs log error errors debug status health healthcheck metrics actuator "
    "user users account accounts profile profiles member members customer customers "
    "password passwd credentials secret secrets token tokens key keys private "
    "db database sql data dump dumps export exports import phpmyadmin pma adminer "
    "wp-admin wp-login.php wp-content wp-includes xmlrpc.php wp-json "
    "server-status server-info cgi-bin .well-known .well-known/security.txt "
    "console shell cmd terminal portal internal intranet private secure "
    "search query report reports invoice invoices order orders payment payments "
    "cart checkout store shop product products category categories "
    "auth oauth sso saml jwt session sessions cookie reset forgot verify "
    "v1 v2 v3 beta alpha legacy archive archives mail email webmail smtp ftp "
    "404 403 500 index.php index.html home main default app application "
    "json xml yaml yml txt csv pdf zip tar gz bak~ .bak .old .save .swp "
    "actuator/health actuator/env .DS_Store web.config phpinfo.php info.php"
).split()


def ensure_builtin_wordlist() -> str:
    """Write (once) and return a compact content-discovery wordlist for ffuf."""
    d = os.path.join(tools_dir(), 'wordlists')
    try:
        os.makedirs(d, exist_ok=True)
    except OSError:
        pass
    p = os.path.join(d, 'common.txt')
    if not os.path.exists(p):
        try:
            with open(p, 'w', encoding='utf-8') as f:
                f.write('\n'.join(dict.fromkeys(_COMMON_WORDS)))
        except OSError:
            pass
    return p


# --------------------------------------------------------------------------- #
# Public entry point
# --------------------------------------------------------------------------- #
def download_all(only: Optional[List[str]] = None,
                 log: _Logger = _noop,
                 status: _Logger = _noop) -> Dict[str, Tuple[str, str]]:
    """Download/install the requested recon tools into the managed tools dir.

    ``only`` is a list of binary names (e.g. the missing ones); ``None`` means
    install every supported tool. Returns ``{name: ('ok'|'error', detail)}`` and
    never raises. PATH is refreshed at the end so the tools resolve immediately.
    """
    names = list(only) if only else list(GITHUB_TOOLS.keys()) + ['nmap']
    results: Dict[str, Tuple[str, str]] = {}
    ensure_tools_on_path()
    for i, name in enumerate(names, 1):
        status(f'Installing {name} ({i}/{len(names)}) …')
        log(f'[{name}]')
        try:
            if name == 'nmap':
                path = _install_nmap(log)
            elif name == 'sqlmap':
                path = _install_sqlmap(log)
            elif name in PIP_URL_TOOLS:
                path = _install_pip_url(name, log)
            elif name in SCRIPT_REPO_TOOLS:
                path = _install_script_repo(name, log)
            elif name in GITHUB_TOOLS:
                repo, binary = GITHUB_TOOLS[name]
                path = _install_github_tool(repo, binary, log)
            else:
                raise RuntimeError(f'unknown tool "{name}"')
            log(f'  installed -> {path}')
            results[name] = ('ok', path)
        except Exception as e:  # noqa: BLE001 - report, never abort the batch
            log(f'  FAILED: {type(e).__name__}: {e}')
            results[name] = ('error', f'{type(e).__name__}: {e}')
    ensure_tools_on_path()
    ok = sum(1 for v in results.values() if v[0] == 'ok')
    status(f'Done — {ok}/{len(names)} installed.')
    return results
