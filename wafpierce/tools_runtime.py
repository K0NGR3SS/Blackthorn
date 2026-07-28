"""
WAFPierce external-tool runtime: detection + killable runner.

Qt-free and importable from workers/tests. Two responsibilities:

1. **Detection** (``detect``) — locate an installed tool without ever installing
   anything, following one canonical order (custom path -> PATH -> default dirs ->
   version probe). Returns a :class:`ToolStatus` whose ``state`` drives the GUI
   badge (ready / needs_config / not_installed).

2. **Execution** (``run_tool``) — template an argv *list* from a
   :class:`~wafpierce.tools_registry.ToolSpec`, run it as a child process, stream
   stdout, and hand the output to the spec's parser (in :mod:`wafpierce.tools_parsers`)
   to produce canonical WAFPierce finding dicts.

Process-tree kill (Windows ``taskkill /F /T`` / POSIX group kill) lives here as
``popen_killable`` + ``kill_proc_tree`` and is reused by the GUI scan worker so a
single ``abort()`` reliably terminates interpreter-based tools and their children.
"""
from __future__ import annotations

import os
import queue
import re
import shutil
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional
from urllib.parse import urlparse

from .tools_registry import ToolSpec, get_spec


# --------------------------------------------------------------------------- #
# Detection
# --------------------------------------------------------------------------- #
@dataclass
class ToolStatus:
    key: str
    found: bool
    path: Optional[str] = None
    version: Optional[str] = None
    state: str = 'not_installed'      # ready | needs_config | not_installed
    error: Optional[str] = None

    def badge(self) -> str:
        return {'ready': 'READY', 'needs_config': 'NEEDS CONFIG',
                'not_installed': 'NOT INSTALLED'}.get(self.state, self.state.upper())


# Extra directories tools commonly install into, probed after PATH.
def _candidate_dirs(extra: tuple = ()) -> List[str]:
    home = os.path.expanduser('~')
    dirs = list(extra)
    if os.name == 'nt':
        dirs += [
            os.path.join(home, 'go', 'bin'),
            os.path.join(os.environ.get('APPDATA', ''), 'Python', 'Scripts'),
            os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Programs'),
            os.path.join(os.environ.get('ProgramData', ''), 'chocolatey', 'bin'),
            os.path.join(home, 'scoop', 'shims'),
            r'C:\Tools', r'C:\Program Files', r'C:\Program Files (x86)',
        ]
    else:
        dirs += [
            os.path.join(home, 'go', 'bin'),
            os.path.join(home, '.local', 'bin'),
            '/usr/bin', '/usr/local/bin', '/opt', '/snap/bin',
        ]
    return [d for d in dirs if d]


def _which_in_dirs(binary: str, dirs: List[str]) -> Optional[str]:
    exts = ['', '.exe', '.bat', '.cmd'] if os.name == 'nt' else ['']
    for d in dirs:
        for ext in exts:
            cand = os.path.join(d, binary + ext)
            if os.path.isfile(cand) and os.access(cand, os.X_OK if os.name != 'nt' else os.F_OK):
                return cand
    return None


def _probe_version(path: str, args: tuple, timeout: int = 8) -> str:
    try:
        out = subprocess.run([path, *args], capture_output=True, text=True,
                             timeout=timeout, errors='replace')
        blob = (out.stdout or '') + (out.stderr or '')
        return blob.strip()
    except Exception:
        return ''


_VERSION_RE = re.compile(r'v?(\d+\.\d+[\w.\-]*)')


def detect(spec: ToolSpec, custom_path: Optional[str] = None) -> ToolStatus:
    """Locate ``spec``'s binary. Never installs. Returns a :class:`ToolStatus`."""
    path = None
    # 1) explicit user override
    if custom_path:
        cp = os.path.expandvars(os.path.expanduser(custom_path))
        if os.path.isfile(cp):
            path = cp
        else:
            return ToolStatus(spec.key, False, state='needs_config',
                              error=f'Configured path not found: {custom_path}')
    # 2) PATH
    if not path:
        for b in spec.binaries:
            p = shutil.which(b)
            if p:
                path = p
                break
    # 3) default dirs
    if not path:
        dirs = _candidate_dirs(spec.default_dirs)
        for b in spec.binaries:
            p = _which_in_dirs(b, dirs)
            if p:
                path = p
                break
    if not path:
        return ToolStatus(spec.key, False, state='not_installed',
                          error=f'{spec.name} not found on PATH or default dirs.')

    # 4) version probe + disambiguation (e.g. PD httpx vs python httpx CLI)
    vblob = _probe_version(path, spec.version_args)
    if spec.version_match and spec.version_match.lower() not in vblob.lower():
        return ToolStatus(spec.key, False, path=path, state='needs_config',
                          error=f'Binary at {path} does not look like {spec.name} '
                                f'(expected "{spec.version_match}" in version output).')
    m = _VERSION_RE.search(vblob)
    version = m.group(1) if m else (vblob.splitlines()[0][:60] if vblob else None)
    return ToolStatus(spec.key, True, path=path, version=version, state='ready')


def detect_all(custom_paths: Optional[Dict[str, str]] = None) -> Dict[str, ToolStatus]:
    from .tools_registry import TOOL_REGISTRY
    custom_paths = custom_paths or {}
    return {k: detect(s, custom_paths.get(k)) for k, s in TOOL_REGISTRY.items()}


# --------------------------------------------------------------------------- #
# Killable process helpers (shared with the GUI scan worker — R2 mitigation)
# --------------------------------------------------------------------------- #
def popen_killable(argv: List[str], **kwargs) -> subprocess.Popen:
    """Popen that can be tree-killed. On Windows starts a new process group so
    ``taskkill /T`` reaches grandchildren (sqlmap/nikto spawn helpers)."""
    if os.name == 'nt':
        kwargs.setdefault('creationflags', 0)
        kwargs['creationflags'] |= subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs.setdefault('start_new_session', True)
    return subprocess.Popen(argv, **kwargs)


def kill_proc_tree(proc: Optional[subprocess.Popen], timeout: int = 5) -> None:
    """Terminate ``proc`` and ALL of its descendants. Windows: ``taskkill /F /T``;
    POSIX: kill the process group, fall back to terminate/kill."""
    if proc is None or proc.poll() is not None:
        return
    try:
        if os.name == 'nt':
            subprocess.run(['taskkill', '/F', '/T', '/PID', str(proc.pid)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout)
        else:
            import signal
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except Exception:
                proc.terminate()
            try:
                proc.wait(timeout)
            except Exception:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except Exception:
                    proc.kill()
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


# --------------------------------------------------------------------------- #
# Target context + argv templating
# --------------------------------------------------------------------------- #
def _build_context(spec: ToolSpec, target: str, wordlist: Optional[str], tmp_dir: str) -> Dict[str, str]:
    """Derive {url, host, domain, port, ...} from a target string for templating."""
    t = (target or '').strip()
    parsed = urlparse(t if '://' in t else 'http://' + t)
    host = parsed.hostname or t
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    url = t if '://' in t else f'http://{t}'
    domain = host
    ctx = {
        'target': t,
        'url': url,
        'host': host,
        'domain': domain,
        'port': str(port),
        'port_list': str(port),
        'host_port': f'{host}:{port}',
        'wordlist': wordlist or '',
        'tmp_dir': tmp_dir,
        'outdir': tmp_dir,
        'outfile': os.path.join(tmp_dir, f'{spec.key}_out'),
        'out_json': os.path.join(tmp_dir, f'{spec.key}_out.json'),
        'infile': '',
    }
    return ctx


def _validate_target(value: str) -> None:
    # Refuse values that would be parsed as flags by the tool (argv injection guard).
    if value.startswith('-'):
        raise ValueError(f'Refusing target/host beginning with "-": {value!r}')


def build_argv(spec: ToolSpec, path: str, ctx: Dict[str, str],
               extra_args: Optional[List[str]] = None) -> List[str]:
    """Render the spec's argv template. Only known {placeholders} are substituted;
    everything is a list element so a target can never inject a flag."""
    for k in ('target', 'host', 'url', 'domain'):
        if ctx.get(k):
            _validate_target(ctx[k])
    argv = [path]
    for part in spec.argv_template:
        try:
            argv.append(part.format(**ctx))
        except (KeyError, IndexError):
            argv.append(part)
    if extra_args:
        argv.extend(extra_args)
    return argv


def _redact_argv(argv: List[str], secrets: Optional[List[str]] = None) -> List[str]:
    """Return a log-safe command line without changing the executed argv."""
    secret_values = [str(value) for value in (secrets or []) if value]
    safe = []
    for part in argv:
        text = str(part)
        for secret in secret_values:
            text = text.replace(secret, '<redacted>')
        safe.append(text)
    return safe


def _stream_process(
    proc: subprocess.Popen,
    *,
    on_line: Optional[Callable[[str], None]] = None,
    timeout: Optional[int] = None,
    redact_values: Optional[List[str]] = None,
) -> tuple:
    """Stream a process without letting a blocking stdout read defeat timeout."""
    output_queue: queue.Queue = queue.Queue()
    done = object()

    def reader():
        try:
            if proc.stdout is not None:
                for raw in proc.stdout:
                    line = raw.rstrip('\r\n')
                    for secret in (redact_values or []):
                        if secret:
                            line = line.replace(str(secret), '<redacted>')
                    output_queue.put(line)
        finally:
            output_queue.put(done)

    thread = threading.Thread(target=reader, daemon=True)
    thread.start()
    started = time.monotonic()
    lines: List[str] = []
    reader_done = False
    timed_out = False

    while True:
        if timeout and time.monotonic() - started >= timeout:
            timed_out = True
            kill_proc_tree(proc)
            break
        try:
            item = output_queue.get(timeout=0.1)
            if item is done:
                reader_done = True
            else:
                lines.append(item)
                if on_line and item:
                    on_line(item)
        except queue.Empty:
            pass
        if reader_done and proc.poll() is not None:
            break

    thread.join(timeout=1)
    while True:
        try:
            item = output_queue.get_nowait()
        except queue.Empty:
            break
        if item is done:
            continue
        lines.append(item)
        if on_line and item:
            on_line(item)
    if proc.poll() is None:
        proc.wait(timeout=5)
    return lines, proc.returncode, timed_out


# --------------------------------------------------------------------------- #
# Runner
# --------------------------------------------------------------------------- #
def run_tool(spec_or_key, target: str, *,
             custom_path: Optional[str] = None,
             extra_args: Optional[List[str]] = None,
             wordlist: Optional[str] = None,
             api_key: Optional[str] = None,
             on_line: Optional[Callable[[str], None]] = None,
             register_proc: Optional[Callable[[subprocess.Popen], None]] = None,
             timeout: Optional[int] = None,
             authorize_target: Optional[Callable[[str], bool]] = None) -> Dict:
    """Detect, run, and parse one tool against ``target``.

    Returns ``{ok, state, returncode, findings, raw_lines, error, argv}``.
    ``register_proc`` (if given) receives the live Popen so a GUI worker can
    ``kill_proc_tree`` it on abort. Output is streamed via ``on_line``.
    """
    from . import tools_parsers
    spec = spec_or_key if isinstance(spec_or_key, ToolSpec) else get_spec(spec_or_key)

    if authorize_target is not None:
        try:
            allowed = bool(authorize_target(target))
        except Exception as exc:
            return {
                'ok': False, 'state': 'scope_error',
                'error': f'Target authorization check failed: {exc}',
                'findings': [], 'raw_lines': [], 'argv': [],
            }
        if not allowed:
            return {
                'ok': False, 'state': 'scope_blocked',
                'error': 'Target is outside the active engagement scope.',
                'findings': [], 'raw_lines': [], 'argv': [],
            }

    status = detect(spec, custom_path)
    if not status.found:
        return {'ok': False, 'state': status.state, 'error': status.error,
                'findings': [], 'raw_lines': [], 'argv': []}

    tmp_dir = tempfile.mkdtemp(prefix=f'wp_{spec.key}_')
    ctx = _build_context(spec, target, wordlist, tmp_dir)
    extra = list(extra_args or [])
    if spec.needs_api_key and api_key:
        extra += ['--api-token', api_key] if spec.key == 'wpscan' else []

    try:
        argv = build_argv(spec, status.path, ctx, extra)
    except Exception as e:
        _rmtree(tmp_dir)
        return {'ok': False, 'state': 'error', 'error': f'argv build failed: {e}',
                'findings': [], 'raw_lines': [], 'argv': []}

    safe_argv = _redact_argv(argv, [api_key] if api_key else [])
    raw_lines: List[str] = []
    try:
        if on_line:
            on_line(f'[*] {spec.name}: {" ".join(safe_argv)}')
        proc = popen_killable(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              text=True, bufsize=1, errors='replace')
        if register_proc:
            register_proc(proc)
        raw_lines, returncode, timed_out = _stream_process(
            proc,
            on_line=on_line,
            timeout=timeout,
            redact_values=[api_key] if api_key else [],
        )
    except FileNotFoundError as e:
        _rmtree(tmp_dir)
        return {'ok': False, 'state': 'not_installed', 'error': str(e),
                'findings': [], 'raw_lines': raw_lines, 'argv': safe_argv}
    except Exception as e:
        _rmtree(tmp_dir)
        return {'ok': False, 'state': 'error', 'error': str(e),
                'findings': [], 'raw_lines': raw_lines, 'argv': safe_argv}

    if timed_out:
        _rmtree(tmp_dir)
        return {
            'ok': False, 'state': 'timeout', 'returncode': returncode,
            'error': f'{spec.name} exceeded the {timeout}s execution limit.',
            'findings': [], 'raw_lines': raw_lines, 'argv': safe_argv,
            'tool': {'key': spec.key, 'name': spec.name,
                     'version': status.version or '', 'path': status.path or ''},
        }

    # Parse output into canonical findings (defensive: never raise to caller).
    parser = getattr(tools_parsers, spec.parser, tools_parsers.generic_lines)
    parse_error = ''
    try:
        findings = parser(spec, target, '\n'.join(raw_lines), ctx) or []
    except Exception as e:
        findings = []
        parse_error = f'Parser error: {e}'
    for finding in findings:
        if isinstance(finding, dict):
            finding.setdefault('tool_version', status.version or '')
            finding.setdefault('tool_path', status.path or '')
    _rmtree(tmp_dir)
    ok = returncode == 0 and not parse_error
    error = parse_error or (
        f'{spec.name} exited with status {returncode}' if returncode else ''
    )
    return {
        'ok': ok,
        'state': 'ok' if ok else ('parse_error' if parse_error else 'failed'),
        'returncode': returncode,
        'error': error,
        'findings': findings,
        'raw_lines': raw_lines,
        'argv': safe_argv,
        'tool': {
            'key': spec.key, 'name': spec.name,
            'version': status.version or '', 'path': status.path or '',
        },
    }


def _rmtree(path: str) -> None:
    try:
        shutil.rmtree(path, ignore_errors=True)
    except Exception:
        pass
