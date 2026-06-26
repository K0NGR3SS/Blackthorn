"""
WAFPierce pipeline / chain engine  (GUI-free, P3).

A *pipeline* is an ordered, linear list of typed stages run against one target,
with findings accumulating across stages into a shared context. It is the
configurable, visible cousin of the fixed 5-phase ``chain.py``.

This module is Qt-free so it can power the GUI builder, a headless runner, and
unit tests. Stage execution reuses:
  * the existing scanner CLI (``python -m wafpierce.pierce`` / frozen ``--scan-worker``)
    for ``wafpierce_scan`` stages,
  * :func:`wafpierce.tools_runtime.run_tool` for ``external_tool`` stages,
  * :mod:`wafpierce.exporters` for ``report`` stages.

Every long-running child is launched through
:func:`wafpierce.tools_runtime.popen_killable` and registered with the caller so a
single ``abort`` tree-kills it (taskkill /T on Windows).
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from .tools_runtime import popen_killable, kill_proc_tree, run_tool
from .tools_registry import TOOL_REGISTRY


SCHEMA_VERSION = 1

# Supported stage types and the config keys they understand.
STAGE_TYPES = {
    'wafpierce_scan': 'WAFPierce scan',     # config: {categories: [..], threads, delay, safe_mode}
    'external_tool': 'External tool',        # config: {tool: <key>, extra_args, wordlist}
    'report': 'Report / export',             # config: {format: html|json|sarif|nuclei|pdf, path}
}


@dataclass
class Stage:
    id: str
    type: str
    config: Dict = field(default_factory=dict)

    def label(self) -> str:
        if self.type == 'external_tool':
            return f"tool:{self.config.get('tool', '?')}"
        if self.type == 'report':
            return f"report:{self.config.get('format', 'html')}"
        return STAGE_TYPES.get(self.type, self.type)


def stages_from_def(pdef: Dict) -> List[Stage]:
    out = []
    for i, s in enumerate(pdef.get('stages', [])):
        out.append(Stage(id=s.get('id') or f'stage{i+1}', type=s.get('type', ''),
                         config=dict(s.get('config') or {})))
    return out


def default_pipeline() -> Dict:
    """A sensible starter pipeline: recon scan -> nuclei -> HTML report."""
    return {
        'name': 'New pipeline',
        'schema_version': SCHEMA_VERSION,
        'stages': [
            {'id': 'scan', 'type': 'wafpierce_scan',
             'config': {'categories': ['detection_recon', 'info_disclosure']}},
            {'id': 'nuclei', 'type': 'external_tool', 'config': {'tool': 'nuclei'}},
            {'id': 'report', 'type': 'report', 'config': {'format': 'html'}},
        ],
    }


def validate_pipeline(pdef: Dict) -> List[str]:
    """Return a list of human-readable errors (empty == valid)."""
    errors: List[str] = []
    stages = pdef.get('stages')
    if not isinstance(stages, list) or not stages:
        return ['Pipeline has no stages.']
    seen_ids = set()
    for i, s in enumerate(stages):
        sid = s.get('id') or f'stage{i+1}'
        if sid in seen_ids:
            errors.append(f'Duplicate stage id: {sid}')
        seen_ids.add(sid)
        st = s.get('type')
        if st not in STAGE_TYPES:
            errors.append(f'{sid}: unknown stage type {st!r}')
            continue
        cfg = s.get('config') or {}
        if st == 'external_tool':
            tool = cfg.get('tool')
            if tool not in TOOL_REGISTRY:
                errors.append(f'{sid}: unknown tool {tool!r}')
        elif st == 'report':
            fmt = cfg.get('format', 'html')
            if fmt not in ('html', 'json', 'sarif', 'nuclei', 'pdf'):
                errors.append(f'{sid}: unsupported report format {fmt!r}')
    return errors


def build_scan_argv(target: str, config: Dict, output_path: str,
                    frozen: bool = False, python_exe: Optional[str] = None) -> List[str]:
    """Build the argv for a wafpierce_scan stage, mirroring the GUI scan worker so
    behavior is identical (frozen --scan-worker vs `python -m wafpierce.pierce`)."""
    python_exe = python_exe or sys.executable
    cats = config.get('categories') or []
    if frozen:
        argv = [python_exe, '--scan-worker', '--target', target,
                '--threads', str(config.get('threads', 10)),
                '--delay', str(config.get('delay', 0.2)), '--output', output_path]
        if cats:
            argv += ['--categories', ','.join(cats)]
        if config.get('safe_mode'):
            argv += ['--safe-mode']
    else:
        argv = [python_exe, '-u', '-m', 'wafpierce.pierce', target,
                '-t', str(config.get('threads', 10)), '-d', str(config.get('delay', 0.2)),
                '-o', output_path]
        if cats:
            argv += ['-c', ','.join(cats)]
        if config.get('safe_mode'):
            argv += ['--safe-mode']
    return argv


@dataclass
class PipelineHooks:
    on_log: Optional[Callable[[str], None]] = None
    on_stage: Optional[Callable[[str, str], None]] = None     # (stage_id, status)
    on_findings: Optional[Callable[[list], None]] = None       # findings as they arrive
    register_proc: Optional[Callable[[subprocess.Popen], None]] = None
    is_aborted: Optional[Callable[[], bool]] = None

    def log(self, msg: str):
        if self.on_log:
            self.on_log(msg)

    def stage(self, sid: str, status: str):
        if self.on_stage:
            self.on_stage(sid, status)

    def findings(self, items: list):
        if items and self.on_findings:
            self.on_findings(items)

    def aborted(self) -> bool:
        return bool(self.is_aborted and self.is_aborted())


class PipelineRunner:
    """Headless sequential executor. Usable from the GUI worker, a CLI, and tests."""

    def __init__(self, pdef: Dict, target: str, hooks: Optional[PipelineHooks] = None,
                 frozen: bool = False):
        self.pdef = pdef
        self.target = target
        self.hooks = hooks or PipelineHooks()
        self.frozen = frozen
        self.all_findings: List[Dict] = []

    def run(self) -> Dict:
        errs = validate_pipeline(self.pdef)
        if errs:
            self.hooks.log('[!] Pipeline invalid: ' + '; '.join(errs))
            return {'ok': False, 'errors': errs, 'findings': []}

        for stage in stages_from_def(self.pdef):
            if self.hooks.aborted():
                self.hooks.log('[!] Pipeline aborted.')
                self.hooks.stage(stage.id, 'skipped')
                continue
            self.hooks.stage(stage.id, 'running')
            self.hooks.log(f'\n=== Stage {stage.id} ({stage.label()}) ===')
            try:
                if stage.type == 'wafpierce_scan':
                    self._run_scan_stage(stage)
                elif stage.type == 'external_tool':
                    self._run_tool_stage(stage)
                elif stage.type == 'report':
                    self._run_report_stage(stage)
                self.hooks.stage(stage.id, 'done')
            except Exception as e:
                self.hooks.log(f'[!] Stage {stage.id} failed: {e}')
                self.hooks.stage(stage.id, 'error')
        return {'ok': True, 'findings': self.all_findings, 'count': len(self.all_findings)}

    # -- stage implementations -------------------------------------------- #
    def _run_scan_stage(self, stage: Stage):
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.json')
        tmp.close()
        argv = build_scan_argv(self.target, stage.config, tmp.name, frozen=self.frozen)
        env = os.environ.copy()
        env['PYTHONIOENCODING'] = 'utf-8'
        env['PYTHONUNBUFFERED'] = '1'
        proc = popen_killable(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              text=True, bufsize=1, errors='replace', env=env)
        if self.hooks.register_proc:
            self.hooks.register_proc(proc)
        if proc.stdout is not None:
            for line in proc.stdout:
                self.hooks.log(line.rstrip())
                if self.hooks.aborted():
                    kill_proc_tree(proc)
                    break
        proc.wait()
        findings = []
        try:
            if os.path.exists(tmp.name):
                with open(tmp.name, encoding='utf-8') as fh:
                    data = json.load(fh)
                findings = data if isinstance(data, list) else []
        except Exception:
            pass
        finally:
            try:
                os.unlink(tmp.name)
            except Exception:
                pass
        for f in findings:
            if isinstance(f, dict):
                f.setdefault('target', self.target)
        self.all_findings.extend(findings)
        self.hooks.findings(findings)
        self.hooks.log(f'[+] scan stage: {len(findings)} finding(s)')

    def _run_tool_stage(self, stage: Stage):
        tool = stage.config.get('tool')
        extra = (stage.config.get('extra_args') or '')
        extra_list = extra.split() if isinstance(extra, str) else (extra or None)
        res = run_tool(tool, self.target,
                       extra_args=extra_list or None,
                       wordlist=stage.config.get('wordlist'),
                       api_key=stage.config.get('api_key'),
                       on_line=self.hooks.log,
                       register_proc=self.hooks.register_proc)
        if not res.get('ok'):
            self.hooks.log(f"[!] {tool}: {res.get('error') or res.get('state')}")
            return
        findings = res.get('findings', []) or []
        self.all_findings.extend(findings)
        self.hooks.findings(findings)
        self.hooks.log(f'[+] {tool} stage: {len(findings)} finding(s)')

    def _run_report_stage(self, stage: Stage):
        fmt = stage.config.get('format', 'html')
        path = stage.config.get('path')
        if not path:
            base = tempfile.gettempdir()
            path = os.path.join(base, f'wafpierce_pipeline_report.{fmt if fmt != "nuclei" else "yaml"}')
        try:
            from .exporters import export as _export
            _export(self.all_findings, self.target, fmt, path)
            self.hooks.log(f'[+] report stage: wrote {fmt.upper()} -> {path}')
            stage.config['_written_path'] = path
        except Exception as e:
            self.hooks.log(f'[!] report stage failed: {e}')
