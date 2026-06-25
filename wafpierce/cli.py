"""Unified WAFPierce command-line entry point.

Historically the installed ``wafpierce`` console script pointed at the minimal
:func:`wafpierce.chain.main`, so none of the documented scanner flags
(``--oob``, ``--impersonate``, ``--resume``, ``--import-har`` …) were reachable
from the entry point users actually install. This dispatcher fixes that by
exposing subcommands:

    wafpierce scan   <url> [rich scanner flags]   # full technique scanner
    wafpierce recon  <domain> [...]               # external-tool reconnaissance
    wafpierce chain  <url> [...]                  # bypass->enum->scan->recon chain
    wafpierce msf    <check|scan|push> [...]      # Metasploit RPC integration
    wafpierce caido  <check|push|export> [...]    # Caido proxy integration
    wafpierce doctor                              # environment preflight
    wafpierce gui                                 # launch the desktop GUI
    wafpierce --version | -V

A bare ``wafpierce <url>`` (no recognized subcommand) defaults to ``scan`` so the
documented flags Just Work.
"""
from __future__ import annotations

import sys
from typing import List, Optional

from . import __version__

_SUBCOMMANDS = {'scan', 'recon', 'chain', 'msf', 'caido',
                'doctor', 'gui', 'version', 'help'}


def _print_usage() -> None:
    print(f"""WAFPierce {__version__} - WAF/CDN assessment & bypass validation

usage: wafpierce <command> [options]

commands:
  scan <url> [flags]   Run the full technique scanner (all documented flags:
                       --oob, --impersonate, --resume, --safe-mode, --import-*,
                       --export, --ai-*, scope/auth, --dry-run, ...).
                       This is the default if you pass a URL with no command.
  recon <domain>       External-tool recon (subfinder/amass/dnsx/httpx/nmap).
                       Requires those tools on PATH; `wafpierce doctor` checks.
  chain <url> [flags]  Run the bypass -> enum -> scan -> recon -> report chain.
  msf <sub> [flags]    Metasploit RPC: check | scan <target> | push <results>.
  caido <sub> [flags]  Caido: check | push <results> | export <results> -o.
  doctor               Environment preflight (deps, config dir, egress, OOB).
  gui                  Launch the desktop GUI.
  version              Show version + which optional components are installed.

global:
  -V, --version        Same as `version`.
  -h, --help           Show this message. `wafpierce scan -h` for scanner flags.

examples:
  wafpierce scan https://target --impersonate chrome --oob interactsh
  wafpierce scan https://target --dry-run --safe-mode
  wafpierce https://target            # == wafpierce scan https://target
  wafpierce doctor
""")


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    # Global version flag works in any position before a subcommand's own parsing.
    if any(a in ('-V', '--version') for a in argv) and (
        not argv or argv[0] in ('-V', '--version', 'version')
        or not _looks_like_subcommand(argv[0])
    ):
        from .diagnostics import print_version
        no_color = '--no-color' in argv
        print_version(no_color=no_color)
        return 0

    if not argv:
        _print_usage()
        return 0

    head = argv[0]

    if head in ('-h', '--help'):
        _print_usage()
        return 0

    if head in ('version',):
        from .diagnostics import print_version
        print_version(no_color='--no-color' in argv)
        return 0

    if head == 'help':
        _print_usage()
        return 0

    if head == 'doctor':
        from .diagnostics import run_doctor
        rest = argv[1:]
        return run_doctor(no_color=('--no-color' in rest),
                          check_network=('--no-network' not in rest))

    if head == 'gui':
        from .gui import main as gui_main
        return gui_main() or 0

    if head == 'scan':
        from .pierce import main as scan_main
        return scan_main(argv[1:])

    if head == 'recon':
        from .recon import main as recon_main
        return recon_main(argv[1:])

    if head == 'chain':
        from .chain import main as chain_main
        return chain_main(argv[1:])

    if head == 'msf':
        from .msf import main as msf_main
        return msf_main(argv[1:])

    if head == 'caido':
        from .caido import main as caido_main
        return caido_main(argv[1:])

    # No recognized subcommand -> treat the whole argv as a `scan` invocation so
    # `wafpierce https://target --oob ...` behaves like `wafpierce scan ...`.
    from .pierce import main as scan_main
    return scan_main(argv)


def _looks_like_subcommand(token: str) -> bool:
    return token in _SUBCOMMANDS


if __name__ == '__main__':
    raise SystemExit(main())
