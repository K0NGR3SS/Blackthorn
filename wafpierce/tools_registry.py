"""
WAFPierce external-tool registry  (detect-&-drive model)
========================================================

A declarative catalogue of third-party pentest tools that WAFPierce can *drive*
when they are **already installed** on the host. WAFPierce never bundles, downloads
or installs any of these — absent tools simply render a "not installed / configure
path" state in the GUI and are skipped.

This module is intentionally:
  * pure data + tiny helpers (no Qt, no network, no heavy imports), so it can be
    imported from the killable ``--tool-worker`` subprocess and from unit tests;
  * the single source of truth shared by the Tools section (P2), the Pipeline
    builder (P3) and any other feature that needs to run an external binary.

``argv_template`` entries are formatted with ``str.format(**ctx)`` where ``ctx``
may contain: ``target host url domain port_list wordlist out_json outfile outdir
tmp_dir infile``. Templating is done by :mod:`wafpierce.tools_runtime` against an
argv *list* (never a shell string), so target values can never inject flags.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Tuple


# Categories surfaced in the GUI "Tools" section. Keys are stable identifiers.
TOOL_CATEGORIES: Dict[str, str] = {
    'recon': 'Recon & Discovery',
    'content': 'Content Discovery',
    'vuln': 'Vulnerability Scanning',
    'cloud': 'Cloud & Secrets',
    'exploit': 'Exploitation',
}

# Output handling modes understood by the runner.
#   none         - no structured output; capture stdout lines
#   stdout_jsonl - one JSON object per stdout line
#   stdout_json  - a single JSON document on stdout
#   file_json    - a single JSON document written to {outfile}/{out_json}
#   file_jsonl   - JSON-lines written to {outfile}
#   xml_file     - XML written to {outfile}  (or '-' for stdout)
#   lines        - plain text lines (parsed heuristically)
JSON_MODES = (
    'none', 'stdout_jsonl', 'stdout_json', 'file_json', 'file_jsonl',
    'xml_file', 'xml_stdout', 'lines',
)

TARGET_KINDS = ('url', 'host', 'host_port', 'domain', 'path')


@dataclass(frozen=True)
class ToolSpec:
    """Immutable description of how to detect and drive one external tool."""
    key: str
    name: str
    category: str
    binaries: Tuple[str, ...]                 # candidate executable names (no ext)
    target_kind: str = 'url'                  # see TARGET_KINDS
    version_args: Tuple[str, ...] = ('-version',)
    version_match: str = ''                    # if set, this substring must appear in
                                               # version output to count as "this" tool
    argv_template: Tuple[str, ...] = ()        # run argv with {placeholders}
    json_mode: str = 'lines'                   # see JSON_MODES
    parser: str = 'generic_lines'              # function name in tools_parsers.py
    install_hint: str = ''
    homepage: str = ''
    default_severity: str = 'INFO'
    needs_api_key: bool = False
    long_running: bool = True
    needs_wordlist: bool = False
    default_dirs: Tuple[str, ...] = ()
    notes: str = ''

    def display_category(self) -> str:
        return TOOL_CATEGORIES.get(self.category, self.category)


def _spec(**kw) -> ToolSpec:
    return ToolSpec(**kw)


# --------------------------------------------------------------------------- #
# The registry. Flags below are chosen to produce machine-readable output.
# Every spec degrades gracefully: if its structured output can't be parsed the
# runner falls back to capturing notable stdout lines as INFO findings.
# --------------------------------------------------------------------------- #
_SPECS = [
    # ---- Recon & discovery ------------------------------------------------ #
    _spec(key='nmap', name='Nmap', category='recon', binaries=('nmap',),
          target_kind='host', version_args=('--version',),
          argv_template=('-Pn', '-T4', '-oX', '-', '{host}'),
          json_mode='xml_stdout', parser='parse_nmap_xml',
          install_hint='Install Nmap from https://nmap.org/download (needs Npcap on Windows).',
          homepage='https://nmap.org', long_running=True),
    _spec(key='masscan', name='Masscan', category='recon', binaries=('masscan',),
          target_kind='host', version_args=('--version',),
          argv_template=('-p1-1000', '--rate', '1000', '-oJ', '{outfile}', '{host}'),
          json_mode='file_json', parser='parse_masscan_json',
          install_hint='Build/install masscan from https://github.com/robertdavidgraham/masscan',
          homepage='https://github.com/robertdavidgraham/masscan'),
    _spec(key='naabu', name='Naabu', category='recon', binaries=('naabu',),
          target_kind='host', version_args=('-version',),
          argv_template=('-host', '{host}', '-json', '-silent'),
          json_mode='stdout_jsonl', parser='parse_pd_jsonl',
          install_hint='go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest',
          homepage='https://github.com/projectdiscovery/naabu'),
    _spec(key='subfinder', name='Subfinder', category='recon', binaries=('subfinder',),
          target_kind='domain', version_args=('-version',),
          argv_template=('-d', '{domain}', '-silent', '-oJ', '-'),
          json_mode='stdout_jsonl', parser='parse_pd_jsonl',
          install_hint='go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest',
          homepage='https://github.com/projectdiscovery/subfinder'),
    _spec(key='amass', name='OWASP Amass', category='recon', binaries=('amass',),
          target_kind='domain', version_args=('-version',),
          argv_template=('enum', '-passive', '-d', '{domain}', '-json', '{outfile}'),
          json_mode='file_jsonl', parser='parse_amass_jsonl',
          install_hint='Install amass from https://github.com/owasp-amass/amass', long_running=True,
          homepage='https://github.com/owasp-amass/amass'),
    _spec(key='dnsx', name='dnsx', category='recon', binaries=('dnsx',),
          target_kind='domain', version_args=('-version',),
          argv_template=('-d', '{domain}', '-json', '-silent'),
          json_mode='stdout_jsonl', parser='parse_pd_jsonl',
          install_hint='go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest',
          homepage='https://github.com/projectdiscovery/dnsx'),
    _spec(key='httpx', name='httpx (ProjectDiscovery)', category='recon', binaries=('httpx',),
          target_kind='url', version_args=('-version',), version_match='projectdiscovery',
          argv_template=('-u', '{url}', '-json', '-silent'),
          json_mode='stdout_jsonl', parser='parse_pd_jsonl',
          install_hint='go install github.com/projectdiscovery/httpx/cmd/httpx@latest '
                       '(NOTE: distinct from the Python "httpx" library CLI).',
          homepage='https://github.com/projectdiscovery/httpx'),
    _spec(key='whatweb', name='WhatWeb', category='recon', binaries=('whatweb',),
          target_kind='url', version_args=('--version',),
          argv_template=('--log-json=-', '--no-errors', '{url}'),
          json_mode='stdout_json', parser='parse_whatweb_json',
          install_hint='Install WhatWeb from https://github.com/urbanadventurer/WhatWeb',
          homepage='https://github.com/urbanadventurer/WhatWeb'),
    _spec(key='katana', name='katana', category='recon', binaries=('katana',),
          target_kind='url', version_args=('-version',),
          argv_template=('-u', '{url}', '-jsonl', '-silent'),
          json_mode='stdout_jsonl', parser='parse_pd_jsonl',
          install_hint='go install github.com/projectdiscovery/katana/cmd/katana@latest',
          homepage='https://github.com/projectdiscovery/katana'),

    # ---- Content discovery ------------------------------------------------ #
    _spec(key='ffuf', name='ffuf', category='content', binaries=('ffuf',),
          target_kind='url', version_args=('-V',), needs_wordlist=True,
          argv_template=('-u', '{url}/FUZZ', '-w', '{wordlist}', '-of', 'json', '-o', '{outfile}', '-s'),
          json_mode='file_json', parser='parse_ffuf_json',
          install_hint='go install github.com/ffuf/ffuf/v2@latest',
          homepage='https://github.com/ffuf/ffuf'),
    _spec(key='feroxbuster', name='feroxbuster', category='content', binaries=('feroxbuster',),
          target_kind='url', version_args=('--version',), needs_wordlist=True,
          argv_template=('-u', '{url}', '-w', '{wordlist}', '--json', '-o', '{outfile}', '--silent'),
          json_mode='file_jsonl', parser='parse_ferox_jsonl',
          install_hint='Install feroxbuster from https://github.com/epi052/feroxbuster',
          homepage='https://github.com/epi052/feroxbuster'),
    _spec(key='gobuster', name='gobuster', category='content', binaries=('gobuster',),
          target_kind='url', version_args=('version',), needs_wordlist=True,
          argv_template=('dir', '-u', '{url}', '-w', '{wordlist}', '-q', '--no-color'),
          json_mode='lines', parser='parse_gobuster_lines',
          install_hint='go install github.com/OJ/gobuster/v3@latest',
          homepage='https://github.com/OJ/gobuster'),
    _spec(key='dirsearch', name='dirsearch', category='content', binaries=('dirsearch',),
          target_kind='url', version_args=('--version',), needs_wordlist=False,
          argv_template=('-u', '{url}', '--format=json', '-o', '{outfile}', '-q'),
          json_mode='file_json', parser='parse_dirsearch_json',
          install_hint='pipx install dirsearch  (or git clone maurosoria/dirsearch)',
          homepage='https://github.com/maurosoria/dirsearch'),

    # ---- Vulnerability scanning ------------------------------------------ #
    _spec(key='nuclei', name='Nuclei', category='vuln', binaries=('nuclei',),
          target_kind='url', version_args=('-version',),
          argv_template=('-u', '{url}', '-jsonl', '-silent'),
          json_mode='stdout_jsonl', parser='parse_nuclei_jsonl',
          install_hint='go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest',
          homepage='https://github.com/projectdiscovery/nuclei', default_severity='INFO'),
    _spec(key='nikto', name='Nikto', category='vuln', binaries=('nikto', 'nikto.pl'),
          target_kind='url', version_args=('-Version',),
          argv_template=('-h', '{url}', '-Format', 'json', '-output', '{outfile}', '-nointeractive'),
          json_mode='file_json', parser='parse_nikto_json',
          install_hint='Install Nikto from https://github.com/sullo/nikto (needs Perl).',
          homepage='https://github.com/sullo/nikto'),
    _spec(key='wpscan', name='WPScan', category='vuln', binaries=('wpscan',),
          target_kind='url', version_args=('--version',), needs_api_key=True,
          argv_template=('--url', '{url}', '-f', 'json', '-o', '{outfile}', '--no-banner'),
          json_mode='file_json', parser='parse_wpscan_json',
          install_hint='gem install wpscan  (WPScan API token optional for vuln data).',
          homepage='https://wpscan.com'),
    _spec(key='dalfox', name='dalfox', category='vuln', binaries=('dalfox',),
          target_kind='url', version_args=('version',),
          argv_template=('url', '{url}', '--format', 'json', '--silence', '--no-spinner'),
          json_mode='stdout_json', parser='parse_dalfox_json',
          install_hint='go install github.com/hahwul/dalfox/v2@latest',
          homepage='https://github.com/hahwul/dalfox'),
    _spec(key='sslyze', name='SSLyze', category='vuln', binaries=('sslyze',),
          target_kind='host_port', version_args=('--version',),
          argv_template=('--json_out', '{outfile}', '{host}'),
          json_mode='file_json', parser='parse_sslyze_json',
          install_hint='pipx install sslyze',
          homepage='https://github.com/nabla-c0d3/sslyze'),
    _spec(key='sqlmap', name='sqlmap', category='vuln', binaries=('sqlmap', 'sqlmap.py'),
          target_kind='url', version_args=('--version',),
          argv_template=('-u', '{url}', '--batch', '--output-dir', '{outdir}', '--flush-session'),
          json_mode='lines', parser='parse_sqlmap_lines',
          install_hint='pipx install sqlmap  (or git clone sqlmapproject/sqlmap).',
          homepage='https://sqlmap.org', default_severity='INFO'),

    # ---- Cloud & secrets -------------------------------------------------- #
    _spec(key='trufflehog', name='TruffleHog', category='cloud', binaries=('trufflehog',),
          target_kind='url', version_args=('--version',),
          argv_template=('--json', '--no-update', 'git', '{url}'),
          json_mode='stdout_jsonl', parser='parse_trufflehog_jsonl',
          install_hint='Install trufflehog from https://github.com/trufflesecurity/trufflehog',
          homepage='https://github.com/trufflesecurity/trufflehog'),
    _spec(key='gitleaks', name='gitleaks', category='cloud', binaries=('gitleaks',),
          target_kind='path', version_args=('version',),
          argv_template=('detect', '--report-format', 'json', '--report-path', '{outfile}',
                         '--no-banner', '--source', '{target}'),
          json_mode='file_json', parser='parse_gitleaks_json',
          install_hint='go install github.com/gitleaks/gitleaks/v8@latest',
          homepage='https://github.com/gitleaks/gitleaks'),
    _spec(key='scoutsuite', name='ScoutSuite', category='cloud', binaries=('scout',),
          target_kind='host', version_args=('--version',),
          argv_template=('--no-browser',),
          json_mode='lines', parser='generic_lines',
          install_hint='pipx install scoutsuite  (cloud creds configured separately).',
          homepage='https://github.com/nccgroup/ScoutSuite', long_running=True),
    _spec(key='prowler', name='Prowler', category='cloud', binaries=('prowler',),
          target_kind='host', version_args=('--version',),
          argv_template=('aws', '-M', 'json-ocsf', '-o', '{outdir}'),
          json_mode='lines', parser='generic_lines',
          install_hint='pipx install prowler  (cloud creds configured separately).',
          homepage='https://github.com/prowler-cloud/prowler', long_running=True),
]

TOOL_REGISTRY: Dict[str, ToolSpec] = {s.key: s for s in _SPECS}


def tools_by_category() -> Dict[str, list]:
    """Return {category_key: [ToolSpec, ...]} preserving TOOL_CATEGORIES order."""
    out: Dict[str, list] = {c: [] for c in TOOL_CATEGORIES}
    for spec in TOOL_REGISTRY.values():
        out.setdefault(spec.category, []).append(spec)
    return out


def get_spec(key: str) -> ToolSpec:
    return TOOL_REGISTRY[key]
