<div align="center">
  <img src="blackthornlogo-background.jpg" alt="Blackthorn" width="100%" />
  <h1>Blackthorn</h1>
  <p><strong>Threat hunting and bug bounty web security toolkit</strong></p>
  <p>Discover attack surface, test web applications, validate findings, reproduce evidence, and build reports from a desktop workspace or CLI.</p>
  <p>
    <img src="https://img.shields.io/badge/version-1.8-1f2937" alt="Version 1.8" />
    <img src="https://img.shields.io/badge/catalogued_techniques-128-1f2937" alt="128 catalogued technique groups" />
    <img src="https://img.shields.io/badge/categories-16-1f2937" alt="16 categories" />
    <img src="https://img.shields.io/badge/python-3.8%2B-1f2937" alt="Python 3.8+" />
    <img src="https://img.shields.io/badge/license-MIT-1f2937" alt="MIT license" />
  </p>
</div>

> **Naming note (ex-WAFPierce):** Blackthorn is the current product name. The repository URL, Python package, and some legacy commands still use `WAFPierce`/`wafpierce` for compatibility.

> Use Blackthorn only on systems you own or are explicitly authorized to test. Scans use safe mode by default. Use `--authorize` and scope rules for production-like targets; `--full-impact` is an explicit opt-out from safe mode.

## Run it now

### Desktop GUI

```bash
git clone https://github.com/K0NGR3SS/WAFPierce.git blackthorn
cd blackthorn

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .

python3 run_gui.py
```

After installation, the same GUI can be opened with:

```bash
blackthorn gui
```

On Windows, activate the environment with `.venv\Scripts\activate` and use `python run_gui.py`.

### CLI

```bash
git clone https://github.com/K0NGR3SS/WAFPierce.git blackthorn
cd blackthorn
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

blackthorn doctor
blackthorn scan https://target.example --dry-run --safe-mode
```

Passing a URL without a subcommand defaults to `scan`:

```bash
blackthorn https://target.example --dry-run
```

### Docker

```bash
docker build -t blackthorn .
docker run --rm blackthorn doctor
docker run --rm blackthorn scan https://target.example --safe-mode
```

The Docker entrypoint is the headless CLI.

## Capability summary

The counts below come from the version 1.8 registered scanner and tool catalogs. A technique group is a distinct test implementation; many groups send multiple payloads, encodings, headers, paths, methods, or confirmation requests.

| Capability | Current coverage |
| --- | ---: |
| Catalogued web-security technique groups | **128** |
| Proof-capable groups with vulnerability-specific confirmation | **18** |
| Candidate-only differential groups requiring analyst verification | **79** |
| Observation-only inventory/configuration groups | **23** |
| Runnable in a normal non-intrusive scan | **101** |
| Additional runnable groups requiring `--intrusive` | **19** |
| Raw-transport groups disabled until a faithful engine exists | **7** |
| DNS-rebinding group disabled until a proof-capable engine exists | **1** |
| Runnable with safe mode and non-intrusive defaults | **87** |
| Scan categories | **16** |
| External tool drivers | **23** |
| Export formats | **9** |
| Recorded-traffic import formats | **3** |
| AI provider types | **3** |
| Desktop workspace sections | **22** |

Catalog coverage is not a claim that every group can prove a vulnerability.
Blackthorn exposes each registered group as proof-capable, candidate-only,
observation-only, or unavailable. Candidate and external-tool alerts stay
separate from confirmed findings until they are verified.

To verify the current scanner catalog from the installed version:

```bash
blackthorn scan --list-categories
blackthorn scan --list-techniques
```

## What Blackthorn can do

### Attack-surface discovery

- Crawl same-host links, forms, and parameters.
- Parse `robots.txt` and `sitemap.xml`.
- Ingest OpenAPI/Swagger documents and GraphQL schemas.
- Discover API routes, debug endpoints, sensitive files, JavaScript bundles, and content paths.
- Enumerate subdomains and check DNS resolution, certificate transparency, historical DNS, and zone-transfer exposure.
- Fingerprint frameworks, servers, CMS platforms, cloud providers, edge controls, and known vulnerable software versions.
- Detect subdomain takeover conditions across supported provider signatures.
- Run a dedicated discovery workflow with Subfinder, Amass, Certificate Transparency, dnsx, and ProjectDiscovery httpx; Nmap is a separately confirmed active option.
- Filter the finished host inventory by DNS state, HTTP availability, response class, or exact status code, and copy one URL directly from its row.

### Active web-security testing

- Test authentication, authorization, IDOR, mass assignment, API-version exposure, and role-related logic.
- Test SQL injection, XSS, command injection, NoSQL, LDAP, SSTI, XXE, CRLF, SSI, XSLT, CSS injection, deserialization, prototype pollution, and traversal behavior.
- Test JWT, OAuth/OIDC, SAML, GraphQL, WebSocket, SSRF, cloud metadata, file upload, cache, and race behavior with proof-specific checks and impact gates.
- Exercise parser differences using alternate methods, encodings, content types, duplicate parameters, multipart boundaries, transfer encodings, and HTTP protocol variations.
- Run optional browser-backed DOM XSS and client-side path traversal checks.
- Probe AI/LLM-backed endpoints for prompt-injection behavior.

### Finding validation and evidence

- Establish a multi-sample response baseline and normalize dynamic values before comparison.
- Compare status, size, content similarity, and response behavior instead of relying on status code alone.
- Re-run candidate bypasses with cache disabled and record confirmation counts.
- Attach confidence, severity, CVSS v3.1 score/vector, CWE, request details, and reproduction `curl` data where available.
- Confirm blind SSRF, XXE, and JNDI-style behavior through Interactsh or the self-hosted OOB listener.
- Redact cookies, tokens, authorization headers, and other secrets from saved reports by default.
- Save scan history, compare runs, identify new/resolved findings, and monitor a target over time.

### Real traffic and authenticated testing

- Import HAR captures, Postman v2 collections, and Burp items XML.
- Seed testing from real application routes and parameters instead of only the target root.
- Supply cookies, repeatable custom headers, bearer tokens, or HTTP Basic credentials.
- Authenticate through a login URL with form data and a configurable success marker.
- Re-authenticate when a configured session expires during a scan.
- Send captured requests between the Browser, Proxy, Repeater, Fuzzer, and findings workflow.

### Execution controls

- Run specific categories or the complete catalog.
- Use `stealth`, `normal`, or `aggressive` profiles.
- Control threads, per-request delay, timeout, jitter, seed, and maximum runtime.
- Rotate a proxy pool or route traffic through Tor.
- Resume interrupted scans from checkpoints.
- Run multiple targets from the GUI queue with per-target and total progress.
- Use dry-run mode to inspect the plan without sending requests.
- Safe mode is on by default and skips noisy, denial-of-service, and state-changing probes.
- Use `--full-impact` only when the engagement explicitly permits the additional probes.
- Use `--intrusive` only when the engagement explicitly permits guessed state-changing workflows such as uploads, email, cache, race, and metadata tests.

### Reporting and automation

- Export HTML, JSON, PDF, SARIF, Nuclei YAML, JUnit XML, CSV, Prometheus/OpenMetrics, or HAR.
- Emit JSON to stdout for pipelines.
- Return exit code `10` when a finding meets a configured `--fail-on` severity threshold.
- Generate standalone HTML diffs against a previous JSON result set.
- Push summaries to Slack, Discord, Microsoft Teams, or a generic webhook.
- Map confirmed findings into DefectDojo-compatible records.
- Hand findings to Metasploit RPC or replay/export them through Caido.
- Run a local JSON-lines agent bridge over standard input/output.

### Extensibility and AI

- Load user plugins without changing the core scanner.
- Add database-backed custom payloads and evasion profiles.
- Build typed pipelines from Blackthorn scans, external tools, and report stages.
- Use Anthropic Claude, a local Ollama model, or an OpenAI-compatible endpoint.
- Run opt-in false-positive triage, report drafting, and payload-mutation assistance.
- Continue scanning when an optional AI provider is unavailable; AI is never required for the core engine.

## Detailed scanner coverage: 128 catalogued technique groups

Blackthorn currently runs 101 groups in a normal non-intrusive scan. Nineteen
additional stateful, billable, or internal-network groups require the separate
`--intrusive` impact opt-in. Seven ambiguous HTTP framing/race groups remain
visible but disabled until Blackthorn has a raw HTTP/1.1 and HTTP/2 transport.
DNS rebinding is also disabled until a user-owned authoritative DNS workflow can
change answers and capture proof; a Host-header size difference is insufficient.

### Header Manipulation — 9

- Host header injection
- `X-Forwarded-For` behavior
- `X-Forwarded-Host` behavior
- `X-Original-URL` / rewrite-path behavior
- Header injection
- Origin header manipulation
- Custom header fuzzing
- IP-spoofing header variants
- Extended host-header attacks

### Encoding & Obfuscation — 9

- URL encoding variations
- Double encoding
- Case manipulation
- Comment injection
- Whitespace manipulation
- Unicode normalization
- Payload mutation
- Polyglot payloads
- Extended path normalization

### Protocol-Level Attacks — 19

- HTTP method bypass
- HTTP method override
- Content-type bypass
- HTTP parameter pollution
- Transfer-Encoding request smuggling *(disabled: raw transport required)*
- HTTP/2 downgrade behavior
- HTTP/2-specific attacks *(disabled: raw HTTP/2 transport required)*
- WebSocket upgrade behavior
- WebSocket security checks
- Chunked transfer variations *(disabled: raw transport required)*
- HTTP pipelining
- Extended request smuggling *(disabled: raw transport required)*
- HTTP desynchronization *(disabled: raw transport required)*
- Extended verb tampering *(`--intrusive`; read-only methods only)*
- Multipart boundary bypass
- WebSocket fuzzing
- CL.0 / 0.CL smuggling *(disabled: raw transport required)*
- gRPC detection
- HTTP/3 detection

### Cache & Control — 6

- Cache-Control manipulation
- Range-header behavior
- Cache poisoning
- Web cache deception
- Extended range attacks
- Deep cache poisoning

### Injection Testing — 22

- SQL injection bypass
- XSS bypass
- Command injection bypass
- Windows command injection
- Path traversal bypass
- NoSQL injection
- LDAP injection
- Server-side template injection
- XML external entity injection
- CRLF injection
- Prototype pollution
- JSON injection and parser differentials
- Insecure deserialization
- Server-Side Includes injection
- Log4Shell/JNDI patterns
- Dangling markup
- CSS injection
- XSLT injection
- JSON-based SQL injection bypass
- DOM XSS
- Client-side path traversal
- Mutation fuzzing

### Security Misconfigurations — 8

- CORS misconfiguration
- Open redirect
- Security-header audit
- Cookie-security audit
- Clickjacking
- Content sniffing *(`--intrusive`; inert upload canaries)*
- HTTP response splitting
- Content Security Policy analysis

### Business Logic & Authorization — 8

- API versioning bypass
- Mass assignment
- IDOR patterns
- Business-logic boundary checks
- Email-header injection
- File-upload bypass
- Rate-limit detection
- Race-condition testing

### JWT & Authentication Attacks — 6

- JWT/OAuth bypass cases
- JWT algorithm, key, and claim attacks
- OAuth/OIDC configuration and redirect behavior
- Embedded JWK self-signing
- SAML XML Signature Wrapping surface checks
- Authentication and authorization logic checks

### GraphQL Attacks — 3

- GraphQL bypass cases
- Deep GraphQL testing, introspection, batching, depth, and alias behavior
- GraphQL CSRF

### AI / LLM Attacks — 1

- LLM endpoint and direct instruction-following behavior *(`--intrusive`)*

### SSRF Advanced — 3

- SSRF bypass variants
- SSRF protocol smuggling
- DNS rebinding *(disabled: authoritative DNS proof engine required)*

### PDF / Document Attacks — 3

- PDF generation surface discovery *(`--intrusive`; inert markup only)*
- `postMessage` security checks
- Relative Path Overwrite

### Cloud Security — 8

- Azure Blob enumeration
- Google Cloud Storage bucket discovery
- Serverless function detection
- Kubernetes API exposure
- Cloud-provider detection
- Cloud metadata enumeration
- Extended multi-cloud metadata testing
- Amazon S3 bucket enumeration

### Advanced Payloads — 7

- Time-based detection
- Buffer and size limits
- Integer overflow boundaries
- Bot-detection evasion
- IPv6 representation bypass
- Charset and overlong-UTF-8 confusion
- HTTP/2 single-packet race testing *(disabled: synchronized raw HTTP/2 required)*

### Information Disclosure — 6

- Sensitive-file and configuration disclosure
- Subdomain takeover detection
- API key and secret exposure
- Timing-based discovery
- Error-based disclosure
- Secrets in JavaScript bundles

### Detection & Reconnaissance — 10

- Edge rule-version detection
- JavaScript challenge and bot-control detection
- API endpoint discovery
- DNS zone-transfer testing
- Subdomain enumeration
- Historical DNS lookup
- Certificate-transparency lookup
- Technology-stack fingerprinting
- CVE fingerprinting
- Content discovery

## Desktop GUI workspace

The PySide6 desktop application keeps five primary workflow destinations visible
and moves specialist surfaces into one Workbench chooser:

| Area | Sections and tools |
| --- | --- |
| Workflow | Scope & scan, Discover, Test plan, Analyze, Report |
| Workbench | External Tools, Browser, Proxy, Repeater, Fuzzer, SQLi, Secrets, Payloads, ZAP/Burp, AD / Internal, AI assistance, Live Logs, Timeline, Schedule, Plugins |
| Utilities | Engagements, Settings |

GUI functionality includes:

- Multi-target queue with task-based profiles, optional advanced categories, configurable concurrency, threads, and delay.
- Engagement selection, authorization file, include/exclude scope rules, safe mode, dry run, re-confirmation, impersonation, AI triage, and OOB settings.
- Evidence-led results workspace with target grouping, verification/workflow filters, exact-request reproduction, authorized re-test, Repeater handoff, analyst notes, and export.
- Dashboard statistics, scan comparison, historical timeline, and live logs.
- Built-in intercepting proxy, local CA management, traffic history, and Repeater.
- Browser workspace and ZAP/Burp handoff.
- Fuzzer, SQLi helper, secrets workflow, payload management, and custom payload packs.
- External-tool detection, execution, output streaming, and normalized findings.
- Engagement management, scheduled scans, scan-profile import/export, plugins, and persistent settings.

## External tool drivers — 23

Blackthorn does not silently install these tools. When already available on the host, it can detect and drive:

| Purpose | Tools |
| --- | --- |
| Reconnaissance | Nmap, Masscan, Naabu, Subfinder, OWASP Amass, dnsx, httpx, WhatWeb, Katana |
| Content discovery | ffuf, Feroxbuster, Gobuster, dirsearch |
| Vulnerability testing | Nuclei, Nikto, WPScan, Dalfox, SSLyze, sqlmap |
| Secrets and cloud | TruffleHog, Gitleaks, ScoutSuite, Prowler |

The table describes supported adapters, not tools bundled with Blackthorn.
Availability, binary path, and version are detected at runtime. Empty output is
reported as an empty run—not fabricated as a finding—and tool alerts enter the
candidate workflow until Blackthorn verifies them independently.

The dedicated `blackthorn recon` workflow expects Subfinder, Amass, dnsx, and
the ProjectDiscovery httpx binary (not the Python package with the same command
name). It merges those sources with public Certificate Transparency names and
keeps DNS-resolved, HTTP-live, DNS-only, and unresolved hosts distinct.
Independent passive sources run concurrently and their complete results are
merged with source attribution, reducing wait time without dropping a source.
Wildcard scope notation is accepted and normalized:

```bash
blackthorn doctor
blackthorn recon '*.example.com'
```

Nmap is disabled by default because it is an active scan that can trigger
network or endpoint security alerts. Enable its unprivileged, capped connect
scan only for an authorized target:

```bash
blackthorn recon example.com --ports
```

## CLI commands

| Command | Function |
| --- | --- |
| `blackthorn scan <url>` | Run the built-in 128-group web-security scanner |
| `blackthorn recon <domain>` | Run the external-tool reconnaissance workflow |
| `blackthorn chain <url>` | Run discovery, testing, reconnaissance, and reporting as one workflow |
| `blackthorn msf ...` | Check Metasploit RPC, run auxiliary scanners, or push findings |
| `blackthorn caido ...` | Check Caido, replay findings through its proxy, or export raw requests |
| `blackthorn agent-server --stdio` | Start the local JSON-lines agent bridge |
| `blackthorn doctor` | Check dependencies, configuration, OOB support, recon tools, and integrations |
| `blackthorn gui` | Open the desktop application |
| `blackthorn version` | Show the version and optional component availability |

### Practical scan examples

```bash
# Inspect the safe-by-default request plan without sending traffic
blackthorn scan https://target.example --dry-run

# Authorized, allowlisted scan with browser impersonation
blackthorn scan https://target.example \
  --authorize scope.txt \
  --impersonate chrome \
  --export report.html \
  --export-format html

# Authenticated scan
blackthorn scan https://target.example \
  --bearer "$TOKEN" \
  --header "X-Researcher: handle" \
  --scope-include '^https://target\.example/'

# Seed testing from captured traffic
blackthorn scan https://target.example \
  --import-har session.har \
  --safe-mode

# OOB confirmation for blind findings
blackthorn scan https://target.example \
  --oob interactsh \
  --oob-wait 15

# Disable safe mode only for an engagement that explicitly permits it
blackthorn scan https://target.example \
  --authorize scope.txt \
  --full-impact

# CI output and severity gate
blackthorn scan https://target.example \
  --json \
  --export findings.sarif \
  --export-format sarif \
  --fail-on high

# Resume and monitor
blackthorn scan https://target.example --resume --monitor
```

Run `blackthorn scan --help` for every flag.

## Configuration files

Blackthorn accepts JSON or TOML configuration. Explicit CLI flags take precedence over file values.

```toml
threads = 10
delay = 0.2
impersonate = "chrome"
safe_mode = true

[profiles.staging]
target = "https://staging.example.com"
oob = "interactsh"
```

```bash
blackthorn scan --config blackthorn.toml --config-profile staging
```

## Optional components

```bash
# Headless browser checks
pip install -e ".[browser]"
python -m playwright install chromium

# Anthropic AI provider
pip install -e ".[ai]"

# OS keychain storage for GUI-entered integration secrets
pip install -e ".[secrets]"

# Browser, AI, keychain, and development dependencies
pip install -e ".[full,dev]"
```

Other optional integrations include Metasploit RPC through `pymetasploit3`, a running Caido instance, a local Ollama server, or an OpenAI-compatible API endpoint.

### Credential storage

Blackthorn does not write AI keys, external-tool API keys, proxy passwords, ZAP keys, or the Metasploit RPC password to its preferences JSON or SQLite database. Environment variables take precedence. With the optional `keyring` extra installed, GUI-entered secrets are saved in the operating-system credential store; otherwise they remain available only for the current process.

Common variables include `ANTHROPIC_API_KEY`, `AI_API_KEY`, `OPENAI_API_KEY`, `MSF_RPC_PASSWORD`, and `ZAP_API_KEY`. External-tool keys use `BLACKTHORN_TOOL_<TOOL>_API_KEY`.

## Build the desktop executable

```bash
pip install -r requirements.txt
python3 build_exe.py
```

The PyInstaller configuration bundles the Blackthorn identity assets, Qt runtime, wordlists, scanner modules, and supported native dependencies.

## Development

```bash
pip install -e ".[dev]"
python3 -m pytest
ruff check .
```

The Python package retains its ex-WAFPierce internal module path during the
rebrand so existing imports, plugins, and stored configuration remain
compatible. User-facing commands and product copy use Blackthorn.

The UI and enhancement plan lives in [docs/BLACKTHORN_PRODUCT_PLAN.md](docs/BLACKTHORN_PRODUCT_PLAN.md).

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidance and [SECURITY.md](SECURITY.md) for private vulnerability reporting.

## Responsible use and disclosure

If Blackthorn helps identify a vulnerability:

1. Stay inside the program's documented scope and rules.
2. Minimize data access and service impact.
3. Preserve clear, redacted evidence.
4. Report through the organization's approved channel.
5. Allow reasonable remediation time before coordinated disclosure.

## Authors

- [Nazariy Buryak](https://github.com/K0NGR3SS)
- [Marwan Fayad](https://github.com/Marwan-verse)
- [Mykhailo Kholiev](https://github.com/classified-mick)

## License and legal notice

Blackthorn is released under the [MIT License](LICENSE).

This software is intended exclusively for authorized security testing and research. You must obtain explicit permission before testing systems you do not own. The authors and contributors accept no liability for misuse, damage, service disruption, data loss, or legal consequences. The software is provided “as is,” without warranty.
