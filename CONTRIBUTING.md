# Contributing to Blackthorn

Thank you for helping improve Blackthorn. Contributions should support its role as a practical threat-hunting and bug bounty web security workspace.

## Report bugs

Open an issue after checking that the problem has not already been reported. Include:

- Operating system and version.
- Python and PySide6 versions.
- A minimal sequence that reproduces the problem.
- A redacted traceback, log, or sample artifact.
- Whether the issue occurs in the GUI, CLI, packaged executable, or all three.

Report vulnerabilities in Blackthorn privately under [SECURITY.md](SECURITY.md), not in a public issue.

## Propose tests and enhancements

Explain the researcher workflow first: what question the feature answers, what evidence it produces, and how it stays within declared scope. For a new probe, include a safe test fixture, expected positive and negative behavior, false-positive considerations, and a reference where possible.

UI proposals should follow [docs/BLACKTHORN_PRODUCT_PLAN.md](docs/BLACKTHORN_PRODUCT_PLAN.md): restrained color, clear hierarchy, plain language, keyboard access, and evidence-first results.

## Development setup

```bash
git clone <your-fork-url> blackthorn
cd blackthorn
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
python3 -m pytest
ruff check .
```

The public CLI is `blackthorn`. The existing Python module path remains in place during the rebrand for compatibility.

## Pull requests

- Keep each pull request focused.
- Add or update tests for behavior changes.
- Avoid live third-party targets in tests; use local fixtures and mocked network boundaries.
- Preserve authorization checks, redaction, and safe-mode behavior.
- Explain user-visible copy or layout decisions and include screenshots for GUI changes.
- Note commands run and anything that could not be verified.
