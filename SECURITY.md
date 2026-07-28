# Security Policy

Thank you for helping keep Blackthorn and its users safe. Blackthorn is a
threat-hunting and bug bounty web security tool, so please distinguish between:

- vulnerabilities in Blackthorn itself; and
- findings discovered while using Blackthorn against a third-party system.

This policy covers vulnerabilities in Blackthorn itself.

## Supported Versions

Security fixes are provided for the latest released version only. Users should
upgrade to the latest release before reporting an issue that may already have
been fixed.

| Version | Supported |
| ------- | --------- |
| 1.8.x   | Yes       |
| 1.7.x and earlier | No |

## Scope

Examples of in-scope issues include:

- arbitrary code execution, command injection, or unsafe plugin execution;
- path traversal, unsafe file writes, or report-generation issues that can
  overwrite unintended files;
- credential, token, cookie, or scan-data disclosure;
- authorization bypasses in safety controls such as `--authorize`;
- unsafe handling of proxies, certificates, imported scan data, or external
  tool output; and
- dependency or packaging issues that create a practical exploit path for
  Blackthorn users.

Out-of-scope reports include:

- vulnerabilities in third-party targets tested with Blackthorn;
- payloads or edge-control techniques that work as intended against a target;
- missing detections, false positives, or scanner accuracy issues without a
  security impact on Blackthorn users;
- social engineering, spam, physical attacks, or denial-of-service testing
  against project infrastructure; and
- issues that require a malicious local user on an already-compromised machine
  without increasing impact.

## Reporting a Vulnerability

Please do not open a public GitHub issue for security vulnerabilities.

Report vulnerabilities privately through the repository's GitHub Security tab
using a private Security Advisory.

If GitHub advisories are not available to you, contact the maintainers directly:
Nazariy Buryak or Marwan Fayad.

Please include as much of the following as possible:

- the affected Blackthorn version or commit;
- your operating system and Python version;
- a clear description of the issue and impact;
- reproduction steps, proof-of-concept input, or a minimal test case;
- any relevant configuration, command-line flags, plugins, reports, or imported
  files; and
- whether the issue has been disclosed anywhere else.

Avoid sending real credentials, private target data, or sensitive scan output
unless we explicitly request it. Redacted examples are preferred.

## What to Expect

We aim to acknowledge new reports within 72 hours. After triage, we will let you
know whether the issue is accepted, needs more information, or is out of scope.

For accepted vulnerabilities, we will work on a fix, prepare a release when
appropriate, and coordinate public disclosure. We are happy to credit reporters
in release notes or changelogs if they want recognition.

If we decline a report, we will explain why, for example when the behavior is a
documented limitation, a third-party target finding, or not a practical security
risk for Blackthorn users.

## Safe Harbor

We will not pursue legal action or request law-enforcement investigation for
good-faith research that follows this policy. Good-faith research means you:

- test only Blackthorn or systems you are authorized to test;
- avoid privacy violations, data destruction, persistence, or service
  disruption;
- stop testing and report promptly if you discover sensitive data;
- give us reasonable time to investigate and fix before public disclosure; and
- do not use the vulnerability for personal gain or to harm others.

This safe harbor does not authorize testing third-party systems without
permission. When using Blackthorn against external systems, obtain explicit
authorization and follow responsible disclosure practices.
