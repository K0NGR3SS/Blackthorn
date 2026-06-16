# Security Policy

## Supported Versions

The following table lists the versions of WAFPierce that are currently being supported with security updates. We highly recommend always running the latest release to ensure you have the most up-to-date security tests, GUI stability, and bypass techniques.

| Version | Supported          |
| ------- | ------------------ |
|(current version)| :white_check_mark: |
| 1.3     | :x:                |
| 1.2     | :x:                |
| < 1.2   | :x:                |

## Reporting a Vulnerability

We take the security of WAFPierce seriously. If you discover a security vulnerability within the WAFPierce tool itself (e.g., an arbitrary code execution flaw in the Plugin Manager, a path traversal in the automated Markdown reporting, etc.), please **do not** report it through public GitHub issues. 

**Where to Report:**
Please report all security vulnerabilities privately by directly contacting the authors, **Nazariy Buryak** or **Marwan Fayad**, or by utilizing the private "Security Advisories" reporting feature on our [GitHub repository](https://github.com/K0NGR3SS/WAFPierce).

**What to Expect:**
* **Acknowledgement:** You can expect an initial acknowledgement of your report within 48 to 72 hours.
* **Updates:** We will keep you informed on our progress as we triage the vulnerability, determine its severity, and develop a fix.
* **Resolution:** If the vulnerability is accepted, we will prioritize a patch in the next immediate release (e.g., a hotfix for the 1.4.x branch). We will also gladly provide credit in our changelog for your discovery, should you want it. If the report is declined (e.g., it is a known limitation or not considered a security risk for a local pentesting tool), we will provide a detailed explanation as to why.

**Responsible Disclosure:**
WAFPierce firmly advocates for responsible disclosure when using our tool to test external systems (allowing 90 days for fixes, coordinating disclosure, and not exploiting findings for personal gain). We ask that you extend us the exact same courtesy. Please coordinate with us and refrain from publicly disclosing the vulnerability in WAFPierce until a patched version is available to our users.
