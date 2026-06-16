# Contributing to WAFPierce

First off, thank you for considering contributing to WAFPierce! It's people like you that make this tool a powerful asset for the penetration testing and security research community. 

Whether you're fixing a bug, adding a new WAF bypass technique, or improving the PySide6 GUI, your help is greatly appreciated.

---

## 🐞 Reporting Bugs

If you find a bug, please help us squash it by opening an issue on our [GitHub repository](https://github.com/K0NGR3SS/WAFPierce). Before creating a new issue, please check the existing open and closed issues to see if it has already been reported.

When reporting a bug, please include:
* **Your operating system and version.**
* **Your Python version** (WAFPierce requires Python 3.8+).
* **Your PySide6 version** (requires 6.10.1+).
* **A clear description of the issue**, including steps to reproduce the crash or unexpected behavior.
* **Error tracebacks or logs**, especially if the GUI crashes or a specific module (like the Plugin Manager) throws an exception.

*(Note: If you've found a security vulnerability within the tool itself, please refer to our [SECURITY.md](SECURITY.md) instead of opening a public issue.)*

---

## 💡 Suggesting Enhancements & New Tests

WAFPierce thrives on having the latest and greatest bypass techniques. If you have ideas for new attack vectors (SQLi, SSRF, JWT, GraphQL, etc.), new WAF/CDN fingerprints, or GUI improvements:

1. **Open a Feature Request Issue**: Detail how the new technique works and provide sample payloads or heuristic baselines if possible.
2. **Direct Contact**: You can also reach out directly to **Marwan** or **Nazariy** to discuss new tests or community suggestions.

---

## 🛠️ Setting Up Your Development Environment

To start contributing code, you'll need to set up the project locally:

1. **Fork the repository** on GitHub.
2. **Clone your fork** to your local machine:
   ```bash
   git clone [https://github.com/K0NGR3SS/WAFPierce.git](https://github.com/K0NGR3SS/WAFPierce.git)
   cd WAFPierce
