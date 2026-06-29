# Security Policy

We take the security of the **Vajraa** framework and the AI models it protects very seriously. If you believe you have found a security vulnerability, we appreciate your help in disclosing it to us responsibly.

This document outlines our policy for reporting, triaging, and resolving security vulnerabilities.

---

## Supported Versions

We actively provide security updates and patches for the following versions of Vajraa:

| Version | Supported | Release Date |
| :--- | :--- | :--- |
| **0.1.x** | ✅ Yes | June 2026 (Active) |
| **< 0.1.0** | ❌ No | Deprecated |

We recommend always running the latest patch release to ensure all dynamic protections (anti-debugging, page locking, and memory zeroing) are up to date.

---

## Reporting a Vulnerability

**Please do not report security vulnerabilities via public GitHub Issues.** 

To report a vulnerability privately, choose one of the following methods:

1.  **Email**: Send an email to **security@vakira.ai**. If possible, encrypt your message using our PGP key (available upon request).
2.  **GitHub Private Vulnerability Reporting**: If available on this repository, you can submit a report directly through the **Security** tab ➔ **Vulnerability reporting** on GitHub.

### What to Include in Your Report
To help us triage and resolve the issue quickly, please include:
*   A description of the vulnerability and its potential impact (e.g., JIT bypass, memory extraction, anti-debugging bypass).
*   Detailed steps to reproduce the issue (PoC scripts, ONNX graphs, or PyTorch wrapper configurations).
*   Any details about the environment in which you reproduced the bug (OS, Python version, ONNX Runtime version, CPU/GPU configurations).

---

## Our Security Response Process

Once a vulnerability report is received, the Vajraa security team will follow this process:

1.  **Acknowledgment (within 48 hours)**: We will acknowledge receipt of your report and assign a primary handler to investigate.
2.  **Triage & Validation**: We will attempt to reproduce and validate the finding.
3.  **Remediation**: If validated, we will develop a patch. We may contact you to review or test the proposed fix.
4.  **Coordinated Disclosure**: We aim to release a patch and a security advisory within **90 days** of the initial report. We will credit you for the discovery in the release notes and advisory unless you request anonymity.

---

## Policy Scope

This policy applies to:
*   All source code within this repository (Python wrapper modules and C++ native PAL/Custom operators).
*   Compiler outputs and graph-rewriting files (`.ems` graphs and `.lic` files).

It does *not* apply to vulnerabilities in upstream dependencies (e.g., ONNX Runtime or PyTorch core libraries), unless they are caused by our integration or misconfiguration of those libraries.
