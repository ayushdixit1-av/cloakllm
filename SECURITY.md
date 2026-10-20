# Security Policy

## Supported Versions

Only the latest release of CloakLLM receives active security updates and vulnerability patches.

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1.0 | :x:                |

## Reporting a Vulnerability

We take the security of CloakLLM seriously. As a tool designed to prevent credential exfiltration to LLM APIs, confidential and prompt reporting of potential bypasses, leaks, or cryptographic defects is critical.

### Reporting Process

1. **Do NOT open a public GitHub issue** for undisclosed security vulnerabilities.
2. Please use **GitHub Private Vulnerability Reporting** via the repository's Security tab:
   - Navigate to [https://github.com/ayushdixit1-av/cloakllm/security/advisories](https://github.com/ayushdixit1-av/cloakllm/security/advisories)
   - Click **"Report a vulnerability"**
3. Alternatively, email the maintainer directly at:
   - **`ayushdixitvsecpanki@gmail.com`** with the subject line `[SECURITY] CloakLLM Vulnerability Report`.
4. Please include:
   - Description of the vulnerability and attack vector.
   - Exact steps or minimal reproducer code to trigger the issue.
   - Any potential impact or data exposure scenarios.
   - Operating system and Python version.

### Response Timeline

- **Initial Acknowledgement:** Within 48 hours.
- **Triage & Reproduction:** Within 5 business days.
- **Fix & Disclosure Coordination:** Coordinated patch release within 30 days of confirmed reproduction.
