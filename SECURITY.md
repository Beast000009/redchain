# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 2.x     | ✅ Current          |
| 1.x     | ❌ End of Life      |

## Reporting a Vulnerability

**Please do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please report security issues by emailing: **singhpiyushsingh707@gmail.com**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will respond within 48 hours and work with you on a fix.

## Security Considerations

RedChain is a penetration testing tool designed to be used **only against authorized targets**. Users must:

1. **Obtain written authorization** before scanning any target
2. **Define scope** using `scope.json` to prevent accidental scanning of unauthorized targets
3. **Handle API keys securely** — never commit `.env` files to version control
4. **Use responsibly** — this tool is for authorized security testing only

## Known Security Limitations

- SSL verification is disabled for some HTTP requests (required for self-signed certs on targets)
- Report output may contain sensitive target information — handle reports securely
- API keys are stored in plaintext in `.env` — use a secrets manager in production environments
