# Security Policy

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security vulnerability in this project, please report it responsibly.

### How to Report

**Please DO NOT create a public GitHub issue for security vulnerabilities.**

Instead, please report them via one of these methods:

1. **GitHub Security Advisories** (Preferred)
   - Go to the [Security tab](../../security/advisories) of this repository
   - Click "Report a vulnerability"
   - Provide details about the vulnerability

2. **Email**
   - Send details to: sunandamandal28@gmail.com
   - Subject: `[SECURITY] Vulnerability Report - secure-sdlc-automation`

### What to Include

Please include the following in your report:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)
- Your name/handle for acknowledgment (optional)

### Response Timeline

| Action | Timeline |
|--------|----------|
| Initial response | Within 48 hours |
| Vulnerability confirmation | Within 7 days |
| Patch release | Within 30 days (critical: 7 days) |

### Supported Versions

| Version | Supported |
|---------|-----------|
| main branch | ✅ Yes |
| develop branch | ✅ Yes |
| Other branches | ❌ No |

## Security Measures in This Project

This project implements multiple layers of security:

### Automated Security Scanning

- **SAST**: Semgrep, Bandit, CodeQL
- **SCA**: Snyk, Safety, pip-audit, OSV-Scanner
- **Secret Detection**: Gitleaks, TruffleHog
- **Container Security**: Trivy, Grype, Hadolint
- **IaC Security**: Checkov, tfsec
- **DAST**: OWASP ZAP (on staging)

### Security Gates

- All PRs require passing security checks
- Critical/High vulnerabilities block merges
- Security team review required for sensitive files

### Compliance

- OWASP ASVS v4.0 Level 2 compliance
- NIST 800-53 Rev 5 Moderate baseline
- Continuous compliance validation

### Dependency Management

- Dependabot enabled for automated updates
- SBOM generation on every build
- License compliance checking

## Security Best Practices for Contributors

1. **Never commit secrets** - Use environment variables
2. **Keep dependencies updated** - Review Dependabot PRs promptly
3. **Follow secure coding guidelines** - See `security/` folder
4. **Request security review** - For any auth/crypto changes

## Acknowledgments

We appreciate responsible disclosure and will acknowledge security researchers who report valid vulnerabilities (unless they prefer to remain anonymous).
