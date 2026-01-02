# 🛡️ Secure SDLC Automation

> End-to-end security automation across the Software Development Lifecycle - from pre-commit hooks to production monitoring, with integrated vulnerability management and compliance-as-code.

[![Security Pipeline](https://github.com/YOUR_USERNAME/secure-sdlc-automation/actions/workflows/security-pipeline.yml/badge.svg)](https://github.com/YOUR_USERNAME/secure-sdlc-automation/actions)
[![OWASP ASVS](https://img.shields.io/badge/OWASP%20ASVS-Level%202-green)](https://owasp.org/www-project-application-security-verification-standard/)
[![NIST 800-53](https://img.shields.io/badge/NIST%20800--53-Moderate-blue)](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Security Tools Integrated](#security-tools-integrated)
- [Pipeline Stages](#pipeline-stages)
- [Vulnerability Management](#vulnerability-management)
- [Compliance Mapping](#compliance-mapping)
- [Custom Security Policies](#custom-security-policies)
- [Metrics & Reporting](#metrics--reporting)
- [Local Development](#local-development)
- [Contributing](#contributing)

---

## 🎯 Overview

This project demonstrates a **comprehensive DevSecOps implementation** that goes beyond basic CI/CD security scanning. It includes:

- **10+ security tools** integrated into a unified pipeline
- **Custom Semgrep rules** for organization-specific vulnerabilities
- **Automated vulnerability triage** with severity-based SLAs
- **Compliance-as-Code** mapped to OWASP ASVS and NIST 800-53
- **Security metrics dashboard** tracking MTTR, vulnerability trends
- **Slack/Email alerting** for critical findings
- **DefectDojo integration** for centralized vulnerability management

### Why This Matters

| Traditional Approach | This Implementation |
|---------------------|---------------------|
| Run scanner, get report | Automated triage + ticket creation |
| Manual compliance checks | Compliance-as-Code with evidence |
| Security at the end | Shift-left with pre-commit hooks |
| Alert fatigue | Risk-based prioritization + SLAs |
| Siloed tools | Unified vulnerability management |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           DEVELOPER WORKSTATION                              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                          │
│  │ Pre-commit  │  │   Semgrep   │  │  Gitleaks   │                          │
│  │   Hooks     │  │   (Local)   │  │   (Local)   │                          │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘                          │
└─────────┼────────────────┼────────────────┼─────────────────────────────────┘
          │                │                │
          ▼                ▼                ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              GITHUB ACTIONS                                  │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                        STAGE 1: CODE ANALYSIS                        │    │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │    │
│  │  │ Semgrep  │ │  Bandit  │ │ Gitleaks │ │  CodeQL  │ │ Checkov  │  │    │
│  │  │  (SAST)  │ │ (Python) │ │(Secrets) │ │ (GitHub) │ │  (IaC)   │  │    │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘  │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                    │                                         │
│                                    ▼                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                      STAGE 2: DEPENDENCY ANALYSIS                    │    │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐               │    │
│  │  │  Safety  │ │   Snyk   │ │ OSV-Scan │ │   SBOM   │               │    │
│  │  │ (Python) │ │  (SCA)   │ │ (Google) │ │ (CycloneDX)│              │    │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘               │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                    │                                         │
│                                    ▼                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                      STAGE 3: CONTAINER SECURITY                     │    │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐                             │    │
│  │  │  Trivy   │ │  Grype   │ │  Hadolint│                             │    │
│  │  │(Scanner) │ │ (Anchore)│ │(Dockerfile)│                            │    │
│  │  └──────────┘ └──────────┘ └──────────┘                             │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                    │                                         │
│                                    ▼                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                         STAGE 4: DAST (On PR)                        │    │
│  │  ┌──────────┐ ┌──────────┐                                          │    │
│  │  │ OWASP ZAP│ │  Nuclei  │                                          │    │
│  │  │ (Scanner)│ │(Templates)│                                          │    │
│  │  └──────────┘ └──────────┘                                          │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                    │                                         │
└────────────────────────────────────┼────────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                        VULNERABILITY MANAGEMENT                              │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐          │
│  │    DefectDojo    │  │  Security Lake   │  │   Slack/Email    │          │
│  │  (Aggregation)   │  │    (Metrics)     │  │    (Alerts)      │          │
│  └──────────────────┘  └──────────────────┘  └──────────────────┘          │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 🔧 Security Tools Integrated

### Static Analysis (SAST)

| Tool | Purpose | Configuration |
|------|---------|---------------|
| **Semgrep** | Multi-language SAST with custom rules | `security/semgrep/` |
| **CodeQL** | GitHub's semantic code analysis | `.github/codeql/` |
| **Bandit** | Python-specific security linter | `.bandit.yml` |

### Software Composition Analysis (SCA)

| Tool | Purpose | Configuration |
|------|---------|---------------|
| **Snyk** | Dependency vulnerabilities + license | `snyk.config.json` |
| **Safety** | Python dependency checking | `requirements.txt` |
| **OSV-Scanner** | Google's OSV database | Native |
| **SBOM Generator** | CycloneDX bill of materials | `sbom/` |

### Secret Detection

| Tool | Purpose | Configuration |
|------|---------|---------------|
| **Gitleaks** | Git history secret scanning | `.gitleaks.toml` |
| **TruffleHog** | Entropy-based detection | Native |

### Container Security

| Tool | Purpose | Configuration |
|------|---------|---------------|
| **Trivy** | Container + filesystem scanning | `trivy.yaml` |
| **Grype** | Anchore's vulnerability scanner | Native |
| **Hadolint** | Dockerfile best practices | `.hadolint.yaml` |

### Infrastructure as Code (IaC)

| Tool | Purpose | Configuration |
|------|---------|---------------|
| **Checkov** | Terraform/CloudFormation scanning | `.checkov.yaml` |
| **tfsec** | Terraform-specific scanner | Native |

### Dynamic Analysis (DAST)

| Tool | Purpose | Configuration |
|------|---------|---------------|
| **OWASP ZAP** | Automated web app scanning | `zap/` |
| **Nuclei** | Template-based scanning | `nuclei-templates/` |

---

## 📊 Pipeline Stages

### Stage 1: Pre-commit (Developer Machine)

```bash
# Runs before code is committed
- Semgrep (fast rules only)
- Gitleaks (secret detection)
- Hadolint (if Dockerfile changed)
```

### Stage 2: PR Checks (Automated)

```bash
# Runs on every pull request
- Full SAST scan (Semgrep, Bandit, CodeQL)
- Dependency scan (Snyk, Safety, OSV)
- Secret scan (Gitleaks, TruffleHog)
- IaC scan (Checkov, tfsec)
- Container scan (Trivy, Grype)
- SBOM generation
```

### Stage 3: DAST (Staging Environment)

```bash
# Runs after deployment to staging
- OWASP ZAP baseline scan
- Nuclei vulnerability templates
- Custom API security tests
```

### Stage 4: Production Monitoring

```bash
# Continuous monitoring
- Dependency vulnerability alerts
- Runtime security monitoring
- Compliance drift detection
```

---

## 🎫 Vulnerability Management

### Severity-Based SLAs

| Severity | CVSS Score | SLA to Remediate | Auto-Block PR |
|----------|------------|------------------|---------------|
| Critical | 9.0 - 10.0 | 24 hours | ✅ Yes |
| High | 7.0 - 8.9 | 7 days | ✅ Yes |
| Medium | 4.0 - 6.9 | 30 days | ❌ No |
| Low | 0.1 - 3.9 | 90 days | ❌ No |

### Triage Workflow

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Finding    │────▶│    Triage    │────▶│   Classify   │
│  Detected    │     │   (Auto/Manual)    │   (TP/FP/Risk)│
└──────────────┘     └──────────────┘     └──────┬───────┘
                                                  │
                     ┌────────────────────────────┼────────────────────────────┐
                     │                            │                            │
                     ▼                            ▼                            ▼
              ┌──────────────┐           ┌──────────────┐           ┌──────────────┐
              │ True Positive│           │False Positive│           │ Risk Accepted│
              │              │           │              │           │              │
              │ Create Jira  │           │  Suppress +  │           │  Document +  │
              │ Track SLA    │           │  Document    │           │  Review Date │
              └──────────────┘           └──────────────┘           └──────────────┘
```

### Integration with DefectDojo

All findings are automatically imported into DefectDojo for:
- Centralized vulnerability tracking
- Deduplication across tools
- Metrics and trending
- Compliance reporting

---

## 📜 Compliance Mapping

### OWASP ASVS v4.0 Coverage

| ASVS Category | Controls Implemented | Evidence |
|---------------|---------------------|----------|
| V1: Architecture | Threat model, security requirements | `docs/threat-model.md` |
| V2: Authentication | Semgrep auth rules | `security/semgrep/auth.yaml` |
| V3: Session Management | Custom session rules | `security/semgrep/session.yaml` |
| V4: Access Control | RBAC validation rules | `security/semgrep/authz.yaml` |
| V5: Validation | Input validation rules | `security/semgrep/input.yaml` |
| V6: Cryptography | Crypto policy rules | `security/semgrep/crypto.yaml` |
| V7: Error Handling | Logging rules | `security/semgrep/logging.yaml` |
| V8: Data Protection | PII detection rules | `security/semgrep/pii.yaml` |
| V9: Communication | TLS configuration | `security/semgrep/tls.yaml` |
| V10: Malicious Code | Dependency scanning | SCA tools |
| V11: Business Logic | Manual review required | N/A |
| V12: Files | File upload rules | `security/semgrep/files.yaml` |
| V13: API | API security rules | `security/semgrep/api.yaml` |
| V14: Configuration | IaC scanning | Checkov, tfsec |

### NIST 800-53 Mapping

| Control Family | Controls | Implementation |
|----------------|----------|----------------|
| SA-11 | Developer Security Testing | SAST, DAST pipeline |
| SA-15 | Development Process | Secure SDLC workflow |
| SI-10 | Information Input Validation | Semgrep input rules |
| SC-13 | Cryptographic Protection | Crypto policy rules |
| AU-2 | Audit Events | Logging rules |
| CM-7 | Least Functionality | Container scanning |

---

## 🔒 Custom Security Policies

### Organization-Specific Rules

Beyond default rulesets, this pipeline includes **custom Semgrep rules** for:

```yaml
# Example: Detect unsafe deserialization in our codebase
rules:
  - id: unsafe-pickle-load
    pattern: pickle.loads(...)
    message: "Unsafe deserialization detected. Use json instead."
    severity: ERROR
    metadata:
      cwe: "CWE-502"
      owasp: "A8:2017"
      
  - id: missing-rate-limiting
    pattern-not: "@rate_limit(...)"
    pattern: |
      @app.route(...)
      def $FUNC(...):
        ...
    message: "API endpoint missing rate limiting"
    severity: WARNING
```

See `security/semgrep/custom-rules/` for full ruleset.

---

## 📈 Metrics & Reporting

### Security KPIs Tracked

| Metric | Description | Target |
|--------|-------------|--------|
| **MTTR** | Mean Time to Remediate | < 7 days (High) |
| **Vulnerability Density** | Vulns per 1000 LOC | < 1.0 |
| **Fix Rate** | % vulns fixed within SLA | > 95% |
| **False Positive Rate** | FPs / Total Findings | < 10% |
| **Coverage** | % code scanned | 100% |
| **SBOM Freshness** | Age of dependency data | < 24 hours |

### Dashboard

Security metrics are exported to:
- GitHub Security tab (native)
- DefectDojo dashboards
- Custom Grafana dashboard (optional)

---

## 💻 Local Development

### Prerequisites

```bash
# Install pre-commit
pip install pre-commit

# Install security tools
pip install semgrep bandit safety
brew install gitleaks trivy hadolint  # macOS
# or
apt-get install -y gitleaks trivy hadolint  # Linux
```

### Setup

```bash
# Clone repository
git clone https://github.com/YOUR_USERNAME/secure-sdlc-automation.git
cd secure-sdlc-automation

# Install pre-commit hooks
pre-commit install

# Run all security scans locally
make security-scan

# Run specific scanner
make sast        # Semgrep + Bandit
make sca         # Dependency scanning
make secrets     # Secret detection
make container   # Container scanning
make iac         # Infrastructure as Code
```

### Running the Application

```bash
# Build and run with Docker
docker-compose up --build

# Run security tests against local instance
make dast-local
```

---

## 📁 Repository Structure

```
.
├── .github/
│   ├── workflows/
│   │   ├── security-pipeline.yml      # Main security pipeline
│   │   ├── dast-scan.yml              # DAST on staging
│   │   └── compliance-check.yml       # Compliance validation
│   └── codeql/
│       └── codeql-config.yml          # CodeQL configuration
├── app/
│   ├── api/                           # API endpoints
│   ├── auth/                          # Authentication module
│   ├── models/                        # Data models
│   └── utils/                         # Utility functions
├── infrastructure/
│   ├── terraform/                     # IaC definitions
│   ├── kubernetes/                    # K8s manifests
│   └── docker/                        # Dockerfiles
├── security/
│   ├── semgrep/
│   │   ├── custom-rules/              # Organization-specific rules
│   │   └── policies/                  # Policy definitions
│   ├── nuclei-templates/              # Custom DAST templates
│   └── compliance/
│       ├── owasp-asvs-mapping.yml     # ASVS control mapping
│       └── nist-800-53-mapping.yml    # NIST control mapping
├── scripts/
│   ├── vulnerability-triage.py        # Auto-triage script
│   ├── defectdojo-import.py          # DefectDojo integration
│   └── metrics-export.py             # Metrics collection
├── docs/
│   ├── threat-model.md               # Application threat model
│   ├── security-requirements.md      # Security requirements
│   └── runbooks/                     # Incident response runbooks
├── tests/
│   └── security/                     # Security test cases
├── .pre-commit-config.yaml           # Pre-commit hooks
├── .gitleaks.toml                    # Gitleaks configuration
├── .hadolint.yaml                    # Hadolint configuration
├── trivy.yaml                        # Trivy configuration
├── Makefile                          # Build automation
└── docker-compose.yml                # Local development
```

---

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for security-focused contribution guidelines.

---

## 👤 Author

**Sunanda Mandal**  
Cybersecurity Professional | GRC | Cloud Security | DevSecOps

- LinkedIn: [linkedin.com/in/sunanda-mandal](https://www.linkedin.com/in/sunanda-mandal/)
- Email: sunandamandal28@gmail.com

---

## 📄 License

MIT License - See [LICENSE](LICENSE) for details.
