# Enterprise DevSecOps Pipeline - Makefile
# Author: Sunanda Mandal

.PHONY: help install security-scan sast sca secrets container iac dast clean

SHELL := /bin/bash
RESULTS_DIR := security-results
APP_DIR := app

# Colors for output
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[0;33m
BLUE := \033[0;34m
NC := \033[0m # No Color

# Default target
help:
	@echo "╔══════════════════════════════════════════════════════════════╗"
	@echo "║          Enterprise DevSecOps Pipeline - Commands            ║"
	@echo "╠══════════════════════════════════════════════════════════════╣"
	@echo "║  make install        - Install all security tools            ║"
	@echo "║  make security-scan  - Run ALL security scans                ║"
	@echo "║  make sast           - Run SAST (Semgrep + Bandit)           ║"
	@echo "║  make sca            - Run dependency scanning               ║"
	@echo "║  make secrets        - Run secret detection                  ║"
	@echo "║  make container      - Run container security scans          ║"
	@echo "║  make iac            - Run IaC security scans                ║"
	@echo "║  make dast-local     - Run DAST against local app            ║"
	@echo "║  make compliance     - Run compliance validation             ║"
	@echo "║  make report         - Generate aggregated report            ║"
	@echo "║  make pre-commit     - Install pre-commit hooks              ║"
	@echo "║  make clean          - Clean scan results                    ║"
	@echo "╚══════════════════════════════════════════════════════════════╝"

# ============================================================================
# SETUP & INSTALLATION
# ============================================================================

install: install-python install-system
	@echo "$(GREEN)✅ All security tools installed$(NC)"

install-python:
	@echo "$(BLUE)📦 Installing Python security tools...$(NC)"
	pip install --upgrade pip
	pip install semgrep bandit safety pip-audit cyclonedx-bom pyyaml requests
	pip install bandit-sarif-formatter

install-system:
	@echo "$(BLUE)📦 Installing system security tools...$(NC)"
	@if command -v brew &> /dev/null; then \
		brew install gitleaks trivy hadolint checkov tfsec; \
	elif command -v apt-get &> /dev/null; then \
		sudo apt-get update && sudo apt-get install -y gitleaks trivy hadolint; \
		pip install checkov; \
	else \
		echo "$(YELLOW)⚠️  Please install gitleaks, trivy, hadolint, checkov manually$(NC)"; \
	fi

pre-commit:
	@echo "$(BLUE)🪝 Setting up pre-commit hooks...$(NC)"
	pip install pre-commit
	pre-commit install
	@echo "$(GREEN)✅ Pre-commit hooks installed$(NC)"

# ============================================================================
# DIRECTORY SETUP
# ============================================================================

$(RESULTS_DIR):
	@mkdir -p $(RESULTS_DIR)

# ============================================================================
# FULL SECURITY SCAN
# ============================================================================

security-scan: $(RESULTS_DIR) sast sca secrets container iac report
	@echo ""
	@echo "$(GREEN)╔══════════════════════════════════════════════════════════════╗$(NC)"
	@echo "$(GREEN)║              SECURITY SCAN COMPLETE                          ║$(NC)"
	@echo "$(GREEN)╚══════════════════════════════════════════════════════════════╝$(NC)"
	@echo ""
	@echo "Results saved to: $(RESULTS_DIR)/"

# ============================================================================
# SAST - STATIC APPLICATION SECURITY TESTING
# ============================================================================

sast: sast-semgrep sast-bandit
	@echo "$(GREEN)✅ SAST scans complete$(NC)"

sast-semgrep: $(RESULTS_DIR)
	@echo ""
	@echo "$(BLUE)🔍 Running Semgrep SAST scan...$(NC)"
	@semgrep scan \
		--config=p/security-audit \
		--config=p/owasp-top-ten \
		--config=p/python \
		--config=p/secrets \
		--config=./security/semgrep/custom-rules/ \
		--json \
		--output=$(RESULTS_DIR)/semgrep-results.json \
		--sarif \
		--sarif-output=$(RESULTS_DIR)/semgrep-results.sarif \
		$(APP_DIR)/ 2>/dev/null || true
	@echo "$(GREEN)   ✓ Semgrep results: $(RESULTS_DIR)/semgrep-results.json$(NC)"

sast-bandit: $(RESULTS_DIR)
	@echo ""
	@echo "$(BLUE)🔍 Running Bandit Python security scan...$(NC)"
	@bandit -r $(APP_DIR)/ \
		-f json \
		-o $(RESULTS_DIR)/bandit-results.json \
		--severity-level medium \
		--confidence-level medium \
		2>/dev/null || true
	@echo "$(GREEN)   ✓ Bandit results: $(RESULTS_DIR)/bandit-results.json$(NC)"

# ============================================================================
# SCA - SOFTWARE COMPOSITION ANALYSIS
# ============================================================================

sca: sca-safety sca-pip-audit sca-sbom
	@echo "$(GREEN)✅ SCA scans complete$(NC)"

sca-safety: $(RESULTS_DIR)
	@echo ""
	@echo "$(BLUE)📦 Running Safety dependency scan...$(NC)"
	@safety check \
		--full-report \
		--json \
		--output $(RESULTS_DIR)/safety-results.json \
		-r requirements.txt 2>/dev/null || true
	@echo "$(GREEN)   ✓ Safety results: $(RESULTS_DIR)/safety-results.json$(NC)"

sca-pip-audit: $(RESULTS_DIR)
	@echo ""
	@echo "$(BLUE)📦 Running pip-audit scan...$(NC)"
	@pip-audit \
		--format json \
		--output $(RESULTS_DIR)/pip-audit-results.json \
		-r requirements.txt 2>/dev/null || true
	@echo "$(GREEN)   ✓ pip-audit results: $(RESULTS_DIR)/pip-audit-results.json$(NC)"

sca-sbom: $(RESULTS_DIR)
	@echo ""
	@echo "$(BLUE)📋 Generating SBOM (CycloneDX)...$(NC)"
	@cyclonedx-py requirements \
		--input-file requirements.txt \
		--output-format json \
		--output-file $(RESULTS_DIR)/sbom.json 2>/dev/null || true
	@echo "$(GREEN)   ✓ SBOM generated: $(RESULTS_DIR)/sbom.json$(NC)"

# ============================================================================
# SECRET DETECTION
# ============================================================================

secrets: secrets-gitleaks
	@echo "$(GREEN)✅ Secret detection complete$(NC)"

secrets-gitleaks: $(RESULTS_DIR)
	@echo ""
	@echo "$(BLUE)🔑 Running Gitleaks secret detection...$(NC)"
	@gitleaks detect \
		--source . \
		--report-format json \
		--report-path $(RESULTS_DIR)/gitleaks-results.json \
		--config .gitleaks.toml \
		2>/dev/null || true
	@echo "$(GREEN)   ✓ Gitleaks results: $(RESULTS_DIR)/gitleaks-results.json$(NC)"

# ============================================================================
# CONTAINER SECURITY
# ============================================================================

container: container-hadolint container-trivy
	@echo "$(GREEN)✅ Container security scans complete$(NC)"

container-hadolint: $(RESULTS_DIR)
	@echo ""
	@echo "$(BLUE)🐳 Running Hadolint Dockerfile scan...$(NC)"
	@if [ -f infrastructure/docker/Dockerfile ]; then \
		hadolint infrastructure/docker/Dockerfile \
			--format json \
			> $(RESULTS_DIR)/hadolint-results.json 2>/dev/null || true; \
		echo "$(GREEN)   ✓ Hadolint results: $(RESULTS_DIR)/hadolint-results.json$(NC)"; \
	else \
		echo "$(YELLOW)   ⚠ No Dockerfile found$(NC)"; \
	fi

container-trivy: $(RESULTS_DIR)
	@echo ""
	@echo "$(BLUE)🐳 Running Trivy filesystem scan...$(NC)"
	@trivy fs \
		--format json \
		--output $(RESULTS_DIR)/trivy-fs-results.json \
		--severity CRITICAL,HIGH,MEDIUM \
		. 2>/dev/null || true
	@echo "$(GREEN)   ✓ Trivy results: $(RESULTS_DIR)/trivy-fs-results.json$(NC)"

container-image: $(RESULTS_DIR)
	@echo ""
	@echo "$(BLUE)🐳 Building and scanning container image...$(NC)"
	@docker build -t app:scan -f infrastructure/docker/Dockerfile . 2>/dev/null
	@trivy image \
		--format json \
		--output $(RESULTS_DIR)/trivy-image-results.json \
		--severity CRITICAL,HIGH,MEDIUM \
		app:scan 2>/dev/null || true
	@echo "$(GREEN)   ✓ Trivy image results: $(RESULTS_DIR)/trivy-image-results.json$(NC)"

# ============================================================================
# INFRASTRUCTURE AS CODE (IaC) SECURITY
# ============================================================================

iac: iac-checkov iac-tfsec
	@echo "$(GREEN)✅ IaC security scans complete$(NC)"

iac-checkov: $(RESULTS_DIR)
	@echo ""
	@echo "$(BLUE)🏗️  Running Checkov IaC scan...$(NC)"
	@if [ -d infrastructure/ ]; then \
		checkov \
			-d infrastructure/ \
			--output-file-path $(RESULTS_DIR) \
			--output json \
			--soft-fail \
			2>/dev/null || true; \
		echo "$(GREEN)   ✓ Checkov results: $(RESULTS_DIR)/$(NC)"; \
	else \
		echo "$(YELLOW)   ⚠ No infrastructure/ directory found$(NC)"; \
	fi

iac-tfsec: $(RESULTS_DIR)
	@echo ""
	@echo "$(BLUE)🏗️  Running tfsec Terraform scan...$(NC)"
	@if [ -d infrastructure/terraform/ ]; then \
		tfsec infrastructure/terraform/ \
			--format json \
			--out $(RESULTS_DIR)/tfsec-results.json \
			2>/dev/null || true; \
		echo "$(GREEN)   ✓ tfsec results: $(RESULTS_DIR)/tfsec-results.json$(NC)"; \
	else \
		echo "$(YELLOW)   ⚠ No Terraform files found$(NC)"; \
	fi

# ============================================================================
# DAST - DYNAMIC APPLICATION SECURITY TESTING
# ============================================================================

dast-local: $(RESULTS_DIR)
	@echo ""
	@echo "$(BLUE)🌐 Running OWASP ZAP baseline scan...$(NC)"
	@echo "$(YELLOW)   ⚠ Ensure application is running on http://localhost:8080$(NC)"
	@docker run --rm -v $(PWD)/$(RESULTS_DIR):/zap/wrk:rw \
		-t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py \
		-t http://host.docker.internal:8080 \
		-J zap-results.json \
		-r zap-report.html \
		2>/dev/null || true
	@echo "$(GREEN)   ✓ ZAP results: $(RESULTS_DIR)/zap-results.json$(NC)"

# ============================================================================
# COMPLIANCE VALIDATION
# ============================================================================

compliance: $(RESULTS_DIR)
	@echo ""
	@echo "$(BLUE)📋 Running compliance validation...$(NC)"
	@python scripts/compliance-check.py \
		--framework owasp-asvs \
		--mapping security/compliance/owasp-asvs-mapping.yml \
		--output $(RESULTS_DIR)/compliance-asvs-report.json \
		2>/dev/null || true
	@echo "$(GREEN)   ✓ Compliance report: $(RESULTS_DIR)/compliance-asvs-report.json$(NC)"

# ============================================================================
# REPORTING & AGGREGATION
# ============================================================================

report: $(RESULTS_DIR)
	@echo ""
	@echo "$(BLUE)📊 Generating aggregated security report...$(NC)"
	@python scripts/vulnerability-triage.py \
		--input-dir $(RESULTS_DIR)/ \
		--output $(RESULTS_DIR)/aggregated-findings.json \
		--sla-config security/sla-policy.yml \
		2>/dev/null || true
	@echo "$(GREEN)   ✓ Aggregated report: $(RESULTS_DIR)/aggregated-findings.json$(NC)"

# ============================================================================
# QUICK SCANS (for development)
# ============================================================================

quick: $(RESULTS_DIR)
	@echo "$(BLUE)⚡ Running quick security scan (SAST + Secrets only)...$(NC)"
	@$(MAKE) sast-semgrep secrets-gitleaks
	@echo "$(GREEN)✅ Quick scan complete$(NC)"

# ============================================================================
# CI/CD GATE CHECK
# ============================================================================

gate-check: $(RESULTS_DIR)
	@echo ""
	@echo "$(BLUE)🚦 Running security gate check...$(NC)"
	@python scripts/security-gate.py \
		--findings $(RESULTS_DIR)/aggregated-findings.json \
		--policy security/gate-policy.yml

# ============================================================================
# CLEANUP
# ============================================================================

clean:
	@echo "$(BLUE)🧹 Cleaning scan results...$(NC)"
	@rm -rf $(RESULTS_DIR)
	@rm -f *.sarif *.json
	@echo "$(GREEN)✅ Cleanup complete$(NC)"

# ============================================================================
# DEVELOPMENT HELPERS
# ============================================================================

run:
	@echo "$(BLUE)🚀 Starting application...$(NC)"
	@python -m flask run --host=0.0.0.0 --port=8080

docker-run:
	@echo "$(BLUE)🐳 Starting application in Docker...$(NC)"
	@docker-compose up --build

test:
	@echo "$(BLUE)🧪 Running security tests...$(NC)"
	@pytest tests/security/ -v

lint:
	@echo "$(BLUE)🔍 Running linters...$(NC)"
	@flake8 $(APP_DIR)/
	@black --check $(APP_DIR)/
