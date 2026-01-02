# Enterprise Application Dockerfile
# Following security best practices for container security
#
# Author: Sunanda Mandal

# =============================================================================
# STAGE 1: Build Stage
# =============================================================================
FROM python:3.14-slim-bookworm AS builder

# Set build-time environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --upgrade pip && \
    pip install -r requirements.txt

# =============================================================================
# STAGE 2: Production Stage
# =============================================================================
FROM python:3.14-slim-bookworm AS production

# Labels for image metadata
LABEL maintainer="security@company.com" \
      version="1.0.0" \
      description="Enterprise Application with security hardening" \
      org.opencontainers.image.source="https://github.com/company/app"

# Security: Create non-root user
RUN groupadd --gid 1000 appgroup && \
    useradd --uid 1000 --gid appgroup --shell /bin/bash --create-home appuser

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1 \
    PATH="/opt/venv/bin:$PATH" \
    # Application settings
    APP_HOME=/app \
    PORT=8080 \
    ENV=production

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Required for healthcheck
    curl \
    # Security: Install security updates
    && apt-get upgrade -y \
    # Cleanup
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /tmp/* \
    && rm -rf /var/tmp/*

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv

# Create application directory
WORKDIR ${APP_HOME}

# Copy application code
COPY --chown=appuser:appgroup app/ ./app/
COPY --chown=appuser:appgroup requirements.txt .

# Security: Set restrictive permissions
RUN chmod -R 550 ${APP_HOME}/app && \
    chmod 440 ${APP_HOME}/requirements.txt

# Security: Create directory for runtime files with proper permissions
RUN mkdir -p /var/log/app && \
    chown appuser:appgroup /var/log/app && \
    chmod 750 /var/log/app

# Security: Remove unnecessary setuid/setgid binaries
RUN find / -perm /6000 -type f -exec chmod a-s {} \; 2>/dev/null || true

# Security: Switch to non-root user
USER appuser

# Expose port (non-privileged port)
EXPOSE ${PORT}

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:${PORT}/health || exit 1

# Security: Read-only root filesystem compatible entrypoint
# Application should write only to /tmp and /var/log/app
ENTRYPOINT ["python", "-m", "gunicorn"]

# Default command with security settings
CMD ["--bind", "0.0.0.0:8080", \
     "--workers", "4", \
     "--threads", "2", \
     "--worker-class", "gthread", \
     "--worker-tmp-dir", "/dev/shm", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "--capture-output", \
     "--enable-stdio-inheritance", \
     "--timeout", "120", \
     "--keep-alive", "5", \
     "--max-requests", "1000", \
     "--max-requests-jitter", "50", \
     "app.main:app"]
