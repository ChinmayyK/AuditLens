# ── AuditLens PR Review Service ────────────────────
# Slim Dockerfile — SAST scanners only (no DAST tools).
# For the full platform image, use docker/Dockerfile.api.

FROM python:3.11-slim

WORKDIR /app

ARG TARGETARCH

# ── System dependencies ───────────────────────────
RUN apt-get update && apt-get install -y \
    git curl gcc libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# ── Gitleaks ──────────────────────────────────────
RUN GITLEAKS_ARCH="${TARGETARCH:-$(uname -m)}" \
    && case "$GITLEAKS_ARCH" in x86_64|amd64) GITLEAKS_ARCH="x64" ;; aarch64|arm64) GITLEAKS_ARCH="arm64" ;; esac \
    && curl -fsSL -o gitleaks.tar.gz "https://github.com/gitleaks/gitleaks/releases/download/v8.18.4/gitleaks_8.18.4_linux_${GITLEAKS_ARCH}.tar.gz" \
    && tar -xzf gitleaks.tar.gz \
    && mv gitleaks /usr/local/bin/ \
    && rm gitleaks.tar.gz

# ── Trivy ─────────────────────────────────────────
RUN TRIVY_ARCH="${TARGETARCH:-$(uname -m)}" \
    && case "$TRIVY_ARCH" in x86_64|amd64) TRIVY_FILE="trivy_0.69.3_Linux-64bit.tar.gz" ;; aarch64|arm64) TRIVY_FILE="trivy_0.69.3_Linux-ARM64.tar.gz" ;; *) TRIVY_FILE="trivy_0.69.3_Linux-64bit.tar.gz" ;; esac \
    && curl -fsSL -o trivy.tar.gz "https://github.com/aquasecurity/trivy/releases/download/v0.69.3/${TRIVY_FILE}" \
    && tar -xzf trivy.tar.gz \
    && mv trivy /usr/local/bin/ \
    && rm trivy.tar.gz

# ── Python dependencies ──────────────────────────
# Semgrep and Bandit are installed via pip
COPY api/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── Application code ─────────────────────────────
COPY api/ .

# ── Runtime directories ──────────────────────────
RUN mkdir -p /tmp/shieldsentinel/uploads \
             /tmp/shieldsentinel/reports \
             /tmp/shieldsentinel/ide

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
