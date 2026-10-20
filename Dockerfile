# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>

# ---------- Stage 1: build the frontend ----------
# Static assets only, so it runs natively on the build host even when the image
# is built for another architecture.
FROM --platform=$BUILDPLATFORM node:22-slim AS frontend

WORKDIR /build/frontend

COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

COPY frontend/ ./
RUN npm run build

# ---------- Stage 2: runtime ----------
FROM python:3.12-slim AS runtime

LABEL org.opencontainers.image.title="Vulnyard" \
      org.opencontainers.image.description="Centrální skenování GitLab repozitářů přes Trivy a Dependency-Track" \
      org.opencontainers.image.url="https://vulnyard.eu" \
      org.opencontainers.image.authors="Lukáš Zuzaňák <lukas@zuzanak.eu>" \
      org.opencontainers.image.licenses="Apache-2.0"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PORT=8000

RUN apt-get update \
    && apt-get install --yes --no-install-recommends git ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Trivy: pinned version with a verified SHA256 checksum (same script as nixpacks).
COPY scripts/install-trivy.sh scripts/install-trivy.sh
RUN bash scripts/install-trivy.sh /usr/local/bin

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ app/
COPY alembic/ alembic/
COPY alembic.ini ./
COPY LICENSE NOTICE ./
COPY --from=frontend /build/frontend/dist frontend/dist

# Run as an unprivileged user.
RUN useradd --create-home --uid 10001 vulnyard \
    && chown -R vulnyard:vulnyard /app
USER vulnyard

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl --fail --silent --show-error "http://127.0.0.1:${PORT:-8000}/health" || exit 1

CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
