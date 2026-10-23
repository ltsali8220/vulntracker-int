# syntax=docker/dockerfile:1

# Base image choice: the distroless Python 3.11 image was tried first, but a
# Trivy scan showed it ships Debian's Python 3.11.2 and OS libraries with 44
# HIGH vulnerabilities that already have fixes. The official slim image is
# rebuilt with current patches (0 CRITICAL, 2 fixable HIGH at time of writing),
# so it is the smaller real risk. It is pinned by digest for reproducibility;
# bump the digest regularly (e.g. via Dependabot/Renovate).
ARG BASE_IMAGE=python:3.11-slim-trixie@sha256:b7a9e5f6a93d6d4a31f129bbd4bdee69efccb6ded0fb230d78aafaf37af98377

# ---------------------------------------------------------------------------
# Build stage: install dependencies into an isolated virtualenv
# ---------------------------------------------------------------------------
FROM ${BASE_IMAGE} AS build

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

COPY requirements.txt /tmp/requirements.txt
# --only-binary avoids running arbitrary setup.py code from sdists at build time
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --only-binary=:all: -r /tmp/requirements.txt \
 && /opt/venv/bin/pip uninstall -y pip setuptools

# ---------------------------------------------------------------------------
# Runtime stage
# ---------------------------------------------------------------------------
FROM ${BASE_IMAGE}

LABEL org.opencontainers.image.title="vulntracker-api" \
      org.opencontainers.image.description="VulnTracker FastAPI service"

# Apply any OS security updates published since the base image was built,
# remove package-install tooling the app does not need, and create a
# dedicated unprivileged user (uid matches the Helm securityContext).
RUN apt-get update \
 && apt-get upgrade -y --no-install-recommends \
 && rm -rf /var/lib/apt/lists/* \
 && rm -rf /usr/local/lib/python3.11/site-packages/pip* \
           /usr/local/lib/python3.11/site-packages/setuptools* \
           /usr/local/lib/python3.11/site-packages/wheel* \
           /usr/local/bin/pip* \
 && groupadd --system --gid 65532 app \
 && useradd --system --uid 65532 --gid app --no-create-home --shell /usr/sbin/nologin app \
 && mkdir -p /data \
 && chown app:app /data

ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATABASE_URL=sqlite:////data/vulntracker.db

# Code and dependencies are owned by root and read-only for the app user;
# only /data (SQLite) is writable. No secrets are copied: SECRET_KEY or
# SECRET_KEY_FILE must be supplied at runtime, or the app refuses to start.
COPY --from=build /opt/venv /opt/venv
COPY app/ /app/

WORKDIR /app
USER 65532:65532
EXPOSE 8000

# No curl/wget in the image, so the probe uses the bundled interpreter
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3).status == 200 else 1)"]

ENTRYPOINT ["python", "-m", "uvicorn", "main:app"]
CMD ["--host", "0.0.0.0", "--port", "8000", "--no-server-header"]
