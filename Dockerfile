# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# Build stage: resolve and install Python dependencies.
# Debian 12 base matches the runtime image (same glibc), so compiled wheels
# such as bcrypt and pydantic-core work unchanged in the final stage.
# ---------------------------------------------------------------------------
FROM python:3.11-slim-bookworm@sha256:f06d01d4ba3f8ad5af45a3ec87df19c1d317d8e8961edc0fabda61811af6f7cf AS build

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build
COPY requirements.txt .
# --only-binary avoids running arbitrary setup.py code from sdists at build time
RUN pip install --only-binary=:all: --target /deps -r requirements.txt \
 && mkdir -p /data

# ---------------------------------------------------------------------------
# Runtime stage: distroless Python 3.11 (no shell, no package manager),
# running as the built-in non-root user (uid/gid 65532).
# ---------------------------------------------------------------------------
FROM gcr.io/distroless/python3-debian12:nonroot@sha256:7d1042ce588ab97019fe95c24ffca7bc5a82ccdac572511d5e09bda4435c89c5

LABEL org.opencontainers.image.title="vulntracker-api" \
      org.opencontainers.image.source="https://github.com/cloudtriquetra/asa-assignment"

ENV PYTHONPATH=/deps \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATABASE_URL=sqlite:////data/vulntracker.db

COPY --from=build --chown=root:root /deps /deps
COPY --chown=root:root app/ /app/
# Only the SQLite data directory is writable by the app user
COPY --from=build --chown=65532:65532 /data /data

WORKDIR /app
USER 65532:65532
EXPOSE 8000

# No curl/wget in distroless, so the probe uses the bundled interpreter
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["python3", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3).status == 200 else 1)"]

ENTRYPOINT ["python3", "-m", "uvicorn", "main:app"]
CMD ["--host", "0.0.0.0", "--port", "8000", "--no-server-header"]
