import os


def _read_secret(name: str) -> str:
    """Read a secret from the file named by <NAME>_FILE, falling back to <NAME>.

    In Kubernetes the secret is mounted as a file by the Secrets Store CSI
    driver (see helm/), so it never appears in the pod spec or environment.
    The plain environment variable is a convenience for local development.
    """
    path = os.getenv(f"{name}_FILE")
    if path:
        with open(path, encoding="utf-8") as fh:
            return fh.read().strip()
    return os.getenv(name, "")


DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./vulntracker.db")

SECRET_KEY = _read_secret("SECRET_KEY")
if len(SECRET_KEY) < 32:
    # Fail closed: never fall back to a default signing key
    raise RuntimeError("SECRET_KEY or SECRET_KEY_FILE must provide a key of at least 32 characters")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

NOTIFY_SERVICE_URL = os.getenv("NOTIFY_SERVICE_URL", "http://localhost:3001")

# Shared report links. share_url is built from this configured base URL rather
# than the request Host header, which is attacker-controlled.
SHARE_BASE_URL = os.getenv("SHARE_BASE_URL", "http://localhost:8000").rstrip("/")
SHARE_LINK_TTL_HOURS = 24
SHARE_LINK_MAX_PASSWORD_ATTEMPTS = 5
