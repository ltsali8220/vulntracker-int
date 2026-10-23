# VulnTracker: Security Automation Take-Home (Solution)

VulnTracker is a two-service system for tracking vulnerability scan results:
a Python/FastAPI API (`app/`) and a Node.js webhook notification service (`notify/`).
The original assignment brief is in [`docs/ASSIGNMENT.md`](docs/ASSIGNMENT.md).

| Deliverable | Where |
|---|---|
| Task 1: Shared Report Link feature | `app/main.py` (`/scans/{id}/share`, `/share/{token}`), `app/models.py` (`ShareLink`), tests in `tests/test_api.py` |
| Task 2: Scan reports | [`reports/`](reports/) (baseline) and [`reports/post-remediation/`](reports/post-remediation/) |
| Task 2: Prioritised findings | [`docs/findings.md`](docs/findings.md) |
| Task 3: Fixes | one commit per fix (see `git log`), [`docs/remediation-plan.md`](docs/remediation-plan.md) |
| Task 4: Container + deployment | [`Dockerfile`](Dockerfile), [`helm/vulntracker/`](helm/vulntracker/) |
| Task 5: Executive summary | [`docs/executive-summary.md`](docs/executive-summary.md) |
| CI security gates | [`.github/workflows/ci.yml`](.github/workflows/ci.yml) |

---

## Running locally

**Requirements:** Python 3.11 (exactly, matching CI), Node.js 20+, Docker.

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
```

The API **refuses to start without a signing key** (there is deliberately no default). Generate one per environment:

```bash
export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
cd app
uvicorn main:app --reload
```

API at `http://localhost:8000`, docs at `http://localhost:8000/docs`.

Tests (from the repo root): `pytest tests/ -v`

Notification service: `cd notify && npm ci && npm start` (port 3001). Tests: `npm test` (stop the service first; the tests use the same port).

### Configuration

| Variable | Purpose | Default |
|---|---|---|
| `SECRET_KEY_FILE` | Path to a file containing the JWT signing key (used in Kubernetes) | none |
| `SECRET_KEY` | JWT signing key (local development only); ≥ 32 characters | none (**required** if no file) |
| `DATABASE_URL` | SQLAlchemy URL | `sqlite:///./vulntracker.db` (`sqlite:////data/vulntracker.db` in the image) |
| `SHARE_BASE_URL` | Base used to build share links | `http://localhost:8000` |
| `CORS_ALLOWED_ORIGINS` | Comma-separated browser origins | none (no cross-origin access) |
| `NOTIFY_SERVICE_URL` | Notification service URL | `http://localhost:3001` |
| `NOTIFY_SERVICE_KEY` | (notify) key sent to webhooks | empty |

---

## Docker

Build:

```bash
docker build -t vulntracker-api:latest .
```

Run (key passed as a mounted file, the same pattern as production):

```bash
mkdir -p secrets
python -c 'import secrets; print(secrets.token_urlsafe(48))' > secrets/jwt_secret_key

docker run -d --name vulntracker -p 8000:8000 \
  --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges \
  -v vulntracker-data:/data \
  -v "$PWD/secrets:/mnt/secrets:ro" \
  -e SECRET_KEY_FILE=/mnt/secrets/jwt_secret_key \
  vulntracker-api:latest

curl http://localhost:8000/health
docker inspect --format '{{.State.Health.Status}}' vulntracker   # "healthy" after ~30 s
```

For a quick local try you can pass `-e SECRET_KEY=...` instead of the file mount. `secrets/` is not committed (add it to `.gitignore` if you create it inside the repo).

Image properties: multi-stage build; digest-pinned `python:3.11-slim-trixie` base (chosen over distroless after scanning, see `docs/findings.md` F-12); OS security updates applied at build; pip/setuptools removed; runs as uid **65532**; `HEALTHCHECK` on `/health`; only `/data` is writable; no secrets in the image.

---

## Kubernetes (Helm)

Prerequisites in the cluster: an NGINX ingress controller, the [Secrets Store CSI driver](https://secrets-store-csi-driver.sigs.k8s.io/) with the AWS provider, a NetworkPolicy-enforcing CNI, and an IAM role (IRSA) allowed to read only the app's secret.

```bash
# 1. Store the key in AWS Secrets Manager (never in the chart)
aws secretsmanager create-secret --name prod/vulntracker/api \
  --secret-string "{\"jwt_secret_key\":\"$(python -c 'import secrets;print(secrets.token_urlsafe(48))')\"}"

# 2. Namespace with Pod Security "restricted"
kubectl create namespace vulntracker
kubectl label namespace vulntracker pod-security.kubernetes.io/enforce=restricted

# 3. Deploy by image digest (the chart refuses to render without one)
helm upgrade --install vulntracker helm/vulntracker -n vulntracker \
  --set image.repository=<registry>/vulntracker-api \
  --set image.digest=sha256:<digest-from-ci> \
  --set serviceAccount.roleArn=arn:aws:iam::<acct>:role/vulntracker-api-secrets-read
```

What the chart enforces:

* **Secrets from a secrets manager:** `SecretProviderClass` mounts the key from AWS Secrets Manager as a read-only file at `/mnt/secrets`. It is not in the chart, not a Kubernetes `Secret` object, and not an environment variable; the app reads it via `SECRET_KEY_FILE`.
* **Restricted network access:** `ClusterIP` service, external access only through a TLS ingress with rate limits; `NetworkPolicy` allows ingress **only from the ingress controller** on port 8000, and egress only to DNS and the notify service.
* **Resource limits and security contexts:** CPU/memory requests and limits; `runAsNonRoot`, uid 65532, `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`, all capabilities dropped, seccomp `RuntimeDefault`; service-account token not mounted; image by digest; dedicated namespace.

---

## Shared Report Link feature

```bash
# Create a link (owner only). Password optional, 8+ characters.
curl -X POST http://localhost:8000/scans/1/share \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"password": "auditor-pass-1"}'
# -> {"share_url": "http://localhost:8000/share/<token>", "expires_at": "...", "password_protected": true}

# Open it (public). Header form preferred; ?password= also accepted per the spec.
curl http://localhost:8000/share/<token> -H "X-Share-Password: auditor-pass-1"
curl "http://localhost:8000/share/<token>?password=auditor-pass-1"
```

**`share_url` decision:** links are built from the configured `SHARE_BASE_URL` (default `http://localhost:8000`), **not** from the incoming request's Host header. The Host header is client-controlled, so using it would let an attacker get the API to issue links pointing to their own domain.

Other decisions: 256-bit random tokens stored only as SHA-256 hashes; 24 h server-side expiry; bcrypt-hashed password with a 5-attempt lockout; identical 404 for unknown/expired/revoked links; public view omits `owner_id` and internal `remediation_notes` (assumption: external stakeholders should not see internal remediation notes); `no-store` / `no-referrer` headers; tokens and passwords are redacted from logs.

---

## Security scanning

| Type | Tool | Local command (examples) | CI job |
|---|---|---|---|
| SAST | Semgrep, Bandit, gitleaks | `semgrep scan --config p/python --config p/security-audit --config p/secrets app notify/src` | `sast` (fails on high/critical) |
| SCA | pip-audit, npm audit | `pip-audit -r requirements-dev.txt`; `cd notify && npm audit` | `sca` (fails on any Python vuln / Node high+) |
| Container | Trivy | `trivy image vulntracker-api:latest` | `container-scan` (fails on fixable critical) |
| IaC | Checkov | `checkov -d helm --framework helm` | `iac-scan` (fails on any failed check) |

Tool choices and how findings were prioritised are explained in [`docs/findings.md`](docs/findings.md).

## Assumptions

* Notify is internal-only; its redesign is deferred (documented in the remediation plan), but its vulnerable dependencies and hard-coded key were fixed.
* SQLite is kept for the prototype; the chart therefore runs a single replica.
* AWS (Secrets Manager + IRSA) is used as the example cloud; the chart's `secrets.provider` can be switched to Vault/Azure/GCP CSI providers.
