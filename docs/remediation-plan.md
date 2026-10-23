# Remediation Plan

Finding IDs refer to [findings.md](findings.md).

## 1. What was fixed (Task 3)

Each fix is a separate commit with a test that fails on the old code.

| Finding | Severity | Fix | Commit message (search `git log`) | Proof |
|---|---|---|---|---|
| F-01, F-07, F-10 (code) | Critical / High | JWT key read from `SECRET_KEY_FILE` (mounted secret) or `SECRET_KEY`; app **refuses to start** without a 32+ char key; algorithm pinned to HS256; `exp` and `sub` required; python-jose replaced by PyJWT; unused hard-coded `DB_PASSWORD`/`ADMIN_API_KEY` deleted | *Fix token forgery...* | Old-key forged token and `alg:none` token both get `401` from the container; tests `test_token_signed_with_old_hardcoded_key_rejected`, `test_unsigned_alg_none_token_rejected` |
| F-02, F-03 | Critical / High | Search rewritten as ORM query with bound parameters, **scoped to the caller**, LIKE wildcards escaped, input ≤ 200 chars, ≤ 100 rows | *Fix SQL injection and cross-user...* | UNION payload returns `{"count":0}`; `test_search_sql_injection_payload_is_inert`, `test_search_only_returns_own_scans` |
| F-04 | High | `GET /scans/{id}` filters on `owner_id`; 404 otherwise | *Fix IDOR...* | `test_get_scan_of_another_user_returns_404` |
| F-05, F-13 | High / Medium | Passwords never logged (username only, `%r` against log injection); 500 responses return only an `error_id`, details logged server-side | *Stop logging passwords...* | `test_login_never_logs_password`, `test_unhandled_error_does_not_leak_internals`; container logs contain 0 passwords |
| **F-06 (my Task 1 code)** | High | Logging filter masks `/share/<token>` and `?password=` in uvicorn access/error logs and app logs; link password also accepted via `X-Share-Password` header (not stored in browser history/proxy logs) | *Redact share-link tokens...* | Live log line: `GET /share/[REDACTED]?password=[REDACTED]`; `test_access_log_redacts_share_token_and_password` |
| F-08, F-11 | High | Python: 67 advisories → 0 (fastapi/starlette upgraded, passlib→bcrypt, python-multipart and cryptography removed as unused, pytest moved to dev requirements). Node: 1 critical + 5 high → 0 (axios 1.20.0, express 4.22.3, uuid 11.1.1, transitive fixes). All versions ≥ 2 weeks old. | *Upgrade vulnerable dependencies...* | `reports/post-remediation/sca.*.json` |
| F-14, F-16, F-20 | Medium / Low | CORS allow-list without credentials; password ≥ 8 chars and ≤ 72 bytes; page size ≤ 100; `nosniff` / `X-Frame-Options` headers | *Harden CORS...* | tests in "Hardening" section |
| F-12, F-25, notify `SERVICE_KEY` | High / Low | Base image switched to patched, digest-pinned `python:3.11-slim-trixie` (0 critical, 0 fixable); pip/setuptools removed from runtime; Helm namespace + digest-only images; notify key from env | *Harden container base image...* | `reports/post-remediation/container.trivy.json`, `iac.checkov.json` (96 passed, 0 failed) |

## 2. What was not fixed, and why

### R1: Secrets in git history (F-10): **must be done before any real deployment**

* **Residual risk:** The old JWT key, `DB_PASSWORD`, `ADMIN_API_KEY` and notify `SERVICE_KEY` are in the commit history of this repository and every clone or fork. If any of them is (or was) used in a real environment, that environment is compromised. The code no longer accepts the old JWT key, but other systems might.
* **Why not done here:** Rotation needs access to the systems that use those credentials (not available in the take-home). Rewriting history (`git filter-repo`) breaks every existing clone and, for this assignment, would hide the starting point from reviewers. History rewrite also does **not** un-leak a secret, so rotation is the real fix.
* **Effort:** Rotation ≈ 1-2 hours per credential once owners are identified. Optional history purge ≈ 1 hour + coordinating re-clones.
* **Compensating controls now:** New JWT key is generated per environment and stored only in AWS Secrets Manager; app fails closed without it; gitleaks runs in CI to stop new secrets landing.

### R2: Notify service has no authentication; SSRF via webhook URLs (F-09, F-19, F-24)

* **Residual risk:** Anyone who can reach the notify service on the network can subscribe to a live feed of new vulnerabilities, inject fake events, and make the service call internal addresses (cloud metadata, internal admin APIs).
* **Why not done here:** The brief scopes notify as "no changes required" and the time box was spent on the API. A correct fix is a small redesign, not a one-liner, and doing it half-way would give false assurance. I did fix its vulnerable dependencies and moved its hard-coded key to an environment variable, since both were near-zero risk to change.
* **Effort:** ≈ 2 days:
  1. Require a shared secret / mTLS on `/notify` (only the API may call it), and admin auth on `/webhooks`.
  2. Validate webhook URLs: HTTPS only, resolve DNS and **block private, loopback and link-local ranges** (re-check after DNS resolution to stop rebinding), disable redirects (`maxRedirects: 0`).
  3. Sign outgoing payloads with HMAC instead of sending the raw service key to third parties.
  4. Persist the registry (currently in memory) and audit-log registrations; strip owner usernames from payloads.
  5. Generic error responses.
* **Compensating controls now:** The service is intended for internal use only. The Helm chart's NetworkPolicy for the API allows egress only to DNS and notify. A matching policy for notify (ingress only from API pods, egress only to an allow-listed webhook proxy) should be applied when notify is deployed.

### R3: Login brute-force protection (F-15)

* **Residual risk:** Unlimited password guessing against `/auth/login`.
* **Why not done here:** Correct rate limiting needs shared state (e.g. Redis) to work across replicas and restarts; an in-process counter would be bypassed on restart and gives false confidence.
* **Effort:** ≈ 0.5-1 day (per-IP + per-account limits, exponential back-off, alerting on spikes).
* **Compensating controls now:** NGINX ingress `limit-rps: 10` / `limit-connections: 20` per client IP (in `helm/vulntracker/values.yaml`); bcrypt makes each guess slow; new 8-character minimum password; share links have their own 5-attempt lockout.

### R4: SQLite → managed database (F-17)

* **Residual risk:** No encryption at rest by default, single replica (no high availability), backups depend on the volume.
* **Why not done here:** Out of scope for a 4-6 hour prototype; requires migrations (Alembic) and a DB credential flow.
* **Effort:** ≈ 2-3 days (managed PostgreSQL with IAM auth or a secrets-manager credential, TLS, Alembic migrations, backups).
* **Compensating controls now:** Chart runs one replica with `Recreate` strategy (no concurrent writers), volume via an encrypted StorageClass (cluster setting), DB file not in the image, container user can only write `/data`.

### R5: Container OS vulnerabilities without an upstream fix (F-18)

* **Residual risk:** 44 HIGH / 58 MEDIUM in Debian 13 packages (e.g. libuuid, sqlite, ncurses) where Debian has not released a fix.
* **Why not done here:** No patched version exists. Alternatives were evaluated: the distroless image was *worse* (44 fixable HIGH). A Chainguard/Wolfi image would reduce the count but needs a paid tier for pinned Python 3.11.
* **Effort:** Ongoing: Renovate/Dependabot bumps of the base-image digest (≈ 15 min/week).
* **Compensating controls now:** CI fails on any *fixable* CRITICAL; runtime is non-root (uid 65532), read-only root filesystem, all capabilities dropped, `allowPrivilegeEscalation: false`, seccomp `RuntimeDefault`, no pip/setuptools, and NetworkPolicy limits what a compromised pod could reach.

### R6: Low-severity items (F-21, F-23, JWT revocation)

| Item | Residual risk | Effort | Note |
|---|---|---|---|
| User enumeration / no email validation | Attackers can confirm usernames | 2-4 h | Generic register response, constant-time dummy bcrypt for unknown users, `EmailStr` |
| Public `/docs` and `/openapi.json` | Recon aid | 30 min | Disable via env in production, or protect behind auth |
| JWTs cannot be revoked before 30-min expiry | Stolen token valid ≤ 30 min | 1 day | Short expiry already; add refresh tokens + deny-list for logout |
| Share link can be locked by holder (F-22) | Nuisance | n/a | Accepted design trade-off: owner re-issues link |

## 3. Process / pipeline gaps

* **CI not yet observed green on GitHub:** each job's commands were dry-run locally (Docker), but a first push is the real test.
* Pin scanner container images by digest (currently by exact version tag).
* Add **DAST** (OWASP ZAP baseline against the container in CI) and an **SBOM + image signing** step (Syft + cosign) with signature verification at admission.
* Enable Dependabot/Renovate for pip, npm, GitHub Actions and the base-image digest.
* Notify service is not yet in the Helm chart (only the API is deployed).
