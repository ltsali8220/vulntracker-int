# Security Findings: VulnTracker

Scope: `app/` (FastAPI API, including the new Shared Report Link feature), `notify/` (Node webhook service), `Dockerfile` and `helm/`.
Method: four automated scan types (raw output in [`reports/`](../reports/)), manual code review, and **exploit verification against the running container**. Every Critical/High below was reproduced or confirmed by reading the code path, not taken on a tool's word.

## How severity was assessed

Severity is my judgment for **this** application, not the scanner's or CVSS label:

* **Who can reach it?** Unauthenticated internet user > any registered user > someone already inside the cluster network.
* **What does it expose?** VulnTracker stores *unpatched vulnerabilities* for the company and its customers. That data is effectively a step-by-step map for breaking into those systems, so any confidentiality failure is high impact by default. Customers and auditors receive shared links, so a leak is also a trust and contractual problem.
* **Is it exploitable today?** Verified exploits rank above theoretical ones. A dangerous pattern that is currently blocked by circumstance is rated lower than its label but still fixed.

| Severity | Meaning here |
|---|---|
| **Critical** | Remote, low-skill, leads to full account takeover or bulk data theft. Fix before any deployment. |
| **High** | Serious confidentiality/integrity loss or service outage with a realistic attacker, or a critical issue one small change away. |
| **Medium** | Requires a precondition (insider, other bug, user interaction) or limited impact. |
| **Low** | Defence in depth, hygiene, or minor information disclosure. |

## Tool selection

| Scan type | Tool(s) | Why this tool |
|---|---|---|
| SAST | **Semgrep** (`p/python`, `p/security-audit`, `p/secrets`, `p/javascript`, `p/nodejs`) | Open-source, fast, covers **both** Python and Node in one tool, readable rules, easy CI gating by severity. |
| SAST (2nd opinion) | **Bandit** | Python-specific AST checks; cheap cross-check of Semgrep. |
| Secrets | **gitleaks** | Scans the working tree **and git history**. History matters because removing a secret from code does not remove it from the repo. |
| SCA | **pip-audit** (Python), **npm audit** (Node) | pip-audit is maintained by PyPA and uses the PyPI advisory DB + OSV; it resolves the real dependency tree from `requirements.txt`, including transitive packages (starlette, anyio, ecdsa). npm audit is the native tool for the lockfile. |
| Container | **Trivy** | Scans OS packages, language packages inside the image, secrets and Dockerfile misconfiguration in one pass; reports whether a fix exists, which is what drives priority. |
| IaC | **Checkov** | Native Helm support (renders the chart, then applies ~100 Kubernetes policies); maps to CIS benchmarks. |

**Reports.** The required files (`reports/sast.semgrep.json`, `reports/sca.pip-audit.json`, `reports/container.trivy.json`, `reports/iac.checkov.json`) are the **baseline** scans of the code *before* remediation, plus the supplementary `sast.bandit.json`, `sca.npm-audit.json` and `secrets.gitleaks.json`. The same scans after remediation are in [`reports/post-remediation/`](../reports/post-remediation/).

**Observation on tooling:** the scanners found only part of the real problems. Two of the four High/Critical access-control bugs (F-03, F-04) were found by **no tool**. gitleaks found 2 of the 4 hard-coded secrets. Bandit rated the SQL injection as Medium/Low-confidence and the hard-coded JWT key as Low. Manual review and testing were essential.

## Summary

| | Critical | High | Medium | Low |
|---|---|---|---|---|
| Found | 2 | 10 | 7 | 6 |
| Fixed | 2 | 8 (+1 partly) | 3 | 2 |

## Findings

Origin: **S** = starter code, **N** = my new code (Task 1 feature, Dockerfile, Helm).

| ID | Finding | Detected by | Severity & justification | Business impact for VulnTracker | Origin | Status |
|---|---|---|---|---|---|---|
| F-01 | **Hard-coded JWT signing key** in `app/config.py` | Bandit B105 (rated *Low*), manual. *gitleaks missed it* | **Critical.** I forged a valid token for any username with the key from the source, then got `200` from the API. Anyone who has ever seen the repo (or a leaked copy) can log in as any user, no password needed. | Complete loss of confidentiality and integrity of every customer's vulnerability data; attacker can also mark findings "resolved" to hide them. | S | Fixed |
| F-02 | **SQL injection** in `GET /scans/search` (f-string into raw SQL) | Semgrep ERROR `avoid-sqlalchemy-text`, Bandit B608 (rated *Medium*), manual | **Critical.** Any registered user (self-registration is open) ran a `UNION SELECT` and dumped the `users` table, bcrypt hashes included. Low skill, remote. | Bulk theft of all users and all scans; hashes enable offline cracking; with SQLite, potential data destruction. | S | Fixed |
| F-03 | **Search ignores ownership:** returns every user's scans | Manual only | **High.** Any registered user reads all organisations' findings via a normal search, no injection needed. | Cross-customer data leak, the core confidentiality promise of the product. | S | Fixed |
| F-04 | **IDOR on `GET /scans/{id}`:** no owner check | Manual only | **High.** Iterating ids 1..N returns every scan. Update/delete were correctly scoped, so this is an inconsistency, not a design choice. | Same as F-03; trivially scriptable. | S | Fixed |
| F-05 | **Plaintext passwords in logs** (`/auth/login` logs the password on every attempt, again on failure) | Semgrep WARNING `python-logger-credential-disclosure`, manual; confirmed in `docker logs` | **High.** Everyone with log access (ops staff, log SaaS, SIEM) collects working credentials; failed attempts reveal near-miss passwords users reuse elsewhere. | Account takeover by insiders or via a log-platform breach; likely breach-notification obligations. | S | Fixed |
| F-06 | **Share token and link password written to access log** (`GET /share/<token>?password=...`) | Manual (dynamic test of my own feature) | **High.** The token *is* the credential for a public endpoint, and the brief requires the password in the query string. Log readers could open any customer-shared report. | Defeats the purpose of password protection on the feature built for external customers/auditors. | **N** | Fixed |
| F-07 | **JWT decoder accepts `alg: none`** | Semgrep ERROR `jwt-python-none-alg`, manual | **High, not Critical.** I tested it: with python-jose 3.3.0 an unsigned token causes a `500` (library cannot build a key for "none"), *not* a bypass. But this is one library upgrade or swap away from full authentication bypass, and today it still produces a 500 with internal details. | Latent total auth bypass; current impact is error noise + info leak. | S | Fixed |
| F-08 | **Vulnerable Python dependencies:** 67 known advisories in 8 packages | pip-audit, Trivy | **High.** Most relevant: python-jose CVE-2024-33663 (algorithm confusion; CVSS critical but only exploitable with asymmetric keys, while this app uses HS256, so High here) and CVE-2024-33664 (JWE DoS); python-multipart CVE-2024-24762/CVE-2024-53981 and starlette CVE-2024-47874: **unauthenticated** request-parsing DoS that takes the API down; cryptography 38 (CVE-2023-50782 etc.). | Outage of the tracking system during an incident, when the security team needs it most; auth library weaknesses. | S | Fixed |
| F-09 | **Notify service has no authentication** on `/webhooks` and `/notify`; webhook URL is unrestricted | Manual | **High.** Anyone who can reach port 3001 can (a) register a webhook and silently receive every scan event (title, severity, owner) = live feed of new vulnerabilities; (b) make the server call internal URLs such as cloud metadata `169.254.169.254` (**SSRF**); (c) list all webhooks; (d) inject fake events via `/notify`. Not Critical only because the service is meant to be internal-only. | Real-time leak of which systems are vulnerable; pivot into internal network/cloud credentials. | S | **Deferred**: see remediation plan R2 |
| F-10 | **Hard-coded secrets committed to git:** JWT key, `DB_PASSWORD`, `ADMIN_API_KEY` (`sk-vt-prod-...`), notify `SERVICE_KEY` | gitleaks (2 of 4), Bandit, manual | **High.** Removing them from code does not remove them from history; this repo (and every clone of it) still contains them. Names like `-prod-` suggest they may be real elsewhere. | Credential reuse in other environments; F-01 attack on any deployment that ever used the old key. | S | **Partly fixed:** removed from code; rotation + history purge in R1 |
| F-11 | **Vulnerable Node dependencies:** 1 critical, 5 high | npm audit | **High.** axios 0.21.1 (CVE-2025-27152 SSRF, CVE-2023-45857), follow-redirects credential-header leak on redirect. Relevant because notify sends `X-Service-Key` to arbitrary webhook URLs that can redirect. express/path-to-regexp ReDoS (CVE-2024-45296), body-parser DoS. proxy-addr (critical label) only matters with `trust proxy`, which notify does not set, so not critical here. | Service-key leakage and DoS of event delivery. | S | Fixed |
| F-12 | **Base image with 44 fixable HIGH vulnerabilities** (distroless Python 3.11 image ships Debian's Python 3.11.2, OpenSSL, expat, Kerberos without published fixes) | Trivy | **High.** My first Dockerfile choice. "Minimal" did not mean "patched": the vendor image lags Debian security updates. Includes CPython and OpenSSL flaws reachable from request handling. | Known-exploitable components in production. | **N** | Fixed (switched base) |
| F-13 | **Stack traces returned to clients** (global exception handler returns `traceback`, error text, URL) | Manual; confirmed: a single `'` in search returned the raw SQL statement | **Medium.** No direct data access, but it handed attackers the exact SQL needed for F-02 plus file paths and library versions. | Speeds up every other attack. | S | Fixed |
| F-14 | **CORS reflects any Origin with `Allow-Credentials: true`** | Manual | **Medium, not High.** Normally this lets any website act as the logged-in user. Here auth is a Bearer header that browsers do not attach automatically, so cross-site abuse needs the token already. Becomes High the moment cookie auth is added. | Latent cross-site data theft. | S | Fixed |
| F-15 | **No rate limiting / lockout on `/auth/login`** | Manual | **Medium.** Unlimited online guessing; bcrypt slows each guess but does not stop credential stuffing. | Account takeover of users with reused passwords. | S | **Deferred** (R3); compensating control in Helm ingress |
| F-16 | **No password policy** (1-character passwords accepted; >72-byte passwords silently truncated by bcrypt) | Manual | **Medium.** Makes F-15 much easier. | Weak accounts. | S | Fixed (min 8, max 72 bytes) |
| F-17 | **SQLite as the data store** | Manual | **Medium.** No encryption at rest, no access control between app and data, single replica (no HA), file on a volume. | Data loss / availability risk; weak at-rest protection. | S | **Deferred** (R4) |
| F-18 | **Container OS packages: 44 HIGH with no upstream fix** (Debian 13: libuuid, sqlite, ncurses, ...) | Trivy | **Medium.** No fix exists; most are in libraries the app does not call from request paths; container runs non-root, read-only, no capabilities. | Residual exposure until Debian ships fixes. | N (inherited) | **Accepted / monitored** (R5) |
| F-19 | **Notify error handler returns stack traces** | Manual | **Medium** (same reasoning as F-13). | Recon aid. | S | Deferred with F-09 |
| F-20 | **Unbounded `limit` on `GET /scans`** | Manual | **Low.** Authenticated memory/CPU exhaustion. | Minor availability. | S | Fixed (max 100) |
| F-21 | **User enumeration:** register says "Username already registered"; login timing differs for unknown users. Email not validated. | Manual | **Low.** | Helps targeted guessing. | S | Deferred (R6) |
| F-22 | **Share-link lockout can be triggered by anyone who holds the link** (5 bad passwords locks it) | Manual (design review of my feature) | **Low.** Deliberate trade-off: brute-force resistance over availability; the owner simply issues a new link. | Minor nuisance. | **N** | Accepted |
| F-23 | **API docs (`/docs`, `/openapi.json`) public** | Manual | **Low.** Exposes full attack surface map. | Recon aid. | S | Deferred (R6) |
| F-24 | **Webhook payload includes owner username** sent to external endpoints | Manual | **Low.** Data minimisation. | Minor PII leak. | S | Deferred with F-09 |
| F-25 | **Helm chart: default namespace, image by tag not digest** | Checkov CKV_K8S_21, CKV_K8S_43 | **Low.** Tags are mutable (a re-pushed tag silently changes what runs); default namespace weakens isolation. | Supply-chain / isolation hygiene. | **N** | Fixed |

### Triaged false positives (post-remediation)

| Tool | Location | Why it is not a vulnerability |
|---|---|---|
| Semgrep `python-logger-credential-disclosure` | `app/main.py` "Failed password attempt on share link %s" | Logs the database id of the link, never the password; the rule matches the word "password" in the message. |
| Bandit B105 | `app/main.py` `"token_type": "bearer"` | OAuth token-type literal, not a secret. |
| gitleaks | two lines in `tests/test_api.py` | Throwaway test credentials and the revoked old key used in a regression test; marked `gitleaks:allow`. |

### What my new feature does right (design choices reviewers should check)

* Share tokens: 256-bit `secrets.token_urlsafe`, stored only as SHA-256 (DB leak ≠ usable links).
* Owner-only creation; 404 for others' scans (no existence oracle); identical 404 for unknown/expired/revoked links.
* Server-side 24 h expiry; bcrypt-hashed optional password; 5-attempt lockout with atomic counter.
* `share_url` built from configured `SHARE_BASE_URL`, **not the Host header** (prevents host-header link poisoning).
* Public view omits `owner_id` and internal `remediation_notes`; `Cache-Control: no-store`, `Referrer-Policy: no-referrer`, `X-Robots-Tag: noindex`.
