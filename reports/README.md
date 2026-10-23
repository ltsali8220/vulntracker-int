# Scan reports

Raw JSON output from each scanner. Interpretation is in [`docs/findings.md`](../docs/findings.md).

**`reports/` (top level): baseline**, scanned *before* remediation (starter code + Task 1 feature + first Dockerfile/Helm chart):

| File | Scan type | Tool |
|---|---|---|
| `sast.semgrep.json` | SAST | Semgrep 1.181.1 |
| `sast.bandit.json` | SAST (Python) | Bandit 1.9.4 |
| `secrets.gitleaks.json` | Secrets (git history) | gitleaks 8.30.1 |
| `sca.pip-audit.json` | SCA (Python) | pip-audit 2.10.1 |
| `sca.npm-audit.json` | SCA (Node) | npm audit |
| `container.trivy.json` | Container image | Trivy 0.76.1 |
| `iac.checkov.json` | IaC (Helm) | Checkov 3.3.30 |

**`reports/post-remediation/`:** the same scans after the Task 3 fixes (gitleaks here scans the working tree, not history).

| Scan | Baseline | After |
|---|---|---|
| Semgrep | 2 ERROR, 3 WARNING | 0 ERROR, 1 WARNING (false positive) |
| pip-audit | 67 vulns in 8 packages | 0 |
| npm audit | 1 critical, 5 high, 2 moderate, 3 low | 0 |
| Trivy (image) | 5 CRITICAL, 75 HIGH (OS + Python libs); 44 OS HIGH fixable | 0 CRITICAL, 0 fixable; 44 HIGH with no upstream fix |
| Checkov | 5 failed / 91 passed | 0 failed / 96 passed |
| gitleaks | 2 secrets | 0 |
