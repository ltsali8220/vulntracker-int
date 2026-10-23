# Executive Summary: VulnTracker Security Review

**Bottom line:** Before this work, anyone could have logged in as any user and copied every customer's list of unpatched weaknesses: in effect, a burglar's map of our customers' systems. Those doors are now closed and the fixes are proven by tests. VulnTracker is **fit for a controlled internal pilot**, but **not yet for production with external customers** until three remaining items (below) are done, roughly one to two weeks of effort.

## 1. Where we were, and where we are now

**Before:** The prototype had several independent ways for an outsider or any registered user to read all data:

* The "master key" that proves who a user is was written into the source code. Anyone who had seen the code could impersonate anyone. *(Demonstrated.)*
* The search box could be tricked into handing over the entire user database. *(Demonstrated.)*
* Any user could read any other organisation's findings just by changing a number in the address.
* Users' passwords were written into the system logs in plain text.
* Many third-party components had publicly known flaws, some allowing anyone on the internet to crash the service.

**After:**

* All of the above are fixed and each has an automated test that fails if the problem comes back.
* The new **customer share-link** feature was built to be secure by design: links are unguessable, expire after 24 hours, can be password-protected with lockout after 5 wrong guesses, show only what an external party needs, and are kept out of logs.
* Every code change now automatically goes through four kinds of security check (our code, third-party components, the server image, and the deployment settings). A serious, fixable problem **blocks the release**.
* The service is packaged to run with minimal privileges, cannot modify itself, takes its secrets from a central vault rather than files or settings, and can only talk to the systems it needs.

| | Before | After |
|---|---|---|
| Ways to take over any account or steal all data | 3 confirmed | 0 known |
| Known flaws in third-party components (app) | 67 Python + 11 Node | 0 |
| Fixable serious flaws in the server image | 44 | 0 |
| Deployment configuration checks failing | n/a | 0 of 96 |
| Automated security gates on every change | None | 4 scan types + 45 tests |

## 2. Top 3 remaining risks

| # | Risk in plain terms | Why it is not fixed yet | What protects us meanwhile |
|---|---|---|---|
| 1 | **Old passwords and keys are still in the project's history.** If any were ever used in a real environment, that environment should be treated as exposed. | Changing them requires access to the systems that use them; the code itself no longer relies on them. | The application now refuses to start without a new, vault-stored key and rejects the old one. Automated checks stop new secrets being committed. **Action: rotate all four credentials (hours, not days).** |
| 2 | **The notification component has no login at all.** Someone inside our network could subscribe to a live feed of newly found weaknesses, or use it to reach other internal systems. | It was outside the scope of this exercise and needs a small redesign (about 2 days) rather than a quick patch. | It is meant to run internally only, and network rules restrict what talks to what. Its own known component flaws were fixed. |
| 3 | **Unlimited password guessing on the login page,** and the data store is a single file on one server (no automatic failover, limited at-rest protection). | Doing these properly needs shared infrastructure (a rate-limit store and a managed database), about 3-4 days combined. | Traffic limits at the network edge, slow password checking, a new minimum password length, and single-instance operation with backups of the storage volume. |

## 3. Recommended next steps

1. **This week:** Rotate the four exposed credentials. Put the notification component behind authentication and block it from contacting internal addresses.
2. **Before external customers:** Add login rate-limiting; move data to a managed, encrypted database with backups; run an independent penetration test focused on the share-link feature.
3. **Ongoing:** Keep the automated security gates mandatory; turn on automatic dependency and server-image updates; add live-attack simulation to the pipeline; review access logs for the share feature monthly.

*Detailed findings: [findings.md](findings.md). Remediation detail and effort estimates: [remediation-plan.md](remediation-plan.md).*
