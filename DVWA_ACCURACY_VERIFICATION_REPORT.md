# DVWA Accuracy Verification and Scanner Improvement Report

**Repository:** `m-zohaibk/api-security-platform`
**Selected target:** [https://pentest-ground.com:4280/](https://pentest-ground.com:4280/)
**Application:** Damn Vulnerable Web Application (DVWA), security level `low`
**Verification date:** 2026-08-20

## Executive Summary

The scanner was tested against a public DVWA training instance explicitly presented for security-tool practice. The initial 20-endpoint run discovered vulnerable directories but did not test their actual form inputs. It produced only generic suspected findings and missed the target’s command-injection and reflected-XSS behavior. Subsequent independent checks exposed a false-positive time-based SQLi result caused by ordinary target latency and a command-injection classification error caused by overlapping payload rules.

The scanner was improved through repeated test-and-verify cycles. The final current-code run tested 15 endpoints and correctly confirmed two independently reproducible findings: **command injection** on `/vulnerabilities/exec/` and **reflected XSS** on `/vulnerabilities/xss_r/`. It did not confirm the earlier false SQLi result on `/instructions.php`. The complete repository suite passes **49 tests**.

> The tool is materially more accurate than the initial version, but no bounded scanner run can establish that it finds every vulnerability. The remaining limitations are documented below rather than being presented as perfect coverage.

## Target Selection and Scope

The OWASP Vulnerable Web Applications Directory is a registry of intentionally vulnerable applications for security training [1]. The selected DVWA service states that it exists to help security professionals test skills and tools in a legal, controlled environment and exposes modules for SQL injection, command injection, reflected/stored XSS, file inclusion, CSRF, weak session IDs, and other classes [2].

Testing was limited to non-destructive GET and POST requests. No brute-force campaign, file upload, database reset, stored-XSS submission, password change, or destructive state change was performed.

## What Was Wrong Initially

| Issue | Initial behavior | Accuracy impact |
|---|---|---|
| Endpoint budget was not applied consistently. | The scanner could discover many endpoints and spend a long time sending the full generic queue. | Real-target runs became unnecessarily slow and difficult to bound. |
| BOLA suffix construction used full query-bearing URLs. | A suffix could be appended after an existing query string. | BOLA requests could target malformed paths. |
| Form metadata was discarded by URL/method deduplication. | A GET link record could hide a later POST form record, including fields such as `ip`, `id`, and `name`. | The scanner reached module pages but did not submit the real application inputs. |
| Generic payload delivery used `q` when no metadata was available. | SQLi/XSS/command payloads were often sent to irrelevant parameters. | Vulnerable modules were under-tested and produced false negatives. |
| Module HTTP methods were not respected. | A POST form could be probed as GET. | The target application did not execute the intended server-side handler. |
| Form submit/default fields were omitted. | Controls such as `Submit=Submit` were dropped. | Some DVWA forms returned their normal page instead of processing the probe. |
| Candidate categories were selected only by overlapping regex order. | `; cat /etc/passwd` could be classified through an SQL-related rule before command-injection verification. | A real command-injection proof was stored as a non-confirmed generic finding. |
| Any response delay over three seconds could confirm SQLi. | A slow ordinary page response was enough to create time-based SQLi proof. | `/instructions.php` was falsely confirmed during the earlier run. |
| Stored XSS was treated like a normal active probe. | A generic queue could submit persistent content to a shared public lab. | This was unsafe and unsuitable for a public training service. |

## Fixes Implemented

The endpoint budget is now enforced, with the default set to **20** and environment overrides preserved. Discovery now passes the configured timeout, builds BOLA URLs from the target origin, merges duplicate URL metadata across link and form discoveries, retains the actual form method, preserves hidden and submit defaults, and records query fields.

The request path now binds payloads to actual discovered fields. For example, DVWA command injection is sent as a POST to `ip` with `Submit=Submit`; SQLi is sent to `id`; and reflected XSS is sent to `name`. Module-aware routing limits probes to relevant cases: SQLi modules receive SQL probes, reflected XSS receives a GET reflection probe, command injection receives a command probe, and stored XSS is skipped to avoid persistent writes.

The signature layer now receives the intended probe category, preventing cross-category misclassification. Time-based SQLi proof requires both a measured delay and an explicit delay payload such as `SLEEP(...)`, `BENCHMARK(...)`, `pg_sleep(...)`, or `WAITFOR DELAY`. A slow response to a plain SQL-looking payload is therefore retained as suspected evidence rather than confirmed proof.

## Independent Manual Evidence

The independent verifier reproduced the final confirmed findings without relying on the scanner’s classification.

| Module | Manual observation | Platform result |
|---|---|---|
| `/vulnerabilities/exec/` | POSTing `ip=127.0.0.1; cat /etc/passwd` produced the marker `root:x:0:0:` and increased the response size by 839 bytes. | Confirmed `Command_Injection`; proof stored as `root:x:0:0:`. |
| `/vulnerabilities/xss_r/` | GET request with `name=<script>alert('xss')</script>` returned the payload verbatim in `text/html`. | Confirmed `XSS`; proof stored as unescaped HTML reflection. |
| `/instructions.php` | The control request was slower than the ordinary SQL-looking probe; the measured delta was negative rather than a delay. No multiple-row SQL response was observed. | No SQLi confirmation after the timing-proof fix. |

The raw independent artifacts are [`tests/dvwa_manual_module_results.json`](tests/dvwa_manual_module_results.json) and [`tests/dvwa_manual_confirmations.json`](tests/dvwa_manual_confirmations.json).

## Final Current-Code Scan

The final run used `MAX_ENDPOINTS=15` to cover the command-injection, SQLi, and reflected-XSS modules within a bounded public-target test.

| Metric | Result |
|---|---:|
| Endpoints tested | 15 |
| Persisted findings | 52 |
| Confirmed findings | 2 |
| Suspected findings | 50 |
| Confirmed vulnerabilities counted | 2 |
| Overall risk score | **14.0/100** |
| Overall severity | **LOW** |
| Runtime | **258 seconds** |

### Confirmed Findings

| Endpoint | Category | Score | Proof |
|---|---|---:|---|
| `/vulnerabilities/exec/` | Command Injection | 14.0 | `root:x:0:0:` appeared after the `; cat /etc/passwd` probe. |
| `/vulnerabilities/xss_r/` | Reflected XSS | 14.0 | `<script>alert('xss')</script>` was reflected unescaped in an HTML response. |

The earlier 20-endpoint run had falsely confirmed SQLi on `/instructions.php` due to a 29-second response delay. After the timing-proof fix, the targeted scan no longer confirmed that result.

## Automated Verification

| Verification | Result |
|---|---:|
| Complete repository test suite | **49 passed** |
| Latest focused accuracy suite | **32 passed** |
| Python compilation checks | Passed |
| `git diff --check` | Passed |

The suite still emits existing deprecation warnings related to `datetime.utcnow()`, ReportLab compatibility, and optional PyArrow support. These warnings did not cause failures.

## Remaining Limitations

The scanner should not yet be described as perfect or exhaustive. The final verification intentionally skipped stored XSS because it would create persistent state on a shared public service. File upload, brute force, CSRF state changes, password-changing flows, and authentication/session weaknesses require dedicated safe workflows and were not claimed as verified by this run. DOM XSS and open redirects also need browser-aware or redirect-aware proof checks rather than generic response-body checks.

The scanner remains sequential and can take several minutes against a slow public service even with a 20-endpoint cap. Public training targets can also rate-limit, reset sessions, or vary response latency. Confirmed results should therefore continue to require reproducible evidence, and suspected findings should remain distinct from confirmed vulnerabilities.

## Conclusion

The tool now demonstrates verified, evidence-backed detection for reflected XSS and command injection on the selected DVWA target, avoids the reproduced time-based SQLi false positive, routes probes through actual form fields and methods, and maintains a passing regression suite. The result is a substantial accuracy improvement, with explicit remaining coverage boundaries for future development.

## References

[1]: https://owasp.org/www-project-vulnerable-web-applications-directory/ "OWASP Vulnerable Web Applications Directory"
[2]: https://pentest-ground.com:4280/ "DVWA training application on Pentest Ground"
