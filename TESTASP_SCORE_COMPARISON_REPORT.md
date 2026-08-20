# Real-Target Platform vs Manual Verification Report

**Target:** [http://testasp.vulnweb.com](http://testasp.vulnweb.com)
**Application:** AcuForum intentionally vulnerable training application
**Verification date:** 2026-08-20
**Repository:** `m-zohaibk/api-security-platform`

## Executive Summary

The initial real-target scan appeared stalled because the platform discovered **30 endpoints** and then sent its full active payload queue sequentially to every endpoint. Each request took approximately one to two seconds, so the scan expanded into hundreds of requests. Diagnosis showed that the process was active rather than crashed, but the behavior was not appropriately bounded for a public training target.

The scanner was corrected before comparison. It now enforces the configured endpoint limit, uses the configured scan timeout during discovery, and constructs BOLA path probes from the target origin rather than appending them to query-bearing page URLs. The repaired scan completed successfully with a five-endpoint budget.

> **The platform score matched the independent manual score on all five endpoints: 3.5/100, with a score delta of 0.0 for every endpoint. Both methods found zero confirmed exploit findings.**

## Scanner Repair

| Problem | Fix | Verification |
|---|---|---|
| `MAX_ENDPOINTS` was defined but not applied after discovery. | The pipeline now truncates discovered endpoints to the configured limit. The default was changed from 50 to 10, and the test run explicitly used 5. | The scan discovered 30 endpoints but tested only 5. |
| Discovery used the default endpoint timeout rather than the configured `SCAN_TIMEOUT`. | `EndpointDiscovery` now receives `SCAN_TIMEOUT`. | The repaired run completed without request timeout or process hang. |
| BOLA suffixes were appended directly to complete URLs, producing malformed paths such as `Login.asp?RetURL=.../users/v1/3`. | BOLA probes now use the parsed target origin and append the suffix to the origin path. | The scan log no longer showed malformed query-bearing suffix URLs. |

The related implementation changes are in [`main.py`](main.py) and [`config/settings.py`](config/settings.py). The focused regression and existing test suites passed after the changes.

## Platform Scan Results

The repaired platform scan used:

| Parameter | Value |
|---|---:|
| Target | `http://testasp.vulnweb.com` |
| Endpoint budget | 5 |
| Endpoints discovered before cap | 30 |
| Endpoints tested | 5 |
| Active test categories | SQL injection, XSS, command injection, authentication weakness, BOLA/IDOR, baseline inspection |
| Persisted findings | 30 |
| Finding status distribution | 30 Suspected, 0 Confirmed |
| Vulnerabilities counted | 0 |
| Overall risk score | 3.5/100 |
| Overall severity | LOW |
| Scan completion | Successful |

The platform’s 3.5 score came from the missing security-header signal. The score was not treated as confirmed exploit proof, which is consistent with the earlier accuracy fixes.

## Independent Manual Verification

The manual verification replayed the same five endpoints and the same payload categories using an independent HTTP client and separate evidence rules. It checked response status, response size, response headers, SQL error signatures, command-output signatures, reflected XSS payloads, sensitive BOLA object properties, and authentication evidence.

| Endpoint | Platform max score | Manual score | Difference | Platform confirmed | Manual confirmed |
|---|---:|---:|---:|---|---|
| `/` | 3.5 | 3.5 | 0.0 | No | No |
| `/Templatize.asp?item=html/about.html` | 3.5 | 3.5 | 0.0 | No | No |
| `/Default.asp` | 3.5 | 3.5 | 0.0 | No | No |
| `/Search.asp` | 3.5 | 3.5 | 0.0 | No | No |
| `/Login.asp?RetURL=%2FSearch%2Easp%3F` | 3.5 | 3.5 | 0.0 | No | No |

The independent check observed that each endpoint lacked the four required response headers: `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, and `Strict-Transport-Security`. It did not observe confirmed SQL injection, reflected XSS, command execution, broken authentication, or unauthorized sensitive-object disclosure on the bounded test set.

The machine-readable comparison is saved in [`tests/testasp_score_comparison.json`](tests/testasp_score_comparison.json), and the independent verification implementation is in [`tests/manual_testasp_compare.py`](tests/manual_testasp_compare.py).

## Agreement Assessment

| Comparison measure | Result |
|---|---:|
| Endpoint scores compared | 5 |
| Exact score matches | 5 of 5 |
| Maximum score delta | 0.0 |
| Confirmed-status matches | 5 of 5 |
| Platform confirmed vulnerabilities | 0 |
| Manual confirmed vulnerabilities | 0 |

Accordingly, the platform and manual method produced the same score and the same confirmed/not-confirmed conclusion for every endpoint included in this bounded run.

## Automated Verification After the Fix

The full repository test suite completed with **36 passed tests**. Syntax compilation also passed. The run produced existing deprecation warnings related to `datetime.utcnow()` and optional PyArrow support; these warnings did not cause test failures and were outside the scope of this real-target scan repair.

## Limitations

This comparison is not a claim that the entire testasp application is free of vulnerabilities. It covers the first five endpoints selected by the bounded discovery result and the platform’s current fixed payload queue. A broader authorized assessment would require a larger endpoint budget, more application-specific request construction, and manual review of additional pages and parameters.

The target is an intentionally vulnerable public training application. Testing was restricted to bounded non-destructive probes; no brute force, denial-of-service activity, destructive modification, or real-account access was performed.

## References

[1]: http://testasp.vulnweb.com "AcuForum intentionally vulnerable training application"
[2]: https://github.com/m-zohaibk/api-security-platform "API Security Platform repository"
