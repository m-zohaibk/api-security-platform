# API Security Platform — Updated Accuracy Fix Report

**Target used for verification:** [http://testasp.vulnweb.com](http://testasp.vulnweb.com)
**Repository:** `m-zohaibk/api-security-platform`
**Verification date:** 2026-08-20

## Summary

The scanner was further corrected after the first real-target run. The initial run was not crashed, but it was inefficient and under-modeled the target: it discovered many endpoints, sent a generic `q` parameter instead of using real form-field names, constructed malformed BOLA suffix URLs for query-bearing pages, and treated payload-triggered target disconnects only as generic network failures.

The updated implementation now enforces the endpoint budget, uses the configured timeout, binds payloads to discovered form fields, constructs BOLA probes from the target origin, and distinguishes a payload-triggered connection reset after a healthy baseline from a completely unreachable target.

> **Final result:** The repaired scan completed, the complete test suite passed, and independent verification produced the same maximum score of **3.5/100** with **zero confirmed vulnerabilities**.

## Defects Fixed

| Defect | Correction | Evidence |
|---|---|---|
| Configured `MAX_ENDPOINTS` was not enforced. | The pipeline now caps discovered endpoints. The default is 10 and the verification run explicitly used 5. | The target discovery returned 63 endpoints, but only 5 were tested. |
| Discovery timeout configuration was ignored by the live pipeline. | `SCAN_TIMEOUT` is now passed into `EndpointDiscovery`. | The bounded scan completed without hanging. |
| BOLA probes were appended to full URLs, including query strings. | BOLA probes now use the target origin before appending `/users/v1/{id}`. | Final logs show clean origin-based BOLA paths. |
| HTML form fields were discovered but discarded. | Discovery now records named fields, and the request engine supports named query/form data. | `Search.asp` uses `tfSearch`; `Login.asp` uses `tfUName` and `tfUPass`. |
| All payloads were sent through a generic `q` parameter when no override was supplied. | The pipeline binds payloads to discovered form fields and preserves the generic fallback only for endpoints without field metadata. | Added regression tests for GET query and POST form binding. |
| Active payload connection resets were reported only as network errors. | If the baseline is healthy and an active payload disconnects, the signature layer reports `Application_Connection_Reset` as suspected, never confirmed. | Added regression tests for healthy-baseline and no-baseline cases. |

## Final Automated Verification

The complete repository suite passed:

| Check | Result |
|---|---:|
| Full pytest suite | **40 passed** |
| Focused accuracy/regression suite before final run | **23 passed** |
| Python compilation | Passed |
| `git diff --check` | Passed |

The remaining 112 warnings are existing maintenance warnings involving `datetime.utcnow()`, ReportLab compatibility, and optional PyArrow support. They do not cause test failures.

## Final Real-Target Scan

The final bounded run used `MAX_ENDPOINTS=5` against the reachable testasp training application.

| Metric | Result |
|---|---:|
| Endpoints discovered | 63 |
| Endpoints tested | 5 |
| Persisted findings | 30 |
| Suspected findings | 20 |
| Unreachable/network-drop findings | 10 |
| Confirmed vulnerabilities counted | 0 |
| Overall score | **3.5/100** |
| Overall severity | **LOW** |
| Scan completion | Successful |

The target closed connections for some attack-like probes. Those responses were not promoted to confirmed vulnerabilities. They remained either network-drop telemetry or low-confidence suspected signals, depending on whether a healthy baseline was available.

## Independent Manual Comparison

Independent verification replayed the same five endpoint URLs and used the same relevant field names. It checked baseline status, response headers, SQL error indicators, command-output indicators, reflected payloads, sensitive BOLA properties, and transport errors.

| Endpoint | Platform maximum | Manual score | Difference | Confirmed by platform | Confirmed manually |
|---|---:|---:|---:|---|---|
| `/` | 3.5 | 3.5 | 0.0 | No | No |
| `/Templatize.asp?item=html/about.html` | 3.5 | 3.5 | 0.0 | No | No |
| `/Default.asp` | 3.5 | 3.5 | 0.0 | No | No |
| `/Search.asp` | 3.5 | 3.5 | 0.0 | No | No |
| `/Login.asp?RetURL=%2FSearch%2Easp%3F` | 3.5 | 3.5 | 0.0 | No | No |

The final comparison artifact is [`tests/testasp_final_comparison.json`](tests/testasp_final_comparison.json). It records `all_scores_match: true`, a platform overall score of 3.5, a manual maximum score of 3.5, and zero confirmed findings from either method.

## Interpretation

The score agreement is meaningful for the bounded test set: the platform and manual method both identified missing security headers as the only consistent finding and both rejected exploit confirmation. The transport differences reflect target-side connection handling rather than a score discrepancy. Because the target is intentionally vulnerable and the run covered only five endpoints, this result should not be interpreted as proof that the entire application is secure or that all vulnerability classes were exhausted.

## Changed Areas

The primary production changes are in [`main.py`](main.py), [`config/settings.py`](config/settings.py), [`core/discovery.py`](core/discovery.py), [`core/request_engine.py`](core/request_engine.py), and [`detection/signature.py`](detection/signature.py). Regression coverage is in [`tests/test_accuracy_regressions.py`](tests/test_accuracy_regressions.py). The independent verifier is in [`tests/manual_testasp_compare.py`](tests/manual_testasp_compare.py).

## References

[1]: http://testasp.vulnweb.com "AcuForum intentionally vulnerable training application"
[2]: https://github.com/m-zohaibk/api-security-platform "API Security Platform repository"
