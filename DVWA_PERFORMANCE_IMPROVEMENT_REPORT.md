# DVWA Performance Improvement and Accuracy Verification

**Target:** [`https://pentest-ground.com:4280/`](https://pentest-ground.com:4280/)
**Application:** DVWA training instance, low security
**Verification date:** 2026-08-20
**Repository:** [`m-zohaibk/api-security-platform`](https://github.com/m-zohaibk/api-security-platform)

## Executive Summary

The earlier broader scan was slow because every active probe was sent sequentially, while the request engine performed multiple network operations per endpoint. The scanner has now been improved with **bounded active-probe concurrency**. The default is four workers and can be changed through `ACTIVE_CONCURRENCY`; analysis, proof verification, risk scoring, and SQLite persistence remain sequential and deterministic.

The broader DVWA scan now completed successfully in **216 seconds** with `MAX_ENDPOINTS=15` and `ACTIVE_CONCURRENCY=4`. The prior broader attempt exceeded its 420-second bound. This is an observed reduction of approximately **49% versus the previous time bound**, while preserving the known findings and adding the independently verified DVWA LFI result.

## Implementation Change

The main pipeline now prepares the selected probe requests for each endpoint, dispatches those HTTP requests through a bounded `ThreadPoolExecutor`, and then processes the returned telemetry in the original sequential order. This design avoids concurrent database writes and avoids concurrent mutation of the detector or scoring state. It improves network utilization without allowing an uncontrolled request flood.

The concurrency setting is explicit:

```text
ACTIVE_CONCURRENCY=4
```

The existing endpoint budget remains active. The tested broader run discovered 42 endpoints but intentionally tested the first 15 because it used `MAX_ENDPOINTS=15`, matching the previous DVWA comparison scope. The improvement changes request scheduling, not endpoint selection or vulnerability proof requirements.

## Broad Scan Results

| Metric | Previous broader attempt | Improved run |
|---|---:|---:|
| Endpoint inventory discovered | 42 | 42 |
| Endpoint budget | 15 | 15 |
| Active concurrency | Sequential | 4 workers |
| Runtime result | Exceeded 420-second bound | **216 seconds** |
| Pipeline completion | No final completion record | **Completed successfully** |
| Persisted findings | Partial database only | 50 |
| Confirmed findings | 0 in partial database | **3** |
| Suspected findings | 16 in partial database | 47 |
| Overall score | Not usable from partial run | **14.0/100 LOW** |

## Confirmed Findings

| Endpoint | Category | Method | Payload | Proof |
|---|---|---|---|---|
| `/vulnerabilities/exec/` | Command Injection | POST | `; cat /etc/passwd` bound to `ip` | `root:x:0:0:` |
| `/vulnerabilities/fi/?page=include.php` | Local File Inclusion | GET | `../../../../../../etc/passwd` | `root:x:0:0:` |
| `/vulnerabilities/xss_r/` | Reflected XSS | GET | `<script>alert('xss')</script>` bound to `name` | Verbatim unescaped reflection in `text/html;charset=utf-8` |

The two findings previously confirmed manually—command injection and reflected XSS—remain confirmed after the concurrency change. The LFI finding is consistent with the earlier independent DVWA LFI verification cycle.

## Focused Accuracy Retest

Before the broad run, the improved concurrent pipeline was executed directly against the two known vulnerable module pages using the exact discovered form metadata. Both focused scans completed successfully in approximately 15–16 seconds each.

| Module | Result | Score |
|---|---|---:|
| `/vulnerabilities/exec/` | Confirmed command injection with `root:x:0:0:` | 14.0/100 |
| `/vulnerabilities/xss_r/` | Confirmed reflected XSS with exact HTML reflection | 14.0/100 |

The focused output matched the manual verification on endpoint, HTTP method, parameter field, payload, proof marker, and confirmed count. The scanner did not promote the residual syntax-only SQLi observations into confirmed vulnerabilities.

## Validation

The complete repository suite passed **64 tests** after the performance change. Python compilation checks passed and `git diff --check` reported no whitespace errors. Existing deprecation warnings remain for `datetime.utcnow()`, ReportLab compatibility, and optional PyArrow support; none caused a failure.

## Remaining Performance Work

The largest remaining cost is discovery, which still probes many common paths sequentially. The next performance step should be a separate bounded concurrency layer for discovery with deduplicated work queues, per-host rate limits, and cancellation when the endpoint budget is satisfied. The current implementation deliberately improved only active probing first, because discovery metadata and ordering are more sensitive to concurrency and can affect coverage.

Further work should also add persistent HTTP connection reuse, adaptive per-host backoff, and a scan progress estimate. Any future concurrency increase must retain the present safety controls: explicit endpoint budgets, per-host worker limits, read-only modes, no stored-XSS probes by default, and deterministic proof-gated confirmation.

## Conclusion

The sequential timeout was a real performance defect and has now been improved rather than ignored. The broader DVWA scan completed within its new bounded execution window, persisted complete results, and retained the two manually verified vulnerabilities as confirmed. The scanner is faster while preserving the accuracy behavior established during the earlier target-verification work.

## References

[1]: https://pentest-ground.com:4280/ "DVWA training target"
[2]: DVWA_CURRENT_RETEST_REPORT.md "Current focused DVWA retest"
[3]: DVWA_ACCURACY_VERIFICATION_REPORT.md "Prior DVWA accuracy verification"
[4]: DVWA_LFI_VERIFICATION_SUMMARY.md "DVWA LFI verification"
[5]: tests/dvwa_manual_confirmations.json "Manual DVWA confirmation artifact"
