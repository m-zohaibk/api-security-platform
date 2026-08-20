# DVWA File-Inclusion Verification Summary

**Target directory:** `https://pentest-ground.com:4280/vulnerabilities/fi/?page=include.php`

## Result

The independent manual check used `page=../../../../../../etc/passwd` and received HTTP 200 with the marker `root:x:0:0:`. The response grew by 488 bytes compared with the control request, confirming local file inclusion in the intentionally vulnerable training application.

The scanner’s first run missed this vulnerability because it sent generic SQLi, XSS, and command probes and had no local-file-inclusion signature. It reported 0 confirmed vulnerabilities and a 3.5/100 score.

## Fixes

The scanner now has a dedicated `Local_File_Inclusion` category, a bounded traversal probe, module-specific routing for `/vulnerabilities/fi/`, and proof verification requiring known system-file markers such as `root:x:0:0:`. It still reports traversal syntax without file content as suspected rather than confirmed.

## Final verification

The repaired scanner was run directly against the same directory with `MAX_ENDPOINTS=1`. It produced:

| Metric | Result |
|---|---:|
| Confirmed vulnerabilities | **1** |
| Finding type | **Local_File_Inclusion** |
| Score | **14.0/100 LOW** |
| Proof | `root:x:0:0:` |
| Manual score comparison | **14.0/100; exact agreement** |
| Full automated suite | **51 passed** |

The full suite passed with existing deprecation warnings only. The raw manual evidence is in [`tests/dvwa_lfi_manual_results.json`](tests/dvwa_lfi_manual_results.json), and the scanner regression coverage is in [`tests/test_accuracy_regressions.py`](tests/test_accuracy_regressions.py).
