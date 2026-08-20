# API Security Platform Accuracy Fix Report

**Repository:** `m-zohaibk/api-security-platform`
**Working copy:** `/home/ubuntu/api-security-platform`
**Author:** Manus AI
**Verification date:** 2026-08-20

## Executive Summary

The platform’s original automated tests passed, but targeted manual testing exposed several accuracy defects in the distinction between a **suspected detection signal** and a **confirmed vulnerability**. The most serious issue was that a numeric object URL such as `/users/2` could be reported as confirmed BOLA/IDOR without sensitive data being returned. In addition, the aggregate risk scorer and live pipeline could convert non-zero triage scores into vulnerability flags and inflated vulnerability counts.

The implementation now preserves triage signals while requiring response evidence for confirmed vulnerability status. Request serialization, query-parameter feature extraction, BOLA proof checks, pipeline counting, and evaluator fallbacks were corrected. A new regression test module and two deterministic local manual probes were added.

> **Result:** The corrected platform reports suspected findings as suspected, confirmed findings only when proof criteria are met, and a clean local end-to-end scan produced **0 confirmed vulnerabilities**.

## What Was Wrong

| Area | Original behavior | Accuracy impact |
|---|---|---|
| Risk aggregation | `RiskScorer` treated any signature match as proof and set `is_vulnerable` when the final score reached 40 or more. | Suspected payload matches or multi-layer anomalies could be mislabeled as confirmed vulnerabilities. |
| Proof text | A suspected result could inherit text such as “Vulnerability signature verified with active response indicators.” | Reports overstated the strength of evidence. |
| BOLA/IDOR detection | A numeric user/account path plus a successful response and missing authorization could be confirmed even when the body contained no sensitive object data. | Clean object endpoints generated false-positive BOLA findings. |
| Request engine | An explicitly supplied empty JSON object `{}` was treated as false and omitted from the request body. | Tests against endpoints requiring an empty JSON object did not reproduce the intended request. |
| Feature extraction | `parse_qs()` discarded blank-valued parameters such as `?flag` and `?empty=`. | Query parameter counts and downstream feature vectors were inaccurate. |
| Live pipeline accounting | Any score greater than zero incremented the vulnerability count, even for suspected or informational findings. | Scan summaries could report inflated vulnerability totals. |
| Evaluation fallback | Missing test data generated fabricated labels and timing values. | Reported precision, recall, F1, and performance could look valid despite no evaluation dataset. |
| Evaluation coverage | VAmPI failures used hardcoded success-like results, and OWASP coverage was hardcoded as fully detected. | Accuracy and coverage claims were not based on observed detector output. |

## Fixes Implemented

The risk scorer in [`detection/risk_scorer.py`](detection/risk_scorer.py) now separates **layer detection** from **exploit proof**. Signature matches can still contribute to a triage score, but `is_vulnerable` is true only when a proof-bearing result is present. Suspected results remain visible with `finding_status = "Suspected"`, and their proof text explicitly states that proof was not established.

The BOLA/IDOR rules in [`detection/signature.py`](detection/signature.py) now require an HTTP success response, sensitive object-property evidence, and no authorization header before confirming an unauthenticated object-access vulnerability. A numeric URL by itself remains a suspected probe rather than a confirmed finding.

The request engine in [`core/request_engine.py`](core/request_engine.py) now checks `json_payload is not None`, so `{}` is transmitted as an actual JSON object. The parser in [`core/response_parser.py`](core/response_parser.py) now uses `keep_blank_values=True`, preserving blank query parameters in telemetry.

The live persistence logic in [`main.py`](main.py) now increments `total_vulnerabilities_found` only for confirmed evidence. Non-zero suspected scores can still be persisted for audit and triage, but they no longer inflate the confirmed vulnerability total or receive an attack label as if they were proven.

The evaluator in [`training/evaluate_models.py`](training/evaluate_models.py) now marks missing datasets, unavailable performance measurements, and unavailable VAmPI runs explicitly rather than fabricating results. Per-category, VAmPI, clean-endpoint, and OWASP coverage calculations use the corrected confirmed-vulnerability result. The tracked [`datasets/evaluation_results.json`](datasets/evaluation_results.json) was regenerated accordingly; with no processed test dataset and no VAmPI service running, its dataset metrics are `null` and its external-run status is `unavailable`.

## Verification Performed

| Verification | Result |
|---|---:|
| Full automated test suite | **36 passed**, 112 deprecation warnings |
| Focused accuracy regressions, signature, and risk tests | **16 passed**, 65 deprecation warnings |
| Python bytecode compilation | Passed with no errors |
| Git whitespace validation (`git diff --check`) | Passed |
| Manual request serialization probe | Empty JSON object round-tripped as `{}` |
| Manual OpenAPI/discovery probe | 5 unique local endpoints discovered; feature vector length was 17 |
| Manual clean BOLA probe | `finding_status = Suspected`, `has_proof = false`, `is_vulnerable = false` |
| Manual suspected-risk probe | `finding_status = Suspected`, `is_vulnerable = false`, proof text no longer claimed verification |
| Full pipeline against deterministic clean local API | 4 endpoints, 9 triage findings, 0 confirmed findings, 0 vulnerabilities counted, maximum score 3.5 |

The full-pipeline probe is implemented in [`tests/manual_pipeline_probe.py`](tests/manual_pipeline_probe.py). Its database-backed result was:

```json
{
  "endpoints_found": 4,
  "finding_count": 9,
  "finding_status_counts": {"Suspected": 9},
  "confirmed_finding_count": 0,
  "overall_score": 3.5,
  "vulnerabilities_found": 0
}
```

The regression coverage is in [`tests/test_accuracy_regressions.py`](tests/test_accuracy_regressions.py), with the smaller component probe in [`tests/manual_accuracy_probe.py`](tests/manual_accuracy_probe.py).

## Remaining Limitations

The repository does not currently contain the processed evaluation dataset expected by the evaluator, and the VAmPI target was not running during verification. Therefore, no defensible real-dataset precision, recall, F1, or live VAmPI accuracy number is claimed in the regenerated evaluation artifact. The corrected evaluator now exposes that limitation instead of masking it with fallback values.

The existing deprecation warnings for `datetime.utcnow()` and the missing optional PyArrow dependency were not part of the accuracy fixes. They do not cause the verified tests to fail, but they should be addressed in a separate maintenance change.

## Changed Files

| File | Purpose |
|---|---|
| [`core/request_engine.py`](core/request_engine.py) | Preserve explicitly supplied empty JSON payloads. |
| [`core/response_parser.py`](core/response_parser.py) | Count blank-valued query parameters accurately. |
| [`detection/signature.py`](detection/signature.py) | Require sensitive unauthorized data for confirmed BOLA/IDOR. |
| [`detection/risk_scorer.py`](detection/risk_scorer.py) | Separate anomaly triage from confirmed vulnerability proof. |
| [`main.py`](main.py) | Count only confirmed findings as vulnerabilities while retaining triage findings. |
| [`training/evaluate_models.py`](training/evaluate_models.py) | Remove fabricated evaluator fallbacks and compute observed coverage. |
| [`datasets/evaluation_results.json`](datasets/evaluation_results.json) | Regenerated truthful evaluation-status artifact. |
| [`tests/test_accuracy_regressions.py`](tests/test_accuracy_regressions.py) | Regression tests for all principal accuracy fixes. |
| [`tests/manual_accuracy_probe.py`](tests/manual_accuracy_probe.py) | Deterministic component-level manual verification. |
| [`tests/manual_pipeline_probe.py`](tests/manual_pipeline_probe.py) | Deterministic database-backed end-to-end verification. |

## Conclusion

The principal accuracy problem was not that the detector failed to produce signals; it was that the platform promoted weak signals into confirmed vulnerability claims. The fixes preserve useful suspected/anomaly triage while making confirmed status evidence-based. Automated tests, targeted regressions, syntax checks, and manual local end-to-end verification all pass under the corrected behavior.
