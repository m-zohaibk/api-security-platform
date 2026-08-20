# Final Accuracy and Cross-Target Verification Report

**Repository:** [`m-zohaibk/api-security-platform`](https://github.com/m-zohaibk/api-security-platform)
**Assessment date:** 2026-08-20
**Author:** Manus AI

## Executive Summary

The API security platform was reviewed, corrected, and tested against intentionally vulnerable training applications rather than production systems. The work covered testasp, DVWA, DVGA GraphQL, and crAPI. Testing used bounded, non-destructive requests, with the exception that DVWA’s public reflected-XSS and command-injection training forms were submitted only with standard lab payloads; stored-XSS and other persistent/state-changing workflows were deliberately skipped.

The principal accuracy defect was that payload syntax and anomaly signals could be presented too close to exploit proof. The scanner now separates **confirmed**, **suspected**, **informational**, and **blocked/inconclusive** outcomes. Confirmed totals require deterministic evidence. After the final changes, the complete repository suite passed **64 tests**, compilation passed, and `git diff --check` passed.

The final cross-target evidence is consistent. The scanner and independent manual verification agreed on a 3.5/100 score with no confirmed findings for testasp; agreed on two confirmed DVWA findings—command injection and reflected XSS—while removing a false time-based SQLi confirmation; agreed that DVGA introspection is informational rather than an exploit; and agreed that the final 42-endpoint crAPI read-only scan had zero confirmed active-probe findings.

## Cross-Target Results

| Target | Scope | Final scanner result | Independent verification | Status |
|---|---:|---|---|---|
| testasp | Bounded public training scan | 0 confirmed; **3.5/100 LOW** | Same score and zero-confirmed result | Matched |
| DVWA | 15 endpoints covering selected low-security modules | 2 confirmed; **14.0/100 LOW** | Command injection proved by `root:x:0:0:`; reflected XSS proved by verbatim HTML reflection | Matched |
| DVGA GraphQL | `/graphql` and `/graphiql` discovery plus structured introspection | 0 confirmed; informational GraphQL introspection; **3.5/100 LOW** | Manual introspection returned 12 query fields, including sensitive/debug-oriented names; treated as exposure telemetry | Matched |
| crAPI | 51 discovered; 42 safe read-only endpoints retained | 0 confirmed; **3.5/100 LOW**; 42 baseline header observations | SPA-shell routes returned frontend HTML; credential SQLi probe showed no bypass evidence | Matched |

The detailed evidence is preserved in [`TESTASP_SCORE_COMPARISON_REPORT.md`](TESTASP_SCORE_COMPARISON_REPORT.md), [`DVWA_ACCURACY_VERIFICATION_REPORT.md`](DVWA_ACCURACY_VERIFICATION_REPORT.md), [`DVWA_LFI_VERIFICATION_SUMMARY.md`](DVWA_LFI_VERIFICATION_SUMMARY.md), [`DVGA_CROSS_SITE_VERIFICATION_SUMMARY.md`](DVGA_CROSS_SITE_VERIFICATION_SUMMARY.md), and [`CRAPI_VERIFICATION_SUMMARY.md`](CRAPI_VERIFICATION_SUMMARY.md).

## What Was Wrong

The initial scanner had defects at several layers. Discovery could find more endpoints than the active test budget consistently respected, and its timeout was not always propagated. URL deduplication could discard form metadata, BOLA suffixes could be appended after query strings, and payloads were often sent to a generic `q` parameter instead of the application’s real form or JSON fields. Form methods, hidden fields, and submit defaults were also not reliably preserved.

The detection layer had proof-quality problems. Suspected signatures could be promoted into confirmed vulnerability totals, proof text could claim verification without evidence, overlapping regex rules could classify a command payload as SQLi, and any response delay above three seconds could confirm time-based SQLi even when the payload did not request a delay. BOLA relied too heavily on numeric paths, HTTP 405 responses were not treated as blocked, and GET-only endpoints could receive POST XSS probes.

The platform was also not sufficiently application-aware. Stored XSS probes were unsuitable for a shared public lab, GraphQL routes were treated as generic REST endpoints, and SPA frontend shells returned from API-like paths could be mistaken for API responses. Credential/login endpoints did not have a dedicated SQLi probe. Finally, model evaluation fallback could fabricate labels when datasets were absent, and OWASP coverage could be reported independently of actual detector output.

## What Was Fixed

| Area | Implemented correction | Result |
|---|---|---|
| Risk accounting | Only confirmed proof-gated findings increment vulnerability totals; suspected results remain visible but do not inflate confirmed counts. | Score and counts are more defensible. |
| Proof wording | Suspected findings explicitly state what proof is missing. | Reports no longer imply exploit verification from syntax alone. |
| Endpoint budget and timeout | `MAX_ENDPOINTS` is enforced and `SCAN_TIMEOUT` reaches discovery. | Runs are bounded and reproducible. |
| Discovery metadata | Duplicate URL records merge fields, methods, defaults, and form metadata. | Real form handlers and parameters are reached. |
| Request binding | Empty JSON objects are transmitted; blank query values are retained; payloads bind to discovered query, form, or JSON fields. | Probes reach intended application inputs. |
| Method-aware routing | Module queues respect form methods; GET-only routes receive GET XSS probes; stored XSS is skipped by default. | Fewer method errors and no unsafe persistence on public labs. |
| Category routing | Expected attack category is passed to the signature layer. | Command payloads are not misclassified as SQLi through rule order. |
| SQLi timing proof | A delay is confirmed only when timing evidence accompanies an explicit delay payload. | DVWA’s ordinary-latency false positive was removed. |
| BOLA/IDOR proof | Requires sensitive-data evidence and an unauthenticated context; suffix URLs are built from the origin. | Numeric paths alone no longer become IDOR proof. |
| LFI verification | Added traversal probes and local-file content markers. | DVWA LFI behavior can be distinguished from traversal syntax alone. |
| Connection reset handling | Healthy-baseline/payload-triggered disconnects become suspected application-impact findings. | Network failures are not silently conflated with exploit proof. |
| Response gates | 403, 404, 405, 429, and gateway/server blocks are excluded from exploit proof. | Blocked requests no longer create injection findings. |
| GraphQL support | Added endpoint discovery, valid structured 400 handling, introspection JSON, dedicated routing, and informational classification. | DVGA schema exposure is reported accurately. |
| SPA-shell handling | Header keys are normalized; shell markers are recognized across API-like route families; baseline shell endpoints skip active payloads. | crAPI active-probe false positives were eliminated. |
| Credential testing | Added JSON login SQLi probe and mapped it to the standard SQLi verifier. | Login coverage exists without calling identical error responses a bypass. |
| Evaluation integrity | Missing datasets return `null`/unavailable results instead of fabricated labels. | ML evaluation output is honest about missing evidence. |
| Coverage reporting | OWASP coverage is derived from actual detector output. | Coverage summaries no longer rely on hardcoded claims. |

## Manual Verification Outcomes

The DVWA manual verifier independently reproduced the two final confirmed findings. A POST to the command-injection form with a benign lab command payload returned the `/etc/passwd` marker `root:x:0:0:`. A reflected-XSS request returned the exact script string unescaped in an HTML response. The earlier SQLi result did not survive a control-versus-probe timing comparison and was therefore not counted after the timing-proof correction.

The DVGA manual verifier submitted a structured introspection query and observed 12 query fields, including `systemDebug`, `systemDiagnostics`, `users`, `audits`, `readAndBurn`, and `deleteAllPastes`. The scanner recorded this as `GraphQL_Introspection` informational exposure and counted **zero confirmed vulnerabilities**, which is the correct classification for the tested condition.

The crAPI credential verifier compared the login baseline and SQLi-shaped JSON probe. Both returned HTTP 500 with the same 74-byte plain-text response, no token-like output, no SQL-error signature, and no positive timing or size delta. The result is inconclusive about the application’s broken error handling but is not evidence of SQLi authentication bypass, so no confirmed SQLi was reported.

## Final Validation

| Validation | Result |
|---|---:|
| Focused accuracy, signature, core, and risk tests | 47 passed |
| Complete repository suite | **64 passed** |
| Python compilation | Passed |
| `git diff --check` | Passed |
| Final crAPI safe scan | 51 discovered; 42 tested; 0 confirmed |
| Final crAPI non-baseline active findings | **0** |

The test suite still emits deprecation warnings for `datetime.utcnow()`, ReportLab compatibility, and optional PyArrow support. These warnings did not cause test failures and should be addressed separately as maintenance work.

## Capability Boundary

The platform currently tests selected SQLi, reflected XSS, command injection, LFI, BOLA/IDOR, authentication weakness indicators, GraphQL introspection, missing security headers, verbose errors, and sensitive data patterns. It does not yet provide complete coverage for stored or DOM XSS, CSRF, file upload, brute force, open redirects, blind SQLi, JWT/token manipulation, SSRF, XXE, insecure deserialization, rate limiting, mass assignment, broken object-property authorization, or business-logic abuse. The detailed matrix and prioritized roadmap are in [`CAPABILITY_GAP_ASSESSMENT.md`](CAPABILITY_GAP_ASSESSMENT.md).

The most important next function is an authenticated, specification-driven scan mode with disposable account profiles. That foundation is required for reliable authorization testing and should be followed by differential proof analysis, browser-assisted DOM coverage, safe workflow/state modeling, asynchronous scheduling, and labeled ML evaluation. The scanner should continue to keep deterministic proof separate from ML triage signals.

## Conclusion

The tool is substantially more accurate and safer than the starting implementation. Its confirmed findings now correspond to manually reproducible evidence, its suspected findings are not promoted into confirmed totals, and target-specific behavior is handled rather than hidden behind generic payloads. The current evidence supports calling it a **credible bounded proof-of-concept scanner for selected API and web checks**, not a complete vulnerability assessment platform. The remaining gaps are clearly defined, and the reports in this repository provide the basis for the next development cycle.

## References

[1]: https://github.com/m-zohaibk/api-security-platform "API Security Platform repository"
[2]: TESTASP_SCORE_COMPARISON_REPORT.md "testasp score comparison report"
[3]: DVWA_ACCURACY_VERIFICATION_REPORT.md "DVWA accuracy verification report"
[4]: DVWA_LFI_VERIFICATION_SUMMARY.md "DVWA LFI verification summary"
[5]: DVGA_CROSS_SITE_VERIFICATION_SUMMARY.md "DVGA GraphQL verification summary"
[6]: CRAPI_VERIFICATION_SUMMARY.md "crAPI verification summary"
[7]: CAPABILITY_GAP_ASSESSMENT.md "capability and gap assessment"
[8]: tests/dvwa_manual_confirmations.json "DVWA manual confirmation artifact"
[9]: tests/dvga_manual_results.json "DVGA manual verification artifact"
[10]: tests/crapi_login_manual_sql_results.json "crAPI credential SQLi artifact"
