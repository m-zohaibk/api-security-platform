# Latest API Security Platform Capability and Gap Assessment

**Repository:** [`m-zohaibk/api-security-platform`](https://github.com/m-zohaibk/api-security-platform)
**Assessment date:** 2026-08-21
**Assessment scope:** Current working version after the repository cleanup and the open-redirect capability improvement
**Automated validation:** **71 tests passed**

## Executive Assessment

The previous gap assessment was substantially accurate about the scanner’s proof-oriented design and its major missing capabilities, but it was not fully current. In particular, it still described the scanner as sequential and listed open-redirect detection as missing. The current version uses bounded active-probe concurrency, preserves redirect responses when required, and now confirms external open redirects from an untrusted `Location` header. This document replaces the previous assessment and should be treated as the current capability baseline.

The platform is a **proof-oriented API and web-application scanner**, not yet a complete authenticated API security platform. It is strongest when a vulnerability can be established from a deterministic HTTP response marker. Confirmed findings require proof such as a database error, explicit delay response, unescaped reflection, command output, local-file content, or an external redirect response. Payload syntax, anomaly scores, and missing headers remain separate from confirmed vulnerability counts.

The current implementation has been verified on authorized training targets. It confirmed command injection and reflected XSS on DVWA, confirmed LFI on DVWA, confirmed an external open redirect on the DVWA training endpoint, detected GraphQL introspection as informational on DVGA, matched the testasp manual score, and completed a safe-mode crAPI assessment without confirmed active-probe findings. The repository’s complete test suite now passes **71 tests**.

## What Changed Since the Previous Assessment

| Previous assessment statement | Current status |
|---|---|
| Active scanning was sequential and slow. | Updated. Active probes now use bounded concurrency controlled by `ACTIVE_CONCURRENCY`, defaulting to four workers. Detection and persistence remain sequential. |
| Open redirect was missing. | Updated. External redirects are tested with `follow_redirects=False` and confirmed only from an external 3xx `Location` header. |
| Redirect evidence was not preserved. | Updated. The request engine now accepts an explicit `follow_redirects` option for synchronous and asynchronous requests. |
| Redirect routes were not reliably selected. | Updated. Paths containing `open_redirect`, `redirect`, or a discovered `redirect` query field route to the dedicated probe. |
| The report described only the earlier 64-test state. | Updated. The latest suite contains **71 passing tests**, including redirect transport, proof, routing, schema-binding, and BOLA-selection regressions. |

The repository cleanup removed older session-history reports and raw exploratory artifacts. The retained documents are the final accuracy report, this capability assessment, and the performance report. The current regression source remains [`tests/test_accuracy_regressions.py`](tests/test_accuracy_regressions.py), and the focused scan harness remains [`tests/targeted_main_scan.py`](tests/targeted_main_scan.py).

## Current Capability Matrix

| Capability | Current implementation | Current verification | Remaining boundary |
|---|---|---|---|
| Endpoint discovery | Crawls HTML, parses OpenAPI/Swagger when available, extracts documented query and JSON fields, probes common paths, records forms, merges duplicate metadata, and applies `MAX_ENDPOINTS`. | Exercised across DVWA, DVGA, testasp, and crAPI; schema-binding is regression-tested. | Dynamic JavaScript routes, authenticated routes, and API routes revealed only after workflow actions may be missed. |
| HTTP transport | Supports GET, POST, PUT, PATCH, DELETE, named query/form/JSON fields, empty JSON objects, custom headers, async requests, and explicit redirect-following control. | Regression-tested and used on real training targets. | No persistent connection pool across all sync requests; discovery remains mostly sequential. |
| Bounded performance | Active probes are dispatched with bounded concurrency through `ACTIVE_CONCURRENCY`; analysis and SQLite writes remain sequential. | Broader DVWA run completed in 216 seconds with four workers after a prior sequential timeout. | Discovery is still a significant sequential cost; no adaptive host rate control or progress ETA. |
| SQL injection | Tests error-based and selected time-based SQLi, with explicit delay payload requirements and credential/login JSON routing. | Timing false positive removed on DVWA; credential endpoint compared on crAPI. | Blind SQLi differential analysis, broad DBMS payload families, and authenticated parameter coverage are missing. |
| Reflected XSS | Sends method-aware probes to discovered fields and confirms only exact unescaped reflection in HTML/XML. | Confirmed manually and automatically on DVWA. | Stored XSS, DOM XSS, JavaScript-context XSS, attribute-context XSS, CSP bypass, and browser execution are missing. |
| Command injection | Routes command probes to relevant module fields and confirms strong command-output markers or delay evidence. | Confirmed manually and automatically on DVWA using `root:x:0:0:`. | Payload corpus is small; blind command injection and broader OS/shell coverage are missing. |
| Local file inclusion | Sends traversal probes and checks known local-file markers. | Confirmed on DVWA using `/etc/passwd` evidence. | Windows paths, encoding bypasses, wrappers, remote inclusion, and protocol-specific behavior are not covered. |
| Open redirect | Sends an external destination to redirect-like query routes without following the redirect and confirms an external 3xx `Location` header. | Confirmed on DVWA: HTTP 302 to `https://example.com/api-security-redirect-check`. | No redirect-chain policy analysis, JavaScript redirects, meta refresh, encoded bypass matrix, or allowlist-aware validation. |
| BOLA/IDOR | Routes discovered user/account/profile object paths to bounded distinct ID probes and requires sensitive data plus an unauthenticated context before confirmation. | Selection and proof are regression-tested; no unsupported confirmed claim was made on crAPI. | No two-principal ownership model, role comparison, or field-level property authorization. |
| Authentication weakness | Tests limited null/undefined bearer patterns, weak-auth signatures, and credential SQLi routing. | Credential endpoint manually compared on crAPI. | No complete login/session lifecycle, MFA, password reset, token replay, lockout, or session fixation workflow. |
| GraphQL introspection | Discovers `/graphql` and `/graphiql`, sends structured introspection JSON, and classifies schema exposure as informational. | Manually verified on DVGA with 12 query fields. | No field authorization, mutation safety, depth/alias abuse, resolver injection, batching, or GraphQL rate-limit testing. |
| Security misconfiguration | Checks configured security headers and separates observations from confirmed vulnerability totals. | Observed on training targets, including crAPI. | Header policy is generic and does not yet account for route role, TLS policy, browser context, or API-specific risk. |
| Verbose errors | Detects configured stack traces, SQL errors, and runtime exception signatures. | Covered by regression tests and pipeline behavior. | No systematic error-trigger matrix, secret classification, or stack-trace normalization. |
| Sensitive data exposure | Detects configured password, secret, token, and API-key patterns and supports sensitive-data-aware BOLA proof. | Covered by regression tests and used in risk gating. | No entropy analysis, structured secret scanner, PII classification, or response-field sensitivity model. |
| ML/DL triage | Combines Isolation Forest, LSTM, and autoencoder signals in risk scoring. | Pipeline behavior is tested; missing datasets no longer receive fabricated labels. | Models are not evidence of exploitability and are not validated against a representative labeled API corpus. |

## Gap Status and Improvement Method

The following table distinguishes gaps that are still absent from capabilities that are present but incomplete. It also provides a concrete improvement method and a safe testing method rather than only naming the gap.

| Gap | Current status | Improvement method | Safe validation method |
|---|---|---|---|
| Authenticated scanning | Missing | Add disposable account profiles, cookie/token capture, refresh handling, CSRF-token extraction, and explicit read-only/state-changing policies. | Use a disposable account on a local or authorized training target; verify login, authenticated GET, logout, and token refresh without destructive actions. |
| Multi-principal BOLA | Partial only | Model anonymous, user, and administrator principals; compare object ownership and sensitive fields across identities. | Use two disposable accounts and harmless read-only object IDs; confirm only when one principal reads another’s protected object or field. |
| Broken object-property authorization | Missing | Derive writable/read-only fields from OpenAPI and observed JSON; send harmless extra fields and compare accepted properties. | Use a disposable record and non-sensitive canary properties; verify server-side field filtering without persisting harmful changes. |
| Blind SQLi | Partial only | Add repeated controls, median/MAD timing, status/body-shape diffs, stable-size comparisons, and DBMS-specific explicit delay families. | Use DVWA blind-SQLi training mode with bounded probes and no destructive SQL; require repeated differential evidence. |
| Stored XSS | Deliberately skipped by default | Add an opt-in disposable-record workflow, retrieval verification, cleanup, and a hard target-scope guard. | Use only a disposable local/training account and a canary record; verify storage and retrieval, then delete the record. |
| DOM XSS | Missing | Add optional browser instrumentation, network-log import, URL source tracking, and sink detection. | Use a browser-enabled training page with a non-persistent canary and verify DOM execution without stored content. |
| CSRF | Missing | Test Origin/Referer validation, CSRF tokens, SameSite cookies, and safe canary state actions. | Use a disposable account and a harmless state-change endpoint that can be reverted; never submit password, purchase, or deletion actions. |
| File upload | Missing | Add benign file fixtures, content-type mismatch checks, filename/path traversal checks, size limits, and cleanup. | Upload only inert text/image canaries to an authorized lab; verify storage behavior and remove the artifact. |
| Brute force and rate limiting | Missing | Add low-volume policy-aware attempts, backoff, thresholds, and lockout detection. | Use a disposable account, very small request budgets, and stop at the first lockout or rate-limit signal. |
| Redirect chains and browser redirects | Partial | Follow redirect chains in a separate opt-in mode; add JavaScript and meta-refresh analysis and allowlist validation. | Use external canary domains and never follow into private network ranges; classify only controlled redirect destinations. |
| SSRF | Missing | Add an authorized callback collector and safe URL classes; distinguish DNS, HTTP, and internal-address behavior. | Use a dedicated callback endpoint owned by the tester; never probe cloud metadata or private infrastructure without explicit authorization. |
| XXE | Missing | Add content-type-aware XML probes with external entity disabled/enabled comparisons and safe local canaries. | Use a local or training parser target and a non-sensitive canary file; do not read host secrets. |
| Insecure deserialization | Missing | Add format detection and benign serialized-object canaries with strict content-type routing. | Use isolated training targets and harmless object markers; never execute arbitrary gadget chains. |
| JWT/token manipulation | Missing | Parse claims, mutate `alg`, expiry, issuer, audience, and signature fields, then replay against read-only endpoints. | Use disposable tokens on an authorized lab; never replay real user tokens or attack production identity providers. |
| Mass assignment | Missing | Use OpenAPI/JSON schemas to identify server-managed fields and send harmless unknown properties. | Use disposable records and canary fields; verify whether unauthorized fields are accepted without harmful state changes. |
| API rate limiting | Missing | Measure requests per route with controlled concurrency, Retry-After handling, and per-account budgets. | Use low request counts on training targets and stop on a 429, lockout, or service degradation signal. |
| Business-logic abuse | Missing | Add explicit state machines, invariants, transaction limits, and rollback/cleanup hooks. | Validate only on disposable accounts and reversible training workflows; do not test purchases, transfers, or deletion on shared public labs. |
| GraphQL authorization and abuse | Partial introspection only | Add schema-driven field authorization, mutation classification, query depth, aliases, batching, and resolver timing checks. | Use read-only queries and bounded depth/alias counts against DVGA or a local clone. |
| Browser and SPA coverage | Partial shell detection only | Add optional browser crawling and import of browser network logs while retaining deterministic HTTP verification. | Use a sandbox browser session and non-persistent payloads; keep browser execution separate from confirmed server-side proof. |
| ML/DL validation | Triage only | Build a labeled corpus containing vulnerable and clean API responses, calibrate thresholds, and report confidence intervals. | Evaluate offline against fixed training/validation/test splits; never let an unvalidated model promote a finding to confirmed. |

## Improvements Implemented and Tested in the Current Version

The current version includes proof-gated confirmed counts, explicit suspected wording, form-aware payload binding, method-aware routing, GraphQL-specific probing, LFI proof checks, credential SQLi routing, SPA-shell suppression, blocked-response gates, and bounded active-probe concurrency.

The latest improvement adds open-redirect capability. The request engine can now preserve a 3xx response by disabling redirect following for a specific probe. Redirect-like paths and discovered `redirect` query fields receive an external destination canary. The signature layer confirms the finding only when the response is a 3xx and its `Location` header resolves to a different host. Relative redirects and payload syntax without an external `Location` remain suspected.

The improvement was tested against the authorized DVWA training endpoint. A manual request returned HTTP 302 with:

```text
Location: https://example.com/api-security-redirect-check
```

The improved scanner reproduced the same behavior and persisted one confirmed `Open_Redirect` finding with the same external destination. The same release also adds OpenAPI request-body field extraction and bounded BOLA probes for discovered user/account/profile object routes. Focused and full regression coverage increased the suite from 64 to **71 passing tests**, including transport preservation, external-location proof, relative-redirect non-confirmation, redirect-route selection, schema-aware JSON binding, and BOLA route selection.

## Priority Roadmap

The highest-priority improvement is **authenticated, specification-driven scanning**. OpenAPI input, disposable account profiles, and multiple principals would unlock reliable BOLA, broken-property authorization, mass assignment, JWT, and business-logic testing. This should be implemented before adding a large number of unrelated payload signatures.

The second priority is **differential proof quality**. Repeated controls, response fingerprints, timing statistics, status transitions, and structured field diffs should become first-class evidence objects. Blind SQLi, rate limiting, SSRF, redirect chains, and authorization checks all depend on this foundation.

The third priority is **safe workflow orchestration**. Add per-host rate limits, adaptive backoff, scan cancellation, discovery concurrency, authenticated cleanup, and explicit approval gates for state-changing tests. The current active-probe concurrency improves runtime, but discovery remains predominantly sequential.

The fourth priority is **browser and model validation**. Browser instrumentation is needed for DOM XSS and SPA network discovery. A labeled dataset is needed before ML/DL outputs can be treated as anything more than triage signals.

## Conclusion

The previous gap assessment was directionally correct but stale in two important areas: it did not include open-redirect detection, and it described the scanner as sequential after bounded concurrency had been implemented. This replacement is the current assessment for the latest version.

The scanner now covers selected SQLi, credential SQLi routing, reflected XSS, command injection, LFI, open redirects, limited BOLA/IDOR, authentication weakness indicators, GraphQL introspection, security headers, verbose errors, and sensitive-data patterns. It remains incomplete for authenticated authorization, blind/differential testing, browser-only behavior, stateful business logic, SSRF, file upload, JWT, rate limiting, and other advanced API risks. The recommended method is to improve those areas through authenticated disposable workflows, specification-driven inputs, differential proof objects, strict safety policies, and target-specific regression tests.

## References

[1]: https://github.com/m-zohaibk/api-security-platform "API Security Platform repository"
[2]: https://owasp.org/API-Security/ "OWASP API Security project"
[3]: https://owasp.org/API-Security/editions/2023/en/0x11-t10/ "OWASP API Security Top 10 2023"
[4]: https://owasp.org/www-project-vulnerable-web-applications-directory/ "OWASP Vulnerable Web Applications Directory"
[5]: FINAL_ACCURACY_AND_VERIFICATION_REPORT.md "Final accuracy and cross-target verification report"
[6]: DVWA_PERFORMANCE_IMPROVEMENT_REPORT.md "DVWA performance improvement and accuracy verification"
[7]: tests/test_accuracy_regressions.py "Current accuracy regression tests"
[8]: tests/targeted_main_scan.py "Targeted full-pipeline scan harness"
