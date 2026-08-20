# API Security Platform Capability and Gap Assessment

**Repository:** [`m-zohaibk/api-security-platform`](https://github.com/m-zohaibk/api-security-platform)
**Assessment date:** 2026-08-20
**Author:** Manus AI

## Executive Assessment

The platform is a useful proof-oriented prototype for bounded API and web-application testing. Its strongest current capability is the separation between **confirmed** and **suspected** findings. A confirmed result requires a concrete response proof such as SQL error text, an explicit time-delay response, verbatim reflected HTML, command output, or local-file content. This design is materially safer than counting payload syntax or model anomaly scores as exploitable vulnerabilities.

The cross-target work demonstrates meaningful coverage. The scanner independently confirmed command injection and reflected XSS on DVWA, detected GraphQL introspection as informational on DVGA, matched the manual and automated score on testasp, and completed a 42-endpoint safe-mode crAPI scan with no confirmed findings. The complete automated suite contains **64 passing tests** after the final changes.

The platform is not yet a full API security testing product. It lacks authenticated session workflows, specification-driven parameter coverage, browser execution, state-aware business-logic checks, robust differential analysis for blind vulnerabilities, and several major API abuse classes. ML and deep-learning layers exist in the architecture, but they should not be described as validated vulnerability detectors until representative labeled training and evaluation datasets are available.

## Current Capability Matrix

| Capability | Current behavior | Verification status | Main boundary |
|---|---|---|---|
| Endpoint discovery | Crawls HTML, parses OpenAPI when available, records methods and form metadata, merges duplicate URL discoveries, and applies a configurable endpoint budget. | Exercised on testasp, DVWA, DVGA, and crAPI. | Dynamic JavaScript routes and undocumented authenticated routes may remain undiscovered. |
| SQL injection | Sends GET/form/JSON SQL probes; checks SQL error signatures and explicit delay payloads such as `SLEEP`, `BENCHMARK`, `pg_sleep`, and `WAITFOR DELAY`. | Timing false positive reproduced and fixed on DVWA; credential probe exercised on crAPI. | No reliable blind differential inference, DBMS-specific depth, or authenticated parameter coverage. |
| Reflected XSS | Sends method-aware payloads and confirms only verbatim reflection in HTML/XML responses. | Confirmed independently on DVWA reflected-XSS module. | Stored, DOM, JavaScript-context, attribute-context, CSP-bypass, and browser-execution cases are not covered. |
| Command injection | Routes command probes to relevant forms/parameters and verifies command output markers or strong execution evidence. | Confirmed independently on DVWA using `root:x:0:0:` proof. | Limited payload set; no broad shell/OS matrix or blind command differential analysis. |
| Local file inclusion | Sends traversal probes and confirms known local-file markers such as `/etc/passwd` content. | Confirmed in the DVWA LFI verification cycle. | No Windows path matrix, wrapper abuse coverage, remote inclusion workflow, or encoding bypass matrix. |
| BOLA/IDOR | Tests selected numeric object suffixes and requires both sensitive-data evidence and an unauthenticated context before confirmation. | Regression-tested; no confirmed crAPI BOLA claim was made without authenticated object pairs. | Requires multiple identities and object ownership context for meaningful authorization testing. |
| Authentication weakness | Exercises limited null/undefined bearer and weak-auth signatures; credential-specific SQLi routing was added. | Credential endpoint manually compared on crAPI. | No complete login/session lifecycle, MFA, password-reset, token replay, or account-lockout workflow. |
| GraphQL introspection | Discovers `/graphql` and `/graphiql`, sends structured introspection JSON, and classifies schema exposure as informational. | Manually verified on DVGA; 12 fields observed and scanner category preserved. | No field-level authorization, mutation safety, depth/alias abuse, resolver injection, or GraphQL rate-limit testing. |
| Security misconfiguration | Checks configured security headers and keeps the observation separate from confirmed exploit counts. | Observed across training targets, including crAPI. | Header policy is generic and should be risk-contextualized by content type, route, TLS, and deployment role. |
| Verbose error exposure | Detects configured stack-trace, SQL error, and runtime exception signatures. | Covered by signature/regression tests. | No systematic error-trigger matrix or sensitive-secret classification beyond configured patterns. |
| Sensitive data exposure | Checks configured password, secret, token, and API-key patterns and supports sensitive-data-aware BOLA proof. | Covered in regression tests and used in risk gating. | Limited pattern language; no entropy analysis, structured secret scanners, or data classification. |
| ML/DL anomaly layers | Combines Isolation Forest, LSTM, and autoencoder signals in the risk scorer. | Pipeline behavior is tested; evaluation fallback no longer fabricates labels when datasets are missing. | Models are not evidence of exploitability and are not presently validated on a representative labeled API corpus. |

## Major Missing or Insufficient Capabilities

| Gap | Why it matters | Required improvement |
|---|---|---|
| Authenticated scanning | Most meaningful API authorization flaws are visible only after login and across more than one identity. | Add disposable-account profiles, cookie/token capture, refresh handling, CSRF-token support, and separate read-only versus state-changing policies. |
| BOLA and broken object-property authorization | Numeric ID probing alone cannot establish ownership or field-level authorization. | Model principals, object owners, roles, response diffs, and sensitive-field access across at least two identities. |
| Blind SQL injection | Absence of an error message does not prove absence of injection. | Add baseline repetition, control/payload pairs, stable timing statistics, status/body-shape diffs, and DBMS-specific payload families. |
| Stored XSS | Persistence and later rendering are distinct from immediate reflection. | Add an opt-in disposable-record workflow, retrieval verification, cleanup, and strict target-scope safeguards. |
| DOM XSS | The vulnerability may exist only after client-side JavaScript executes. | Add browser instrumentation, sink/source tracing where possible, and a non-persistent payload corpus. |
| CSRF | APIs using cookies or browser sessions may accept cross-origin state changes. | Add origin/referrer checks, CSRF-token validation, same-site cookie analysis, and safe canary actions. |
| File upload | Upload handlers commonly expose parser, path, content-type, and storage weaknesses. | Add controlled benign files, polyglot checks, filename/path traversal probes, size limits, and cleanup. |
| Brute force and rate limiting | Abuse resistance requires repeated controlled requests and account lockout/rate-limit measurement. | Add a low-volume policy-aware test with explicit thresholds, backoff, and opt-in authorization. |
| Open redirect | Redirect validation requires following and classifying `Location` responses. | Add external-origin canaries, relative/encoded redirect payloads, and redirect-chain proof. |
| SSRF | Server-side URL fetches need an out-of-band or controlled callback proof. | Add an authorized callback collector and safe internal-address test policy. |
| XXE and insecure deserialization | These depend on parser formats and server-side object handling not represented by generic JSON probes. | Add content-type-aware XML and serialized-object probes with non-destructive canaries. |
| JWT and token manipulation | Weak signing, `alg:none`, key confusion, expiry, audience, issuer, and replay defects need token lifecycle analysis. | Add a token parser, controlled mutation engine, claims validation, and authenticated replay checks. |
| Mass assignment | Extra writable properties may alter authorization or business state. | Derive schemas from OpenAPI and observed objects; send harmless unknown/read-only fields and compare responses. |
| API version and shadow endpoints | Deprecated or undocumented versions may expose weaker controls. | Improve specification comparison, version enumeration, route fingerprinting, and authorization parity checks. |
| Business-logic abuse | Coupon, purchase, transfer, feedback, and workflow flaws require state and invariants rather than signatures. | Add explicit state models, test accounts, transaction limits, and cleanup/rollback hooks. |
| Browser and JavaScript coverage | SPA shells can hide API routes and DOM-only behavior. | Add optional browser crawling and network-log import while keeping the core HTTP scanner deterministic. |

## Accuracy Improvements Completed in This Work

The initial implementation had several accuracy defects that were exposed by real training-target testing. Risk aggregation promoted suspected signatures into confirmed totals; proof wording claimed verification where no proof existed; BOLA relied too heavily on numeric paths; empty JSON objects were not transmitted; blank query parameters were dropped from model features; pipeline counts included non-confirmed results; evaluator fallback fabricated labels when datasets were absent; and OWASP coverage was hardcoded rather than derived from detector output.

Target-driven testing exposed further defects. The endpoint cap was not consistently enforced, discovery did not pass the scan timeout, BOLA suffixes could be appended to query-bearing URLs, duplicate URL discovery could discard form metadata, payloads were not bound to real form fields, form methods and hidden defaults were lost, generic routing crossed attack categories, and stored XSS was unsafe for a shared public target. These were corrected with metadata merging, field-aware request binding, method-aware module routing, category-aware verification, and an explicit skip for persistent probes.

DVWA testing also exposed a false time-based SQLi confirmation caused by ordinary latency and a command-injection payload classified through overlapping SQL rules. The timing verifier now requires an explicit delay expression in the payload, and expected attack categories are passed through the queue. DVWA LFI support was added with local-file proof markers, and connection resets after a healthy baseline are preserved as suspected application-impact observations rather than being silently treated as network failures.

DVGA testing exposed that GraphQL was not discovered or tested as GraphQL. The scanner now recognizes `/graphql` and `/graphiql`, retains structured 400 JSON responses as valid API endpoints, submits a structured introspection query, avoids generic REST payloads on GraphQL routes, and stores introspection as informational rather than confirmed vulnerability evidence.

crAPI testing exposed credential-route coverage, SPA-shell false positives, case-sensitive header handling, GET-only XSS method errors, and 405 response noise. Credential SQLi routing, generalized case-normalized shell detection, baseline shell short-circuiting, method-aware XSS dispatch, and a 405 blocked-response gate were added. The final safe scan therefore recorded only baseline header observations and no active-probe false positives.

## Recommended Development Roadmap

The first priority should be **authenticated, specification-driven scanning**. The platform should accept an OpenAPI document, derive parameter locations and schemas, and optionally run with disposable accounts representing anonymous, ordinary-user, and administrator roles. This foundation enables meaningful BOLA, broken property authorization, mass assignment, JWT, and business-logic testing.

The second priority should be **differential proof quality**. Every active probe should have repeated controls, stable response fingerprints, and a proof object that records the exact status, timing distribution, response-size delta, content-type change, and matched marker. Blind SQLi, SSRF, open redirect, rate-limit, and DOM XSS support should build on this evidence model rather than on regex matches alone.

The third priority should be **safe workflow and performance engineering**. Async request scheduling, per-host concurrency limits, adaptive backoff, route-level budgets, authentication-aware cleanup, and explicit state-change approvals would make larger assessments practical without weakening safety. The current sequential design is reliable for bounded training scans but slow on public targets.

The fourth priority should be **model validation and reporting maturity**. A representative labeled dataset should be assembled from intentionally vulnerable applications and clean controls. ML/DL outputs should be calibrated against that dataset, reported as triage signals, and never allowed to promote a result without deterministic proof. Reports should distinguish coverage, attempted checks, blocked checks, inconclusive checks, suspected observations, and confirmed vulnerabilities.

## Conclusion

The platform has reached a credible proof-of-concept level for selected unauthenticated API and web checks. It now demonstrates evidence-backed confirmation for DVWA command injection, reflected XSS, and LFI; correct informational handling of DVGA introspection; safe, uncapped read-only coverage on crAPI; and regression protection against the major accuracy defects found during testing. Its principal gap is not another regex rule but the absence of authenticated, state-aware, specification-driven testing. That should be the central direction for the next version.

## References

[1]: https://github.com/m-zohaibk/api-security-platform "API Security Platform repository"
[2]: https://owasp.org/API-Security/ "OWASP API Security project"
[3]: https://owasp.org/API-Security/editions/2023/en/0x11-t10/ "OWASP API Security Top 10 2023"
[4]: https://owasp.org/www-project-vulnerable-web-applications-directory/ "OWASP Vulnerable Web Applications Directory"
[5]: ACCURACY_FIX_REPORT.md "Initial accuracy fix report"
[6]: DVWA_ACCURACY_VERIFICATION_REPORT.md "DVWA verification report"
[7]: DVWA_LFI_VERIFICATION_SUMMARY.md "DVWA LFI verification summary"
[8]: DVGA_CROSS_SITE_VERIFICATION_SUMMARY.md "DVGA GraphQL verification summary"
[9]: CRAPI_VERIFICATION_SUMMARY.md "crAPI verification summary"
