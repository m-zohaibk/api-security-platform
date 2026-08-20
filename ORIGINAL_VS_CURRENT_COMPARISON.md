# Original Git Baseline vs Current API Security Platform

**Repository:** [`m-zohaibk/api-security-platform`](https://github.com/m-zohaibk/api-security-platform)
**Original baseline:** initial Git commit `582420c`
**Current version:** `main` at commit `a908c5f`
**Comparison date:** 2026-08-21
**Current validation:** 72 automated tests passed

## Executive Summary

This comparison uses the **exact first Git commit** from the repository shared at the beginning of the work, not the later gap-assessment wording. The original project already had a useful three-layer architecture: signature detection, Isolation Forest anomaly detection, and PyTorch LSTM/autoencoder analysis. However, its live scan pipeline performed one baseline request per discovered endpoint, did not actively bind vulnerability payloads to real form/API fields, followed redirects by default, promoted anomaly scores or signatures into vulnerability counts without a strict proof gate, and had only 20 automated tests.

The current version is a substantially more accurate and operationally useful scanner. It retains the original ML/DL triage architecture but adds specialized active probing, proof-gated confirmation, form and OpenAPI field binding, bounded concurrency, GraphQL and open-redirect handling, safer response gates, structured SARIF output, CI exit behavior, and extensive regression coverage. It is still not a complete authenticated penetration-testing platform.

## Capability Comparison

| Area | Original Git baseline (`582420c`) | Current version (`a908c5f`) | Change |
|---|---|---|---|
| Core architecture | Three layers: regex/signature detection, Isolation Forest, and LSTM/autoencoder scoring. | Same three layers retained, with the signature/proof layer authoritative for confirmed findings and ML/DL used as triage signals. | **Accuracy-preserving architecture improvement.** |
| Endpoint discovery | HTML/OpenAPI-style discovery existed, but the main pipeline tested every discovered endpoint with a single baseline request. | Discovery records form methods/defaults/fields, query fields, OpenAPI query fields, JSON body properties, GraphQL paths, and redirect routes; duplicate metadata is merged. | **Much more actionable endpoint inventory.** |
| Endpoint count behavior | No safe, explicit production scan budget in the main pipeline; discovery/testing behavior caused the user-visible mismatch between many discovered endpoints and only a small effective test set. | `MAX_ENDPOINTS` is explicit and configurable, defaulting to 20; the user can raise it for uncapped-by-policy assessments, such as `MAX_ENDPOINTS=100`. | **Predictable coverage and runtime control.** |
| HTTP methods and payload placement | Requests used generic query key `q` for GET/DELETE and raw body data for POST/PUT/PATCH; empty JSON objects were not preserved correctly. | Supports named query, form, and JSON fields; preserves explicit empty `{}` payloads; respects discovered form methods; binds OpenAPI JSON probes to documented properties. | **Major reduction in “payload sent to the wrong place” false negatives.** |
| Redirect handling | `httpx.Client(..., follow_redirects=True)` always followed redirects, making the original 3xx evidence unavailable. | Redirect following is opt-in per request; open-redirect probes preserve the original 3xx and external `Location` header. | **New reliable open-redirect proof.** |
| Active probing | Baseline-only endpoint inspection in the original main loop; no module-specific queue routing. | Specialized queues for SQLi, credential SQLi, reflected XSS, command injection, LFI, GraphQL introspection, BOLA/IDOR, open redirect, authentication checks, and baseline inspection. | **Changed from passive baseline scoring to targeted active assessment.** |
| Form testing | Did not reliably connect payloads to the actual vulnerable form field. | Extracts real form fields/defaults/methods and binds payloads to fields such as DVWA `ip`, `name`, `id`, and search parameters. | **Verified improvement on DVWA.** |
| SQL injection | Generic signature/anomaly behavior with no credential-specific JSON route and weaker timing proof controls. | Error-based and selected time-based SQLi; explicit delay payload requirement; credential/login JSON SQLi route; status/error gates. | **Fewer time-based and credential-route false positives.** |
| Reflected XSS | Generic detection without robust method-aware field routing. | GET-only routes receive GET XSS probes; POST forms receive POST probes; confirmation requires exact unescaped reflection in the response. | **Confirmed manually and automatically on DVWA.** |
| Command injection | Baseline signature support existed, but no reliable module-specific form routing. | Routes probes to command-injection modules and confirms strong output markers such as `root:x:0:0:` or controlled delay evidence. | **Confirmed manually and automatically on DVWA.** |
| Local file inclusion | Not present as a dedicated detector in the original signature categories. | Dedicated LFI traversal probe and proof verifier for local-file markers. | **New capability; confirmed on DVWA.** |
| Open redirect | Not present. | Dedicated external-destination probe, redirect-preserving transport, route selection, and external-host proof. | **New capability; confirmed on DVWA.** |
| GraphQL | No dedicated GraphQL path/probe/category in the original baseline. | Discovers `/graphql` and `/graphiql`, sends structured introspection JSON, retains 400 JSON responses, and classifies introspection as informational rather than a confirmed vulnerability. | **New capability; manually verified on DVGA.** |
| BOLA/IDOR | Existing category, but original confirmation logic could over-rely on numeric URL patterns and did not require the same sensitive-data/unauthenticated proof discipline. | Requires sensitive data plus unauthenticated context; user/account/profile routes receive bounded distinct object-ID probes. | **Accuracy and coverage improvement; full two-principal testing remains missing.** |
| Authentication and credential routes | Existing limited authentication signatures, but no dedicated credential SQLi routing. | Adds credential/login JSON SQLi probes and preserves suspected-versus-confirmed status. | **Improved credential endpoint coverage.** |
| Response gates | Error/network statuses could be interpreted as findings; blocked statuses were not consistently excluded. | Gates 401/403/404/405 and unsuitable 5xx/SPA-shell responses from unsupported vulnerability proof; payload-triggered disconnects become suspected application resets rather than confirmed vulnerabilities. | **Major false-positive reduction.** |
| Security-header findings | Missing headers could increase vulnerability totals through general scoring. | Header observations are persisted as informational/triage signals and do not inflate confirmed vulnerability counts. | **Clearer risk semantics.** |
| Risk aggregation | Suspected signatures and ML/DL anomalies could be promoted into confirmed vulnerability counts; proof wording could claim verification incorrectly. | Only proof-backed results are confirmed; suspected results retain cautious wording; only confirmed results increment the vulnerability total. | **Core accuracy fix.** |
| SPA-heavy applications | No shell-response suppression, so frontend HTML could create noisy API findings. | Detects frontend shell markers and suppresses active probes when the route is only an SPA shell, while preserving genuine reflected payloads. | **Improved crAPI accuracy and runtime.** |
| Active-probe performance | Requests were sequential. A broader DVWA run exceeded the time bound. | Bounded `ThreadPoolExecutor` active-probe concurrency controlled by `ACTIVE_CONCURRENCY`, default four workers; analysis and persistence remain sequential and deterministic. | **Broader DVWA run completed in 216 seconds after a previous sequential timeout.** |
| Request timeout configuration | Discovery did not consistently receive the configured scan timeout. | `SCAN_TIMEOUT` is passed through discovery and request paths; endpoint caps and concurrency are explicit. | **Predictable bounded execution.** |
| Reporting | JSON, HTML, and PDF exports existed, but evidence/status interoperability was limited. | Adds SARIF 2.1.0 with rule IDs, endpoint logical locations, proof text, status, confirmed flag, response metadata, request payload, and stable fingerprints. | **New CI/security-tool integration.** |
| Headless CI behavior | CLI ran scans but had no dedicated SARIF output flag or confirmed-finding exit status. | `--sarif-output PATH` writes SARIF; CLI exits with code 1 when confirmed vulnerabilities exist and succeeds when none are confirmed. | **New CI gating capability.** |
| Automated tests | **20 tests passed** in the exact original worktree. | **72 tests passed** in the current version, including 52 additional tests and broad accuracy regressions. | **3.6× the original test count.** |
| Real-target verification | No documented manual-versus-scanner cross-target verification. | DVWA: command injection, reflected XSS, and LFI; DVGA: informational GraphQL introspection; testasp: score comparison; crAPI: safe-mode endpoint assessment; DVWA open redirect: manual and scanner match. | **Evidence-based validation added.** |
| Machine-learning validation | ML/DL existed but missing datasets could be treated as a fallback rather than an explicit unavailable state. | Missing datasets remain `null` rather than fabricated labels; ML/DL cannot promote a finding without deterministic proof. | **More honest model reporting.** |

## What the Original Version Could Test

The initial baseline’s signature layer included SQL injection, command injection, BOLA/IDOR, authentication weakness, security misconfiguration, verbose error exposure, and sensitive-data patterns, with the three-layer ML/DL scoring pipeline. It had basic report exporters and a Flask dashboard. These were meaningful foundations, but the original live pipeline did not yet provide the field-aware, proof-oriented active testing needed to reliably exercise real training targets.

## What the Current Version Can Test

The current platform tests selected error/time-based SQL injection, credential/login SQL injection, reflected XSS, command injection, LFI, open redirects, limited BOLA/IDOR, authentication weakness indicators, GraphQL introspection, security-header observations, verbose errors, sensitive-data patterns, and SPA-shell behavior. It also supports OpenAPI query/JSON field extraction, bounded active concurrency, SARIF export, and CI exit behavior.

Confirmed finding promotion is now intentionally conservative:

> A payload pattern, anomaly score, missing header, or unusual response is not enough to become a confirmed vulnerability. Confirmation requires a deterministic proof marker appropriate to the category.

## Remaining Gaps in the Current Version

| Remaining gap | Current status | Why it remains important |
|---|---|---|
| Authenticated scanning | Missing | Without disposable cookies/tokens and role context, protected routes and authorization flaws cannot be assessed reliably. |
| Multi-principal BOLA/BFLA | Partial | The scanner can send bounded object-ID probes, but it does not compare two user principals or privilege levels. |
| Broken object-property authorization and mass assignment | Missing | OpenAPI fields are extracted, but writable/server-managed field authorization is not tested systematically. |
| Blind SQLi and differential proof | Partial | Selected explicit time-based probes exist, but repeated controls, robust timing statistics, body-shape diffs, and DBMS breadth are incomplete. |
| Stored and DOM XSS | Missing/deliberately skipped | Stored testing needs disposable records and cleanup; DOM XSS needs browser instrumentation. |
| CSRF | Missing | Requires cookie/browser context, Origin/Referer analysis, token validation, and safe reversible state actions. |
| File upload | Missing | Needs inert fixtures, content-type/path checks, size policies, and cleanup. |
| Brute force and rate limiting | Missing | Requires low-volume policy-aware attempts, Retry-After handling, lockout detection, and adaptive backoff. |
| SSRF, XXE, deserialization | Missing | These need isolated callbacks/canaries and stricter authorization boundaries. |
| JWT and session lifecycle | Missing/partial | No full token mutation, refresh, replay, fixation, MFA, password-reset, or logout workflow exists. |
| Browser/SPA behavior | Partial | SPA-shell suppression exists, but DOM sinks, JavaScript redirects, CSRF, and browser network logs do not. |
| GraphQL authorization and abuse | Partial | Introspection is covered, but field authorization, mutations, batching, aliases, depth, and resolver abuse are not. |
| Business logic and race conditions | Missing | Requires explicit state machines, invariants, concurrency experiments, rollback, and cleanup. |
| SAST/source-aware analysis | Missing | The platform is primarily DAST; source locations and code-level dataflow are not modeled. |
| ML/DL evidence validation | Triage only | The models are not trained and calibrated on a representative labeled API vulnerability corpus. |
| Discovery performance | Improved but incomplete | Active probes are concurrent, but discovery remains predominantly sequential and can still time out on slow public targets. |

## Bottom Line

Compared with the exact original Git baseline, the platform has moved from a prototype anomaly/signature scanner to a tested, proof-oriented active API/web scanner with deterministic confirmation, target-aware payload routing, bounded performance, stronger reporting, and real training-target verification. The largest capability increase is not simply the number of signatures; it is the improved reliability of the complete request-to-proof-to-count pipeline.

The most important next development is **authenticated, specification-driven multi-principal testing**. It would unlock reliable BOLA/BFLA, mass assignment, JWT/session testing, and business-logic workflows. The second priority is **differential analysis and rate-limit safety**. Browser automation, SSRF/XXE/file upload, and SAST should follow after authorization, cleanup, and evidence models are established.

## References

[1]: https://github.com/m-zohaibk/api-security-platform "API Security Platform repository"
[2]: https://owasp.org/API-Security/editions/2023/en/0x11-t10/ "OWASP API Security Top 10 2023"
[3]: https://github.com/m-zohaibk/api-security-platform/commit/582420c "Original Git baseline commit"
[4]: https://github.com/m-zohaibk/api-security-platform/commit/a908c5f "Current improved version commit"
