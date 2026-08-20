# Strix Feature Comparison and Adaptation Report

**Compared project:** [`usestrix/strix`](https://github.com/usestrix/strix)
**Current platform:** [`m-zohaibk/api-security-platform`](https://github.com/m-zohaibk/api-security-platform)
**Review date:** 2026-08-21
**Strix revision reviewed:** Public `main` shallow clone at commit `deb2057`
**Strix license:** Apache License 2.0

## Executive Summary

Strix is broader than the current platform, but it is also a different class of system. The current project is a deterministic HTTP/API scanner with explicit proof gates, while Strix is an autonomous AI penetration-testing framework with a multi-agent runtime, browser and proxy tools, terminal/Python execution, code analysis, local run state, and developer workflow integrations.

The most valuable compatible ideas are the **API-spec-first inventory**, **structured proof-oriented findings**, **SARIF/CI output**, **rate-limit and retry safety**, and **clear separation between validated findings and triage observations**. The current implementation already had several of these foundations, so the adaptation focused on low-risk, independently implemented reporting and workflow improvements rather than copying Strix’s autonomous exploit runtime.

## Verified Strix Capability Comparison

| Strix capability | Current platform status | Adaptation decision |
|---|---|---|
| OpenAPI/Swagger/Postman-driven API testing | OpenAPI/Swagger parsing exists; Postman and full contract inventory are not yet supported. | Continue improving the existing independent OpenAPI inventory. Add operation IDs, auth schemes, `$ref` resolution, and coverage tracking next. |
| Structured validated findings with proof-of-concept details | Current findings store category, status, severity, score, payload, response metadata, proof text, and recommendation. | Extended machine-readable reporting through SARIF with evidence, status, endpoint location, severity, and stable fingerprints. |
| SARIF and CI-friendly reporting | Previously absent as a dedicated export. | Added an independent SARIF 2.1.0 exporter and dashboard `format=sarif` route. The CLI now accepts `--sarif-output`. |
| Headless execution and non-zero vulnerability exit code | CLI existed, but it did not return a confirmed-finding exit status. | Added return of confirmed count and exit code `1` when confirmed vulnerabilities are found, enabling CI gating. |
| Browser automation | Not available in the deterministic HTTP core. | Not copied. Browser execution is a separate subsystem needed for DOM XSS, CSRF, SPA route discovery, and JavaScript redirects. |
| HTTP interception proxy | Not available as a full proxy. | Not copied. The current request engine remains simpler and easier to audit; proxy integration should be a separately scoped feature. |
| Shell and Python exploit runtime | Command-injection probes exist, but no autonomous post-exploitation runtime. | Not copied. Arbitrary shell execution would materially increase safety and authorization risk. |
| Multi-agent orchestration | ML/DL triage layers exist, but no autonomous agent graph. | Deferred. Deterministic proof must remain authoritative; an agent layer should be added only after scope, budgets, sandboxing, and cleanup controls exist. |
| Reconnaissance and OSINT | Basic endpoint discovery and common-path probing exist. | Improve within authorized scope through subdomain/spec inventories and route fingerprinting; do not add open-ended internet reconnaissance by default. |
| SAST plus DAST | Current platform is primarily DAST with ML/DL response analysis. | SAST is a future module requiring source ingestion, language parsers, and separate findings/provenance models. |
| CVSS/OWASP classification | OWASP-related categories and risk scores exist, but CVSS vectors are not complete. | Add normalized CWE/OWASP mappings and optional CVSS 3.1 vectors to structured findings. |
| Authentication and session workflows | Limited bearer and credential-route checks exist; no full lifecycle. | Prioritize disposable auth profiles, cookie/token capture, refresh handling, and multi-principal authorization tests. |
| Business-logic and workflow testing | Not implemented as a state machine. | Add explicit opt-in workflows with disposable accounts, invariants, rollback, and request budgets. |
| Rate-limit and retry handling | Bounded active concurrency exists, but no full Retry-After/adaptive-backoff policy. | Add per-host budgets, Retry-After parsing, adaptive backoff, and a low-volume rate-limit observation mode. |
| Local viewer and run history | Flask dashboard and persisted SQLite sessions exist. | Preserve the existing dashboard; add SARIF and richer evidence links rather than replacing it. |
| Auto-fix and pull requests | Not implemented. | Defer until findings include reliable source locations and a validated remediation workflow. Never auto-apply changes based only on an unconfirmed finding. |

## Implemented Adaptations

### Structured SARIF reporting

The new `reports/sarif_exporter.py` is an independent implementation inspired by Strix’s documented SARIF/reporting capability. It emits SARIF 2.1.0 with a tool driver, normalized rule IDs, endpoint logical locations, severity levels, finding status, confirmation state, proof/evidence text, response metadata, request payload, stable partial fingerprints, and session-level scan properties.

The dashboard can export a session through `/export/<session_id>?format=sarif`. The command-line interface accepts:

```bash
python3 main.py --url https://authorized-target.example --sarif-output reports/findings.sarif
```

The CLI returns exit code `1` when the scan completes with one or more confirmed vulnerabilities and returns success when no confirmed vulnerabilities are present. This makes the tool usable as a CI gate without treating suspected or informational observations as confirmed failures.

### API specification and payload coverage

The current platform now extracts documented query parameters and JSON request-body property names from OpenAPI operations. It preserves these fields during endpoint deduplication and binds probes to documented fields instead of sending generic payloads to an arbitrary parameter. This is a conservative adaptation of Strix’s spec-driven testing principle, implemented independently in the existing discovery/request architecture.

### Authorization-oriented route coverage

Discovered `/users/`, `/accounts/`, and `/profiles/` object routes now receive a bounded pair of distinct object-ID probes. The existing proof gate remains unchanged: a numeric path or successful response is not enough. A confirmed BOLA/IDOR result still requires sensitive object data and an unauthenticated context. Full multi-principal BOLA remains a future feature.

## Validation Results

The updated repository passes **72 automated tests**, including the SARIF exporter, dashboard export path, proof/status serialization, stable fingerprints, CLI help exposure, OpenAPI field binding, BOLA route selection, redirect proof, and the existing accuracy regressions.

The open-redirect capability was manually and automatically tested against the authorized DVWA training target. The manual response returned HTTP 302 with an external `Location` header, and the scanner produced a confirmed `Open_Redirect` finding with the same destination. Existing DVWA command-injection, reflected-XSS, and LFI proof behavior remains covered by the prior authorized training-target verification.

A bounded live test of the full CLI against testasp was attempted for SARIF artifact generation but the public target’s discovery phase exceeded the 120-second test bound before completion. This is a known discovery-performance limitation; the SARIF serializer itself is covered by unit tests, and the successful target-level scanner tests use the same persistence and detection pipeline. The performance limitation does not invalidate the report format.

## Features Not Copied and Why

The Strix README and documentation describe browser exploitation, terminal execution, custom Python exploit development, autonomous multi-agent coordination, source-aware SAST/DAST, post-exploitation, auto-fix, and continuous cloud workflows. These capabilities are materially larger and carry more safety, authorization, dependency, and maintenance risk than a direct feature addition to this project. They should not be copied piecemeal without a sandbox, explicit rules of engagement, user approval for state changes, request/time budgets, secret isolation, cleanup, and a separate threat model.

The user’s platform should remain **proof-first**: LLM or agent reasoning may generate hypotheses or prioritize routes, but only deterministic request/response evidence should promote a finding to confirmed. This preserves the accuracy improvements achieved during testasp, DVWA, DVGA, and crAPI validation.

## License and Attribution

Strix is distributed under Apache License 2.0. This repository did not copy Strix source code. The SARIF exporter and related CLI/dashboard changes are independent implementations of broadly documented interoperability ideas. This report records Strix as the inspiration and source of the comparison. If future work copies or adapts Strix source files, the project must retain the Apache-2.0 license, preserve applicable notices, identify modified files, and review any transitive third-party licenses.

## Recommended Next Improvements

The highest-value next step is authenticated, specification-driven scanning. The platform should add operation IDs, `$ref`/`allOf` schema resolution, auth requirements, coverage status, and disposable multi-principal profiles. The second step is rate-limit/retry safety: parse `Retry-After`, cap per-host request budgets, add adaptive backoff, and report inconclusive rate-limit observations without converting them into vulnerabilities. The third step is optional browser/network-log integration for DOM XSS, CSRF, JavaScript redirects, and SPA route discovery. The fourth step is normalized CWE/OWASP/CVSS metadata and richer remediation evidence.

## References

[1]: https://github.com/usestrix/strix "Strix official repository and README"
[2]: https://github.com/usestrix/strix/blob/main/LICENSE "Strix Apache License 2.0"
[3]: https://docs.strix.ai/ "Strix official documentation"
[4]: https://github.com/m-zohaibk/api-security-platform "Current API Security Platform repository"
[5]: https://owasp.org/API-Security/ "OWASP API Security project"
