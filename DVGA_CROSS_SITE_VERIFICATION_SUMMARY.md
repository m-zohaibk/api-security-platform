# DVGA Cross-Site Verification Summary

**Previously unused target:** [https://pentest-ground.com:5013](https://pentest-ground.com:5013)
**Application:** Damn Vulnerable GraphQL Application (DVGA)
**GraphQL endpoint:** `https://pentest-ground.com:5013/graphql`

## Summary

This was a new target; the earlier DVWA and testasp targets were not reused. The DVGA landing page identifies the service as a deliberately vulnerable GraphQL implementation for safe learning and security-tool testing. The official OWASP Juice Shop online demo was also checked but returned an application error, so it was not used.

The initial scanner run against the DVGA root discovered ordinary HTML routes and sent generic REST payloads. It did not treat `/graphql` as a GraphQL API and therefore missed the application’s introspection exposure. Independent manual verification using a safe GraphQL introspection query found 12 query fields, including `systemDebug`, `systemDiagnostics`, `users`, `audits`, `readAndBurn`, and `deleteAllPastes`.

## Fixes

The scanner now discovers `/graphql` and `/graphiql`, retains a GraphQL endpoint that returns the normal structured 400 JSON response when no query is supplied, and sends a structured JSON introspection request:

```json
{"query":"{ __schema { queryType { fields { name } } } }"}
```

GraphQL endpoints no longer receive generic SQLi, XSS, and command-injection payloads. Introspection exposure is classified as **informational**, not as a confirmed vulnerability, and its finding is persisted with the explicit `GraphQL_Introspection` category.

## Manual and Scanner Comparison

| Check | Independent manual result | Scanner result |
|---|---|---|
| GraphQL endpoint | POST `/graphql` returned HTTP 200 JSON. | POST `/graphql` completed successfully. |
| Introspection | Schema returned 12 query fields and no GraphQL errors. | Informational `GraphQL_Introspection` finding with matching proof. |
| Vulnerability count | Introspection exposure was treated as exposure/telemetry, not exploit proof. | **0 confirmed vulnerabilities**. |
| Overall score | No exploit score assigned to introspection. | **3.5/100 LOW**, due only to missing security-header telemetry. |

The raw manual artifact is [`tests/dvga_manual_results.json`](tests/dvga_manual_results.json). The final scanner database was `/tmp/dvga_graphql_final.sqlite` during verification and recorded one informational GraphQL finding plus one suspected security-misconfiguration finding.

## Verification Status

The final direct scan used a one-endpoint scope against the new GraphQL endpoint and completed in approximately 42 seconds. Discovery found the endpoint, routing selected `GraphQL_Introspection`, the structured POST returned HTTP 200, and the persisted finding retained the correct category. The full repository suite passes **55 tests**, Python compilation passes, and `git diff --check` reports no whitespace errors.

The scanner is now aware of this GraphQL introspection exposure, but this does not constitute complete GraphQL security coverage. Query-depth abuse, alias duplication, authorization flaws in individual fields, resolver-specific injection, mutations, and denial-of-service-style resource exhaustion require separate safe test cases and were not attempted.

## References

[1]: https://pentest-ground.com:5013 "Damn Vulnerable GraphQL Application training target"
[2]: https://owasp.org/www-project-juice-shop/ "OWASP Juice Shop project page"
