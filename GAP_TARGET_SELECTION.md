# Gap-Only Target Selection

**Source:** https://pentest-ground.com/
**Review date:** 2026-08-21

Pentest-Ground identifies itself as a free playground with deliberately vulnerable web applications and network services for benchmarking scanners and educational testing. It states that the services are redeployed every 30 minutes and can be tested without authentication.

| Training target | Advertised classes relevant to current gaps |
|---|---|
| DVWA :4280 | CSRF, XSS, SQLi |
| DVGA :5013 | GraphQL CMDi, XSS, SQLi |
| RestFlaw :9000 | REST API SQLi, code injection, XXE |
| GuardianLeaks :81 | XSS, SSRF, code injection |

The first gap-only target should be **RestFlaw on port 9000** for XXE because it is explicitly advertised as a REST API with an XML parser vulnerability. XXE can be implemented as a content-type-aware, non-destructive canary probe and manually verified with a harmless local canary response. The next candidates are GuardianLeaks SSRF and DVWA CSRF, but SSRF requires a controlled callback or safe target response and CSRF requires browser/cookie/origin context.

The target page explicitly warns that other users may test the shared applications concurrently, so all probes must remain bounded, non-destructive, and limited to the advertised training services.

## RestFlaw XML operation

The authorized RestFlaw OpenAPI document exposes `POST /search` with an `application/xml` request body and an XML response. The documented body has a `user` property and an example `<root><user>username</user></root>` payload. This is the selected endpoint for the first gap-only XXE verification.

## GuardianLeaks SSRF reconnaissance

The authorized GuardianLeaks service exposes `/search` with a plain text search input and no visible URL-fetch parameter in the landing/search page. The public page advertises SSRF, but the reachable form did not yet expose a concrete remote-fetch input. A further source/route inspection or documented target path is required before sending an SSRF canary; no private-network or metadata targets will be probed.

## XXE validation outcome

Manual `POST /search` with `Content-Type: application/xml` and a `file:///etc/passwd` external entity returned HTTP 200 with `application/xml`, but the body was only `{"message": "Search made successfully"}` and did not contain the `root:x:0:0:` canary. Manual `POST /tokens` with the reference implementation’s XML login shape returned HTTP 415 because the deployed OpenAPI contract accepts JSON for `/tokens`.

The improved scanner was run on the exact `/search` endpoint with OpenAPI-declared XML metadata. It sent the XML probe, persisted an `XXE` finding as **Suspected**, and did not confirm a vulnerability. This matches the manual evidence; no scanner discrepancy was found. The live service therefore did not provide a confirmed XXE proof during this cycle, despite the playground listing RestFlaw as an XXE training target.

## DVWA CSRF validation outcome

The authorized DVWA CSRF module exposed a password-change form with no visible anti-CSRF token. With confirmation, a disposable canary password was submitted through the browser. The request reached the vulnerable handler, but the training instance returned a fatal application error because the `dvwa.users` table does not exist. This is a target deployment/database failure, not proof of either a working or blocked CSRF exploit. No scanner comparison should treat this response as a confirmed CSRF finding.

## CSRF discrepancy and fix

Manual browser verification showed a DVWA CSRF form with a state-changing GET request and no hidden anti-CSRF token. The first scanner attempt missed the form because it assumed CSRF state-changing forms were POST-only and the focused discovery record retained only the GET page metadata. This was a real scanner discrepancy.

The scanner was corrected to preserve form metadata, treat explicit CSRF routes with state-changing GET/POST/PUT/PATCH/DELETE forms as passive CSRF candidates, and record an **Informational** `CSRF` finding without submitting the password-change action. The matching rerun recorded `CSRF / Informational / 0.0` with the same missing-token observation. The manual state-changing request itself returned a fatal `dvwa.users` table-missing error, so exploitability was not confirmed against this deployment.
