# DVWA Manual-versus-Tool Comparison

**Target:** [`https://pentest-ground.com:4280/`](https://pentest-ground.com:4280/)
**Application:** DVWA training instance, low security
**Verification date:** 2026-08-20
**Scope:** The exact two modules manually visited and tested immediately before the scanner run.

## Executive Result

The manual test and the improved scanner agree on both known vulnerabilities. The manual browser session first visited the command-injection and reflected-XSS modules, submitted non-persistent training payloads, and recorded the returned evidence. The scanner then ran against the same two module URLs, using the same discovered methods, fields, and payload behavior.

| Module | Manual result | Scanner result | Agreement |
|---|---|---|---|
| `/vulnerabilities/exec/` | Confirmed command injection; response displayed `/etc/passwd` content including `root:x:0:0:root:/root:/bin/bash`. | Confirmed `Command_Injection`; POST to `ip`; proof `root:x:0:0:`; HTTP 200; 1 confirmed vulnerability. | **Exact match** |
| `/vulnerabilities/xss_r/` | Confirmed reflected XSS; browser submission used the `name` field and the same payload was corroborated in the returned HTML as an exact unescaped string. | Confirmed `XSS`; GET to `name`; proof `Unescaped string reflection detected in text/html;charset=utf-8 body`; HTTP 200; 1 confirmed vulnerability. | **Exact match** |

Both scanner runs produced a **14.0/100 LOW** score for the module-specific scope. Residual syntax-only or baseline header observations remained suspected and did not increase the confirmed vulnerability count.

## Manual Verification Evidence

### Command Injection

The DVWA command-injection page displayed a form labeled “Enter an IP address” with a submit control. The manually submitted value was:

```text
127.0.0.1; cat /etc/passwd
```

The browser response displayed normal ping output followed by local password-file content. The visible response included:

```text
root:x:0:0:root:/root:/bin/bash
```

This is deterministic command-output evidence, not merely a syntax match. The manual browser artifact is [`tests/manual_dvwa_retest_browser_results.json`](tests/manual_dvwa_retest_browser_results.json).

### Reflected XSS

The DVWA reflected-XSS page displayed a “What’s your name?” field. The manually submitted value was:

```html
<script>alert('xss')</script>
```

The browser action returned an unavailable page state immediately after submission, consistent with the script execution path. The exact same non-persistent GET request was then captured without storing data; it returned HTTP 200 with `Content-Type: text/html;charset=utf-8`, a 4,262-byte response, and exactly one occurrence of the literal payload in the response body. The raw corroborating response is [`tests/manual_dvwa_xss_response.html`](tests/manual_dvwa_xss_response.html), with headers in [`tests/manual_dvwa_xss_headers.txt`](tests/manual_dvwa_xss_headers.txt).

## Matching-Scope Scanner Evidence

The scanner was run after the manual checks with `MAX_ENDPOINTS=1`, `ACTIVE_CONCURRENCY=4`, and the targeted full-pipeline harness. The harness only limited discovery to the two explicitly selected DVWA pages; it preserved the form metadata discovered from each page. The scanner’s detection, proof verification, risk scoring, and persistence logic were unchanged.

| Scanner database | Endpoint | Discovered method and field | Confirmed category | Proof |
|---|---|---|---|---|
| `/tmp/dvwa_matching_scope_command_injection.sqlite` | `/vulnerabilities/exec/` | POST, `ip` | `Command_Injection` | `root:x:0:0:` |
| `/tmp/dvwa_matching_scope_reflected_xss.sqlite` | `/vulnerabilities/xss_r/` | GET, `name` | `XSS` | Exact unescaped HTML reflection |

The scanner also retained expected non-confirmed observations: a syntax-only SQLi suspicion on the command-injection page and a missing-security-header suspicion on the reflected-XSS page. These did not become confirmed vulnerabilities, which demonstrates that the proof gate remained active during the faster concurrent run.

## Accuracy and Performance Assessment

The manual and scanner evidence agree on endpoint, method, input field, payload, HTTP success response, proof marker, category, and confirmed count. The focused scanner runs completed in approximately 18 seconds each with bounded concurrency. The improved broader DVWA scan also completed successfully in 216 seconds for 15 endpoints, compared with the earlier sequential attempt that exceeded its 420-second bound.

The current result supports the conclusion that the performance change did not weaken detection accuracy. HTTP requests are dispatched with bounded concurrency, while analysis and persistence remain sequential and deterministic. The full repository suite remains at **64 passing tests**, with compilation and whitespace checks passing.

## Conclusion

The requested order of operations was completed: **manual browser verification first, improved-tool verification second, and direct comparison third**. The scanner correctly reproduced both manually observed vulnerabilities on the same DVWA training modules. No discrepancy was found in this comparison.

## References

[1]: https://pentest-ground.com:4280/ "DVWA training target"
[2]: tests/manual_dvwa_retest_browser_results.json "Browser-manual DVWA retest results"
[3]: tests/manual_dvwa_xss_response.html "Manual reflected-XSS response body"
[4]: tests/manual_dvwa_xss_headers.txt "Manual reflected-XSS response headers"
[5]: /tmp/dvwa_matching_scope_command_injection.sqlite "Matching-scope command-injection scanner database"
[6]: /tmp/dvwa_matching_scope_reflected_xss.sqlite "Matching-scope reflected-XSS scanner database"
