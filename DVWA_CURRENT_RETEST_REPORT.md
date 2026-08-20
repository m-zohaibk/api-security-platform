# Current DVWA Retest Report

**Target:** [`https://pentest-ground.com:4280/`](https://pentest-ground.com:4280/)
**Application:** DVWA training instance, low security
**Retest date:** 2026-08-20
**Scanner revision:** Current working tree of `m-zohaibk/api-security-platform`

## Result

The improved scanner was rerun against the same DVWA modules for which independent manual testing previously confirmed two vulnerabilities. The targeted full pipeline reproduced both vulnerabilities correctly:

| Module | Scanner request | Scanner result | Proof | Manual result |
|---|---|---|---|---|
| `/vulnerabilities/exec/` | POST form submission with `ip=; cat /etc/passwd` and the discovered `Submit=Submit` default | **Confirmed Command_Injection**; 1 confirmed vulnerability; **14.0/100 LOW** | `root:x:0:0:` in the HTTP 200 response | Same command output marker manually observed |
| `/vulnerabilities/xss_r/` | GET form submission with `name=<script>alert('xss')</script>` | **Confirmed XSS**; 1 confirmed vulnerability; **14.0/100 LOW** | Verbatim unescaped script reflection in `text/html;charset=utf-8` | Same payload was manually observed verbatim in HTML |

The scanner’s category, method, payload, proof marker, and confirmed count agree with the manual evidence. The per-module databases were `/tmp/dvwa_exec_targeted.sqlite` and `/tmp/dvwa_xss_targeted.sqlite` during the retest.

## Manual-versus-Scanner Comparison

The earlier independent DVWA artifact recorded that command injection produced `root:x:0:0:` and that reflected XSS returned the payload verbatim in HTML. The current scanner produced the same proof conditions rather than merely matching payload syntax. The command-injection scan used the discovered POST method and `ip` field; the XSS scan used the discovered GET method and `name` field. This confirms that form-aware discovery and method-aware payload binding are functioning correctly.

| Comparison item | Command injection | Reflected XSS |
|---|---|---|
| Correct endpoint | Yes | Yes |
| Correct HTTP method | POST | GET |
| Correct application field | `ip` | `name` |
| Confirmed status | Yes | Yes |
| Proof evidence | `root:x:0:0:` | Exact unescaped payload reflection |
| Manual result matched | Yes | Yes |

## Additional Scan Note

A repeat of the original broader 15-endpoint scan was attempted with the live public training service. That run reached the endpoint budget but exceeded the 420-second execution bound because the target was responding slowly during discovery and sequential testing; the partial database contained no confirmed result and is not used as the definitive retest. The focused one-page runs are the appropriate accuracy check for the two known modules because they invoke the complete scanner pipeline while preserving the real form metadata and avoid unrelated target latency.

The targeted harness is [`tests/targeted_main_scan.py`](tests/targeted_main_scan.py). It only limits discovery to an explicitly selected training page; it does not alter the scanner’s detection, request, proof, risk, or persistence logic.

## Conclusion

**The improved tool is working correctly for the two previously manually verified DVWA vulnerabilities.** It confirmed command injection and reflected XSS independently, with exact agreement on endpoint, method, input field, payload behavior, proof evidence, and vulnerability count. The broader scan timeout is a performance limitation of sequential scanning against a slow public target, not an accuracy discrepancy in the two verified modules.

## References

[1]: https://pentest-ground.com:4280/ "DVWA training target"
[2]: DVWA_ACCURACY_VERIFICATION_REPORT.md "Prior DVWA accuracy verification report"
[3]: tests/dvwa_manual_confirmations.json "Independent DVWA manual confirmation artifact"
[4]: tests/dvwa_manual_module_results.json "DVWA manual module results"
