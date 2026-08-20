# Real Training Target Validation

## Date

2026-08-20

## Reachability checks

Passive HTTP checks returned `200 OK` for the following intentionally vulnerable training targets:

| Target | Reachability | Initial application signal |
|---|---|---|
| `http://testasp.vulnweb.com` | Reachable | HTML title `acuforum forums`; links include `Search.asp`, `Login.asp`, `Register.asp`, and `showforum.asp?id=...`. |
| `http://demo.testfire.net` | Reachable | HTML response from Apache-Coyote; public demo application. |
| `https://pentest-ground.com:4280` | Reachable | PHP application; response sets a low-security cookie. |
| `https://pentest-ground.com:5013` | Reachable | GraphiQL-style application response. |
| `https://pentest-ground.com:9000` | Reachable | Public HTML application response. |

The supplied `testhtml5.vulnweb.com` entry was malformed as a Google search URL, and the browser subsystem subsequently entered a crash-loop-disabled state. The first `testphp.vulnweb.com` browser checks returned an empty response/connection closed. The next target selected for actual testing is `http://testasp.vulnweb.com` because it is reachable and exposes a bounded, crawlable forum/search surface.

## Safety boundary

Testing is limited to the public intentionally vulnerable training application. The comparison uses the platform’s existing bounded discovery and payload queue plus independent passive/manual response checks. No authentication bypass against real accounts, destructive writes, brute force, denial-of-service behavior, or data extraction is performed.
