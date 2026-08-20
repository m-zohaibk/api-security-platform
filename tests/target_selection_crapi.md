# Target Selection: crAPI

The previously used DVWA, testasp, and DVGA targets are excluded from this run. The official OWASP crAPI project page states that crAPI (Completely Ridiculous API) is an intentionally vulnerable application built primarily for teaching, learning, and practicing API security, with OWASP API Top 10-style challenges.

A separate public instance at `http://crapi.apisec.ai` is reachable and redirects to the crAPI login page. HTTPS on the host closed the connection, so testing is limited to the reachable HTTP training instance. Passive inspection shows a crAPI login UI. No login, signup, password-reset, mutation, or state-changing action will be performed.

Selected base URL: `http://crapi.apisec.ai`

Selected safe scope: public endpoint discovery and read-only GET/API response checks, bounded to five endpoints. Authentication-required and state-changing API operations are excluded.

References:

- https://owasp.org/www-project-crapi/
- http://crapi.apisec.ai/login

## Live verification observations

On 2026-08-20, `http://crapi.apisec.ai/health`, `/api/Feedbacks`, and `/api/v1/users` returned the same 2,835-byte `text/html` frontend shell containing `<div id="root">`; query payloads did not change status or size. The reachable public `/graphql` route returned HTTP 405 from the proxy for POST introspection in this HTTP instance. The actual identity login API identified from the frontend bundle was `/identity/api/auth/login`; both the invalid baseline and password SQLi probe returned the same HTTP 500 body: `UserDetailsService returned null, which is an interface contract violation`.
