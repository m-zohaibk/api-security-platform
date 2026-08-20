# Selected Training Target

## Target

`https://pentest-ground.com:4280/`

## Validation

The OWASP Vulnerable Web Applications Directory identifies intentionally vulnerable web applications for security training. The selected Pentest Ground service presents Damn Vulnerable Web Application (DVWA), whose landing page explicitly describes it as a legal environment for testing security skills and tools and lists modules for command injection, SQL injection, reflected/stored XSS, file inclusion, CSRF, weak session IDs, and open redirects.

The page reports `Security Level: low`, `SQLi DB: mysql`, and exposes public module links. Testing is limited to bounded, non-destructive GET/POST probes against this training service; no brute force, file upload, database reset, destructive write, or stored-XSS submission will be performed.

## Source references

- OWASP Vulnerable Web Applications Directory: https://owasp.org/www-project-vulnerable-web-applications-directory/
- DVWA training target: https://pentest-ground.com:4280/
