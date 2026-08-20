# Target Selection: Damn Vulnerable GraphQL Application

The official OWASP Juice Shop online demo link returned an application error, so it was not selected. The listed `https://pentest-ground.com:5013` service is reachable and identifies itself as the Damn Vulnerable GraphQL Application (DVGA). Its landing page states that it is a vulnerable GraphQL implementation for learning how GraphQL can be exploited and defended in a safe environment. The page describes a beginner mode with intentionally unrestricted GraphQL behavior and an expert/hard mode with additional controls.

Selected target: `https://pentest-ground.com:5013`

Scope: passive landing-page inspection followed by bounded, non-destructive GraphQL introspection and a simple query. No mutation, authentication attack, data modification, or resource-intensive query will be attempted.

Source URL: https://pentest-ground.com:5013
