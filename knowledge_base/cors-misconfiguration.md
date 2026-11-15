# CORS Misconfiguration

**CWE:** CWE-942
**OWASP:** A05 Security Misconfiguration

## What it is
Cross-Origin Resource Sharing rules are too permissive, letting malicious websites read responses from an authenticated user's session.

## How it happens
Common mistakes: reflecting any Origin header back, allowing the null origin, wildcard origins combined with credentials, regex checks that match attacker domains, and trusting all subdomains.

## Signs in code
Server code that copies the request Origin header into the allow-origin response header. Wildcard allow-origin together with allow-credentials. Weak origin-matching patterns.

## Severity and context
Medium to high when the API returns private data and uses cookies for authentication.

## Likely false positives
Wildcard origin on public, unauthenticated, read-only resources.

## How to fix
Keep an explicit allow-list of trusted origins and compare exactly. Do not allow credentials with wildcard. Never trust the null origin. Limit allowed methods and headers. Return a Vary header on Origin.

## Related scanner signals
DAST header checks. Configuration scanners flagging permissive CORS.
