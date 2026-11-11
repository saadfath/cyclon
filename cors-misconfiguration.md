# CORS Misconfiguration

## Overview
Cross-Origin Resource Sharing is configured too permissively, letting malicious sites read authenticated responses from the API in the victim's browser.
- CWE-942 | OWASP A05:2021 Security Misconfiguration

## Vulnerable patterns
```js
app.use(cors({ origin: true, credentials: true }));      // reflects any Origin
res.setHeader("Access-Control-Allow-Origin", req.headers.origin);
res.setHeader("Access-Control-Allow-Credentials", "true");
```
```python
CORS(app, origins="*", supports_credentials=True)
CORS_ALLOW_ALL_ORIGINS = True   # Django corsheaders
```
- `Origin: null` allowed.
- Weak regex such as `endswith("example.com")` (matches `evilexample.com`).

## How to detect
- Wildcard or reflected origin combined with credentials.
- Allow-lists built with substring/regex checks.

## False positives
- `Access-Control-Allow-Origin: *` on a public, unauthenticated, cookie-less API is acceptable.

## Fix
- Use an exact allow-list of trusted origins.
- Never combine `*` or a reflected origin with `Allow-Credentials: true`.
- Reject `null` origin; add `Vary: Origin`.

## Severity
Medium to High depending on whether authenticated data is exposed.
