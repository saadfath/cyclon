# Missing Security Headers and Insecure Cookies

## Overview
Missing HTTP response headers and weak cookie flags remove browser-side defenses against XSS, clickjacking, MITM, and CSRF.
- CWE-693, CWE-1004, CWE-614, CWE-1275 | OWASP A05:2021

## Headers to check
| Header | Recommended |
|---|---|
| Content-Security-Policy | restrictive policy, no `unsafe-inline` / `unsafe-eval` |
| Strict-Transport-Security | `max-age=31536000; includeSubDomains` |
| X-Content-Type-Options | `nosniff` |
| X-Frame-Options / CSP frame-ancestors | `DENY` or `frame-ancestors 'none'` |
| Referrer-Policy | `strict-origin-when-cross-origin` |
| Permissions-Policy | disable unused features |

## Cookie flags
- `HttpOnly` (blocks JS access), `Secure` (HTTPS only), `SameSite=Lax|Strict`.
- Session cookies without these are a finding.

## Vulnerable patterns
```python
resp.set_cookie("session", token)                       # no flags
SESSION_COOKIE_SECURE = False                           # Django
```
```js
app.use(session({ cookie: { secure: false, httpOnly: false } }));
```

## False positives
- Static/public sites with no sessions: cookie flags are not relevant.
- Headers set at a reverse proxy / CDN outside the scanned repo.

## Fix
- Use `helmet` (Express), `django-csp` + `SECURE_*` settings, or set headers at the proxy.
- Set all three cookie flags on session and auth cookies.

## Severity
Low to Medium (defense in depth); higher if combined with XSS or CSRF.
