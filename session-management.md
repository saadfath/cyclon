# Session Management Weaknesses

## Overview
Flaws in how sessions are created, stored, and ended let attackers hijack or fixate sessions. Related to `authentication-failures.md`.
- CWE-384, CWE-613, CWE-330, CWE-565 | OWASP A07:2021

## Problems to look for
1. **Session fixation**: session id not regenerated after login.
2. **No expiry / no logout invalidation**: tokens valid forever; logout only clears the client cookie.
3. **Session id in URL**: `?sessionid=...` leaks via logs and Referer.
4. **Predictable ids**: sequential or weak random (see `insecure-randomness.md`).
5. **Weak cookie flags**: see `security-headers-and-cookies.md`.
6. **Hardcoded session secret**: `SECRET_KEY = "changeme"`.
7. **No concurrent-session or idle-timeout control** on sensitive apps.

## Vulnerable patterns
```python
# Flask
app.secret_key = "dev"
session["user"] = user.id        # no session.clear() before login
```
```js
app.use(session({ secret: "keyboard cat", resave: false, cookie: { maxAge: null } }));
```

## Fix
- Regenerate session id on login and privilege change (`req.session.regenerate`).
- Set idle and absolute timeouts; invalidate server-side on logout and password change.
- Load secrets from environment; use cryptographically random ids.
- Use `HttpOnly; Secure; SameSite` cookies.

## False positives
- Stateless APIs using short-lived JWTs (see `jwt-security.md`) have different controls.

## Severity
Medium to High (account takeover).
