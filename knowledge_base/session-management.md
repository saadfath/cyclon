# Session Management Weaknesses

**CWE:** CWE-384, CWE-613, CWE-614, CWE-1004
**OWASP:** A07 Identification and Authentication Failures

## What it is
Flaws in how sessions are created, stored, expired and destroyed let attackers take over a logged-in user.

## How it happens
Examples: session identifiers that are predictable, not renewed after login, kept in URLs, never expired, not invalidated at logout, or sent in cookies lacking the Secure, HttpOnly and SameSite attributes.

## Signs in code
Custom session id generation, missing regeneration step at login, cookies set manually without flags, long or infinite lifetimes, tokens stored in browser local storage for sensitive apps.

## Severity and context
High when combined with cross-site scripting or insecure transport.

## Likely false positives
Frameworks configured with secure defaults that are overridden elsewhere in a way that restores safe values.

## How to fix
Use the framework session system. Regenerate identifier after login and privilege changes. Set Secure, HttpOnly and SameSite. Apply idle and absolute timeouts. Invalidate on server side at logout. Bind sessions to risk signals where practical.

## Related scanner signals
DAST cookie checks, SAST rules on cookie creation.
