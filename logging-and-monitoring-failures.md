# Security Logging and Monitoring Failures

## Overview
The application does not log security-relevant events, logs sensitive data, or allows log injection, so attacks go undetected or leak secrets.
- CWE-778, CWE-532, CWE-117 | OWASP A09:2021

## Problems to look for
1. **Missing logs**: no logging of login failures, access denials, privilege changes, input validation failures.
2. **Sensitive data in logs**: passwords, tokens, API keys, credit cards, full request bodies.
3. **Log injection**: user input with newlines written raw to logs.
4. **Swallowed errors**: empty `except: pass` / `catch {}` on security checks.

## Vulnerable patterns
```python
logger.info(f"Login attempt {username} password={password}")
logger.debug(request.headers)           # includes Authorization
logging.info("User: " + user_input)     # CRLF injection
try: verify_token(t)
except Exception: pass
```

## How to detect
- Logging calls containing `password`, `token`, `secret`, `authorization`.
- Authentication/authorization code paths with no logging.
- Empty exception handlers around security logic.

## False positives
- Logging of a username or user id alone is normally fine.
- Values already masked/redacted before logging.

## Fix
- Log security events with timestamp, user id, IP, outcome.
- Redact secrets; never log credentials or full tokens.
- Sanitize or encode newlines in logged user input.
- Send logs to central storage with alerting.

## Severity
Low to Medium; High when credentials or tokens are written to logs.
