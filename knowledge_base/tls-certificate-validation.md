# TLS and Certificate Validation Failures

**CWE:** CWE-295, CWE-297, CWE-327
**OWASP:** A02 Cryptographic Failures

## What it is
The application disables or weakens verification of server certificates, or allows old protocol versions, which enables machine-in-the-middle attacks.

## How it happens
Developers switch off verification to get past a certificate error during development and ship it. Others accept any host name, trust all certificates, or allow outdated protocols and weak cipher suites.

## Signs in code
Settings such as verify equals false, reject-unauthorized false, custom trust managers that accept everything, host name verifiers that always agree, and flags that ignore certificate errors.

## Severity and context
High on any network crossing untrusted links.

## Likely false positives
Local test configurations that are never deployed, if clearly separated by environment.

## How to fix
Keep verification on. Fix the real certificate problem instead. Use up-to-date TLS versions, and pin certificates only with a rotation plan. Use environment-specific configuration rather than code edits.

## Related scanner signals
SAST rules on disabled verification. Dependency scanners flag outdated TLS libraries.
