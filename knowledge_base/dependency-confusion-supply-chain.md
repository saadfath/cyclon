# Dependency Confusion and Supply Chain Attacks

**CWE:** CWE-829, CWE-1357
**OWASP:** A06 Vulnerable and Outdated Components, A08 Integrity Failures

## What it is
Attackers get malicious code into a project through its dependencies, build tools or package names.

## How it happens
Dependency confusion happens when a private package name also exists on a public registry and the build prefers the public one. Other forms are typosquatting, compromised maintainers, malicious install scripts and unpinned versions.

## Signs in code
Internal package names without a scope or registry pin. Missing lock files. Version ranges that accept any newer release. Install scripts that download and run remote content. Unknown packages with names close to popular ones.

## Severity and context
High to critical because the code runs with build or runtime privileges.

## Likely false positives
Well-known maintained packages from the intended registry with locked, verified versions.

## How to fix
Commit lock files and verify checksums. Use scoped or namespaced private packages and configure registries explicitly. Review new dependencies. Disable install scripts when possible. Use software bill of materials and continuous advisory scanning.

## Related scanner signals
OSV-Scanner advisories and malware flags, lock file checks.
