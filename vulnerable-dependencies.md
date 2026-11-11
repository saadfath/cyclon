---
id: vulnerable-dependencies
title: Vulnerable and Outdated Dependencies
cwe: CWE-1104
owasp: A06 Vulnerable and Outdated Components
severity: varies (low to critical, depends on the CVE)
languages: [python, javascript, java, go, php, ruby, rust, any]
scanner_rules: [osv-scanner, known-vulnerability, cve-match]
---

## What it is
A vulnerable dependency is a third-party library or package used by the project that has a publicly known security problem. The problem is usually published as a CVE (or another ID like GHSA) in public vulnerability databases. The project's own code can be perfect and the application is still at risk.

## How it happens
Modern projects use many libraries, and those libraries use other libraries (transitive dependencies). When a vulnerability is found in one of them, every project using the affected version is exposed. This happens when versions are pinned and never updated, when nobody checks for new advisories, or when a library is no longer maintained.

## Vulnerable example
A project that uses a version of a library with a known critical vulnerability. Example: Log4Shell (CVE-2021-44228) in `log4j-core`.
```xml
<dependency>
  <groupId>org.apache.logging.log4j</groupId>
  <artifactId>log4j-core</artifactId>
  <version>2.14.1</version>
</dependency>
```
Python and JavaScript projects have the same problem with pinned old versions:
```text
# requirements.txt
somelibrary==1.0.0      # old version with a known CVE
```
```json
"dependencies": {
  "somelibrary": "1.0.0"
}
```

## Safe example
The same dependency updated to a fixed version.
```xml
<dependency>
  <groupId>org.apache.logging.log4j</groupId>
  <artifactId>log4j-core</artifactId>
  <version>2.17.1</version>
</dependency>
```
In general: use the fixed version listed in the advisory (or a newer one), keep the lockfile committed, and run a dependency scan regularly.

## How to detect it
- Read the dependency files: `requirements.txt`, `poetry.lock`, `Pipfile.lock`, `package.json`, `package-lock.json`, `yarn.lock`, `pom.xml`, `build.gradle`, `go.mod`, `Gemfile.lock`, `Cargo.lock`, `composer.lock`.
- Compare each package name and exact version with a vulnerability database (OSV, GitHub Advisories, NVD). OSV-Scanner does this automatically.
- Check both direct and transitive dependencies. Lockfiles show the exact versions of both.
- Check if the library is unmaintained or archived, even without a CVE.

## Impact
- Depends on the vulnerability. It can be anything from information leaks to full remote code execution.
- Attackers often scan the internet for applications using known vulnerable versions, so exposure can be fast.
- A single vulnerable library can affect many parts of the application.

## How to fix it
1. Read the advisory and find the fixed version.
2. Update the dependency to the fixed version (or newer) and update the lockfile.
3. If the vulnerable library is transitive, update the parent package that brings it, or force a safe version using the package manager's override feature.
4. Run the tests, because updates can break behavior.
5. If no fixed version exists, look for a safe alternative library, or reduce the risk (disable the vulnerable feature, add protections).
6. Automate: run OSV-Scanner in CI and use automatic update tools (Dependabot or Renovate).

## False positives
- The vulnerable function or feature of the library is never used by the project (the package is present but the vulnerable code path is not reachable).
- The vulnerability needs a configuration or environment that the project does not use.
- The dependency is only used in development or tests and does not go to production.
- The advisory is for a different ecosystem or a different package with a similar name.
- The vulnerable version range was already fixed through a patched or vendor-backported version.

## Confidence guide
- **High:** the exact package and version match a published advisory, the package is a production dependency, and the vulnerable feature is used or likely reachable.
- **Medium:** the package and version match, but it is not clear if the vulnerable code path is used.
- **Low:** the match is only a dev or test dependency, the vulnerable feature is clearly not used, or the package match is uncertain.

Severity note: the severity (for example the CVSS score) comes from the advisory. The AI should explain it but must not invent a different score.
