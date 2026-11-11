---
id: scanner-rule-mapping
title: Mapping Scanner Findings to Knowledge Files
type: guideline
---

## Purpose
This file tells the system which knowledge file to use for each scanner finding. Use the scanner and the finding category first. Use exact rule names when they are known.

## By scanner
| Scanner | What it checks | Knowledge file |
|---------|----------------|----------------|
| Gitleaks | Secrets in code and Git history | hardcoded-secrets |
| OSV-Scanner | Known vulnerabilities in dependencies | vulnerable-dependencies |
| SAST | Vulnerable patterns in source code | by vulnerability type (table below) |
| DAST | Vulnerabilities found in the running application | by vulnerability type (table below) |

## By vulnerability type (SAST and DAST)
| Finding category | Knowledge file |
|------------------|----------------|
| SQL injection | SQLinjection |
| Shell or OS command execution | command-injection |
| Python subprocess or os.system | command-injection, python-subprocess |
| Cross-site scripting | cross-site-scripting |
| Cross-site request forgery | cross-site-request-forgery |
| Server-side request forgery | ssrf |
| XML parsing with external entities | xml-external-entities |
| File path built from user input | path-traversal |
| Redirect to a user-controlled URL | open-redirect |
| Deserialization of untrusted data | insecure-deserialization |
| File upload without checks | insecure-file-upload |
| JWT problems | jwt-security |
| Login, session, or password problems | authentication-failures |
| Missing permission checks | broken-access-control |
| Missing request limits | rate-limiting |
| Race conditions | race-conditions |
| Sensitive data in errors, logs, or responses | information-disclosure |
| Debug mode, default settings, open services | security-misconfiguration |
| Weak hashing, weak encryption, weak randomness | weak-cryptography |

## Exact rule names
Add the exact rule IDs of each scanner here when you see them in real scanner output. Use this format:

| Scanner | Rule ID | Knowledge file |
|---------|---------|----------------|
| (scanner name) | (rule id) | (knowledge file id) |

## Rules
- If one finding fits two files, use both and explain which one is the main problem.
- If no file matches, say that no knowledge is available. Do not invent an explanation.
