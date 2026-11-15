# CI/CD Pipeline Security

**CWE:** CWE-829, CWE-522, CWE-77
**OWASP:** A08 Integrity Failures, A05 Security Misconfiguration

## What it is
Build and deployment pipelines are attacked to steal secrets, change builds or deploy malicious code.

## How it happens
Risks include secrets exposed to pull requests from forks, workflow steps that put untrusted text such as branch names or issue titles into shell commands, unpinned third-party actions, and broad token permissions.

## Signs in code
Workflow files using untrusted event data inside script steps. Actions referenced by moving tags. Write permissions granted by default. Secrets printed or echoed. Self-hosted runners accepting public jobs.

## Severity and context
High to critical. A compromised pipeline can ship malicious releases.

## Likely false positives
Steps using only trusted, fixed values and minimal permissions.

## How to fix
Pin actions to full commit hashes. Grant least privilege tokens. Keep secrets away from untrusted triggers. Treat event data as untrusted. Require reviews on workflow changes. Use short-lived credentials.

## Related scanner signals
Workflow linters, Gitleaks, and SAST for workflow files.
