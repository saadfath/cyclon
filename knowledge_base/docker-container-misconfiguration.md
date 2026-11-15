# Docker and Container Misconfiguration

**CWE:** CWE-250, CWE-269, CWE-798
**OWASP:** A05 Security Misconfiguration

## What it is
Container images and runtime settings give attackers more access than needed, or hide secrets inside images.

## How it happens
Typical mistakes: running as root, using the latest tag, bloated base images, secrets baked in during build, privileged mode, mounting the Docker socket, and exposing unnecessary ports.

## Signs in code
Image definitions without a non-root user instruction. Environment or build arguments holding passwords. Privileged flag in compose or orchestrator files. Host path mounts of sensitive directories.

## Severity and context
Medium to critical. Privileged containers and exposed sockets can lead to full host takeover.

## Likely false positives
Local development setups, if clearly separated from production.

## How to fix
Run as a non-root user. Pin base images by version or digest, use minimal images, and scan them. Pass secrets at runtime through a secret manager. Drop capabilities, use read-only file systems, and avoid privileged mode.

## Related scanner signals
Container image scanners, Gitleaks on image history, configuration linters.
