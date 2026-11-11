# Docker and Infrastructure-as-Code Misconfiguration

## Overview
Insecure defaults in Dockerfiles, docker-compose, Kubernetes manifests, and Terraform expose containers and cloud resources.
- CWE-250, CWE-732, CWE-798 | OWASP A05:2021

## Dockerfile / compose issues
- No `USER` instruction: container runs as root.
- `FROM image:latest` (unpinned) or untrusted base images.
- `ADD` of remote URLs; `curl | sh` in `RUN`.
- Secrets in `ENV`, `ARG`, or copied `.env` files into the image.
- `privileged: true`, `network_mode: host`, mounting `/var/run/docker.sock`.
- Exposed ports that should be internal (e.g. database `5432:5432`).

## Kubernetes
- `privileged: true`, `allowPrivilegeEscalation: true`, `hostPath` mounts.
- No resource limits; secrets stored as plain ConfigMap values.
- `runAsNonRoot` not set; default service account with broad RBAC.

## Terraform / cloud
- Public S3 buckets (`acl = "public-read"`), security groups `0.0.0.0/0` on SSH/DB.
- Unencrypted storage; hardcoded credentials in `.tf` files.

## Example
```dockerfile
FROM node:latest
ENV API_KEY=sk_live_123
COPY . .
CMD ["node","app.js"]        # runs as root
```

## Fix
- Pin versions/digests; add `USER appuser`; use multi-stage builds.
- Pass secrets at runtime (secret managers, orchestrator secrets).
- Drop capabilities, read-only filesystem, least-privilege RBAC.
- Restrict network exposure and encrypt storage.

## False positives
- Dev-only compose files clearly labeled as local; images in a private, controlled registry with pinned tags.

## Severity
Medium to Critical (privileged container + docker.sock is Critical).
