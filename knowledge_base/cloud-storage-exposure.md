# Cloud Storage and Data Exposure

**CWE:** CWE-552, CWE-200, CWE-732
**OWASP:** A01 Broken Access Control, A05 Security Misconfiguration

## What it is
Buckets, blobs, databases and backups are left readable or writable by anyone on the internet.

## How it happens
Teams grant public access to make something work, reuse broad policies, or forget old test resources. Unprotected storage gets scanned by automated tools within hours.

## Signs in code
Public access settings, wildcard principals in policies, URLs of storage resources in code that return data without authentication, unencrypted backups, and long-lived presigned links.

## Severity and context
High to critical depending on the data. Often causes reportable breaches.

## Likely false positives
Buckets that intentionally serve public static assets with nothing private inside.

## How to fix
Block public access at the account level. Use least-privilege policies and short-lived presigned links. Encrypt data at rest. Enable access logging and alerts. Inventory and delete forgotten resources.

## Related scanner signals
IaC scanners, cloud posture tools, Gitleaks for access keys.
