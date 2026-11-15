# Infrastructure as Code Misconfiguration

**CWE:** CWE-16, CWE-732, CWE-284
**OWASP:** A05 Security Misconfiguration

## What it is
Terraform, CloudFormation, Kubernetes manifests and similar files define insecure infrastructure.

## How it happens
Insecure defaults get committed: open firewall rules to the whole internet, unencrypted storage and databases, public buckets, overly broad permissions, and disabled logging.

## Signs in code
Network rules allowing all addresses on sensitive ports. Permission policies with wildcard actions and resources. Missing encryption settings. Kubernetes pods allowing privilege escalation. Hardcoded credentials in variables.

## Severity and context
High, because the problem is deployed repeatedly and at scale.

## Likely false positives
Intentionally public resources such as static website buckets, documented and reviewed.

## How to fix
Follow least privilege. Restrict network access to known ranges. Enable encryption and logging by default. Use policy-as-code checks in review. Keep secrets in a secret manager, not in variable files.

## Related scanner signals
IaC scanners such as Checkov or tfsec, Gitleaks on configuration files.
