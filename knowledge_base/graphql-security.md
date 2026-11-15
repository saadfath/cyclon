# GraphQL API Security

**CWE:** CWE-200, CWE-770, CWE-285
**OWASP:** A01 Broken Access Control, A05 Security Misconfiguration

## What it is
GraphQL exposes a flexible query language that adds risks: schema disclosure, expensive queries, and missing authorization on individual fields.

## How it happens
Introspection left on in production reveals the full schema. Deeply nested or aliased queries consume resources. Batching allows brute force. Authorization is checked at the endpoint but not inside resolvers.

## Signs in code
Introspection enabled with no environment check. No depth, complexity or timeout limits. Resolvers returning objects without ownership checks. Verbose error messages.

## Severity and context
Medium to high. Object-level authorization gaps are usually the most serious.

## Likely false positives
Public read-only schemas that are deliberately open.

## How to fix
Check authorization in every resolver. Disable introspection and suggestions in production if not needed. Limit depth, complexity, and batch size. Apply rate limits and timeouts. Use persisted queries where possible.

## Related scanner signals
DAST introspection probes. Configuration scanners for GraphQL servers.
