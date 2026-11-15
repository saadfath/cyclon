# Host Header Injection

**CWE:** CWE-644, CWE-640
**OWASP:** A05 Security Misconfiguration

## What it is
The application trusts the Host or forwarded headers from the request when building links, which attackers can forge.

## How it happens
Password reset emails, absolute redirects and cache keys use the header value. An attacker sends a reset request with a fake host so that the victim's email contains a link to the attacker's site.

## Signs in code
Link generation using request host headers. Trust of forwarded host or protocol headers without a trusted proxy setting. Missing allowed-hosts configuration.

## Severity and context
Medium to high when it affects password reset or cached content.

## Likely false positives
Applications behind a proxy that overwrites these headers and enforces a host allow-list.

## How to fix
Configure a fixed list of allowed hosts. Build absolute links from server configuration, not request headers. Accept forwarded headers only from known proxies. Validate or reject unexpected host values.

## Related scanner signals
DAST probes using altered Host headers, framework configuration checks.
