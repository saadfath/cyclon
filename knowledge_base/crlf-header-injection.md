# CRLF and HTTP Header Injection

**CWE:** CWE-113
**OWASP:** A03 Injection

## What it is
Carriage return and line feed characters in user input let an attacker add headers or split an HTTP response.

## How it happens
Input is placed into response headers, such as redirect locations, cookie values or custom headers, without removing line breaks. This can set cookies, enable cache poisoning, or inject content.

## Signs in code
Header setting functions or redirect calls receiving unfiltered request data. Cookie values taken from input.

## Severity and context
Medium. Modern frameworks often reject line breaks, so exploitability depends on the stack.

## Likely false positives
Frameworks and library versions that already reject control characters in header values.

## How to fix
Reject or strip carriage return and line feed in any value used in a header. Use framework helpers for redirects and cookies. Validate against an allow-list. Keep the web framework updated.

## Related scanner signals
SAST rules on header and redirect functions. DAST probes using encoded line breaks.
