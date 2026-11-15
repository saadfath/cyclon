# Clickjacking

**CWE:** CWE-1021
**OWASP:** A05 Security Misconfiguration

## What it is
A malicious site loads the target page invisibly inside a frame and tricks users into clicking buttons they cannot see.

## How it happens
The application does not tell browsers to refuse framing, so sensitive actions such as payments, password changes or approvals can be triggered by a disguised click.

## Signs in code
Missing frame-ancestors directive in the content security policy and missing X-Frame-Options header on pages with state-changing actions.

## Severity and context
Low to medium. Higher for banking, admin and account-settings pages.

## Likely false positives
Pages with no sensitive actions, or APIs returning only data.

## How to fix
Set the frame-ancestors directive to none or to specific trusted origins. Add X-Frame-Options as a fallback. Require re-authentication for critical actions.

## Related scanner signals
DAST and header scanners reporting missing anti-framing headers.
