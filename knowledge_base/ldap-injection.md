# LDAP Injection

**CWE:** CWE-90
**OWASP:** A03 Injection

## What it is
Untrusted text is inserted into an LDAP search filter or distinguished name and alters the directory query.

## How it happens
Applications build filters by joining strings, such as a username inside a filter pattern. Special characters like parentheses, asterisks and the null character let an attacker widen the filter, bypass login, or read other entries.

## Signs in code
String concatenation or formatting used to create LDAP filters or DNs. Login code that searches the directory using raw form fields.

## Severity and context
High when it protects authentication or directory data. Often leads to authentication bypass or user enumeration.

## Likely false positives
Filters built from constants only, or values passed through the library escaping function for the correct context.

## How to fix
Use the escaping helpers of the LDAP library, with separate escaping for filters and for distinguished names. Prefer parameterized or bind-based authentication. Apply an allow-list on usernames. Run the directory account with least privilege.

## Related scanner signals
SAST findings on LDAP search calls with non-constant filters.
