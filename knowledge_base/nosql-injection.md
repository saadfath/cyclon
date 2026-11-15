# NoSQL Injection

**CWE:** CWE-943
**OWASP:** A03 Injection

## What it is
An attacker changes the meaning of a query sent to a document database such as MongoDB by supplying structured input instead of plain text.

## How it happens
Request data is passed straight into a query object. When the framework parses JSON or nested form fields, an attacker can send an object containing query operators (for example a not-equal or greater-than operator) where a simple string was expected. A login check can then match any user.

## Signs in code
User input placed directly into a find, update or delete filter without checking its type. Request bodies used as whole filter objects. Server-side JavaScript evaluation inside queries (the where operator or mapReduce with user text).

## Severity and context
High to critical when it affects authentication or authorization queries. Medium when it only affects search filters over non-sensitive data.

## Likely false positives
Filters built only from constants or from values already forced to a string or number by a schema validator.

## How to fix
Validate the type and shape of every field before it reaches the query. Cast values to strings explicitly. Use a schema validation layer. Disable or avoid server-side JavaScript evaluation. Reject keys beginning with a dollar sign or containing dots in user input.

## Related scanner signals
SAST rules on database driver query calls receiving request properties. Linters flagging untyped request bodies.
