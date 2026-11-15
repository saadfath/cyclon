# Mass Assignment

**CWE:** CWE-915
**OWASP:** A01 Broken Access Control, A04 Insecure Design

## What it is
An application copies all fields from a request into an internal object, so attackers can set fields they should never control, such as role or price.

## How it happens
Frameworks that automatically bind request properties to model attributes will accept extra fields unless an allow-list exists.

## Signs in code
Models created or updated directly from the full request body. Missing allow-lists on bindable fields. Administrative flags stored in the same model as user profile data.

## Severity and context
High when privilege or ownership fields can be changed.

## Likely false positives
Models containing only user-editable fields, or binding already restricted by explicit field lists.

## How to fix
Define explicit allow-lists of writable fields per operation. Use separate input objects from the database model. Make sensitive fields read-only and set only by server logic. Test with extra fields.

## Related scanner signals
SAST rules about unguarded model binding.
