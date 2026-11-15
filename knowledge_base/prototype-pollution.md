# Prototype Pollution (JavaScript)

**CWE:** CWE-1321
**OWASP:** A08 Integrity Failures, A03 Injection

## What it is
An attacker adds or changes properties on the base object prototype, which then appear on every object in the application.

## How it happens
Code that merges, clones or assigns nested objects from user input without blocking special keys such as the proto key, constructor and prototype. Polluted defaults can change logic, bypass checks, or reach code execution in some libraries.

## Signs in code
Recursive merge, deep copy, set-by-path and query-string parsing helpers applied to request data. Old versions of popular utility libraries with known pollution advisories.

## Severity and context
Medium to critical depending on what reads the polluted properties. Often found through dependency advisories.

## Likely false positives
Merge functions that only copy from trusted constants, or libraries already patched.

## How to fix
Block the dangerous keys during merges. Create lookup objects without a prototype or use Map. Freeze the object prototype where possible. Update vulnerable dependencies. Validate input with a schema.

## Related scanner signals
OSV-Scanner advisories on utility libraries. SAST rules on recursive merge of request data.
