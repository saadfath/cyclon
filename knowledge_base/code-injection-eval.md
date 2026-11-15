# Code Injection and Unsafe Evaluation

**CWE:** CWE-94, CWE-95
**OWASP:** A03 Injection

## What it is
Untrusted input is executed as program code by the language runtime.

## How it happens
Functions that evaluate text as code, such as eval, exec, Function constructors, dynamic compile calls, or expression languages, receive data that an attacker influences. This gives full control of the application process.

## Signs in code
Calls to eval, exec, compile, setTimeout or setInterval with strings, new Function, and expression evaluators fed from request data, files or databases. Dynamic imports built from input.

## Severity and context
Critical. Usually leads to remote code execution.

## Likely false positives
Evaluation of constant strings, or of values proven to be numbers through strict parsing before use.

## How to fix
Remove evaluation entirely and use safe parsers such as a JSON parser or a literal-only parser. Map user choices to fixed functions through a lookup table. If an expression language is needed, use a sandboxed one with an allow-list.

## Related scanner signals
SAST rules named dangerous-eval, exec-used, and similar.
