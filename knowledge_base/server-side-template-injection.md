# Server-Side Template Injection (SSTI)

**CWE:** CWE-1336, CWE-94
**OWASP:** A03 Injection

## What it is
User input is treated as part of a template and evaluated by the template engine on the server, which can expose internal data or lead to remote code execution.

## How it happens
The mistake is building the template text itself from user input, instead of passing user input as data into a fixed template. Engines like Jinja2, Twig, Freemarker and Velocity can reach internal objects through expressions.

## Signs in code
Functions that render a template from a string, where that string contains request data. Email, report or notification features where users edit templates. Format strings built from input.

## Severity and context
Critical when expressions can reach the runtime. A simple arithmetic expression echoing back in a response is a common detection sign.

## Likely false positives
Templates loaded from fixed files with user values passed only as variables.

## How to fix
Never concatenate user input into template source. Pass input as variables. If users must edit templates, use a logic-less or sandboxed engine with a strict allow-list. Run rendering with minimal privileges.

## Related scanner signals
SAST rules on render-from-string functions. DAST probes using harmless expression markers.
