# Server-Side Template Injection (SSTI)

## Overview
User input is concatenated into a template string that is then rendered by the template engine (Jinja2, Twig, Freemarker, Velocity, Handlebars, ERB). The attacker's input runs as template code.
- CWE-1336, CWE-94 | OWASP A03:2021 Injection

## Why it matters
Often leads to Remote Code Execution (RCE) on the server.

## Vulnerable patterns
```python
# Flask / Jinja2: input becomes part of the template itself
return render_template_string("Hello " + name)
return Template(user_input).render()
```
```js
// Handlebars/Pug/EJS compiled from user input
const tpl = ejs.render(req.query.tpl, data);
```
Probe payload: `{{7*7}}` returning `49` confirms injection.

## How to detect
- `render_template_string`, `Template(...)`, `Environment().from_string(...)` with non-constant input.
- `ejs.render`, `pug.compile`, `handlebars.compile` where the template comes from a request.

## False positives
- Template string is a constant and user data is passed only as context variables.

## Fix
- Never build templates from user input; pass data as context: `render_template("page.html", name=name)`.
- If user templates are required, use a sandboxed environment (`jinja2.sandbox.SandboxedEnvironment`) and a strict allow-list.
- Keep autoescaping enabled.

## Severity
Critical when input reaches the template compiler.
