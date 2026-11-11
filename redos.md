# Regular Expression Denial of Service (ReDoS)

## Overview
A regex with nested or overlapping quantifiers takes exponential time on crafted input, freezing the process (especially single-threaded Node.js).
- CWE-1333, CWE-400 | OWASP A05:2021

## Vulnerable patterns
```
(a+)+$        (a|aa)+$        (.*a){20}        ^(\w+\s?)*$
([a-zA-Z]+)*@       (x+x+)+y
```
```js
const re = new RegExp(req.query.pattern);   // user-controlled regex
```
Attack: `"aaaaaaaaaaaaaaaaaaaaaaaa!"` against `(a+)+$`.

## How to detect
- Nested quantifiers (`(...+)+`, `(...*)*`), alternation with overlap under a quantifier.
- Regexes built from user input.
- Email/URL validators copied from old blog posts.
- Tools: `safe-regex`, `rxxr2`, `recheck`.

## False positives
- Input length is strictly bounded and small.
- Engine with linear-time guarantees (RE2, Rust `regex`, Go `regexp`).

## Fix
- Rewrite the pattern without ambiguity; use atomic groups/possessive quantifiers where supported.
- Limit input length before matching.
- Use RE2 (`google-re2`), or run matching with a timeout.
- Never compile user-supplied patterns; escape them (`re.escape`).

## Severity
Medium (DoS), High for unauthenticated, internet-facing endpoints.
