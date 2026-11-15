# Regular Expression Denial of Service (ReDoS)

**CWE:** CWE-1333, CWE-400
**OWASP:** A04 Insecure Design

## What it is
A regular expression with catastrophic backtracking makes the CPU spend a very long time on a short crafted input, freezing a worker or a whole server.

## How it happens
Patterns containing nested repetition or overlapping alternatives, matched with engines that backtrack, cause running time to grow exponentially or polynomially with input length.

## Signs in code
Expressions with nested quantifiers like a group repeated with plus inside another plus, or alternations where branches overlap. Expressions used on long, user-controlled strings such as emails, URLs and headers. Regex built from user input.

## Severity and context
Medium. High for single-threaded servers where one request blocks everyone.

## Likely false positives
Patterns run only on short, fixed-length or already length-limited inputs.

## How to fix
Limit input length before matching. Rewrite the pattern to remove ambiguity. Use a linear-time engine such as RE2. Set matching timeouts where supported. Never compile user input as a pattern without escaping.

## Related scanner signals
SAST ReDoS detectors, dependency advisories for validators.
