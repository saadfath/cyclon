# Format String Vulnerabilities

**CWE:** CWE-134
**OWASP:** A03 Injection

## What it is
Untrusted input is used as the format text of printf-style functions, letting attackers read memory, crash the program or write to memory.

## How it happens
Format functions interpret special conversion markers. If a user supplies the marker text, the function pulls extra values from the stack or writes counts to memory addresses.

## Signs in code
A printf-family function (printf, fprintf, sprintf, snprintf, syslog) where the first format argument is a variable rather than a literal. Logging wrappers that forward their message as the format. Same pattern in Python, Java and Go with user-controlled format strings.

## Severity and context
High in C and C++ with attacker-controlled input. Lower, mostly information disclosure, in managed languages.

## Likely false positives
Format arguments that are string literals, with user data passed only as later arguments.

## How to fix
Always use a constant format string and pass user data as separate arguments. Compile with format security warnings enabled and treat them as errors. Review logging helpers that wrap formatting functions.

## Related scanner signals
Compiler format warnings, SAST rules on non-literal format arguments.
