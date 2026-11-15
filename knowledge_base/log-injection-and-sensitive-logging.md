# Log Injection and Sensitive Data in Logs

**CWE:** CWE-117, CWE-532
**OWASP:** A09 Logging and Monitoring Failures

## What it is
Two related problems: attackers forge or hide log entries by inserting line breaks, and applications write secrets or personal data into logs.

## How it happens
User text is written to logs without neutralizing newline characters, so fake entries appear. Developers also log full requests, tokens, passwords, card numbers or health data during debugging and forget to remove it.

## Signs in code
Logging calls that include raw request bodies, headers, authorization values, passwords or whole user objects. Log statements using user input without encoding.

## Severity and context
Medium. Becomes high when logs are widely accessible or shipped to third parties.

## Likely false positives
Logging of non-sensitive identifiers, or fields already masked.

## How to fix
Strip or encode line breaks and control characters in logged user input. Log identifiers instead of secrets. Mask or hash sensitive fields. Use structured logging with field allow-lists. Restrict log access and set retention.

## Related scanner signals
Secret scanners finding tokens in log files. SAST rules on logging of sensitive variable names.
