---
id: report-format
title: Format of the Security Report
type: guideline
---

## Purpose
Every finding in the Cyclone report must use the same structure, so developers can read it quickly and the output can be processed by other tools.

## Fields for each finding
- **title:** a short name of the problem (for example "SQL injection in get_user").
- **vulnerability_type:** the knowledge file id (for example `sql-injection`).
- **file:** the path of the affected file.
- **line:** the line number or range.
- **scanner:** the tool that found it and the rule name.
- **severity:** low, medium, high, or critical. Take it from the scanner or the knowledge file. Do not invent it.
- **confidence:** high, medium, or low, chosen using the analysis guidelines.
- **is_likely_real:** yes, no, or unsure.
- **explanation:** why the code is risky or why it is probably a false positive, in simple words.
- **impact:** what an attacker could do.
- **evidence:** the exact lines of code and the reasoning that supports the decision.
- **fix:** the recommended change, with a safer code example when possible.
- **references:** CWE, OWASP category, and CVE or advisory ID when available.

## JSON example
```json
{
  "title": "SQL injection in get_user",
  "vulnerability_type": "sql-injection",
  "file": "app/users.py",
  "line": 12,
  "scanner": "semgrep: string-concat-in-query",
  "severity": "high",
  "confidence": "high",
  "is_likely_real": "yes",
  "explanation": "The user_id value is added to the SQL query with string concatenation, so the input can change the query.",
  "impact": "An attacker could read or change data in the users table.",
  "evidence": "query = \"SELECT * FROM users WHERE id = \" + user_id",
  "fix": "Use a parameterized query: cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))",
  "references": ["CWE-89", "OWASP A03 Injection"]
}
```

## Rules
- Always return all fields. If a value is unknown, write "unknown" and do not remove the field.
- Write the explanation and the fix in simple, clear language.
- Never include a full real secret in any field. Hide most of it.
- If the finding is probably a false positive, still return the full structure and explain why.
