---
id: hardcoded-secrets
title: Hardcoded Secrets
cwe: CWE-798
owasp: A07 Identification and Authentication Failures
severity: high
languages: [python, javascript, java, php, go, any]
scanner_rules: [gitleaks, generic-api-key, aws-access-key, private-key]
---

## What it is
A hardcoded secret is a password, API key, token, or private key written directly in the source code or in a config file saved in the repository. Anyone who can read the code can use the secret.

## How it happens
Developers put a secret in the code to test quickly and forget to remove it. Then the code is committed to Git. Even if the secret is deleted later, it stays in the Git history and can still be found.

## Vulnerable example
```python
API_KEY = "sk_live_51H8xExampleKey1234567890"
DB_PASSWORD = "admin123"

connection = connect(host="db.example.com", password=DB_PASSWORD)
```

## Safe example
```python
import os

API_KEY = os.environ["API_KEY"]
DB_PASSWORD = os.environ["DB_PASSWORD"]

connection = connect(host="db.example.com", password=DB_PASSWORD)
```
The secrets are read from environment variables (or a secret manager) and are never saved in the repository.

## How to detect it
- Variable names like `password`, `secret`, `token`, `api_key`, `private_key` assigned to a string value.
- Strings with known formats (for example AWS keys starting with `AKIA`, or blocks starting with `-----BEGIN PRIVATE KEY-----`).
- Long random-looking strings (high entropy) in code or config files.
- `.env` files or config files with real values committed to the repository.
- Secrets in old commits, not only in the current files.

## Impact
- An attacker can use the key to access cloud services, databases, or paid APIs.
- Data theft, data deletion, or high unexpected costs.
- Because of Git history, the secret is exposed even after the file is fixed.

## How to fix it
1. Revoke the exposed secret and create a new one. This is the most important step, because the old one must be treated as stolen.
2. Move the new secret to an environment variable or a secret manager.
3. Add `.env` and other secret files to `.gitignore`.
4. Remove the secret from Git history if needed (for example with `git filter-repo`).
5. Add a pre-commit check with Gitleaks to stop it from happening again.

## False positives
- Example or placeholder values like `"your-api-key-here"`, `"changeme"`, or `"xxxx"`.
- Test files using fake credentials that are not valid anywhere.
- Public keys, which are meant to be shared (only private keys are secret).
- Long random strings that are not secrets, such as hashes, IDs, or commit SHAs.

## Confidence guide
- **High:** the string matches a known secret format (AWS key, private key block) or is a real-looking value assigned to a secret-like variable name.
- **Medium:** a secret-like variable name with a value that could be real, in code that is not a test.
- **Low:** a placeholder, an obvious example value, a hash or ID, or a value inside a test or documentation file.
