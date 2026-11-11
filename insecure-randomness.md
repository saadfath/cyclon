# Insecure Randomness

## Overview
A predictable pseudo-random generator is used for security-sensitive values (tokens, passwords, reset codes, session ids, keys, IVs, nonces).
- CWE-330, CWE-338, CWE-339 | OWASP A02:2021 Cryptographic Failures

## Vulnerable patterns
```python
import random
token = "".join(random.choice(chars) for _ in range(32))
```
```js
const token = Math.random().toString(36).slice(2);
```
```java
new Random().nextInt();   // use SecureRandom
```
```c
rand(); srand(time(NULL));
```

## How to detect
- `random`, `Math.random`, `java.util.Random`, `rand()` in code that names the result `token`, `secret`, `key`, `otp`, `reset`, `session`, `salt`, `nonce`.

## False positives
- Random used for UI effects, shuffling a playlist, test data, jitter/backoff.

## Fix
- Python: `secrets.token_urlsafe(32)` / `secrets.token_hex`.
- Node: `crypto.randomBytes(32)` / `crypto.randomUUID()`.
- Java: `SecureRandom`. Go: `crypto/rand`. C: `getrandom()` / `/dev/urandom`.
- Use at least 128 bits of entropy for tokens.

## Severity
Medium to High when tokens guard authentication or password reset.
