# Insecure Password Storage

**CWE:** CWE-256, CWE-257, CWE-759, CWE-916
**OWASP:** A02 Cryptographic Failures

## What it is
Passwords are kept in plain text, reversibly encrypted, or hashed with fast algorithms, so a database leak exposes user passwords.

## How it happens
Developers use MD5, SHA-1 or plain SHA-256, skip per-user salts, or store passwords in logs and configuration. Fast hashes allow billions of guesses per second.

## Signs in code
Hashing functions from the fast family applied to passwords. Password columns holding readable text. Home-made salting or iteration schemes. Comparison with ordinary string equality.

## Severity and context
High. A breach becomes account takeover across other sites through password reuse.

## Likely false positives
Fast hashes used for non-password purposes such as file checksums.

## How to fix
Use a dedicated password hashing algorithm: Argon2id, scrypt or bcrypt, with sensible cost settings. Let the library generate salts. Compare with constant-time functions. Plan migration by rehashing at next login.

## Related scanner signals
SAST weak-hash rules near password variables. Database dump scans.
