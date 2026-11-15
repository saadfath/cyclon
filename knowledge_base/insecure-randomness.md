# Insecure Randomness

**CWE:** CWE-330, CWE-338
**OWASP:** A02 Cryptographic Failures

## What it is
Security-sensitive values such as tokens, reset codes, session ids and keys are generated with a predictable random generator.

## How it happens
Standard pseudo-random generators designed for simulations or games can be predicted once a few outputs are observed. Time-based seeds make guessing easier.

## Signs in code
Use of general-purpose random functions, such as Math.random, the Python random module, or rand in C, to create tokens, passwords, one-time codes or keys. Seeding with the current time.

## Severity and context
High when the value protects authentication or secrecy. Low for cosmetic uses.

## Likely false positives
Randomness used for shuffling UI elements, test data, load balancing or jitter.

## How to fix
Use the operating-system secure generator: the secrets module in Python, crypto random functions in Node.js, SecureRandom in Java, or equivalent. Generate enough length. Make tokens single-use and short-lived.

## Related scanner signals
SAST insecure-random rules.
