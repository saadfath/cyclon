# Weak Cryptography

## 1. Overview

Weak Cryptography is a security vulnerability category that occurs when an application uses outdated, insecure, or incorrectly implemented cryptographic mechanisms to protect sensitive information.

Cryptography is used to protect data confidentiality, integrity, and authenticity.

Incorrect cryptographic choices or implementations may allow attackers to recover sensitive information, manipulate protected data, or compromise authentication mechanisms.

This vulnerability commonly affects password storage, encryption, digital signatures, API authentication, and secure communication.

## 2. Common Types

### 2.1 Weak Hashing Algorithms

Occurs when applications use outdated hashing algorithms that are unsuitable for security-sensitive operations.

Examples include:

- MD5.
- SHA-1.
- Unsalted SHA-256 for password storage.

Cryptographic hashing and password hashing have different security requirements.

### 2.2 Insecure Password Storage

Occurs when applications store passwords using fast general-purpose hash functions instead of dedicated password-hashing algorithms.

Suitable alternatives include:

- Argon2id.
- bcrypt.
- scrypt.
- PBKDF2.

### 2.3 Weak Encryption Algorithms

Occurs when applications use outdated or insufficiently secure encryption algorithms.

Examples include:

- DES.
- RC4.
- Weak or improperly configured encryption modes.

AES with an authenticated encryption mode such as AES-GCM is generally preferred for modern application encryption.

### 2.4 Hardcoded Cryptographic Keys

Occurs when cryptographic keys or encryption secrets are embedded directly in application source code.

This overlaps with the hardcoded-secrets vulnerability category.

### 2.5 Insecure Random Number Generation

Occurs when applications use predictable random number generators for security-sensitive operations.

Examples include generating authentication tokens or cryptographic keys using Python's random module.

## 3. Detection Indicators

The scanner should investigate:

- Use of MD5 or SHA-1 in security-sensitive contexts.
- Passwords stored using ordinary hash functions.
- Missing salts in password hashing.
- Use of deprecated encryption algorithms.
- Weak encryption modes.
- Hardcoded cryptographic keys.
- Predictable random number generation for security tokens.
- Insecure TLS configurations.
- Improper cryptographic key management.
- Reuse of cryptographic keys in inappropriate contexts.

## 4. Potentially Vulnerable Patterns

### 4.1 Weak Password Hashing

Example:

    import hashlib

    def hash_password(password):
        return hashlib.md5(password.encode()).hexdigest()

The application uses MD5 to hash passwords.

MD5 is not suitable for password storage because it is too fast and vulnerable to efficient offline guessing.

This is a potential weak cryptography vulnerability.

### 4.2 Predictable Random Values

Example:

    import random

    def generate_token():
        return str(random.randint(100000, 999999))

The application uses Python's general-purpose random module to generate a security-sensitive token.

The random module is not designed for cryptographic security.

### 4.3 Weak Encryption

Example:

    from Crypto.Cipher import DES

    cipher = DES.new(key, DES.MODE_ECB)

DES is an outdated encryption algorithm, and ECB mode does not provide appropriate protection for general-purpose application data.

This is a potential weak cryptography finding.

## 5. Safe Patterns

### 5.1 Secure Password Hashing

Use dedicated password-hashing algorithms.

Recommended options:

- Argon2id.
- bcrypt.
- scrypt.
- PBKDF2 with an appropriate configuration.

Password hashing should include unique salts and suitable computational cost parameters.

### 5.2 Cryptographically Secure Randomness

Use Python's secrets module for security-sensitive random values.

Example:

    import secrets

    token = secrets.token_urlsafe(32)

### 5.3 Modern Encryption

Use established cryptographic libraries and authenticated encryption modes.

AES-GCM is one commonly used option.

Avoid designing custom cryptographic algorithms.

### 5.4 Secure Key Management

- Avoid hardcoding cryptographic keys.
- Store secrets in appropriate secret-management systems.
- Restrict access to cryptographic keys.
- Rotate compromised keys.
- Avoid logging sensitive cryptographic material.

## 6. Relevant Python Functions and Libraries

The scanner should recognize:

### Hashing

- hashlib.md5()
- hashlib.sha1()
- hashlib.sha256()
- hashlib.pbkdf2_hmac()

### Password Hashing

- bcrypt.hashpw()
- argon2.PasswordHasher()
- scrypt()

### Random Generation

- random.random()
- random.randint()
- random.choice()
- secrets.token_bytes()
- secrets.token_urlsafe()
- secrets.randbelow()

### Encryption

- DES.new()
- AES.new()
- Cryptography Fernet.
- Cryptography Cipher.

The scanner must consider the algorithm, configuration, and security context.

For example, SHA-256 is not inherently insecure. Its suitability depends on its purpose. It is appropriate for many integrity and fingerprinting applications but is not recommended as a standalone password-hashing algorithm.

## 7. False Positives

The scanner should not automatically classify every use of a cryptographic function as vulnerable.

Consider:

- SHA-256 is used for file integrity rather than password storage.
- MD5 is used for non-security-sensitive checksums.
- A weak algorithm appears only in legacy compatibility code.
- Secure cryptographic parameters are configured externally.
- Random values are used for non-security-sensitive purposes.
- A cryptographic library provides secure defaults.

The scanner should determine the purpose of the cryptographic operation before assigning severity.

## 8. Severity Assessment

Severity depends on:

- Which cryptographic operation is affected.
- Whether sensitive information is protected.
- Whether passwords or authentication tokens are involved.
- Whether encryption keys are exposed.
- Whether an attacker can exploit the weakness.
- The sensitivity of the protected information.

Typical severity: Medium to Critical.

## 9. Remediation

Recommended fixes:

1. Replace deprecated cryptographic algorithms.
2. Use Argon2id, bcrypt, scrypt, or PBKDF2 for password storage.
3. Use cryptographically secure random generators.
4. Prefer authenticated encryption modes such as AES-GCM.
5. Avoid hardcoding cryptographic keys.
6. Use established cryptographic libraries.
7. Protect cryptographic keys through appropriate secret management.
8. Apply suitable TLS configurations.
9. Review cryptographic configurations regularly.
10. Avoid implementing custom cryptographic algorithms.

## 10. CWE References

- CWE-327: Use of a Broken or Risky Cryptographic Algorithm.
- CWE-328: Use of Weak Hash.
- CWE-330: Use of Insufficiently Random Values.
- CWE-916: Use of Password Hash With Insufficient Computational Effort.

## 11. Scanner Output Fields

When reporting a potential Weak Cryptography vulnerability, provide:

- vulnerability: Weak Cryptography
- vulnerability_type: Weak Hash / Weak Password Storage / Weak Encryption / Predictable Randomness / Insecure Key Management
- file: Source file containing the finding
- location: Relevant line number or code location
- evidence: Relevant code fragment
- cryptographic_function: Function or library used
- algorithm: Identified cryptographic algorithm
- security_context: Password Storage / Encryption / Token Generation / Integrity / Unknown
- explanation: Why the cryptographic implementation may be insecure
- severity: Estimated severity
- confidence: Confidence in the finding
- false_positive_reason: Possible reasons the implementation is safe
- remediation: Recommended correction
