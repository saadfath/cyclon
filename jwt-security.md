# JWT Security

## 1. Description

JSON Web Token (JWT) is a compact token format commonly used to transmit information between parties and authenticate users in web applications and APIs.

A JWT typically contains three parts:

1. Header – identifies the token type and signing algorithm.
2. Payload – contains claims such as user identifiers and expiration information.
3. Signature – allows the receiving application to verify the token's integrity and authenticity.

JWT security vulnerabilities occur when applications generate, store, or validate tokens incorrectly.

If token validation is insufficient, attackers may be able to impersonate users, access protected resources, or manipulate authentication claims.

Potential consequences include:

- Authentication bypass.
- Unauthorized account access.
- Privilege escalation.
- Token impersonation.
- Exposure of sensitive information.
- Unauthorized API access.

### Example

Imagine an application that uses JWTs to authenticate API requests.

If the application accepts tokens without properly verifying their signatures, an attacker may be able to submit manipulated authentication claims.

## 2. Common Causes

JWT vulnerabilities commonly occur when:

- Token signatures are not verified.
- Applications accept unexpected signing algorithms.
- Token expiration is not enforced.
- Signing secrets are weak or hardcoded.
- Sensitive information is stored inside JWT payloads.
- Token claims are not validated.
- Tokens are accepted without checking their issuer or audience.
- Applications use insecure token storage.
- Authentication tokens are not invalidated when necessary.
- Different services validate tokens inconsistently.
- Applications trust unverified token payloads.

## 3. Vulnerable Code Patterns

### Pattern 1: Decoding without signature verification

Python example:

```python
import jwt

def authenticate_token(token):
    payload = jwt.decode(
        token,
        options={"verify_signature": False}
    )

    return payload
```

**Problem:**

The application explicitly disables signature verification.

The decoded claims cannot be trusted as authenticated information.

### Pattern 2: Weak signing secret

```python
import jwt

SECRET_KEY = "secret123"

def create_token(user_id):
    return jwt.encode(
        {"user_id": user_id},
        SECRET_KEY,
        algorithm="HS256"
    )
```

**Problem:**

The application uses a predictable signing secret.

If the secret is discovered, an attacker may be able to forge tokens.

### Pattern 3: Missing expiration

```python
import jwt

def create_token(user_id, secret):
    return jwt.encode(
        {"user_id": user_id},
        secret,
        algorithm="HS256"
    )
```

**Problem:**

The token does not contain an expiration claim.

Without an expiration policy, a token may remain valid indefinitely unless another mechanism invalidates it.

### Pattern 4: Trusting unverified claims

```python
import jwt

def get_user_role(token):
    payload = jwt.decode(
        token,
        options={"verify_signature": False}
    )

    return payload.get("role")
```

**Problem:**

The application uses an unverified token claim to determine the user's role.

Authentication and authorization decisions must never rely on untrusted claims.

## 4. Safer Implementation

A secure JWT implementation should:

- Verify token signatures.
- Explicitly allow only expected signing algorithms.
- Use strong, securely managed signing keys.
- Validate expiration claims.
- Validate issuer and audience where applicable.
- Validate other required claims.
- Avoid storing sensitive information in JWT payloads.
- Use secure token transmission and storage.
- Apply appropriate token expiration policies.
- Implement token revocation or rotation where necessary.
- Ensure all services enforce consistent validation rules.

### Example: Secure JWT validation

```python
import jwt

SECRET_KEY = load_secret_from_environment()

def verify_token(token):
    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=["HS256"],
            options={
                "require": ["exp", "sub"]
            },
            issuer="https://auth.example.com",
            audience="example-api"
        )

        return payload

    except jwt.InvalidTokenError:
        return None
```

**Explanation:**

- `algorithms=["HS256"]` restricts accepted algorithms.
- Signature verification is enabled by default.
- `exp` is required to enforce token expiration.
- `sub` is required to identify the token subject.
- `issuer` checks who issued the token.
- `audience` checks which application the token is intended for.
- Invalid tokens are rejected.

**Important:** The issuer and audience values must match the application's actual configuration. The signing secret must be securely managed and must not be hardcoded.

## 5. Detection Indicators

Cyclone should investigate the following patterns:

| Indicator | Description |
|---|---|
| Disabled signature verification | JWT decoding explicitly disables signature verification. |
| Weak signing secret | Predictable or hardcoded signing keys are used. |
| Missing expiration | Tokens do not enforce an expiration policy. |
| Algorithm confusion | Unexpected or insecure algorithms are accepted. |
| Missing issuer validation | Token issuer is not checked when required. |
| Missing audience validation | Tokens are accepted without verifying their intended recipient. |
| Unverified claims | Token payloads are trusted before verification. |
| Sensitive payload data | Passwords, secrets, or confidential information are included in claims. |
| Missing token revocation | Compromised or invalidated tokens remain usable when revocation is required. |
| Inconsistent validation | Different application components apply different token-validation rules. |

These indicators require contextual analysis. Not every JWT implementation has the same requirements.

## 6. Python Functions and Libraries to Inspect

Cyclone should inspect common JWT libraries and operations.

### PyJWT

```python
jwt.encode()
jwt.decode()
jwt.get_unverified_header()
jwt.get_unverified_claims()
```

### python-jose

```python
jose.jwt.encode()
jose.jwt.decode()
```

### Authlib

```python
jwt.encode()
jwt.decode()
```

### Token handling

```python
request.headers.get("Authorization")
request.cookies.get()
```

The presence of these functions does not automatically indicate a vulnerability.

Cyclone must inspect token creation, validation, configuration, and how claims are used.

## 7. Detection Logic for Cyclone

Cyclone should analyze JWT implementation using the following process:

1. Identify JWT libraries and token-related operations.
2. Identify where tokens are generated.
3. Inspect the signing algorithm.
4. Determine how signing keys are obtained and managed.
5. Identify where tokens are decoded.
6. Check whether signature verification is enabled.
7. Inspect the allowed algorithm configuration.
8. Check expiration validation.
9. Inspect issuer and audience validation where required.
10. Identify whether unverified claims influence authentication or authorization.
11. Check whether sensitive information is included in token payloads.
12. Inspect token revocation and rotation mechanisms where necessary.

### Important distinction

Using `jwt.decode()` does not automatically indicate a vulnerability.

For example, an application may correctly verify signatures, enforce expiration, and validate required claims.

Likewise, decoding a token without signature verification may be acceptable for limited non-security purposes, such as inspecting an untrusted header before a separate secure validation step.

However, unverified claims must never be trusted for authentication or authorization decisions.

Cyclone must analyze how the decoded information is used.

## 8. Severity Assessment

| Severity | Conditions |
|---|---|
| Critical | Token-validation weaknesses enable broad compromise of privileged accounts or critical systems. |
| High | Attackers can forge or manipulate authentication tokens and gain unauthorized access. |
| Medium | Weak token controls create meaningful authentication or information-disclosure risks. |
| Low | Limited token-handling weaknesses with restricted impact. |
| Informational | Suspicious JWT configuration without sufficient evidence of exploitation. |

Severity should consider:

- Whether signature verification is enforced.
- Whether signing keys are compromised or predictable.
- Which claims influence authorization.
- Whether administrative access is affected.
- Token lifetime and revocation mechanisms.
- Existing authentication controls.

Do not assign severity based only on the presence of a JWT library.

## 9. Evidence Collection

For every potential JWT finding, Cyclone should collect:

- File name.
- Function name.
- Line number.
- JWT library.
- Token generation logic.
- Signing algorithm.
- Signing key source.
- Signature verification configuration.
- Expiration validation.
- Issuer and audience validation.
- Claims used for authorization.
- Token storage and transmission mechanisms.
- Revocation and rotation implementation.

Cyclone must distinguish between confirmed evidence and assumptions.

## 10. Recommended Fixes

- Always verify token signatures before trusting claims.
- Explicitly configure accepted signing algorithms.
- Use strong, securely managed signing keys.
- Never hardcode signing secrets.
- Require and validate expiration claims.
- Validate issuer and audience where appropriate.
- Validate required claims.
- Never use unverified claims for authorization decisions.
- Avoid storing sensitive information in JWT payloads.
- Protect tokens during transmission and storage.
- Implement token rotation and revocation where necessary.
- Apply consistent validation across application services.
- Keep JWT libraries updated.

## 11. False Positives

Cyclone should avoid reporting every JWT decoding operation as vulnerable.

Possible false positives include:

- Token decoding performed only for non-security inspection.
- Signature verification performed by centralized middleware.
- Token expiration validated by an external identity provider.
- Signing keys managed through a secure key-management service.
- Revocation handled through a centralized authentication system.
- Issuer and audience validation performed by shared authentication components.

The scanner should inspect the complete token lifecycle before reporting a vulnerability.

## 12. RAG Knowledge Summary

**Vulnerability:** JWT Security Weaknesses

**Category:** Authentication / Token Security

**Affected Languages:** Python and other languages implementing JWT authentication.

**Primary Risk:** Improper token validation may allow authentication bypass, token impersonation, or unauthorized access.

**Common Sources:**
- Authorization headers.
- Authentication cookies.
- API requests.
- Login endpoints.
- External identity providers.

**Common Sinks:**
- `jwt.decode()`
- `jose.jwt.decode()`
- Authentication middleware.
- Authorization checks.
- User-role determination.
- Protected API endpoints.

**Detection Strategy:**

Identify JWT generation and decoding operations, inspect signing algorithms and key management, verify signature and claim validation, and trace whether token claims influence security decisions.

**Recommended Fix:**

Enforce signature verification, explicitly restrict algorithms, securely manage signing keys, validate expiration and required claims, and never trust unverified token information.

**Confidence Requirements:**

The presence of JWT decoding alone is insufficient to confirm a vulnerability. Cyclone must establish that token validation is missing or incorrect and determine whether untrusted claims can influence security decisions.

**Important:**

JWT payloads are generally encoded, not encrypted.

Anyone who obtains a standard signed JWT can usually read its payload. Sensitive information such as passwords, private keys, and confidential personal data should not be placed inside ordinary JWT claims.

RAG should provide security knowledge and explain findings. The scanner's actual code analysis must independently establish whether the vulnerability exists.
