# Rate Limiting

## 1. Description

Rate limiting is a security mechanism that restricts how many requests a client can make to an application within a specific period.

A rate-limiting vulnerability occurs when an application fails to enforce appropriate request limits on sensitive or resource-intensive operations.

Without proper limits, attackers may abuse application endpoints by sending excessive requests.

This can lead to:

- Brute-force attacks against login endpoints.
- Password-reset abuse.
- API resource exhaustion.
- Automated account creation.
- Excessive resource consumption.
- Denial of Service (DoS).

### Example

Imagine an application that provides a login endpoint.

If the application allows unlimited login attempts, an attacker may repeatedly submit password guesses without encountering any restrictions.

Rate limiting helps control this behavior.

## 2. Common Causes

Rate-limiting weaknesses commonly occur when:

- Login endpoints allow unlimited authentication attempts.
- Password-reset endpoints have no request restrictions.
- Public APIs accept unlimited requests.
- Expensive operations have no usage limits.
- Rate limits are applied only on the client side.
- Rate limits can be bypassed through inconsistent client identification.
- Different application instances do not share rate-limit state.
- Rate-limit middleware is configured incorrectly.
- Sensitive endpoints are excluded from rate-limiting rules.
- Applications do not enforce request-size or resource-consumption limits.

## 3. Vulnerable Code Patterns

### Pattern 1: Login without rate limiting

Python example:

```python
@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]

    return authenticate(username, password)
```

**Problem:**

The endpoint performs authentication without any visible request-limiting mechanism.

An attacker may repeatedly submit authentication attempts.

Note: Rate limiting might exist in middleware or infrastructure outside this function. Cyclone must inspect the complete application before reporting a finding.

### Pattern 2: Unlimited password-reset requests

```python
@app.route("/reset-password", methods=["POST"])
def reset_password():
    email = request.form["email"]

    send_reset_email(email)

    return {"message": "Request processed"}
```

**Problem:**

The endpoint has no visible restriction on how frequently password-reset requests can be submitted.

This may allow automated abuse and excessive email generation.

### Pattern 3: Unrestricted expensive operation

```python
@app.route("/generate-report")
def generate_report():
    return create_expensive_report()
```

**Problem:**

The endpoint performs a potentially expensive operation without visible request limits or resource controls.

Repeated requests may consume significant server resources.

## 4. Safer Implementation

A secure application should:

- Apply server-side rate limits to sensitive endpoints.
- Use different limits for different operations.
- Limit login and password-reset attempts.
- Apply account-based and network-based controls where appropriate.
- Use shared rate-limit storage in distributed applications.
- Return HTTP 429 when request limits are exceeded.
- Include appropriate `Retry-After` information when possible.
- Monitor repeated failures and unusual traffic patterns.
- Protect expensive operations with resource limits.
- Avoid relying exclusively on client-side restrictions.

### Example: Flask-Limiter

```python
from flask import Flask
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

@app.route("/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():
    return authenticate_user()
```

**Explanation:**

- `Limiter` configures request-limiting behavior.
- `get_remote_address` identifies the client using its remote address.
- `@limiter.limit()` applies a specific limit to an endpoint.
- Requests exceeding the configured limit are rejected.

**Important:** This is an illustrative configuration. Production systems should use trusted client identification, shared storage where necessary, and account-level controls for authentication endpoints.

## 5. Detection Indicators

Cyclone should investigate the following patterns:

| Indicator | Description |
|---|---|
| Missing login limits | Authentication endpoints have no visible request restrictions. |
| Missing reset limits | Password-reset endpoints allow repeated requests. |
| Unlimited API access | Public endpoints have no appropriate usage restrictions. |
| Unrestricted expensive operations | Resource-intensive functions can be repeatedly invoked. |
| Client-side-only limits | Restrictions exist only in frontend code. |
| Missing 429 handling | Excessive requests are not properly rejected. |
| Missing shared storage | Distributed application instances do not share rate-limit state where required. |
| Weak client identification | Rate limits rely on untrusted or incorrectly configured client identifiers. |

These indicators require contextual analysis. Not every endpoint needs the same rate limit.

## 6. Python Functions and Libraries to Inspect

Cyclone should inspect common rate-limiting implementations.

### Flask-Limiter

```python
Limiter()
@limiter.limit()
@limiter.shared_limit()
```

### Django REST Framework

```python
AnonRateThrottle
UserRateThrottle
ScopedRateThrottle
```

### FastAPI

```python
slowapi.Limiter
@limiter.limit()
```

### Redis

```python
redis.incr()
redis.expire()
redis.set()
```

### HTTP response handling

```python
abort(429)
```

The presence or absence of these functions alone does not establish whether an application is vulnerable.

Rate limiting may also be implemented through API gateways, reverse proxies, middleware, or external infrastructure.

## 7. Detection Logic for Cyclone

Cyclone should analyze rate-limiting behavior using the following process:

1. Identify public and sensitive application endpoints.
2. Classify endpoints according to their purpose.
3. Identify authentication, password-reset, registration, and expensive operations.
4. Search for rate-limiting middleware and decorators.
5. Inspect whether limits are actually applied to the identified endpoints.
6. Determine how clients are identified.
7. Check whether distributed instances share rate-limit state where necessary.
8. Inspect handling of requests that exceed configured limits.
9. Identify endpoints that perform expensive operations without resource controls.
10. Consider external infrastructure protections when their configuration is available.

### Important distinction

The absence of `@limiter.limit()` inside a function does not automatically mean that the endpoint is vulnerable.

For example, an application may enforce rate limiting globally through middleware or an API gateway.

Cyclone should analyze the complete request-handling architecture before reporting missing rate limiting.

## 8. Severity Assessment

| Severity | Conditions |
|---|---|
| Critical | Severe uncontrolled resource consumption can compromise critical services at scale. |
| High | Sensitive endpoints allow significant automated abuse, such as account attacks or substantial resource exhaustion. |
| Medium | Missing limits create meaningful abuse or availability risks with additional restrictions. |
| Low | Limited exposure with relatively small impact. |
| Informational | Missing visible rate-limiting controls without sufficient evidence of practical impact. |

Severity should consider:

- Endpoint sensitivity.
- Resource consumption.
- Authentication requirements.
- Existing infrastructure protections.
- Potential impact on availability.
- Whether the weakness can be practically abused.

Do not assign severity based only on the absence of a rate-limiting decorator.

## 9. Evidence Collection

For every potential rate-limiting finding, Cyclone should collect:

- File name.
- Endpoint or function name.
- Line number.
- HTTP method.
- Endpoint purpose.
- Existing rate-limiting decorators.
- Middleware configuration.
- Rate-limit storage mechanism.
- Client identification method.
- HTTP 429 response handling.
- Resource-intensive operations.
- External rate-limiting controls, if known.

Cyclone must distinguish between confirmed evidence and assumptions.

## 10. Recommended Fixes

- Apply rate limits to authentication endpoints.
- Restrict password-reset and account-creation requests.
- Configure appropriate limits for public APIs.
- Apply resource controls to expensive operations.
- Use account-based and network-based restrictions where appropriate.
- Store rate-limit state centrally in distributed systems.
- Return HTTP 429 when limits are exceeded.
- Use trusted proxy configuration when identifying client addresses.
- Monitor unusual request patterns.
- Apply request-size and execution-time limits.
- Consider progressive delays and additional verification for suspicious authentication activity.

## 11. False Positives

Cyclone should avoid reporting every endpoint without a local rate-limiting decorator.

Possible false positives include:

- Global rate-limiting middleware.
- Reverse-proxy rate limits.
- API gateway restrictions.
- External authentication-provider protections.
- Shared rate-limiting services.
- Endpoints with intentionally different usage policies.

The scanner should inspect application configuration and available infrastructure evidence before reporting a vulnerability.

## 12. RAG Knowledge Summary

**Vulnerability:** Missing or Insufficient Rate Limiting

**Category:** Application Security / Resource Management

**Affected Languages:** Python and other languages implementing web applications and APIs.

**Primary Risk:** Excessive requests may allow automated abuse, brute-force attempts, or resource exhaustion.

**Common Sources:**
- Login endpoints.
- Password-reset forms.
- Registration endpoints.
- Public API routes.
- Search endpoints.
- Expensive report-generation operations.

**Common Controls:**
- Flask-Limiter.
- Django REST Framework throttling.
- FastAPI rate-limiting middleware.
- Redis-backed request counters.
- Reverse-proxy restrictions.
- API gateway policies.

**Detection Strategy:**

Identify sensitive and resource-intensive endpoints, inspect application-level and infrastructure-level rate limits, and determine whether appropriate restrictions are enforced.

**Recommended Fix:**

Implement server-side request limits, shared rate-limit state where necessary, proper client identification, HTTP 429 handling, and resource-consumption controls.

**Confidence Requirements:**

The absence of a rate-limiting function in an individual endpoint is insufficient to confirm a vulnerability. Cyclone must inspect middleware, framework configuration, and external infrastructure controls where available.

**Important:**

Rate limiting and resource management are related but different controls. Rate limiting restricts request frequency, while resource management also controls request size, execution time, concurrency, and memory consumption.

RAG should provide security knowledge and explain findings. The scanner's actual code analysis must independently establish whether the vulnerability exists.
