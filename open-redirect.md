# Open Redirect

## 1. Description

An Open Redirect vulnerability occurs when an application redirects users to a URL supplied or controlled by an external party without properly validating the destination.

An attacker may abuse this behavior to make a legitimate application redirect users to an untrusted website.

This can make malicious links appear trustworthy because they begin with the domain of a legitimate application.

Open Redirect vulnerabilities commonly affect login systems, authentication callbacks, and URL forwarding functionality.

### Example

Imagine an application that redirects users to a destination specified by a `next` parameter after login.

If the application accepts any URL without validation, a user may be redirected to an unintended external website.

## 2. Common Causes

Open Redirect vulnerabilities commonly occur when:

- User-controlled URLs are passed directly to redirect functions.
- Redirect destinations are not validated.
- Applications accept arbitrary external domains.
- URL validation relies on incomplete string comparisons.
- Redirect parameters are not restricted to approved destinations.
- Authentication callbacks accept untrusted redirect URLs.
- URL parsing is performed incorrectly.
- Redirect validation does not account for URL encoding or normalization.

## 3. Vulnerable Code Patterns

### Pattern 1: Direct user-controlled redirect

Python example:

```python
from flask import Flask, request, redirect

app = Flask(__name__)

@app.route("/redirect")
def redirect_user():
    destination = request.args.get("next")

    return redirect(destination)
```

**Problem:**

The application accepts a destination directly from user input and redirects the browser without validating the destination.

An attacker may provide an untrusted external URL.

### Pattern 2: Redirect after login

```python
def login_success(request):
    next_url = request.args.get("next")

    if authenticate_user():
        return redirect(next_url)
```

**Problem:**

The application redirects users after authentication without establishing whether the requested destination is trusted.

### Pattern 3: Incomplete domain validation

```python
def redirect_user(url):
    if "example.com" in url:
        return redirect(url)

    return "Invalid destination"
```

**Problem:**

Checking whether a URL contains a trusted domain name is not a reliable validation method.

A malicious URL may contain the trusted domain as part of an unrelated hostname or URL component.

## 4. Safer Implementation

A secure redirect implementation should:

- Prefer relative paths instead of arbitrary external URLs.
- Use an explicit allowlist when external destinations are necessary.
- Validate URL scheme and hostname.
- Normalize and parse URLs before making security decisions.
- Avoid substring-based domain validation.
- Reject unexpected schemes.
- Validate authentication callback destinations.
- Use predefined destination identifiers where possible.

### Example: Restricting redirects to local paths

```python
from flask import redirect, request, url_for

@app.route("/redirect")
def redirect_user():
    destination = request.args.get("next", "")

    if destination.startswith("/") and not destination.startswith("//"):
        return redirect(destination)

    return redirect(url_for("home"))
```

**Important:** This is a simplified example, not a complete URL-validation implementation. Production code should use a well-tested URL validation strategy that accounts for URL normalization, backslashes, encoded characters, and framework-specific behavior.

## 5. Detection Indicators

Cyclone should investigate the following patterns:

| Indicator | Description |
|---|---|
| User-controlled redirect | A redirect destination originates from request parameters or user input. |
| Missing destination validation | Redirect URLs are not checked against trusted destinations. |
| Arbitrary external redirects | Applications allow unrestricted external domains. |
| Weak domain validation | Validation uses substring matching or incomplete comparisons. |
| Unvalidated authentication callback | Login or OAuth flows accept untrusted redirect destinations. |
| Unsafe URL normalization | Different URL representations are not handled consistently. |
| Unexpected URL schemes | Redirect destinations accept schemes that are not intended. |

These indicators require contextual analysis. A redirect function is not inherently vulnerable.

## 6. Python Functions and Libraries to Inspect

Cyclone should inspect common redirect functionality.

### Flask

```python
redirect()
request.args.get()
request.form.get()
```

### Django

```python
redirect()
HttpResponseRedirect()
request.GET.get()
```

### FastAPI / Starlette

```python
RedirectResponse()
Request.query_params.get()
```

### URL parsing

```python
urllib.parse.urlparse()
urllib.parse.urlsplit()
urllib.parse.urljoin()
```

The scanner should identify whether user-controlled data reaches a redirect destination and whether validation is enforced.

## 7. Detection Logic for Cyclone

Cyclone should analyze redirect behavior using the following process:

1. Identify redirect functions and response objects.
2. Identify the destination URL passed to each redirect.
3. Trace the destination back to its original source.
4. Determine whether the destination can be influenced by external input.
5. Inspect URL parsing and validation logic.
6. Check whether approved domains or relative paths are enforced.
7. Examine domain comparisons for incomplete validation.
8. Inspect authentication and OAuth redirect flows.
9. Determine whether validation occurs before the redirect.
10. Evaluate whether an attacker can influence the final browser destination.

### Important distinction

Calling `redirect()` does not automatically indicate an Open Redirect vulnerability.

For example:

```python
return redirect("/dashboard")
```

This uses a fixed local destination.

However:

```python
return redirect(request.args.get("next"))
```

This deserves investigation because the destination originates from user-controlled input.

Cyclone must perform data-flow analysis instead of relying exclusively on function names.

## 8. Severity Assessment

| Severity | Conditions |
|---|---|
| Critical | Usually not appropriate for Open Redirect alone; requires additional severe demonstrated impact. |
| High | Redirect behavior enables a serious compromise in a sensitive authentication or trust flow. |
| Medium | Users can be redirected to arbitrary external destinations, creating meaningful phishing or trust-abuse risks. |
| Low | Redirect behavior is restricted or has limited practical impact. |
| Informational | Suspicious redirect patterns exist without sufficient evidence of an exploitable issue. |

Severity should consider:

- Whether external destinations are permitted.
- Whether the redirect affects authentication.
- Whether sensitive tokens or information can be exposed.
- Whether the destination is controlled by an attacker.
- Whether additional security controls are present.

Do not assign severity based only on a redirect function.

## 9. Evidence Collection

For every potential Open Redirect finding, Cyclone should collect:

- File name.
- Function or endpoint name.
- Line number.
- Redirect function used.
- Source of the destination URL.
- User-input data-flow evidence.
- URL validation logic.
- Allowed destination configuration.
- URL normalization behavior.
- Authentication callback configuration.
- Final redirect behavior, if verified.

Cyclone must distinguish between confirmed evidence and assumptions.

## 10. Recommended Fixes

- Prefer fixed relative redirect paths.
- Use explicit destination allowlists when external redirects are required.
- Validate hostnames using proper URL parsing.
- Avoid substring-based domain validation.
- Normalize URLs before validating them.
- Reject unexpected URL schemes.
- Validate redirect destinations in authentication flows.
- Use predefined destination identifiers instead of arbitrary URLs.
- Apply the same validation rules across all redirect endpoints.
- Avoid exposing sensitive authentication information through redirect parameters.

## 11. False Positives

Cyclone should avoid reporting every redirect operation as vulnerable.

Possible false positives include:

- Redirects to fixed internal paths.
- Redirects using predefined destination identifiers.
- Redirects with properly enforced domain allowlists.
- Framework-managed safe redirect mechanisms.
- Redirect destinations validated by centralized middleware.

The scanner should inspect the complete data flow and validation logic before reporting a vulnerability.

## 12. RAG Knowledge Summary

**Vulnerability:** Open Redirect

**Category:** Input Validation / Navigation Security

**Affected Languages:** Python and other languages implementing web applications.

**Primary Risk:** Users may be redirected from a trusted application to an untrusted destination.

**Common Sources:**
- URL query parameters.
- Form submissions.
- Login redirect parameters.
- Authentication callbacks.
- User profile settings.

**Common Sinks:**
- Flask `redirect()`.
- Django `HttpResponseRedirect()`.
- Starlette `RedirectResponse()`.
- Other HTTP redirect response implementations.

**Detection Strategy:**

Identify redirect operations, trace destination URLs to their sources, and determine whether user-controlled destinations are properly validated against trusted paths or domains.

**Recommended Fix:**

Use relative paths or explicit destination allowlists, perform proper URL validation, and reject untrusted redirect destinations.

**Confidence Requirements:**

A redirect operation alone is insufficient to confirm a vulnerability. Cyclone must establish that untrusted input can influence the final destination without effective validation.

**Important:**

Open Redirect and SSRF are different vulnerabilities.

- Open Redirect affects the destination where the user's browser is redirected.
- SSRF affects requests made by the application server itself.

RAG should provide security knowledge and explain findings. The scanner's actual code analysis must independently establish whether the vulnerability exists.
