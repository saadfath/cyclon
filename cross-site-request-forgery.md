# Cross-Site Request Forgery (CSRF)

## 1. Overview

Cross-Site Request Forgery (CSRF) is a web security vulnerability that occurs when an application accepts unauthorized requests because it does not adequately verify that the request was intentionally initiated by the authenticated user.

Browsers automatically attach certain authentication credentials, such as session cookies, to applicable requests.

An attacker may exploit this behavior to cause a victim's browser to submit an unintended request to an application where the victim is authenticated.

Depending on the application's functionality, this may result in unauthorized changes to user data or account settings.

CSRF primarily affects applications that rely on automatically transmitted browser credentials.

## 2. Common Types

### 2.1 Traditional CSRF

Occurs when an application performs sensitive operations without verifying that the request originated from an authorized interaction.

### 2.2 Stored CSRF-Related Content

Some applications contain functionality that allows untrusted content to trigger sensitive requests when users interact with it.

The security issue depends on how requests are authenticated and validated.

### 2.3 Login CSRF

Occurs when an attacker causes a victim to authenticate into an application using an account controlled by the attacker.

This may cause the victim to unknowingly interact with the wrong account.

## 3. Detection Indicators

The scanner should investigate:

- State-changing HTTP endpoints using cookie-based authentication.
- Missing CSRF token validation.
- Missing request-origin verification.
- Sensitive operations implemented through GET requests.
- Forms that perform state-changing operations without CSRF protection.
- Authentication mechanisms that rely on automatically transmitted cookies.
- Incorrect SameSite cookie configuration.
- CSRF protection disabled in framework configuration.

## 4. Potentially Vulnerable Patterns

### Python Flask Application

Example:

    from flask import Flask, request

    app = Flask(__name__)

    @app.route("/change-email", methods=["POST"])
    def change_email():
        email = request.form.get("email")

        update_user_email(email)

        return "Email updated"

The endpoint performs a sensitive state-changing operation.

If the application relies on automatically transmitted session cookies and does not implement appropriate CSRF protections, this may introduce a CSRF vulnerability.

The absence of a token in this isolated example is not sufficient to prove the application is vulnerable. Other protection mechanisms may exist.

### Django Application

Investigate whether CSRF protection has been disabled through framework settings or decorators.

Relevant indicators include:

- csrf_exempt
- CSRF middleware configuration
- Missing CSRF token validation in applicable request flows.

## 5. Safe Patterns

### 5.1 CSRF Tokens

Use unpredictable, session-associated CSRF tokens for state-changing requests.

The server should validate the token before performing the requested operation.

### 5.2 SameSite Cookies

Configure session cookies with an appropriate SameSite policy.

Common values:

- Strict: Restricts cookies in cross-site contexts.
- Lax: Allows certain top-level cross-site navigations.
- None: Allows cross-site cookie transmission and requires Secure.

SameSite is an additional defense and should not automatically replace other CSRF protections.

### 5.3 Origin and Referer Validation

For applicable requests, validate the Origin header and use Referer checks as an additional security measure.

These checks should account for legitimate application deployment and proxy configurations.

### 5.4 Safe HTTP Method Usage

Use GET requests for operations that retrieve information rather than modify application state.

Sensitive state-changing operations should use appropriate methods and CSRF protections.

## 6. Relevant Python Framework Indicators

### Flask

Investigate:

- Flask-WTF CSRFProtect.
- CSRF token validation.
- Session cookie configuration.

### Django

Investigate:

- CsrfViewMiddleware.
- csrf_exempt.
- csrf_protect.
- CSRF_TRUSTED_ORIGINS.
- CSRF token validation.

### FastAPI and Starlette

Investigate:

- Cookie-based authentication.
- CSRF middleware or equivalent protection.
- State-changing endpoints.
- Origin validation.

These frameworks and functions must be evaluated in their application context.

## 7. False Positives

The scanner should not automatically classify every POST endpoint as vulnerable.

Consider:

- The application uses CSRF token validation.
- A framework provides centralized CSRF protection.
- The endpoint uses authentication that is not automatically attached by the browser.
- SameSite cookie restrictions provide relevant protection.
- Origin validation is implemented centrally.
- The endpoint does not perform state-changing operations.
- The application uses an appropriate alternative request-authentication mechanism.

The scanner should analyze the complete authentication and request-validation flow.

## 8. Severity Assessment

Severity depends on:

- Whether the application uses cookie-based authentication.
- Whether the endpoint modifies sensitive information.
- Whether CSRF protections are missing or incorrectly implemented.
- Whether the victim must be authenticated.
- Whether the affected operation has significant consequences.

Typical severity: Medium to High.

## 9. Remediation

Recommended fixes:

1. Implement CSRF tokens for state-changing requests.
2. Validate tokens on the server side.
3. Configure appropriate SameSite cookie attributes.
4. Validate Origin headers where appropriate.
5. Avoid state-changing operations through GET requests.
6. Use framework-provided CSRF protection.
7. Avoid disabling CSRF middleware without a justified security design.
8. Review all sensitive endpoints that rely on cookie-based authentication.

## 10. CWE References

- CWE-352: Cross-Site Request Forgery (CSRF).
- CWE-1275: Sensitive Cookie with Improper SameSite Attribute.

## 11. Scanner Output Fields

When reporting a potential CSRF vulnerability, provide:

- vulnerability: Cross-Site Request Forgery
- vulnerability_type: Traditional CSRF / Login CSRF / Unknown
- file: Source file containing the finding
- location: Relevant line number or code location
- evidence: Relevant code fragment
- endpoint: Affected route or API endpoint
- http_method: HTTP method used
- authentication_type: Cookie-Based / Token-Based / Unknown
- csrf_protection: Present / Missing / Unknown
- origin_validation: Present / Missing / Unknown
- explanation: Why the request may be accepted without sufficient verification
- severity: Estimated severity
- confidence: Confidence in the finding
- false_positive_reason: Possible reasons the endpoint is protected
- remediation: Recommended correction
- cwe: CWE-352

## 12. References

- OWASP Cross-Site Request Forgery Prevention Cheat Sheet
  https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html

- OWASP CSRF
  https://owasp.org/www-community/attacks/csrf

- Django CSRF Protection
  https://docs.djangoproject.com/en/stable/ref/csrf/

- CWE-352
  https://cwe.mitre.org/data/definitions/352.html
