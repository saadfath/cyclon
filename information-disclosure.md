# Information Disclosure

## 1. Overview

Information Disclosure is a security weakness that occurs when an application exposes information that should not be accessible to unauthorized users.

The exposed information may reveal internal application details, sensitive user data, infrastructure information, or implementation details.

Information disclosure can help attackers understand an application's internal structure and identify additional security weaknesses.

It commonly affects web applications, APIs, backend services, configuration files, and application logs.

## 2. Common Types

### 2.1 Sensitive Data Exposure

Occurs when applications expose confidential information such as personal data, authentication credentials, or private records.

### 2.2 Error Message Disclosure

Occurs when applications return detailed error messages containing internal implementation information.

### 2.3 Debug Information Disclosure

Occurs when debugging information, stack traces, or internal application details are accessible to unauthorized users.

### 2.4 Directory and File Disclosure

Occurs when sensitive files, backups, configuration files, or directory listings are publicly accessible.

### 2.5 API Information Disclosure

Occurs when API responses contain unnecessary or unauthorized information.

For example, an API may return internal database identifiers, private account information, or administrative fields.

## 3. Detection Indicators

The scanner should investigate:

- API responses containing sensitive information.
- Passwords or authentication tokens included in responses.
- Detailed exception messages returned to users.
- Stack traces exposed through HTTP responses.
- Sensitive information written into application logs.
- Configuration files exposed through application routes.
- Publicly accessible backup files.
- Debug endpoints returning internal application information.
- Database errors revealing internal schema details.
- Responses containing unnecessary internal metadata.

## 4. Potentially Vulnerable Patterns

### 4.1 Exposing Internal Exceptions

Example:

    from flask import Flask

    app = Flask(__name__)

    @app.route("/error")
    def error():
        try:
            result = 10 / 0
        except Exception as error:
            return str(error)

The application returns internal exception information directly to the user.

Depending on the exception, this may reveal implementation details.

### 4.2 Exposing Sensitive User Information

Example:

    @app.route("/profile")
    def profile():
        user = {
            "username": "alice",
            "email": "alice@example.com",
            "password_hash": "example_hash"
        }

        return user

The endpoint returns a password hash as part of the user profile response.

Password hashes should not be exposed through ordinary application responses.

### 4.3 Sensitive Information in Logs

Example:

    import logging

    def login(username, password):
        logging.info(
            "Login attempt: username=%s password=%s",
            username,
            password
        )

The application writes a plaintext password into its logs.

This creates a potential information disclosure vulnerability.

## 5. Safe Patterns

### 5.1 Generic Error Responses

Return generic error messages to external users.

Keep detailed diagnostic information in protected application logs.

### 5.2 Response Data Filtering

Return only the information required by the client.

Use explicit response schemas or serializers to prevent accidental exposure of internal fields.

### 5.3 Secure Logging

Avoid logging:

- Passwords.
- Authentication tokens.
- Session identifiers.
- Private cryptographic keys.
- Sensitive personal information.

Sanitize and restrict access to application logs.

### 5.4 Protect Sensitive Files

Ensure configuration files, backups, and internal resources are not exposed through public routes or static file directories.

### 5.5 Access Control

Verify that users are authorized to access the information returned by an endpoint.

## 6. Relevant Python Indicators

The scanner should investigate:

### Logging

- logging.info()
- logging.debug()
- logging.warning()
- logging.error()
- print()

### Exception Handling

- str(exception)
- traceback.format_exc()
- traceback.print_exc()

### Web Responses

- jsonify()
- json.dumps()
- Flask response objects.
- FastAPI response models.

These functions are not inherently insecure. The scanner must determine whether sensitive information reaches an unauthorized destination.

## 7. False Positives

The scanner should not automatically classify every error message or logging operation as information disclosure.

Consider:

- Error details are only available to authorized administrators.
- Stack traces are disabled in production.
- Logs are protected and access-controlled.
- API response schemas intentionally expose the returned fields.
- Data is publicly available by design.
- Sensitive information is properly redacted.
- A debug message is only written to a local development environment.

The scanner should consider the sensitivity of the information and who can access it.

## 8. Severity Assessment

Severity depends on:

- The type of information exposed.
- Whether the information is publicly accessible.
- Whether authentication is required.
- Whether credentials or personal information are involved.
- Whether the exposed information enables additional attacks.
- The number of affected users.

Typical severity: Low to Critical.

Exposing a harmless framework version is different from exposing authentication credentials or private user information.

## 9. Remediation

Recommended fixes:

1. Avoid returning internal exception details to users.
2. Remove passwords and authentication tokens from logs.
3. Filter API responses to include only necessary fields.
4. Restrict access to sensitive files and resources.
5. Disable production debugging interfaces.
6. Apply authorization checks before returning private information.
7. Sanitize sensitive application logs.
8. Protect backups and configuration files.
9. Review API response schemas.
10. Regularly audit information exposed through application endpoints.

## 10. CWE References

- CWE-200: Exposure of Sensitive Information to an Unauthorized Actor.
- CWE-209: Generation of Error Message Containing Sensitive Information.
- CWE-532: Insertion of Sensitive Information into Log File.
- CWE-538: Insertion of Sensitive Information into Externally-Accessible File or Directory.

## 11. Scanner Output Fields

When reporting a potential Information Disclosure vulnerability, provide:

- vulnerability: Information Disclosure
- vulnerability_type: Sensitive Data / Error Disclosure / Debug Information / File Exposure / API Data Exposure / Log Exposure
- file: Source file containing the finding
- location: Relevant line number or code location
- evidence: Relevant code fragment
- information_type: Type of potentially exposed information
- exposure_location: HTTP Response / Log / File / Debug Interface / Other
- input_source: Relevant source if applicable
- access_control: Whether access restrictions are enforced
- explanation: Why the information may be exposed to unauthorized users
- severity: Estimated severity
- confidence: Confidence in the finding
- false_positive_reason: Possible reasons the information is not sensitive or is properly protected
- remediation: Recommended correction
- cwe: Relevant CWE identifier

## 12. References

- OWASP Error Handling Cheat Sheet
  https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html

- OWASP Logging Cheat Sheet
  https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html

- CWE-200
  https://cwe.mitre.org/data/definitions/200.html

- CWE-209
  https://cwe.mitre.org/data/definitions/209.html

- CWE-532
  https://cwe.mitre.org/data/definitions/532.html
