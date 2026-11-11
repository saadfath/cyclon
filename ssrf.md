# Server-Side Request Forgery (SSRF)

## 1. Overview

Server-Side Request Forgery (SSRF) is a security vulnerability that occurs when an application makes server-side requests using untrusted user input without properly validating or restricting the destination.

An attacker may manipulate the destination of a request, causing the application server to communicate with unintended systems or services.

Depending on the application's network access and permissions, this may expose internal services, sensitive information, or resources that are not publicly accessible.

SSRF primarily affects applications that retrieve external resources, process URLs, or communicate with other services.

## 2. Common Types

### 2.1 Basic SSRF

Occurs when an application accepts a user-controlled URL and makes a server-side request to that destination without sufficient validation.

### 2.2 Blind SSRF

Occurs when the application makes a request to an attacker-influenced destination but does not return the response content to the user.

The request may still cause unintended interactions with external or internal systems.

### 2.3 Internal Service SSRF

Occurs when an application can be manipulated into communicating with services available within its internal network.

The impact depends on network architecture and access restrictions.

## 3. Detection Indicators

The scanner should investigate:

- User-controlled URLs passed to HTTP request functions.
- External input used to construct request destinations.
- Missing destination validation.
- Missing restrictions on allowed protocols.
- HTTP clients accepting arbitrary destinations.
- URL redirects that are followed without revalidating the destination.
- User-controlled hostnames resolved without appropriate network restrictions.
- Backend services that retrieve remote resources on behalf of users.

## 4. Potentially Vulnerable Patterns

### Python Requests

Investigate situations where user-controlled input is passed directly to an HTTP client.

Example:

    import requests
    from flask import Flask, request

    app = Flask(__name__)

    @app.route("/fetch")
    def fetch():
        url = request.args.get("url")
        response = requests.get(url)
        return response.text

The application uses a user-controlled URL as the destination of a server-side HTTP request.

This is a potential SSRF vulnerability.

### Other Relevant Python Functions and Libraries

Investigate:

- requests.get()
- requests.post()
- requests.request()
- urllib.request.urlopen()
- httpx.get()
- httpx.request()
- aiohttp.ClientSession.get()

These functions are not inherently vulnerable. Their security depends on how the destination is obtained and validated.

## 5. Safe Patterns

### Destination Allowlisting

Applications should restrict outgoing requests to explicitly authorized hosts and services.

For example, an application that retrieves images from a known provider should only permit approved destinations.

### URL Validation

Validate:

- URL scheme.
- Hostname.
- Port.
- Destination authorization.
- Redirect destinations.

Validation should be performed before making the request and after every redirect.

### Network-Level Restrictions

Application validation should be supported by network controls.

Recommended protections include:

- Blocking access to internal networks when unnecessary.
- Restricting access to sensitive internal services.
- Using outbound firewall rules.
- Disabling unnecessary protocols.
- Applying DNS and IP address validation.

## 6. False Positives

The scanner should not automatically classify every HTTP request as SSRF.

Consider:

- The destination is a fixed, trusted URL.
- The destination is selected from a controlled allowlist.
- User input only modifies a harmless request parameter.
- The application validates the destination before making the request.
- Network-level restrictions prevent access to unauthorized destinations.

The scanner should analyze the complete data flow from input source to HTTP request destination.

## 7. Severity Assessment

Severity depends on:

- Whether the destination is user-controlled.
- Which network resources the server can access.
- Whether internal services are reachable.
- Whether sensitive responses are returned.
- Whether authentication or authorization is required.
- Whether redirects and DNS resolution are safely handled.

Typical severity: High, potentially Critical in environments with sensitive internal services.

The scanner should not assign a definitive severity based only on the presence of requests.get() or another HTTP client.

## 8. Remediation

Recommended fixes:

1. Avoid accepting arbitrary URLs from users.
2. Use explicit destination allowlists.
3. Validate URL schemes, hostnames, and ports.
4. Resolve and validate destination IP addresses.
5. Revalidate destinations after redirects.
6. Restrict outbound network access.
7. Disable unnecessary protocols.
8. Avoid exposing internal request responses to external users.
9. Apply appropriate request timeouts.

## 9. CWE References

- CWE-918: Server-Side Request Forgery (SSRF).
- CWE-441: Unintended Proxy or Intermediary ('Confused Deputy').

## 10. Scanner Output Fields

When reporting a potential SSRF vulnerability, provide:

- vulnerability: Server-Side Request Forgery (SSRF)
- vulnerability_type: Basic / Blind / Internal Service / Unknown
- file: Source file containing the finding
- location: Relevant line number or code location
- evidence: Relevant code fragment
- input_source: Origin of the user-controlled URL
- request_sink: HTTP client or request function receiving the URL
- destination_validation: Whether destination validation exists
- redirect_handling: Whether redirects are safely validated
- explanation: Why the request destination may be externally controlled
- severity: Estimated severity
- confidence: Confidence in the finding
- false_positive_reason: Possible reasons the finding is not exploitable
- remediation: Recommended correction
- cwe: CWE-918

## 11. References

- OWASP Server-Side Request Forgery Prevention Cheat Sheet
  https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html

- OWASP SSRF
  https://owasp.org/www-community/attacks/Server_Side_Request_Forgery

- CWE-918
  https://cwe.mitre.org/data/definitions/918.html

- Python Requests Documentation
  https://requests.readthedocs.io/
