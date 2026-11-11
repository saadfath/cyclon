# Insecure File Upload

## 1. Description

Insecure File Upload is a security vulnerability that occurs when an application accepts files from users without properly validating, restricting, or safely handling them.

File upload functionality is common in web applications, including profile pictures, document submissions, image processing, and file-sharing services.

If upload controls are insufficient, attackers may upload files that create security risks for the application or its users.

Potential consequences include:

- Unauthorized file storage.
- Exposure of sensitive information.
- Stored Cross-Site Scripting (XSS).
- Execution of uploaded files in unsafe environments.
- Storage exhaustion.
- Malware distribution.
- Unauthorized access to uploaded content.

### Example

Imagine an application that allows users to upload profile pictures.

If the application checks only the filename extension and does not validate the actual file content, users may upload files that do not match the expected image format.

## 2. Common Causes

Insecure file uploads commonly occur when:

- Applications trust filename extensions.
- MIME types are accepted without verification.
- File content is not validated.
- Uploaded files are stored inside publicly executable directories.
- Original filenames are used directly.
- File sizes are not restricted.
- Upload directories have excessive permissions.
- Uploaded files are accessible without authorization.
- Applications do not restrict dangerous file types.
- Archive extraction is performed without proper path validation.
- Image-processing libraries handle untrusted files unsafely.

## 3. Vulnerable Code Patterns

### Pattern 1: Missing file validation

Python example:

```python
from flask import request

@app.route("/upload", methods=["POST"])
def upload():
    file = request.files["file"]

    file.save("uploads/" + file.filename)

    return "File uploaded"
```

**Problem:**

The application saves user-provided files without validating their content, type, filename, or destination.

Using the original filename also creates potential path-handling risks.

### Pattern 2: Extension-only validation

```python
def upload_file(file):
    if file.filename.endswith(".jpg"):
        file.save("uploads/" + file.filename)
        return "Uploaded"

    return "Invalid file"
```

**Problem:**

The application trusts the filename extension to determine the file type.

An extension alone does not establish the actual content or safety of a file.

### Pattern 3: Missing file-size restrictions

```python
@app.route("/upload", methods=["POST"])
def upload():
    file = request.files["file"]

    process_file(file)

    return "Processed"
```

**Problem:**

The application does not show any file-size restrictions.

Large uploads may consume excessive memory, storage, or processing resources.

## 4. Safer Implementation

A secure file-upload system should:

- Allow only explicitly approved file types.
- Validate file content instead of relying only on extensions.
- Apply strict file-size limits.
- Generate server-controlled filenames.
- Store uploads outside executable application directories.
- Apply restrictive filesystem permissions.
- Prevent unauthorized access to private uploads.
- Avoid trusting client-provided MIME types.
- Scan files where appropriate.
- Process untrusted files in isolated environments.
- Validate archive contents before extraction.
- Avoid executing uploaded content.

### Example: Safer Flask upload

```python
import os
from uuid import uuid4
from flask import request, abort
from werkzeug.utils import secure_filename

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg"}

def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower()
        in ALLOWED_EXTENSIONS
    )

@app.route("/upload", methods=["POST"])
def upload():
    file = request.files.get("file")

    if not file or not file.filename:
        abort(400)

    if not allowed_file(file.filename):
        abort(400)

    filename = str(uuid4()) + ".jpg"

    file.save(os.path.join("/safe/uploads", filename))

    return "Uploaded"
```

**Important:** This is an illustrative starting point, not a complete secure upload implementation.

A production implementation must also validate the actual file format, apply size limits, handle storage errors, and ensure that the storage directory is not executable.

## 5. Detection Indicators

Cyclone should investigate the following patterns:

| Indicator | Description |
|---|---|
| Missing extension validation | Uploaded filenames are not restricted. |
| Extension-only validation | The application trusts filename extensions without checking content. |
| Client-controlled MIME type | The application trusts the uploaded Content-Type header. |
| Original filename usage | User-provided filenames are used directly in storage paths. |
| Missing size limits | Uploads have no appropriate size restrictions. |
| Executable upload directory | Uploaded files are stored where the server may execute them. |
| Missing access controls | Private uploaded files are publicly accessible. |
| Unsafe archive extraction | Archive contents are extracted without path validation. |
| Missing content validation | File content is not checked against the expected format. |

These indicators require contextual analysis. A file-upload function is not automatically vulnerable.

## 6. Python Functions and Libraries to Inspect

Cyclone should inspect common file-upload and file-processing functionality.

### Flask

```python
request.files
file.save()
```

### Werkzeug

```python
secure_filename()
FileStorage.save()
```

### Django

```python
request.FILES
UploadedFile
FileField
ImageField
```

### Python file operations

```python
open()
os.path.join()
os.rename()
shutil.copy()
```

### Archive processing

```python
zipfile.ZipFile()
tarfile.open()
extractall()
```

The presence of these functions does not automatically indicate a vulnerability.

Cyclone must inspect validation, storage location, permissions, and how uploaded content is processed.

## 7. Detection Logic for Cyclone

Cyclone should analyze file-upload functionality using the following process:

1. Identify endpoints that accept uploaded files.
2. Identify the source of uploaded content.
3. Trace filenames and file contents through the application.
4. Inspect filename extension validation.
5. Check whether actual file content is validated.
6. Inspect MIME-type handling.
7. Identify file-size restrictions.
8. Determine where uploaded files are stored.
9. Inspect whether uploaded files can be executed or interpreted by the server.
10. Check access controls for stored files.
11. Inspect archive extraction and file-processing operations.
12. Evaluate whether multiple security controls are enforced together.

### Important distinction

Using `request.files` does not automatically indicate an insecure upload vulnerability.

For example, an application may accept uploads while enforcing strict content validation, file-size limits, safe storage, and access controls.

Cyclone must analyze the complete upload lifecycle rather than relying on function names.

## 8. Severity Assessment

| Severity | Conditions |
|---|---|
| Critical | Confirmed uploaded content can cause severe compromise of the application or server. |
| High | Uploaded files can be executed in an unsafe environment or expose highly sensitive resources. |
| Medium | Insufficient validation creates meaningful security or resource-exhaustion risks. |
| Low | Limited upload validation weaknesses with restricted impact. |
| Informational | Suspicious upload handling without sufficient evidence of exploitation. |

Severity should consider:

- Whether uploaded content can be executed.
- Whether files are publicly accessible.
- Whether sensitive information can be exposed.
- Whether upload size is restricted.
- Whether authorization is enforced.
- Whether file processing occurs in an isolated environment.

Do not assign severity based only on the existence of an upload endpoint.

## 9. Evidence Collection

For every potential insecure file-upload finding, Cyclone should collect:

- File name.
- Endpoint or function name.
- Line number.
- Uploaded file source.
- Filename validation logic.
- Content validation logic.
- MIME-type validation.
- File-size restrictions.
- Storage destination.
- File permissions.
- Access-control implementation.
- File-processing operations.
- Archive extraction behavior.

Cyclone must distinguish between confirmed evidence and assumptions.

## 10. Recommended Fixes

- Use an explicit allowlist of permitted file types.
- Validate actual file content.
- Generate random server-controlled filenames.
- Never trust original filenames.
- Apply upload-size limits.
- Store uploaded files outside executable directories.
- Use restrictive filesystem permissions.
- Enforce authorization when retrieving uploaded files.
- Scan files where appropriate.
- Process untrusted files in isolated environments.
- Validate archive paths before extraction.
- Keep file-processing libraries updated.
- Avoid executing uploaded content.

## 11. False Positives

Cyclone should avoid reporting every file-upload function as vulnerable.

Possible false positives include:

- Uploads with strict content validation.
- Applications using secure storage services.
- Files stored outside executable directories.
- Uploads protected by centralized middleware.
- Storage systems with appropriate access controls.
- Applications using server-generated filenames.

The scanner should inspect the complete file-upload lifecycle before reporting a vulnerability.

## 12. RAG Knowledge Summary

**Vulnerability:** Insecure File Upload

**Category:** File Handling / Input Validation

**Affected Languages:** Python and other languages implementing file-upload functionality.

**Primary Risk:** Untrusted files may be stored, processed, or exposed in ways that compromise application security.

**Common Sources:**
- Profile-picture uploads.
- Document submission forms.
- File-sharing endpoints.
- API multipart requests.
- Archive uploads.

**Common Sinks:**
- `file.save()`
- `open()`
- `os.rename()`
- `shutil.copy()`
- `zipfile.ZipFile()`
- `tarfile.open()`

**Detection Strategy:**

Identify uploaded-file sources, trace filenames and file contents into storage and processing operations, and inspect validation, permissions, size restrictions, and access controls.

**Recommended Fix:**

Validate actual file content, enforce strict file-type and size restrictions, generate server-controlled filenames, and store uploads in non-executable locations with appropriate access controls.

**Confidence Requirements:**

A file-upload operation alone is insufficient to confirm a vulnerability. Cyclone must identify the missing security control and establish its potential impact.

**Important:**

Insecure File Upload can lead to several other vulnerabilities, including:

- Path Traversal.
- Stored Cross-Site Scripting.
- Denial of Service.
- Unauthorized file access.
- Remote Code Execution in certain configurations.

RAG should provide security knowledge and explain findings. The scanner's actual code analysis must independently establish whether the vulnerability exists.
