# Path Traversal

## 1. Overview

Path Traversal is a security vulnerability that occurs when an application uses untrusted input to construct or access file paths without properly validating or restricting the resulting path.

An attacker may manipulate file path values to access files outside the application's intended directory.

This can expose sensitive files, application configuration, source code, or other information that should not be accessible.

Path Traversal is also known as Directory Traversal.

## 2. Common Types

### 2.1 Relative Path Traversal

Occurs when an application accepts relative file paths without ensuring that the resulting path remains inside an authorized directory.

### 2.2 Absolute Path Manipulation

Occurs when an application allows user-controlled absolute paths to be used directly in file operations.

### 2.3 Encoded Path Traversal

Occurs when path validation does not properly account for encoded or normalized path representations.

Different operating systems and frameworks may process path separators and encoding differently.

## 3. Detection Indicators

The scanner should investigate:

- User-controlled input passed to file operations.
- Dynamic construction of file paths using request parameters.
- File access without directory restrictions.
- Missing path normalization.
- Missing validation after resolving a path.
- User-controlled filenames passed to file-reading or file-writing functions.
- File operations involving absolute paths supplied externally.

## 4. Potentially Vulnerable Patterns

### Python File Operations

Investigate user-controlled input passed directly to file operations.

Example:

    from flask import Flask, request

    app = Flask(__name__)

    @app.route("/download")
    def download():
        filename = request.args.get("file")
        with open("uploads/" + filename, "r") as file:
            return file.read()

The application combines a user-controlled filename with a directory path without verifying that the final resolved path remains inside the intended directory.

This is a potential Path Traversal vulnerability.

### Other Relevant Python Functions

Investigate the use of:

- open()
- pathlib.Path.open()
- os.open()
- os.path.join()
- pathlib.Path.resolve()
- shutil.copy()
- shutil.move()

These functions are not inherently vulnerable. Their security depends on the source of the path and the validation applied.

## 5. Safe Patterns

### Path Resolution and Validation

Resolve the requested path and verify that it remains within the authorized directory.

Conceptual example:

    from pathlib import Path

    base_dir = Path("uploads").resolve()
    requested_file = (base_dir / filename).resolve()

    if not requested_file.is_relative_to(base_dir):
        raise PermissionError("Invalid file path")

    with requested_file.open("r") as file:
        content = file.read()

This approach demonstrates directory-boundary validation.

For security-sensitive applications, also consider symbolic links and filesystem changes between validation and file access.

### Use Controlled File Identifiers

Instead of accepting arbitrary filesystem paths, applications can accept predefined file identifiers and map them to authorized files.

## 6. False Positives

The scanner should not classify every file operation as a vulnerability.

Consider:

- The filename is generated internally and cannot be controlled externally.
- The application validates the resolved path against an authorized base directory.
- The application uses predefined file identifiers.
- The file operation only accesses a fixed, trusted path.
- The framework enforces appropriate file access restrictions.

The scanner should analyze the complete data flow before reporting a finding.

## 7. Severity Assessment

Severity depends on:

- Whether the path is externally controllable.
- Which files can potentially be accessed.
- Whether the application permits reading or writing.
- Whether sensitive information is exposed.
- Whether authentication or authorization is required.

Typical severity: Medium to High.

The scanner should not assign a definitive severity based solely on the presence of open() or os.path.join().

## 8. Remediation

Recommended fixes:

1. Avoid accepting arbitrary filesystem paths from users.
2. Use controlled file identifiers whenever possible.
3. Resolve paths before validating them.
4. Verify that resolved paths remain inside an authorized directory.
5. Consider symbolic links and filesystem race conditions.
6. Apply appropriate file permissions.
7. Avoid exposing sensitive filesystem locations through application responses.

## 9. CWE References

- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal').
- CWE-23: Relative Path Traversal.
- CWE-36: Absolute Path Traversal.

## 10. Scanner Output Fields

When reporting a potential Path Traversal vulnerability, provide:

- vulnerability: Path Traversal
- vulnerability_type: Relative / Absolute / Encoded / Unknown
- file: Source file containing the finding
- location: Relevant line number or code location
- evidence: Relevant code fragment
- input_source: Origin of the user-controlled path
- file_operation: File operation receiving the path
- explanation: Why the path may escape the authorized directory
- severity: Estimated severity
- confidence: Confidence in the finding
- false_positive_reason: Possible reasons the finding is not exploitable
- remediation: Recommended correction
- cwe: CWE-22

## 11. References

- OWASP Path Traversal
  https://owasp.org/www-community/attacks/Path_Traversal

- CWE-22
  https://cwe.mitre.org/data/definitions/22.html

- CWE-23
  https://cwe.mitre.org/data/definitions/23.html

- Python pathlib Documentation
  https://docs.python.org/3/library/pathlib.html
