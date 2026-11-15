# Zip Slip and Unsafe Archive Extraction

**CWE:** CWE-22, CWE-409
**OWASP:** A01 Broken Access Control

## What it is
An archive contains entries with path traversal sequences or links, and extraction writes files outside the intended folder. Huge archives can also exhaust disk or memory.

## How it happens
Extraction code joins the destination folder with the entry name from the archive without verifying the final path. Symbolic links inside archives can also point outside.

## Signs in code
Archive extraction loops that use entry names directly. No size, count or compression ratio limits. Extraction of untrusted uploads.

## Severity and context
High when attackers can overwrite scripts, configuration or executables. Medium for resource exhaustion.

## Likely false positives
Archives created and consumed only by trusted internal processes, with fixed contents.

## How to fix
Resolve the final path and verify it stays inside the destination. Reject absolute paths, parent-directory sequences and links. Limit number of files, total size and ratio. Use library versions that include these protections. Extract in a sandboxed folder.

## Related scanner signals
SAST rules on archive extraction, advisories for archive libraries.
