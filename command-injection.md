---
id: command-injection
title: OS Command Injection
cwe: CWE-78
owasp: A03 Injection
severity: critical
languages: [python, javascript, php, java, c, any]
scanner_rules: [command-injection, os-system-with-user-input, subprocess-shell-true, exec-with-user-input]
---

## What it is
Command injection happens when user input is placed inside a command that the application sends to the operating system shell. The attacker adds their own commands, and the server runs them with the permissions of the application.

## How it happens
The code builds a shell command as a string and runs it through a shell (for example `os.system`, `subprocess` with `shell=True`, `exec`, `system()`). The shell treats special characters such as `;`, `&&`, `||`, `|`, `` ` `` and `$()` as command separators or substitutions, so the user's input can add extra commands.

## Vulnerable example
### Python
```python
import os

def ping(host):
    os.system("ping -c 1 " + host)
```
```python
import subprocess

def ping(host):
    subprocess.run(f"ping -c 1 {host}", shell=True)
```
If `host` is `example.com; cat /etc/passwd`, the shell runs the ping and then the second command.

### JavaScript (Node.js)
```javascript
const { exec } = require("child_process");
exec("ping -c 1 " + req.query.host);
```

### PHP
```php
system("ping -c 1 " . $_GET['host']);
```

### Java
```java
Runtime.getRuntime().exec("sh -c \"ping -c 1 " + host + "\"");
```

## Safe example
### Python
```python
import subprocess

def ping(host):
    subprocess.run(["ping", "-c", "1", host], shell=False, check=True)
```
The command and its arguments are passed as a list and no shell is used, so `;` or `&&` in `host` is just text, not a separator.

### JavaScript (Node.js)
```javascript
const { execFile } = require("child_process");
execFile("ping", ["-c", "1", req.query.host]);
```

### PHP
```php
$host = escapeshellarg($_GET['host']);
system("ping -c 1 " . $host);
```
Better in PHP: validate the input first (for example with a strict hostname pattern) and avoid shell functions when possible.

### Java
```java
ProcessBuilder pb = new ProcessBuilder("ping", "-c", "1", host);
pb.start();
```

## How to detect it
- Calls to shell or process functions: `os.system`, `os.popen`, `subprocess.*` with `shell=True`, `exec`, `execSync`, `child_process.exec`, `system`, `shell_exec`, `passthru`, backticks, `Runtime.exec`.
- The command string is built with `+`, an f-string, `.format()`, or a template literal.
- The variable comes from user input: request parameters, form fields, headers, filenames, uploaded file names, or environment values.
- `eval` or `exec` of code strings built from user data (code injection, a close relative of this issue).
- Arguments that start with `-` taken from the user (argument injection), even without a shell.

## Impact
- The attacker can run any command with the permissions of the application.
- Reading or deleting files, stealing secrets and keys.
- Installing malware or opening a reverse shell.
- Moving to other systems in the network.
- Full server takeover, which is why severity is critical.

## How to fix it
1. Avoid calling the operating system when a library or built-in function can do the same job.
2. If a command is needed, pass the command and arguments as a list (`shell=False`, `execFile`, `ProcessBuilder`) so no shell reads the input.
3. Validate the input against a strict allow-list (for example a pattern for hostnames or a fixed set of values).
4. If a shell is unavoidable, escape arguments with the language's proper function (for example `escapeshellarg` in PHP, `shlex.quote` in Python), but treat this as the last option.
5. Block option-like input: reject values starting with `-` or put `--` before user arguments when the command supports it.
6. Run the application with the lowest permissions possible.

## False positives
- The command is fully hardcoded and no variable is used.
- The variable is a constant, or comes from a trusted internal source, or was checked against a fixed allow-list.
- The command is called with a list of arguments and without a shell, with no user-controlled value.
- The scanner flags build scripts, tests, or admin tools that never receive outside input.

## Confidence guide
- **High:** user input reaches a shell command (`shell=True`, `system`, `exec`) through concatenation or formatting, with no validation.
- **Medium:** a shell function is used with a dynamic value and it is not clear where the value comes from, or only partial escaping is used.
- **Low:** the command is hardcoded, uses a list of arguments without a shell, or the value is checked against an allow-list.
