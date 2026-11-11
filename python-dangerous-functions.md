# Python Dangerous Functions

## Overview
Built-ins and library calls that execute code or deserialize untrusted data when given user-controlled input. Complements `python-subprocess.md` and `insecure-deserialization.md`.
- CWE-95, CWE-502, CWE-78 | OWASP A03 / A08:2021

## Functions and risk
| Call | Risk | Safer alternative |
|---|---|---|
| `eval(x)`, `exec(x)` | arbitrary code | `ast.literal_eval`, explicit parsing |
| `pickle.load(s)`, `pickle.loads` | RCE on untrusted data | JSON, or signed data |
| `yaml.load(x)` (no Loader) | RCE | `yaml.safe_load` |
| `marshal.loads`, `shelve` | RCE | JSON |
| `os.system`, `os.popen` | command injection | `subprocess.run([...], shell=False)` |
| `subprocess(..., shell=True)` | command injection | list args, `shlex.quote` |
| `__import__(user)`, `importlib.import_module(user)` | arbitrary module load | allow-list |
| `input()` in Python 2 | eval | `raw_input` / Python 3 |
| `tempfile.mktemp` | race condition | `NamedTemporaryFile`, `mkstemp` |
| `assert` for security checks | removed with `-O` | explicit `if` + raise |
| `requests.get(url, verify=False)` | MITM | keep verification on |

## How to detect
Grep for the calls above, then trace whether the argument comes from request data, files, sockets, or environment.

## False positives
- Argument is a hardcoded literal or fully validated against an allow-list.
- `yaml.load(x, Loader=yaml.SafeLoader)`.

## Fix
Replace with the safer alternative in the table; validate and allow-list any dynamic value.

## Severity
Critical when input is attacker-controlled; Low if constant.
