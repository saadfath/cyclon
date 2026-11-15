# cyclon

CLI tool that scans your code for bugs and security issues using the Grok (xAI) API.

## Install

```bash
cd cli-cyclon
pip install -e .
```

## Configure API key

```bash
export XAI_API_KEY="your-key"
# or
cyclon config set-key your-key
```

## Usage

```bash
cyclon scan .                      # scan current directory
cyclon scan src/ --output report.json
cyclon scan file.py --model grok-3-latest
cyclon scan . --extensions py,js --concurrency 4
cyclon scan . --dry-run
cyclon scan . --json
cyclon scan . --no-open            # skip opening the HTML report
```

Multi-agent: configure multiple keys in `~/.config/cyclon/config.json` under `"api_keys": [...]`.
Each scan runs all agents in parallel and writes report.html, opening it in your browser.

## Vulnerability knowledge base

The repository ships a Markdown knowledge base (SQL injection, SSRF, JWT, XSS,
path traversal, race conditions, and more). During a scan Cyclon selects the
documents that match the code being analysed and adds them to the model prompt,
so findings are grounded in concrete vulnerability guidance and false positives
are called out explicitly.

```bash
cyclon scan .                     # knowledge base enabled by default
cyclon scan . --no-knowledge      # plain scan
cyclon scan . --knowledge-dir ./kb

cyclon knowledge                  # list documents
cyclon knowledge sql-injection    # print one document
cyclon knowledge --json           # machine-readable index
```

Documents are loaded from (in order): `--knowledge-dir`, `CYCLON_KB_DIR`, a
`cyclon/knowledge/` package directory, the repository root, then the current
directory.

## Live progress events

`cyclon scan --events` writes JSONL progress events to stderr, prefixed with
`@@cyclon@@ `. This is consumed by the
[Cyclon VS Code extension](https://github.com/saadfath/cyclon-vscode) to drive
its live dashboard. Stdout stays pure JSON when `--json` is used.

Event types: `start`, `file_start`, `finding`, `error`, `file_done`, `done`.
