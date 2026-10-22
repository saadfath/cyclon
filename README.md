# cyclon

CLI tool that scans your code for bugs using the Grok (xAI) API.

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

Multi-agent: configure multiple keys in ~/.config/cyclon/config.json under "api_keys": [...].
Each scan runs all agents in parallel and writes report.html, opening it in your browser.
```