"""CLI entry point."""

import json
import os
import sys
from pathlib import Path

import click

from . import __version__
from .config import (
    get_api_keys, get_model, get_models, get_base_url, set_api_key, set_model, load_config, save_config,
)
from .filters import collect_files, DEFAULT_EXTENSIONS
from .scanner import scan_agents, ScanResult
import webbrowser
from .grok import GrokClient, GrokError


def _print_finding(f, use_color=True):
    sev_colors = {
        "critical": "\033[91m",
        "high": "\033[91m",
        "medium": "\033[93m",
        "low": "\033[94m",
        "info": "\033[90m",
    }
    reset = "\033[0m"
    color = sev_colors.get(f.severity, "") if use_color and sys.stdout.isatty() else ""
    r = reset if color else ""
    loc = f"{f.file}"
    if f.line:
        loc += f":{f.line}"
    print(f"{color}[{f.severity.upper()}]{r} {loc} - {f.title}")
    if f.category:
        print(f"  category: {f.category}")
    if f.description:
        print(f"  {f.description}")
    if f.suggestion:
        print(f"  suggestion: {f.suggestion}")
    print()


def _render(result: ScanResult, as_json: bool):
    if as_json:
        out = {
            "root": result.root,
            "files_scanned": result.files_scanned,
            "findings": [
                {
                    "file": f.file,
                    "line": f.line,
                    "severity": f.severity,
                    "category": f.category,
                    "title": f.title,
                    "description": f.description,
                    "suggestion": f.suggestion,
                }
                for f in result.findings
            ],
            "errors": result.errors,
        }
        print(json.dumps(out, indent=2))
        return
    print(f"Scanned {result.files_scanned} file(s). Found {len(result.findings)} issue(s).")
    if result.errors:
        print(f"Errors: {len(result.errors)}")
        for e in result.errors:
            print(f"  - {e}")
    print()
    # sort by severity
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for f in sorted(result.findings, key=lambda x: order.get(x.severity, 5)):
        _print_finding(f)


@click.group()
@click.version_option("0.1.0", prog_name="cyclon")
def cli():
    """cyclon - scan your code for bugs using the Grok (xAI) API."""


@cli.command("scan")
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), help="Write JSON report to file.")
@click.option("--model", "-m", default=None, help="Grok model to use.")
@click.option("--extensions", "-e", default=None, help="Comma-separated file extensions.")
@click.option("--max-size", default=200000, type=int, help="Max file size in bytes.")
@click.option("--concurrency", "-c", default=3, type=int, help="Number of concurrent file scans.")
@click.option("--json", "as_json", is_flag=True, help="Output JSON to stdout.")
@click.option("--dry-run", is_flag=True, help="List files that would be scanned, no API calls.")
@click.option("--include", "includes", multiple=True, help="Glob include pattern (repeatable).")
@click.option("--exclude", "excludes", multiple=True, help="Glob exclude pattern (repeatable).")
@click.option("--extra-prompt", default="", help="Extra instructions appended to system prompt.")
@click.option("--keys", default=None, help="Comma-separated API keys (multi-agent).")
@click.option("--models", default=None, help="Comma-separated models aligned with keys.")
@click.option("--html", "html_path", default="report.html", help="HTML report path.")
@click.option("--no-open", is_flag=True, help="Do not open report in browser.")
@click.option("--no-cache", is_flag=True, help="Disable scan cache.")
@click.option("--clear-cache", is_flag=True, help="Clear scan cache before running.")
@click.option("--agents", default=None, help="Comma-separated agent names (optional).")
@click.option("--events", is_flag=True, help="Emit machine-readable JSONL progress events on stderr.")
def scan_cmd(path, output, model, extensions, max_size, concurrency, as_json, dry_run,
             includes, excludes, extra_prompt, keys, models, html_path, no_open, no_cache, clear_cache, agents, events):
    """Scan PATH (file or directory) for bugs."""
    root = Path(path).resolve()
    ext_set = None
    if extensions:
        ext_set = {x.strip() for x in extensions.split(",") if x.strip()}

    files = collect_files(root, extensions=ext_set, max_size=max_size)
    # apply include/exclude globs
    if includes or excludes:
        import fnmatch
        filtered = []
        for f in files:
            rel = str(f.relative_to(root)) if root.is_dir() else f.name
            ok = True
            if includes:
                ok = any(fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(f.name, pat) for pat in includes)
            if ok and excludes:
                if any(fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(f.name, pat) for pat in excludes):
                    ok = False
            if ok:
                filtered.append(f)
        files = filtered

    if dry_run:
        print(f"Would scan {len(files)} file(s):")
        for f in files:
            print(f"  {f}")
        return

    if not files:
        click.echo("No files to scan.")
        return

    # Override collect by monkey: scan() re-collects; instead pass a temp? Easiest: chdir? We'll just call scan with extensions and max_size; filtering already done but scan re-collects all. To respect includes/excludes/max, re-run collect inside scan is okay but loses filters. Instead replicate: create a list and scan manually.
    # We'll use scan() but it re-collects; includes/excludes/max_size still applied via max_size & extensions. includes/excludes lost. For simplicity, if filters used, do manual loop.
    keys = get_api_keys(keys)
    if not keys:
        click.echo("Error: No API key found. Set XAI_API_KEY or pass --keys.", err=True)
        sys.exit(1)
    base_url = get_base_url()
    if models:
        model_list = get_models(models, count=len(keys))
    elif model:
        model_list = [model] * len(keys)
    else:
        model_list = get_models(None, count=len(keys))
    from .grok import GrokClient, GrokError
    clients = []
    agent_names = None
    if agents:
        agent_names = [a.strip() for a in agents.split(",") if a.strip()]
    default_names = ["Security Agent", "Bug Hunter Agent", "Quality Agent"]
    if agent_names is None or len(agent_names) != len(keys):
        agent_names = [default_names[i] if i < len(default_names) else f"Agent {i+1}" for i in range(len(keys))]
    try:
        for i, k in enumerate(keys):
            m = model_list[i] if i < len(model_list) else model_list[-1]
            clients.append(GrokClient(api_key=k, base_url=base_url, model=m))
    except GrokError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    from .grok import SYSTEM_PROMPT as BASE_PROMPT
    sys_prompt = BASE_PROMPT
    if extra_prompt:
        sys_prompt = BASE_PROMPT + "\n\nAdditional instructions: " + extra_prompt

    from .scanner import scan_agents
    total = len(files)

    focuses = [
        "Focus primarily on SECURITY vulnerabilities: injection, XSS, CSRF, authentication/authorization flaws, secrets, insecure deserialization, path traversal, SSRF, and unsafe input handling. Prioritize exploitable issues.",
        "Focus primarily on BUGS and LOGIC errors: null/undefined dereferences, off-by-one, incorrect conditions, race conditions, error handling, type errors, and runtime exceptions.",
        "Focus primarily on PERFORMANCE and CODE QUALITY: inefficient algorithms, resource leaks, blocking calls, memory issues, maintainability, dead code, and best practices.",
    ]
    system_prompts = []
    for i in range(len(keys)):
        f = focuses[i] if i < len(focuses) else "Perform a thorough code review."
        system_prompts.append(sys_prompt + "\n\nSpecialization: " + f)

    if events:
        import threading
        event_lock = threading.Lock()

        def emit(event):
            with event_lock:
                click.echo("@@cyclon@@ " + json.dumps(event, default=str), err=True)

        progress = None
    else:
        emit = None

        def progress(msg):
            if not as_json:
                click.echo(msg, err=True)

    if clear_cache:
        from pathlib import Path as _P
        cf = _P.home() / ".cache" / "cyclon" / "checkpoint.json"
        try:
            cf.unlink()
        except FileNotFoundError:
            pass

    use_cache = not no_cache

    # Banner
    if not as_json and not events:
        _banner()

    result = scan_agents(
        root, clients, agent_names=agent_names, extensions=None, max_size=max_size,
        concurrency=concurrency, progress=progress, system_prompt=sys_prompt,
        system_prompts=system_prompts, files=files, split_work=True, use_cache=use_cache,
        event=emit,
    )

    _render(result, as_json)

    # Write HTML report
    from .report import write_html_report
    from pathlib import Path as _P
    hp = _P(html_path)
    write_html_report(result, hp, agents=agent_names)
    click.echo(f"HTML report: {hp.resolve()}", err=True)
    if not no_open:
        try:
            webbrowser.open(f"file://{hp.resolve()}")
        except Exception:
            pass

    if output:
        out_obj = {
            "root": result.root,
            "files_scanned": result.files_scanned,
            "findings": [
                {
                    "file": f.file, "line": f.line, "severity": f.severity,
                    "category": f.category, "title": f.title,
                    "description": f.description, "suggestion": f.suggestion,
                } for f in result.findings
            ],
            "errors": result.errors,
        }
        Path(output).write_text(json.dumps(out_obj, indent=2))
        click.echo(f"Report written to {output}", err=True)



def _banner():
    art = r"""
   ____ _ _  __  __
  / ___| | | \ \/ / 
 | |   | | |  \  /  
 | |___| | |  /  \  
  \____|_|_| /_/\_\ 
"""
    colors = ["\033[91m", "\033[93m", "\033[92m", "\033[96m", "\033[94m", "\033[95m"]
    reset = "\033[0m"
    lines = art.strip("\n").splitlines()
    for i, line in enumerate(lines):
        c = colors[i % len(colors)]
        click.echo(f"{c}{line}{reset}", err=True)
    click.echo("\033[96m  Multi-Agent Code Scanner\033[0m", err=True)
    click.echo()

def main():
    cli()


if __name__ == "__main__":
    main()


