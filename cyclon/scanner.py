"""Scanning orchestration."""

import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .filters import collect_files
from .grok import GrokClient, SYSTEM_PROMPT as DEFAULT_SYSTEM_PROMPT, parse_json_array
from .knowledge import KnowledgeBase, language_for_path

CHUNK_CHARS = 9000
OVERLAP = 400


@dataclass
class Finding:
    file: str
    agent: str = ""
    line: int | None = None
    severity: str = "medium"
    category: str = "bug"
    title: str = ""
    description: str = ""
    suggestion: str = ""
    raw: dict = field(default_factory=dict)


@dataclass
class ScanResult:
    root: str
    files_scanned: int = 0
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)



CACHE_FILE = Path.home() / ".cache" / "cyclon" / "checkpoint.json"


def _load_cache() -> dict:
    if CACHE_FILE.exists():
        try:
            return json.loads(CACHE_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            return {"entries": {}}
    return {"entries": {}}


def _save_cache(cache: dict) -> None:
    try:
        CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        CACHE_FILE.write_text(json.dumps(cache))
    except OSError:
        pass


def _finding_to_dict(f: Finding) -> dict:
    return {
        "file": f.file,
        "agent": f.agent,
        "line": f.line,
        "severity": f.severity,
        "category": f.category,
        "title": f.title,
        "description": f.description,
        "suggestion": f.suggestion,
    }


def _dict_to_finding(d: dict) -> Finding:
    return Finding(
        file=d.get("file", ""),
        agent=d.get("agent", ""),
        line=d.get("line"),
        severity=d.get("severity", "medium"),
        category=d.get("category", "bug"),
        title=d.get("title", ""),
        description=d.get("description", ""),
        suggestion=d.get("suggestion", ""),
    )

def _chunks(text: str) -> list[tuple[int, str]]:
    """Split text into (start_line, content) chunks."""
    lines = text.splitlines(keepends=True)
    if not lines:
        return [(1, text)]
    chunks = []
    cur: list[str] = []
    cur_chars = 0
    start_line = 1
    line_no = 1
    for ln in lines:
        if cur_chars + len(ln) > CHUNK_CHARS and cur:
            chunks.append((start_line, "".join(cur)))
            overlap_lines = []
            ol = 0
            for l in reversed(cur):
                if ol + len(l) > OVERLAP:
                    break
                overlap_lines.insert(0, l)
                ol += len(l)
            cur = overlap_lines + [ln]
            cur_chars = sum(len(x) for x in cur)
            start_line = line_no - len(overlap_lines) + 1
            if start_line < 1:
                start_line = 1
        else:
            cur.append(ln)
            cur_chars += len(ln)
        line_no += 1
    if cur:
        chunks.append((start_line, "".join(cur)))
    if not chunks:
        chunks = [(1, text)]
    return chunks


def scan_file(
    client: GrokClient,
    path: Path,
    root: Path,
    system_prompt: str | None = None,
    agent: str = "",
    on_finding: Callable[[Finding], None] | None = None,
    knowledge: KnowledgeBase | None = None,
) -> tuple[list[Finding], str | None]:
    if system_prompt is None:
        system_prompt = DEFAULT_SYSTEM_PROMPT
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        return [], f"{path}: read error {e}"
    rel = str(path.relative_to(root)) if root.is_dir() else str(path)
    language = language_for_path(path)
    findings: list[Finding] = []
    chunks = _chunks(content)
    for start_line, chunk in chunks:
        numbered = "\n".join(
            f"{i}: {ln}" for i, ln in enumerate(chunk.splitlines(), start=start_line)
        )
        reference = ""
        if knowledge is not None:
            reference = knowledge.render(knowledge.retrieve(chunk, language=language))
        instruction = (
            "Analyze for bugs. Return JSON array."
            if not reference
            else (
                "Analyze for bugs and security issues. Use the reference knowledge "
                "below to judge severity and rule out false positives, but only report "
                "issues you can justify from the code shown. Do not invent CVEs, CWEs, "
                "versions or scores that the reference does not state. Return JSON array."
            )
        )
        user_msg = (
            f"File: {rel}\n"
            f"Chunk starts at line {start_line}.\n"
            f"```\n{numbered}\n```\n"
            + (f"\n{reference}\n" if reference else "")
            + instruction
        )
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_msg},
        ]
        try:
            raw = client.chat(messages)
        except Exception as e:  # noqa
            return findings, f"{rel}: API error {e}"
        arr = parse_json_array(raw)
        for item in arr:
            if not isinstance(item, dict):
                continue
            f = Finding(
                file=item.get("file") or rel,
                agent=agent,
                line=item.get("line"),
                severity=str(item.get("severity", "medium")).lower(),
                category=str(item.get("category", "bug")),
                title=str(item.get("title", "")),
                description=str(item.get("description", "")),
                suggestion=str(item.get("suggestion", "")),
                raw=item,
            )
            findings.append(f)
            if on_finding is not None:
                on_finding(f)
    return findings, None


def scan(
    root: Path,
    client: GrokClient,
    extensions: set[str] | None = None,
    max_size: int = 200_000,
    concurrency: int = 1,
    progress: Callable[[str], None] | None = None,
    system_prompt: str | None = None,
    agent: str = "",
    knowledge: KnowledgeBase | None = None,
) -> ScanResult:
    if system_prompt is None:
        system_prompt = DEFAULT_SYSTEM_PROMPT
    result = ScanResult(root=str(root))
    files = collect_files(root, extensions=extensions, max_size=max_size)
    if not files:
        return result

    if concurrency <= 1:
        for p in files:
            if progress:
                progress(f"Scanning {p}")
            fs, err = scan_file(
                client, p, root if root.is_dir() else p.parent,
                system_prompt=system_prompt, agent=agent, knowledge=knowledge,
            )
            result.files_scanned += 1
            result.findings.extend(fs)
            if err:
                result.errors.append(err)
    else:
        with ThreadPoolExecutor(max_workers=concurrency) as ex:
            futures = {
                ex.submit(
                    scan_file, client, p, root if root.is_dir() else p.parent,
                    system_prompt, agent, None, knowledge,
                ): p
                for p in files
            }
            for fut in as_completed(futures):
                p = futures[fut]
                if progress:
                    progress(f"Scanning {p}")
                fs, err = fut.result()
                result.files_scanned += 1
                result.findings.extend(fs)
                if err:
                    result.errors.append(err)
    return result


def scan_agents(
    root: Path,
    clients: list[GrokClient],
    agent_names: list[str] | None = None,
    extensions: set[str] | None = None,
    max_size: int = 200_000,
    concurrency: int = 4,
    progress: Callable[[str], None] | None = None,
    system_prompt: str | None = None,
    system_prompts: list[str] | None = None,
    files: list[Path] | None = None,
    split_work: bool = False,
    use_cache: bool = True,
    event: Callable[[dict], None] | None = None,
    knowledge: KnowledgeBase | None = None,
) -> ScanResult:
    if system_prompt is None:
        system_prompt = DEFAULT_SYSTEM_PROMPT
    if agent_names is None:
        agent_names = [f"Agent {i+1}" for i in range(len(clients))]

    def emit(payload: dict) -> None:
        if event is not None:
            event(payload)

    result = ScanResult(root=str(root))
    if files is None:
        files = collect_files(root, extensions=extensions, max_size=max_size)
    if not files or not clients:
        result.files_scanned = len(files)
        emit({
            "type": "start", "root": str(root), "files": len(files),
            "agents": list(agent_names), "models": [c.model for c in clients],
            "knowledge": len(knowledge.vulnerabilities) if knowledge else 0,
        })
        emit({"type": "done", "files_scanned": len(files), "findings": 0, "errors": 0})
        return result

    emit({
        "type": "start", "root": str(root), "files": len(files),
        "agents": list(agent_names), "models": [c.model for c in clients],
        "knowledge": len(knowledge.vulnerabilities) if knowledge else 0,
    })

    cache = _load_cache() if use_cache else {"entries": {}}
    entries = cache.setdefault("entries", {})

    if split_work and len(clients) > 1:
        tasks = [(p, i % len(clients)) for i, p in enumerate(files)]
    else:
        tasks = [(p, ci) for p in files for ci in range(len(clients))]

    def work(item):
        p, ci = item
        client = clients[ci]
        agent = agent_names[ci] if ci < len(agent_names) else f"Agent {ci+1}"
        rel = str(p.relative_to(root)) if root.is_dir() else str(p)
        emit({"type": "file_start", "file": rel, "agent": agent})
        if system_prompts and ci < len(system_prompts):
            sp = system_prompts[ci]
        else:
            sp = system_prompt
        if use_cache:
            try:
                mtime = p.stat().st_mtime
            except OSError:
                mtime = 0
            cache_key = f"{str(p.resolve())}|{agent}"
            cached = entries.get(cache_key)
            if cached and cached.get("mtime") == mtime:
                fs = [_dict_to_finding(d) for d in cached.get("findings", [])]
                for f in fs:
                    emit({"type": "finding", "file": rel, "agent": agent, "finding": _finding_to_dict(f)})
                emit({"type": "file_done", "file": rel, "agent": agent, "count": len(fs), "cached": True})
                return p, agent, fs, None
        scan_root = root if root.is_dir() else p.parent

        def on_finding(f: Finding) -> None:
            emit({"type": "finding", "file": rel, "agent": agent, "finding": _finding_to_dict(f)})

        fs, err = scan_file(
            client, p, scan_root, system_prompt=sp, agent=agent,
            on_finding=on_finding, knowledge=knowledge,
        )
        if err:
            emit({"type": "error", "file": rel, "agent": agent, "message": err})
        emit({"type": "file_done", "file": rel, "agent": agent, "count": len(fs)})
        if use_cache and err is None:
            try:
                mtime = p.stat().st_mtime
            except OSError:
                mtime = 0
            cache_key = f"{str(p.resolve())}|{agent}"
            entries[cache_key] = {"mtime": mtime, "findings": [_finding_to_dict(f) for f in fs]}
        return p, agent, fs, err

    all_findings: list[Finding] = []
    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        futures = {ex.submit(work, t): t for t in tasks}
        for fut in as_completed(futures):
            p, agent, fs, err = fut.result()
            all_findings.extend(fs)
            if err:
                result.errors.append(err)
            if progress:
                progress(f"{p} [{agent}]")

    merged: dict[tuple, Finding] = {}
    for f in all_findings:
        key = (f.file, f.line, f.title.strip().lower())
        if key in merged:
            existing = merged[key]
            if f.agent and f.agent not in [a.strip() for a in existing.agent.split(",")]:
                existing.agent = (existing.agent + ", " + f.agent).strip(", ")
        else:
            merged[key] = f
    result.findings = list(merged.values())
    result.files_scanned = len(files)
    if use_cache:
        _save_cache(cache)
    emit({
        "type": "done",
        "files_scanned": len(files),
        "findings": len(result.findings),
        "errors": len(result.errors),
    })
    return result
