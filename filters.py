"""File discovery and filtering helpers."""

import os
from pathlib import Path
DEFAULT_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rs", ".c", ".cpp",
    ".h", ".hpp", ".cs", ".rb", ".php", ".swift", ".kt", ".scala", ".sh",
    ".bash", ".zsh", ".sql", ".lua", ".r", ".m", ".mm", ".vue", ".svelte",
    ".html", ".css", ".scss", ".json", ".yaml", ".yml", ".toml", ".ini",
    ".cfg", ".md", ".txt",
}

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv",
    "env", ".env", "dist", "build", "target", ".idea", ".vscode", ".next",
    ".nuxt", "coverage", ".pytest_cache", ".mypy_cache", ".tox", "vendor",
    "Pods", "DerivedData",
}

BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp",
    ".pdf", ".zip", ".tar", ".gz", ".tgz", ".7z", ".rar", ".exe", ".dll",
    ".so", ".dylib", ".bin", ".o", ".a", ".class", ".jar", ".war", ".pyc",
    ".pyo", ".mp3", ".mp4", ".wav", ".avi", ".mov", ".mkv", ".ttf", ".otf",
    ".woff", ".woff2", ".eot",
}

MAX_FILE_SIZE = 200_000  # bytes


def is_binary(path: Path) -> bool:
    if path.suffix.lower() in BINARY_EXTENSIONS:
        return True
    try:
        with path.open("rb") as f:
            chunk = f.read(2048)
        if b"\x00" in chunk:
            return True
    except OSError:
        return True
    return False


def should_skip_dir(name: str) -> bool:
    return name in SKIP_DIRS or name.startswith(".")


def collect_files(
    root: Path,
    extensions: set[str] | None = None,
    max_size: int = MAX_FILE_SIZE,
) -> list[Path]:
    if extensions is None:
        extensions = DEFAULT_EXTENSIONS
    exts = {e.lower() if e.startswith(".") else "." + e.lower() for e in extensions}
    result: list[Path] = []

    if root.is_file():
        if root.suffix.lower() in exts and not is_binary(root):
            try:
                if root.stat().st_size <= max_size:
                    result.append(root)
            except OSError:
                pass
        return result

    for dirpath, dirnames, filenames in os.walk(root):
        # prune
        dirnames[:] = [d for d in dirnames if not should_skip_dir(d)]
        for fn in filenames:
            p = Path(dirpath) / fn
            if p.suffix.lower() not in exts:
                continue
            if is_binary(p):
                continue
            try:
                if p.stat().st_size > max_size:
                    continue
            except OSError:
                continue
            result.append(p)
    return sorted(result)
