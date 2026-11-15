"""Vulnerability knowledge base loader and lightweight retrieval.

The repository ships a set of Markdown knowledge files (SQL injection, SSRF,
JWT, ...). This module loads them, tolerates inconsistent filenames and
frontmatter, and selects the most relevant documents for a given code chunk.

Retrieval is intentionally dependency-free: it scores documents by matching
curated trigger phrases against the code being scanned, then injects the best
matches into the model prompt. This keeps prompts small while still grounding
the analysis in the knowledge base.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

GUIDELINE_IDS = {"analysis-guidelines", "scanner-rule-mapping", "report-format"}

# Trigger phrases per knowledge document id. Matching is case-insensitive and
# operates on the raw code chunk. Keep phrases specific enough to avoid
# dragging unrelated documents into every prompt.
TRIGGERS: dict[str, list[str]] = {
    "sql-injection": [
        "select ", "insert into", "update ", "delete from", "execute(", "executemany(",
        "cursor.execute", "db.query", "query(", "rawsql", "raw(", "where ", ".format(",
        "f\"select", "f'select", "%s", "concat", "createquery", "createnativequery",
        "jdbctemplate", "statement", "sequelize.query", "knex.raw",
    ],
    "command-injection": [
        "os.system", "os.popen", "subprocess.", "child_process", "exec(", "execsync",
        "shell=true", "system(", "popen(", "`", "runtime.getruntime().exec",
        "process.start", "commands.getoutput", "shell_exec", "passthru",
    ],
    "python-subprocess": [
        "subprocess.popen", "subprocess.run", "subprocess.call", "subprocess.check_output",
        "shell=true", "os.system", "os.popen", "shlex",
    ],
    "python-dangerous-functions": [
        "eval(", "exec(", "pickle.loads", "pickle.load", "yaml.load", "marshal.loads",
        "__import__", "compile(", "input(",
    ],
    "cross-site-scripting": [
        "innerhtml", "outerhtml", "document.write", "insertadjacenthtml", "dangerouslysetinnerhtml",
        "v-html", "render_template_string", "mark_safe", "|safe", "echo $", "print(",
        "response.write", "res.send(", "jquery.html", ".html(",
    ],
    "cross-site-request-forgery": [
        "csrf", "xsrf", "state-changing", "same-site", "samesite", "forgery", "anti-forgery",
        "csrftoken", "csrf_token",
    ],
    "server-side-template-injection": [
        "render_template_string", "template.render", "jinja2", "twig", "freemarker",
        "velocity", "handlebars.compile", "ejs.render", "pug.render", "mustache",
    ],
    "ssrf": [
        "requests.get", "requests.post", "urllib.request", "urlopen", "http.get",
        "axios.get", "axios.post", "fetch(", "httpx.", "curl ", "ssrf", "url=",
        "redirect_uri", "callback",
    ],
    "xml-external-entities": [
        "etree.parse", "xml.etree", "lxml", "minidom", "saxparser", "documentbuilder",
        "xmlreader", "xpath", "doctype", "entityresolver", "xmlreader", "simplexml_load",
    ],
    "path-traversal": [
        "open(", "readfile(", "sendfile(", "path.join", "os.path.join", "filename",
        "filepath", "file_path", "download", "getfile", "read_text", "fs.readfile",
        "res.sendfile", "zipfile", "tarfile", "../", "..\\\\",
    ],
    "open-redirect": [
        "redirect(", "redirect_uri", "return redirect", "location.href", "location.assign",
        "response.redirect", "window.location", "next=", "return_url", "continue=",
        "goto=", "callback",
    ],
    "insecure-deserialization": [
        "pickle.loads", "pickle.load", "cpickle", "yaml.load", "marshal.loads", "unserialize(",
        "objectinputstream", "readobject", "jsonpickle", "dill.loads", "joblib.load",
        "torch.load", "shelve.open",
    ],
    "insecure-file-upload": [
        "upload", "multipart", "filename", "file.save", "save(", "content_type",
        "mimetype", "allowed_extensions", "secure_filename", "filefield", "multer",
    ],
    "jwt-security": [
        "jwt", "jsonwebtoken", "pyjwt", "jose", "alg", "none", "verify=False",
        "jwt.decode", "jwt.encode", "bearer", "signature", "hs256", "rs256",
    ],
    "authentication-failures": [
        "password", "login", "authenticate", "bcrypt", "hashlib", "md5", "sha1",
        "session", "credential", "auth", "passwd", "signin", "remember_me",
    ],
    "broken-access-control": [
        "authorize", "authorization", "is_admin", "permission", "acl",
        "can(", "tenant", "owner", "check_access", "access_control",
    ],
    "session-management": [
        "session", "cookie", "setcookie", "httponly", "secure=", "sessionid",
        "session_id", "express-session", "flask.session", "req.session",
    ],
    "rate-limiting": [
        "rate limit", "ratelimit", "throttle", "brute force", "attempts", "login",
        "otp", "captcha", "too many requests", "429",
    ],
    "race-conditions": [
        "thread", "lock", "mutex", "semaphore", "concurrent",
        "transaction", "check-then-act", "race", "atomic", "goroutine",
    ],
    "information-disclosure": [
        "traceback", "stack trace", "debug", "log.", "logger",
        "print(", "console.log", "verbose", "str(e)", "repr(e)",
    ],
    "security-misconfiguration": [
        "debug=true", "debug = true", "app.run(", "0.0.0.0", "cors", "allow_origins",
        "verify=false", "insecure", "default", "admin", "root", "chmod 777",
    ],
    "weak-cryptography": [
        "md5", "sha1", "rc4", "ecb", "random.random", "math.random",
        "hashlib", "crypto", "encrypt", "cipher", "salt", "pbkdf2", "bcrypt",
        "aes", "rsa",
    ],
    "insecure-randomness": [
        "math.random", "random.random", "randint", "rand(", "randn", "mt19937",
        "random.choice", "random.choices", "uuid1", "time()", "seed(",
    ],
    "hardcoded-secrets": [
        "api_key", "apikey", "secret", "password", "passwd", "token", "private_key",
        "access_key", "aws_secret", "bearer ", "sk-", "-----begin", "client_secret",
    ],
    "vulnerable-dependencies": [
        "requirements.txt", "package.json", "pom.xml", "gemfile", "cargo.toml",
        "go.mod", "dependencies", "version", "cve-", "advisory",
    ],
    "cors-misconfiguration": [
        "access-control-allow-origin", "cors", "allow_origins", "origins=", "*",
        "credentials", "allow_credentials",
    ],
    "security-headers-and-cookies": [
        "content-security-policy", "x-frame-options", "strict-transport-security",
        "set-cookie", "httponly", "samesite", "x-content-type-options",
    ],
    "logging-and-monitoring-failures": [
        "log.", "logger", "audit", "monitor", "alert", "logging", "audit_log",
    ],
    "mass-assignment": [
        "update(", "assign", "setattr", "**kwargs", "**request", "fill(", "mass assignment",
        "update_attributes", "permit(", "filter_input",
    ],
    "nosql-injection": [
        "mongodb", "mongoose", "find(", "findone(", "$where", "$ne", "$gt", "nosql",
        "collection.find", "db.collection", "aggregate(",
    ],
    "redos": [
        "regex", "regexp", "re.compile", "re.match", "re.search", "pattern",
        "new regexp", "preg_match", "backtracking", "(.*)+", "(.+)+",
    ],
    "docker-and-iac-misconfiguration": [
        "dockerfile", "from ", "run ", "privileged", "user root", "latest",
        "terraform", "kubernetes", "securitycontext", "cap_add", "volume",
    ],
}

# Human-readable language names used by frontmatter `languages:`.
LANGUAGE_BY_EXT = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript", ".ts": "typescript",
    ".tsx": "typescript", ".java": "java", ".php": "php", ".rb": "ruby", ".go": "go",
    ".rs": "rust", ".cs": "csharp", ".kt": "kotlin", ".swift": "swift", ".c": "c",
    ".cpp": "cpp", ".h": "c", ".hpp": "cpp", ".sh": "bash", ".sql": "sql",
}


@dataclass
class KnowledgeDoc:
    id: str
    title: str
    path: Path
    body: str
    kind: str = "vulnerability"
    cwe: str = ""
    severity: str = ""
    languages: list[str] = field(default_factory=list)
    rules: list[str] = field(default_factory=list)
    triggers: list[str] = field(default_factory=list)

    @property
    def is_guideline(self) -> bool:
        return self.kind == "guideline" or self.id in GUIDELINE_IDS


def _parse_frontmatter(text: str) -> tuple[dict[str, str], str]:
    """Parse the tiny YAML-ish frontmatter used by the knowledge files."""
    if not text.startswith("---"):
        return {}, text
    end = text.find("\n---", 3)
    if end == -1:
        return {}, text
    block = text[3:end]
    body = text[end + 4 :]
    data: dict[str, str] = {}
    for line in block.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, value = line.split(":", 1)
        data[key.strip().lower()] = value.strip().strip("[]")
    return data, body.lstrip("\n")


def _filename_id(path: Path) -> str:
    name = path.name
    # The knowledge base contains a few files with a stray trailing dot
    # (``ssrf.md.``); normalise those instead of ignoring the document.
    name = re.sub(r"\.md\.?$", "", name, flags=re.IGNORECASE)
    name = re.sub(r"[^a-zA-Z0-9]+", "-", name).strip("-").lower()
    return name


def _title_from_id(doc_id: str) -> str:
    words = doc_id.replace("_", "-").split("-")
    small = {"and", "or", "of", "the", "in", "to"}
    return " ".join(w if w in small else w.capitalize() for w in words if w)


def _derive_triggers(doc_id: str, title: str, rules: list[str]) -> list[str]:
    triggers: list[str] = list(TRIGGERS.get(doc_id, []))
    for rule in rules:
        rule = rule.strip().lower()
        if rule:
            triggers.append(rule)
    # Filename words are weak but useful for documents without a trigger map.
    for word in re.split(r"[-_ ]+", doc_id):
        if len(word) >= 5:
            triggers.append(word)
    triggers.append(title.lower())
    # De-duplicate while preserving order.
    seen: set[str] = set()
    unique = []
    for trigger in triggers:
        if trigger and trigger not in seen:
            seen.add(trigger)
            unique.append(trigger)
    return unique


def _candidate_dirs(explicit: str | None) -> list[Path]:
    dirs: list[Path] = []
    if explicit:
        dirs.append(Path(explicit).expanduser())
    env = os.environ.get("CYCLON_KB_DIR")
    if env:
        dirs.append(Path(env).expanduser())
    package = Path(__file__).resolve().parent
    dirs.append(package / "knowledge")
    dirs.append(package.parent)  # editable install / repo root
    dirs.append(Path.cwd())
    seen: set[Path] = set()
    unique = []
    for directory in dirs:
        resolved = directory.resolve()
        if resolved not in seen:
            seen.add(resolved)
            unique.append(resolved)
    return unique


class KnowledgeBase:
    def __init__(self, docs: list[KnowledgeDoc], source: Path | None = None):
        self.docs = docs
        self.source = source

    @property
    def vulnerabilities(self) -> list[KnowledgeDoc]:
        return [d for d in self.docs if not d.is_guideline]

    def get(self, doc_id: str) -> KnowledgeDoc | None:
        wanted = doc_id.strip().lower()
        for doc in self.docs:
            if doc.id == wanted:
                return doc
        return None

    def guidelines(self) -> list[KnowledgeDoc]:
        return [d for d in self.docs if d.is_guideline]

    def retrieve(
        self,
        code: str,
        language: str = "",
        max_chars: int = 7000,
        max_docs: int = 3,
    ) -> list[KnowledgeDoc]:
        """Return the knowledge documents most relevant to ``code``.

        A document is only returned when at least one trigger matches, so
        unrelated prompts are not polluted. The analysis guidelines are
        prepended when there is at least one match.
        """
        if not code.strip():
            return []
        lower = code.lower()
        scored: list[tuple[float, KnowledgeDoc]] = []
        for doc in self.vulnerabilities:
            # Weight longer (more specific) triggers higher so generic tokens
            # like "open(" do not crowd out an exact match such as "os.system".
            score = 0.0
            for trigger in doc.triggers:
                if not trigger or trigger not in lower:
                    continue
                if len(trigger) >= 14:
                    score += 3.0
                elif len(trigger) >= 8:
                    score += 2.0
                else:
                    score += 1.0
            if score < 2.0:
                continue
            if language and language in doc.languages:
                score += 1.5
            scored.append((score, doc))
        if not scored:
            return []
        scored.sort(key=lambda item: (-item[0], item[1].id))

        selected: list[KnowledgeDoc] = []
        used = 0
        for _score, doc in scored[:max_docs]:
            body = doc.body.strip()
            if not body:
                continue
            remaining = max_chars - used
            if remaining <= 400:
                break
            if len(body) > remaining:
                body = body[:remaining].rstrip() + "\n\n… (truncated)"
            doc = KnowledgeDoc(
                id=doc.id, title=doc.title, path=doc.path, body=body, kind=doc.kind,
                cwe=doc.cwe, severity=doc.severity, languages=doc.languages,
                rules=doc.rules, triggers=doc.triggers,
            )
            selected.append(doc)
            used += len(body)

        guideline = self.get("analysis-guidelines")
        if guideline is not None and selected:
            body = guideline.body.strip()
            remaining = max_chars - used
            if remaining > 400:
                if len(body) > remaining:
                    body = body[:remaining].rstrip() + "\n\n… (truncated)"
                selected.insert(
                    0,
                    KnowledgeDoc(
                        id=guideline.id, title=guideline.title, path=guideline.path,
                        body=body, kind=guideline.kind, cwe=guideline.cwe,
                        severity=guideline.severity, languages=guideline.languages,
                        rules=guideline.rules, triggers=guideline.triggers,
                    ),
                )
        return selected

    def render(self, docs: list[KnowledgeDoc]) -> str:
        if not docs:
            return ""
        parts = ["Reference knowledge from the Cyclon vulnerability knowledge base:"]
        for doc in docs:
            parts.append(f"\n### {doc.title} ({doc.id})")
            if doc.cwe:
                parts.append(f"CWE: {doc.cwe}")
            parts.append(doc.body.strip())
        return "\n".join(parts)


_KB_CACHE: dict[str, KnowledgeBase] = {}


def load_knowledge(directory: str | None = None) -> KnowledgeBase:
    """Load the knowledge base from disk (cached per directory)."""
    cache_key = directory or "<auto>"
    if cache_key in _KB_CACHE:
        return _KB_CACHE[cache_key]

    for candidate in _candidate_dirs(directory):
        if not candidate.is_dir():
            continue
        files = sorted(
            p for p in candidate.iterdir()
            if p.is_file() and re.search(r"\.md\.?$", p.name, re.IGNORECASE)
        )
        if len(files) < 3:
            continue
        docs: list[KnowledgeDoc] = []
        seen_ids: set[str] = set()
        for path in files:
            if path.name.lower() == "readme.md":
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            meta, body = _parse_frontmatter(text)
            filename_id = _filename_id(path)
            frontmatter_id = (meta.get("id") or "").strip().lower()
            doc_id = frontmatter_id
            # Missing, duplicated, or clearly copy-pasted ids (one
            # vulnerability file claims to be a guideline): use the filename.
            if (
                not doc_id
                or doc_id in seen_ids
                or (doc_id in GUIDELINE_IDS and filename_id not in GUIDELINE_IDS)
            ):
                doc_id = filename_id
            if doc_id in seen_ids:
                continue
            seen_ids.add(doc_id)
            kind = (meta.get("type") or "vulnerability").strip().lower()
            # A vulnerability file with a copy-pasted `type: guideline`
            # frontmatter should still be treated as a vulnerability.
            if doc_id not in GUIDELINE_IDS and kind == "guideline":
                kind = "vulnerability"
            rules = [r.strip() for r in meta.get("scanner_rules", "").split(",") if r.strip()]
            languages = [l.strip().lower() for l in meta.get("languages", "").split(",") if l.strip()]
            # If we rejected the frontmatter id, its title is usually
            # copy-pasted too; derive a correct one from the filename.
            if doc_id != frontmatter_id:
                title = _title_from_id(doc_id)
            else:
                title = (meta.get("title") or _title_from_id(doc_id)).strip()
            docs.append(
                KnowledgeDoc(
                    id=doc_id,
                    title=title,
                    path=path,
                    body=body,
                    kind=kind,
                    cwe=(meta.get("cwe") or "").strip(),
                    severity=(meta.get("severity") or "").strip(),
                    languages=languages,
                    rules=rules,
                    triggers=_derive_triggers(doc_id, title, rules),
                )
            )
        if docs:
            kb = KnowledgeBase(docs, source=candidate)
            _KB_CACHE[cache_key] = kb
            return kb

    empty = KnowledgeBase([], source=None)
    _KB_CACHE[cache_key] = empty
    return empty


def language_for_path(path: Path) -> str:
    return LANGUAGE_BY_EXT.get(path.suffix.lower(), "")
