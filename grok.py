"""Client for the xAI (Grok) chat completions API."""

import json
import re
import time
from typing import Any

import requests

from .config import get_api_key, get_base_url


class GrokError(Exception):
    pass


class GrokClient:
    def __init__(self, api_key: str | None = None, base_url: str | None = None,
                 model: str = "grok-2-latest", timeout: int = 90):
        self.api_key = api_key or get_api_key()
        if not self.api_key:
            raise GrokError(
                "No API key found. Set XAI_API_KEY/GROK_API_KEY env var "
                "or run 'cyclon config set-key <KEY>'."
            )
        self.base_url = (base_url or get_base_url()).rstrip("/")
        self.model = model
        self.timeout = timeout
        self.extra = {}
        if "nvidia" in self.base_url:
            self.extra = {"chat_template_kwargs": {"enable_thinking": False}}

    def chat(self, messages: list[dict], temperature: float = 0.2,
             max_tokens: int = 4096, retries: int = 2) -> str:
        url = f"{self.base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        last_err = None
        for attempt in range(retries):
            payload = {
                "model": self.model,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens,
            }
            payload.update(self.extra or {})
            try:
                resp = requests.post(url, headers=headers, json=payload, timeout=self.timeout)
                if resp.status_code == 429:
                    # Honor Retry-After if present.
                    retry_after = resp.headers.get("Retry-After")
                    wait = 5
                    if retry_after:
                        try:
                            wait = int(retry_after)
                        except ValueError:
                            wait = 5
                    wait = min(max(wait, 1), 15) + attempt
                    last_err = GrokError(f"HTTP 429: rate limited, waiting {wait}s")
                    time.sleep(wait)
                    continue
                if 500 <= resp.status_code < 600:
                    last_err = GrokError(f"HTTP {resp.status_code}: {resp.text[:300]}")
                    time.sleep(min(2 ** attempt, 30))
                    continue
                if resp.status_code == 400 and self.extra:
                    self.extra = {}
                    last_err = GrokError(f"HTTP 400: {resp.text[:200]}")
                    continue
                if not resp.ok:
                    raise GrokError(f"HTTP {resp.status_code}: {resp.text[:500]}")
                data = resp.json()
                choices = data.get("choices") or []
                if not choices:
                    raise GrokError(f"Empty choices in response: {data}")
                msg = choices[0].get("message", {}) or {}
                content = msg.get("content")
                if content is None:
                    content = msg.get("reasoning_content")
                if content is None:
                    content = ""
                return content
            except requests.RequestException as e:
                last_err = GrokError(str(e))
                time.sleep(min(2 ** attempt, 30))
        raise last_err or GrokError("Unknown error")


def parse_json_array(text: str) -> list[dict]:
    """Extract a JSON array of findings from model output."""
    text = text.strip()
    # Strip an outer fenced code block only (not fences embedded in strings).
    if text.startswith("```"):
        # Strip outer fence: from first ``` to the last ``` in the text.
        first = text.find("```")
        last = text.rfind("```")
        if last > first:
            inner = text[first:last]
            # remove the opening fence line
            inner = re.sub(r"^```(?:json|JSON)?\s*\n?", "", inner)
            text = inner.strip()
    # Try direct
    try:
        obj = json.loads(text)
        if isinstance(obj, list):
            return obj
        if isinstance(obj, dict):
            for key in ("findings", "bugs", "issues", "results"):
                if isinstance(obj.get(key), list):
                    return obj[key]
            # single object -> wrap
            return [obj]
    except json.JSONDecodeError:
        pass
    # Try to find array substring
    start = text.find("[")
    end = text.rfind("]")
    if start != -1 and end != -1 and end > start:
        try:
            obj = json.loads(text[start:end + 1])
            if isinstance(obj, list):
                return obj
        except json.JSONDecodeError:
            pass
    return []


SYSTEM_PROMPT = """You are an expert code reviewer and bug hunter. Analyze the provided source file for bugs, defects, security issues, logic errors, and potential runtime problems.

Return ONLY a JSON array (no prose outside). Each element must be an object with these keys:
- "file": string (file path)
- "line": integer or null (best-effort line number where issue occurs)
- "severity": one of "critical", "high", "medium", "low", "info"
- "category": short string (e.g. "null-deref", "off-by-one", "security", "logic")
- "title": short title
- "description": detailed explanation
- "suggestion": concrete fix suggestion (code if helpful)

If no issues found, return an empty array []. Be precise; do not invent issues. Prefer fewer high-quality findings over many speculative ones."""
