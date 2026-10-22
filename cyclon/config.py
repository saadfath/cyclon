"""Configuration helpers for cyclon."""

import json
import os
from pathlib import Path

CONFIG_DIR = Path.home() / ".config" / "cyclon"
CONFIG_FILE = CONFIG_DIR / "config.json"

DEFAULT_MODEL = "grok-2-latest"
DEFAULT_BASE_URL = "https://api.x.ai/v1"

ENV_KEYS = ("XAI_API_KEY", "GROK_API_KEY")
ENV_MULTI_KEYS = ("XAI_API_KEYS", "GROK_API_KEYS")


def load_config() -> dict:
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def save_config(cfg: dict) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2))


def get_api_key() -> str | None:
    keys = get_api_keys()
    return keys[0] if keys else None


def get_api_keys(cli_keys: str | None = None) -> list[str]:
    if cli_keys:
        return [k.strip() for k in cli_keys.split(",") if k.strip()]
    for k in ENV_MULTI_KEYS:
        v = os.environ.get(k)
        if v:
            return [x.strip() for x in v.split(",") if x.strip()]
    for k in ENV_KEYS:
        v = os.environ.get(k)
        if v:
            return [v.strip()]
    cfg = load_config()
    if isinstance(cfg.get("api_keys"), list):
        return [str(x).strip() for x in cfg["api_keys"] if str(x).strip()]
    if cfg.get("api_key"):
        return [str(cfg["api_key"]).strip()]
    return []


def get_model(cli_model: str | None = None) -> str:
    if cli_model:
        return cli_model
    cfg = load_config()
    models = cfg.get("models")
    if isinstance(models, list) and models:
        return str(models[0])
    return cfg.get("model", DEFAULT_MODEL)


def get_models(cli_models: str | None = None, count: int = 1) -> list[str]:
    if cli_models:
        parts = [m.strip() for m in cli_models.split(",") if m.strip()]
        if parts:
            # pad to count
            while len(parts) < count:
                parts.append(parts[-1])
            return parts[:count]
    cfg = load_config()
    models = cfg.get("models")
    if isinstance(models, list) and models:
        parts = [str(m).strip() for m in models if str(m).strip()]
        if parts:
            while len(parts) < count:
                parts.append(parts[-1])
            return parts[:count]
    single = get_model(None)
    return [single] * count


def get_base_url() -> str:
    cfg = load_config()
    return os.environ.get("XAI_BASE_URL") or cfg.get("base_url", DEFAULT_BASE_URL)


def set_api_key(key: str) -> None:
    cfg = load_config()
    cfg["api_key"] = key.strip()
    save_config(cfg)


def set_model(model: str) -> None:
    cfg = load_config()
    cfg["model"] = model.strip()
    save_config(cfg)
