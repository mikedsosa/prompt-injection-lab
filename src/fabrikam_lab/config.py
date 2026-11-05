"""Load model endpoint settings from ``config/models.toml``."""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

from fabrikam_lab.models.openai_compat import OpenAICompatClient

DEFAULT_CONFIG = Path(__file__).resolve().parents[2] / "config" / "models.toml"


def load_config(path: Path | str = DEFAULT_CONFIG) -> dict[str, Any]:
    with open(path, "rb") as fh:
        cfg = tomllib.load(fh)
    cfg.setdefault("defaults", {})
    cfg.setdefault("models", {})
    return cfg


def make_client(key: str, cfg: dict[str, Any], extra_body: dict[str, Any] | None = None) -> OpenAICompatClient:
    try:
        m = cfg["models"][key]
    except KeyError as exc:
        raise KeyError(f"no model {key!r} in config; have {sorted(cfg['models'])}") from exc
    return OpenAICompatClient(
        base_url=m["base_url"],
        model=m["model"],
        api_key_env=m.get("api_key_env"),
        timeout_s=m.get("timeout_s", cfg["defaults"].get("timeout_s", 900)),
        extra_body=extra_body,
    )
