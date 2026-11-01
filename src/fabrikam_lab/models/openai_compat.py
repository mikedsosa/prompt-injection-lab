"""Client for any OpenAI-compatible ``/chat/completions`` endpoint.

The default target is a local Ollama server (``http://127.0.0.1:11434/v1``). A
hosted endpoint would only need a different ``base_url``, ``model`` and, if it
requires one, an API key read from an environment variable. Nothing here stores keys.

Standard library only (urllib), so the harness has no runtime dependencies.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from typing import Any

from fabrikam_lab.models.base import ChatResponse, ModelError, ToolCall


class OpenAICompatClient:
    def __init__(
        self,
        base_url: str,
        model: str,
        api_key_env: str | None = None,
        timeout_s: float = 900,
        extra_body: dict[str, Any] | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key_env = api_key_env
        self.timeout_s = timeout_s
        self.extra_body = extra_body or {}

    # --- HTTP ------------------------------------------------------------

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key_env:
            key = os.environ.get(self.api_key_env)
            if key:
                headers["Authorization"] = f"Bearer {key}"
        return headers

    def _request(self, url: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, headers=self._headers(), method="POST" if data else "GET")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:500]
            raise ModelError(f"HTTP {exc.code} from {url}: {detail}") from exc
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise ModelError(f"request to {url} failed: {exc}") from exc

    # --- ModelClient -----------------------------------------------------

    def build_body(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        temperature: float = 0.0,
        seed: int | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {"model": self.model, "messages": messages, "temperature": temperature, "stream": False}
        if tools:
            body["tools"] = tools
        if seed is not None:
            body["seed"] = seed
        body.update(self.extra_body)
        return body

    def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        temperature: float = 0.0,
        seed: int | None = None,
    ) -> ChatResponse:
        body = self.build_body(messages, tools, temperature, seed)
        start = time.monotonic()
        raw = self._request(f"{self.base_url}/chat/completions", body)
        latency = time.monotonic() - start
        return parse_chat_completion(raw, latency_s=latency)

    def info(self) -> dict[str, Any]:
        return {"client": "openai_compat", "base_url": self.base_url, "model": self.model}

    def ollama_metadata(self) -> dict[str, Any]:
        """Best-effort Ollama version and model digest, for reproducibility records.

        Only meaningful when ``base_url`` points at Ollama. Returns what it can and
        records errors instead of raising.
        """
        root = self.base_url.removesuffix("/v1")
        meta: dict[str, Any] = {}
        try:
            meta["ollama_version"] = self._request(f"{root}/api/version").get("version")
        except ModelError as exc:
            meta["ollama_version_error"] = str(exc)
        try:
            tags = self._request(f"{root}/api/tags").get("models", [])
            match = next((m for m in tags if m.get("name") == self.model or m.get("model") == self.model), None)
            if match:
                meta["model_digest"] = match.get("digest")
                meta["model_details"] = match.get("details")
        except ModelError as exc:
            meta["model_digest_error"] = str(exc)
        return meta


def parse_chat_completion(raw: dict[str, Any], latency_s: float | None = None) -> ChatResponse:
    """Turn an OpenAI-style chat completion into a ``ChatResponse``."""
    try:
        choice = raw["choices"][0]
        message = choice["message"]
    except (KeyError, IndexError, TypeError) as exc:
        raise ModelError(f"unexpected response shape: {str(raw)[:300]}") from exc
    calls: list[ToolCall] = []
    for i, tc in enumerate(message.get("tool_calls") or []):
        fn = tc.get("function", {})
        raw_args = fn.get("arguments", "")
        args: dict[str, Any] = {}
        error = None
        if isinstance(raw_args, dict):
            args, raw_args = raw_args, json.dumps(raw_args)
        else:
            try:
                parsed = json.loads(raw_args) if raw_args else {}
                if isinstance(parsed, dict):
                    args = parsed
                else:
                    error = "arguments are not a JSON object"
            except json.JSONDecodeError as exc:
                error = f"invalid JSON arguments: {exc}"
        calls.append(
            ToolCall(
                id=tc.get("id") or f"call_{i}",
                name=fn.get("name", ""),
                arguments=args,
                raw_arguments=raw_args,
                parse_error=error,
            )
        )
    return ChatResponse(
        content=message.get("content"),
        tool_calls=calls,
        finish_reason=choice.get("finish_reason"),
        usage=raw.get("usage") or {},
        latency_s=latency_s,
        raw=raw,
    )
