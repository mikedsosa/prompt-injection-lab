"""Model client interface shared by the real client and the offline stub."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


class ModelError(Exception):
    """The model endpoint failed or returned something unusable."""


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]
    raw_arguments: str = ""
    parse_error: str | None = None  # set when the model's argument JSON did not parse


@dataclass
class ChatResponse:
    content: str | None
    tool_calls: list[ToolCall] = field(default_factory=list)
    finish_reason: str | None = None
    usage: dict[str, Any] = field(default_factory=dict)
    latency_s: float | None = None
    raw: dict[str, Any] | None = None


class ModelClient(Protocol):
    def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        temperature: float = 0.0,
        seed: int | None = None,
    ) -> ChatResponse: ...

    def info(self) -> dict[str, Any]:
        """Metadata recorded with every run (model name, endpoint, versions)."""
        ...
