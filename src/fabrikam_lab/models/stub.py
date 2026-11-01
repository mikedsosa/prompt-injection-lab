"""Offline stand-in for a model, used by unit tests and dry runs. Never calls a network."""

from __future__ import annotations

import copy
from typing import Any

from fabrikam_lab.models.base import ChatResponse, ModelError, ToolCall


def tool_call(name: str, call_id: str = "call_0", **arguments: Any) -> ChatResponse:
    """A response in which the model asks for one tool call."""
    return ChatResponse(
        content=None, tool_calls=[ToolCall(id=call_id, name=name, arguments=arguments)], finish_reason="tool_calls"
    )


def answer(text: str) -> ChatResponse:
    """A final plain-text response."""
    return ChatResponse(content=text, finish_reason="stop")


class ScriptedModel:
    """Returns a fixed list of responses in order and records what it was sent."""

    def __init__(self, responses: list[ChatResponse], name: str = "stub") -> None:
        self._responses = list(responses)
        self.name = name
        self.requests: list[dict[str, Any]] = []

    def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        temperature: float = 0.0,
        seed: int | None = None,
    ) -> ChatResponse:
        self.requests.append(
            {"messages": copy.deepcopy(messages), "tools": tools, "temperature": temperature, "seed": seed}
        )
        if not self._responses:
            raise ModelError("scripted model ran out of responses")
        return self._responses.pop(0)

    def info(self) -> dict[str, Any]:
        return {"client": "scripted_stub", "model": self.name}
