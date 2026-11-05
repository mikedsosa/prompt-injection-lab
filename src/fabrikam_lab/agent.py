"""Plain Python tool-calling agent loop (no framework).

Each turn: send the conversation and tool list to the model. If it asks for tools,
run them against the mock ``ToolEnv`` and append the results; otherwise its text is
the final answer. Model mistakes (unknown tool, bad JSON, wrong arguments) are fed
back as tool errors rather than crashing the run, so they show up in the logs.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from typing import Any

from fabrikam_lab.models.base import ChatResponse, ModelClient, ModelError
from fabrikam_lab.prompts import BASELINE_SYSTEM_PROMPT
from fabrikam_lab.tools import ToolCallRecord, ToolEnv, openai_tools

DEFAULT_MAX_TURNS = 8


@dataclass
class AgentResult:
    final_text: str | None
    stop_reason: str  # "final_answer" | "max_turns" | "model_error"
    turns: int
    messages: list[dict[str, Any]]
    tool_calls: list[ToolCallRecord]
    malformed_tool_calls: int = 0
    error: str | None = None
    wall_s: float = 0.0
    model_latencies_s: list[float] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["tool_calls"] = [asdict(c) for c in self.tool_calls]
        return d


def _assistant_message(resp: ChatResponse) -> dict[str, Any]:
    msg: dict[str, Any] = {"role": "assistant", "content": resp.content or ""}
    if resp.tool_calls:
        msg["tool_calls"] = [
            {
                "id": tc.id,
                "type": "function",
                "function": {"name": tc.name, "arguments": tc.raw_arguments or json.dumps(tc.arguments)},
            }
            for tc in resp.tool_calls
        ]
    return msg


def run_agent(
    model: ModelClient,
    user_message: str,
    env: ToolEnv | None = None,
    system_prompt: str = BASELINE_SYSTEM_PROMPT,
    max_turns: int = DEFAULT_MAX_TURNS,
    temperature: float = 0.0,
    seed: int | None = None,
    history: list[dict[str, str]] | None = None,
) -> AgentResult:
    """Run the loop. ``history`` is an optional scripted earlier conversation (user and
    assistant turns) placed between the system prompt and ``user_message``."""
    env = env if env is not None else ToolEnv()
    tools = openai_tools()
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system_prompt},
        *({"role": h["role"], "content": h["content"]} for h in history or []),
        {"role": "user", "content": user_message},
    ]
    malformed = 0
    latencies: list[float] = []
    start = time.monotonic()

    def result(final: str | None, reason: str, turns: int, error: str | None = None) -> AgentResult:
        return AgentResult(
            final_text=final,
            stop_reason=reason,
            turns=turns,
            messages=messages,
            tool_calls=env.calls,
            malformed_tool_calls=malformed,
            error=error,
            wall_s=round(time.monotonic() - start, 3),
            model_latencies_s=latencies,
        )

    for turn in range(1, max_turns + 1):
        try:
            resp = model.chat(messages, tools, temperature=temperature, seed=seed)
        except ModelError as exc:
            return result(None, "model_error", turn, error=str(exc))
        if resp.latency_s is not None:
            latencies.append(round(resp.latency_s, 3))
        messages.append(_assistant_message(resp))
        if not resp.tool_calls:
            return result(resp.content or "", "final_answer", turn)
        for tc in resp.tool_calls:
            if tc.parse_error:
                malformed += 1
                rec = ToolCallRecord(tc.name, {"_raw": tc.raw_arguments}, ok=False, error=tc.parse_error)
                env.calls.append(rec)
            else:
                rec = env.call(tc.name, tc.arguments)
                if not rec.ok and (rec.error or "").startswith(("unknown tool", "missing", "unexpected", "argument")):
                    malformed += 1
            content = json.dumps({"ok": True, "result": rec.result} if rec.ok else {"ok": False, "error": rec.error})
            messages.append({"role": "tool", "tool_call_id": tc.id, "name": tc.name, "content": content})
    return result(None, "max_turns", max_turns)
