"""Run one injection case against a model, score it, and record replayable responses."""

from __future__ import annotations

from typing import Any

from fabrikam_lab.agent import AgentResult, run_agent
from fabrikam_lab.cases import Case
from fabrikam_lab.models.base import ChatResponse, ModelClient, ToolCall
from fabrikam_lab.models.stub import ScriptedModel
from fabrikam_lab.prompts import BASELINE_SYSTEM_PROMPT
from fabrikam_lab.scoring import Score, score_run

DEFAULT_CASE_MAX_TURNS = 6


def response_to_dict(resp: ChatResponse) -> dict[str, Any]:
    return {
        "content": resp.content,
        "finish_reason": resp.finish_reason,
        "tool_calls": [
            {
                "id": tc.id,
                "name": tc.name,
                "arguments": tc.arguments,
                "raw_arguments": tc.raw_arguments,
                "parse_error": tc.parse_error,
            }
            for tc in resp.tool_calls
        ],
    }


def response_from_dict(d: dict[str, Any]) -> ChatResponse:
    return ChatResponse(
        content=d.get("content"),
        finish_reason=d.get("finish_reason"),
        tool_calls=[ToolCall(**tc) for tc in d.get("tool_calls", [])],
    )


class RecordingClient:
    """Wraps a model client and keeps every response, so a run can be replayed offline."""

    def __init__(self, inner: ModelClient) -> None:
        self.inner = inner
        self.responses: list[dict[str, Any]] = []
        self.usage: list[dict[str, Any]] = []

    def chat(self, messages, tools, temperature=0.0, seed=None) -> ChatResponse:
        resp = self.inner.chat(messages, tools, temperature=temperature, seed=seed)
        self.responses.append(response_to_dict(resp))
        self.usage.append(resp.usage or {})
        return resp

    def info(self) -> dict[str, Any]:
        return self.inner.info()


def run_case(
    model: ModelClient,
    case: Case,
    system_prompt: str = BASELINE_SYSTEM_PROMPT,
    max_turns: int = DEFAULT_CASE_MAX_TURNS,
    temperature: float = 0.0,
    seed: int | None = None,
) -> tuple[AgentResult, Score, list[dict[str, Any]], list[dict[str, Any]]]:
    """Run ``case`` once. Returns the agent result, its score, recorded responses and token usage."""
    env = case.make_env()
    rec = RecordingClient(model)
    res = run_agent(
        rec,
        case.user_message,
        env=env,
        system_prompt=system_prompt + case.secret_line(),
        max_turns=max_turns,
        temperature=temperature,
        seed=seed,
        history=case.history or None,
    )
    return res, score_run(case, res.final_text, env), rec.responses, rec.usage


def replay_case(case: Case, responses: list[dict[str, Any]], max_turns: int = DEFAULT_CASE_MAX_TURNS) -> Score:
    """Re-run a recorded case offline from its saved responses and score it again."""
    model = ScriptedModel([response_from_dict(r) for r in responses], name="replay")
    _, score, _, _ = run_case(model, case, max_turns=max_turns)
    return score
