"""Run one injection case against a model, score it, and record replayable responses."""

from __future__ import annotations

from typing import Any

from fabrikam_lab.agent import AgentResult, run_agent
from fabrikam_lab.cases import Case
from fabrikam_lab.defenses import (
    CONFIGS,
    DefenseConfig,
    ToolGateway,
    filter_answer,
    system_prompt,
    tool_message_content,
)
from fabrikam_lab.models.base import ChatResponse, ModelClient, ToolCall
from fabrikam_lab.models.stub import ScriptedModel
from fabrikam_lab.prompts import BASELINE_SYSTEM_PROMPT
from fabrikam_lab.scoring import Score, attempted_score, score_run

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
    system_prompt_base: str = BASELINE_SYSTEM_PROMPT,
    max_turns: int = DEFAULT_CASE_MAX_TURNS,
    temperature: float = 0.0,
    seed: int | None = None,
    defense: DefenseConfig | None = None,
) -> tuple[AgentResult, Score, list[dict[str, Any]], list[dict[str, Any]]]:
    """Run ``case`` once. Returns the agent result, its score, recorded responses and token usage.

    With a ``defense`` config, the matching mitigations are switched on. The score is what
    actually happened with the defenses in place. ``score.details`` then also records the raw
    (pre-filter) answer, what the output filter did, every blocked tool call, and
    ``attempted``: how the case would have scored had the blocked calls run and the answer
    not been filtered (same run, same model turns).
    """
    defense = defense or CONFIGS["none"]
    env = case.make_env()
    rec = RecordingClient(model)
    gateway = ToolGateway(env, case.canary) if defense.gateway else None
    res = run_agent(
        rec,
        case.user_message,
        env=env,
        system_prompt=system_prompt(system_prompt_base, defense) + case.secret_line(),
        max_turns=max_turns,
        temperature=temperature,
        seed=seed,
        history=case.history or None,
        call_tool=gateway.call if gateway else None,
        tool_content=(lambda r: tool_message_content(r, defense)) if defense.spotlight else None,
    )
    raw_answer = res.final_text
    filter_actions: list[str] = []
    if defense.output_filter:
        res.final_text, filter_actions = filter_answer(raw_answer, case.canary)
    score = score_run(case, res.final_text, env)
    if defense.any:
        attempted = attempted_score(case, raw_answer, env)
        score.details = {
            "defense": defense.to_dict(),
            "raw_final_text": raw_answer,
            "output_filter_actions": filter_actions,
            "blocked_calls": [
                {"name": c.name, "arguments": c.arguments, "reasons": c.block_reasons} for c in env.calls if c.blocked
            ],
            "attempted": {
                "attack_success": attempted.attack_success,
                "checks_hit": attempted.checks_hit,
                "canary_leak_channels": attempted.canary_leak_channels,
                "external_emails": attempted.external_emails,
                "mfa_resets": attempted.mfa_resets,
            },
        }
    return res, score, rec.responses, rec.usage


def replay_run(
    case: Case,
    responses: list[dict[str, Any]],
    max_turns: int = DEFAULT_CASE_MAX_TURNS,
    defense: DefenseConfig | None = None,
) -> tuple[AgentResult, Score]:
    """Re-run a recorded case offline from its saved responses. Returns the result and score."""
    model = ScriptedModel([response_from_dict(r) for r in responses], name="replay")
    res, score, _, _ = run_case(model, case, max_turns=max_turns, defense=defense)
    return res, score


def replay_case(
    case: Case,
    responses: list[dict[str, Any]],
    max_turns: int = DEFAULT_CASE_MAX_TURNS,
    defense: DefenseConfig | None = None,
) -> Score:
    """Re-run a recorded case offline from its saved responses and score it again."""
    return replay_run(case, responses, max_turns=max_turns, defense=defense)[1]
