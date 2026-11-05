import json

from fabrikam_lab.agent import run_agent
from fabrikam_lab.models.base import ChatResponse, ModelError, ToolCall
from fabrikam_lab.models.stub import ScriptedModel, answer, tool_call
from fabrikam_lab.prompts import BASELINE_SYSTEM_PROMPT
from fabrikam_lab.tools import ToolEnv


def test_single_tool_then_answer():
    model = ScriptedModel([tool_call("read_kb_article", article_id="KB-1001"), answer("Open the VPN client.")])
    res = run_agent(model, "How do I connect to VPN?", seed=1)
    assert res.stop_reason == "final_answer"
    assert res.final_text == "Open the VPN client."
    assert res.turns == 2
    assert [c.name for c in res.tool_calls] == ["read_kb_article"]
    assert res.malformed_tool_calls == 0


def test_messages_sent_to_model():
    model = ScriptedModel([tool_call("fetch_ticket", call_id="c1", ticket_id="HD-2002"), answer("done")])
    run_agent(model, "Summarize HD-2002", temperature=0.0, seed=7)
    first, second = model.requests
    assert first["messages"][0] == {"role": "system", "content": BASELINE_SYSTEM_PROMPT}
    assert first["messages"][1] == {"role": "user", "content": "Summarize HD-2002"}
    assert first["seed"] == 7 and first["temperature"] == 0.0
    assert {t["function"]["name"] for t in first["tools"]} >= {"fetch_ticket", "send_email"}
    assistant, tool_msg = second["messages"][2], second["messages"][3]
    assert assistant["tool_calls"][0]["function"]["name"] == "fetch_ticket"
    assert json.loads(assistant["tool_calls"][0]["function"]["arguments"]) == {"ticket_id": "HD-2002"}
    assert tool_msg["role"] == "tool" and tool_msg["tool_call_id"] == "c1"
    assert json.loads(tool_msg["content"])["result"]["ticket_id"] == "HD-2002"


def test_unknown_tool_is_fed_back_as_error():
    model = ScriptedModel([tool_call("delete_everything"), answer("sorry")])
    res = run_agent(model, "hi")
    assert res.stop_reason == "final_answer"
    assert res.malformed_tool_calls == 1
    payload = json.loads(model.requests[1]["messages"][-1]["content"])
    assert payload["ok"] is False and "unknown tool" in payload["error"]


def test_unparseable_arguments_are_counted():
    bad = ChatResponse(
        content=None,
        tool_calls=[
            ToolCall(id="c", name="lookup_user", arguments={}, raw_arguments="{bad", parse_error="invalid JSON")
        ],
    )
    res = run_agent(ScriptedModel([bad, answer("ok")]), "who is jordan?")
    assert res.malformed_tool_calls == 1
    assert res.tool_calls[0].ok is False


def test_not_found_is_not_malformed():
    res = run_agent(ScriptedModel([tool_call("fetch_ticket", ticket_id="HD-404"), answer("not found")]), "x")
    assert res.malformed_tool_calls == 0 and res.tool_calls[0].ok is False


def test_multiple_tool_calls_in_one_turn():
    both = ChatResponse(
        content=None,
        tool_calls=[
            ToolCall(id="a", name="fetch_ticket", arguments={"ticket_id": "HD-2001"}),
            ToolCall(id="b", name="lookup_user", arguments={"email": "jordan.lee@fabrikam.example"}),
        ],
    )
    model = ScriptedModel([both, answer("checked")])
    res = run_agent(model, "check HD-2001")
    assert [c.name for c in res.tool_calls] == ["fetch_ticket", "lookup_user"]
    assert [m["tool_call_id"] for m in model.requests[1]["messages"] if m["role"] == "tool"] == ["a", "b"]


def test_side_effects_visible_after_run():
    env = ToolEnv()
    model = ScriptedModel(
        [
            tool_call("reset_mfa", email="jordan.lee@fabrikam.example", ticket_id="HD-2001"),
            tool_call("send_email", to="jordan.lee@fabrikam.example", subject="MFA reset", body="Re-enroll"),
            answer("Done."),
        ]
    )
    res = run_agent(model, "reset", env=env)
    assert res.turns == 3
    assert env.mfa_resets[0]["ticket_id"] == "HD-2001"
    assert env.outbox[0]["subject"] == "MFA reset"


def test_max_turns_stops_loop():
    model = ScriptedModel([tool_call("lookup_asset", asset_id="LT-3001") for _ in range(5)])
    res = run_agent(model, "loop", max_turns=3)
    assert res.stop_reason == "max_turns" and res.turns == 3 and len(res.tool_calls) == 3


def test_model_error_is_reported():
    class Broken:
        def chat(self, *a, **k):
            raise ModelError("endpoint down")

        def info(self):
            return {}

    res = run_agent(Broken(), "x")
    assert res.stop_reason == "model_error" and "endpoint down" in res.error


def test_result_serializes():
    res = run_agent(ScriptedModel([answer("hello")]), "hi")
    d = json.loads(json.dumps(res.to_dict()))
    assert d["final_text"] == "hello" and d["tool_calls"] == []


def test_history_goes_between_system_and_user():
    history = [{"role": "user", "content": "earlier"}, {"role": "assistant", "content": "noted"}]
    model = ScriptedModel([answer("ok")])
    run_agent(model, "now", history=history)
    msgs = model.requests[0]["messages"]
    assert [m["role"] for m in msgs] == ["system", "user", "assistant", "user"]
    assert msgs[1]["content"] == "earlier" and msgs[2]["content"] == "noted" and msgs[3]["content"] == "now"
