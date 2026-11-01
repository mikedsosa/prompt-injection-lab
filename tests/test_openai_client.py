import io
import json
import urllib.request

import pytest

from fabrikam_lab.models.base import ModelError
from fabrikam_lab.models.openai_compat import OpenAICompatClient, parse_chat_completion
from fabrikam_lab.tools import openai_tools


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def completion(message, finish="stop"):
    return {"choices": [{"message": message, "finish_reason": finish}], "usage": {"prompt_tokens": 10}}


@pytest.fixture
def captured(monkeypatch):
    sent = {}

    def fake_urlopen(req, timeout=None):
        sent["url"] = req.full_url
        sent["headers"] = dict(req.header_items())
        sent["body"] = json.loads(req.data.decode()) if req.data else None
        reply = sent.get("reply") or completion({"role": "assistant", "content": "hi"})
        return FakeResponse(json.dumps(reply).encode())

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    return sent


def test_request_shape(captured):
    client = OpenAICompatClient("http://127.0.0.1:11434/v1/", "qwen2.5:7b-instruct")
    resp = client.chat([{"role": "user", "content": "hello"}], openai_tools(), temperature=0.0, seed=3)
    assert captured["url"] == "http://127.0.0.1:11434/v1/chat/completions"
    body = captured["body"]
    assert body["model"] == "qwen2.5:7b-instruct" and body["seed"] == 3 and body["temperature"] == 0.0
    assert body["stream"] is False and len(body["tools"]) == 6
    assert "Authorization" not in captured["headers"]
    assert resp.content == "hi" and resp.latency_s is not None


def test_api_key_only_from_env(captured, monkeypatch):
    monkeypatch.setenv("LAB_TEST_KEY", "dummy-value")
    OpenAICompatClient("http://h/v1", "m", api_key_env="LAB_TEST_KEY").chat([], [])
    assert captured["headers"]["Authorization"] == "Bearer dummy-value"


def test_parse_tool_calls_string_and_dict_arguments():
    raw = completion(
        {
            "role": "assistant",
            "content": "",
            "tool_calls": [
                {
                    "id": "x1",
                    "type": "function",
                    "function": {"name": "fetch_ticket", "arguments": '{"ticket_id": "HD-2001"}'},
                },
                {"type": "function", "function": {"name": "lookup_user", "arguments": {"email": "a@fabrikam.example"}}},
            ],
        },
        finish="tool_calls",
    )
    resp = parse_chat_completion(raw)
    assert [tc.name for tc in resp.tool_calls] == ["fetch_ticket", "lookup_user"]
    assert resp.tool_calls[0].arguments == {"ticket_id": "HD-2001"}
    assert resp.tool_calls[1].id == "call_1" and resp.tool_calls[1].arguments["email"] == "a@fabrikam.example"
    assert resp.finish_reason == "tool_calls"


@pytest.mark.parametrize("bad", ["{not json", "[1, 2]"])
def test_parse_bad_arguments(bad):
    raw = completion({"role": "assistant", "tool_calls": [{"function": {"name": "lookup_user", "arguments": bad}}]})
    tc = parse_chat_completion(raw).tool_calls[0]
    assert tc.parse_error and tc.arguments == {} and tc.raw_arguments == bad


def test_bad_response_shape_raises():
    with pytest.raises(ModelError):
        parse_chat_completion({"error": "nope"})


def test_connection_failure_becomes_model_error():
    # The autouse no-network guard makes any real connection fail.
    client = OpenAICompatClient("http://127.0.0.1:9/v1", "m", timeout_s=1)
    with pytest.raises((ModelError, RuntimeError)):
        client.chat([{"role": "user", "content": "x"}], [])
