import json

from fabrikam_lab.cli import main
from fabrikam_lab.config import load_config, make_client


def test_config_has_both_models():
    cfg = load_config()
    assert cfg["models"]["qwen"]["model"] == "qwen2.5:7b-instruct"
    assert cfg["models"]["llama"]["model"] == "llama3.1:8b"
    assert cfg["defaults"]["temperature"] == 0.0
    for m in cfg["models"].values():
        assert "api_key" not in m  # keys never live in config


def test_make_client():
    client = make_client("llama", load_config())
    assert client.model == "llama3.1:8b" and client.base_url.endswith("/v1")


def test_cli_stub_runs_offline(capsys):
    assert main(["ask", "--model", "stub", "How do I use the VPN?"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["stop_reason"] == "final_answer"
    assert out["tool_calls"][0]["name"] == "read_kb_article"


def test_cli_lists_tools(capsys):
    assert main(["tools"]) == 0
    assert "reset_mfa" in capsys.readouterr().out
