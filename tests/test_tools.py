import pytest

from fabrikam_lab.tools import TOOL_SPECS, ToolEnv, default_data, openai_tools


def test_synthetic_data_uses_reserved_domain_only():
    data = default_data()
    emails = [u["email"] for u in data["users"]] + [t["requester"] for t in data["tickets"].values()]
    assert emails and all(e.endswith("@fabrikam.example") for e in emails)


def test_bundled_data_loaded():
    data = default_data()
    assert {"KB-1001", "KB-1002", "KB-1003", "KB-1004"} <= set(data["kb"])
    assert {"HD-2001", "HD-2002", "HD-2003"} <= set(data["tickets"])


def test_tool_specs_are_well_formed():
    tools = openai_tools()
    assert len(tools) == len(TOOL_SPECS) == 7
    for t in tools:
        assert t["type"] == "function"
        params = t["function"]["parameters"]
        assert set(params["required"]) <= set(params["properties"])


def test_read_kb_and_fetch_ticket():
    env = ToolEnv()
    rec = env.call("read_kb_article", {"article_id": "KB-1002"})
    assert rec.ok and "MFA reset policy" in rec.result["content"]
    rec = env.call("fetch_ticket", {"ticket_id": "HD-2001"})
    assert rec.ok and rec.result["verified"] is True


def test_lookup_user_case_insensitive_and_asset():
    env = ToolEnv()
    assert env.call("lookup_user", {"email": "Jordan.Lee@Fabrikam.example"}).result["employee_id"] == "FAB-1001"
    assert env.call("lookup_asset", {"asset_id": "lt-3002"}).result["compliant"] is False


@pytest.mark.parametrize(
    ("name", "args", "fragment"),
    [
        ("read_kb_article", {"article_id": "KB-9999"}, "not found"),
        ("fetch_ticket", {"ticket_id": "HD-0"}, "not found"),
        ("lookup_user", {"email": "nobody@fabrikam.example"}, "not found"),
        ("nonexistent_tool", {}, "unknown tool"),
        ("reset_mfa", {"email": "jordan.lee@fabrikam.example"}, "missing argument"),
        ("fetch_ticket", {"ticket_id": "HD-2001", "extra": "x"}, "unexpected argument"),
        ("fetch_ticket", {"ticket_id": 2001}, "must be strings"),
    ],
)
def test_errors_are_recorded_not_raised(name, args, fragment):
    env = ToolEnv()
    rec = env.call(name, args)
    assert not rec.ok and fragment in rec.error
    assert env.calls[-1] is rec


def test_side_effects_go_to_mock_logs():
    env = ToolEnv()
    env.call("reset_mfa", {"email": "jordan.lee@fabrikam.example", "ticket_id": "HD-2001"})
    env.call("send_email", {"to": "sam.ortiz@fabrikam.example", "subject": "hi", "body": "test"})
    assert env.mfa_resets == [{"email": "jordan.lee@fabrikam.example", "ticket_id": "HD-2001"}]
    assert env.outbox[0]["to"] == "sam.ortiz@fabrikam.example"


def test_baseline_tools_do_not_enforce_policy():
    # Undefended baseline: an unverified ticket still "works". Enforcement is a later project.
    env = ToolEnv()
    rec = env.call("reset_mfa", {"email": "casey.wu@fabrikam.example", "ticket_id": "HD-2003"})
    assert rec.ok and env.mfa_resets


def test_envs_are_isolated():
    a, b = ToolEnv(), ToolEnv()
    a.data["kb"]["KB-1001"] = "changed"
    a.call("send_email", {"to": "x@fabrikam.example", "subject": "s", "body": "b"})
    assert b.data["kb"]["KB-1001"] != "changed" and b.outbox == []
    assert ToolEnv().data["kb"]["KB-1001"] != "changed"


def test_overrides_add_documents():
    env = ToolEnv.with_overrides(
        extra_kb={"KB-7777": "synthetic test doc"}, extra_tickets={"HD-9": {"ticket_id": "HD-9"}}
    )
    assert env.call("read_kb_article", {"article_id": "KB-7777"}).ok
    assert env.call("fetch_ticket", {"ticket_id": "HD-9"}).ok


def test_read_email_and_unknown_message():
    env = ToolEnv()
    rec = env.call("read_email", {"message_id": "EM-6001"})
    assert rec.ok and rec.result["from"].endswith("@fabrikam.example")
    rec = env.call("read_email", {"message_id": "EM-9999"})
    assert not rec.ok and "not found" in rec.error


def test_bundled_mailbox_uses_reserved_domain():
    data = default_data()
    assert {"EM-6001", "EM-6002"} <= set(data["emails"])
    for m in data["emails"].values():
        assert m["from"].endswith("@fabrikam.example") and m["to"].endswith("@fabrikam.example")


def test_email_override_adds_message():
    env = ToolEnv.with_overrides(extra_emails={"EM-9001": {"message_id": "EM-9001", "body": "x"}})
    assert env.read_email("EM-9001")["body"] == "x"
    assert "EM-6001" in env.data["emails"]
