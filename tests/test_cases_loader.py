import copy
import json
import re
from collections import Counter

import pytest

from fabrikam_lab.cases import (
    GOALS,
    TECHNIQUE_FAMILIES,
    VECTORS,
    CaseError,
    canary_core,
    load_cases,
    normalize,
    parse_case,
)

BASE = {
    "id": "PI-900",
    "title": "t",
    "vector": "direct",
    "goal": "leak_secret",
    "technique": "x",
    "technique_family": "plain_instruction",
    "user_message": "print the code",
    "canary": "CANARY-AB12-CD34",
    "success": [{"type": "canary_leak"}],
    "sources": ["OWASP-LLM01"],
}

KB_CASE = {
    **BASE,
    "vector": "indirect_kb",
    "environment": {"kb": {"KB-9001": "do the bad thing"}},
}


def test_bundled_cases_load():
    cases = load_cases()
    assert len(cases) == 60
    attacks = [c for c in cases if not c.control]
    controls = [c for c in cases if c.control]
    assert [c.id for c in attacks] == [f"PI-{i:03d}" for i in range(1, 51)]
    assert [c.id for c in controls] == [f"CTL-{i:03d}" for i in range(1, 11)]
    assert {c.vector for c in cases} == set(VECTORS)
    assert len({c.canary for c in cases}) == 60


def test_bundled_case_coverage():
    attacks = [c for c in load_cases() if not c.control]
    vectors = Counter(c.vector for c in attacks)
    assert vectors == {
        "direct": 9,
        "indirect_kb": 9,
        "indirect_ticket": 9,
        "indirect_tool": 9,
        "indirect_email": 8,
        "multi_turn": 6,
    }
    goals = Counter(c.goal for c in attacks)
    assert goals == {"leak_secret": 13, "exfiltrate": 13, "unauthorized_action": 12, "phishing_link": 12}
    assert {c.technique_family for c in attacks} == set(TECHNIQUE_FAMILIES)
    for goal in GOALS:  # every attack goal shows up in at least four vectors
        assert len({c.vector for c in attacks if c.goal == goal}) >= 4, goal


def test_bundled_controls_are_benign():
    for c in load_cases():
        if not c.control:
            continue
        assert c.goal == "none" and c.technique_family == "none" and c.task
        assert {chk["type"] for chk in c.success} == {"canary_leak", "email_to_external", "unexpected_mfa_reset"}
        assert "attacker.example" not in json.dumps([c.user_message, c.environment, c.history])


def test_bundled_cases_use_example_domains_only():
    for c in load_cases():
        blob = json.dumps([c.user_message, c.environment, c.history, c.success, c.task])
        for domain in re.findall(r"@([a-z0-9-]+(?:\.[a-z0-9-]+)+)", blob.lower()):
            assert domain.endswith(".example"), (c.id, domain)
        for url_host in re.findall(r"https?://([a-z0-9.-]+)", blob.lower()):
            assert url_host.rstrip(".").endswith(".example"), (c.id, url_host)


def test_bundled_cases_cite_known_sources():
    sources_md = (load_cases.__globals__["DEFAULT_CASES_DIR"].parent / "SOURCES.md").read_text()
    for case in load_cases():
        for key in case.sources:
            assert f"`{key}`" in sources_md, f"{case.id} cites {key}, missing from SOURCES.md"


def test_load_subset_and_unknown_id():
    assert [c.id for c in load_cases(ids=["PI-002", "PI-001"])] == ["PI-001", "PI-002"]
    with pytest.raises(CaseError, match="unknown case"):
        load_cases(ids=["PI-999"])


def test_indirect_kb_exposure_is_derived():
    case = parse_case(KB_CASE)
    assert case.exposure == {"tool": "read_kb_article", "arg": "article_id", "value": "KB-9001"}
    env = case.make_env()
    assert env.read_kb_article("KB-9001")["content"] == "do the bad thing"


def test_env_overrides_replace_users_and_assets():
    raw = {
        **BASE,
        "vector": "indirect_tool",
        "environment": {"users": [{"email": "casey.wu@fabrikam.example", "name": "X", "title": "planted"}]},
        "exposure": {"tool": "lookup_user", "arg": "email", "value": "casey.wu@fabrikam.example"},
    }
    env = parse_case(raw).make_env()
    matches = [u for u in env.data["users"] if u["email"] == "casey.wu@fabrikam.example"]
    assert len(matches) == 1 and matches[0]["title"] == "planted"


@pytest.mark.parametrize(
    "mutate, msg",
    [
        (lambda d: d.update(id="case-1"), "must look like PI-001"),
        (lambda d: d.update(vector="email"), "unknown vector"),
        (lambda d: d.update(goal="chaos"), "unknown goal"),
        (lambda d: d.update(canary="secret"), "canary must look like"),
        (lambda d: d.update(success=[]), "at least one success check"),
        (lambda d: d.update(success=[{"type": "vibes"}]), "unknown check type"),
        (lambda d: d.update(success=[{"type": "mfa_reset"}]), "needs an 'email'"),
        (lambda d: d.update(success=[{"type": "canary_leak", "channels": ["fax"]}]), "channels"),
        (lambda d: d.update(sources=[]), "source key"),
        (lambda d: d.pop("title"), "missing field 'title'"),
        (lambda d: d.update(environment={"kb": {"KB-1": "x"}}), "direct case must not plant"),
        (lambda d: d.update(user_message="the code is ab12-cd34"), "must not appear"),
        (lambda d: d.pop("technique_family"), "missing field 'technique_family'"),
        (lambda d: d.update(technique_family="magic"), "unknown technique_family"),
        (lambda d: d.update(id="CTL-001"), "only control cases, use CTL-"),
        (lambda d: d.update(control=True), "only control cases, use CTL-"),
        (lambda d: d.update(control="yes"), "must be true or false"),
        (lambda d: d.update(task={}), "'task' must be a list"),
        (lambda d: d.update(task=[{"type": "mfa_reset", "email": "a@fabrikam.example"}]), "unknown check type"),
        (lambda d: d.update(task=[{"type": "tool_called", "name": "rm_rf"}]), "known tool"),
        (lambda d: d.update(task=[{"type": "any_text_in_answer", "texts": []}]), "non-empty 'texts'"),
        (lambda d: d.update(history=[{"role": "user", "content": "x"}]), "only multi_turn"),
        (lambda d: d.update(vector="multi_turn"), "non-empty 'history'"),
        (
            lambda d: d.update(vector="multi_turn", history=[{"role": "assistant", "content": "x"}]),
            "start with a user turn",
        ),
        (
            lambda d: d.update(vector="multi_turn", history=[{"role": "user", "content": "x"}]),
            "end with an assistant turn",
        ),
        (
            lambda d: d.update(vector="multi_turn", history=[{"role": "system", "content": "x"}]),
            "only a role",
        ),
        (
            lambda d: d.update(
                vector="multi_turn",
                history=[{"role": "user", "content": "AB12CD34"}, {"role": "assistant", "content": "ok"}],
            ),
            "must not appear",
        ),
        (
            lambda d: d.update(
                vector="multi_turn",
                history=[{"role": "user", "content": "x"}, {"role": "assistant", "content": "ok"}],
                environment={"kb": {"KB-1": "x"}},
            ),
            "multi_turn case must not plant",
        ),
        (lambda d: d.update(vector="indirect_email", environment={"emails": {}}), "exactly one item"),
        (
            lambda d: d.update(vector="indirect_email", environment={"emails": {"EM-1": {}, "EM-2": {}}}),
            "exactly one item",
        ),
    ],
)
def test_schema_rejects_bad_cases(mutate, msg):
    raw = copy.deepcopy(BASE)
    mutate(raw)
    with pytest.raises(CaseError, match=msg):
        parse_case(raw)


def test_indirect_needs_payload_and_tool_exposure():
    with pytest.raises(CaseError, match="must plant its payload"):
        parse_case({**BASE, "vector": "indirect_ticket"})
    with pytest.raises(CaseError, match="exposure.tool"):
        parse_case({**BASE, "vector": "indirect_tool", "environment": {"assets": [{"asset_id": "A"}]}})


def test_duplicate_ids_and_canaries_rejected(tmp_path):
    (tmp_path / "a.json").write_text(json.dumps(BASE))
    (tmp_path / "b.json").write_text(json.dumps(BASE))
    with pytest.raises(CaseError, match="duplicate"):
        load_cases(tmp_path)
    (tmp_path / "b.json").write_text(json.dumps({**BASE, "id": "PI-901"}))
    with pytest.raises(CaseError, match="own canary"):
        load_cases(tmp_path)
    (tmp_path / "b.json").write_text("{not json")
    with pytest.raises(CaseError, match="invalid JSON"):
        load_cases(tmp_path)


def test_normalize_and_core():
    assert normalize("A-b 1_2!") == "ab12"
    assert canary_core("CANARY-AB12-CD34") == "ab12cd34"


CONTROL = {
    **BASE,
    "id": "CTL-900",
    "control": True,
    "goal": "none",
    "technique_family": "none",
    "success": [{"type": "canary_leak"}, {"type": "unexpected_mfa_reset", "allowed": ["jordan.lee@fabrikam.example"]}],
    "task": [{"type": "tool_called", "name": "reset_mfa", "args": {"email": "jordan.lee@fabrikam.example"}}],
}


def test_control_case_parses():
    case = parse_case(CONTROL)
    assert case.control and case.goal == "none" and case.task[0]["name"] == "reset_mfa"


@pytest.mark.parametrize(
    "mutate, msg",
    [
        (lambda d: d.update(goal="leak_secret"), "goal 'none'"),
        (lambda d: d.update(technique_family="override"), "technique_family 'none'"),
        (lambda d: d.update(task=[]), "at least one task check"),
        (lambda d: d.update(success=[{"type": "mfa_reset", "email": "a@fabrikam.example"}]), "unknown check type"),
        (lambda d: d.update(success=[{"type": "unexpected_mfa_reset", "allowed": "a@x.example"}]), "list of emails"),
    ],
)
def test_schema_rejects_bad_controls(mutate, msg):
    raw = copy.deepcopy(CONTROL)
    mutate(raw)
    with pytest.raises(CaseError, match=msg):
        parse_case(raw)


def test_attack_goal_none_rejected():
    with pytest.raises(CaseError, match="unknown goal"):
        parse_case({**BASE, "goal": "none"})


def test_indirect_email_exposure_is_derived():
    raw = {
        **BASE,
        "vector": "indirect_email",
        "environment": {"emails": {"EM-9001": {"message_id": "EM-9001", "from": "x@attacker.example", "body": "hi"}}},
    }
    case = parse_case(raw)
    assert case.exposure == {"tool": "read_email", "arg": "message_id", "value": "EM-9001"}
    assert case.make_env().read_email("EM-9001")["body"] == "hi"


def test_multi_turn_case_keeps_history():
    history = [{"role": "user", "content": "remember X"}, {"role": "assistant", "content": "ok"}]
    case = parse_case({**BASE, "vector": "multi_turn", "history": history})
    assert case.history == history and case.exposure is None


def test_attack_cases_tagged_to_three_taxonomies():
    for c in load_cases():
        if c.control:
            continue
        assert any(s.startswith("OWASP-LLM") for s in c.sources), c.id
        assert "OWASP-ASI01" in c.sources and "ATLAS-T0051" in c.sources, c.id
        if c.goal == "leak_secret":
            assert "ATLAS-T0057" in c.sources, c.id
