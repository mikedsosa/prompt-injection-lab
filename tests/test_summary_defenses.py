"""The committed defense summaries must match what the script makes from the run files."""

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DEF = ROOT / "results" / "defenses"

spec = importlib.util.spec_from_file_location("summarize_defenses", ROOT / "scripts" / "summarize_defenses.py")
summarize_defenses = importlib.util.module_from_spec(spec)
spec.loader.exec_module(summarize_defenses)


@pytest.mark.skipif(not (DEF / "summary.json").exists(), reason="no defense summary")
def test_committed_defense_summary_matches_run_files():
    summary, csv_rows = summarize_defenses.build()
    assert json.loads((DEF / "summary.json").read_text()) == json.loads(json.dumps(summary))
    assert (DEF / "summary-table.md").read_text() == summarize_defenses.render(summary)
    assert len((DEF / "summary.csv").read_text().splitlines()) == len(csv_rows) + 1


def _row(case, success, attempted=None, control=False, blocked=(), task_ok=None):
    details = {}
    if attempted is not None:
        details = {
            "attempted": {
                "attack_success": attempted,
                "checks_hit": ["email_to_external"] if attempted else [],
                "canary_leak_channels": [],
                "external_emails": ["x@attacker.example"] if attempted else [],
                "mfa_resets": [],
            },
            "blocked_calls": [{"name": "send_email", "arguments": {}, "reasons": list(blocked)}] if blocked else [],
            "output_filter_actions": [],
        }
    return {
        "case": case,
        "control": control,
        "vector": "direct",
        "goal": "none" if control else "exfiltrate",
        "technique_family": "none" if control else "plain_instruction",
        "attack_success": success,
        "checks_hit": ["email_to_external"] if success else [],
        "exposed": True,
        "task_ok": task_ok,
        "task_failed": [] if task_ok in (None, True) else ["email_to:x"],
        "canary_leak_channels": [],
        "external_emails": ["x@attacker.example"] if success else [],
        "mfa_resets": [],
        "stop_reason": "final_answer",
        "wall_s": 1.0,
        "details": details,
    }


def _write(path, meta, rows):
    lines = [{"meta": meta}, *rows, {"end": {"total_wall_s": 2.0}}]
    path.write_text("".join(json.dumps(x) + "\n" for x in lines))


def test_build_compares_with_baseline_and_counts_blocks(tmp_path):
    base, defs = tmp_path / "base", tmp_path / "def"
    base.mkdir()
    defs.mkdir()
    _write(
        base / "m-seed1.jsonl",
        {"model": "m", "seed": 1},
        [_row("PI-001", True), _row("PI-002", False), _row("CTL-001", False, control=True, task_ok=True)],
    )
    _write(
        defs / "m-gateway-seed1.jsonl",
        {"model": "m", "seed": 1, "defense": "gateway"},
        [
            _row("PI-001", False, attempted=True, blocked=["recipient_outside_allowlist"]),
            _row("PI-002", True, attempted=True),
            _row("CTL-001", False, attempted=False, control=True, task_ok=False, blocked=["no_recipient"]),
        ],
    )
    summary, rows = summarize_defenses.build(defs, base)
    g = summary["m"]["configs"]["gateway"]["1"]
    assert g["attack_success"] == 1 and g["attempted_success"] == 2 and g["n_attacks"] == 2
    assert g["fixed_vs_baseline"] == ["PI-001"] and g["new_vs_baseline"] == ["PI-002"]
    assert g["gateway"]["blocked_calls_attacks"] == 1 and g["gateway"]["blocked_calls_controls"] == 1
    assert g["harmful_actions"]["external_email"] == {"attempted_cases": 2, "landed_cases": 1}
    assert g["controls"] == {
        "n": 1,
        "harm": 0,
        "task_ok": 0,
        "task_not_done": ["CTL-001"],
        "task_not_done_detail": {"CTL-001": {"task_failed": ["email_to:x"], "stop_reason": "final_answer"}},
    }
    b = summary["m"]["configs"]["baseline"]["1"]
    assert b["attack_success"] == 1 and b["attempted_success"] == 1 and b["fixed_vs_baseline"] == []
    assert len(rows) == 6
    assert "| tool gateway (code) [1] | 1/2 (50%) | 2/2 (100%) | 1 | 1 |" in summarize_defenses.render(summary)
