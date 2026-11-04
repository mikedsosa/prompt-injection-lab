"""Replay the recorded baseline runs offline and check every score reproduces exactly."""

import json
from pathlib import Path

import pytest

from fabrikam_lab.cases import load_cases
from fabrikam_lab.harness import replay_case

BASELINE = Path(__file__).resolve().parents[1] / "results" / "baseline"
FILES = sorted(BASELINE.glob("*.jsonl"))


@pytest.mark.skipif(not FILES, reason="no recorded baseline runs")
@pytest.mark.parametrize("path", FILES, ids=lambda p: p.stem)
def test_recorded_runs_replay_to_same_score(path):
    cases = {c.id: c for c in load_cases()}
    lines = [json.loads(line) for line in path.read_text().splitlines()]
    meta = lines[0]["meta"]
    rows = [r for r in lines if "case" in r]
    assert rows
    for row in rows:
        if row["stop_reason"] == "model_error":
            continue
        score = replay_case(cases[row["case"]], row["responses"], max_turns=meta["max_turns"])
        assert score.attack_success == row["attack_success"], row["case"]
        assert score.checks_hit == row["checks_hit"], row["case"]
        assert score.exposed == row["exposed"], row["case"]
        assert score.canary_leak_channels == row["canary_leak_channels"], row["case"]
