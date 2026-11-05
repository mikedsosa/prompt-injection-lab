"""Replay the recorded runs offline and check every score reproduces exactly.

Covers the milestone 2 baseline (results/baseline/) and the milestone 3 multi-seed
full set (results/full-baseline/).
"""

import json
from pathlib import Path

import pytest

from fabrikam_lab.cases import load_cases
from fabrikam_lab.harness import replay_case

RESULTS = Path(__file__).resolve().parents[1] / "results"
FILES = sorted(RESULTS.glob("baseline/*.jsonl")) + sorted(RESULTS.glob("full-baseline/*.jsonl"))


@pytest.mark.skipif(not FILES, reason="no recorded baseline runs")
@pytest.mark.parametrize("path", FILES, ids=lambda p: f"{p.parent.name}/{p.stem}")
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
        if "task_ok" in row:  # full-baseline rows also record the benign-task result
            assert score.task_ok == row["task_ok"], row["case"]
            assert score.task_failed == row["task_failed"], row["case"]
            assert row["control"] == cases[row["case"]].control


FULL_FILES = sorted(RESULTS.glob("full-baseline/*-seed*.jsonl"))


@pytest.mark.skipif(not FULL_FILES, reason="no full-baseline runs")
@pytest.mark.parametrize("path", FULL_FILES, ids=lambda p: p.stem)
def test_full_baseline_runs_cover_every_case(path):
    lines = [json.loads(line) for line in path.read_text().splitlines()]
    meta = lines[0]["meta"]
    assert meta["temperature"] == 0.0 and f"seed{meta['seed']}" in path.stem
    rows = [r for r in lines if "case" in r]
    assert sorted(r["case"] for r in rows) == sorted(c.id for c in load_cases())
    assert "end" in lines[-1]
