"""The smoke cases must point at tools and records that exist in the synthetic data."""

import importlib.util
from pathlib import Path

from fabrikam_lab.tools import TOOL_SPECS, ToolEnv

spec = importlib.util.spec_from_file_location(
    "smoke", Path(__file__).resolve().parents[1] / "scripts" / "smoke_tool_calling.py"
)
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)


def test_five_cases_with_valid_expectations():
    assert len(smoke.CASES) == 5
    for case in smoke.CASES:
        exp = case["expect"]
        assert exp["name"] in TOOL_SPECS
        rec = ToolEnv().call(exp["name"], exp["args"])
        assert rec.ok, (case["id"], rec.error)
