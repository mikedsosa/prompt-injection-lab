"""Re-score recorded full-baseline runs offline after a scoring-check fix.

    python scripts/rescore_full.py --reason "why the check changed"

Replays every row of results/full-baseline/<model>-seed<N>.jsonl from its recorded model
responses (no model is called), recomputes the score with the current case files, and
rewrites the score fields in place. Any row whose score changed keeps its old values under
"before_rescore", and the meta line gets a "rescored" entry with the time and reason, so
the change is visible in the raw files.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from fabrikam_lab.cases import load_cases  # noqa: E402
from fabrikam_lab.harness import replay_case  # noqa: E402

FULL = ROOT / "results" / "full-baseline"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--reason", required=True)
    args = ap.parse_args()
    cases = {c.id: c for c in load_cases()}
    for path in sorted(FULL.glob("*-seed*.jsonl")):
        lines = [json.loads(line) for line in path.read_text().splitlines()]
        meta = lines[0]["meta"]
        if "end" not in lines[-1]:
            print(f"{path.name}: skipped, run not finished")
            continue
        changed = []
        for row in lines:
            if "case" not in row or row["stop_reason"] == "model_error":
                continue
            new = replay_case(cases[row["case"]], row["responses"], max_turns=meta["max_turns"]).to_dict()
            new.pop("case_id")
            old = {k: row[k] for k in new if row.get(k) != new[k]}
            if old:
                row.setdefault("before_rescore", {}).update(old)
                row.update(new)
                changed.append(row["case"])
        if changed:
            meta.setdefault("rescored", []).append(
                {
                    "utc": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
                    "reason": args.reason,
                    "cases_changed": changed,
                }
            )
            path.write_text("".join(json.dumps(x) + "\n" for x in lines))
        print(f"{path.name}: {len(changed)} row(s) changed {changed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
