"""Build the output-filter-only runs offline from the recorded baseline (milestone 4).

    python scripts/derive_output_filter.py

The output filter runs after the agent loop and never changes what the model sees, so
running it live would send the model exactly the same requests as the baseline. Instead,
this replays each recorded baseline seed 1 run (results/full-baseline/<model>-seed1.jsonl)
with the filter switched on and writes results/defenses/<model>-output_filter-seed1.jsonl.
No model is called. The meta line says the file was derived offline and from which file.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from fabrikam_lab.cases import load_cases  # noqa: E402
from fabrikam_lab.defenses import CONFIGS  # noqa: E402
from fabrikam_lab.harness import replay_run  # noqa: E402

SRC = ROOT / "results" / "full-baseline"
OUT = ROOT / "results" / "defenses"
SEED = 1


def derive(src: Path, out: Path) -> dict:
    cases = {c.id: c for c in load_cases()}
    lines = [json.loads(line) for line in src.read_text(encoding="utf-8").splitlines() if line.strip()]
    meta = dict(lines[0]["meta"])
    meta.update(
        {
            "defense": "output_filter",
            "defense_flags": CONFIGS["output_filter"].to_dict(),
            "max_tokens": None,
            "derived_offline_from": str(src.relative_to(ROOT)),
            "system_prompt": "baseline (undefended) + per-case canary line; output filter applied offline",
        }
    )
    written = [{"meta": meta}]
    n_changed = 0
    for d in lines[1:]:
        if "case" not in d:
            written.append(d)
            continue
        res, score = replay_run(
            cases[d["case"]], d["responses"], max_turns=meta["max_turns"], defense=CONFIGS["output_filter"]
        )
        row = dict(d)
        row.update(score.to_dict())
        row["final_text"] = res.final_text
        n_changed += row["attack_success"] != d["attack_success"]
        written.append(row)
    out.write_text("".join(json.dumps(x) + "\n" for x in written), encoding="utf-8")
    return {"file": str(out.relative_to(ROOT)), "rows": sum("case" in x for x in written), "outcome_changed": n_changed}


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    for src in sorted(SRC.glob(f"*-seed{SEED}.jsonl")):
        model = src.name.removesuffix(f"-seed{SEED}.jsonl")
        print(json.dumps(derive(src, OUT / f"{model}-output_filter-seed{SEED}.jsonl")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
