"""Run the injection cases against one local model and record every run.

    python scripts/run_cases.py --model qwen            # all cases
    python scripts/run_cases.py --model llama --cases PI-001 PI-007

Writes results/baseline/<model>.jsonl: a meta line (model tag and digest, Ollama
version, server context length, temperature, seed), then one line per case with the
score and the recorded model responses, so CI can replay and re-score the run offline.
Needs a running local Ollama server; CI never runs this. Load one model at a time.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import platform
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from fabrikam_lab.cases import load_cases  # noqa: E402
from fabrikam_lab.config import load_config, make_client  # noqa: E402
from fabrikam_lab.harness import DEFAULT_CASE_MAX_TURNS, run_case  # noqa: E402


def ollama_ps(base_url: str) -> list[dict]:
    root = base_url.rstrip("/").removesuffix("/v1")
    try:
        with urllib.request.urlopen(f"{root}/api/ps", timeout=10) as r:
            return json.loads(r.read()).get("models", [])
    except Exception as exc:  # best effort, recorded only
        return [{"error": str(exc)}]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True, help="key in config/models.toml")
    ap.add_argument("--cases", nargs="*", help="case ids (default: all)")
    ap.add_argument("--max-turns", type=int, default=DEFAULT_CASE_MAX_TURNS)
    ap.add_argument("--out", default=None, help="output path (default results/baseline/<model>.jsonl)")
    args = ap.parse_args()

    cfg = load_config()
    client = make_client(args.model, cfg)
    seed = cfg["defaults"].get("seed")
    temperature = cfg["defaults"].get("temperature", 0.0)
    cases = load_cases(ids=args.cases)
    out_path = Path(args.out) if args.out else ROOT / "results" / "baseline" / f"{args.model}.jsonl"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    meta = {
        "model_key": args.model,
        **client.info(),
        **client.ollama_metadata(),
        "temperature": temperature,
        "seed": seed,
        "max_turns": args.max_turns,
        "system_prompt": "baseline (undefended) + per-case canary line",
        "n_cases": len(cases),
        "python": platform.python_version(),
        "started_utc": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
    }
    t0 = time.monotonic()
    rows = []
    with out_path.open("w", encoding="utf-8") as fh:
        fh.write(json.dumps({"meta": meta}) + "\n")
        for i, case in enumerate(cases):
            res, score, responses, usage = run_case(
                client, case, max_turns=args.max_turns, temperature=temperature, seed=seed
            )
            if i == 0:
                fh.write(json.dumps({"server": {"ollama_ps": ollama_ps(client.base_url)}}) + "\n")
            row = {
                "case": case.id,
                "vector": case.vector,
                "goal": case.goal,
                **score.to_dict(),
                "stop_reason": res.stop_reason,
                "turns": res.turns,
                "malformed_tool_calls": res.malformed_tool_calls,
                "calls": [{"name": c.name, "arguments": c.arguments, "ok": c.ok} for c in res.tool_calls],
                "final_text": res.final_text,
                "error": res.error,
                "wall_s": res.wall_s,
                "prompt_tokens": [u.get("prompt_tokens") for u in usage],
                "responses": responses,
            }
            rows.append(row)
            fh.write(json.dumps(row) + "\n")
            fh.flush()
            print(
                json.dumps({k: row[k] for k in ("case", "attack_success", "exposed", "stop_reason", "wall_s")}),
                flush=True,
            )
        fh.write(json.dumps({"end": {"total_wall_s": round(time.monotonic() - t0, 1)}}) + "\n")
    n = len(rows)
    print(
        json.dumps(
            {
                "model": args.model,
                "attack_success": f"{sum(r['attack_success'] for r in rows)}/{n}",
                "total_wall_s": round(time.monotonic() - t0, 1),
                "file": str(out_path.relative_to(ROOT)),
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
