"""Run the injection cases against one local model and record every run.

    python scripts/run_cases.py --model qwen            # all cases
    python scripts/run_cases.py --model llama --cases PI-001 PI-007
    python scripts/run_cases.py --model qwen --seeds 1 2 3 --out-dir results/full-baseline

Without --seeds, writes results/baseline/<model>.jsonl with the config seed (milestone 2
layout). With --seeds, writes <out-dir>/<model>-seed<N>.jsonl, one file per seed.
Each file has a meta line (model tag and digest, Ollama
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


def run_one(args, client, cases, seed, temperature, out_path: Path) -> None:
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
    prefix: list[dict] = []
    if args.resume and out_path.exists():
        old = [json.loads(line) for line in out_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        done = [r for r in old if "case" in r]
        old_meta = old[0]["meta"]
        for k in ("model", "model_digest", "temperature", "seed", "max_turns"):
            if old_meta.get(k) != meta.get(k):
                raise SystemExit(f"cannot resume {out_path.name}: {k} differs ({old_meta.get(k)!r} vs {meta.get(k)!r})")
        old_meta.setdefault("resumed", []).append(
            {"started_utc": meta["started_utc"], "kept_cases": [r["case"] for r in done]}
        )
        prefix = [{"meta": old_meta}] + [d for d in old if "server" in d] + done
        rows = list(done)
    done_ids = {r["case"] for r in rows}
    with out_path.open("w", encoding="utf-8") as fh:
        for d in prefix or [{"meta": meta}]:
            fh.write(json.dumps(d) + "\n")
        fh.flush()
        wrote_server = any("server" in d for d in prefix)
        for case in cases:
            if case.id in done_ids:
                continue
            res, score, responses, usage = run_case(
                client, case, max_turns=args.max_turns, temperature=temperature, seed=seed
            )
            if not wrote_server:
                fh.write(json.dumps({"server": {"ollama_ps": ollama_ps(client.base_url)}}) + "\n")
                wrote_server = True
            row = {
                "case": case.id,
                "vector": case.vector,
                "goal": case.goal,
                "technique_family": case.technique_family,
                "control": case.control,
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
                json.dumps(
                    {k: row[k] for k in ("case", "attack_success", "exposed", "task_ok", "stop_reason", "wall_s")}
                    | {"seed": seed}
                ),
                flush=True,
            )
        end = {"total_wall_s": round(time.monotonic() - t0, 1)}
        if prefix:
            end["note"] = (
                "resumed run: total_wall_s sums per-case wall_s; "
                "resumed_part_wall_s is the clock time of the resumed part"
            )
            end["resumed_part_wall_s"] = end["total_wall_s"]
            end["total_wall_s"] = round(sum(r["wall_s"] for r in rows), 1)
        fh.write(json.dumps({"end": end}) + "\n")
    attacks = [r for r in rows if not r["control"]]
    print(
        json.dumps(
            {
                "model": args.model,
                "seed": seed,
                "attack_success": f"{sum(r['attack_success'] for r in attacks)}/{len(attacks)}",
                "total_wall_s": round(time.monotonic() - t0, 1),
                "file": str(out_path.resolve().relative_to(ROOT)),
            }
        ),
        flush=True,
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True, help="key in config/models.toml")
    ap.add_argument("--cases", nargs="*", help="case ids (default: all)")
    ap.add_argument("--max-turns", type=int, default=DEFAULT_CASE_MAX_TURNS)
    ap.add_argument("--out", default=None, help="output path (default results/baseline/<model>.jsonl)")
    ap.add_argument("--seeds", nargs="*", type=int, help="run the whole set once per seed")
    ap.add_argument(
        "--resume",
        action="store_true",
        help="keep finished case rows already in the output file and run only the rest",
    )
    ap.add_argument("--out-dir", default=str(ROOT / "results" / "full-baseline"), help="directory for --seeds runs")
    args = ap.parse_args()

    cfg = load_config()
    client = make_client(args.model, cfg)
    temperature = cfg["defaults"].get("temperature", 0.0)
    cases = load_cases(ids=args.cases)
    if args.seeds:
        out_dir = Path(args.out_dir)
        jobs = [(seed, out_dir / f"{args.model}-seed{seed}.jsonl") for seed in args.seeds]
    else:
        out_path = Path(args.out) if args.out else ROOT / "results" / "baseline" / f"{args.model}.jsonl"
        jobs = [(cfg["defaults"].get("seed"), out_path)]
    for seed, out_path in jobs:
        run_one(args, client, cases, seed, temperature, out_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
