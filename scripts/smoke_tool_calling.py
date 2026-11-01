"""Five-case tool-calling smoke test for one local model.

Checks that a model can drive the agent loop at all before it is used for the real
matrix: does it call tools, are the calls well-formed, does it pick the expected
tool and arguments, and does it finish with an answer. This is NOT an attack test
and its numbers are not lab results.

    python scripts/smoke_tool_calling.py --model llama

Writes one JSON line per case to results/smoke/<model>-<UTC timestamp>.jsonl and
prints a summary. Requires a running local model server; CI never runs this.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import platform
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from fabrikam_lab.agent import run_agent  # noqa: E402
from fabrikam_lab.config import load_config, make_client  # noqa: E402
from fabrikam_lab.tools import ToolEnv  # noqa: E402

CASES = [
    {
        "id": "smoke-1-kb",
        "message": "What does KB-1001 say about connecting to the VPN?",
        "expect": {"name": "read_kb_article", "args": {"article_id": "KB-1001"}},
    },
    {
        "id": "smoke-2-user",
        "message": "Who is the manager of priya.natarajan@fabrikam.example?",
        "expect": {"name": "lookup_user", "args": {"email": "priya.natarajan@fabrikam.example"}},
    },
    {
        "id": "smoke-3-ticket",
        "message": "Can you summarize helpdesk ticket HD-2002 for me?",
        "expect": {"name": "fetch_ticket", "args": {"ticket_id": "HD-2002"}},
    },
    {
        "id": "smoke-4-asset",
        "message": "Is laptop LT-3002 compliant?",
        "expect": {"name": "lookup_asset", "args": {"asset_id": "LT-3002"}},
    },
    {
        "id": "smoke-5-mfa",
        "message": "Please reset MFA for jordan.lee@fabrikam.example. The ticket is HD-2001.",
        "expect": {"name": "reset_mfa", "args": {"email": "jordan.lee@fabrikam.example", "ticket_id": "HD-2001"}},
    },
]


def matches(call, expect) -> bool:
    return call.name == expect["name"] and all(
        str(call.arguments.get(k, "")).lower() == v.lower() for k, v in expect["args"].items()
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True, help="key in config/models.toml")
    ap.add_argument("--max-turns", type=int, default=5)
    args = ap.parse_args()

    cfg = load_config()
    client = make_client(args.model, cfg)
    seed = cfg["defaults"].get("seed")
    temperature = cfg["defaults"].get("temperature", 0.0)
    meta = {
        "model_key": args.model,
        **client.info(),
        **client.ollama_metadata(),
        "temperature": temperature,
        "seed": seed,
        "python": platform.python_version(),
        "started_utc": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
    }
    out_dir = ROOT / "results" / "smoke"
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
    out_path = out_dir / f"{args.model}-{stamp}.jsonl"

    rows = []
    with out_path.open("w", encoding="utf-8") as fh:
        fh.write(json.dumps({"meta": meta}) + "\n")
        for case in CASES:
            env = ToolEnv()
            res = run_agent(
                client, case["message"], env=env, max_turns=args.max_turns, temperature=temperature, seed=seed
            )
            row = {
                "case": case["id"],
                "made_tool_call": bool(res.tool_calls),
                "all_calls_well_formed": res.malformed_tool_calls == 0,
                "expected_call_made": any(matches(c, case["expect"]) for c in res.tool_calls),
                "finished_with_answer": res.stop_reason == "final_answer" and bool((res.final_text or "").strip()),
                "stop_reason": res.stop_reason,
                "turns": res.turns,
                "calls": [{"name": c.name, "arguments": c.arguments, "ok": c.ok} for c in res.tool_calls],
                "malformed_tool_calls": res.malformed_tool_calls,
                "final_text": (res.final_text or "")[:500],
                "error": res.error,
                "wall_s": res.wall_s,
                "model_latencies_s": res.model_latencies_s,
            }
            rows.append(row)
            fh.write(json.dumps(row) + "\n")
            fh.flush()
            print(
                json.dumps(
                    {
                        k: row[k]
                        for k in (
                            "case",
                            "expected_call_made",
                            "all_calls_well_formed",
                            "finished_with_answer",
                            "wall_s",
                        )
                    }
                )
            )

    n = len(rows)
    summary = {
        k: f"{sum(r[k] for r in rows)}/{n}"
        for k in ("made_tool_call", "all_calls_well_formed", "expected_call_made", "finished_with_answer")
    }
    summary["total_wall_s"] = round(sum(r["wall_s"] for r in rows), 1)
    print(json.dumps({"summary": summary, "file": str(out_path.relative_to(ROOT))}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
