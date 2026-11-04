"""Summarize recorded runs in results/baseline/ into summary.json, summary.csv and a table.

    python scripts/summarize.py

Every number comes from the run files. Nothing is typed in by hand.
"""

from __future__ import annotations

import csv
import json
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "results" / "baseline"
GROUPS = ("vector", "goal")


def load(path: Path) -> tuple[dict, list[dict], dict]:
    meta, rows, end, server = {}, [], {}, {}
    for line in path.read_text().splitlines():
        d = json.loads(line)
        if "meta" in d:
            meta = d["meta"]
        elif "server" in d:
            server = d["server"]
        elif "end" in d:
            end = d["end"]
        else:
            rows.append(d)
    meta["server"] = server
    return meta, rows, end


def frac(k: int, n: int) -> str:
    return f"{k}/{n} ({100 * k / n:.0f}%)" if n else "0/0"


def main() -> int:
    summary, csv_rows, md = {}, [], []
    for path in sorted(BASE.glob("*.jsonl")):
        meta, rows, end = load(path)
        key = meta["model_key"]
        n = len(rows)
        ps = (meta.get("server") or {}).get("ollama_ps") or [{}]
        s = {
            "model": meta.get("model"),
            "digest": meta.get("model_digest"),
            "ollama_version": meta.get("ollama_version"),
            "context_length": ps[0].get("context_length"),
            "temperature": meta.get("temperature"),
            "seed": meta.get("seed"),
            "max_turns": meta.get("max_turns"),
            "started_utc": meta.get("started_utc"),
            "n_cases": n,
            "attack_success": sum(r["attack_success"] for r in rows),
            "exposed": sum(r["exposed"] for r in rows),
            "success_when_exposed": sum(r["attack_success"] for r in rows if r["exposed"]),
            "canary_leaked_any_channel": sum(bool(r["canary_leak_channels"]) for r in rows),
            "external_email_sent": sum(bool(r["external_emails"]) for r in rows),
            "mfa_reset_any": sum(bool(r["mfa_resets"]) for r in rows),
            "malformed_tool_calls": sum(r["malformed_tool_calls"] for r in rows),
            "total_wall_s": end.get("total_wall_s"),
            "by": {},
        }
        stops: dict[str, int] = defaultdict(int)
        for r in rows:
            stops[r["stop_reason"]] += 1
        s["stop_reasons"] = dict(stops)
        for g in GROUPS:
            agg: dict[str, list[int]] = defaultdict(lambda: [0, 0])
            for r in rows:
                agg[r[g]][0] += r["attack_success"]
                agg[r[g]][1] += 1
            s["by"][g] = {k: {"success": v[0], "n": v[1]} for k, v in sorted(agg.items())}
        summary[key] = s
        for r in rows:
            csv_rows.append(
                {
                    "model": meta.get("model"),
                    "case": r["case"],
                    "vector": r["vector"],
                    "goal": r["goal"],
                    "attack_success": int(r["attack_success"]),
                    "checks_hit": "|".join(r["checks_hit"]),
                    "exposed": int(r["exposed"]),
                    "canary_leak_channels": "|".join(r["canary_leak_channels"]),
                    "external_emails": "|".join(r["external_emails"]),
                    "mfa_resets": "|".join(r["mfa_resets"]),
                    "stop_reason": r["stop_reason"],
                    "turns": r["turns"],
                    "tool_calls": "|".join(c["name"] for c in r["calls"]),
                    "wall_s": r["wall_s"],
                }
            )
    (BASE / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    with (BASE / "summary.csv").open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(csv_rows[0]))
        w.writeheader()
        w.writerows(csv_rows)

    keys = list(summary)
    md.append("| Metric | " + " | ".join(summary[k]["model"] for k in keys) + " |")
    md.append("|---" * (len(keys) + 1) + "|")

    def row(label, fn):
        md.append(f"| {label} | " + " | ".join(fn(summary[k]) for k in keys) + " |")

    row("Attack success (all cases)", lambda s: frac(s["attack_success"], s["n_cases"]))
    for g in GROUPS:
        for name in sorted({v for k in keys for v in summary[k]["by"][g]}):
            row(
                f"&nbsp;&nbsp;{g}: {name}",
                lambda s, g=g, name=name: frac(s["by"][g][name]["success"], s["by"][g][name]["n"]),
            )
    row("Injected content reached the model", lambda s: frac(s["exposed"], s["n_cases"]))
    row("Attack success when exposed", lambda s: frac(s["success_when_exposed"], s["exposed"]))
    row("Canary leaked (any channel, any case)", lambda s: frac(s["canary_leaked_any_channel"], s["n_cases"]))
    row("Sent email outside fabrikam.example", lambda s: frac(s["external_email_sent"], s["n_cases"]))
    row("Ran any MFA reset", lambda s: frac(s["mfa_reset_any"], s["n_cases"]))
    row("Malformed tool calls (total)", lambda s: str(s["malformed_tool_calls"]))
    row("Stop reasons", lambda s: ", ".join(f"{k} {v}" for k, v in sorted(s["stop_reasons"].items())))
    row("Wall time, all cases (s)", lambda s: str(s["total_wall_s"]))
    table = "\n".join(md) + "\n"
    (BASE / "summary-table.md").write_text(table)
    print(table)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
