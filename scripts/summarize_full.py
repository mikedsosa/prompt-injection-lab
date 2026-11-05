"""Summarize the multi-seed full-set runs in results/full-baseline/.

    python scripts/summarize_full.py

Reads results/full-baseline/<model>-seed<N>.jsonl and writes summary.json, summary.csv
and summary-table.md next to them. Attack success rates count attack cases only;
control cases are reported apart (harm flags and benign-task completion). Every number
comes from the run files. Nothing is typed in by hand.
"""

from __future__ import annotations

import csv
import json
import re
import statistics
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FULL = ROOT / "results" / "full-baseline"
GROUPS = ("vector", "goal", "technique_family")
FILE_RE = re.compile(r"^(?P<model>.+)-seed(?P<seed>\d+)\.jsonl$")


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


def spread(rates: list[float]) -> dict:
    return {
        "min": round(min(rates), 4),
        "max": round(max(rates), 4),
        "mean": round(statistics.fmean(rates), 4),
        "sd": round(statistics.stdev(rates), 4) if len(rates) > 1 else 0.0,
    }


def pct(x: float) -> str:
    return f"{100 * x:.0f}%"


def rate_cell(per_seed: list[tuple[int, int]]) -> str:
    """'7/9 (78%)' for one seed; 'mean 74% (min 67%, max 78%)' plus counts for several."""
    if len(per_seed) == 1:
        k, n = per_seed[0]
        return f"{k}/{n} ({pct(k / n)})" if n else "0/0"
    rates = [k / n for k, n in per_seed if n]
    counts = ", ".join(f"{k}/{n}" for k, n in per_seed)
    if min(rates) == max(rates):
        return f"{pct(rates[0])} every seed ({counts})"
    return f"mean {pct(statistics.fmean(rates))}, min {pct(min(rates))}, max {pct(max(rates))} ({counts})"


def behavior_key(row: dict) -> str:
    return json.dumps([row["final_text"], [(c["name"], c["arguments"]) for c in row["calls"]]], sort_keys=True)


def summarize_model(runs: dict[int, tuple[dict, list[dict], dict]]) -> dict:
    seeds = sorted(runs)
    first_meta = runs[seeds[0]][0]
    ps = (first_meta.get("server") or {}).get("ollama_ps") or [{}]
    out: dict = {
        "model": first_meta.get("model"),
        "digest": first_meta.get("model_digest"),
        "ollama_version": first_meta.get("ollama_version"),
        "context_length": ps[0].get("context_length"),
        "temperature": first_meta.get("temperature"),
        "max_turns": first_meta.get("max_turns"),
        "seeds": seeds,
        "per_seed": {},
        "by": {g: {} for g in GROUPS},
    }
    group_counts: dict[str, dict[str, dict[int, list[int]]]] = {g: defaultdict(dict) for g in GROUPS}
    for seed in seeds:
        meta, rows, end = runs[seed]
        attacks = [r for r in rows if not r["control"]]
        controls = [r for r in rows if r["control"]]
        stops: dict[str, int] = defaultdict(int)
        for r in rows:
            stops[r["stop_reason"]] += 1
        out["per_seed"][seed] = {
            "started_utc": meta.get("started_utc"),
            "n_cases": len(rows),
            "n_attacks": len(attacks),
            "attack_success": sum(r["attack_success"] for r in attacks),
            "exposed": sum(r["exposed"] for r in attacks),
            "success_when_exposed": sum(r["attack_success"] for r in attacks if r["exposed"]),
            "canary_leaked_any_channel": sum(bool(r["canary_leak_channels"]) for r in attacks),
            "external_email_sent": sum(bool(r["external_emails"]) for r in attacks),
            "mfa_reset_any": sum(bool(r["mfa_resets"]) for r in attacks),
            "malformed_tool_calls": sum(r["malformed_tool_calls"] for r in rows),
            "stop_reasons": dict(stops),
            "total_wall_s": end.get("total_wall_s"),
            "controls": {
                "n": len(controls),
                "harm": sum(r["attack_success"] for r in controls),
                "task_ok": sum(bool(r["task_ok"]) for r in controls),
                "failed": {
                    r["case"]: {
                        "harm_checks": r["checks_hit"],
                        "task_failed": r["task_failed"],
                        "stop_reason": r["stop_reason"],
                    }
                    for r in controls
                    if r["attack_success"] or not r["task_ok"]
                },
            },
        }
        for g in GROUPS:
            agg: dict[str, list[int]] = defaultdict(lambda: [0, 0])
            for r in attacks:
                agg[r[g]][0] += r["attack_success"]
                agg[r[g]][1] += 1
            for k, (succ, n) in agg.items():
                group_counts[g][k][seed] = [succ, n]
    for g in GROUPS:
        for k in sorted(group_counts[g]):
            per = group_counts[g][k]
            out["by"][g][k] = {
                "n_per_seed": per[seeds[0]][1],
                "success_per_seed": {s: per[s][0] for s in seeds},
                "rate": spread([per[s][0] / per[s][1] for s in seeds]),
            }
    ps_rates = [out["per_seed"][s]["attack_success"] / out["per_seed"][s]["n_attacks"] for s in seeds]
    out["overall_rate"] = spread(ps_rates)
    # seed agreement, case by case
    by_case: dict[str, list[dict]] = defaultdict(list)
    for seed in seeds:
        for r in runs[seed][1]:
            by_case[r["case"]].append(r)
    same_outcome = sum(len({r["attack_success"] for r in rs}) == 1 for rs in by_case.values())
    same_behavior = sum(len({behavior_key(r) for r in rs}) == 1 for rs in by_case.values())
    out["seed_agreement"] = {
        "n_cases": len(by_case),
        "same_attack_outcome_all_seeds": same_outcome,
        "identical_answer_and_tool_calls_all_seeds": same_behavior,
        "cases_with_mixed_outcome": sorted(
            c for c, rs in by_case.items() if len({r["attack_success"] for r in rs}) > 1
        ),
        "attack_cases_success_every_seed": sorted(
            c for c, rs in by_case.items() if not rs[0]["control"] and all(r["attack_success"] for r in rs)
        ),
    }
    out["total_wall_s_all_seeds"] = round(sum(out["per_seed"][s]["total_wall_s"] or 0 for s in seeds), 1)
    return out


def build(directory: Path = FULL) -> tuple[dict, list[dict]]:
    """Summary dict and per-run CSV rows for every <model>-seed<N>.jsonl in ``directory``."""
    files: dict[str, dict[int, Path]] = defaultdict(dict)
    for p in sorted(directory.glob("*.jsonl")):
        m = FILE_RE.match(p.name)
        if m:
            files[m["model"]][int(m["seed"])] = p
    summary, csv_rows = {}, []
    for key, seed_files in sorted(files.items()):
        runs = {s: load(p) for s, p in seed_files.items()}
        for s in [s for s, run in runs.items() if not run[2]]:  # no closing line: still running or cut off
            print(f"skipping {seed_files[s].name}: run not finished", file=sys.stderr)
            del runs[s]
        if not runs:
            continue
        summary[key] = summarize_model(runs)
        for s, (_, rows, _) in sorted(runs.items()):
            for r in rows:
                csv_rows.append(
                    {
                        "model": key,
                        "seed": s,
                        "case": r["case"],
                        "control": r["control"],
                        "vector": r["vector"],
                        "goal": r["goal"],
                        "technique_family": r["technique_family"],
                        "attack_success": r["attack_success"],
                        "checks_hit": ";".join(r["checks_hit"]),
                        "exposed": r["exposed"],
                        "task_ok": "" if r["task_ok"] is None else r["task_ok"],
                        "task_failed": ";".join(r["task_failed"]),
                        "canary_leak_channels": ";".join(r["canary_leak_channels"]),
                        "external_emails": ";".join(r["external_emails"]),
                        "mfa_resets": ";".join(r["mfa_resets"]),
                        "stop_reason": r["stop_reason"],
                        "turns": r["turns"],
                        "malformed_tool_calls": r["malformed_tool_calls"],
                        "wall_s": r["wall_s"],
                    }
                )
    return summary, csv_rows


def main() -> int:
    summary, csv_rows = build()
    if not summary:
        print("no runs in results/full-baseline/", file=sys.stderr)
        return 1
    (FULL / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    with (FULL / "summary.csv").open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(csv_rows[0]))
        w.writeheader()
        w.writerows(csv_rows)
    (FULL / "summary-table.md").write_text(render(summary))
    print(f"wrote {len(csv_rows)} rows for {', '.join(summary)}")
    return 0


def render(summary: dict) -> str:
    keys = list(summary)
    md = ["# Full baseline summary (generated by scripts/summarize_full.py)", ""]
    md.append("Attack success counts attack cases only (controls excluded). Per-seed counts in parentheses.")
    md.append("")
    md += ["| | " + " | ".join(f"{k} ({summary[k]['model']})" for k in keys) + " |"]
    md += ["|---|" + "---|" * len(keys)]

    def seeds_of(k):
        return summary[k]["seeds"]

    def line(label, fn):
        md.append(f"| {label} | " + " | ".join(fn(summary[k]) for k in keys) + " |")

    line("Seeds", lambda s: ", ".join(map(str, s["seeds"])))
    line("Temperature", lambda s: str(s["temperature"]))
    line("Server context length", lambda s: str(s["context_length"]))
    line(
        "Attack success, all attacks",
        lambda s: rate_cell([(s["per_seed"][x]["attack_success"], s["per_seed"][x]["n_attacks"]) for x in s["seeds"]]),
    )
    line(
        "Exposed to the payload",
        lambda s: rate_cell([(s["per_seed"][x]["exposed"], s["per_seed"][x]["n_attacks"]) for x in s["seeds"]]),
    )
    line(
        "Success when exposed",
        lambda s: rate_cell(
            [(s["per_seed"][x]["success_when_exposed"], s["per_seed"][x]["exposed"]) for x in s["seeds"]]
        ),
    )
    for f, label in (
        ("canary_leaked_any_channel", "Attacks where the canary left (any channel)"),
        ("external_email_sent", "Attacks with an email to an outside address"),
        ("mfa_reset_any", "Attacks with any MFA reset"),
    ):
        line(
            label, lambda s, f=f: rate_cell([(s["per_seed"][x][f], s["per_seed"][x]["n_attacks"]) for x in s["seeds"]])
        )
    line(
        "Controls: harm (leak, outside email or unexpected reset)",
        lambda s: rate_cell(
            [(s["per_seed"][x]["controls"]["harm"], s["per_seed"][x]["controls"]["n"]) for x in s["seeds"]]
        ),
    )
    line(
        "Controls: benign task done",
        lambda s: rate_cell(
            [(s["per_seed"][x]["controls"]["task_ok"], s["per_seed"][x]["controls"]["n"]) for x in s["seeds"]]
        ),
    )
    line(
        "Cases with the same outcome on every seed",
        lambda s: (
            f"{s['seed_agreement']['same_attack_outcome_all_seeds']}/{s['seed_agreement']['n_cases']}"
            if len(s["seeds"]) > 1
            else "n/a (1 seed)"
        ),
    )
    line(
        "Cases with identical answer and tool calls on every seed",
        lambda s: (
            f"{s['seed_agreement']['identical_answer_and_tool_calls_all_seeds']}/{s['seed_agreement']['n_cases']}"
            if len(s["seeds"]) > 1
            else "n/a (1 seed)"
        ),
    )
    line(
        "Runs that ended without a final answer (all cases, all seeds)",
        lambda s: (
            ", ".join(
                f"{reason} {sum(s['per_seed'][x]['stop_reasons'].get(reason, 0) for x in s['seeds'])}"
                for reason in sorted(
                    {r for x in s["seeds"] for r in s["per_seed"][x]["stop_reasons"]} - {"final_answer"}
                )
            )
            or "none"
        ),
    )
    line(
        "Malformed tool calls (all seeds)",
        lambda s: str(sum(s["per_seed"][x]["malformed_tool_calls"] for x in s["seeds"])),
    )
    line("Wall time, all seeds", lambda s: f"{s['total_wall_s_all_seeds']} s")
    for g in GROUPS:
        md += ["", f"## By {g.replace('_', ' ')}", ""]
        md += ["| " + g + " | n per seed | " + " | ".join(keys) + " |", "|---|---|" + "---|" * len(keys)]
        cats = sorted({c for k in keys for c in summary[k]["by"][g]})
        for c in cats:
            n = next(summary[k]["by"][g][c]["n_per_seed"] for k in keys if c in summary[k]["by"][g])
            cells = []
            for k in keys:
                d = summary[k]["by"][g].get(c)
                if d is None:
                    cells.append("-")
                    continue
                cells.append(rate_cell([(d["success_per_seed"][x], d["n_per_seed"]) for x in seeds_of(k)]))
            md.append(f"| {c} | {n} | " + " | ".join(cells) + " |")
    md += ["", "## Control cases that failed (harm, or benign task not done)", ""]
    for k in keys:
        for x in seeds_of(k):
            failed = summary[k]["per_seed"][x]["controls"]["failed"]
            if not failed:
                md.append(f"- {k} seed {x}: none")
            for cid, d in sorted(failed.items()):
                parts = []
                if d["harm_checks"]:
                    parts.append("harm: " + ", ".join(d["harm_checks"]))
                if d["task_failed"]:
                    parts.append("task not done: " + ", ".join(d["task_failed"]))
                if d["stop_reason"] != "final_answer":
                    parts.append(f"stop reason: {d['stop_reason']}")
                md.append(f"- {k} seed {x}: {cid} ({'; '.join(parts)})")
    md += ["", "## Seed agreement", ""]
    for k in keys:
        a = summary[k]["seed_agreement"]
        if len(summary[k]["seeds"]) < 2:
            md.append(f"- {k}: one seed only, so no seed comparison")
            continue
        mixed = ", ".join(a["cases_with_mixed_outcome"]) or "none"
        md.append(f"- {k}: cases whose outcome differed between seeds: {mixed}")
    return "\n".join(md) + "\n"


if __name__ == "__main__":
    raise SystemExit(main())
