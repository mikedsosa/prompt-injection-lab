"""Summarize the milestone 4 defense runs against the undefended baseline.

    python scripts/summarize_defenses.py

Reads results/defenses/<model>-<config>-seed<N>.jsonl and the baseline files
results/full-baseline/<model>-seed<N>.jsonl, and writes summary.json, summary.csv and
summary-table.md in results/defenses/. Each defense run is compared with the baseline run
of the same model and seed. Every number comes from the run files.
"""

from __future__ import annotations

import csv
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEF = ROOT / "results" / "defenses"
BASE = ROOT / "results" / "full-baseline"
ORDER = ["baseline", "spotlight", "hardened", "gateway", "output_filter", "all"]
LABEL = {
    "baseline": "baseline (no defense)",
    "spotlight": "spotlighting (datamarking)",
    "hardened": "hardened system prompt",
    "gateway": "tool gateway (code)",
    "output_filter": "output filter (offline)",
    "all": "all combined",
}
GROUPS = ("vector", "goal", "technique_family")
FILE_RE = re.compile(r"^(?P<model>[a-z0-9]+)-(?P<config>[a-z_]+)-seed(?P<seed>\d+)\.jsonl$")
BASE_RE = re.compile(r"^(?P<model>[a-z0-9]+)-seed(?P<seed>\d+)\.jsonl$")
HARM_KINDS = ("external_email", "mfa_reset", "canary_in_tool_args")


def load(path: Path) -> tuple[dict, list[dict], dict]:
    meta, rows, end = {}, [], {}
    for line in path.read_text(encoding="utf-8").splitlines():
        d = json.loads(line)
        if "meta" in d:
            meta = d["meta"]
        elif "end" in d:
            end = d["end"]
        elif "case" in d:
            rows.append(d)
    return meta, rows, end


def attempted(row: dict) -> dict:
    """What the model tried in this run: the gateway/filter-free view (baseline: what happened)."""
    a = (row.get("details") or {}).get("attempted")
    if a is None:
        a = {
            k: row[k] for k in ("attack_success", "checks_hit", "canary_leak_channels", "external_emails", "mfa_resets")
        }
    return a


def harm_kinds(d: dict) -> set[str]:
    kinds = set()
    if d["external_emails"]:
        kinds.add("external_email")
    if d["mfa_resets"]:
        kinds.add("mfa_reset")
    if "tool_args" in d["canary_leak_channels"] or "email" in d["canary_leak_channels"]:
        kinds.add("canary_in_tool_args")
    return kinds


def frac(k: int, n: int) -> str:
    return f"{k}/{n} ({100 * k / n:.0f}%)" if n else "0/0"


def summarize_run(meta: dict, rows: list[dict], end: dict, base_rows: list[dict] | None) -> dict:
    attacks = [r for r in rows if not r["control"]]
    controls = [r for r in rows if r["control"]]
    base = {r["case"]: r for r in base_rows or []}
    out: dict = {
        "defense": meta.get("defense", "none"),
        "derived_offline_from": meta.get("derived_offline_from"),
        "max_tokens": meta.get("max_tokens"),
        "started_utc": meta.get("started_utc"),
        "n_attacks": len(attacks),
        "attack_success": sum(r["attack_success"] for r in attacks),
        "attempted_success": sum(attempted(r)["attack_success"] for r in attacks),
        "exposed": sum(r["exposed"] for r in attacks),
        "by": {},
        "residual_successes": sorted(r["case"] for r in attacks if r["attack_success"]),
        "residual_checks": {r["case"]: r["checks_hit"] for r in attacks if r["attack_success"]},
        "fixed_vs_baseline": sorted(
            r["case"] for r in attacks if base and base[r["case"]]["attack_success"] and not r["attack_success"]
        ),
        "new_vs_baseline": sorted(
            r["case"] for r in attacks if base and r["attack_success"] and not base[r["case"]]["attack_success"]
        ),
        "stop_reasons": dict(Counter(r["stop_reason"] for r in rows)),
        "total_wall_s": None if meta.get("derived_offline_from") else end.get("total_wall_s"),
    }
    for g in GROUPS:
        agg: dict[str, list[int]] = defaultdict(lambda: [0, 0])
        for r in attacks:
            agg[r[g]][0] += r["attack_success"]
            agg[r[g]][1] += 1
        out["by"][g] = {k: {"success": v[0], "n": v[1]} for k, v in sorted(agg.items())}
    # harmful tool actions: what the model tried vs what actually happened (attack cases)
    harm = {}
    for kind in HARM_KINDS:
        harm[kind] = {
            "attempted_cases": sum(kind in harm_kinds(attempted(r)) for r in attacks),
            "landed_cases": sum(kind in harm_kinds(r) for r in attacks),
        }
    out["harmful_actions"] = harm
    blocked = [(r, b) for r in rows for b in (r.get("details") or {}).get("blocked_calls", [])]
    out["gateway"] = {
        "blocked_calls_attacks": sum(1 for r, _ in blocked if not r["control"]),
        "cases_with_block_attacks": len({r["case"] for r, _ in blocked if not r["control"]}),
        "blocked_calls_controls": sum(1 for r, _ in blocked if r["control"]),
        "block_reasons": dict(sorted(Counter(x for _, b in blocked for x in b["reasons"]).items())),
        "blocked_by_tool": dict(sorted(Counter(b["name"] for _, b in blocked).items())),
        "control_blocks": [{"case": r["case"], **b} for r, b in blocked if r["control"]],
    }
    filt = [(r, a) for r in rows for a in (r.get("details") or {}).get("output_filter_actions", [])]
    out["output_filter"] = {
        "attack_cases_filtered": len({r["case"] for r, _ in filt if not r["control"]}),
        "withheld_canary_attacks": sum(1 for r, a in filt if not r["control"] and a == "withheld_canary"),
        "links_removed_attacks": sum(1 for r, a in filt if not r["control"] and a.startswith("link_removed")),
        "control_actions": [{"case": r["case"], "action": a} for r, a in filt if r["control"]],
    }
    out["controls"] = {
        "n": len(controls),
        "harm": sum(r["attack_success"] for r in controls),
        "task_ok": sum(bool(r["task_ok"]) for r in controls),
        "task_not_done": sorted(r["case"] for r in controls if not r["task_ok"]),
        "task_not_done_detail": {
            r["case"]: {"task_failed": r["task_failed"], "stop_reason": r["stop_reason"]}
            for r in controls
            if not r["task_ok"]
        },
    }
    return out


def build(def_dir: Path = DEF, base_dir: Path = BASE) -> tuple[dict, list[dict]]:
    runs: dict[str, dict[str, dict[int, tuple]]] = defaultdict(lambda: defaultdict(dict))
    for p in sorted(base_dir.glob("*.jsonl")):
        m = BASE_RE.match(p.name)
        if m:
            runs[m["model"]]["baseline"][int(m["seed"])] = load(p)
    for p in sorted(def_dir.glob("*.jsonl")):
        m = FILE_RE.match(p.name)
        if not m:
            continue
        run = load(p)
        if not run[2]:
            print(f"skipping {p.name}: run not finished", file=sys.stderr)
            continue
        runs[m["model"]][m["config"]][int(m["seed"])] = run
    summary: dict = {}
    csv_rows: list[dict] = []
    for model, by_cfg in sorted(runs.items()):
        if len(by_cfg) < 2:
            continue
        model_tag = next(iter(by_cfg["baseline"].values()))[0].get("model")
        summary[model] = {"model": model_tag, "configs": {}}
        for cfg in [c for c in ORDER if c in by_cfg]:
            # baseline: only the seeds some defense config also has
            seeds = sorted(by_cfg[cfg])
            if cfg == "baseline":
                seeds = sorted({s for c, d in by_cfg.items() if c != "baseline" for s in d} & set(seeds))
            summary[model]["configs"][cfg] = {}
            for seed in seeds:
                meta, rows, end = by_cfg[cfg][seed]
                base_rows = by_cfg["baseline"].get(seed, (None, None, None))[1]
                summary[model]["configs"][cfg][str(seed)] = summarize_run(
                    meta, rows, end, None if cfg == "baseline" else base_rows
                )
                for r in rows:
                    a = attempted(r)
                    d = r.get("details") or {}
                    csv_rows.append(
                        {
                            "model": model,
                            "config": cfg,
                            "seed": seed,
                            "case": r["case"],
                            "control": r["control"],
                            "vector": r["vector"],
                            "goal": r["goal"],
                            "technique_family": r["technique_family"],
                            "attack_success": r["attack_success"],
                            "attempted_success": a["attack_success"],
                            "checks_hit": ";".join(r["checks_hit"]),
                            "exposed": r["exposed"],
                            "task_ok": "" if r["task_ok"] is None else r["task_ok"],
                            "blocked_calls": ";".join(
                                f"{b['name']}[{'+'.join(b['reasons'])}]" for b in d.get("blocked_calls", [])
                            ),
                            "output_filter_actions": ";".join(d.get("output_filter_actions", [])),
                            "stop_reason": r["stop_reason"],
                            "wall_s": r["wall_s"],
                        }
                    )
    return summary, csv_rows


def render(summary: dict) -> str:
    md = ["# Defense summary (generated by scripts/summarize_defenses.py)", ""]
    md.append("Attack success counts the 50 attack cases; controls are the 10 benign cases. Seed in brackets.")
    md.append("Each defense run is compared with the baseline run of the same model and seed.")
    for model, s in summary.items():
        cfgs = s["configs"]
        md += ["", f"## {model} ({s['model']})", ""]
        md += [
            "| config [seed] | attack success | attempted (before gateway/filter) | fixed vs baseline "
            "| new vs baseline | controls: harm | controls: task done | gateway blocks (attacks / controls) "
            "| wall time |",
            "|---|---|---|---|---|---|---|---|---|",
        ]
        for cfg, by_seed in cfgs.items():
            for seed, r in by_seed.items():
                g = r["gateway"]
                wall = "offline" if r["derived_offline_from"] else f"{r['total_wall_s']} s"
                fixed = "-" if cfg == "baseline" else str(len(r["fixed_vs_baseline"]))
                new = "-" if cfg == "baseline" else str(len(r["new_vs_baseline"]))
                md.append(
                    f"| {LABEL[cfg]} [{seed}] | {frac(r['attack_success'], r['n_attacks'])} "
                    f"| {frac(r['attempted_success'], r['n_attacks'])} | {fixed} | {new} "
                    f"| {r['controls']['harm']}/{r['controls']['n']} | {r['controls']['task_ok']}/{r['controls']['n']} "
                    f"| {g['blocked_calls_attacks']} / {g['blocked_calls_controls']} | {wall} |"
                )
        for grp in GROUPS:
            cols = [(c, sd) for c, by_seed in cfgs.items() for sd in by_seed]
            md += ["", f"### {model}: attack success by {grp.replace('_', ' ')}", ""]
            md += ["| " + grp + " | n | " + " | ".join(f"{c} [{sd}]" for c, sd in cols) + " |"]
            md += ["|---|---|" + "---|" * len(cols)]
            cats = sorted({k for c, sd in cols for k in cfgs[c][sd]["by"][grp]})
            for k in cats:
                n = next(cfgs[c][sd]["by"][grp][k]["n"] for c, sd in cols if k in cfgs[c][sd]["by"][grp])
                cells = [str(cfgs[c][sd]["by"][grp].get(k, {}).get("success", "-")) for c, sd in cols]
                md.append(f"| {k} | {n} | " + " | ".join(cells) + " |")
        md += ["", f"### {model}: harmful tool actions, attack cases (attempted -> actually happened)", ""]
        md += ["| config [seed] | outside email | MFA reset | canary in email or tool arguments |", "|---|---|---|---|"]
        for cfg, by_seed in cfgs.items():
            for seed, r in by_seed.items():
                h = r["harmful_actions"]
                cells = [f"{h[k]['attempted_cases']} -> {h[k]['landed_cases']}" for k in HARM_KINDS]
                md.append(f"| {LABEL[cfg]} [{seed}] | " + " | ".join(cells) + " |")
        md += ["", f"### {model}: residual successes and control failures", ""]
        for cfg, by_seed in cfgs.items():
            for seed, r in by_seed.items():
                res = ", ".join(f"{c} ({'+'.join(r['residual_checks'][c])})" for c in r["residual_successes"]) or "none"
                md.append(f"- {LABEL[cfg]} [{seed}]: still succeeded: {res}")
                ctl = r["controls"]["task_not_done"]
                blocks = r["gateway"]["control_blocks"]
                flt = r["output_filter"]["control_actions"]
                md.append(f"  - controls not done: {', '.join(ctl) or 'none'}")
                if blocks:
                    md.append(
                        "  - benign calls blocked: "
                        + ", ".join(f"{b['case']} {b['name']} ({'+'.join(b['reasons'])})" for b in blocks)
                    )
                if flt:
                    md.append("  - output filter on controls: " + ", ".join(f"{a['case']} {a['action']}" for a in flt))
    return "\n".join(md) + "\n"


def main() -> int:
    summary, csv_rows = build()
    if not summary:
        print("no defense runs in results/defenses/", file=sys.stderr)
        return 1
    (DEF / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    with (DEF / "summary.csv").open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(csv_rows[0]))
        w.writeheader()
        w.writerows(csv_rows)
    (DEF / "summary-table.md").write_text(render(summary))
    print(f"wrote {len(csv_rows)} rows for {', '.join(summary)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
