"""Check that attack-success tables in the docs match the generated defense summary."""

import csv
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LABELS = {
    "baseline (no defense)": "baseline",
    "spotlighting": "spotlight",
    "hardened system prompt": "hardened",
    "tool gateway": "gateway",
    "output filter (offline)": "output_filter",
    "all combined": "all",
}
ROW = re.compile(r"^\| (?P<label>[^|]+?) \| (?P<qwen>\d+)/50 \(\d+%\) \| (?P<llama>\d+)/50 \(\d+%\) \|$")


def _summary_counts():
    counts = Counter()
    with open(ROOT / "results/defenses/summary.csv", newline="") as f:
        for row in csv.DictReader(f):
            if row["control"] == "False" and row["attack_success"] == "True":
                counts[(row["model"], row["config"])] += 1
    return counts


def _doc_rows(path):
    rows = {}
    for line in path.read_text().splitlines():
        m = ROW.match(line)
        if m and m["label"] in LABELS:
            rows[LABELS[m["label"]]] = (int(m["qwen"]), int(m["llama"]))
    return rows


def test_doc_tables_match_summary():
    counts = _summary_counts()
    for doc in ("results/defenses/RESULTS.md", "docs/findings.md"):
        rows = _doc_rows(ROOT / doc)
        assert set(rows) == set(LABELS.values()), doc
        for config, (qwen, llama) in rows.items():
            assert qwen == counts[("qwen", config)], (doc, config)
            assert llama == counts[("llama", config)], (doc, config)
