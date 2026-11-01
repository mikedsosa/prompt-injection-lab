"""Command line entry point.

fabrikam-lab tools                      # list the mock tools
fabrikam-lab ask --model stub "..."     # offline dry run, no model needed
fabrikam-lab ask --model qwen "..."     # one agent run against a local model
"""

from __future__ import annotations

import argparse
import json
import sys

from fabrikam_lab.agent import DEFAULT_MAX_TURNS, run_agent
from fabrikam_lab.config import DEFAULT_CONFIG, load_config, make_client
from fabrikam_lab.models.stub import ScriptedModel, answer, tool_call
from fabrikam_lab.tools import TOOL_SPECS, ToolEnv


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="fabrikam-lab")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("tools", help="list the mock tools")
    ask = sub.add_parser("ask", help="run the agent once on a message")
    ask.add_argument("message")
    ask.add_argument("--model", default="stub", help="'stub' or a key from config/models.toml")
    ask.add_argument("--config", default=str(DEFAULT_CONFIG))
    ask.add_argument("--max-turns", type=int, default=DEFAULT_MAX_TURNS)
    ask.add_argument("--seed", type=int, default=None)
    args = parser.parse_args(argv)

    if args.cmd == "tools":
        for spec in TOOL_SPECS.values():
            print(f"{spec['name']}({', '.join(spec['parameters']['required'])}): {spec['description']}")
        return 0

    if args.model == "stub":
        model = ScriptedModel([tool_call("read_kb_article", article_id="KB-1001"), answer("(stub) See KB-1001.")])
        seed = args.seed
    else:
        cfg = load_config(args.config)
        model = make_client(args.model, cfg)
        seed = args.seed if args.seed is not None else cfg["defaults"].get("seed")
    res = run_agent(model, args.message, env=ToolEnv(), max_turns=args.max_turns, seed=seed)
    json.dump(res.to_dict(), sys.stdout, indent=2, default=str)
    print()
    return 0 if res.stop_reason == "final_answer" else 1


if __name__ == "__main__":
    raise SystemExit(main())
