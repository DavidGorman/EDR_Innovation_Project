#!/usr/bin/env python3
# Owner: David. Fires every test case on Kali and logs when each ran to
# attack_log.csv. Run from attacker-playbook/ with the EDR running on the VM:
#   python3 run_eval.py   (then score with EDR/score_eval.py)

import argparse
import csv
import os
import subprocess
import sys
import time

try:
    import yaml
except ImportError:
    sys.exit("Missing dependency: pip install pyyaml")

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CASES = os.path.join(HERE, "..", "EDR", "Test", "testcases.yaml")
DEFAULT_LOG = os.path.join(HERE, "attack_log.csv")


def load_cases(path):
    with open(path) as f:
        cases = yaml.safe_load(f)
    if not isinstance(cases, list):
        sys.exit(f"[run_eval] {path} did not parse as a list of cases")
    return cases


def main():
    p = argparse.ArgumentParser(description="EDR evaluation runner")
    p.add_argument("--testcases", default=DEFAULT_CASES)
    p.add_argument("--out", default=DEFAULT_LOG)
    p.add_argument("--gap", type=float, default=20.0,
                   help="seconds to wait after each case (default 20)")
    p.add_argument("--only", help="run only cases whose id starts with this")
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args()

    cases = load_cases(args.testcases)
    if args.only:
        cases = [c for c in cases if c["id"].startswith(args.only)]
    if not cases:
        sys.exit("[run_eval] no cases to run")

    print(f"[run_eval] {len(cases)} cases, {args.gap}s gap, "
          f"~{len(cases) * (args.gap + 5) / 60:.0f} min estimated")
    if args.dry_run:
        for c in cases:
            print(f"  would run {c['id']:14} [{c['label']:9}] -> {c['command']}")
        return

    rows = []
    try:
        for i, c in enumerate(cases, 1):
            launched_at = time.time()
            print(f"\n[{i}/{len(cases)}] {c['id']} [{c['label']}] "
                  f"expect={c['expected_rule']}")
            print(f"    $ {c['command']}")
            try:
                subprocess.run(c["command"], shell=True, cwd=HERE,
                               timeout=120, check=False)
            except subprocess.TimeoutExpired:
                print("    (timed out after 120s, continuing)")
            finished_at = time.time()
            rows.append({"case_id": c["id"], "label": c["label"],
                         "expected_rule": c["expected_rule"],
                         "launched_at": f"{launched_at:.3f}",
                         "finished_at": f"{finished_at:.3f}",
                         "command": c["command"]})
            if i < len(cases):
                print(f"    waiting {args.gap}s for the window to clear...")
                time.sleep(args.gap)
    except KeyboardInterrupt:
        print("\n[run_eval] interrupted - writing what ran so far")

    with open(args.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["case_id", "label", "expected_rule",
                                          "launched_at", "finished_at", "command"])
        w.writeheader()
        w.writerows(rows)
    print(f"\n[run_eval] wrote {len(rows)} rows to {args.out}")


if __name__ == "__main__":
    main()
