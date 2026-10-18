#!/usr/bin/env python3
# Owner: David. Matches the EDR's alerts.jsonl to the test cases in
# attack_log.csv, classifies each TP/FP/TN/FN, and reports detection accuracy
# and MTTD per slice and overall. Use --offset to correct Kali/VM clock skew.
#   python3 score_eval.py --alerts alerts.jsonl

import argparse
import csv
import json
import sys
from collections import defaultdict

SLICES = {
    "TC-RCE": ("RCE", "David"),
    "TC-AUTH": ("Broken auth", "Kikiola"),
    "TC-SQLI": ("SQL injection", "Thapanawat"),
    "TC-BRUTE": ("Brute force", "Oliver"),
    "TC-UPLOAD": ("File upload", "Louis"),
}


def slice_of(case_id):
    for pfx, (name, _) in SLICES.items():
        if case_id.startswith(pfx):
            return name
    return "Other"


def load_alerts(path, offset):
    alerts = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                a = json.loads(line)
            except json.JSONDecodeError:
                continue
            a["detected_at"] = float(a.get("detected_at", 0)) + offset
            alerts.append(a)
    return alerts


def pct(n, d):
    return f"{100 * n / d:.1f}%" if d else "-"


def main():
    p = argparse.ArgumentParser(description="Score an EDR evaluation run")
    p.add_argument("--attack-log", default="../attacker-playbook/attack_log.csv")
    p.add_argument("--alerts", default="alerts.jsonl")
    p.add_argument("--pre", type=float, default=1.0)
    p.add_argument("--grace", type=float, default=5.0,
                   help="seconds after finish to keep matching (detection lag)")
    p.add_argument("--offset", type=float, default=0.0,
                   help="seconds to add to alert times to align clocks")
    p.add_argument("--out", default="eval_results.csv")
    args = p.parse_args()

    try:
        with open(args.attack_log) as f:
            cases = list(csv.DictReader(f))
    except FileNotFoundError:
        sys.exit(f"[score] attack log not found: {args.attack_log}")
    try:
        alerts = load_alerts(args.alerts, args.offset)
    except FileNotFoundError:
        sys.exit(f"[score] alerts file not found: {args.alerts} "
                 f"(copy it from the Juice Shop VM's ~/edr_lab/)")

    results = []
    for c in cases:
        launched = float(c["launched_at"])
        finished = float(c["finished_at"])
        lo, hi = launched - args.pre, finished + args.grace
        matched = [a for a in alerts if lo <= a["detected_at"] <= hi]
        fired = {a["rule_id"] for a in matched}

        verdict, mttd = None, None
        if c["label"] == "malicious":
            if c["expected_rule"] in fired:
                verdict = "TP"
                hits = [a for a in matched if a["rule_id"] == c["expected_rule"]]
                mttd = min(a["detected_at"] for a in hits) - launched
            else:
                verdict = "FN"
        else:
            verdict = "FP" if matched else "TN"

        results.append({"case_id": c["case_id"], "slice": slice_of(c["case_id"]),
                        "label": c["label"], "expected_rule": c["expected_rule"],
                        "verdict": verdict, "fired": "|".join(sorted(fired)),
                        "mttd_s": f"{mttd:.2f}" if mttd is not None else ""})

    by_slice = defaultdict(lambda: {"TP": 0, "FP": 0, "TN": 0, "FN": 0, "mttd": []})
    for r in results:
        s = by_slice[r["slice"]]
        s[r["verdict"]] += 1
        if r["verdict"] == "TP" and r["mttd_s"]:
            s["mttd"].append(float(r["mttd_s"]))

    def line(name, s):
        tp, fp, tn, fn = s["TP"], s["FP"], s["TN"], s["FN"]
        total = tp + fp + tn + fn
        recall = tp / (tp + fn) if (tp + fn) else 0
        prec = tp / (tp + fp) if (tp + fp) else 0
        f1 = 2 * prec * recall / (prec + recall) if (prec + recall) else 0
        mttd = sum(s["mttd"]) / len(s["mttd"]) if s["mttd"] else None
        return (f"{name:16} {tp:3} {fp:3} {tn:3} {fn:3}  "
                f"{pct(tp, tp + fn):>7} {pct(tp, tp + fp):>8} "
                f"{pct(fp, fp + tn):>8} {pct(tp + tn, total):>8} "
                f"{f1:>5.2f} " + (f"{mttd:>7.2f}s" if mttd is not None else "      -"))

    print()
    print("EDR7 evaluation results")
    print("=" * 86)
    print(f"{'slice':16} {'TP':>3} {'FP':>3} {'TN':>3} {'FN':>3}  "
          f"{'detect':>7} {'precis':>8} {'FP-rate':>8} {'accur':>8} "
          f"{'F1':>5} {'MTTD':>8}")
    print("-" * 86)
    tot = {"TP": 0, "FP": 0, "TN": 0, "FN": 0, "mttd": []}
    for name in [v[0] for v in SLICES.values()] + ["Other"]:
        if name in by_slice:
            s = by_slice[name]
            print(line(name, s))
            for k in ("TP", "FP", "TN", "FN"):
                tot[k] += s[k]
            tot["mttd"] += s["mttd"]
    print("-" * 86)
    print(line("OVERALL", tot))
    print("=" * 86)

    print("\nPer-case:")
    for r in results:
        flag = "" if r["verdict"] in ("TP", "TN") else "  <-- check"
        print(f"  {r['case_id']:14} {r['verdict']:3} "
              f"expected={r['expected_rule']:14} fired=[{r['fired']}]{flag}")

    with open(args.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["case_id", "slice", "label",
                                          "expected_rule", "verdict", "fired", "mttd_s"])
        w.writeheader()
        w.writerows(results)
    print(f"\n[score] wrote per-case results to {args.out}")


if __name__ == "__main__":
    main()
