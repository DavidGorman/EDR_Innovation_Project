#!/usr/bin/env python3
# Owner: David. Converts Wazuh's alerts.json into the one-alert-per-line format
# score_eval.py reads, so the Wazuh baseline scores through the same harness.
#   python3 wazuh_adapter.py --in /var/ossec/logs/alerts/alerts.json --out wazuh_alerts.jsonl

import argparse
import json
import sys
from datetime import datetime


def to_epoch(ts):
    # Wazuh stamps alerts like 2026-10-18T14:23:45.123+0000; parse to epoch seconds.
    try:
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%f%z").timestamp()
    except (ValueError, TypeError):
        try:
            return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S%z").timestamp()
        except (ValueError, TypeError):
            return None


def main():
    p = argparse.ArgumentParser(description="Normalise Wazuh alerts for scoring")
    p.add_argument("--in", dest="infile", default="/var/ossec/logs/alerts/alerts.json")
    p.add_argument("--out", default="wazuh_alerts.jsonl")
    p.add_argument("--min-level", type=int, default=5,
                   help="drop Wazuh alerts below this level to cut host noise (default 5)")
    p.add_argument("--srcip", help="keep only alerts from this source IP (e.g. the Kali attacker)")
    p.add_argument("--location-contains", action="append", default=[],
                   help="keep only alerts whose log location contains this (repeatable)")
    args = p.parse_args()

    try:
        f = open(args.infile)
    except FileNotFoundError:
        sys.exit(f"[wazuh] alerts file not found: {args.infile} "
                 f"(run on the Wazuh manager, or copy its alerts.json over)")

    kept, skipped = 0, 0
    with f, open(args.out, "w") as out:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                a = json.loads(line)
            except json.JSONDecodeError:
                skipped += 1
                continue
            rule = a.get("rule", {})
            level = int(rule.get("level", 0))
            if level < args.min_level:
                continue
            detected_at = to_epoch(a.get("timestamp", ""))
            if detected_at is None:
                skipped += 1
                continue
            srcip = a.get("data", {}).get("srcip")
            location = a.get("location", "")
            if args.srcip and srcip != args.srcip:
                continue
            if args.location_contains and not any(s in location for s in args.location_contains):
                continue
            out.write(json.dumps({
                "detected_at": detected_at,
                "rule_id": f"WAZUH-{rule.get('id', '?')}",
                "title": rule.get("description", ""),
                "level": level,
                "groups": rule.get("groups", []),
                "location": location,
                "srcip": srcip,
            }) + "\n")
            kept += 1

    print(f"[wazuh] wrote {kept} alerts to {args.out} (level>={args.min_level}, skipped {skipped})")


if __name__ == "__main__":
    main()
