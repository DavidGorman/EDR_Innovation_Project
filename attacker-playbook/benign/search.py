#!/usr/bin/env python3
# Owner: Thapanawat. Benign product search used as the SQLi false-positive
# test: SQL-looking but legitimate terms that must NOT raise a WEB-SQLI alert.

import argparse
import os
import sys

try:
    import requests
except ImportError:
    sys.exit("Missing dependency: pip install requests")

BASE = os.environ.get("JS_TARGET", "http://192.168.100.51:3000").rstrip("/")


def main():
    p = argparse.ArgumentParser(description="Benign product search (lab use)")
    p.add_argument("--term", required=True, help="the search term")
    args = p.parse_args()

    try:
        r = requests.get(f"{BASE}/rest/products/search",
                         params={"q": args.term}, timeout=5)
        print(f"[benign] searched {args.term!r} -> HTTP {r.status_code}")
    except requests.RequestException as e:
        print(f"[benign] request failed: {e}")


if __name__ == "__main__":
    main()
