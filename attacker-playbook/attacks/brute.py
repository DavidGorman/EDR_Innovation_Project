#!/usr/bin/env python3
# Owner: Oliver. Brute-force login against Juice Shop.
# Each --case (rapid, sustained, repeated) makes 5+ failed logins within the
# 15s window so WEB-BRUTE-001 fires.

import argparse
import os
import sys
import time

try:
    import requests
except ImportError:
    sys.exit("Missing dependency: pip install requests")

BASE = os.environ.get("JS_TARGET", "http://192.168.100.51:3000").rstrip("/")
URL = f"{BASE}/rest/user/login"
EMAIL = os.environ.get("JS_EMAIL", "admin@juice-sh.op")


def fail(n):
    try:
        r = requests.post(URL, json={"email": EMAIL, "password": f"wrong{n}"}, timeout=5)
        print(f"[brute] attempt {n} -> {r.status_code}")
    except requests.RequestException as e:
        print(f"[brute] attempt {n} failed: {e}")


def main():
    p = argparse.ArgumentParser(description="Brute-force attack (lab use only)")
    p.add_argument("--case", required=True, choices=["rapid", "sustained", "repeated"])
    args = p.parse_args()

    if args.case == "rapid":
        for n in range(8):
            fail(n)
    elif args.case == "sustained":
        for n in range(10):
            fail(n)
            time.sleep(1)
    elif args.case == "repeated":
        for n in range(6):
            fail(n)
            time.sleep(0.5)
        time.sleep(3)
        for n in range(6, 12):
            fail(n)
            time.sleep(0.5)


if __name__ == "__main__":
    main()
