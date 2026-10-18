#!/usr/bin/env python3
# Owner: Oliver. Benign login activity that must NOT trip WEB-BRUTE-001.
# Each --case stays under 5 failures per 15s (mistyped-password, slow-failures,
# shared-ip) to prove the threshold does not fire on normal users.

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
GOOD = os.environ.get("JS_PASSWORD", "admin123")


def attempt(email, password):
    try:
        r = requests.post(URL, json={"email": email, "password": password}, timeout=5)
        print(f"[benign] {email} / {password!r} -> {r.status_code}")
    except requests.RequestException as e:
        print(f"[benign] request failed: {e}")


def main():
    p = argparse.ArgumentParser(description="Benign login activity (lab use)")
    p.add_argument("--case", required=True,
                   choices=["mistyped-password", "slow-failures", "shared-ip"])
    args = p.parse_args()

    if args.case == "mistyped-password":
        for pw in ["Wrong1", "Wrong2", "Wrong3", "Wrong4"]:
            attempt(EMAIL, pw)
            time.sleep(1)
        attempt(EMAIL, GOOD)

    elif args.case == "slow-failures":
        for pw in ["nope1", "nope2", "nope3", "nope4", "nope5"]:
            attempt(EMAIL, pw)
            time.sleep(4)

    elif args.case == "shared-ip":
        for user in ["alice@juice-sh.op", "bob@juice-sh.op",
                     "carol@juice-sh.op", "dave@juice-sh.op"]:
            attempt(user, "oops")
            time.sleep(1)


if __name__ == "__main__":
    main()
