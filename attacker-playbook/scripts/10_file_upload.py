#!/usr/bin/env python3
"""
10_file_upload.py  -  file-upload attack + negative-control runner for Juice Shop.

Exercises the /file-upload endpoint to generate telemetry for the custom EDR /
Wazuh rules (FILE-UPLOAD-00x). Covers both the malicious cases that SHOULD trip
a rule and the benign "negative control" cases that should NOT, so detection
can be measured against a clean baseline.

    python3 10_file_upload.py --case all            # every case (default)
    python3 10_file_upload.py --case dangerous_extension
    python3 10_file_upload.py --case legit_pdf

Cases:
  benign (negative controls, should not alert):
    legit_pdf            normal small PDF upload
    under_limit          ~95 KB PDF, just under the 100000-byte limit (FILE-UPLOAD-003)
    zip                  a valid .zip, an allowed type (FILE-UPLOAD-002)
    slow                 one upload then a 25s wait, outside the threshold window (FILE-UPLOAD-004)
  malicious (should alert):
    renamed_extension    non-PDF bytes sent with a .pdf name + application/pdf
    dangerous_extension  a .php file spoofed as application/pdf
    oversized            ~150 KB, over the 100000-byte limit (FILE-UPLOAD-003)
    fuzz                 5 rapid uploads to trip the rate threshold (FILE-UPLOAD-004)

SCOPE: isolated host-only lab only. Point this only at a Juice Shop you own.

Config comes from the environment (set by run_all.py), with standalone defaults:
    JS_TARGET    base URL, default http://192.168.100.51:3000
    JS_TOKEN     JWT to authenticate the upload (optional)
    JS_EMAIL     used to log in for a token if JS_TOKEN is not set
    JS_PASSWORD  "
"""

import argparse
import os
import sys
import time
import zipfile

try:
    import requests
except ImportError:
    sys.exit("Missing dependency: pip install requests")

BASE = os.environ.get("JS_TARGET", "http://192.168.100.51:3000").rstrip("/")
URL = f"{BASE}/file-upload"
PAYLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "payloads")

BENIGN = ["legit_pdf", "under_limit", "zip", "slow"]
MALICIOUS = ["renamed_extension", "dangerous_extension", "oversized", "fuzz"]
ALL_CASES = BENIGN + MALICIOUS


def get_token():
    """Use JS_TOKEN if set, else log in with JS_EMAIL/JS_PASSWORD for a fresh one."""
    token = os.environ.get("JS_TOKEN", "")
    if token:
        return token
    email = os.environ.get("JS_EMAIL", "admin@juice-sh.op")
    password = os.environ.get("JS_PASSWORD", "admin123")
    try:
        r = requests.post(f"{BASE}/rest/user/login",
                          json={"email": email, "password": password}, timeout=10)
        token = r.json().get("authentication", {}).get("token", "")
        if token:
            print(f"[+] logged in as {email} for an upload token")
    except requests.RequestException as e:
        print(f"[!] login for token failed ({e}); uploading unauthenticated")
    return token


def send(headers, local_name, sent_name, content_type, data):
    """Write the payload to disk, POST it, report the status."""
    os.makedirs(PAYLOAD_DIR, exist_ok=True)
    path = os.path.join(PAYLOAD_DIR, local_name)
    mode = "wb" if isinstance(data, bytes) else "w"
    with open(path, mode) as f:
        f.write(data)
    try:
        with open(path, "rb") as f:
            files = {"file": (sent_name, f, content_type)}
            r = requests.post(URL, headers=headers, files=files, timeout=10)
        print(f"[*] sent {sent_name} as {content_type} | HTTP {r.status_code}")
        return r.status_code
    except requests.RequestException as e:
        print(f"[!] upload of {sent_name} failed: {e}")
        return None


# --- cases -----------------------------------------------------------------

def c_legit_pdf(h):
    send(h, "legit.pdf", "legit.pdf", "application/pdf", "%PDF-1.4 normal user upload")

def c_under_limit(h):
    send(h, "under_limit.pdf", "under_limit.pdf", "application/pdf", b"\x00" * 95000)

def c_zip(h):
    path = os.path.join(PAYLOAD_DIR, "legit.zip")
    os.makedirs(PAYLOAD_DIR, exist_ok=True)
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("readme.txt", "normal zip contents")
    with open(path, "rb") as f:
        files = {"file": ("legit.zip", f, "application/zip")}
        try:
            r = requests.post(URL, headers=h, files=files, timeout=10)
            print(f"[*] sent legit.zip as application/zip | HTTP {r.status_code}")
        except requests.RequestException as e:
            print(f"[!] zip upload failed: {e}")

def c_slow(h):
    send(h, "slow_upload.pdf", "slow_upload.pdf", "application/pdf",
         "%PDF-1.4 single normal upload")
    print("[*] waiting 25s (outside the FILE-UPLOAD-004 threshold window)...")
    time.sleep(25)
    print("[*] done waiting")

def c_renamed_extension(h):
    send(h, "malicious_renamed.pdf", "malicious_renamed.pdf", "application/pdf",
         "fake jpg content for testing")

def c_dangerous_extension(h):
    send(h, "shell.php", "shell.php", "application/pdf", "<?php echo 'test'; ?>")

def c_oversized(h):
    send(h, "oversized.pdf", "oversized.pdf", "application/pdf", b"\x00" * 150000)

def c_fuzz(h):
    for i in range(5):
        send(h, f"fuzz_{i}.pdf", f"fuzz_{i}.pdf", "application/pdf", f"fuzz attempt {i}")

CASES = {
    "legit_pdf": c_legit_pdf,
    "under_limit": c_under_limit,
    "zip": c_zip,
    "slow": c_slow,
    "renamed_extension": c_renamed_extension,
    "dangerous_extension": c_dangerous_extension,
    "oversized": c_oversized,
    "fuzz": c_fuzz,
}


def main():
    ap = argparse.ArgumentParser(description="Juice Shop file-upload runner (lab only)")
    ap.add_argument("--case", default="all", choices=["all", "benign", "malicious"] + ALL_CASES,
                    help="which case(s) to run (default: all)")
    args = ap.parse_args()

    requests.packages.urllib3.disable_warnings()

    if args.case == "all":
        selected = ALL_CASES
    elif args.case == "benign":
        selected = BENIGN
    elif args.case == "malicious":
        selected = MALICIOUS
    else:
        selected = [args.case]

    token = get_token()
    headers = {"Authorization": f"Bearer {token}"} if token else {}

    print(f"[*] target: {URL}")
    print(f"[*] running case(s): {', '.join(selected)}")
    for name in selected:
        print(f"\n=== {name} ===")
        CASES[name](headers)


if __name__ == "__main__":
    main()
