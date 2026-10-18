import os
import requests

URL = os.environ.get("JS_TARGET", "http://192.168.100.51:3000").rstrip("/") + "/file-upload"
TOKEN = os.environ.get("JS_TOKEN", "")
HEADERS = {"Authorization": f"Bearer {TOKEN}"}

os.makedirs("payloads", exist_ok=True)
os.chdir("payloads")

# just under Juice Shop's stated 100000 byte limit - should not trip FILE-UPLOAD-003
with open("under_limit.pdf", "wb") as f:
    f.write(b"\x00" * 95000)

with open("under_limit.pdf", "rb") as f:
    files = {"file": ("under_limit.pdf", f, "application/pdf")}
    r = requests.post(URL, headers=HEADERS, files=files, timeout=5)

print(f"[*] Under-limit PDF upload | Status: {r.status_code}")
