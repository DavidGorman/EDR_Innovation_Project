import os
import time
import requests

URL = os.environ.get("JS_TARGET", "http://192.168.100.51:3000").rstrip("/") + "/file-upload"
TOKEN = os.environ.get("JS_TOKEN", "")
HEADERS = {"Authorization": f"Bearer {TOKEN}"}

os.makedirs("payloads", exist_ok=True)
os.chdir("payloads")

# one upload only, well spaced out - should not trip the FILE-UPLOAD-004 threshold
with open("slow_upload.pdf", "w") as f:
    f.write("%PDF-1.4 single normal upload")

with open("slow_upload.pdf", "rb") as f:
    files = {"file": ("slow_upload.pdf", f, "application/pdf")}
    r = requests.post(URL, headers=HEADERS, files=files, timeout=5)

print(f"[*] Single slow PDF upload | Status: {r.status_code}")
time.sleep(25)
print("[*] Done waiting - outside the 20s threshold window")
