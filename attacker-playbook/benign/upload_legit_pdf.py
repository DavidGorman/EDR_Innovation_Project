import os
import requests

URL = os.environ.get("JS_TARGET", "http://192.168.100.51:3000").rstrip("/") + "/file-upload"
TOKEN = os.environ.get("JS_TOKEN", "")
HEADERS = {"Authorization": f"Bearer {TOKEN}"}

os.makedirs("payloads", exist_ok=True)
os.chdir("payloads")

with open("legit.pdf", "w") as f:
    f.write("%PDF-1.4 normal user upload")

with open("legit.pdf", "rb") as f:
    files = {"file": ("legit.pdf", f, "application/pdf")}
    r = requests.post(URL, headers=HEADERS, files=files, timeout=5)

print(f"[*] Normal PDF upload | Status: {r.status_code}")
