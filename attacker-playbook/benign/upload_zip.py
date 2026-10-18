import os
import zipfile
import requests

URL = os.environ.get("JS_TARGET", "http://192.168.100.51:3000").rstrip("/") + "/file-upload"
TOKEN = os.environ.get("JS_TOKEN", "")
HEADERS = {"Authorization": f"Bearer {TOKEN}"}

os.makedirs("payloads", exist_ok=True)
os.chdir("payloads")

# zip is an allowed type per Juice Shop's own upload config, should not trip FILE-UPLOAD-002
with zipfile.ZipFile("legit.zip", "w") as z:
    z.writestr("readme.txt", "normal zip contents")

with open("legit.zip", "rb") as f:
    files = {"file": ("legit.zip", f, "application/zip")}
    r = requests.post(URL, headers=HEADERS, files=files, timeout=5)

print(f"[*] Normal ZIP upload | Status: {r.status_code}")
