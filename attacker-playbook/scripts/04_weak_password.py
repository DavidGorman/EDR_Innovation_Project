import os
import requests
import time

BASE = os.environ.get("JS_TARGET", "http://192.168.100.51:3000").rstrip("/")
URL = f"{BASE}/rest/user/login"

email = os.environ.get("JS_EMAIL", "admin@juice-sh.op")
password = os.environ.get("JS_PASSWORD", "admin123")

for i in range(10):
    print(f"[*] Attempt {i+1}")
    r = requests.post(URL, json={"email": email, "password": password}, timeout=5)
    print("Status:", r.status_code)
    print("Body:", r.text)
    time.sleep(1)
