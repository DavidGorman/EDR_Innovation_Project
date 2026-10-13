import os
import requests
import json

BASE = os.environ.get("JS_TARGET", "http://192.168.100.51:3000").rstrip("/")
URL = f"{BASE}/rest/user/login"

email = os.environ.get("JS_EMAIL", "admin@juice-sh.op")
password = os.environ.get("JS_PASSWORD", "admin123")

r = requests.post(URL, json={"email": email, "password": password}, timeout=5)

print("Status:", r.status_code)
try:
    print("Response:", json.dumps(r.json(), indent=4))
except requests.exceptions.JSONDecodeError:
    print("Response (not JSON):", r.text)
