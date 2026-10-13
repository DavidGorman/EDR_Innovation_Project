import os
import requests

BASE = os.environ.get("JS_TARGET", "http://192.168.100.51:3000").rstrip("/")
URL = f"{BASE}/rest/user/login"

data = {"email": os.environ.get("JS_EMAIL", "admin@juice-sh.op"),
        "password": os.environ.get("JS_PASSWORD", "admin123")}
r = requests.post(URL, json=data, timeout=5)

print("Status:", r.status_code)
try:
    token = r.json().get("authentication", {}).get("token")
    print("Token:", token)
    print("\nCopy the token above into TOKEN in step B.")
except requests.exceptions.JSONDecodeError:
    print("Response (not JSON):", r.text)
