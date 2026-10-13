import os
import requests

BASE = os.environ.get("JS_TARGET", "http://192.168.100.51:3000").rstrip("/")
URL = f"{BASE}/rest/user/login"

# Step 1: Login normally
data = {"email": os.environ.get("JS_EMAIL", "admin@juice-sh.op"),
        "password": os.environ.get("JS_PASSWORD", "admin123")}
r = requests.post(URL, json=data, timeout=5)

try:
    token = r.json().get("authentication", {}).get("token")
except requests.exceptions.JSONDecodeError:
    print("Login did not return JSON:", r.status_code, r.text)
    raise SystemExit(1)

if not token:
    print("Login failed, no token returned:", r.status_code, r.text)
    raise SystemExit(1)

session = requests.Session()
session.headers.update({"Authorization": f"Bearer {token}"})

# Step 2: Replace token with invalid one
session.headers["Authorization"] = "Bearer invalid_token"

# Step 3: Test protected endpoint
resp = session.get(f"{BASE}/rest/user/whoami", timeout=5)

print("Status:", resp.status_code)
print("Body:", resp.text)
