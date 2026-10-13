#!/usr/bin/env python3
"""
run_all.py  -  one-command attacker playbook for the ICT30016 EDR project.

Runs every attack in this folder against your lab OWASP Juice Shop, in order,
and writes a single timeline to attack_log.csv (timestamp_utc,attack,event) so
detections in Wazuh / Sysmon / auditd can be matched back to the attack that
caused them (MTTD).

    python3 run_all.py                 # run the whole suite with the config below
    python3 run_all.py --quick         # same, but no gaps and fast brute force
    python3 run_all.py --target http://10.0.0.5:3000
    python3 run_all.py --only sqli,brute_force
    python3 run_all.py --skip rce,ssti
    python3 run_all.py --list          # show attack names and exit

Runs on Kali (the intended attacker box) or on Windows -- it only sends HTTP,
so either works. Needs: python3, and `pip install requests`.

SCOPE: isolated host-only lab only. Point this only at a Juice Shop you own and
are authorised to test.

------------------------------------------------------------------------------
CONFIG -- the only place you edit. Everything below reads from this block.
------------------------------------------------------------------------------
"""

import argparse
import datetime
import os
import re
import subprocess
import sys

# ---- EDIT THESE ----
TARGET   = "http://192.168.100.51:3000"   # your Juice Shop base URL (ip:port)
EMAIL    = "admin@juice-sh.op"            # account used by the auth/brute attacks
PASSWORD = "admin123"                     # its current password
NEWPASS  = "NewPass123!"                  # what attack 9 changes it to (then restored)
WORDLIST = "wordlist.txt"                 # brute-force list (relative to this folder)
SQLI_PAYLOADS = "payloads.txt"            # SQLi payload list for the sqli attack
GAP      = 90                             # seconds between attacks (separates MTTD windows)
RCE_MODE = "all"                          # dos-loop | redos | dos-occupy | cmdexec | all
# --------------------

HERE = os.path.dirname(os.path.abspath(__file__))
LOG  = os.path.join(HERE, "attack_log.csv")
PY   = sys.executable or "python3"        # same interpreter, portable across OSes


def now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") \
        + f"{datetime.datetime.now(datetime.timezone.utc).microsecond // 1000:03d}Z"


def log_event(attack, event):
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(f"{now()},{attack},{event}\n")


def banner(name, detail=""):
    print("\n" + "=" * 60)
    print(f"[*] {name}  {detail}")
    print(f"    start: {now()}")


def run(cmd, env):
    """Run a sub-attack, stream its output, return captured stdout."""
    print(f"    $ {' '.join(cmd)}")
    try:
        proc = subprocess.Popen(cmd, cwd=HERE, env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, bufsize=1)
    except FileNotFoundError as e:
        print(f"    [!] could not launch: {e}")
        return ""
    out_lines = []
    for line in proc.stdout:
        sys.stdout.write("    | " + line)
        out_lines.append(line)
    proc.wait()
    if proc.returncode != 0:
        print(f"    [!] exit code {proc.returncode} (continuing)")
    return "".join(out_lines)


def main():
    ap = argparse.ArgumentParser(description="One-command Juice Shop attack suite (lab only)")
    ap.add_argument("--target", default=TARGET, help="Juice Shop base URL")
    ap.add_argument("--email", default=EMAIL)
    ap.add_argument("--password", default=PASSWORD)
    ap.add_argument("--wordlist", default=WORDLIST)
    ap.add_argument("--sqli-payloads", default=SQLI_PAYLOADS,
                    help="SQLi payload list for the sqli attack")
    ap.add_argument("--gap", type=float, default=GAP, help="seconds between attacks")
    ap.add_argument("--quick", action="store_true",
                    help="no gaps, fast brute force (smoke test, not for MTTD timing)")
    ap.add_argument("--only", help="comma-separated attack names to run (only these)")
    ap.add_argument("--skip", help="comma-separated attack names to skip")
    ap.add_argument("--no-restore", action="store_true",
                    help="don't change the password back after attack 9")
    ap.add_argument("--list", action="store_true", help="list attack names and exit")
    args = ap.parse_args()

    target = args.target.rstrip("/")
    gap = 0 if args.quick else args.gap

    # Shared config handed to every sub-script via the environment. The patched
    # scripts read these; unpatched ones (sqli/rce/ssti) get it on the CLI below.
    env = dict(os.environ)
    env.update({
        "JS_TARGET": target,
        "JS_EMAIL": args.email,
        "JS_PASSWORD": args.password,
        "JS_WORDLIST": args.wordlist,
        "JS_NEWPASS": NEWPASS,
        "JS_BRUTE_DELAY": "0" if args.quick else "1",
        "PYTHONUNBUFFERED": "1",
    })

    # Attack order: benign baseline first, password-change last (it mutates the
    # account), then restore. Each entry is (name, callable(env)).
    def a_normal(e):   run([PY, "scripts/01_normal_login.py"], e)
    def a_sqli(e):     run([PY, "scripts/02_sqli.py", target, args.sqli_payloads], e)
    def a_brute(e):    run([PY, "scripts/03_brute_force.py"], e)
    def a_weakpw(e):   run([PY, "scripts/04_weak_password.py"], e)
    def a_jwt(e):
        out = run([PY, "scripts/05_jwt_get_token.py"], e)      # get a fresh token
        m = re.search(r"Token:\s*(eyJ[\w.\-]+)", out)       # fix: hand it to 3b
        if m:
            e = dict(e); e["JS_TOKEN"] = m.group(1)
            print("    [+] captured fresh JWT, reusing it in step 3b")
        else:
            print("    [!] no token captured; 3b will fall back to its stored token")
        run([PY, "scripts/06_jwt_reuse_token.py"], e)
    def a_invalid(e):  run([PY, "scripts/07_invalid_token.py"], e)
    def a_ssti(e):     run([PY, "scripts/08_ssti.py",
                            "--target", target, "--email", args.email,
                            "--password", args.password], e)
    def a_rce(e):      run([PY, "scripts/09_rce.py",
                            "--target", target, "--mode", RCE_MODE], e)
    def a_pwchange(e): run([PY, "scripts/10_password_change.py"], e)

    ATTACKS = [
        ("normal_login", a_normal),
        ("sqli", a_sqli),
        ("brute_force", a_brute),
        ("weak_password", a_weakpw),
        ("jwt_reuse", a_jwt),
        ("invalid_token", a_invalid),
        ("ssti", a_ssti),
        ("rce", a_rce),
        ("password_change_no_old", a_pwchange),
    ]

    if args.list:
        print("Attacks:", ", ".join(n for n, _ in ATTACKS))
        return

    names = [n for n, _ in ATTACKS]
    only = {s.strip() for s in args.only.split(",")} if args.only else None
    skip = {s.strip() for s in args.skip.split(",")} if args.skip else set()
    selected = [(n, fn) for n, fn in ATTACKS
                if (only is None or n in only) and n not in skip]

    bad = (only or set()) - set(names) | (skip - set(names))
    if bad:
        print(f"[!] unknown attack name(s): {', '.join(sorted(bad))}")
        print(f"    valid: {', '.join(names)}")
        return

    # Fresh log with header each run (matches the old run_suite.sh format).
    with open(LOG, "w", encoding="utf-8") as f:
        f.write("timestamp_utc,attack,event\n")

    print(f"Suite start: {now()}")
    print(f"Target: {target}   Account: {args.email}")
    print(f"Gap between attacks: {gap}s   Logging to: {LOG}")
    print(f"Running {len(selected)} attack(s): {', '.join(n for n, _ in selected)}")

    ran_pwchange = False
    for i, (name, fn) in enumerate(selected):
        banner(name)
        log_event(name, "start")
        try:
            fn(env)
        except Exception as e:  # one broken attack shouldn't kill the suite
            print(f"    [!] {name} raised: {e}")
        log_event(name, "end")
        print(f"    end:   {now()}")
        if name == "password_change_no_old":
            ran_pwchange = True
        if gap and i < len(selected) - 1:
            print(f"\n[*] waiting {gap}s so alert windows don't overlap...")
            __import__("time").sleep(gap)

    # The password-change attack leaves the account on NEWPASS, which would break
    # the next run. Put it back so the suite is repeatable.
    if ran_pwchange and not args.no_restore:
        banner("restore_password", "(housekeeping, not an attack)")
        try:
            import requests
            requests.packages.urllib3.disable_warnings()
            r = requests.post(f"{target}/rest/user/login",
                              json={"email": args.email, "password": NEWPASS}, timeout=10)
            tok = r.json().get("authentication", {}).get("token")
            if tok:
                requests.get(f"{target}/rest/user/change-password",
                             headers={"Authorization": f"Bearer {tok}"},
                             params={"new": args.password, "repeat": args.password},
                             timeout=10)
                print(f"    [+] password restored to the configured one")
            else:
                print(f"    [!] could not log in with {NEWPASS} to restore; "
                      f"reset the VM or change it back manually")
        except Exception as e:
            print(f"    [!] restore failed: {e} (reset the VM snapshot instead)")

    print("\n" + "=" * 60)
    print(f"Suite finished: {now()}")
    print(f"Timeline: {LOG}")


if __name__ == "__main__":
    main()
