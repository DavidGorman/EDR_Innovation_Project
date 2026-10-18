#!/usr/bin/env python3
# Owner: David. Performs the response named by each rule (block_ip,
# kill_process, quarantine_file). Dry-run by default; a response never crashes
# the EDR and a target already handled is skipped.

import os
import shutil
import signal
import subprocess
import time

from edr_core import LAB_DIR, GREEN, RESET

QUARANTINE = os.path.join(LAB_DIR, "quarantine")


class Responder:
    def __init__(self, respond_enabled: bool = False):
        self.respond_enabled = respond_enabled
        self.blocked_ips = set()
        self.killed_pids = set()
        os.makedirs(QUARANTINE, exist_ok=True)

    def handle(self, alert) -> None:
        action = alert.response.get("action", "none")
        if action == "none":
            alert.response["outcome"] = "none"
            return
        handler = getattr(self, f"_{action}", None)
        if handler is None:
            alert.response["outcome"] = "unknown-action"
            return
        target = self._target(action, alert)
        if not self.respond_enabled:
            alert.response["outcome"] = "dry-run"
            print(f"      [DRY-RUN] would: {action} {target}  (use --respond)")
            return
        try:
            handler(alert)
            alert.response["outcome"] = "performed"
            print(f"      {GREEN}[RESPONSE] {action} {target}{RESET}")
        except Exception as err:
            alert.response["outcome"] = f"failed: {err}"
            print(f"      [RESPONSE FAILED] {action} {target}: {err}")

    def _target(self, action, alert):
        d = alert.details
        return {"block_ip": d.get("ip"),
                "kill_process": d.get("pid"),
                "quarantine_file": d.get("path")}.get(action, "")

    def _block_ip(self, alert):
        ip = alert.details.get("ip")
        if not ip or ip in self.blocked_ips:
            return
        ip = ip.removeprefix("::ffff:")   # IPv4-mapped IPv6 -> plain IPv4
        subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                       check=True, capture_output=True)
        self.blocked_ips.add(ip)

    def _kill_process(self, alert):
        pid = alert.details.get("pid")
        if not pid or pid in self.killed_pids:
            return
        os.kill(int(pid), signal.SIGKILL)
        self.killed_pids.add(pid)

    def _quarantine_file(self, alert):
        path = alert.details.get("path")
        if not path or not os.path.exists(path):
            return
        dest = os.path.join(QUARANTINE,
                            f"{int(time.time())}_{os.path.basename(path)}")
        shutil.move(path, dest)
