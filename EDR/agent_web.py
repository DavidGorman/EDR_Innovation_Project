"""
agent_web.py - HTTP telemetry for the EDR7 mini-EDR.

Owner: David (shared web-agent). Used by the SQLi, brute-force and
broken-auth slices, so it must stay stable.

Reads the Juice Shop access log and emits one http_request Event per request.
It only collects now; detection lives in the rules. Changes from the starter
code:
  - emits Events instead of doing its own detection and responding
  - follows daily log rotation (access.log, access.log.YYYY-MM-DD)
  - URL-decodes the path (twice) so encoded payloads are visible to rules
  - carries raw_path, method, status (int) and user_agent

Known limit: the access log records URLs only, never POST bodies. Attacks sent
in a request body (the login SQLi, the B2B order RCE) will not show up here.
Detect those by their side effects (status codes, processes, files).

Open question for the VM: earlier testing suggested Juice Shop logs to journald
(unit juiceshop.service), not to an access file. If that is true on our VM,
this agent needs a journald reader instead of a file reader. Flag it to David
and he will swap the source; the Events it emits stay the same either way.
"""

import glob
import os
import re
from datetime import datetime
from urllib.parse import unquote

from edr_core import Agent, Event, LAB_DIR, base_parser

# Lenient: pulls ip, method, path and status out of common/combined log lines.
LINE = re.compile(r'^(?P<ip>\S+).*?"(?P<method>\S+)\s(?P<path>\S+)[^"]*"\s(?P<status>\d{3})')
# Trailing "...referer" "user-agent" when present.
UA = re.compile(r'"[^"]*"\s+"(?P<ua>[^"]*)"\s*$')
# Bracketed timestamp: [10/Oct/2026:13:55:36 +1100]
TS = re.compile(r"\[([^\]]+)\]")


def _decode(path):
    return unquote(unquote(path))


def _log_time(raw):
    m = TS.search(raw)
    if not m:
        return None
    try:
        return datetime.strptime(m.group(1), "%d/%b/%Y:%H:%M:%S %z").timestamp()
    except ValueError:
        return None


class WebAgent(Agent):
    name = "web-agent"

    def __init__(self, log_path, **kwargs):
        super().__init__(**kwargs)
        self.log_path = log_path
        self.fh = None
        self.cur = None
        self._open_latest()

    def _latest_path(self):
        matches = sorted(glob.glob(self.log_path + "*"))
        return matches[-1] if matches else self.log_path

    def _open_latest(self):
        path = self._latest_path()
        if not os.path.exists(path):
            open(path, "a").close()               # make sure it exists
        self.fh = open(path, "r")
        self.fh.seek(0, os.SEEK_END)
        self.cur = path

    def collect(self):
        try:
            return self._collect()
        except Exception as err:
            print(f"[web-agent] collect error: {err}")
            return []

    def _collect(self):
        import time
        latest = self._latest_path()
        if latest != self.cur:                    # a new day's log appeared
            self.fh.close()
            self.fh = open(latest, "r")
            self.cur = latest
        elif os.path.exists(self.cur) and os.stat(self.cur).st_size < self.fh.tell():
            self.fh.close()                       # same file was truncated
            self.fh = open(self.cur, "r")

        events = []
        for raw in self.fh.readlines():
            m = LINE.match(raw)
            if not m:
                continue
            ua = UA.search(raw.rstrip())
            events.append(Event(
                agent=self.name,
                event_type="http_request",
                observed_at=_log_time(raw) or time.time(),
                data={
                    "ip": m.group("ip"),
                    "method": m.group("method"),
                    "path": _decode(m.group("path")),
                    "raw_path": m.group("path"),
                    "status": int(m.group("status")),
                    "user_agent": ua.group("ua") if ua else "",
                },
            ))
        return events


if __name__ == "__main__":
    import time
    p = base_parser("Web telemetry agent (Juice Shop access log)")
    p.add_argument("--log", default=os.path.join(LAB_DIR, "access.log"))
    a = p.parse_args()
    agent = WebAgent(a.log, interval=a.interval)
    print(f"[*] {agent.name} tailing {agent.cur}. Ctrl+C to stop.")
    try:
        while True:
            for e in agent.collect():
                print(e)
            time.sleep(a.interval)
    except KeyboardInterrupt:
        print(f"\n[*] {agent.name} stopped.")
