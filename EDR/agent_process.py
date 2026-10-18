#!/usr/bin/env python3
# Owner: David. RCE telemetry for the EDR7 mini-EDR. Reads auditd's execve
# records from /var/log/audit/audit.log and emits one process_start Event per
# command, which catches short-lived RCE commands that polling would miss.
# Run the EDR with sudo so this can read audit.log.

import os
import pwd
import re

from edr_core import Agent, Event, base_parser

AUDIT_LOG = "/var/log/audit/audit.log"

MSG_RE = re.compile(r"audit\((?P<ts>\d+\.\d+):(?P<id>\d+)\)")
FIELD_RE = re.compile(r'(\w+)=("[^"]*"|\S+)')


def _unquote(v):
    return v[1:-1] if len(v) >= 2 and v[0] == '"' else v


def _arg_value(raw_v):
    # auditd hex-encodes execve args containing spaces/special chars; decode them.
    if raw_v.startswith('"'):
        return _unquote(raw_v)
    try:
        return bytes.fromhex(raw_v).decode("utf-8", "replace")
    except ValueError:
        return raw_v


def _parent_name(ppid):
    try:
        with open(f"/proc/{ppid}/comm") as fh:
            return fh.read().strip()
    except (OSError, ValueError):
        return ""


def _user_name(uid):
    try:
        return pwd.getpwuid(int(uid)).pw_name
    except (KeyError, ValueError):
        return str(uid)


class ProcessAgent(Agent):
    name = "process-agent"

    def __init__(self, audit_log=AUDIT_LOG, key="proc_exec", **kwargs):
        super().__init__(**kwargs)
        self.audit_log = audit_log
        self.key = key
        self.fh = None
        self._open()

    def _open(self):
        if not os.path.exists(self.audit_log):
            return
        try:
            self.fh = open(self.audit_log, "r")
            self.fh.seek(0, os.SEEK_END)
        except PermissionError:
            print(f"[process-agent] cannot read {self.audit_log} (run the EDR with sudo)")
            self.fh = None

    def collect(self):
        try:
            return self._collect()
        except Exception as err:
            print(f"[process-agent] collect error: {err}")
            return []

    def _collect(self):
        if self.fh is None:
            self._open()
            if self.fh is None:
                return []
        try:
            if os.stat(self.audit_log).st_size < self.fh.tell():
                self.fh.close()                   # rotated or truncated
                self.fh = open(self.audit_log, "r")
        except FileNotFoundError:
            self.fh = None
            return []

        records = {}        # event id -> {ts, syscall fields, execve argv}
        for raw in self.fh.readlines():
            m = MSG_RE.search(raw)
            if not m:
                continue
            rec = records.setdefault(m.group("id"),
                                     {"ts": float(m.group("ts")),
                                      "syscall": None, "argv": None})
            raw_fields = dict(FIELD_RE.findall(raw))
            if raw.startswith("type=SYSCALL"):
                if _unquote(raw_fields.get("key", "")) == self.key:
                    rec["syscall"] = {k: _unquote(v) for k, v in raw_fields.items()}
            elif raw.startswith("type=EXECVE"):
                argc = int(raw_fields.get("argc", "0"))
                rec["argv"] = [_arg_value(raw_fields.get(f"a{i}", '""'))
                               for i in range(argc)]

        events = []
        for rec in records.values():
            s = rec["syscall"]
            if not s:
                continue
            comm = s.get("comm", "") or os.path.basename(s.get("exe", ""))
            ppid = s.get("ppid", "")
            cmdline = " ".join(rec["argv"]) if rec["argv"] else comm
            events.append(Event(
                agent=self.name,
                event_type="process_start",
                observed_at=rec["ts"],
                data={
                    "pid": s.get("pid", ""),
                    "ppid": ppid,
                    "name": comm,
                    "parent_name": _parent_name(ppid),
                    "cmdline": cmdline,
                    "user": _user_name(s.get("uid", "")),
                },
            ))
        return events


if __name__ == "__main__":
    import time
    p = base_parser("RCE process agent (auditd execve)")
    p.add_argument("--audit-log", default=AUDIT_LOG)
    a = p.parse_args()
    agent = ProcessAgent(audit_log=a.audit_log, interval=a.interval)
    print(f"[*] {agent.name} tailing {a.audit_log}. Ctrl+C to stop.")
    try:
        while True:
            for e in agent.collect():
                print(e)
            time.sleep(a.interval)
    except KeyboardInterrupt:
        print(f"\n[*] {agent.name} stopped.")
