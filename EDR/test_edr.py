"""
test_edr.py - quick offline checks for the engine and the agent parsers.

Run:  python3 test_edr.py

These do NOT need the VM, auditd or Juice Shop. They feed synthetic data in
and check the right thing comes out. Use them after any change to the engine,
the web parser or the audit parser before you push.
"""

import os
import tempfile
import time

from edr_core import Event
from engine import DetectionEngine


def test_rce_rule_fires():
    eng = DetectionEngine()
    eng.load_rules("rules")
    ev = Event(agent="process-agent", event_type="process_start",
               observed_at=time.time(),
               data={"parent_name": "node", "name": "sh", "pid": "999",
                     "ppid": "100", "cmdline": "sh -c id", "user": "juiceshop"})
    alerts = eng.evaluate([ev])
    assert any(a.rule_id == "PROC-RCE-001" for a in alerts), "RCE rule did not fire"
    a = next(a for a in alerts if a.rule_id == "PROC-RCE-001")
    assert a.mitre == "T1059.004"
    assert a.response["action"] == "kill_process"
    print("ok: RCE rule fires with the right MITRE id and response")


def test_benign_process_is_quiet():
    eng = DetectionEngine()
    eng.load_rules("rules")
    ev = Event(agent="process-agent", event_type="process_start",
               observed_at=time.time(),
               data={"parent_name": "systemd", "name": "node", "pid": "1",
                     "ppid": "0", "cmdline": "node app.js", "user": "juiceshop"})
    alerts = eng.evaluate([ev])
    assert not alerts, f"false positive on a normal process: {[a.rule_id for a in alerts]}"
    print("ok: a normal Juice Shop process raises nothing (true negative)")


def test_mttd_is_stamped():
    eng = DetectionEngine()
    eng.load_rules("rules")
    observed = time.time() - 1.5           # pretend it happened 1.5s ago
    ev = Event(agent="process-agent", event_type="process_start",
               observed_at=observed,
               data={"parent_name": "node", "name": "bash", "pid": "42",
                     "ppid": "9", "cmdline": "bash -i", "user": "juiceshop"})
    alert = eng.evaluate([ev])[0]
    assert alert.mttd_s >= 1.5, f"mttd too small: {alert.mttd_s}"
    assert alert.observed_at == observed
    print(f"ok: MTTD stamped ({alert.mttd_s:.2f}s from observed_at)")


def test_process_agent_parses_audit():
    from agent_process import ProcessAgent
    fd, path = tempfile.mkstemp()
    os.close(fd)
    agent = ProcessAgent(audit_log=path, interval=1)
    sample = (
        'type=SYSCALL msg=audit(1760425802.123:456): arch=c000003e syscall=59 '
        'success=yes exit=0 ppid=1200 pid=5678 uid=1000 gid=1000 comm="sh" '
        'exe="/usr/bin/dash" key="proc_exec"\n'
        'type=EXECVE msg=audit(1760425802.123:456): argc=3 a0="sh" a1="-c" a2="id"\n'
    )
    with open(path, "a") as fh:
        fh.write(sample)
    events = agent.collect()
    os.unlink(path)
    assert len(events) == 1, f"expected 1 event, got {len(events)}"
    e = events[0]
    assert e.data["name"] == "sh", e.data
    assert e.data["cmdline"] == "sh -c id", e.data
    assert abs(e.observed_at - 1760425802.123) < 0.001
    print("ok: process-agent parses an execve record from audit.log")


def test_audit_record_without_key_is_ignored():
    from agent_process import ProcessAgent
    fd, path = tempfile.mkstemp()
    os.close(fd)
    agent = ProcessAgent(audit_log=path, interval=1)
    # a SYSCALL with a different key must not produce an event
    noise = ('type=SYSCALL msg=audit(1760425900.000:999): syscall=59 '
             'ppid=1 pid=2 uid=0 comm="systemctl" exe="/usr/bin/systemctl" '
             'key="other_key"\n')
    with open(path, "a") as fh:
        fh.write(noise)
    events = agent.collect()
    os.unlink(path)
    assert events == [], f"should ignore records without our key: {events}"
    print("ok: audit records without the proc_exec key are ignored")


def test_web_agent_parses_and_decodes():
    from agent_web import WebAgent
    fd, path = tempfile.mkstemp()
    os.close(fd)
    agent = WebAgent(path, interval=1)
    line = ('192.168.100.10 - - [10/Oct/2026:13:55:36 +1100] '
            '"GET /rest/products/search?q=%27%20OR%201%3D1-- HTTP/1.1" 500 '
            '120 "-" "sqlmap/1.7"\n')
    with open(path, "a") as fh:
        fh.write(line)
    events = agent.collect()
    os.unlink(path)
    assert len(events) == 1, f"expected 1 event, got {len(events)}"
    e = events[0]
    assert e.data["ip"] == "192.168.100.10", e.data
    assert e.data["status"] == 500 and isinstance(e.data["status"], int)
    assert "' OR 1=1--" in e.data["path"], e.data["path"]       # decoded
    assert e.data["user_agent"] == "sqlmap/1.7", e.data
    print("ok: web-agent parses a request and URL-decodes the path")


def test_brute_force_threshold():
    """Five failed logins from one IP inside the window should fire once."""
    import yaml
    rule = {"id": "WEB-BRUTE-TEST", "title": "brute", "owner": "test",
            "event_type": "http_request", "severity": "HIGH",
            "mitre": "T1110.001",
            "conditions": [{"field": "path", "op": "regex", "value": "login"},
                           {"field": "status", "op": "in", "value": [401]}],
            "threshold": {"count": 5, "window_s": 15, "group_by": "ip"},
            "response": "block_ip"}
    fd, path = tempfile.mkstemp(suffix=".yaml")
    with os.fdopen(fd, "w") as fh:
        yaml.safe_dump([rule], fh)
    eng = DetectionEngine()
    eng.load_rules(path)
    os.unlink(path)
    base = time.time()
    fired = 0
    for i in range(6):
        ev = Event(agent="web-agent", event_type="http_request",
                   observed_at=base + i,
                   data={"ip": "10.0.0.9", "path": "/rest/user/login", "status": 401})
        fired += len(eng.evaluate([ev]))
    assert fired == 1, f"expected exactly 1 brute-force alert, got {fired}"
    print("ok: brute-force threshold fires once at 5 failures, not on every hit")


if __name__ == "__main__":
    test_rce_rule_fires()
    test_benign_process_is_quiet()
    test_mttd_is_stamped()
    test_process_agent_parses_audit()
    test_audit_record_without_key_is_ignored()
    test_web_agent_parses_and_decodes()
    test_brute_force_threshold()
    print("\nall checks passed")
