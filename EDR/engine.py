"""
engine.py - the detection engine for the EDR7 mini-EDR.

Loads rules from rules/*.yaml and turns Events into Alerts. Detection logic
lives in the rules, not in the agents, so the EDR is customisable without
code changes (the client requirement).

The engine is the only place that:
  - matches events against everyone's rules
  - counts threshold attacks (brute force) over a time window
  - tags each alert with its MITRE technique
  - stamps the MTTD (detected_at - observed_at)
"""

import glob
import os
import re
import time
from collections import defaultdict, deque

import yaml

from edr_core import Alert

# cooldown for repeat alerts from the same rule + key, in seconds
DEDUP_WINDOW = 30


class Rule:
    """One detection rule loaded from a YAML entry."""

    def __init__(self, raw: dict):
        self.id = raw["id"]
        self.title = raw["title"]
        self.owner = raw.get("owner", "")
        self.event_type = raw["event_type"]
        self.severity = raw.get("severity", "MEDIUM")
        self.mitre = raw.get("mitre", "")
        self.conditions = raw.get("conditions", [])
        self.threshold = raw.get("threshold")        # dict or None
        self.response = raw.get("response", "none")
        for cond in self.conditions:                 # pre-compile regexes once
            if cond.get("op") == "regex":
                cond["_rx"] = re.compile(str(cond["value"]), re.I)

    def event_matches(self, event) -> bool:
        """True if the event type matches and every per-event condition holds."""
        if event.event_type != self.event_type:
            return False
        return all(_check(cond, event.data) for cond in self.conditions)


def _check(cond: dict, data: dict) -> bool:
    actual = data.get(cond["field"])
    op = cond["op"]
    value = cond.get("value")
    if actual is None:
        return False
    if op == "equals":
        return str(actual) == str(value)
    if op == "in":
        return actual in value
    if op == "regex":
        return bool(cond["_rx"].search(str(actual)))
    if op == "contains":
        return str(value) in str(actual)
    if op == "gt":
        try:
            return float(actual) > float(value)
        except (TypeError, ValueError):
            return False
    if op == "lt":
        try:
            return float(actual) < float(value)
        except (TypeError, ValueError):
            return False
    return False


class DetectionEngine:
    def __init__(self):
        self.rules = []
        self.windows = defaultdict(deque)     # (rule_id, group_val) -> deque[observed_at]
        self.recent = {}                      # (rule_id, dedup_key) -> last_detected_at

    def load_rules(self, path: str) -> int:
        """Load every *.yaml under a folder, or a single file. Returns rule count."""
        if os.path.isdir(path):
            files = sorted(glob.glob(os.path.join(path, "*.yaml")) +
                           glob.glob(os.path.join(path, "*.yml")))
        elif os.path.isfile(path):
            files = [path]
        else:
            print(f"[engine] no rules found at {path}")
            return 0
        for fpath in files:
            try:
                with open(fpath) as fh:
                    loaded = yaml.safe_load(fh) or []
                for raw in loaded:
                    self.rules.append(Rule(raw))
            except Exception as err:
                print(f"[engine] failed to load {fpath}: {err}")
        return len(self.rules)

    def evaluate(self, events) -> list:
        """Run every event against every rule and return a list of Alerts."""
        alerts = []
        for event in events:
            for rule in self.rules:
                if not rule.event_matches(event):
                    continue
                alert = (self._threshold(rule, event) if rule.threshold
                         else self._single(rule, event))
                if alert:
                    alerts.append(alert)
        return alerts

    def _single(self, rule, event):
        key = (event.data.get("ip") or event.data.get("pid")
               or event.data.get("path") or "")
        if self._is_duplicate(rule, key):
            return None
        return self._build(rule, [event], event.observed_at)

    def _threshold(self, rule, event):
        t = rule.threshold
        group_val = event.data.get(t.get("group_by", "ip"), "")
        bucket = self.windows[(rule.id, group_val)]
        bucket.append(event.observed_at)
        window = t.get("window_s", 60)
        while bucket and event.observed_at - bucket[0] > window:
            bucket.popleft()
        if len(bucket) >= t.get("count", 5):
            first = bucket[0]
            bucket.clear()               # reset so we do not alert on every later hit
            return self._build(rule, [event], first)
        return None

    def _is_duplicate(self, rule, key):
        now = time.time()
        last = self.recent.get((rule.id, key))
        self.recent[(rule.id, key)] = now
        return last is not None and now - last < DEDUP_WINDOW

    def _build(self, rule, events, observed_at):
        detected_at = time.time()
        return Alert(
            rule_id=rule.id,
            title=rule.title,
            severity=rule.severity,
            mitre=rule.mitre,
            agent=events[-1].agent,
            observed_at=observed_at,
            detected_at=detected_at,
            mttd_s=round(detected_at - observed_at, 3),
            event_ids=[e.event_id for e in events],
            details=dict(events[-1].data),
            response={"action": rule.response, "outcome": "pending"},
        )
