#!/usr/bin/env python3
# Owner: David. Shared core for the EDR7 mini-EDR: the Event and Alert types,
# the Agent base class (subclasses implement collect() only), and the AlertSink
# that prints alerts and writes them to alerts.jsonl.

import argparse
import datetime
import json
import os
import socket
import time
import uuid
from dataclasses import dataclass, field, asdict

LAB_DIR = os.path.expanduser(os.environ.get("EDR_LAB_DIR", "~/edr_lab"))
ALERT_LOG = os.path.join(LAB_DIR, "alerts.jsonl")

COLOURS = {"LOW": "\033[94m", "MEDIUM": "\033[93m", "HIGH": "\033[91m"}
GREEN = "\033[92m"
RESET = "\033[0m"


def now_iso():
    return datetime.datetime.now().isoformat(timespec="seconds")


@dataclass
class Event:
    agent: str
    event_type: str                 # http_request | process_start | file_change | net_connection
    observed_at: float              # epoch seconds, from the source (never poll time)
    data: dict = field(default_factory=dict)
    host: str = field(default_factory=socket.gethostname)
    collected_at: float = field(default_factory=time.time)
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))


@dataclass
class Alert:
    rule_id: str
    title: str
    severity: str                   # LOW | MEDIUM | HIGH
    mitre: str
    agent: str
    observed_at: float
    detected_at: float
    mttd_s: float
    event_ids: list = field(default_factory=list)
    details: dict = field(default_factory=dict)
    response: dict = field(default_factory=dict)
    alert_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=now_iso)


class Agent:
    name = "base-agent"

    def __init__(self, interval: float = 2.0):
        self.interval = interval

    def collect(self) -> list:
        # Return new Events since the last call. Must never raise.
        raise NotImplementedError


class AlertSink:
    def __init__(self, path: str = ALERT_LOG):
        self.path = path
        os.makedirs(os.path.dirname(path), exist_ok=True)

    def show(self, alert: Alert) -> None:
        colour = COLOURS.get(alert.severity, "")
        print(f"{colour}[{alert.timestamp}] [{alert.severity}] "
              f"{alert.agent}: {alert.title} "
              f"({alert.rule_id}, {alert.mitre}) MTTD {alert.mttd_s:.2f}s{RESET}")
        for key, value in alert.details.items():
            print(f"      {key}: {value}")

    def persist(self, alert: Alert) -> None:
        with open(self.path, "a") as log:
            log.write(json.dumps(asdict(alert)) + "\n")


def base_parser(description: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--respond", action="store_true",
                        help="actually perform responses (default is dry-run)")
    parser.add_argument("--interval", type=float, default=2.0,
                        help="seconds between checks (default 2)")
    parser.add_argument("--rules", default="rules",
                        help="folder of rule YAML files (default ./rules)")
    return parser
