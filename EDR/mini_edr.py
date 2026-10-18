#!/usr/bin/env python3
# Owner: David. Wires the agents, the detection engine and the responder:
# agents.collect() -> engine.evaluate() -> AlertSink + Responder.
# Run on the Juice Shop VM: sudo python3 mini_edr.py [--respond]  (sudo is
# needed so the process-agent can read audit.log).

import os
import time

from edr_core import LAB_DIR, AlertSink, base_parser
from engine import DetectionEngine
from responder import Responder

from agent_web import WebAgent
from agent_process import ProcessAgent

# Louis's file agent stays optional, so the EDR still runs without it.
try:
    from agent_fim import FileIntegrityAgent
    HAVE_FIM = True
except ImportError:
    HAVE_FIM = False

# Juice Shop's dated access log on our VM; the web agent follows the rotation.
WEB_ACCESS_LOG = os.environ.get("JS_ACCESS_LOG",
                                "/home/juice/juice-shop/logs/access.log")


def build_agents(args):
    agents = [
        WebAgent(WEB_ACCESS_LOG, interval=args.interval),
        ProcessAgent(interval=args.interval, key="exec"),   # audit key on our VM
    ]
    if HAVE_FIM:
        agents.append(FileIntegrityAgent(interval=args.interval))
    else:
        print("[mini-edr] agent_fim not found, file-upload slice is off")
    return agents


def main():
    p = base_parser("Mini EDR - EDR7")
    args = p.parse_args()
    os.makedirs(LAB_DIR, exist_ok=True)

    engine = DetectionEngine()
    rule_count = engine.load_rules(args.rules)
    sink = AlertSink()
    responder = Responder(respond_enabled=args.respond)
    agents = build_agents(args)

    mode = "RESPOND" if args.respond else "DRY-RUN"
    print(f"[*] Mini-EDR online: {len(agents)} agents, {rule_count} rules, "
          f"{mode}. Ctrl+C to stop.\n")
    try:
        while True:
            events = []
            for agent in agents:
                events.extend(agent.collect())
            for alert in engine.evaluate(events):
                sink.show(alert)
                responder.handle(alert)
                sink.persist(alert)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n[*] Mini-EDR shut down.")


if __name__ == "__main__":
    main()
