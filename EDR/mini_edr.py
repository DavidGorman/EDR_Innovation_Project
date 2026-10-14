"""
mini_edr.py - wires the agents, the detection engine and the responder together.

  agents.collect()  ->  engine.evaluate()  ->  AlertSink + Responder

Run on the Juice Shop VM:
  sudo python3 mini_edr.py              # dry-run: alerts only, nothing is touched
  sudo python3 mini_edr.py --respond    # perform responses (LAB ONLY)

sudo is needed so the process-agent can read audit.log.
"""

import os
import time

from edr_core import LAB_DIR, AlertSink, base_parser
from engine import DetectionEngine
from responder import Responder

from agent_web import WebAgent
from agent_process import ProcessAgent

# Louis's file-upload agent. Stays optional until agent_fim.py is in the folder,
# so the EDR still runs if it is missing.
try:
    from agent_fim import FileIntegrityAgent
    HAVE_FIM = True
except ImportError:
    HAVE_FIM = False


def build_agents(args):
    agents = [
        WebAgent(os.path.join(LAB_DIR, "access.log"), interval=args.interval),
        ProcessAgent(interval=args.interval),
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
                responder.handle(alert)      # sets the outcome
                sink.persist(alert)          # write after the outcome is known
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n[*] Mini-EDR shut down.")


if __name__ == "__main__":
    main()
