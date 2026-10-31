# EDR7: a lightweight, rule-driven EDR for OWASP Juice Shop

A small Endpoint Detection and Response (EDR) tool built in Python by a five-person team for ICT30016 (Swinburne University, 2026). It watches a Linux host running [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/), detects five classes of web attack, tags each alert with a MITRE ATT&CK technique, records mean time to detect (MTTD), and can respond automatically. It was evaluated side by side against a Wazuh agent on the same host using the same attack runs.

> **Lab use only.** The attack scripts in `attacker-playbook/` are for an isolated, host-only lab running a Juice Shop instance you own. Credentials in this repo (`admin@juice-sh.op` / `admin123`) are Juice Shop's built-in defaults.

## How it works

```
 Kali (attacker)                     Juice Shop VM (Ubuntu)
 ┌──────────────────┐   HTTP   ┌──────────────────────────────────────────────┐
 │ attacker-playbook│ ───────▶ │ Juice Shop ──▶ access.log  ──▶ web agent     │
 │  run_eval.py     │          │            ──▶ auditd execve ──▶ process agent│
 │  attack_log.csv  │          │  uploads/  ──▶ watchdog    ──▶ FIM agent     │
 └──────────────────┘          │                     │ Events                 │
                               │                     ▼                        │
                               │          Detection engine (rules/*.yaml)     │
                               │                     │ Alerts (MITRE, MTTD)   │
                               │          ┌──────────┴──────────┐             │
                               │          ▼                     ▼             │
                               │   alerts.jsonl           Responder           │
                               │                (block_ip / kill_process /    │
                               │                 quarantine_file)             │
                               └──────────────────────────────────────────────┘
```

The design rule is **agents only collect, the engine detects, the responder acts.**

- **Agents** (`agent_*.py`) turn raw telemetry into `Event` objects and nothing else:
  - `agent_web.py` tails the Juice Shop access log, follows daily rotation and URL-decodes paths.
  - `agent_process.py` reads auditd `execve` records, so it catches short-lived commands that process polling would miss. It also decodes auditd's hex-encoded arguments and resolves the parent process.
  - `agent_fim.py` watches the upload folder with `watchdog` and hashes new files.
- **Detection engine** (`engine.py`) loads every rule from `rules/*.yaml` and matches events against them. It supports `equals`, `in`, `regex`, `contains`, `gt` and `lt` conditions, sliding-window thresholds (for brute force), a 30-second dedup window, and stamps each alert with MTTD measured from the time the source observed the event, not the poll time.
- **Responder** (`responder.py`) runs the action named by the rule. It is **dry-run by default** and only acts with `--respond`. A failed response is logged and never crashes the EDR.

Detection logic lives in YAML so rules can be added or tuned without touching code, which was a client requirement.

### Detection rules

| Rule | Detects | MITRE ATT&CK | Response |
|---|---|---|---|
| `PROC-RCE-001` | Shell or tool (`sh`, `bash`, `nc`, `curl`, `python`…) spawned by the Juice Shop `node` process | T1059.004 | kill_process |
| `PROC-RCE-002` | Recon commands (`whoami`, `id`, `uname`…) run as the Juice Shop user | T1059 | alert only |
| `WEB-SQLI-001/002` | SQL injection and error-based SQL injection in product search | T1190 | block_ip / alert |
| `WEB-BRUTE-001` | 5 failed logins from one IP within 15 seconds | T1110.001 | block_ip |
| `WEB-AUTH-001` | Password changed without the current password | T1098 | alert only |
| `WEB-AUTH-002` | Invalid or forged JWT used on a protected endpoint | T1550.001 | alert only |
| `FILE-UPLOAD-001…004` | Executable or disallowed file types, oversized files, and repeated upload POSTs | T1505.003, T1036.008, T1499.004 | quarantine_file / alert |

## Evaluation

Each test case in `EDR/Test/testcases.yaml` is labelled malicious or benign. `run_eval.py` fires every case from Kali and logs when it ran. `score_eval.py` matches alerts back to cases, classifies each one as TP/FP/TN/FN, and reports accuracy and MTTD per attack type. `results/wazuh_adapter.py` converts Wazuh's alerts into the same format so both tools are scored by the same harness against the same run.

Results from the final run (`results/Test8`), 12 malicious and 20 benign cases:

| Attack type | Cases (mal / benign) | EDR7 TP · FN · FP | Wazuh TP · FN · FP | EDR7 mean MTTD | Wazuh mean MTTD |
|---|---|---|---|---|---|
| RCE | 3 / 3 | 3 · 0 · 0 | 3 · 0 · 0 | 1.14 s | 1.25 s |
| SQL injection | 1 / 7 | 1 · 0 · 0 | 1 · 0 · 3 | 1.67 s | 0.39 s |
| Brute force | 1 / 3 | 1 · 0 · 1 | 1 · 0 · 3 | 4.69 s* | 1.37 s |
| Broken auth | 3 / 3 | 1 · 2 · 0 | 1 · 2 · 1 | 0.20 s | 0.77 s |
| File upload | 4 / 4 | 0 · 4 · 1 | 0 · 4 · 0 | n/a | n/a |
| **Total** | **12 / 20** | **6 · 6 · 2** | **6 · 6 · 7** | | |

\* Brute-force MTTD is measured from the first failed login, so it includes the time taken to reach the threshold.

**Resource usage** (`results/Test7`, EDR process vs Wazuh agent only, about 17 minutes sampled every second): EDR7 averaged **26.9 MB** RSS and Wazuh **74.4 MB**, both under 0.1% mean CPU. In Tests 6 and 8 the Wazuh figure (~534 MB) also includes the Wazuh manager on the same VM, so it isn't a like-for-like comparison.

### What the results do and don't show

- Both tools caught the same 6 of 12 attacks. EDR7 raised 2 false positives across 20 benign cases, compared with 7 for Wazuh, mostly because EDR7's rules were written for this specific application.
- **The sample is small.** RCE has three malicious and three benign cases, so "100% detection" means 3 out of 3 in one lab run. It isn't evidence of production-grade accuracy.
- **File-upload detection didn't fire** in the final run (0 of 4). The forged-token rule (`WEB-AUTH-002`) also missed 2 of 3 cases. Both are open issues.
- The rules are tuned to Juice Shop, so they would need rewriting for a different application. Wazuh's generic rules trade false positives for broader coverage.
- Only one host was monitored. There is no central management, and MTTD depends on the 2-second poll interval.

## Repository layout

```
EDR/                    The EDR itself (runs on the Juice Shop VM)
  mini_edr.py           Entry point: wires agents -> engine -> sink + responder
  edr_core.py           Event and Alert types, Agent base class, alert sink
  engine.py             Rule loader and detection engine
  responder.py          block_ip / kill_process / quarantine_file
  agent_web.py          Access-log agent
  agent_process.py      auditd execve agent
  agent_fim.py          Upload-folder file integrity agent
  rules/*.yaml          Detection rules, one file per attack type
  Test/testcases.yaml   Labelled evaluation cases
  score_eval.py         Scores alerts against attack_log.csv
  test_edr.py           Offline unit checks (no VM needed)
  reset_lab.sh          Resets iptables, logs and Juice Shop between runs
attacker-playbook/      Runs on Kali
  run_eval.py           Fires every test case and writes attack_log.csv
  run_all.py            Runs the full attack suite in one command
  scripts/              Individual attacks (SQLi, brute force, JWT, SSTI/RCE, upload…)
  benign/               Benign traffic used for false-positive testing
results/                Raw output from each evaluation run (Test1-Test8)
  wazuh_adapter.py      Converts Wazuh alerts for scoring
```

## Running it

**Lab:** a Kali VM and an Ubuntu VM running Juice Shop on a host-only network, with auditd logging `execve` under the key `exec`:

```bash
sudo auditctl -a always,exit -F arch=b64 -S execve -k exec
```

On the Juice Shop VM:

```bash
pip install pyyaml watchdog
cd EDR
python3 test_edr.py                 # offline checks
sudo python3 mini_edr.py            # dry-run: alerts only
sudo python3 mini_edr.py --respond  # also block / kill / quarantine
```

`sudo` is needed so the process agent can read `/var/log/audit/audit.log`. Set `JS_ACCESS_LOG` and `EDR_LAB_DIR` if your paths differ from the defaults. Alerts are written to `~/edr_lab/alerts.jsonl`.

On Kali:

```bash
pip install requests pyyaml
cd attacker-playbook
python3 run_eval.py
```

Then copy `attack_log.csv` from Kali to the VM and score the run:

```bash
cd EDR
python3 score_eval.py --alerts ~/edr_lab/alerts.jsonl --attack-log /path/to/attack_log.csv
```

Use `--offset` to correct any clock skew between Kali and the VM.


The original integration spec the team built to is in [`EDR/EDR7 Module Integration Spec.pdf`](EDR/EDR7%20Module%20Integration%20Spec.pdf).
