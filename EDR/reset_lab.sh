#!/usr/bin/env bash
# reset_lab.sh - put the lab back to a clean state between demo runs.
# Run on the Juice Shop VM with sudo:  sudo ./reset_lab.sh
set -u

LAB_DIR="${EDR_LAB_DIR:-$HOME/edr_lab}"

echo "[*] flushing iptables INPUT rules..."
iptables -F INPUT 2>/dev/null || echo "    (could not flush, run with sudo)"

echo "[*] clearing alerts and attack log..."
: > "$LAB_DIR/alerts.jsonl" 2>/dev/null || true
: > "$LAB_DIR/attack_log.csv" 2>/dev/null || true

echo "[*] restarting Juice Shop..."
systemctl restart juiceshop.service 2>/dev/null \
    && echo "    juiceshop.service restarted" \
    || echo "    (could not restart juiceshop.service, check the unit name)"

echo "[*] done. Ready for the next run."
