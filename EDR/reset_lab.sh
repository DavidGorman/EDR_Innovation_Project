#!/usr/bin/env bash
# Owner: David. Resets the lab between demo runs (flush iptables, clear logs,
# restart Juice Shop). Run on the Juice Shop VM: sudo ./reset_lab.sh
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
