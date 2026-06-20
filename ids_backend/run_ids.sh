#!/bin/bash
# run_ids.sh — Main IDS detection loop
# Run WITHOUT sudo. Only tcpdump inside uses sudo.
set -e

IFACE=enp0s3
INTERVAL=30
MAX_PACKETS=150000      # cap per capture — prevents multi-GB PCAPs during floods
CIC_TIMEOUT=90          # kill CICFlowMeter if it runs longer than this (seconds)
PCAP_DIR=~/ids/pcaps
FLOW_DIR=~/ids/flows
MODEL_DIR=~/ids/models
DB=~/ids/ids.db
VENV=~/ids/venv/bin/python3
LOG=~/ids/logs/ids.log

mkdir -p "$PCAP_DIR" "$FLOW_DIR" ~/ids/logs
export PATH="/home/ids/ids/venv/bin:$PATH"

echo "================================================" | tee -a "$LOG"
echo "IDS started at $(date)"                           | tee -a "$LOG"
echo "Interface: $IFACE  |  Interval: ${INTERVAL}s  |  MaxPkts: ${MAX_PACKETS}" | tee -a "$LOG"
echo "================================================" | tee -a "$LOG"

while true; do
    STAMP=$(date +%Y%m%d_%H%M%S)
    PCAP="$PCAP_DIR/cap_${STAMP}.pcap"
    FLOWS="$FLOW_DIR/flows_${STAMP}.csv"

    echo "[$(date +%H:%M:%S)] Capturing ${INTERVAL}s on $IFACE (max ${MAX_PACKETS} pkts)..." | tee -a "$LOG"
    # -c MAX_PACKETS stops early during floods so the PCAP stays manageable
    sudo tcpdump -i "$IFACE" -w "$PCAP" -G "$INTERVAL" -W 1 -c "$MAX_PACKETS" -s 128 -q -Z ids 2>/dev/null || true

    echo "[$(date +%H:%M:%S)] Converting to flows..."  | tee -a "$LOG"
    CIC_EXIT=0
    timeout "$CIC_TIMEOUT" cicflowmeter -f "$PCAP" -c "$FLOWS" 2>>"$LOG" || CIC_EXIT=$?
    if [ $CIC_EXIT -eq 124 ]; then
        echo "[WARN] CICFlowMeter timed out after ${CIC_TIMEOUT}s — skipping cycle" | tee -a "$LOG"
        continue
    elif [ $CIC_EXIT -ne 0 ]; then
        echo "[WARN] CICFlowMeter failed (exit ${CIC_EXIT}) — skipping cycle" | tee -a "$LOG"
        continue
    fi

    if [ ! -f "$FLOWS" ] || [ ! -s "$FLOWS" ]; then
        echo "[WARN] No flows produced — skipping cycle" | tee -a "$LOG"
        continue
    fi

    echo "[$(date +%H:%M:%S)] Running inference..."    | tee -a "$LOG"
    $VENV ~/ids/infer.py \
        --flows  "$FLOWS"     \
        --models "$MODEL_DIR" \
        --db     "$DB"        \
        --pcap   "$PCAP"      2>>"$LOG" | tee -a "$LOG"

    # Keep only last 5 pcap files
    ls -t "$PCAP_DIR"/*.pcap 2>/dev/null | tail -n +6 | xargs rm -f

    echo "[$(date +%H:%M:%S)] Cycle done."             | tee -a "$LOG"
done
