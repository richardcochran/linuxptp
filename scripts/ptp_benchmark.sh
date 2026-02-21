#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later

set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  ptp_benchmark.sh --master-iface IFACE --slave-iface IFACE [options]

Options:
  --duration SEC            Slave run duration in seconds (default: 120)
  --sync-interval VAL       logSyncInterval (default: -3)
  --delay-interval VAL      logMinDelayReqInterval (default: -3)
  --kp VAL                  PI proportional constant (default: 0.7)
  --ki VAL                  PI integral constant (default: 0.3)
  --master-cpu N            CPU core for master ptp4l (optional)
  --slave-cpu N             CPU core for slave ptp4l (optional)
  --pin-mode MODE           IRQ pin mode: none|selective (default: none)
  --output FILE             Also write summary output to FILE
  --help                    Show this help

Notes:
  - Run as root for IRQ affinity updates and stable benchmarking.
  - "selective" pin mode pins top-2 active IRQs for each interface.
USAGE
}

MASTER_IFACE=""
SLAVE_IFACE=""
DURATION=120
SYNC_INTERVAL=-3
DELAY_INTERVAL=-3
KP=0.7
KI=0.3
MASTER_CPU=""
SLAVE_CPU=""
PIN_MODE="none"
OUTPUT_FILE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --master-iface)
      MASTER_IFACE="$2"
      shift 2
      ;;
    --slave-iface)
      SLAVE_IFACE="$2"
      shift 2
      ;;
    --duration)
      DURATION="$2"
      shift 2
      ;;
    --sync-interval)
      SYNC_INTERVAL="$2"
      shift 2
      ;;
    --delay-interval)
      DELAY_INTERVAL="$2"
      shift 2
      ;;
    --kp)
      KP="$2"
      shift 2
      ;;
    --ki)
      KI="$2"
      shift 2
      ;;
    --master-cpu)
      MASTER_CPU="$2"
      shift 2
      ;;
    --slave-cpu)
      SLAVE_CPU="$2"
      shift 2
      ;;
    --pin-mode)
      PIN_MODE="$2"
      shift 2
      ;;
    --output)
      OUTPUT_FILE="$2"
      shift 2
      ;;
    --help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if [[ -z "$MASTER_IFACE" || -z "$SLAVE_IFACE" ]]; then
  echo "--master-iface and --slave-iface are required" >&2
  usage
  exit 2
fi

if [[ "$PIN_MODE" != "none" && "$PIN_MODE" != "selective" ]]; then
  echo "--pin-mode must be one of: none, selective" >&2
  exit 2
fi

if ! command -v ./ptp4l >/dev/null 2>&1; then
  echo "Run from linuxptp build directory where ./ptp4l exists" >&2
  exit 1
fi

WORKDIR="$(mktemp -d /tmp/ptp-bench.XXXXXX)"
MASTER_CFG="$WORKDIR/master.cfg"
SLAVE_CFG="$WORKDIR/slave.cfg"
MASTER_LOG="$WORKDIR/master.log"
SLAVE_LOG="$WORKDIR/slave.log"
IRQ_SAVE="$WORKDIR/irq_affinity.tsv"
MASTER_PID=""

cleanup() {
  if [[ -n "$MASTER_PID" ]]; then
    kill "$MASTER_PID" >/dev/null 2>&1 || true
  fi

  if [[ -f "$IRQ_SAVE" ]]; then
    while IFS=$'\t' read -r irq mask; do
      [[ -z "$irq" || -z "$mask" ]] && continue
      if [[ -w "/proc/irq/$irq/smp_affinity_list" ]]; then
        echo "$mask" > "/proc/irq/$irq/smp_affinity_list" || true
      fi
    done < "$IRQ_SAVE"
  fi

  rm -rf "$WORKDIR"
}
trap cleanup EXIT

cat > "$MASTER_CFG" <<CFG
[global]
network_transport L2
time_stamping hardware
assume_two_step 1
serverOnly 1
slaveOnly 0
logAnnounceInterval 0
logSyncInterval $SYNC_INTERVAL
logMinDelayReqInterval $DELAY_INTERVAL
clock_servo pi
pi_proportional_const $KP
pi_integral_const $KI
CFG

cat > "$SLAVE_CFG" <<CFG
[global]
network_transport L2
time_stamping hardware
assume_two_step 1
serverOnly 0
slaveOnly 1
logAnnounceInterval 0
logSyncInterval $SYNC_INTERVAL
logMinDelayReqInterval $DELAY_INTERVAL
clock_servo pi
pi_proportional_const $KP
pi_integral_const $KI
step_threshold 0.0
first_step_threshold 0.0
CFG

run_master_cmd=(./ptp4l -m -f "$MASTER_CFG" -i "$MASTER_IFACE")
run_slave_cmd=(./ptp4l -m -f "$SLAVE_CFG" -i "$SLAVE_IFACE")

if [[ -n "$MASTER_CPU" ]]; then
  run_master_cmd=(taskset -c "$MASTER_CPU" "${run_master_cmd[@]}")
fi
if [[ -n "$SLAVE_CPU" ]]; then
  run_slave_cmd=(taskset -c "$SLAVE_CPU" "${run_slave_cmd[@]}")
fi

iface_irqs() {
  local iface="$1"
  awk -v ifa="$iface" '
    index($0, ifa) {
      irq=$1
      gsub(":", "", irq)
      sum=0
      for (i=2; i<=NF; i++) {
        if ($i ~ /^[0-9]+$/) {
          sum += $i
        } else {
          break
        }
      }
      print irq, sum
    }
  ' /proc/interrupts | sort -k2,2nr
}

MASTER_IRQS=""
SLAVE_IRQS=""

if [[ "$PIN_MODE" == "selective" ]]; then
  if [[ -z "$MASTER_CPU" || -z "$SLAVE_CPU" ]]; then
    echo "--pin-mode selective requires --master-cpu and --slave-cpu" >&2
    exit 2
  fi

  MASTER_IRQS="$(iface_irqs "$MASTER_IFACE" | awk 'NR<=2{print $1}' | paste -sd ' ' -)"
  SLAVE_IRQS="$(iface_irqs "$SLAVE_IFACE" | awk 'NR<=2{print $1}' | paste -sd ' ' -)"

  printf "" > "$IRQ_SAVE"
  for irq in $MASTER_IRQS $SLAVE_IRQS; do
    [[ -z "$irq" ]] && continue
    if [[ -r "/proc/irq/$irq/smp_affinity_list" && -w "/proc/irq/$irq/smp_affinity_list" ]]; then
      old_mask="$(cat "/proc/irq/$irq/smp_affinity_list")"
      printf "%s\t%s\n" "$irq" "$old_mask" >> "$IRQ_SAVE"
    fi
  done

  for irq in $MASTER_IRQS; do
    [[ -z "$irq" ]] && continue
    if [[ -w "/proc/irq/$irq/smp_affinity_list" ]]; then
      echo "$MASTER_CPU" > "/proc/irq/$irq/smp_affinity_list"
    fi
  done

  for irq in $SLAVE_IRQS; do
    [[ -z "$irq" ]] && continue
    if [[ -w "/proc/irq/$irq/smp_affinity_list" ]]; then
      echo "$SLAVE_CPU" > "/proc/irq/$irq/smp_affinity_list"
    fi
  done
fi

pkill -f '^./ptp4l| ptp4l ' >/dev/null 2>&1 || true
sleep 1

"${run_master_cmd[@]}" > "$MASTER_LOG" 2>&1 &
MASTER_PID=$!
sleep 3

timeout "$DURATION" "${run_slave_cmd[@]}" > "$SLAVE_LOG" 2>&1 || true
kill "$MASTER_PID" >/dev/null 2>&1 || true
MASTER_PID=""

SUMMARY="$(python3 - "$SLAVE_LOG" <<'PY'
import math
import re
import sys

path = sys.argv[1]
lines = open(path, 'r', errors='ignore').read().splitlines()

trans = sum('UNCALIBRATED to SLAVE' in line for line in lines)
rms = []
mx = []
delay = []
for line in lines:
    m = re.search(r'rms\s+(\d+)\s+max\s+(\d+).*?delay\s+(\d+)', line)
    if m:
        rms.append(int(m.group(1)))
        mx.append(int(m.group(2)))
        delay.append(int(m.group(3)))

def pct(values, p):
    if not values:
        return 'NA'
    values = sorted(values)
    k = (len(values) - 1) * p
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return str(values[int(k)])
    return str(round(values[f] * (c - k) + values[c] * (k - f)))

tail = 30
rms_tail = rms[-tail:] if len(rms) >= tail else rms
mx_tail = mx[-tail:] if len(mx) >= tail else mx

print(f'TRANS={trans}')
print(f'SAMPLES={len(rms)}')
print(f'RMS_P50={pct(rms_tail, 0.50)}')
print(f'RMS_P95={pct(rms_tail, 0.95)}')
print(f'RMS_P99={pct(rms_tail, 0.99)}')
print(f'MAX_P95={pct(mx_tail, 0.95)}')
print(f'MAX_P99={pct(mx_tail, 0.99)}')
print(f'DELAY_P50={pct(delay, 0.50)}')
print(f'DELAY_P95={pct(delay, 0.95)}')
print(f'DELAY_P99={pct(delay, 0.99)}')
PY
)"

report() {
  echo "MASTER_IFACE=$MASTER_IFACE"
  echo "SLAVE_IFACE=$SLAVE_IFACE"
  echo "DURATION=$DURATION"
  echo "SYNC_INTERVAL=$SYNC_INTERVAL"
  echo "DELAY_INTERVAL=$DELAY_INTERVAL"
  echo "KP=$KP"
  echo "KI=$KI"
  echo "MASTER_CPU=${MASTER_CPU:-NA}"
  echo "SLAVE_CPU=${SLAVE_CPU:-NA}"
  echo "PIN_MODE=$PIN_MODE"
  echo "MASTER_IRQS=$(echo "${MASTER_IRQS:-NA}" | tr ' ' ',')"
  echo "SLAVE_IRQS=$(echo "${SLAVE_IRQS:-NA}" | tr ' ' ',')"
  echo "$SUMMARY"
}

if [[ -n "$OUTPUT_FILE" ]]; then
  report | tee "$OUTPUT_FILE"
else
  report
fi
