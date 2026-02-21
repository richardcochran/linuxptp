#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later

set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  ptp_benchmark_compare.sh --master-iface IFACE --slave-iface IFACE [options]

Required:
  --master-iface IFACE
  --slave-iface IFACE

Common options:
  --duration SEC            Duration for each run (default: 120)
  --master-cpu N            Optional CPU pin for master
  --slave-cpu N             Optional CPU pin for slave
  --pin-mode MODE           IRQ pin mode: none|selective (default: none)

Profile A options:
  --a-sync VAL              logSyncInterval (default: -3)
  --a-delay VAL             logMinDelayReqInterval (default: -3)
  --a-kp VAL                PI proportional const (default: 0.7)
  --a-ki VAL                PI integral const (default: 0.3)
  --a-label NAME            Label for profile A (default: A)

Profile B options:
  --b-sync VAL              logSyncInterval (default: -4)
  --b-delay VAL             logMinDelayReqInterval (default: -4)
  --b-kp VAL                PI proportional const (default: 0.5)
  --b-ki VAL                PI integral const (default: 0.2)
  --b-label NAME            Label for profile B (default: B)

Output:
  --output FILE             Write compare report to FILE
  --help                    Show help

Notes:
  - This script depends on scripts/ptp_benchmark.sh.
  - Delta is computed as: B - A (negative is better for jitter metrics).
USAGE
}

MASTER_IFACE=""
SLAVE_IFACE=""
DURATION=120
MASTER_CPU=""
SLAVE_CPU=""
PIN_MODE="none"
OUTPUT_FILE=""

A_SYNC=-3
A_DELAY=-3
A_KP=0.7
A_KI=0.3
A_LABEL="A"

B_SYNC=-4
B_DELAY=-4
B_KP=0.5
B_KI=0.2
B_LABEL="B"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --master-iface) MASTER_IFACE="$2"; shift 2 ;;
    --slave-iface) SLAVE_IFACE="$2"; shift 2 ;;
    --duration) DURATION="$2"; shift 2 ;;
    --master-cpu) MASTER_CPU="$2"; shift 2 ;;
    --slave-cpu) SLAVE_CPU="$2"; shift 2 ;;
    --pin-mode) PIN_MODE="$2"; shift 2 ;;
    --a-sync) A_SYNC="$2"; shift 2 ;;
    --a-delay) A_DELAY="$2"; shift 2 ;;
    --a-kp) A_KP="$2"; shift 2 ;;
    --a-ki) A_KI="$2"; shift 2 ;;
    --a-label) A_LABEL="$2"; shift 2 ;;
    --b-sync) B_SYNC="$2"; shift 2 ;;
    --b-delay) B_DELAY="$2"; shift 2 ;;
    --b-kp) B_KP="$2"; shift 2 ;;
    --b-ki) B_KI="$2"; shift 2 ;;
    --b-label) B_LABEL="$2"; shift 2 ;;
    --output) OUTPUT_FILE="$2"; shift 2 ;;
    --help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ -z "$MASTER_IFACE" || -z "$SLAVE_IFACE" ]]; then
  echo "--master-iface and --slave-iface are required" >&2
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BENCH="$SCRIPT_DIR/ptp_benchmark.sh"
if [[ ! -x "$BENCH" ]]; then
  echo "Missing executable dependency: $BENCH" >&2
  exit 1
fi

TMP_DIR="$(mktemp -d /tmp/ptp-compare.XXXXXX)"
A_OUT="$TMP_DIR/a.txt"
B_OUT="$TMP_DIR/b.txt"

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

base_args=(
  --master-iface "$MASTER_IFACE"
  --slave-iface "$SLAVE_IFACE"
  --duration "$DURATION"
  --pin-mode "$PIN_MODE"
)

if [[ -n "$MASTER_CPU" ]]; then
  base_args+=(--master-cpu "$MASTER_CPU")
fi
if [[ -n "$SLAVE_CPU" ]]; then
  base_args+=(--slave-cpu "$SLAVE_CPU")
fi

"$BENCH" "${base_args[@]}" \
  --sync-interval "$A_SYNC" \
  --delay-interval "$A_DELAY" \
  --kp "$A_KP" \
  --ki "$A_KI" \
  --output "$A_OUT" >/dev/null

"$BENCH" "${base_args[@]}" \
  --sync-interval "$B_SYNC" \
  --delay-interval "$B_DELAY" \
  --kp "$B_KP" \
  --ki "$B_KI" \
  --output "$B_OUT" >/dev/null

REPORT="$(python3 - "$A_LABEL" "$B_LABEL" "$A_OUT" "$B_OUT" <<'PY'
import sys

label_a, label_b, file_a, file_b = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]

def load(path):
    data = {}
    with open(path, 'r', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if '=' in line:
                k, v = line.split('=', 1)
                data[k] = v
    return data

def to_num(value):
    if value is None or value == 'NA':
        return None
    try:
        return float(value)
    except ValueError:
        return None

def fmt_num(value):
    if value is None:
        return 'NA'
    if abs(value - int(value)) < 1e-9:
        return str(int(value))
    return f"{value:.3f}"

def fmt_delta(a, b):
    if a is None or b is None:
        return 'NA'
    d = b - a
    sign = '+' if d > 0 else ''
    if abs(d - int(d)) < 1e-9:
        return f"{sign}{int(d)}"
    return f"{sign}{d:.3f}"

a = load(file_a)
b = load(file_b)

metrics = [
    'TRANS',
    'SAMPLES',
    'RMS_P50',
    'RMS_P95',
    'RMS_P99',
    'MAX_P95',
    'MAX_P99',
    'DELAY_P50',
    'DELAY_P95',
    'DELAY_P99',
]

lines = []
lines.append(
  f"PROFILE_A={label_a} sync={a.get('SYNC_INTERVAL','NA')} "
  f"delay={a.get('DELAY_INTERVAL','NA')} kp={a.get('KP','NA')} "
  f"ki={a.get('KI','NA')}"
)
lines.append(
  f"PROFILE_B={label_b} sync={b.get('SYNC_INTERVAL','NA')} "
  f"delay={b.get('DELAY_INTERVAL','NA')} kp={b.get('KP','NA')} "
  f"ki={b.get('KI','NA')}"
)
lines.append(
  f"MASTER_IFACE={a.get('MASTER_IFACE','NA')} "
  f"SLAVE_IFACE={a.get('SLAVE_IFACE','NA')} DURATION={a.get('DURATION','NA')}"
)
lines.append(
  f"PIN_MODE={a.get('PIN_MODE','NA')} MASTER_CPU={a.get('MASTER_CPU','NA')} "
  f"SLAVE_CPU={a.get('SLAVE_CPU','NA')}"
)
lines.append("---")
for m in metrics:
    av = to_num(a.get(m))
    bv = to_num(b.get(m))
    lines.append(f"{m}_A={fmt_num(av)} {m}_B={fmt_num(bv)} {m}_DELTA_B_MINUS_A={fmt_delta(av, bv)}")

print('\n'.join(lines))
PY
)"

if [[ -n "$OUTPUT_FILE" ]]; then
  printf "%s\n" "$REPORT" | tee "$OUTPUT_FILE"
else
  printf "%s\n" "$REPORT"
fi
