#!/usr/bin/env bash
# Measure startup time and RSS three times and print the median.
# AUTH_TOKEN is read from the environment or from the staging .env and is never printed.
# Startup time and RSS are flagged only when slower than a --compare baseline by more than 20%.
set -euo pipefail

rounds=3
base_url="${BASE_URL:-http://127.0.0.1:4100}"
staging_dir="${METAPI_STAGING_DIR:-}"
compare_file=""
out_file=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --rounds) rounds="$2"; shift 2 ;;
    --base) base_url="$2"; shift 2 ;;
    --staging-dir) staging_dir="$2"; shift 2 ;;
    --compare) compare_file="$2"; shift 2 ;;
    --out) out_file="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 1 ;;
  esac
done

if [[ -z "$staging_dir" ]]; then
  echo "METAPI_STAGING_DIR or --staging-dir is required" >&2
  exit 1
fi
if [[ ! "$rounds" =~ ^[1-9][0-9]*$ ]]; then
  echo "--rounds must be a positive integer" >&2
  exit 1
fi

root="$(cd "$(dirname "$0")/../../.." && pwd)"
bench="${METAPI_BENCH:-$root/test/scripts/perf/bench.mjs}"
node_bin="${NODE:-node}"
settle="${METAPI_STARTUP_SETTLE_SEC:-5}"
bench_n="${METAPI_BENCH_N:-200}"
bench_concurrency="${METAPI_BENCH_CONCURRENCY:-10}"

cd "$staging_dir"
if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source ./.env
  set +a
fi

median_of() {
  printf '%s\n' "$@" | sort -n | awk '{ values[NR] = $1 } END { print values[int((NR + 1) / 2)] }'
}

read_rss() {
  local pid="$1" field="$2"
  awk -v field="$field" '$1 == field":" { print int($2 / 1024) }' "/proc/${pid}/status"
}

declare -a startup_ms rss_idle rss_after hwm
for ((i = 1; i <= rounds; i++)); do
  ./stop.sh --keep-pg >/dev/null
  start_output="$(./start.sh)"
  ms="$(printf '%s\n' "$start_output" | sed -nE 's/.*约 ([0-9]+)ms.*/\1/p; s/^startup_ms=([0-9]+)$/\1/p' || true)"
  ms="${ms%%$'\n'*}"
  if [[ -z "$ms" ]]; then
    echo "start.sh did not report startup time" >&2
    exit 1
  fi
  if [[ "$settle" != "0" ]]; then
    sleep "$settle"
  fi
  pid="$(cat run/app.pid)"
  idle="$(read_rss "$pid" VmRSS)"
  if [[ "${METAPI_SKIP_BENCH:-}" != "1" ]]; then
    "$node_bin" "$bench" --rounds 1 --n "$bench_n" --warmup 0 --concurrency "$bench_concurrency" "$base_url" >/dev/null
  fi
  after="$(read_rss "$pid" VmRSS)"
  peak="$(read_rss "$pid" VmHWM)"
  startup_ms+=("$ms")
  rss_idle+=("$idle")
  rss_after+=("$after")
  hwm+=("$peak")
  echo "run${i} startup=${ms}ms rss_idle=${idle}MB rss_after=${after}MB hwm=${peak}MB"
done

med_startup="$(median_of "${startup_ms[@]}")"
med_idle="$(median_of "${rss_idle[@]}")"
med_after="$(median_of "${rss_after[@]}")"
med_hwm="$(median_of "${hwm[@]}")"
echo "median startup=${med_startup}ms rss_idle=${med_idle}MB rss_after=${med_after}MB hwm=${med_hwm}MB"

if [[ -n "$out_file" ]]; then
  cat >"$out_file" <<EOF
startup=$med_startup
rss_idle=$med_idle
rss_after=$med_after
hwm=$med_hwm
EOF
fi

if [[ -z "$compare_file" ]]; then
  exit 0
fi

flagged=0
report_metric() {
  local name="$1" current="$2" key="$3"
  local baseline
  baseline="$(sed -nE "s/^${key}=([0-9]+)$/\1/p" "$compare_file" | head -n 1)"
  if [[ -z "$baseline" || "$baseline" == "0" ]]; then
    return
  fi
  if awk -v current="$current" -v baseline="$baseline" 'BEGIN { exit !((current - baseline) / baseline > 0.2) }'; then
    flagged=$((flagged + 1))
    echo "flagged ${name} (more than 20% slower)"
  fi
}

report_metric startup "$med_startup" startup
report_metric rss_idle "$med_idle" rss_idle
report_metric rss_after "$med_after" rss_after
report_metric hwm "$med_hwm" hwm
if [[ "$flagged" -eq 0 ]]; then
  echo "no startup or RSS regression over 20%"
  exit 0
fi
echo "flagged ${flagged}"
exit 2
