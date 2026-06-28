#!/usr/bin/env bash
# Scheduler/timer CPU-efficiency validation + regression gate
# (br-asupersync-runtime-cpu-overhaul-5vt09v.6.1).
#
# Builds and runs benches/scheduler_cpu_churn.rs (the runtime-cpu-overhaul
# measurement harness, gated on the `runtime-metrics` + `test-internals`
# features), captures its JSON report, and compares it against the committed
# baseline at artifacts/scheduler_cpu_churn/baseline.json.
#
# It is the regression gate for the scheduler/timer levers: it FAILS (exit 1)
# on any of these regressions, which would mean a lever was reverted/undone:
#   * idle-phase sched_yield_calls climbs above 0  -> idle busy-spin reintroduced
#   * idle-phase cpu_percent climbs materially      -> idle CPU regression
#   * timer_threads_spawned climbs past a small cap -> thread-per-sleep churn back
#     (the shared fallback pump counts 1; ~37/sec per-Sleep churn is the failure)
# Latency and load-CPU are reported but NOT hard-gated, because the harness runs
# a single rep and those figures are noisy run-to-run; treat large deltas as a
# signal to investigate, not an automatic fail.
#
# Usage:
#   bash scripts/run_scheduler_cpu_churn_validation.sh            # validate vs baseline
#   SCHED_CHURN_UPDATE_BASELINE=1 bash scripts/...                # refresh the baseline
#   bash -n scripts/run_scheduler_cpu_churn_validation.sh         # syntax self-test
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BASELINE="${PROJECT_ROOT}/artifacts/scheduler_cpu_churn/baseline.json"
OUTPUT_DIR="${PROJECT_ROOT}/target/scheduler_cpu_churn_validation"
mkdir -p "$OUTPUT_DIR"
CURRENT_RAW="${OUTPUT_DIR}/run_raw.log"
CURRENT_JSON="${OUTPUT_DIR}/current.json"

# Idle CPU above this many percent of a core is treated as a regression.
IDLE_CPU_PCT_MAX="${SCHED_CHURN_IDLE_CPU_PCT_MAX:-5.0}"
# timer_threads_spawned per phase above this is treated as thread-per-sleep churn.
TIMER_THREAD_CAP="${SCHED_CHURN_TIMER_THREAD_CAP:-2}"

CARGO_TARGET_DIR_DEFAULT="${TMPDIR:-/tmp}/rch_target_scheduler_cpu_churn_validation"
BENCH_CMD=(cargo bench --bench scheduler_cpu_churn --features runtime-metrics,test-internals)

if [[ ! -f "$BASELINE" && -z "${SCHED_CHURN_UPDATE_BASELINE:-}" ]]; then
    echo "FATAL: missing baseline $BASELINE (run with SCHED_CHURN_UPDATE_BASELINE=1 to create it)" >&2
    exit 2
fi

echo "[validation] building + running scheduler_cpu_churn bench (via rch)..." >&2
# Offload the build/run to RCH; the bench prints its JSON report to stdout.
if command -v rch >/dev/null 2>&1; then
    ( cd "$PROJECT_ROOT" && rch exec -- env CARGO_TARGET_DIR="$CARGO_TARGET_DIR_DEFAULT" CARGO_INCREMENTAL=0 \
        "${BENCH_CMD[@]}" ) >"$CURRENT_RAW" 2>&1 || {
        echo "FATAL: bench run failed; see $CURRENT_RAW" >&2
        exit 2
    }
else
    echo "[validation] rch not found; running cargo directly" >&2
    ( cd "$PROJECT_ROOT" && env CARGO_TARGET_DIR="$CARGO_TARGET_DIR_DEFAULT" CARGO_INCREMENTAL=0 \
        "${BENCH_CMD[@]}" ) >"$CURRENT_RAW" 2>&1 || {
        echo "FATAL: bench run failed; see $CURRENT_RAW" >&2
        exit 2
    }
fi

# Extract the JSON report (the object whose first key is "bead") from the raw
# output, which is interleaved with rch logs and the bench's stderr summary.
python3 - "$CURRENT_RAW" "$CURRENT_JSON" <<'PY'
import json, sys
raw = open(sys.argv[1]).read()
try:
    key = raw.index('"bead"')
except ValueError:
    sys.stderr.write("FATAL: no JSON report found in bench output\n")
    sys.exit(2)
start = raw.rfind('{', 0, key)
if start < 0:
    sys.stderr.write("FATAL: malformed bench output (no JSON object before report key)\n")
    sys.exit(2)
try:
    obj, _ = json.JSONDecoder().raw_decode(raw[start:])
except ValueError as exc:
    sys.stderr.write(f"FATAL: could not parse bench JSON report: {exc}\n")
    sys.exit(2)
if "phases" not in obj:
    sys.stderr.write("FATAL: bench JSON report has no 'phases'\n")
    sys.exit(2)
with open(sys.argv[2], 'w') as f:
    json.dump(obj, f, indent=2, sort_keys=True)
    f.write('\n')
PY

if [[ -n "${SCHED_CHURN_UPDATE_BASELINE:-}" ]]; then
    mkdir -p "$(dirname "$BASELINE")"
    cp "$CURRENT_JSON" "$BASELINE"
    echo "[validation] baseline refreshed -> $BASELINE" >&2
    exit 0
fi

# Compare current vs baseline and apply the regression gate.
python3 - "$BASELINE" "$CURRENT_JSON" "$IDLE_CPU_PCT_MAX" "$TIMER_THREAD_CAP" <<'PY'
import json, sys
base = json.load(open(sys.argv[1]))
cur = json.load(open(sys.argv[2]))
idle_cpu_max = float(sys.argv[3])
timer_cap = int(sys.argv[4])

bp = {(p['phase'], p['m']): p for p in base['phases']}
fails = []

hdr = ['phase/M', 'sched_yield', 'worker_spins', 'timer_thr', 'p50us', 'p99us', 'cpu%']
print(" ".join(f"{h:>14}" for h in hdr))
for p in cur['phases']:
    b = bp.get((p['phase'], p['m']), {})
    def fmt(k):
        return f"{b.get(k, '?')}->{p.get(k)}"
    print(" ".join(f"{s:>14}" for s in [
        f"{p['phase']}/{p['m']}", fmt('sched_yield_calls'), fmt('worker_spins'),
        fmt('timer_threads_spawned'),
        fmt('latency_p50_us'), fmt('latency_p99_us'),
        f"{round(b.get('cpu_percent',0),1)}->{round(p.get('cpu_percent',0),1)}"]))

    # HARD gates (use .get so a missing key never reads as a false regression).
    if p['phase'] == 'idle':
        if p.get('sched_yield_calls', 0) > 0:
            fails.append(f"idle sched_yield_calls={p.get('sched_yield_calls', 0)} (>0: idle busy-spin reintroduced)")
        if p.get('cpu_percent', 0.0) > idle_cpu_max:
            fails.append(f"idle cpu_percent={p.get('cpu_percent', 0.0):.1f} (> {idle_cpu_max}: idle CPU regression)")
    if p.get('timer_threads_spawned', 0) > timer_cap:
        fails.append(f"{p['phase']}/{p['m']} timer_threads_spawned={p.get('timer_threads_spawned', 0)} (> {timer_cap}: thread-per-sleep churn)")

print()
if fails:
    print("REGRESSION GATE: FAIL")
    for f in fails:
        print("  - " + f)
    sys.exit(1)
print("REGRESSION GATE: PASS (no idle busy-spin, no thread-per-sleep churn, idle CPU bounded)")
PY
