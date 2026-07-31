#!/usr/bin/env bash
# run_sched_perf_e2e.sh — Scheduler perf-epic invariant floor e2e
# (bead asupersync-sched-hot-path-perf-bt4y5f.8).
#
# The SCHED-PERF epic's promise is "faster WITHOUT losing a single
# invariant". Benches measure the first half; this suite is the standing
# proof of the second, with logs detailed enough to diagnose drift.
#
# Stages (each timed; emitted to events.ndjson):
#   S1 regression  — the Phase-6 methodology_baselines comparison gate
#                    against artifacts/baseline.json (max(5%, ci95,
#                    +0.6ns) per row, br-asupersync-87h3es). ALL-SKIPPED
#                    IS BLOCKED, NOT GREEN: when every tracked row skips
#                    (e.g. baseline host absent from the current fleet,
#                    br-asupersync-zqs4bo) the stage reports `blocked`
#                    with a pointed message and the suite fails closed —
#                    a red gate and a skipped gate must never be
#                    indistinguishable.
#   S2 invariants  — mixed workload (spawn storm + cancellation waves +
#                    channel pressure + timers) on the PRODUCTION
#                    runtime via tests/e2e_sched_perf_invariants.rs:
#                    clean quiescence (no live tasks, no draining
#                    regions, no pending obligations — shard-C-aware
#                    since m9wsza S4c-2c-iv) across the S4 config
#                    matrix, PLUS the documented fairness envelope
#                    (PreemptionFairnessCertificate::invariant_holds,
#                    src/runtime/scheduler/three_lane.rs) via the
#                    scheduler's certificate tests by name.
#   S3 determinism — the unified|sharded replay-fingerprint corpus
#                    (lib tests, internally seed-parameterized) run
#                    TWICE; both runs must pass and agree, catching
#                    nondeterministic flake in the fingerprint path.
#   S4 config-matrix — folded into S2: the invariant test enumerates
#                    {spawn_admission Direct|Mailbox} x {state shape
#                    Unified|Sharded}. Grow the matrix in
#                    tests/e2e_sched_perf_invariants.rs as new perf
#                    flags land (io_uring cells require kernel support
#                    and stay script-gated until wired).
#
# Breakage rehearsal (bead AC5), env-injected — never source-mutating:
#   --rehearse runs (a) S2 with ASUPERSYNC_SCHED_E2E_SABOTAGE=quiescence
#   (a deliberately-leaked sleeper must fail the quiescence assertion
#   with a pointed message) and (b) S1 with an impossible regression
#   allowance (ASUPERSYNC_PHASE6_MAX_REGRESSION_PCT=-100) which must
#   NOT report pass (on the current fleet it reports blocked; on a
#   baseline-matched host it reports failed). A rehearsal that comes
#   back green is itself a suite failure.
#
# Usage:
#   bash scripts/run_sched_perf_e2e.sh              # full suite
#   bash scripts/run_sched_perf_e2e.sh --rehearse   # breakage rehearsal
#   SCHED_PERF_SKIP_S1=1 bash scripts/run_sched_perf_e2e.sh  # skip bench stage
#
# All cargo work routes through strict RCH (no local fallback). Needs
# python3 + jq. Nothing shared is removed; everything lands under $OUT.
set -uo pipefail

SUITE_ID="sched-perf"
SCENARIO_ID="E2E-SUITE-SCHED-PERF-INVARIANT-FLOOR"
SCHEMA_VERSION="e2e-suite-summary-v3"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
TS="$(date +%Y%m%d_%H%M%S)"
OUT="${OUT:-$ROOT/target/e2e-results/sched_perf/${TS}_$$}"
EVENTS="$OUT/events.ndjson"
SUMMARY="$OUT/summary.json"
STARTED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
REPRO="bash scripts/run_sched_perf_e2e.sh"
TD="${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}"
REHEARSE=0
[ "${1:-}" = "--rehearse" ] && REHEARSE=1
SKIP_S1="${SCHED_PERF_SKIP_S1:-0}"

mkdir -p "$OUT"
FAILED=0
log() { printf '%s | %s\n' "$(date '+%H:%M:%S')" "$*" >&2; }

emit_event() { # $1=stage $2=status $3=detail $4=elapsed_s $5=repro
  python3 - "$EVENTS" "$1" "$2" "$3" "$4" "$5" <<'PY'
import json, sys
path, stage, status, detail, elapsed, repro = sys.argv[1:7]
with open(path, "a", encoding="utf-8") as f:
    f.write(json.dumps({
        "stage": stage, "status": status, "detail": detail,
        "elapsed_s": float(elapsed), "repro": repro,
    }) + "\n")
PY
}

run_rch() { # $1=log-file, rest=command; returns rch exit
  # Infra-retry: transient fleet conditions (SSH timeout RCH-E104,
  # admission refusals, daemon restarts) get up to 3 attempts with
  # backoff; genuine test failures and compile errors never retry.
  local lf="$1"; shift
  local attempt rc
  for attempt in 1 2 3; do
    RCH_BUILD_TIMEOUT_SEC=5400 RCH_REQUIRE_REMOTE=1 rch exec -- "$@" >"$lf" 2>&1
    rc=$?
    [ "$rc" -eq 0 ] && return 0
    if grep -qEi "RCH-E104|no admissible|insufficient_total_slots|insufficient_slots|critical_pressure|retries exhausted|daemon restart" "$lf" \
       && ! grep -qE "test result: FAILED|^error(\[|:)" "$lf"; then
      log "rch infra-retry (attempt $attempt, rc=$rc) — backing off 120s"
      sleep 120
      continue
    fi
    return "$rc"
  done
  return "$rc"
}

# ---------- S1: regression gate ----------
s1() {
  local t0 t1 rc lf="$OUT/s1_baselines.log" status detail
  t0=$SECONDS
  if [ "$SKIP_S1" = "1" ]; then
    emit_event s1_regression skipped "SCHED_PERF_SKIP_S1=1" 0 "$REPRO"
    log "S1 skipped by env"
    return 0
  fi
  local pct=5
  [ "$REHEARSE" = "1" ] && pct="-100"
  run_rch "$lf" env CARGO_INCREMENTAL=0 \
    CARGO_TARGET_DIR="$TD/rch_target_asupersync_phase6_baselines" \
    ASUPERSYNC_PHASE6_BASELINE=artifacts/baseline.json \
    ASUPERSYNC_PHASE6_MAX_REGRESSION_PCT="$pct" \
    cargo bench -p asupersync --bench methodology_baselines \
    --features test-internals,criterion-benches -- --noplot
  rc=$?
  t1=$((SECONDS - t0))
  local tracked skipped
  tracked=$(grep -c '^\[PHASE6\] row ' "$lf" 2>/dev/null || true)
  skipped=$(grep -c '^\[PHASE6\] row .* skipped' "$lf" 2>/dev/null || true)
  if [ "${tracked:-0}" -gt 0 ] && [ "$tracked" = "$skipped" ]; then
    status=blocked
    detail="ALL $tracked tracked rows skipped (baseline host not in current fleet — br-asupersync-zqs4bo). A fully-skipped gate is BLOCKED, never green."
    FAILED=1
  elif [ "$rc" -eq 0 ]; then
    status=passed
    detail="baseline gate green ($((tracked - skipped)) rows compared, $skipped skipped)"
  else
    status=failed
    detail="baseline gate red (rc=$rc; see s1_baselines.log for per-row deltas)"
    FAILED=1
  fi
  if [ "$REHEARSE" = "1" ] && [ "$status" = "passed" ]; then
    status=failed
    detail="REHEARSAL BREACH: impossible allowance (-100%) still passed — the gate is not comparing"
    FAILED=1
  fi
  emit_event s1_regression "$status" "$detail" "$t1" "ASUPERSYNC_PHASE6_MAX_REGRESSION_PCT=$pct $REPRO"
  log "S1 $status: $detail"
}

# ---------- S2: invariant floor + fairness envelope ----------
s2() {
  local t0 t1 rc lf="$OUT/s2_invariants.log" status detail
  t0=$SECONDS
  local envs=(CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-C debuginfo=0'
              CARGO_TARGET_DIR="$TD/rch_target_test_module")
  if [ "$REHEARSE" = "1" ]; then
    run_rch "$lf" env "${envs[@]}" ASUPERSYNC_SCHED_E2E_SABOTAGE=quiescence \
      cargo test -p asupersync --test e2e_sched_perf_invariants --features test-internals -- mixed_load_floor_direct_unified
    rc=$?
    t1=$((SECONDS - t0))
    if [ "$rc" -ne 0 ] && grep -q "SABOTAGE CONTROL" "$lf"; then
      emit_event s2_invariants passed "rehearsal: sabotaged quiescence failed with the pointed message (control proves the assertion executes)" "$t1" "ASUPERSYNC_SCHED_E2E_SABOTAGE=quiescence $REPRO"
      log "S2 rehearsal control fired correctly"
    else
      emit_event s2_invariants failed "REHEARSAL BREACH: sabotaged run rc=$rc without the pointed message — the floor assertion did not execute" "$t1" "$REPRO"
      log "S2 rehearsal BREACH"
      FAILED=1
    fi
    return 0
  fi
  run_rch "$lf" env "${envs[@]}" \
    cargo test -p asupersync --test e2e_sched_perf_invariants --features test-internals -- --nocapture
  rc=$?
  local matrix_result
  matrix_result=$(grep -E "^test result:" "$lf" | tail -1)
  if [ "$rc" -ne 0 ]; then
    t1=$((SECONDS - t0))
    emit_event s2_invariants failed "matrix floor red: $matrix_result" "$t1" "$REPRO"
    log "S2 matrix failed"
    FAILED=1
    return 0
  fi
  # Fairness envelope: the documented certificate contract, by name.
  run_rch "$OUT/s2_fairness.log" env "${envs[@]}" \
    cargo test -p asupersync --lib --features test-internals -- preemption_fairness_certificate
  rc=$?
  t1=$((SECONDS - t0))
  local fairness_result
  fairness_result=$(grep -E "^test result:" "$OUT/s2_fairness.log" | tail -1)
  if [ "$rc" -eq 0 ] && ! echo "$fairness_result" | grep -q " 0 passed"; then
    status=passed
    detail="matrix floor green ($matrix_result); fairness envelope green ($fairness_result)"
  else
    status=failed
    detail="fairness envelope red or empty (rc=$rc; $fairness_result) — zero matched tests is a FAIL, not a pass"
    FAILED=1
  fi
  emit_event s2_invariants "$status" "$detail" "$t1" "$REPRO"
  log "S2 $status"
}

# ---------- S3: determinism (fingerprint corpus, twice) ----------
s3() {
  local t0 t1 rc1 rc2 status detail
  t0=$SECONDS
  local envs=(CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-C debuginfo=0'
              CARGO_TARGET_DIR="$TD/rch_target_test_module")
  run_rch "$OUT/s3_run1.log" env "${envs[@]}" \
    cargo test -p asupersync --lib --features test-internals -- unified_and_sharded
  rc1=$?
  run_rch "$OUT/s3_run2.log" env "${envs[@]}" \
    cargo test -p asupersync --lib --features test-internals -- unified_and_sharded
  rc2=$?
  t1=$((SECONDS - t0))
  # Compare pass/fail STRUCTURE, not raw result lines: the filtered-out
  # totals legitimately differ across heterogeneous fleet workers
  # (cfg-gated tests vary by host), and timings always differ. The
  # invariant is: both runs green, identical non-zero passed count,
  # zero failures — per-seed fingerprint identity is asserted INSIDE
  # the corpus test itself.
  local p1 p2 f1 f2
  p1=$(grep -E "^test result:" "$OUT/s3_run1.log" | tail -1 | sed -E 's/.* ([0-9]+) passed.*/\1/')
  p2=$(grep -E "^test result:" "$OUT/s3_run2.log" | tail -1 | sed -E 's/.* ([0-9]+) passed.*/\1/')
  f1=$(grep -E "^test result:" "$OUT/s3_run1.log" | tail -1 | sed -E 's/.* ([0-9]+) failed.*/\1/')
  f2=$(grep -E "^test result:" "$OUT/s3_run2.log" | tail -1 | sed -E 's/.* ([0-9]+) failed.*/\1/')
  if [ "$rc1" -eq 0 ] && [ "$rc2" -eq 0 ] \
     && [ "${p1:-0}" = "${p2:-x}" ] && [ "${p1:-0}" -gt 0 ] \
     && [ "${f1:-1}" = "0" ] && [ "${f2:-1}" = "0" ]; then
    status=passed
    detail="fingerprint corpus deterministic across 2 runs ($p1 passed, 0 failed each) — per-seed identity asserted inside the corpus test"
  else
    status=failed
    detail="determinism red (rc1=$rc1 rc2=$rc2; passed=$p1/$p2 failed=$f1/$f2; zero matched tests fails closed)"
    FAILED=1
  fi
  emit_event s3_determinism "$status" "$detail" "$t1" "$REPRO"
  log "S3 $status"
}

log "sched-perf e2e starting (rehearse=$REHEARSE) → $OUT"
s1
s2
[ "$REHEARSE" = "1" ] || s3

VERDICT=passed
[ "$FAILED" -ne 0 ] && VERDICT=failed
python3 - "$SUMMARY" "$SCHEMA_VERSION" "$SUITE_ID" "$SCENARIO_ID" "$STARTED_TS" "$VERDICT" "$EVENTS" "$REPRO" <<'PY'
import json, sys, datetime
summary, schema, suite, scenario, started, verdict, events, repro = sys.argv[1:9]
rows = []
try:
    with open(events, encoding="utf-8") as f:
        rows = [json.loads(l) for l in f if l.strip()]
except FileNotFoundError:
    pass
doc = {
    "schema_version": schema,
    "suite_id": suite,
    "scenario_id": scenario,
    "started_ts": started,
    "finished_ts": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "verdict": verdict,
    "stages": rows,
    "repro": repro,
    "bead": "asupersync-sched-hot-path-perf-bt4y5f.8",
}
with open(summary, "w", encoding="utf-8") as f:
    json.dump(doc, f, indent=2, sort_keys=True)
    f.write("\n")
PY
jq -e '.verdict' "$SUMMARY" >/dev/null || { log "summary.json failed jq validation"; exit 9; }
log "sched-perf e2e $VERDICT → $SUMMARY"
[ "$VERDICT" = "passed" ]
