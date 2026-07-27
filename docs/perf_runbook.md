# Scheduler hot-path perf runbook

> Lever procedure for the `asupersync-sched-hot-path-perf-bt4y5f` epic
> (harness landed by `br-asupersync-sched-hot-path-perf-bt4y5f.1`).

## The bench surface

One tracked-row registry — `artifacts/baseline.json` — holds every Phase 6
gated p50 row. Each bench binary owns a disjoint operation prefix and its gate
compares only its own rows (`benches/phase6_gate.rs`), so binaries never fail
on estimates another binary produced:

| Bench binary | Prefix owned | Lever it instruments |
|---|---|---|
| `methodology_baselines` | `methodology/` | Phase 6 core-op baselines |
| `spawn_throughput` | *(not yet tracked)* | spawn/join admission (bt4y5f.3) |
| `injector_throughput` | `sched/injector/` | LCRQ-style injector upgrade (bt4y5f.5) |
| `task_state_hot_reads` | `sched/task_state/` | seqlock/BRAVO hot reads (bt4y5f.4) |
| `channel_contended` | `sched/channel_contended/` | flat-combining MPSC (bt4y5f.5) |
| `io_token_dedup` | `sched/io_token_dedup/` | seen-token ring upgrade (bt4y5f.9) |

Every workload is fixed-size and seed-free. Contended rows use barrier-synced
persistent threads so per-iteration totals are identical; interleavings vary,
which is the phenomenon under measurement.

## Running one bench (measurement only)

```bash
RCH_BUILD_TIMEOUT_SEC=5400 RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_INCREMENTAL=0 \
  CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_asupersync_sched_bench \
  cargo bench -p asupersync --bench injector_throughput \
  --features test-internals,criterion-benches -- --noplot
```

## Running one bench WITH the 5% p50 gate

```bash
RCH_BUILD_TIMEOUT_SEC=5400 RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_INCREMENTAL=0 \
  CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_asupersync_sched_bench \
  ASUPERSYNC_PHASE6_BASELINE=artifacts/baseline.json \
  ASUPERSYNC_PHASE6_MAX_REGRESSION_PCT=5 \
  cargo bench -p asupersync --bench injector_throughput \
  --features test-internals,criterion-benches -- --noplot
```

The gate compares the run that just happened (same process, same worker)
against the tracked rows under the binary's prefix and exits 2 on any p50 more
than 5% slower. Untracked criterion rows and rows under other prefixes are
outside the gate.

## Environment tags (compare like-to-like ONLY)

Every tracked row carries an `environment` field (for example
`rch-fleet-shared-2026-07` or `bare-metal-<host>`). A gate comparison is only
meaningful when the candidate runs in the same environment class the baseline
was recorded in — shared-fleet numbers are load-sensitive, so a fleet-recorded
baseline must not be "beaten" or "regressed" by a bare-metal run and vice
versa. When re-recording baselines in a new environment, update every row of
the affected prefix in one commit and say so in the message.

## Lever procedure (before/after)

1. **Baseline exists first.** The lever's target rows must already be in
   `artifacts/baseline.json` from a documented run on a healthy fleet
   (`rch status` posture `remote-ready`; note the worker if pinned).
2. **Before:** run the owning bench with the gate on the unchanged tree; it
   must pass. This proves the baseline is still live in your environment.
3. **Implement the lever** behind its bead.
4. **After:** run the owning bench with the gate. Improvements: re-record the
   improved rows (same environment tag) in the lever's closing commit, citing
   both criterion medians. The 5% gate protects everyone else from regressions
   the lever causes outside its target rows.
5. **Flamegraph attribution** (required by the Phase 6 gate matrix for
   scheduler-adjacent directories):

   ```bash
   RCH_BUILD_TIMEOUT_SEC=5400 RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_INCREMENTAL=0 \
     CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_asupersync_flamegraph \
     cargo flamegraph --package asupersync --freq 997 \
     --features test-internals,criterion-benches \
     --bench injector_throughput -o artifacts/flamegraphs/main-<bead-or-short-sha>.svg
   ```

## No-win closure (levers that do not pay)

A lever whose after-numbers do not beat its baseline rows is CLOSED WITH
EVIDENCE, not left open as an aspiration:

1. Record both medians (before/after) and the environment tag on the bead.
2. State the verdict plainly: which rows moved, by how much, and why the
   change does not pay (< noise floor, wins one row but regresses another,
   complexity not justified).
3. Revert the lever implementation (or gate it off) so `main` carries the
   simpler code, close the bead citing the numbers, and leave the benches in
   place — they remain the comparator for any future re-attempt.
4. Do NOT re-record baselines from a no-win attempt.

Precedent for this discipline: `benches/timer_wheel.rs` (wheel-vs-BTreeMap
comparators retained), and the SIMD GF(256) no-win record
(2026-06-17 session notes: "SIMD GF256 = ZERO benefit — do not re-try").
