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
| `task_state_hot_reads` | `sched/task_state/` | historical non-equivalent task-state microbench rows (bt4y5f.4) |
| `channel_contended` | `sched/channel_contended/` | flat-combining MPSC (bt4y5f.5) |
| `io_token_dedup` | *comparator-only (ungated)* | I/O-driver dedup plus worker seen-token table (bt4y5f.9, 9y4yup) |

`io_token_dedup` is deliberately not gated: its value is the RELATIVE
strategy comparison (the I/O driver's hashset vs smallvec rows and the worker's
generation-aware direct table vs historical ring and full-clear rows all run
back-to-back under identical load), while its ABSOLUTE cell costs are
cache-resident microbenches that drifted +15..111% between same-host runs under
co-tenant fleet compile load — a 5% hard gate there would be a flake generator.
Gate rows are only those that survived both the recording run and a loaded
same-host re-run.

Every workload is fixed-size and seed-free. Contended rows use barrier-synced
persistent threads so per-iteration totals are identical; interleavings vary,
which is the phenomenon under measurement.

The `sched/task_state/` family predates the final scheduler ownership shape.
Keep its six host-family rows unchanged as historical observations of that
binary; do not use them as production hot-read baselines. HOTREAD-1's live
ownership inventory and the required `sched/hotread/v2/` replacement operation
IDs are frozen in `docs/scheduler_hot_read_inventory.md` and
`artifacts/scheduler_hot_read_inventory_v1.json`. A new semantic path always
gets a new operation ID rather than rewriting an incumbent row.

The JOIN-BATCH lever has the same evidence rule. Its current source and
semantic map is frozen in `docs/scheduler_join_batch_inventory.md` and
`artifacts/scheduler_join_batch_inventory_v1.json`. The registry currently has
no equivalent rows for isolated legacy `RuntimeHandle` completion, isolated
structured `TaskHandle` completion, or the public `Cx` N=1000 spawn loop.
Existing `join_handle_completion`, `join_set_fanout`, and broad
`spawn_throughput` groups include spawn, execution, or collection work; the
two-host `methodology/task_spawn/local_queue_spawn_batch/1000` rows exercise a
queue primitive only and have null p95 values. Preserve those surfaces as
non-equivalent evidence.

Extend `benches/spawn_throughput.rs` under the new
`sched/join_batch/v1/` namespace. Completion cells must pre-create their
transport and payload, and public-loop submission must remain separate from
submission-plus-collection. Each required operation needs p50, p95,
allocation count and bytes, at least three retained repetitions, and complete
same-host environment, source, harness, feature, allocator, and timer identity
on at least two admitted host families. Until those rows exist, JOIN-BATCH 3.1
remains measurement-blocked and authorizes no implementation or improvement
claim.

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

## Environment tags (compare like-to-like ONLY — enforced by the gate)

The RCH fleet is heterogeneous and `rch exec` cannot pin a worker; measured
cross-class drift on single-thread micro-cycles is 30-70% (ovh-a vs a Contabo
VPS on the channel cycles, 2026-07-27) — far beyond the 5% gate. The gate
therefore enforces like-to-like itself:

- Every `sched/` row carries `environment: "host:<hostname>"` from its
  recording run. The gate resolves the executing worker's hostname in-process
  and **compares a tagged row only on a hostname match**; mismatched rows are
  skipped with a loud `[PHASE6] row ... skipped` line.
- A run where EVERY owned row skips **fails closed** ("environment
  mismatch") — a worker-lottery miss can never be cited as gate evidence.
  Rerun until the dispatch lands on the recording host class (warm
  `CARGO_TARGET_DIR` affinity helps), or re-record the rows for the new class.
- Untagged rows (the legacy `methodology/` set) compare unconditionally —
  original behavior — until br-asupersync-pjivey re-records them with tags.
- **Multi-host row families** (br-asupersync-zqs4bo): one operation may carry
  several rows, one per recorded host class — row identity in the registry is
  `(operation, environment)`, enforced by the gate's duplicate check. Whichever
  host the fleet lands the run on compares against its own row and skips the
  siblings, so the gate engages on every recorded host instead of only the
  original recording box. Do not mix an untagged row into a tagged family for
  the same operation (the untagged row would compare everywhere and
  double-gate recorded hosts). Hosts without rows still all-skip and fail
  closed — that pressure is deliberate: record the host or accept the rerun
  lottery.

**Worker names are not hostnames.** `workers.toml` names (`ovh-a`, `hz1`,
`vmi…`) and the OS `hostname` the gate matches against can differ — `ovh-a`'s
hostname is `fixmydocuments`, `hz1`'s is `hetzner1` (2026-08-02). An
"environment mismatch" streak therefore does NOT prove the recording host left
the fleet; check which worker the run landed on (`[RCH] remote <name>` in the
transcript) before concluding anything (br-asupersync-zqs4bo learned this the
hard way).

When re-recording baselines on a new host class, update every row of the
affected prefix in one commit and say so in the message. To ADD a family row
for a new host, run the owning bench on a quiet fleet (gate env set — the run
self-identifies its landing hostname in the skip lines and still emits full
criterion medians), take at least 2 reps on that host, use the rep with the
median point estimate (its own `[lo mid hi]` becomes
`ci95_lower_ns`/`p50_ns`/`ci95_upper_ns`), and append the row without touching
existing ones.

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
