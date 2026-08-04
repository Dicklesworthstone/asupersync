# Scheduler-Adjacent Attribution Artifact — External-Table Mailbox Admission

Bead: `asupersync-sched-hot-path-perf-bt4y5f.2.2` (E1.2 subsystem 1)
Gate: Phase 6 flamegraph (triggered: `src/runtime/scheduler/three_lane.rs` touched).

## Flamegraph status: infra-blocked, fallback captured

- Kernel-sampled flamegraphs remain fleet-blocked: `perf_event_paranoid`
  forbids unprivileged sampling on the RCH workers and the local host, per
  the precedent recorded in `main-u1z5hn-1-3-attribution.md` (no `.svg` has
  ever been committed to `artifacts/flamegraphs/` repo-wide).
- Binding performance evidence below uses the criterion benches that
  exercise the exact changed path (mailbox admission drains in
  `three_lane.rs`, admission core in `state.rs`).

## What changed on the hot path

Admission now dispatches its Shard-A table operations through
`AdmissionTaskTarget` (`Embedded` for the default unified shape,
`External(locked guard)` for the sharded seam). In the default shape this
adds one enum discriminant match per table operation inside admission
(spawn is not the poll hot loop; admission is batched under one state-lock
acquisition). External-table admission is only reachable through the
test/fuzz constructor seam — `RuntimeBuilder` still gates the sharded
shape.

## Binding performance evidence

`spawn_throughput` (criterion, 20 samples, admission-path comparator),
run on the recording host class (ovh-a / `host:fixmydocuments`,
2026-07-28, clean-overlay of exactly this change over `HEAD`):

| Scenario | Direct (median) | Mailbox (median, changed path) | Delta |
|---|---|---|---|
| single producer | 117.1 Kelem/s | 171.7 Kelem/s | **+47%** |
| 4-producer contended | 124.9 Kelem/s | 163.4 Kelem/s | **+31%** |
| 8-producer contended | 125.0 Kelem/s | 160.7 Kelem/s | **+29%** |

The mailbox path — which now runs through `AdmissionTaskTarget` dispatch —
remains strictly faster than direct admission in every scenario, matching
the relative pattern recorded before this change
(`main-u1z5hn-1-3-attribution.md`: +45%/+54%/+45% on shared workers).

Phase-6 preflight (`methodology_baselines`, 46 tracked rows, 5% p50 gate,
same host class): four scored runs on 2026-07-28 (a fifth landed on a
non-recording host and env-skipped, as designed). Every scored run —
including a clean-`HEAD --no-overlay` control — tripped the 5% comparator
on a *different, disjoint* set of few-ns or high-variance rows, none of them
reproducible in the neighbouring runs and none on code this change
touches (`local_queue_push` measured 731/756/980 ns across runs of
identical bytes; `is_exhausted_infinite`'s flagged value lay inside its
own recorded ci95). Every row on this change's surface (task_spawn,
task_cancellation scheduler rows, channel rows) passed in at least 3 of 4
scored runs and all failures were non-reproducible. The comparator's
inability to produce a stable verdict on this host class is filed as
`br-asupersync-87h3es` (P1) with the full run dossier; five
demonstrated-unstable rows were re-recorded with provenance in
`c6c720d91`. Binding performance evidence for this change is the
`spawn_throughput` table above plus the multi-run methodology dossier —
not a single-run preflight verdict in either direction.

## Non-claims

- Not a kernel-sampled flamegraph; no per-function attribution claim
  beyond the bench rows cited above.
- No performance-improvement claim: this subsystem is a semantics-preserving
  retarget enabling the sharded shape; perf claims belong to E1.3
  (`bt4y5f.2.3`) after the default flip evidence.
- External-table admission is not enabled in any production configuration
  by this change.
