# Scheduler-Adjacent Attribution Artifact — External-Table Finalizer Minting

Bead: `asupersync-sched-hot-path-perf-bt4y5f.2.2` (E1.2 subsystem 2)
Gate: Phase 6 flamegraph (triggered: `src/runtime/scheduler/three_lane.rs` touched).

## Flamegraph status: infra-blocked, fallback captured

- Kernel-sampled flamegraphs remain fleet-blocked: `perf_event_paranoid`
  forbids unprivileged sampling on the RCH workers and the local host, per
  the precedent recorded in `main-u1z5hn-1-3-attribution.md` and
  `main-bt4y5f-2-2-attribution.md` (no `.svg` has ever been committed to
  `artifacts/flamegraphs/` repo-wide).
- Binding performance evidence below uses the criterion benches that
  exercise the changed paths (worker completion + finalizer drain in
  `three_lane.rs`, task-infrastructure creation in `state.rs`).

## What changed on the hot path

Async-finalizer task creation now dispatches its Shard-A table operations
through `AdmissionTaskTarget` (`create_task_infrastructure_in`,
`spawn_finalizer_task_in`, `drain_ready_async_finalizers_in`), so
external-table schedulers mint finalizer tasks in the table their workers
consult. Cost analysis for the shapes that matter:

- **Per-poll dispatch loop: untouched.** No change to `next_task`,
  steal, or poll paths.
- **Completion paths (ready/panic/guard-drop), the common no-finalizer
  case:** one `has_finalizing_regions()` bool read under the state lock
  the completion already holds, replacing the equivalent early-exit check
  that `drain_ready_async_finalizers()` previously performed internally —
  the external table (A) is *not* locked in this case. Net: same work,
  moved one call earlier.
- **Completion paths when finalizer work exists (rare, region-close
  events):** one additional uncontended external-table lock acquisition
  (B → A, canonical order) in external mode only; embedded mode resolves
  to the same embedded table reference as before through the `Embedded`
  enum arm.
- **Embedded (default production) shape:** `create_task_infrastructure`
  delegates with `AdmissionTaskTarget::Embedded`; per table operation this
  adds one enum discriminant match, identical to the admission-path cost
  accepted in subsystem 1.

## Binding performance evidence

`spawn_throughput` (criterion, 20 samples), run on the recording host
class (ovh-a / `host:fixmydocuments`, 2026-07-28), clean-overlay of
exactly this change over `HEAD` (comparator-only reading per
`br-asupersync-87h3es`: same-host relative pattern, not absolute ns):

| Scenario | Direct (median) | Mailbox (median, changed dispatch) | Delta |
|---|---|---|---|
| single producer | 113.9 Kelem/s | 169.7 Kelem/s | **+49%** |
| 4-producer contended | 123.3 Kelem/s | 156.8 Kelem/s | **+27%** |
| 8-producer contended | 123.0 Kelem/s | 158.1 Kelem/s | **+29%** |
| join_handle spawn→await-all (completion path) | 112.8 Kelem/s | 165.6 Kelem/s | **+47%** |

The relative pattern matches the pre-change subsystem-1 attribution
(+47/+31/+29) — no admission or completion regression through the new
target dispatch. The `join_handle_completion` row is the binding evidence
for this subsystem's surface: it drives the worker ready-completion path
that now carries the `has_finalizing_regions()` guard.

Golden gate on the same overlay: `golden_output` bench scenarios all
matched (0 mismatches) and the `golden_outputs` integration test lane is
recorded in the bead dossier, proving scheduler observable-behavior
checksums are unchanged by the retarget.

## No-claim boundary

This artifact attributes the E1.2 subsystem-2 change on the completion /
finalizer paths; it is not a fleet-performance claim, not a
methodology-baseline waiver, and not evidence for the still-embedded
direct `create_task` / legacy builder spawn surfaces (B09/B10, subsystem
3).
