# Scheduler-Adjacent Attribution Artifact — Construction Handle Extraction

Bead: `asupersync-sched-hot-path-perf-bt4y5f.2.2` (E1.2 subsystem 3a)
Gate: Phase 6 flamegraph (triggered: `src/runtime/scheduler/three_lane.rs` touched).

## Flamegraph status: infra-blocked, fallback captured

- Kernel-sampled flamegraphs remain fleet-blocked: `perf_event_paranoid`
  forbids unprivileged sampling on the RCH workers and the local host, per
  the precedent recorded in `main-u1z5hn-1-3-attribution.md`,
  `main-bt4y5f-2-2-attribution.md`, and `main-bt4y5f-2-2-s2-attribution.md`
  (no `.svg` has ever been committed to `artifacts/flamegraphs/` repo-wide).
- Binding performance evidence below uses the criterion bench that
  exercises the admission/dispatch/completion paths adjacent to the
  changed file.

## What changed — and why the hot path carries zero new instructions

Subsystem 3a is a construction-time-only seam (E1.1 inventory rows
T01/T02/W01): `ThreeLaneScheduler` gained a zero-acquisition core
constructor (`new_with_options_task_table_and_handles`) taking a
pre-extracted `SchedulerConstructionHandles` bundle, the deferred-cancel
coordinator install became an explicit caller step
(`install_pending_cancel_dispatch_coordinator`), and legacy `Worker::new`
delegates to a pre-extracted-handles variant.

- **Per-poll dispatch loop, steal, spawn admission, completion, finalizer
  drain: byte-identical.** No executable code inside any worker loop or
  scheduler dispatch path changed; edits are confined to constructor
  bodies, one builder call site, and a test-gated state accessor.
- **Worker structs receive the same handle values** they previously read
  from under the state lock — same `Arc` identities (pinned by test
  `construction_with_extracted_handles_acquires_no_unified_state_lock`,
  which also proves construction completes while another thread holds the
  unified state mutex, i.e. zero constructor acquisitions).
- **Runtime construction cost:** unchanged acquisition count on the
  builder path (one extraction read + one coordinator install vs. the
  previous two constructor-internal acquisitions), all before any worker
  thread exists.
- **Deferred-cancel liveness preserved:** the readiness flag is the same
  state-owned `Arc` (identity-pinned per worker), and the coordinator is
  installed before worker threads start; the sabotage control (skipped
  install / reintroduced constructor acquisition) failed exactly the two
  pinning tests.

## Binding performance evidence

`spawn_throughput` (criterion, 20 samples), run on worker hz1 (2026-07-28),
clean-overlay of exactly this change over `HEAD` (comparator-only reading
per `br-asupersync-87h3es`: same-run relative pattern, not absolute ns;
hz1 is a different host class than the ovh-a numbers in the s1/s2
attributions, so magnitudes are not cross-comparable — only the preserved
mailbox-over-direct direction is the claim):

| Scenario | Direct (median) | Mailbox (median) | Delta |
|---|---|---|---|
| single producer | 39.4 Kelem/s | 83.5 Kelem/s | **+112%** |
| 4-producer contended | 50.2 Kelem/s | 80.2 Kelem/s | **+60%** |
| 8-producer contended | 51.9 Kelem/s | 81.2 Kelem/s | **+56%** |
| join_handle spawn→await-all (completion path) | 48.4 Kelem/s | 89.2 Kelem/s | **+84%** |

Expected and observed: the mailbox-vs-direct advantage is preserved on
every row (same direction as the subsystem-1/-2 ovh-a attributions,
+49/+27/+29/+47), because no benched instruction changed. A material
inversion of that pattern would have indicated an accidental hot-path
edit; none was observed.

Golden gate on the same overlay: `golden_output` bench scenarios and the
`golden_outputs` integration test lane are recorded in the bead dossier,
proving scheduler observable-behavior checksums are unchanged.

## No-claim boundary

This artifact attributes the E1.2 subsystem-3a construction seam; it is
not a fleet-performance claim, not a methodology-baseline waiver, and not
evidence for the remaining sharded-backing conversion (E1.1 rows
T03-T23/W02-W09, builder rows B01-B13) or for the still-state-owned
deferred-cancel dispatch queue (T02 residual).
