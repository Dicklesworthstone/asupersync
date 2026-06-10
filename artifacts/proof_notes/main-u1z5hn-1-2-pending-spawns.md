# Pending-Spawn Accounting Atomics Proof Note

Bead: `asupersync-dx-core-api-v2-u1z5hn.1.2`
Surface: `src/record/region.rs` (`PendingSpawnCounter`, `PendingSpawnReservation`,
`RegionRecord::pending_spawns`), `src/runtime/state.rs` (three close-path
predicates), `src/runtime/spawn_mailbox.rs` (`SpawnRequest::pending_reservation`).

## Claim

A region never closes to quiescence while a spawn request destined for it is
enqueued-but-unprocessed in the spawn mailbox, and the pending-spawn counter
never undercounts live spawn work. Equivalently: at every point where the
close path reads `pending_spawns == 0` and proceeds, every request that was
ever enqueued for the region has already reached its successor state
(admitted into the region's task list, or resolved `Cancelled` with its
future destroyed).

## Ordering argument

Let `C` be the region's `PendingSpawnCounter` (all operations `SeqCst`).

**Producer protocol (increment-before-visibility).**
A producer performs, in program order:

1. `C.fetch_add(1)` (`PendingSpawnCounter::reserve`, SeqCst RMW)
2. queue publish (`SegQueue::push`, release semantics inside crossbeam)

A request is *observable* (dequeueable) only after step 2. SeqCst RMWs and
the release-publish are not reordered against each other on the producer
thread, so **observable request ⇒ its credit is in `C`'s modification
order before any load that could miss it**.

**Consumer protocol (decrement-after-successor-visibility).**
The credit is released (`C` decremented via `PendingSpawnReservation::drop`)
only after the successor state is in place:

- *Admission* (A1.3): the admission path holds the state lock, calls
  `region.add_task(id)` (task now in `inner.tasks`), and only then drops the
  reservation. Both the task list and the counter are read by the close
  predicates under the same lock world, so the close path observes either
  the credit, the task, or both — never neither.
- *Cancel-resolve* (`SpawnRequest::resolve_cancelled`): drops the stored
  future, fires the `UnadmittedCancelFn` completion slot, **then** drops the
  reservation. The slot (which resolves the caller-visible handle) and the
  future destruction strictly precede the decrement. A unit test
  (`resolve_cancelled_releases_reservation_after_slot`) pins this order.
- *Request drop*: the reservation lives inside `SpawnRequest`, so any path
  that destroys the request releases the credit — panic-safe, no leak, no
  double-release (RAII gives exactly-once structurally; a defensive
  `checked_sub` + `underflow_count` diagnostic guards the impossible case,
  mirroring `double_resolve_count`).

**Close-path reads.** Four predicates gate on `C == 0` (SeqCst load):

- `RegionRecord::complete_close` — reads `C` *inside* the `inner` write
  lock, in the same critical section as the `tasks`/`children`/
  `pending_obligations`/`finalizers` emptiness checks (`src/record/region.rs`).
- `RuntimeState::can_region_finalize` — pending spawns are un-admitted
  children; the region cannot enter `Finalizing` while credits are
  outstanding.
- `RuntimeState::can_region_complete_close` — mirrors the record-level gate.
- `RuntimeState::is_quiescent` — global quiescence requires every region's
  counter to read zero, so the lab runtime cannot report quiescent with an
  unprocessed request in the mailbox.

`RegionRecord::is_quiescent` and `has_live_work` are also extended for
introspection consistency.

## Race outcomes (AC3 matrix)

- **Close check lands between increment and publish**: the check sees
  `C ≥ 1` and refuses — conservative wait; the request publishes and is
  drained normally. (`race_matrix_close_check_between_increment_and_publish`)
- **Close completes, then a late producer reserves+publishes**: the region
  is already terminal — and, once fully closed, *removed from the region
  table entirely*, so the late credit on the detached counter Arc is no
  longer visible to the region-table-based `is_quiescent` predicate. The
  per-region accounting therefore guards the window only while the region
  record exists; after removal, liveness is owned by the admission loop's
  closed-region fallback (the request resolves `Cancelled` on the next
  drain pass — identical public semantics to spawning into a closing region
  today) and by A1.3 folding **mailbox emptiness** into the scheduler's
  idle/quiescence decision. The counter still balances to zero and the
  cancel slot fires exactly once.
  (`race_matrix_late_enqueue_after_close_resolves_cancelled`)
- **Deliberate double-count window**: between `add_task` and the
  reservation drop, both the credit and the task are visible. This is safe
  (close waits longer), and the reverse gap — neither visible — cannot occur
  by the two protocols above.

## Why SeqCst

The counter is touched once per spawn and once per close-predicate
evaluation — not on the poll hot path. On x86-64 a SeqCst RMW lowers to the
same `lock xadd` as AcqRel; the simpler total-order argument is worth more
than the unmeasurable difference. A1.3's perf gate re-measures the full
spawn path (`benches/`), which is the binding performance check for this
chain.

## Loom note

AC3 offered lab-explorer or loom. The interleaving matrix above is covered
by deterministic enumeration tests plus a 4-producer × 250-request stress
drain (`race_stress_concurrent_producers_vs_drain`); the SeqCst total order
makes the pencil proof short. Migrating `PendingSpawnCounter` to
`cfg(loom)`-switched atomics is deferred to the existing `loom-tests`
feature lane if A1.3's admission loop wants model-checked coverage of the
combined queue+counter automaton.

## Evidence

- `cargo test --lib --features test-internals spawn_mailbox` — 11 prior +
  5 new accounting/race tests.
- `cargo test --lib --features test-internals record::region` — 5 new
  counter/predicate unit tests.
- `cargo check --all-targets`, `cargo clippy --all-targets -- -D warnings`,
  `cargo fmt --check` — green via `rch exec --` (see bead close comment for
  run evidence).

## Non-claims

- No admission wiring exists yet (A1.3): nothing in production enqueues
  spawn requests, so these gates are exercised by tests only in this slice.
- The per-region credit does not guard the post-removal window (region
  fully closed and recycled out of the table before a late detached
  reserve+enqueue). A1.3 must add mailbox emptiness to the scheduler's
  idle/quiescence decision to close that window; flagged on the A1.3 bead.
- No performance claim: the new counter adds one SeqCst RMW per (future)
  spawn enqueue and one SeqCst load per close-predicate evaluation;
  measurement belongs to A1.3's perf gate.
- The four `+ pending == 0` predicate extensions do not weaken any existing
  close condition — they only add a conjunct, so no region that closed
  before can now close earlier.
