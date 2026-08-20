# OS lock inventory and terminal gate

<!-- BEGIN OSLOCK INVENTORY GATE -->

This is the operator-readable companion to
`artifacts/oslock_inventory_gate_v1.json`. It freezes the claim-time
`CAP-SYNC-LOCKS` baseline for `asupersync-0h6myr.1.1` at revision
`d6bfec75aba10957b6a3e29654a29e650b45d510`.

The gate outcome is terminal `DEFER`. `parking_lot` remains in place, no
implementation child is authorized, and this inventory approves no production
source, manifest, or lockfile change.

## Why the gate is DEFER

The clean-revision census contains 552 exact dependency-token occurrences in
240 Rust files. The surface is not just a collection of private mutex fields:
it includes production `Condvar` behavior, blocking-pool shutdown, DNS
discovery coalescing, visible guard-returning APIs, crate-visible locked state,
and Asupersync's own cancel-aware Mutex and RwLock implementations.

The canonical marginal ledger gives replacement a real but bounded graph
benefit. Across thirteen feature profiles and four targets, 48 of 52 cells
would remove four package versions:

- `parking_lot`
- `parking_lot_core`
- `lock_api`
- `scopeguard`

The four `workspace-dev-build-audit` cells remove zero package versions because
other workspace edges retain the incumbent. Marginal native status is either
`none` or `unknown`; `unknown` is not evidence that native code is present or
absent.

The plan requires a safe wrapper over `std::sync`, explicit poison recovery,
stable-lane support, complete guard and `Condvar` parity, and named-host
performance acceptance. No retained candidate comparison covers throughput,
p50/p95/p99/p999, fairness, starvation, cancellation-adjacent latency,
allocations, RSS, compile time, binary size, and 1/8/32/64-core scaling on
Linux x86_64 and Apple Silicon. Missing evidence is not parity, so it cannot
authorize a rewrite.

## Exact source census

The machine artifact defines the reproducible census:

1. start from the clean baseline revision;
2. recursively inspect Rust files under `benches`, `examples`, `fuzz`, `src`,
   and `tests`;
3. exclude only the focused contract itself;
4. emit `path:text` for every line containing the dependency token, preserving
   duplicate records but excluding line numbers so unrelated insertions cannot
   invalidate an unchanged use;
5. byte-sort the records, terminate each with LF, and hash the stream.

The result is:

| Scope | Files | Occurrences |
| --- | ---: | ---: |
| `benches` | 1 | 1 |
| `examples` | 1 | 4 |
| `fuzz` | 13 | 31 |
| `src` | 180 | 430 |
| `tests` | 52 | 95 |
| **Total** | **247** | **561** |

The SHA-256 receipt is
`738384a996ed1d1a5064b134890aea1aaf9d1d278ebd6aa263f91ebc60120b20`.
The focused contract recomputes the receipt and the nineteen workload buckets
from the clean overlay, so a new, removed, or changed occurrence fails closed.

## Primitive and API surface

There are 183 direct import statements. The dominant forms are 132 standalone
`Mutex` imports, 30 standalone `RwLock` imports, seven combined
`{Mutex, RwLock}` imports, three `{Mutex, MutexGuard}` imports, three
`{Condvar, Mutex}` imports, and aliases named `ParkingMutex` and `PoolMutex`.

The inventory covers:

- `Mutex`: blocking acquisition, `try_lock`, mutable access, guard drop, and
  non-poisoning incumbent behavior;
- `RwLock`: read, write, try operations, reader/writer progress, and
  starvation/fairness obligations;
- `Condvar`: `wait`, `wait_for`, `notify_one`, and `notify_all` in
  `src/runtime/blocking_pool.rs` and `src/service/discover.rs`, plus a
  test-only use in `src/net/resolve.rs`;
- `MutexGuard` and `RwLockReadGuard`: borrowed guard lifetimes and visible
  signatures;
- mapped and owned guards: Asupersync-owned projection APIs in
  `src/sync/mutex.rs` and `src/sync/rwlock.rs`; no direct incumbent
  mapped-guard spelling is present;
- aliases: import aliases and the two example aliases must not hide a mixed
  backend during any future migration.

The direct visible boundary includes:

- `Cx::from_inner` accepting an incumbent `RwLock`;
- `IoDriverHandle::lock` and `try_lock`;
- `RuntimeState::io_driver_mut` and `cancel_protocol_validator`;
- `Steer::services_mut`;
- the crate-visible environment test lock;
- the `test-internals` Kafka serialization guard.

Private signatures such as notify's baton-passing guard are also retained in
the machine inventory because they constrain an atomic migration.

## Semantic obligations

The incumbent is non-poisoning. A safe `std::sync` backend would need to
recover poison internally and make the policy explicit without leaking
`LockResult` through current APIs. Panic must still unlock through guard drop.
Recursive acquisition is not a supported contract and can deadlock.

Try-lock/read/write behavior is used. Timed production behavior is concentrated
in blocking-pool `Condvar::wait_for`; no direct timed Mutex/RwLock acquisition
contract was found. Production `Condvar` parity must cover predicate loops,
atomic unlock/park/relock, timeout accounting, spurious wakeups, wake
cardinality, and shutdown.

Some lock orders are documented locally, such as watch's `send_lock` before
`value`, but there is no complete order graph for the 240-file surface.
Synchronous incumbent locks are not cancellation-aware. Asupersync's async
wrappers own waiter teardown and prohibit guards across await, while direct
call sites still require a cancellation-adjacent audit.

Only a safe std-backed owned wrapper is eligible for a normal gate. A custom
raw futex or parking protocol is `ALGORITHMIC-UNSAFE` and remains prohibited by
default under the dependency safety taxonomy.

## Baseline status

The focused clean-`HEAD` RCH command exercises incumbent sync unit tests:

```bash
RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay --no-overlay -- \
  env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  CARGO_TARGET_DIR=/tmp/rch_target_oslock_a1_sync_baseline \
  RUSTFLAGS='-D warnings -C debuginfo=0' \
  cargo test -p asupersync --lib sync:: -- --nocapture
```

Its terminal receipt is recorded in the machine artifact: 614 tests passed,
two were ignored, and
`sync::mutex::tests::mutex_queued_waiter_sees_poison_after_holder_panics`
failed. A focused single-test reproduction is routed separately to distinguish
a deterministic incumbent defect from suite-order interference. The isolated
test passed: one passed, zero failed, in 0.05 seconds. That pass does not erase
the suite failure. The test coordinates lock acquisition with fixed 10 ms and
50 ms sleeps, so load sensitivity remains routed without claiming a root
cause. This is an incumbent correctness sample only. It is not evidence
against a candidate that does not exist, candidate parity, broad workspace
health, or performance evidence.

The following evidence remains explicitly blocked:

- named Linux x86_64 and Apple Silicon throughput;
- p50/p95/p99/p999 wait and hold latency;
- fairness distributions and starvation bounds;
- cancellation-adjacent guard-hold, waiter-teardown, and shutdown latency;
- allocations, peak/steady RSS, compile time, and binary size;
- the 1/8/32/64-core scaling matrix;
- candidate stable-lane and complete poison/guard/Condvar parity.

## Reconsideration gate

`DEFER` may change only through a new owner-reviewed gate after one or more
evidence-backed triggers:

1. the full named-host correctness and performance matrix exists and meets an
   owner-approved budget;
2. a safe std-backed candidate passes poison, panic, try, `Condvar`, mapping,
   lock-order, cancellation, shutdown, quiescence, and stable-lane contracts;
3. a supported-platform incumbent defect cannot be repaired upstream or while
   retaining the dependency;
4. an advisory, unsoundness report, or maintenance-abandonment record changes
   incumbent risk;
5. a fresh marginal ledger proves an owner-approved graph, native-code, or
   supply-chain budget violation.

Until then, `implementation_authority` is `NONE`,
`implementation_children_authorized` is false, and `children_unblocked` is
empty.

## Focused validation

Run the inventory contract through clean-overlay remote compilation:

```bash
RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay \
  --overlay-path artifacts/oslock_inventory_gate_v1.json \
  --overlay-path docs/oslock_inventory_gate.md \
  --overlay-path tests/oslock_inventory_gate_contract.rs \
  -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  RUSTFLAGS='-D warnings -C debuginfo=0' \
  CARGO_TARGET_DIR="${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_oslock_inventory_gate" \
  cargo test -p asupersync \
  --test oslock_inventory_gate_contract -- --nocapture
```

No local Cargo fallback is approved.

## No-claim boundary

This inventory does not prove release readiness, broad workspace health,
cross-platform correctness, performance equivalence, lock-order completeness,
or cancellation safety for every direct lock site. The graph ledger proves
package deltas only.

Terminal `DEFER` is successful completion of the A1 gate. It does not authorize
a wrapper implementation, call-site migration, dependency removal, manifest
change, implementation-child execution, deletion, destructive cleanup, peer
build cancellation, branch creation, or worktree creation.

<!-- END OSLOCK INVENTORY GATE -->
