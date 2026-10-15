# Cross-Module Lock Ordering

## Problem Statement

Runtime paths can cross scheduler, cancellation, capability, channel, and
obligation domains while holding locks. If those paths acquire locks in different
orders, they can deadlock even when each individual module looks locally sound.

## Solution Overview

The lock-ordering guard in `src/sync/lock_ordering.rs` enforces the canonical
hierarchy:

```text
E(Config) -> D(Instrumentation) -> B(Regions) -> A(Tasks) -> C(Obligations)
```

When `debug_assertions` or the `lock-metrics` feature is enabled, the guard
tracks held ranks and module identities in thread-local state. It panics with
`[ASUP-E205]` before a rank inversion or a known cross-module deadlock pattern
can proceed.

Release builds without `lock-metrics` compile out acquisition/release checks.
The lock constructors still keep their diagnostic rank metadata, but the hot
path ordering guard is disabled.

### Key Components

1. **Rank Classification**: `LockRank::from_name` maps known lock-name prefixes
   into the E/D/B/A/C hierarchy.
2. **Name Policy**: `classify_lock_name` documents whether a lock is ranked,
   explicitly allowed-unranked, or denied as an undocumented unknown.
3. **Module Identification**: `LockModule::from_name` classifies locks by their
   owning module for cross-module checks.
4. **Tracking**: thread-local state tracks held ranks and `LockInfo` records.
5. **Diagnostics**: all ordering and policy failures start with `[ASUP-E205]`
   and include a stable reason string.

### Module Classification

```rust
pub enum LockModule {
    Runtime,     // Core runtime module (scheduler, regions, tasks)
    Sync,        // Synchronization primitives module  
    Cx,          // Capability context module
    Cancel,      // Cancellation protocol module
    Obligation,  // Obligation tracking module
    Channel,     // Channel and messaging modules
    Io,          // I/O and networking modules
    Other,       // Other/unknown modules
}
```

### Lock-Name Policy

Ranked locks are names whose lowercase prefix maps to a rank:

| Prefix | Rank |
| --- | --- |
| `config` | E(Config) |
| `metrics`, `instrumentation`, `trace` | D(Instrumentation) |
| `region` | B(Regions) |
| `task`, `scheduler` | A(Tasks) |
| `obligation` | C(Obligations) |

Some existing locks intentionally remain outside the rank hierarchy because they
span multiple domains, are local test helpers, or are single-purpose non-runtime
guards. These names are allowed only because they are documented in
`allowed_unranked_reason`:

| Names | Reason |
| --- | --- |
| `unknown` | `allowed-default-unranked-lock` |
| `runtime_state`, `metamorphic.runtime_state`, `ws_fairness.runtime_state`, `test_runtime_state`, `test_state` | `allowed-legacy-runtime-state-lock` |
| `atp_transfer_registry` | `allowed-atp-transfer-registry-lock` |
| `atp_memory_object_store` | `allowed-atp-object-store-lock` |
| `transfer_actor`, `atp_transfer_actor` | `allowed-atp-transfer-actor-lock` |
| `epoch_gc.last_advance` | `allowed-epoch-gc-rate-limiter-lock` |
| `service_adapter` | `allowed-service-adapter-lock` |
| `test_abandon_read`, `test_abandon_write` | `allowed-lock-order-test-helper` |

Any other unranked name is denied by `enforce_lock_name_policy` with
`reason=denied-unknown-lock-rank`.

`Mutex::with_name`, `RwLock::with_name`, `Semaphore::with_name`, and
`ContendedMutex::new` route names through `rank_for_lock_name`. With
`lock-metrics` enabled, that path enforces the allow/deny policy and fails
closed for undocumented names. Without `lock-metrics`, it preserves the
historical prefix classifier and does not turn unknown names into runtime
failures.

### Cross-Module Rules

The system enforces three key cross-module patterns:

1. **Obligation-Cancel Ordering**: Obligation module locks should not be acquired while holding Cancel module locks
2. **Cx-Cancel Coordination**: Capability context operations must complete before cancellation  
3. **Runtime-Obligation Consistency**: Task scheduling must be coordinated with obligation tracking

## Usage

### Automatic Constructor Policy

Use a ranked name for runtime locks:

```rust
let mutex = Mutex::with_name("obligation_tracker", data);
let guard = mutex.lock(&cx).await?; // Automatically enforced
```

Use an explicitly documented unranked name only when the lock is intentionally
outside the runtime rank hierarchy. Adding a new unranked production name
requires adding a stable reason string and policy coverage in
`src/sync/lock_ordering.rs`.

### Enhanced API (Explicit)

For fine-grained control, use the `LockOrderEnforcer`:

```rust
use asupersync::sync::lock_ordering::{LockOrderEnforcer, LockRank, LockModule};

let enforcer = LockOrderEnforcer::with_module(
    "runtime_task_queue", 
    LockRank::Tasks, 
    LockModule::Runtime
);

enforcer.acquire(); // Check ordering and record acquisition
// ... critical section ...  
enforcer.release();  // Record release
```

## Implementation Details

### Module Detection

Module classification is automatic based on naming conventions:

- Names containing "runtime" or "scheduler" → `Runtime`
- Names containing "cx" or "scope" → `Cx`  
- Names containing "cancel" → `Cancel`
- Names containing "obligation" → `Obligation`
- etc.

### Thread-Local Tracking

Enhanced tracking uses two thread-local data structures:

```rust
static HELD_RANKS: RefCell<BTreeSet<LockRank>>;           // Basic rank tracking
static HELD_LOCKS: RefCell<BTreeMap<LockRank, Vec<LockInfo>>>; // Detailed lock info
```

### Performance

- **Debug builds**: rank and cross-module validation are active.
- **Release builds with `lock-metrics`**: rank and cross-module validation are
  active, and constructor policy rejects undocumented unknown names.
- **Release builds without `lock-metrics`**: acquisition/release ordering checks
  compile out; constructor prefix classification remains diagnostic metadata.

## Testing

The implementation includes comprehensive test coverage:

- Basic rank ordering preservation
- Cross-module pattern violations (should panic)
- Module detection accuracy
- Integration with existing lock ordering system
- Unknown-name fail-closed policy under `lock-metrics`
- Same-name duplicate acquisition release accounting
- Poisoned ranked lock release accounting

Run tests with:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_lock_order_policy_lib" CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --lib --features lock-metrics lock_ordering -- --nocapture
```

## Migration

When adding a named lock:

1. Prefer a ranked prefix from the table above.
2. If the lock cannot honestly be ranked, document it in
   `allowed_unranked_reason` with a stable `LOCK_ORDER_REASON_*` string and a
   focused test.
3. Do not add a broad allowlist pattern for convenience. Undocumented unknown
   names must continue to fail closed under `lock-metrics`.
4. If the lock crosses modules, use explicit module-aware acquisition helpers or
   `LockOrderEnforcer::with_module` so diagnostics point at the real hierarchy.

## Future Work

- Extend module classification only when a concrete cross-module pattern needs a
  stable diagnostic.
- Feed lock-order atlas rows into the L3 proof-status artifact.
- Keep profiler and contention-atlas work scoped to `lock-metrics`; do not make
  lock-order instrumentation production-on-by-default.
