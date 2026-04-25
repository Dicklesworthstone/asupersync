# Isomorphism Proof: `Metrics` Default Derive

## Change

Replace the manual `impl Default for Metrics` in `src/sync/contended_mutex.rs`
with `#[derive(Default)]`.

## Preconditions

- `Metrics` is private to the `inner` module behind the `lock-metrics` feature.
- Construction sites continue to call `Metrics::default()`.
- The struct layout attributes, field order, field names, and field types are
  unchanged.

## Field Mapping

| Field | Manual default | Derived default |
| --- | --- | --- |
| `acquisitions` | `AtomicU64::new(0)` | `AtomicU64::default()` = `AtomicU64::new(0)` |
| `contentions` | `AtomicU64::new(0)` | `AtomicU64::default()` = `AtomicU64::new(0)` |
| `wait_ns` | `AtomicU64::new(0)` | `AtomicU64::default()` = `AtomicU64::new(0)` |
| `max_wait_ns` | `AtomicU64::new(0)` | `AtomicU64::default()` = `AtomicU64::new(0)` |
| `_pad` | `[0; 32]` | `<[u8; 32] as Default>::default()` = `[0; 32]` |
| `hold_ns` | `AtomicU64::new(0)` | `AtomicU64::default()` = `AtomicU64::new(0)` |
| `max_hold_ns` | `AtomicU64::new(0)` | `AtomicU64::default()` = `AtomicU64::new(0)` |

## Behavior Preservation

- `repr(C, align(64))` is unchanged.
- The lock and unlock paths read and update the same atomic fields with the same
  memory orderings after construction.
- Public `LockMetricsSnapshot` values are computed from the same zero-initialized
  counters.
- No public API changes: `Metrics` remains private and `ContendedMutex` methods
  are unchanged.
