# Isomorphism Proof: `StubBroker` Default Derive

## Change

Replace the manual `impl Default for StubBroker` in `src/messaging/kafka.rs`
with `#[derive(Default)]`.

## Preconditions

- `StubBroker` is private and compiled only when the `kafka` feature is disabled.
- `StubBrokerState` already derives `Default`.
- `Notify::default()` is equivalent to `Notify::new()`.
- `std::sync::Mutex<T>::default()` wraps `T::default()` in a new mutex.

## Field Mapping

| Field | Manual default | Derived default |
| --- | --- | --- |
| `state` | `Mutex::new(StubBrokerState::default())` | `Mutex::<StubBrokerState>::default()` |
| `notify` | `Notify::new()` | `Notify::default()` |

## Behavior Preservation

- `STUB_BROKER` remains a `OnceLock<StubBroker>`.
- The fallback producer and consumer paths still receive an empty broker state
  and a fresh notification primitive.
- No public API changes: `StubBroker` remains private and feature-gated.
