# Isomorphism Proof: `RoundRobin::new()` Delegates to Default

## Change

Replace the manual `RoundRobin::new()` constructor body in
`src/service/load_balance.rs` with `Self::default()`.

## Preconditions

- `RoundRobin` already derives `Default`.
- `RoundRobin` has one field: `next: AtomicUsize`.
- `AtomicUsize::default()` is equivalent to `AtomicUsize::new(0)`.

## Field Mapping

| Field | Manual `new()` value | Derived default value |
| --- | --- | --- |
| `next` | `AtomicUsize::new(0)` | `AtomicUsize::default()` = `AtomicUsize::new(0)` |

## Behavior Preservation

- `RoundRobin::new()` still returns a round-robin strategy whose next index is
  zero.
- `Strategy::pick()` still observes and updates the same atomic counter.
- Public constructor and trait impls are unchanged.
