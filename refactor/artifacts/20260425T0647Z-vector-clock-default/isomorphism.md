# Isomorphism Proof: `VectorClock` Default Delegation

## Change

Delegate `VectorClock::new()` in `src/trace/distributed/vclock.rs` to the
already-derived `Default` implementation.

## Preconditions

- `VectorClock` derives `Default`.
- `VectorClock` has one field: `entries: BTreeMap<NodeId, u64>`.
- `BTreeMap::<NodeId, u64>::default()` is an empty deterministic map,
  equivalent to `BTreeMap::new()`.

## Field Mapping

| Field | Previous `new()` value | Derived `Default` value |
| --- | --- | --- |
| `entries` | `BTreeMap::new()` | empty `BTreeMap` |

## Behavior Preservation

- `VectorClock::new()` still returns a clock with no components.
- `get()` still reports `0` for absent nodes.
- `for_node`, merge, comparison, serialization, and mutation logic are
  unchanged.
- Public API and all existing call sites are unchanged.
