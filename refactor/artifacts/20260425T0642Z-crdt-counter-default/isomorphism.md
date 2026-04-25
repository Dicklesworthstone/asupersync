# Isomorphism Proof: CRDT Counter Default Delegation

## Change

Delegate `GCounter::new()` and `PNCounter::new()` in
`src/trace/distributed/crdt.rs` to their already-derived `Default`
implementations.

## Preconditions

- `GCounter` derives `Default` and has one field:
  `counts: BTreeMap<NodeId, u64>`.
- `BTreeMap::<NodeId, u64>::default()` is an empty map, equivalent to
  `BTreeMap::new()`.
- `PNCounter` derives `Default` and has two fields:
  `positive: GCounter` and `negative: GCounter`.
- `GCounter::default()` is equivalent to an empty `GCounter`.

## Field Mapping

| Constructor | Previous values | Derived `Default` values |
| --- | --- | --- |
| `GCounter::new()` | empty `counts` map | empty `counts` map |
| `PNCounter::new()` | empty `positive`, empty `negative` | empty `positive`, empty `negative` |

## Behavior Preservation

- `GCounter::new()` still returns a counter with global value `0`.
- `PNCounter::new()` still returns a counter with net value `0`.
- Merge, increment, decrement, saturation, and ordering behavior are unchanged.
- Public constructors and all existing call sites are unchanged.
