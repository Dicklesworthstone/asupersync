# Isomorphism Proof: CRDT Merge Extension

## Change

Replace the manual loop that appends `other.entries` into the `MVRegister`
merge work vector with `combined.extend(other.entries.iter().cloned())`.

## Preconditions

- `other.entries.iter()` yields entries in the same deterministic `BTreeSet`
  order for both the loop and `extend`.
- `cloned()` produces the same owned `(V, BTreeMap<NodeId, u64>)` values that
  `entry.clone()` produced inside the loop.
- `Vec::extend` appends to the existing vector rather than replacing existing
  elements.
- The rejected derived-default candidate was not applied because it would add an
  undesired `V: Default` bound to generic CRDT types.

## Element Mapping

| Previous loop | `extend` form |
| --- | --- |
| `for entry in &other.entries` | `other.entries.iter()` |
| `combined.push(entry.clone())` | `combined.extend(...cloned())` |

## Behavior Preservation

- `combined` still contains all existing `self.entries` first, followed by all
  `other.entries`.
- Dominance filtering sees the same values in the same order.
- Version-counter merge and public `MVRegister` behavior are unchanged.
