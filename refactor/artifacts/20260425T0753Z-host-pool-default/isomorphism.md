# Isomorphism Proof: `HostPool` Derived Default

## Change

Derive `Default` for `HostPool` in `src/http/pool.rs` and delegate
the missing-key insertion path to the derived default.

## Preconditions

- `HostPool` has one field: `connections`.
- `HashMap::<u64, PooledConnectionMeta>::default()` is equivalent to
  `HashMap::new()`.
- The only `HostPool::new()` call created empty per-host pools before inserting
  connection metadata.
- Connection insertion, counting, idle/in-use/connecting classification, and
  cleanup behavior are unchanged.

## Field Mapping

| Field | Previous `new()` value | Derived `Default` value |
| --- | --- | --- |
| `connections` | `HashMap::new()` | empty `HashMap` |

## Behavior Preservation

- `HashMap::entry(...).or_default()` creates a host pool with zero tracked
  connections in the same missing-key case as `or_insert_with(HostPool::new)`.
- Per-host capacity checks, idle reuse selection, and cleanup all observe the
  same initial empty map state.
- Public `Pool` behavior and connection ID allocation are unchanged.
