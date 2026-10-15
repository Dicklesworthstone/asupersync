# Isomorphism Proof: `FilterBuilder` Default Delegation

## Change

Delegate `FilterBuilder::new()` in `src/trace/filter.rs` to the
already-derived `Default` implementation.

## Preconditions

- `FilterBuilder` derives `Default`.
- `FilterBuilder` has one field: `filter`.
- Derived `Default` initializes `filter` with `TraceFilter::default()`.
- `TraceFilter::new()` already returns `Self::default()`.
- Builder methods and `build()` are unchanged.

## Field Mapping

| Field | Previous `new()` value | Derived `Default` value |
| --- | --- | --- |
| `filter` | `TraceFilter::new()` | `TraceFilter::default()` |

## Behavior Preservation

- `FilterBuilder::new()` still starts from a default trace filter.
- Include/exclude/sample builder methods mutate the same initial filter state.
- `build()` still returns the accumulated filter without additional work.
- No ordering, error, RNG, or side-effect semantics are involved.
