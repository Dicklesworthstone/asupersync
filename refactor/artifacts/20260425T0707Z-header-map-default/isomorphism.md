# Isomorphism Proof: `HeaderMap` Default Delegation

## Change

Delegate `HeaderMap::new()` in `src/http/body.rs` to the already-derived
`Default` implementation.

## Preconditions

- `HeaderMap` derives `Default`.
- `HeaderMap` has two fields: `headers` and `positions`.
- `Vec::<(HeaderName, HeaderValue)>::default()` is equivalent to `Vec::new()`.
- `DetHashMap::<HeaderName, Vec<usize>>::default()` is the same value the
  previous constructor used explicitly.

## Field Mapping

| Field | Previous `new()` value | Derived `Default` value |
| --- | --- | --- |
| `headers` | `Vec::new()` | empty `Vec` |
| `positions` | `DetHashMap::default()` | `DetHashMap::default()` |

## Behavior Preservation

- `HeaderMap::new()` still returns an empty header map.
- Insertion order, deterministic lookup state, append/get/remove behavior, and
  capacity-specific construction are unchanged.
- Public API and existing call sites are unchanged.
