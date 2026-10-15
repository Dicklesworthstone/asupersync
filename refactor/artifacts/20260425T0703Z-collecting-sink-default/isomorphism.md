# Isomorphism Proof: `CollectingSink` Default Delegation

## Change

Delegate `CollectingSink::new()` in `src/transport/sink.rs` to the
already-derived `Default` implementation.

## Preconditions

- `CollectingSink` derives `Default`.
- `CollectingSink` has one field: `symbols: Vec<AuthenticatedSymbol>`.
- `Vec::<AuthenticatedSymbol>::default()` is equivalent to `Vec::new()`.

## Field Mapping

| Field | Previous `new()` value | Derived `Default` value |
| --- | --- | --- |
| `symbols` | `Vec::new()` | empty `Vec<AuthenticatedSymbol>` |

## Behavior Preservation

- `CollectingSink::new()` still returns a sink with no collected symbols.
- `symbols()`, `into_symbols()`, and sink polling behavior are unchanged.
- Public API and existing call sites are unchanged.
