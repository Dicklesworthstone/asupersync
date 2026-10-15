# Isomorphism Proof: `ConcurrentSymbolSet` Default Delegation

## Change

Delegate `ConcurrentSymbolSet::new()` in `src/types/symbol_set.rs` to the
already-derived `Default` implementation.

## Preconditions

- `ConcurrentSymbolSet` derives `Default`.
- `ConcurrentSymbolSet` has one field: `inner`.
- Derived `Default` initializes `inner` with `RwLock::<SymbolSet>::default()`.
- `RwLock::<SymbolSet>::default()` wraps `SymbolSet::default()`.
- `SymbolSet::default()` delegates to `SymbolSet::new()`, matching the previous
  constructor.

## Field Mapping

| Field | Previous `new()` value | Derived `Default` value |
| --- | --- | --- |
| `inner` | `RwLock::new(SymbolSet::new())` | `RwLock::default()` over `SymbolSet::default()` |

## Behavior Preservation

- `ConcurrentSymbolSet::new()` still returns an empty concurrent symbol set
  with the default threshold configuration.
- Insert, remove, contains, statistics, and snapshot behavior operate on the
  same initial inner set state.
- Locking type and public API are unchanged.
