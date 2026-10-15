# Isomorphism Proof: `SettingsBuilder` Default Delegation

## Change

Delegate `SettingsBuilder::new()` in `src/http/h2/settings.rs` to the
already-derived `Default` implementation.

## Preconditions

- `SettingsBuilder` derives `Default`.
- `SettingsBuilder` has one field: `settings`.
- Derived `Default` initializes `settings` with `Settings::default()`.
- The previous constructor also initialized `settings` with
  `Settings::default()`.
- Builder setter methods and `build()` are unchanged.

## Field Mapping

| Field | Previous `new()` value | Derived `Default` value |
| --- | --- | --- |
| `settings` | `Settings::default()` | `Settings::default()` |

## Behavior Preservation

- `SettingsBuilder::new()` still starts from default HTTP/2 settings.
- Every fluent setter mutates the same initial settings state.
- `build()` still returns the accumulated settings unchanged.
- No ordering, error, RNG, or side-effect semantics are involved.
