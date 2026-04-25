# Isomorphism Proof: `TraceMigrator` Default Delegation

## Change

Delegate `TraceMigrator::new()` in `src/trace/compat.rs` to the already-derived
`Default` implementation.

## Preconditions

- `TraceMigrator` derives `Default`.
- `TraceMigrator` has one field: `migrations`.
- `Vec::<Box<dyn TraceMigration>>::default()` is equivalent to `Vec::new()`.
- Registration, migration ordering, and migration application methods are
  unchanged.

## Field Mapping

| Field | Previous `new()` value | Derived `Default` value |
| --- | --- | --- |
| `migrations` | `Vec::new()` | empty `Vec` |

## Behavior Preservation

- `TraceMigrator::new()` still returns a migrator with no registered
  migrations.
- Later `register` calls push into the same initially empty vector state.
- Migration lookup order, metadata behavior, event behavior, and public API are
  unchanged.
- No ordering, error, RNG, or side-effect semantics are involved before
  migrations are registered.
