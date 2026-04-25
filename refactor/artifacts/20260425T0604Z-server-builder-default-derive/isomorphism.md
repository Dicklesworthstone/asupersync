# Isomorphism Proof: `ServerBuilder` Default Derive

## Change

Replace the manual `impl Default for ServerBuilder` in `src/grpc/server.rs`
with `#[derive(Default)]`.

## Preconditions

- `ServerBuilder` has no generic parameters.
- `ServerBuilder::new()` remains available and unchanged.
- The struct fields are unchanged.

## Field Mapping

| Field | Manual default via `new()` | Derived default |
| --- | --- | --- |
| `config` | `ServerConfig::default()` | `ServerConfig::default()` |
| `services` | `BTreeMap::new()` | `BTreeMap::default()` = empty map |
| `reflection` | `None` | `Option::<ReflectionService>::default()` = `None` |

## Behavior Preservation

- `ServerBuilder::default()` still creates the same empty builder configuration.
- `ServerBuilder::new()` still constructs the same value explicitly.
- The custom `Debug` implementation is unchanged.
- No public API is removed: `ServerBuilder` still implements `Default`.
