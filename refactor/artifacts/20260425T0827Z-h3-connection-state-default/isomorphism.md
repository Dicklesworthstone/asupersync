# Isomorphism Proof: `H3ConnectionState` Derived Default

## Change

Derive `Default` for `H3ConnectionState`, make `new()` call
`Self::default()`, and remove the manual `Default` implementation.

## Preconditions

- `H3ConnectionConfig::default()` preserves the client endpoint role, static
  QPACK mode, 1 MiB max frame payload, and no request-stream limit.
- `H3ControlState::default()` creates the same unset control-stream flags as
  the previous `with_config` path.
- `BTreeMap::default()` and `BTreeSet::default()` are empty collections.
- `Option::<u64>::default()` is `None`.
- `new_server()` and `with_config(...)` keep their explicit configuration paths.

## Field Mapping

| Field group | Previous `new()` path | Derived `Default` value |
| --- | --- | --- |
| `config` | `H3ConnectionConfig::default()` | `H3ConnectionConfig::default()` |
| `control` | `H3ControlState::default()` | `H3ControlState::default()` |
| stream maps/sets | empty `BTreeMap`/`BTreeSet` | empty `BTreeMap`/`BTreeSet` |
| stream IDs / GOAWAY | `None` | `None` |

## Behavior Preservation

- `H3ConnectionState::new()` still builds the client/default connection state.
- `H3ConnectionState::new_server()` still uses the explicit server role config.
- `H3ConnectionState::with_config(...)` remains the only path for custom config.
- Frame ordering, stream tracking, GOAWAY validation, and QPACK state behavior
  are unchanged because only default construction is simplified.
