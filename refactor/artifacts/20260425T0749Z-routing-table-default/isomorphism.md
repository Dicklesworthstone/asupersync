# Isomorphism Proof: `RoutingTable` Derived Default

## Change

Derive `Default` for `RoutingTable` in `src/transport/router.rs`, remove its
manual `Default` implementation, and delegate `RoutingTable::new()` to the
derived default.

## Preconditions

- `RoutingTable` has three fields: `routes`, `default_route`, and `endpoints`.
- `RwLock<HashMap<_, _>>::default()` wraps an empty `HashMap`.
- `RwLock<Option<_>>::default()` wraps `None`.
- The previous constructor initialized those exact empty/none states manually.
- Route mutation, lookup, pruning, and endpoint registration methods are
  unchanged.

## Field Mapping

| Field | Previous `new()` value | Derived `Default` value |
| --- | --- | --- |
| `routes` | `RwLock::new(HashMap::new())` | `RwLock::default()` over empty `HashMap` |
| `default_route` | `RwLock::new(None)` | `RwLock::default()` over `None` |
| `endpoints` | `RwLock::new(HashMap::new())` | `RwLock::default()` over empty `HashMap` |

## Behavior Preservation

- `RoutingTable::new()` and `RoutingTable::default()` still produce a table
  with no routes, no default route, and no endpoints.
- Registration, lookup fallback order, default-route behavior, route counts, and
  pruning are unchanged after construction.
- Locking types and public API are unchanged.
