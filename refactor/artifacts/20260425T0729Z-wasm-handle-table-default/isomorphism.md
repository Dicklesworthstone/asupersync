# Isomorphism Proof: `WasmHandleTable` Derived Default

## Change

Derive `Default` for `WasmHandleTable` in `src/types/wasm_abi.rs`, remove its
manual `Default` implementation, and delegate `WasmHandleTable::new()` to the
derived default.

## Preconditions

- `WasmHandleTable` has four fields: `slots`, `generations`, `free_list`, and
  `live_count`.
- `Vec::<Option<WasmHandleEntry>>::default()` is equivalent to `Vec::new()`.
- `Vec::<u32>::default()` is equivalent to `Vec::new()`.
- `usize::default()` is `0`.
- `with_capacity` remains the only constructor that pre-allocates vector
  capacity and is unchanged.

## Field Mapping

| Field | Previous `new()` value | Derived `Default` value |
| --- | --- | --- |
| `slots` | `Vec::new()` | empty `Vec` |
| `generations` | `Vec::new()` | empty `Vec` |
| `free_list` | `Vec::new()` | empty `Vec` |
| `live_count` | `0` | `usize::default()` (`0`) |

## Behavior Preservation

- `WasmHandleTable::default()` and `WasmHandleTable::new()` still produce an
  empty table with no live handles and no pre-allocated capacity.
- Slot allocation, generation checks, release behavior, and capacity-specific
  construction are unchanged.
- Public API and call sites are unchanged.
