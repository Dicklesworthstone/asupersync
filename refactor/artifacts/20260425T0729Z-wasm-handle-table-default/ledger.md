# Refactor Ledger: `WasmHandleTable` Derived Default

## Scope

- Source: `src/types/wasm_abi.rs`
- Artifact directory:
  `refactor/artifacts/20260425T0729Z-wasm-handle-table-default/`

## Line Delta

- Source lines before: 7128
- Source lines after: 7117
- Source reduction: 11 lines

## Proof Summary

`WasmHandleTable` manually implemented `Default` by calling `new()`, and `new()`
duplicated the field defaults for three vectors plus a zero live-count. Deriving
`Default` directly and delegating `new()` through it preserves the empty table
state while removing repeated initialization.

## Verification

- Passed: `rustfmt --edition 2024 --check src/types/wasm_abi.rs`
- Passed:
  `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-wasm-handle-table-0736-check -p asupersync --lib`
- Passed:
  `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-wasm-handle-table-0738-clippy -p asupersync --lib -- -D warnings`

Note: an earlier check command on target dir
`/tmp/cargo-target-asupersync-wasm-handle-table-0729-check` compiled
successfully remotely but hung during local artifact retrieval, so it was
interrupted and rerun to obtain a complete command exit.

## Fresh-Eyes Review

- Verified `WasmHandleTable` fields remain `slots`, `generations`,
  `free_list`, and `live_count`.
- Verified derived defaults map the three vectors to empty vectors and
  `live_count` to `0`.
- Verified `WasmHandleTable::new()` still returns an empty, unallocated table.
- Verified `with_capacity` still pre-allocates only `slots` and `generations`
  and remains unchanged.
