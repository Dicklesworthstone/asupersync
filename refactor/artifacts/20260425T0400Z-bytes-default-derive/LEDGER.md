# Bytes Default Derive Isomorphic Simplification Ledger

Run: `20260425T0400Z-bytes-default-derive`
Agent: `ProudLake`

## Accepted Passes

| Pass | File | Change | Isomorphism proof |
| --- | --- | --- | --- |
| 1 | `src/bytes/bytes.rs` | Derive `Default` for `Bytes` and private `BytesInner`; remove manual `Bytes` impl. | Manual `Bytes::default()` delegated to `Bytes::new()`, which returns `BytesInner::Empty` with `start = 0` and `len = 0`. Derived default selects the marked `Empty` variant and zero-defaults both `usize` fields. |
| 2 | `src/bytes/bytes_mut.rs` | Derive `Default` for `BytesMut`; remove manual impl. | Manual `BytesMut::default()` delegated to `BytesMut::new()`, which stores `Vec::new()`. Derived default stores `Vec::default()`, the same empty vector state. |

## Verification Results

- `rustfmt --edition 2024 --check src/bytes/bytes.rs src/bytes/bytes_mut.rs`
- `git diff --check -- src/bytes/bytes.rs src/bytes/bytes_mut.rs refactor/artifacts/20260425T0400Z-bytes-default-derive/LEDGER.md`
- `rch exec -- cargo test -p asupersync --lib bytes_default --no-fail-fast`
  - 1 passed.
- `rch exec -- cargo test -p asupersync --lib bytes::bytes_mut --no-fail-fast`
  - 21 passed.
- `rch exec -- cargo check -p asupersync --all-targets`
- `rch exec -- cargo clippy -p asupersync --all-targets -- -D warnings`

## External Blocker

- `rch exec -- cargo test -p asupersync --lib bytes::bytes --no-fail-fast`
  failed 3 pre-existing conformance panic-message tests:
  `bytes_conformance_slice_out_of_bounds`,
  `bytes_conformance_split_off_out_of_bounds`, and
  `bytes_conformance_split_to_out_of_bounds`. The edited diff does not touch
  the panic paths or expected strings; this pass only changes the `Default`
  implementation surface.
