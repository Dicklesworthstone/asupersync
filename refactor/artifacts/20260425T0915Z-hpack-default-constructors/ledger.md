# Refactor Ledger: HPACK Default Constructors

## Candidate

- File: `src/http/h2/hpack.rs`
- Lever: delegate default constructors to existing parameterized constructors.
- Score: `(LOC_saved 2 * Confidence 5) / Risk 1 = 10.0`
- Decision: accepted.

## Baseline

- Source LOC before: `3382 src/http/h2/hpack.rs`
- Git state before edit: `src/http/h2/hpack.rs` had no local modifications.
- Constructor constants checked:
  - `DEFAULT_MAX_TABLE_SIZE = 4096`
  - `MAX_ALLOWED_TABLE_SIZE = 1024 * 1024`

## Expected Delta

- Remove repeated field initialization in three `new` constructors.
- Source LOC after edit: `3369 src/http/h2/hpack.rs`
- Source LOC reduction: `13`
- Preserve public APIs: `DynamicTable::new`, `Encoder::new`, `Decoder::new`, and all `Default` impls remain.
- Preserve `with_max_size` behavior exactly; only default constructors reuse it.

## Verification

- PASS: `rustfmt --edition 2024 --check src/http/h2/hpack.rs`
- PASS: `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-hpack-default-0915-check -p asupersync --lib`
- PASS: `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-hpack-default-0915-test -p asupersync --lib http::h2::hpack`
  - Result: `101 passed; 0 failed; 14432 filtered out`
- PASS: `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-hpack-default-0915-clippy -p asupersync --lib -- -D warnings`

## Fresh-Eyes Review

- Re-read the final `src/http/h2/hpack.rs` diff after verification.
- Confirmed `DynamicTable::new` reaches the same `entries`, `size`, and `max_size` values via `DynamicTable::with_max_size(DEFAULT_MAX_TABLE_SIZE)`.
- Confirmed `Encoder::new` reaches the same dynamic table, Huffman default, and pending-size-update state via `Encoder::with_max_size(DEFAULT_MAX_TABLE_SIZE)`.
- Confirmed `Decoder::new` reaches the same dynamic table, `max_header_list_size`, and `allowed_table_size` values via `Decoder::with_max_size(DEFAULT_MAX_TABLE_SIZE)`.
- Confirmed no public API removal, no new trait bounds, and no unrelated file edits in the source diff.
