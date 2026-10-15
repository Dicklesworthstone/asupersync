# Isomorphism Card: HPACK Default Constructors

## Change

Delegate `DynamicTable::new`, `Encoder::new`, and `Decoder::new` to their existing
`with_max_size(DEFAULT_MAX_TABLE_SIZE)` constructors.

## Equivalence Contract

- Inputs covered: all default HPACK dynamic table, encoder, and decoder construction paths.
- Ordering preserved: yes; constructors allocate the same empty `VecDeque`-backed table state before use.
- Tie-breaking: unchanged; no ordering or selection logic changes.
- Error semantics: unchanged; constructors do not return errors, and `with_max_size(DEFAULT_MAX_TABLE_SIZE)` does not reject values.
- Laziness: unchanged; construction remains eager and does not touch static HPACK indexes.
- Short-circuit eval: not applicable.
- Floating-point: not applicable.
- RNG/hash order: unchanged; no hash maps are constructed by these constructors.
- Observable side-effects: unchanged; constructors do not log, trace, mutate globals, or perform I/O.
- Rust type behavior: unchanged public return types and no new trait bounds.
- Cancellation/runtime behavior: unchanged; this is synchronous pure state initialization.

## Proof Notes

- `DEFAULT_MAX_TABLE_SIZE` is `4096`.
- `MAX_ALLOWED_TABLE_SIZE` is `1024 * 1024`.
- `DEFAULT_MAX_TABLE_SIZE.min(MAX_ALLOWED_TABLE_SIZE) == DEFAULT_MAX_TABLE_SIZE`, so the cap in `with_max_size` preserves the previous default max table size.
- `DynamicTable::with_max_size` initializes `entries` to `VecDeque::new()` and `size` to `0`, matching `DynamicTable::new`.
- `Encoder::with_max_size` initializes `use_huffman` to `true`, `min_size_update` to `None`, and `pending_size_update` to `None`, matching `Encoder::new`.
- `Decoder::with_max_size` initializes `max_header_list_size` to `16384` and `allowed_table_size` to the capped default `4096`, matching `Decoder::new`.

## Verification Plan

- `rustfmt --edition 2024 --check src/http/h2/hpack.rs`
- `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-hpack-default-0915-check -p asupersync --lib`
- `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-hpack-default-0915-test -p asupersync --lib http::h2::hpack`
- `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-hpack-default-0915-clippy -p asupersync --lib -- -D warnings`
