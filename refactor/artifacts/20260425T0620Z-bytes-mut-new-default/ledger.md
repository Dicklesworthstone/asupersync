# Refactor Ledger: `BytesMut` Constructor Delegation

## Scope

- Source: `src/bytes/bytes_mut.rs`
- Artifact directory:
  `refactor/artifacts/20260425T0620Z-bytes-mut-new-default/`

## Line Delta

- Source lines before: 737
- Source lines after: 733
- Source reduction: 4 lines

## Proof Summary

`BytesMut` already exposes equivalent default, slice, and vector conversion
paths. The edited constructors now delegate to those existing paths instead of
repeating the same field construction.

## Verification

- Passed: `rustfmt --edition 2024 --check src/bytes/bytes_mut.rs`
- Passed: `rch exec -- cargo check -p asupersync --lib`
- Passed: `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-bytes-mut-0620-clippy -p asupersync --lib -- -D warnings`

## Fresh-Eyes Review

- Verified that `BytesMut` still derives `Default`.
- Verified that `BytesMut::new()` delegates to the derived empty `Vec<u8>`
  default.
- Verified that `From<&str>` delegates to `From<&[u8]>`, which copies the same
  `s.as_bytes()` with `to_vec()`.
- Verified that `From<String>` delegates to `From<Vec<u8>>`, preserving
  ownership transfer from `String::into_bytes()`.
- Verified that no delegation path recurses.
