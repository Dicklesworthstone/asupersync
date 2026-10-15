# Isomorphic Refactor Pass 034 Ledger

## Baseline

- Commit: `144e18957`
- Scope: `src/codec/bytes_codec.rs`
- Source LOC before: 221
- Source LOC after: 207
- Source LOC delta: -14
- Candidate: generate the three identical `BytesCodec` encoder implementations for `Bytes`, `BytesMut`, and `Vec<u8>` from one local macro.

## Opportunity Matrix

| Candidate | LOC | Confidence | Risk | Score | Decision |
| --- | ---: | ---: | ---: | ---: | --- |
| Macro-generate identical `BytesCodec` encoder impls | 3 | 5 | 1 | 15.0 | Implement |

## Isomorphism Card

### Equivalence Contract

- Inputs covered: the existing concrete `Encoder<Bytes>`, `Encoder<BytesMut>`, and `Encoder<Vec<u8>>` impls and their unit tests.
- Ordering preserved: each generated impl still reserves `item.len()`, appends `&item` with `put_slice`, then returns `Ok(())`.
- Tie-breaking: N/A.
- Error semantics: unchanged; the implementations still cannot construct an error and return `Ok(())`.
- Laziness: N/A.
- Short-circuit eval: unchanged; no short-circuiting is involved.
- Floating-point: N/A.
- RNG / hash order: N/A.
- Observable side-effects: identical destination buffer mutation order and capacity reservation request.
- Type narrowing: Rust trait coverage remains the same three concrete impls; this does not introduce a blanket `AsRef<[u8]>` impl.
- Rerender behavior: N/A.

### Verification Plan

- `rustfmt --edition 2024 --check src/codec/bytes_codec.rs src/codec/bytes_codec_fuzz.rs` - passed
- `git diff --check -- src/codec/bytes_codec.rs src/codec/bytes_codec_fuzz.rs refactor/artifacts/2026-04-27-isomorphic-pass-034/ledger.md` - passed
- `rch exec -- cargo test -p asupersync --lib codec::bytes_codec_fuzz::edge_case_fuzz::fragmented_operations -- --exact` - passed, 1 passed, 0 failed
- `rch exec -- cargo test -p asupersync --lib codec::bytes_codec` - passed, 23 passed, 0 failed, 1 ignored
- `rch exec -- cargo check -p asupersync --lib` - passed
- `rch exec -- cargo clippy -p asupersync --lib -- -D warnings` - passed

## Rejection Log

- No blanket `impl<T: AsRef<[u8]>> Encoder<T>`: it would broaden the public trait surface beyond an isomorphic change.
- No helper-only extraction: it saves too little compared with emitting the exact existing impls from one local macro.
- Pre-refactor validation with `codec::bytes_codec` uncovered a separate fuzz-test assertion bug in `fragmented_operations`; fixed first in `144e18957`.
