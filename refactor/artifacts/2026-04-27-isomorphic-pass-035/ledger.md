# Isomorphic Refactor Pass 035

## Baseline
- Base commit: 3eadf537c
- Target: `src/codec/length_delimited.rs`
- Source LOC before: 2171
- Source LOC after: 2169
- Source LOC delta: -2
- Candidate: collapse repeated `LengthDelimitedCodecBuilder` scalar setters into one local macro.
- Fresh-eyes repairs: aligned two stale inline tests with existing artifacts/current o7e5xu recovery semantics; no golden files changed.

## Isomorphism Card
- Inputs covered: existing `LengthDelimitedCodecBuilder` methods for `length_field_offset`, `length_field_length`, `length_adjustment`, `num_skip`, and `max_frame_length`.
- Ordering preserved: yes; each method still assigns exactly one field before returning `self`.
- Tie-breaking: N/A.
- Error semantics: unchanged; setters still perform no validation and `new_codec` still owns the length-field assertion.
- Laziness: N/A.
- Short-circuit eval: N/A.
- Floating-point: N/A.
- RNG / hash order: N/A.
- Observable side-effects: unchanged; setters have no side effects beyond the builder field assignment.
- Type narrowing: unchanged; each generated method keeps the exact public signature and scalar type.

## Verification Plan
- `rustfmt --edition 2024 --check src/codec/length_delimited.rs` passed.
- `git diff --check -- src/codec/length_delimited.rs refactor/artifacts/2026-04-27-isomorphic-pass-035/ledger.md` passed.
- `rch exec -- cargo test -p asupersync --lib codec::length_delimited` passed: 43 passed, 0 failed.
- `rch exec -- cargo check -p asupersync --lib` passed.
- `rch exec -- cargo clippy -p asupersync --lib -- -D warnings` passed.
