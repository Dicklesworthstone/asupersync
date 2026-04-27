# Isomorphic Simplification Pass 032

## Candidate

- File: `src/types/cancel.rs`
- Lever: generate repeated `CancelReason` const kind constructors with a local macro.
- Score: `(LOC_saved 3 * confidence 5) / risk 1 = 15.0`

## Isomorphism Proof

- Inputs covered: public `CancelReason::{timeout,deadline,poll_quota,cost_budget,sibling_failed,fail_fast,race_loser,race_lost,parent_cancelled,resource_unavailable,shutdown,linked_exit}` keep the same names, visibility, constness, argument list, and return type.
- Ordering preserved: every generated helper still makes exactly one call to `Self::new(CancelKind::...)`.
- Tie-breaking: unchanged / N/A.
- Error semantics: unchanged; each helper maps to the same `CancelKind` variant and preserves the same minimal default attribution from `Self::new`.
- Laziness: unchanged / N/A.
- Short-circuit eval: N/A.
- Floating-point: N/A.
- RNG / hash order: N/A.
- Observable side effects: none; constructors are const and only build the same value.
- Public docs and attributes: existing doc comments, `#[inline]`, and `#[must_use]` are preserved through macro expansion.

## Metrics

- Source LOC before: 2841
- Source LOC after: 2800
- Source LOC delta: -41
- Source diff numstat: 47 insertions, 88 deletions

## Validation

- `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-pass032-baseline -p asupersync --lib test_h2error_helper_constructors_set_codes`: inconclusive abandoned H2 baseline; remote job synced the pre-edit tree but produced no captured cargo summary after several minutes in the crate build phase.
- `rustfmt --edition 2024 --check src/types/cancel.rs`: pass.
- `git diff --check -- src/types/cancel.rs refactor/artifacts/2026-04-27-isomorphic-pass-032/ledger.md`: pass.
- `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-pass032-cancel-constructors -p asupersync --lib new_variants_constructors`: pass, 1 passed, 0 failed, 15169 filtered out.
- `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-pass032-check -p asupersync --lib`: pass.
- `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-pass032-clippy -p asupersync --lib -- -D warnings`: pass.

## Fresh-Eyes Review

- Abandoned `src/http/h2/error.rs` because the first macro shape was not net-negative; file is byte-identical to `HEAD` and its reservation was released.
- Re-read the final `src/types/cancel.rs` diff after rustfmt. The macro emits the same public `pub const fn` wrappers with the same `#[inline]`, `#[must_use]`, docs, names, and `CancelKind` mappings.
- Existing `new_variants_constructors` covers the generated constructor mappings for the newly-added cancel kinds and passed after the edit.
