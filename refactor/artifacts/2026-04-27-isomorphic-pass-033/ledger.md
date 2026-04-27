# Isomorphic Refactor Pass 033 Ledger

## Baseline

- Commit: `7cb69aa50`
- Scope: `src/record/obligation.rs`
- Source LOC before: 878
- Source LOC after: 876
- Source LOC delta: -2
- Candidate: collapse the common resolved-state transition shared by `ObligationRecord::commit`, `abort`, and `mark_leaked`.

## Opportunity Matrix

| Candidate | LOC | Confidence | Risk | Score | Decision |
| --- | ---: | ---: | ---: | ---: | --- |
| Shared obligation resolution transition helper | 2 | 5 | 1 | 10.0 | Implement |

## Isomorphism Card

### Equivalence Contract

- Inputs covered: all existing `ObligationRecord` callers of `commit`, `abort`, and `mark_leaked`; focused unit tests for lifecycle and double-resolution panics.
- Ordering preserved: each public method still validates pending state, mutates `state`/`resolved_at`/`abort_reason`, computes `duration_held`, emits its original log event, and returns the duration.
- Tie-breaking: N/A.
- Error semantics: same `assert!(self.is_pending(), "obligation already resolved")` panic condition and message.
- Laziness: N/A.
- Short-circuit eval: unchanged; the pending assertion still runs before mutation.
- Floating-point: N/A.
- RNG / hash order: N/A.
- Observable side-effects: trace/info/error log events remain in the same public methods with the same event names and payload fields.
- Type narrowing: Rust types unchanged; no public signature changes.
- Rerender behavior: N/A.

### Verification Plan

- `rustfmt --edition 2024 --check src/record/obligation.rs` - passed
- `git diff --check -- src/record/obligation.rs refactor/artifacts/2026-04-27-isomorphic-pass-033/ledger.md` - passed
- `rch exec -- cargo test -p asupersync --lib record::obligation` - passed, 24 passed, 0 failed
- `rch exec -- cargo check -p asupersync --lib` - passed
- `rch exec -- cargo clippy -p asupersync --lib -- -D warnings` - passed

## Rejection Log

- No cross-file test-helper extraction: higher coupling for lower production value.
- No constructor unification: reservation logging differs enough that a helper would obscure event semantics.
