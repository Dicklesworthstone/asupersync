# Isomorphic Refactor Pass 036

## Baseline
- Base commit: fcdf29d34
- Target: `src/http/h2/settings.rs`
- Source LOC before: 467
- Source LOC after: 457
- Source LOC delta: -10
- Candidate: collapse repeated `SettingsBuilder` setter bodies into one local macro while preserving each assignment expression.

## Isomorphism Card
- Inputs covered: `header_table_size`, `enable_push`, `max_concurrent_streams`, `initial_window_size`, `max_frame_size`, `max_header_list_size`, and `continuation_timeout_ms`.
- Ordering preserved: yes; each generated method still evaluates the setter argument expression, assigns exactly one `self.settings` field, then returns `self`.
- Tie-breaking: N/A.
- Error semantics: unchanged; direct setters still assign directly, `initial_window_size` still applies `min(MAX_INITIAL_WINDOW_SIZE)`, and `max_frame_size` still applies `clamp(MIN_MAX_FRAME_SIZE, MAX_MAX_FRAME_SIZE)`.
- Laziness: N/A.
- Short-circuit eval: N/A.
- Floating-point: N/A.
- RNG / hash order: N/A.
- Observable side-effects: unchanged; setters have no side effects beyond the builder field assignment.
- Type narrowing: unchanged; each generated method keeps the exact public signature and argument type.

## Verification Plan
- `rustfmt --edition 2024 --check src/http/h2/settings.rs` passed.
- `git diff --check -- src/http/h2/settings.rs refactor/artifacts/2026-04-27-isomorphic-pass-036/ledger.md` passed.
- `rch exec -- cargo test -p asupersync --lib http::h2::settings` passed: 12 passed, 0 failed.
- `rch exec -- cargo check -p asupersync --lib` reported remote exit 0; local wrapper ended during artifact retrieval.
- `rch exec -- cargo clippy -p asupersync --lib -- -D warnings` reported remote exit 0; local wrapper was terminated after artifact retrieval stalled.
