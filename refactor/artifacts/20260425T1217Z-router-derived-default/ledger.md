# Refactor Ledger: Router Derived Default

## Candidate

- File: `src/web/router.rs`
- Lever: derive the existing empty-router `Default`.
- Score: `(LOC_saved 10 * Confidence 5) / Risk 1 = 50.0`
- Decision: accepted.

## Baseline

- Source LOC before: `895 src/web/router.rs`
- Git state before edit: `src/web/router.rs` had no local modifications.
- Existing tests covering this surface: router tests cover routing, fallback behavior, nesting, path parameters, state extensions, and missing-route behavior.

## Expected Delta

- Add `Default` to `Router`.
- Replace the duplicated `Router::new()` literal with `Self::default()`.
- Remove the hand-written `Default` impl that only called `Self::new()`.
- Source LOC after edit: `885 src/web/router.rs`
- Source LOC reduction: `10`
- Preserve public API: `Router::new()` and `Router::default()` remain available.
- Preserve default state: no routes, no nested routers, no fallback handler, and empty extensions.

## Verification

- PASS `rustfmt --edition 2024 --check src/web/router.rs`
- PASS `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-router-default-1217-check -p asupersync --lib`
- PASS `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-router-default-1217-test -p asupersync --lib web::router::tests::`
  - `30 passed; 0 failed; 14517 filtered out`
- PASS `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-router-default-1217-clippy -p asupersync --lib -- -D warnings`

## Fresh-Eyes Review

- Re-read the changed source after formatting. The only source delta is deriving `Default`, making `Router::new()` call `Self::default()`, and removing the old manual `Default` impl.
- Verified all router mutation and dispatch paths are unchanged: `route`, `nest`, `fallback`, `with_state`, `handle`, and `route_count`.
- Verified derived field defaults match the old literal: `routes` and `nested` are empty vectors, `fallback` is `None`, and `extensions` uses `Extensions::default()`.
- Verified `Extensions::new()` already delegates to `Self::default()`, so replacing `Extensions::new()` in the construction path does not change extension-map contents.
