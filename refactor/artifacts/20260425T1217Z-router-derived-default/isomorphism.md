# Isomorphism Card: Router Derived Default

## Change

Replace the hand-written `Default` impl for `Router` with derived `Default`, and make `Router::new()` return that derived default.

## Equivalence Contract

- Inputs covered: all `Router::new()` and `Router::default()` construction paths.
- Ordering preserved: empty route and nesting vectors have no observable order.
- Tie-breaking: unchanged because no routes or nested routers exist in the constructed state.
- Error semantics: unchanged; construction remains infallible.
- Laziness: unchanged; no routes, fallback, handlers, or extension entries are allocated beyond empty collection construction.
- Short-circuit eval: not applicable.
- Floating-point: not applicable.
- RNG/hash order: unchanged; extension maps remain empty.
- Observable side-effects: unchanged; construction performs no I/O, logging, tracing, or handler invocation.
- Rust type behavior: unchanged public `Default` implementation for the concrete `Router` type.
- Drop/reclaim behavior: unchanged; the default router owns only empty collections and `None`.

## Proof Notes

- The old `Router::new()` literal initialized `routes` to `Vec::new()`, `nested` to `Vec::new()`, `fallback` to `None`, and `extensions` to `Extensions::new()`.
- `Extensions::new()` is already `Self::default()`, and `Extensions` derives `Default` over empty maps.
- Derived `Router::default()` initializes `routes` and `nested` with `Vec::default()`, `fallback` with `Option::default()`, and `extensions` with `Extensions::default()`.
- `Vec::default()` is equivalent to `Vec::new()` and `Option::default()` is `None`, so the constructed router state is unchanged.

## Verification Results

- PASS `rustfmt --edition 2024 --check src/web/router.rs`
- PASS `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-router-default-1217-check -p asupersync --lib`
- PASS `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-router-default-1217-test -p asupersync --lib web::router::tests::`
  - `30 passed; 0 failed; 14517 filtered out`
- PASS `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-router-default-1217-clippy -p asupersync --lib -- -D warnings`
