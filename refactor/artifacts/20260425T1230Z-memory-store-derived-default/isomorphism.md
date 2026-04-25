# Isomorphism Card: MemoryStore Derived Default

## Change

Replace the hand-written `Default` impl for `MemoryStore` with derived `Default`.

## Equivalence Contract

- Inputs covered: all `MemoryStore::default()` construction paths.
- Ordering preserved: unchanged; the default store contains no sessions.
- Tie-breaking: not applicable.
- Error semantics: unchanged; construction remains infallible.
- Laziness: unchanged; construction still allocates one shared map holder.
- Short-circuit eval: not applicable.
- Floating-point: not applicable.
- RNG/hash order: unchanged; the hash map is empty and receives no insertions during construction.
- Observable side-effects: unchanged; construction performs no I/O, logging, tracing, or session mutation.
- Rust type behavior: unchanged public `Default` implementation for the concrete `MemoryStore` type.
- Drop/reclaim behavior: unchanged; the default store owns one `Arc` around an empty mutex-protected map.

## Proof Notes

- The removed `Default` implementation returned `Self::new()`.
- `Self::new()` initialized `sessions` as `Arc::new(Mutex::new(HashMap::new()))`.
- `Arc<T>::default()` for defaultable `T` constructs `Arc::new(T::default())`.
- `parking_lot::Mutex<T>::default()` constructs a mutex around `T::default()`.
- `HashMap::default()` is equivalent to `HashMap::new()` for an empty map.
- Derived `Default` therefore constructs an independent `Arc<Mutex<HashMap<_, _>>>` containing no sessions, matching `Self::new()`.

## Verification Results

- PASS `rustfmt --edition 2024 --check src/web/session.rs`
- PASS `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-memory-store-default-1230-check -p asupersync --lib`
- PASS `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-memory-store-default-1230-test -p asupersync --lib web::session::tests::`
  - `31 passed; 0 failed; 14517 filtered out`
- PASS `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-memory-store-default-1230-clippy -p asupersync --lib -- -D warnings`
