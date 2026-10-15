## Change: derive `PoolStatCounters` default

### Equivalence Contract
- Inputs covered: `PoolStatCounters::default()` through `DbPool` construction and statistics reads.
- Ordering preserved: yes; construction has no iteration or ordering effects.
- Tie-breaking: N/A.
- Error semantics: unchanged; construction is infallible before and after.
- Laziness: N/A.
- Short-circuit eval: N/A.
- Floating-point: N/A.
- RNG / hash order: N/A.
- Observable side-effects: unchanged; counter construction has no logging, I/O, metrics, tracing, or atomic operations beyond initialization.
- Type narrowing: N/A.
- Rerender behavior: N/A.

### Proof
- Every field is `AtomicU64`.
- `AtomicU64::default()` initializes the atomic value to `0`.
- The removed manual implementation initialized every field with `AtomicU64::new(0)`.
- The struct is private, so deriving cannot change public trait bounds or public API.

### Candidate Score
- LOC_saved: 1
- Confidence: 5
- Risk: 1
- Score: 5.0

### Verification
- [x] `rustfmt --edition 2024 --check src/database/pool.rs`
- [x] `rch exec -- cargo check -p asupersync --lib`
- [x] `rch exec -- cargo clippy -p asupersync --lib -- -D warnings`
- [x] LOC delta recorded in `ledger.md`

### Blocked Broader Gates
- `rch exec -- cargo test -p asupersync --lib database::pool --no-fail-fast` compiled but matched 0 tests, so it was not counted as behavioral proof.
- `rch exec -- cargo test -p asupersync --lib pool_new --no-fail-fast` was cancelled after a stale worker artifact-lock wait.
- `cargo check -p asupersync --all-targets` is currently blocked by unrelated dirty changes in `src/cancel/protocol_validator_test_suite.rs` with `new_for_test` `u64` vs `u32` type errors.
