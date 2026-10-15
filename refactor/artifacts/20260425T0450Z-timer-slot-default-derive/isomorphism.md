## Change: derive `TimerSlot` default

### Equivalence Contract
- Inputs covered: private `TimerSlot::default()` callers and timer wheel slot initialization behavior.
- Ordering preserved: yes; construction has no iteration or side effects.
- Tie-breaking: N/A.
- Error semantics: unchanged; construction is infallible before and after.
- Laziness: N/A.
- Short-circuit eval: N/A.
- Floating-point: N/A.
- RNG / hash order: N/A.
- Observable side-effects: unchanged; `TimerSlot` construction has no logging, I/O, metrics, tracing, or waker effects.
- Type narrowing: N/A.
- Rerender behavior: N/A.

### Proof
- `Cell<Option<NonNull<TimerNode>>>` defaults to `Cell::new(None)`.
- `Cell<usize>` defaults to `Cell::new(0)`.
- Those are exactly the three fields constructed by the removed manual `Default` implementation through `TimerSlot::new()`.
- `TimerSlot::new()` remains a `const fn` and continues to be used for const-compatible array initialization.

### Candidate Score
- LOC_saved: 1
- Confidence: 5
- Risk: 1
- Score: 5.0

### Verification
- [x] `rustfmt --edition 2024 --check src/time/intrusive_wheel.rs`
- [x] `rch exec -- cargo test -p asupersync --lib time::intrusive_wheel --no-fail-fast`
- [x] `rch exec -- cargo check -p asupersync --all-targets`
- [x] `rch exec -- cargo clippy -p asupersync --all-targets -- -D warnings`
- [x] LOC delta recorded in `ledger.md`
