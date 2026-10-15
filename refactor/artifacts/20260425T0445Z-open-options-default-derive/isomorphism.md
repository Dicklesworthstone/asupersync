## Change: derive `OpenOptions` default

### Equivalence Contract
- Inputs covered: `OpenOptions::new()`, `OpenOptions::default()`, builder callsites in `src/fs`.
- Ordering preserved: yes; construction has no iteration or ordering effects.
- Tie-breaking: N/A.
- Error semantics: unchanged; only zero-value construction changed from explicit fields to derived field defaults.
- Laziness: N/A.
- Short-circuit eval: N/A.
- Floating-point: N/A.
- RNG / hash order: N/A.
- Observable side-effects: unchanged; construction has no logging, I/O, metrics, or tracing.
- Type narrowing: N/A.
- Rerender behavior: N/A.

### Proof
- `bool` fields default to `false`.
- Unix-only `Option<u32>` and `Option<i32>` fields default to `None`.
- `OpenOptions::new()` still returns `Self::default()`, so public constructor semantics remain the same.
- Existing inline tests already assert `OpenOptions::default()` has every flag disabled and equals `OpenOptions::new()` by field comparison.

### Candidate Score
- LOC_saved: 1
- Confidence: 5
- Risk: 1
- Score: 5.0

### Verification
- [x] `rustfmt --edition 2024 --check src/fs/open_options.rs`
- [x] `rch exec -- cargo test -p asupersync --lib fs::open_options --no-fail-fast`
- [x] `rch exec -- cargo check -p asupersync --all-targets`
- [x] `rch exec -- cargo clippy -p asupersync --all-targets -- -D warnings`
- [x] LOC delta recorded in `ledger.md`
