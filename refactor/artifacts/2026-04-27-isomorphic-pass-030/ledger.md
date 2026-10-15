# Isomorphic Simplification Pass 030

## Candidate

- File: `src/grpc/status.rs`
- Lever: generate the repeated public `Status::*` convenience constructors with a local macro.
- Score: `(LOC_saved 3 * confidence 5) / risk 1 = 15.0`

## Isomorphism Proof

- Inputs covered: all existing `Status::{cancelled,unknown,invalid_argument,deadline_exceeded,not_found,already_exists,permission_denied,resource_exhausted,failed_precondition,aborted,out_of_range,unimplemented,internal,unavailable,data_loss,unauthenticated}` callsites keep the same function names, signatures, and `impl Into<String>` message conversion.
- Ordering preserved: each generated constructor still performs exactly one `Status::new(Code::..., message)` call. `Status::ok()` remains the existing hand-written no-message constructor.
- Tie-breaking: N/A.
- Error semantics: unchanged; status-message UTF-8 truncation and details caps remain centralized in `Status::new` / `Status::with_details`.
- Laziness: unchanged; message conversion still occurs inside the constructor at the same call boundary through `Status::new`.
- Short-circuit eval: N/A.
- Floating-point: N/A.
- RNG / hash order: N/A.
- Observable side effects: none; these constructors only allocate/own the status message exactly as before.
- Type narrowing / public API: unchanged method names, visibility, return type, and doc comments are preserved through macro expansion.

## Metrics

- Source LOC before: 1418
- Source LOC after: 1372
- Source LOC delta: -46
- Source diff numstat: 48 insertions, 94 deletions

## Validation

- `rustfmt --edition 2024 --check src/grpc/status.rs`: pass
- `git diff --check -- src/grpc/status.rs refactor/artifacts/2026-04-27-isomorphic-pass-030/ledger.md`: pass
- `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-pass030-status-test -p asupersync --lib grpc::status`: pass, 40 passed / 0 failed
- `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-pass030-check -p asupersync --lib`: pass
- `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-pass030-clippy-lib -p asupersync --lib -- -D warnings`: pass

## Fresh-Eyes Review

- Re-read the source diff after validation; the macro emits the same public constructor names, signatures, `#[must_use]` attributes, docs, and `Status::new(Code::..., message)` bodies.
- No unrelated dirty files were staged or modified for this pass.
