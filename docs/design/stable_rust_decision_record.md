# Stable Rust Decision Record

Date: 2026-06-10
Owner: DarkStream
Bead: `asupersync-stable-rust-track-tq3ajf.1`

## Decision

Asupersync can have a stable Rust build path for the main runtime crate, but not
by preserving `?` on `Outcome` as the default API. The stable path should make a
single explicit propagation helper the normal spelling, with the nightly
`Try` implementation retained only as opt-in sugar.

The chosen stable pattern is a crate macro named `outcome_try!`:

```rust
let value = outcome_try!(operation(cx).await);
```

The macro should preserve all `Outcome` variants exactly:

- `Outcome::Ok(value)` returns `value`.
- `Outcome::Err(error)` returns `Outcome::Err(error)`.
- `Outcome::Cancelled(reason)` returns `Outcome::Cancelled(reason)`.
- `Outcome::Panicked(payload)` returns `Outcome::Panicked(payload)`.

This keeps cancellation and panic propagation in the `Outcome` domain. It avoids
converting cancellation and panic into ordinary `Result` errors, and it avoids a
per-callsite stable API split. Nightly users may enable `nightly-outcome-try` to
use `?` on `Outcome`, but that is sugar on top of the same semantic primitive.

`simd-intrinsics` remains an opt-in nightly/performance lane unless K2 splits
the current portable-SIMD dependency from the architecture intrinsics. Stable
production lanes must exclude `simd-intrinsics` until that split exists.

No README claim changed in this K1 audit, so no provider audit log update is
required. This repository does not currently contain `provider_audit_log.md`.

## Evidence

Commands run during this audit:

```bash
rg -n '^#!\[feature\(|portable_simd|try_trait_v2|rust-toolchain|nightly|rust-version' --glob '*.rs' --glob '*.toml' --glob '*.md'
rg -n '^#!\[feature\(|cfg_attr\([^\n]*feature\([^\n]*\)' --glob '*.rs' src asupersync-macros asupersync-browser-core asupersync-tokio-compat conformance franken_kernel franken_evidence franken_decision frankenlab drop_unwrap_finder
rg -n '\[features\]|^default =|simd-intrinsics|ci-cross-platform|benchmark-adapters|tokio|rust-version|cargo-features' --glob 'Cargo.toml'
rg -n 'Try for Outcome|FromResidual|Residual<|core::ops::\{ControlFlow|\bTry\b|\bResidual\b|FromResidual' src/types/outcome.rs
rg -n 'std::simd|simd-intrinsics|target_feature|is_x86_feature_detected|is_aarch64_feature_detected|NibbleTables' src/raptorq/gf256.rs
```

The workspace source-level language-feature scan found only these crate-root
language gates:

- `src/lib.rs`: `#![feature(try_trait_v2)]`
- `src/lib.rs`: `#![feature(try_trait_v2_residual)]`
- `src/lib.rs`: `#![cfg_attr(feature = "simd-intrinsics", feature(portable_simd))]`

Auxiliary fuzz documentation, fuzz targets, and the Kafka provisioning script
use `cargo +nightly` or `cargo +nightly -Zscript`, but those are operator or
fuzz lanes, not default runtime crate language requirements.

## Inventory

| Nightly feature or behavior | Crates / files | Activating cargo features | Classification | Decision |
| --- | --- | --- | --- | --- |
| `try_trait_v2` | `asupersync`, `src/lib.rs`, `src/types/outcome.rs` | All root builds today because the crate attribute is unconditional. Default feature set is `proc-macros`, but this gate is independent of default features. | Replaceable for stable builds. Hard only if `?` on `Outcome` must remain default syntax. | Add `nightly-outcome-try = []`; gate the crate attribute and `Try` impls behind it. Introduce `outcome_try!` as the stable-first propagation spelling and migrate stable-relevant callsites to it. |
| `try_trait_v2_residual` | `asupersync`, `src/lib.rs`, `src/types/outcome.rs` | Same as `try_trait_v2`. Required by the current `Residual` and `FromResidual` implementation for `Outcome<Infallible, E>`. | Replaceable for stable builds. | Same as above. The stable helper should not depend on `Residual`; it should match `Outcome` directly. |
| `portable_simd` | `asupersync`, `src/lib.rs`, `src/raptorq/gf256.rs` | `simd-intrinsics`; also pulled by `ci-cross-platform`; included by `--all-features`; fuzz manifests also opt into it. | Gateable. Stable default can use scalar/table fallback. Current comments overstate a safe portable-SIMD fallback when disabled; disabled code uses the scalar `NibbleTables` path. | Keep stable production lanes off `simd-intrinsics`. K2 should either split a future `nightly-portable-simd` feature from architecture intrinsics or keep the whole SIMD feature as nightly-only. Update the feature comment while doing the split. |
| Repo-wide nightly toolchain pin | `rust-toolchain.toml` | Whole repo command default, not a cargo feature. | Gateable policy choice after code gates exist. | Do not flip the repo default in K1. K2 adds explicit `cargo +stable` proof lanes first. The repo may stay nightly-default during migration while the stable lane becomes a checked artifact. |
| Tokio-backed compatibility and benchmark dependencies | `asupersync-tokio-compat`, `conformance`, root `benchmark-adapters`, fuzz fixtures | Satellite crates, conformance crate, optional benchmark/fuzz features. | Not a stable-language blocker. It remains a production graph and no-Tokio governance concern, covered by existing proof lanes. | Do not couple this track to Tokio cleanup. Stable Rust K2 should avoid optional benchmark/fuzz feature sets until the language gates are separated. |
| Fuzz and `-Zscript` operator tooling | `fuzz/**`, `scripts/provision_kafka_test_env.rs`, related docs | Operator-invoked `cargo +nightly` commands, not root workspace production features. | Out of scope for stable runtime crate build. | Keep fuzz/operator docs honest. They can remain nightly-only even after the runtime crate gains a stable profile. |

No additional `#![feature(...)]` sites were found in workspace Rust sources
under `src`, `asupersync-macros`, `asupersync-browser-core`,
`asupersync-tokio-compat`, `conformance`, `franken_kernel`,
`franken_evidence`, `franken_decision`, `frankenlab`, or
`drop_unwrap_finder`.

## Outcome Propagation Study

The current nightly implementation is in `src/types/outcome.rs`:

- `Outcome<T, E>: Try<Output = T, Residual = Outcome<Infallible, E>>`
- `Outcome<Infallible, E>: Residual<T>`
- `Outcome<T, E>: FromResidual<Outcome<Infallible, E>>`
- `Outcome<T, E>: FromResidual<Result<Infallible, E>>`

That is semantically right, but it cannot compile on stable. `Outcome::into_result`
exists, but using it as the stable default would turn cancellation and panic into
`OutcomeError`, then require a second conversion back to `Outcome`. That is too
easy to misuse and makes cancel-correctness look like ordinary error handling.

Candidate comparison:

| Candidate | Representative spelling | Approx. tokens per propagation | Semantic risk | Decision |
| --- | --- | ---: | --- | --- |
| Nightly `?` | `let conn = open(cx).await?;` | 7 | Correct today, unstable language feature. | Keep only behind `nightly-outcome-try`. |
| `outcome_try!` macro | `let conn = outcome_try!(open(cx).await);` | 9 | Correct if macro matches all variants and returns the enclosing `Outcome`. | Chosen stable pattern. |
| `into_result()?` | `let conn = open(cx).await.into_result()?;` | 11 plus conversion boilerplate | Collapses cancellation and panic into a `Result` error unless every boundary maps back carefully. | Reject as default. Use only at external `Result` boundaries. |
| Explicit `match` | `let conn = match open(cx).await { ... };` | 30 to 45 | Correct but noisy; high duplication risk. | Use inside the macro and for unusual boundaries only. |

### Module Port Shape 1: SQLite

Representative source area: `src/database/sqlite.rs`.

Current style:

```rust
let conn = SqliteConnection::open_in_memory(cx).await?;
let rows = conn.query(cx, "SELECT * FROM users", &[]).await?;
```

Stable macro style:

```rust
let conn = outcome_try!(SqliteConnection::open_in_memory(cx).await);
let rows = outcome_try!(conn.query(cx, "SELECT * FROM users", &[]).await);
```

Subjective result: acceptable. This module has many async `Outcome` boundaries
where preserving cancellation matters. The macro is slightly longer than `?`,
but it keeps the control-flow signal visible and does not force `SqliteError` to
learn about cancellation or panic payloads.

Approximate propagation-token cost: 7 tokens for `?`, 10 to 13 tokens for the
macro depending on receiver length, 35 or more for explicit `match`.

### Module Port Shape 2: HTTP/1 Client

Representative source area: `src/http/h1/http_client.rs`.

Current style mixes `Result` APIs and `Outcome`-returning async I/O:

```rust
check_cx(cx)?;
let io = self.connect_io(cx, &proxy).await?;
let resp = self.execute_single(cx, &method, &parsed, &extra_headers, &body).await?;
```

Stable macro style only applies to `Outcome`-returning expressions:

```rust
check_cx(cx)?;
let io = outcome_try!(self.connect_io(cx, &proxy).await);
let resp = outcome_try!(
    self.execute_single(cx, &method, &parsed, &extra_headers, &body).await
);
```

Subjective result: workable, but this module shows why the chosen stable pattern
must be the only stable `Outcome` propagation spelling. `Result` `?` should
remain unchanged. `Outcome` propagation should become visually explicit. Mixing
`.into_result()?`, explicit `match`, and helper methods would be worse than a
small macro tax.

Approximate propagation-token cost: `Result` sites stay unchanged. `Outcome`
sites grow from 8 to 11 tokens for short calls, or wrap across lines for long
calls.

### Module Port Shape 3: H3 Body Streaming E2E

Representative source area:
`src/real_http_h3_server_h3_body_streaming_integration_e2e_tests.rs`.

Current style:

```rust
let response = framework
    .serve_large_body_with_qpack(&region_cx, headers, LARGE_BODY_SIZE)
    .await?;
let result = task.await?;
```

Stable macro style:

```rust
let response = outcome_try!(
    framework
        .serve_large_body_with_qpack(&region_cx, headers, LARGE_BODY_SIZE)
        .await
);
let result = outcome_try!(task.await);
```

Subjective result: acceptable in tests and E2E harnesses. The macro makes
structured-concurrency failure paths visible at task joins and region boundaries.
The cost is one extra wrapper around each propagation point, not a semantic
rewrite.

Approximate propagation-token cost: 8 tokens for `?`, 11 to 14 tokens for the
macro, 35 or more for explicit `match`.

## No-Tech-Debt Review

The stable implementation must not create parallel stable and nightly APIs with
different semantics. The stable helper is the semantic primitive. The nightly
`Try` impl may delegate to the same behavior, but docs, examples, and stable
feature-set code should use `outcome_try!` so stable users do not see a second
class API.

Rejected patterns:

- `Outcome::ok_or_propagate()`: unclear name and still needs `?` over `Result`.
- `Outcome::into_result()?` as normal style: conflates cancellation with
  ordinary error flow at every callsite.
- Permanent explicit `match` migration: correct but verbose enough to invite
  inconsistent shortcuts.
- Keeping nightly as the only normal path: preserves the adoption wall.

## K2 Implementation Plan

1. Add cargo feature `nightly-outcome-try = []`.
2. Change `src/lib.rs` to:

   ```rust
   #![cfg_attr(feature = "nightly-outcome-try", feature(try_trait_v2))]
   #![cfg_attr(feature = "nightly-outcome-try", feature(try_trait_v2_residual))]
   ```

3. In `src/types/outcome.rs`, gate imports and impls for `Try`, `Residual`, and
   `FromResidual` behind `#[cfg(feature = "nightly-outcome-try")]`.
4. Add `outcome_try!` near `Outcome` or crate exports. Its tests must assert
   exact propagation of `Err`, `Cancelled`, and `Panicked`.
5. Port stable-relevant `Outcome` callsites manually in batches. Start with
   database, HTTP client, channel/stream, and real-service E2E harness surfaces.
   Do not rewrite `Result` `?` sites.
6. Split or quarantine SIMD:
   - Stable lanes exclude `simd-intrinsics`.
   - If K2 wants stable arch intrinsics, add a separate feature name and keep
     `portable_simd` under a clearly nightly feature.
   - Fix the `simd-intrinsics` comment so it no longer claims a disabled
     `std::simd` fallback.
7. Add proof-lane manifest entries for stable Rust:

   ```bash
   RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_stable_check_default" cargo +stable check -p asupersync --lib
   RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_stable_check_no_default" cargo +stable check -p asupersync --lib --no-default-features
   RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_stable_test_outcome" cargo +stable test -p asupersync types::outcome --lib
   RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_nightly_outcome_try" cargo check -p asupersync --lib --features nightly-outcome-try
   ```

8. Add proof-status snapshot rows mapping the stable claim to those manifest
   lanes. Until the first stable lane is green, docs must say "stable track in
   progress", not "works on stable".
9. After stable lanes are green, update README/AGENTS/toolchain docs and add the
   provider audit log row if the provider log exists or is introduced by that
   docs change.

## Exit Criteria For K2

- `cargo +stable check -p asupersync --lib` is green under RCH with remote
  required and no local fallback.
- `cargo +stable check -p asupersync --lib --no-default-features` is green under
  RCH with remote required and no local fallback.
- Outcome propagation tests pass on both stable and nightly.
- Existing nightly default proof lanes still pass.
- `--all-features` remains explicitly nightly if it includes
  `simd-intrinsics`, fuzz, benchmark, or other operator-only lanes.
