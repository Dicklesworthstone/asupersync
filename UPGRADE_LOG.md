# Dependency Upgrade Log

## 2026-02-14

**Project:** asupersync
**Language:** Rust
**Manifest:** `Cargo.toml`

### Summary

| Metric | Count |
|--------|-------|
| **Total dependencies updated** | 12 Cargo.toml + 43 Cargo.lock |
| **Skipped** | 2 (bincode, generic-array) |
| **Code migration required** | 3 (nix, criterion, gf256 lints) |
| **Nightly pinned** | `nightly-2026-02-05` (Feb 4 compiler) |

### Nightly Toolchain Pin

**Reason:** `serde_derive` v1.0.228 (latest on crates.io as of Feb 2026) triggers E0282
type inference regressions in `quote_block!` macros with rustc `47611e160` (nightly Feb 12).
No fix available — pinned to `nightly-2026-02-05` (rustc `db3e99bba`, Feb 4) which compiles
cleanly. Remove pin when serde or rustc ships a fix.

**File changed:** `rust-toolchain.toml` → `channel = "nightly-2026-02-05"`

### Cargo.toml Version Bumps

#### webpki-roots: 0.26 → 1.0
- **Breaking:** None (drop-in replacement, license change only)
- **Tests:** ✓ Passed

#### lz4_flex: 0.11 → 0.12
- **Breaking:** None (bugfix only)
- **Tests:** ✓ Passed

#### toml: 0.8 → 1.0
- **Breaking:** API changes for document vs value parsing, `from_slice`/`to_vec` removed
- **Migration:** None needed — our usage is just `toml::from_str()` which is unchanged
- **Tests:** ✓ Passed

#### getrandom: 0.3 → 0.4
- **Breaking:** Function renames (`getrandom` → `fill`, already done in prior upgrade)
- **Migration:** None needed — we already use `getrandom::fill()`
- **Tests:** ✓ Passed

#### criterion: 0.5 → 0.8 (dev-dependency)
- **Breaking:** `criterion::black_box` deprecated → `std::hint::black_box`
- **Migration:** Updated 15 bench files (149 call sites) to use `std::hint::black_box`
- **Tests:** ✓ Passed

#### rcgen: 0.13 → 0.14 (dev-dependency)
- **Breaking:** `signed_by()` takes `&Issuer`, `RemoteKeyPair` → `SigningKey`
- **Migration:** None needed (only used in TLS conformance tests, compiles clean)
- **Tests:** ✓ Passed

#### nix: 0.29 → 0.31
- **Breaking:** `AsRawFd` → `AsFd` for fcntl/read/close; `Errno` moved to `errno` module
- **Migration:** Removed `.as_raw_fd()` from 4 fcntl calls (nix now takes `AsFd` directly);
  converted raw fd in ancillary test to `OwnedFd` for safe read+close
- **Files modified:** `src/net/udp.rs`, `src/net/tcp/listener.rs`, `src/net/tcp/stream.rs`,
  `src/net/unix/stream.rs`
- **Tests:** ✓ Passed

#### rusqlite: 0.33 → 0.38
- **Breaking:** `execute` rejects trailing content; u64 `ToSql`/`FromSql` disabled by default
- **Migration:** None needed — our usage is behind `sqlite` feature flag, compiles clean
- **Tests:** ✓ Passed

#### x509-parser: 0.17 → 0.18
- **Breaking:** Minor API changes
- **Migration:** None needed — compiles clean
- **Tests:** ✓ Passed

#### opentelemetry: 0.28 → 0.31
- **Breaking:** Provider renames, async runtime params removed, Resource builder pattern
- **Migration:** None needed — our usage is behind `metrics` feature flag, compiles clean
- **Tests:** ✓ Passed

#### opentelemetry_sdk: 0.28 → 0.31
- **Breaking:** Same as opentelemetry (tightly coupled)
- **Migration:** None needed — compiles clean
- **Tests:** ✓ Passed

#### polling: 2.8 → 3.11
- **Breaking:** Major I/O safety rework, Event/Events API changes
- **Migration:** None needed — our reactor wraps polling internally, compiles clean
- **Tests:** ✓ Passed

### Cargo.lock Compatible Updates (43 packages)

Auto-updated via `cargo update`: bitflags, cc, clap, clap_builder, clap_lex, deranged,
libc, memchr, proptest, regex, regex-automata, regex-syntax, security-framework,
security-framework-sys, syn, tempfile, time, time-macros, toml_parser, trybuild,
unicode-ident, webpki-roots, zerocopy, zerocopy-derive, zmij, plus new transitive deps
(anyhow, getrandom 0.4, id-arena, leb128fmt, prettyplease, semver, toml_datetime,
unicode-xid, wasip3, wasm-encoder, wasm-metadata, wasmparser, wit-bindgen-*, wit-component,
wit-parser).

### Additional Fixes

#### New clippy lint: `duration_suboptimal_units`
- **Issue:** 75 warnings across test code for patterns like `Duration::from_millis(1000)`
- **Fix:** Added `duration_suboptimal_units = "allow"` to `[lints.clippy]` in Cargo.toml
- **Rationale:** Many of these patterns are intentionally explicit about units for clarity

#### New clippy lints: `cast_ptr_alignment`, `ptr_as_ptr`
- **Issue:** 16 warnings in gf256.rs SIMD intrinsics (AVX2 unaligned load casts)
- **Fix:** Added allows to gf256.rs `#![cfg_attr(feature = "simd-intrinsics", ...)]`
- **Rationale:** Casts are correct — `_mm256_loadu_si256` handles unaligned loads

#### `map_unwrap_or` in linalg.rs
- **Fix:** Changed `.map(f).unwrap_or(default)` → `.map_or(default, f)`

### Skipped

#### bincode: 1.3.3 → 2.0.1/3.0.0
- **Reason:** 3.0.0 is a tombstone that fails to compile; 2.0.1 is a major API rewrite
  requiring >10 file refactor. Kept at 1.3.3 per prior decision.

#### generic-array: 0.14.7 → 0.14.9
- **Reason:** Transitive dependency, cannot directly control version.

---

## 2026-02-03 (in progress)

**Project:** asupersync  
**Language:** Rust  
**Manifest:** `Cargo.toml`

### Summary

| Metric | Count |
|--------|-------|
| **Total dependencies** | 48 |
| **Updated** | 3 |
| **Skipped** | 4 |
| **Failed (rolled back)** | 0 |
| **Requires attention** | 1 |

### Successfully Updated

#### base64: 0.22 → 0.22.1

**Changelog:** https://docs.rs/crate/base64/latest

**Breaking changes:** None (patch update)

**Tests:** Failed due to pre-existing compile errors in `src/lab/replay.rs`
```
error[E0308]: arguments to this function are incorrect
   --> src/lab/replay.rs:263:19
    |
263 |         let div = find_divergence(&a, &b);
    |                   ^^^^^^^^^^^^^^^ --  -- expected `&TraceBufferHandle`, found `&TraceBuffer`
```

#### bytes: 1.7 → 1.11

**Changelog:** https://docs.rs/crate/bytes/latest/source/CHANGELOG.md citeturn0search0

**Breaking changes:** None (minor update; MSRV bump to 1.57 noted in 1.11.0) citeturn0search0

**Tests:** Failed due to pre-existing compile errors in `src/trace/mod.rs` / `src/trace/certificate.rs`
```
error[E0252]: the name `VerificationResult` is defined multiple times
  --> src/trace/mod.rs:77:26
```

#### getrandom: 0.2 → 0.3

**Changelog / docs:** https://docs.rs/getrandom/latest/getrandom/ citeturn8open0

**Breaking changes:** Updated API usage to `getrandom::fill` (docs show `fill` as the primary API in 0.3). citeturn8open0

**Migration applied:**
```diff
- getrandom::getrandom(&mut key)
+ getrandom::fill(&mut key)
```

**Files modified:** 3
- `src/net/websocket/frame.rs`
- `src/net/websocket/handshake.rs`
- `src/util/entropy.rs`

**Tests:** Failed due to pre-existing compile errors in `src/trace/certificate.rs`
```
error[E0599]: no variant or associated item named `ObligationAcquire` found for enum `trace::event::TraceEventKind`
```

### Skipped

#### clap: 4.5.56 → 4.5.56

**Reason:** Already on the latest 4.x release (Cargo.toml allows ^4.5; Cargo.lock shows 4.5.56). citeturn2open0

#### criterion: 0.5.1 → 0.5.1

**Reason:** Already on the latest 0.5.x release (Cargo.toml allows ^0.5; Cargo.lock shows 0.5.1). citeturn4open0

#### crossbeam-queue: 0.3.12 → 0.3.12

**Reason:** Already on the latest 0.3.x release (Cargo.toml allows ^0.3; Cargo.lock shows 0.3.12). citeturn6open0

#### futures-lite: 2.6.1 → 2.6.1

**Reason:** Already on the latest 2.x release (Cargo.toml allows ^2.6; Cargo.lock shows 2.6.1). citeturn7open0

### Requires Attention

#### bincode: 1.3.3 → 2.0.1 (latest usable) / 3.0.0 (tombstone)

**Breaking changes (2.0 migration):**
- `Options` trait replaced by mandatory `Configuration` struct; calls must use `config::legacy()` or `config::standard()` and updated encode/decode APIs. citeturn0search2
- Several config methods renamed or removed (e.g., `with_varint_encoding` → `with_variable_int_encoding`, `with_native_endian` removed). citeturn0search2

**Maintenance status:**
- RustSec notes bincode is unmaintained and considers 1.3.3 “complete.” citeturn0search1
- A 3.0.0 release exists on crates.io but is a tombstone that intentionally fails to compile (docs.rs build failure). citeturn0search8

**Impact:** Migrating to 2.0.1 is a major API change and likely >10 file refactor. Needs explicit user approval before proceeding.

### Notes
- Proceeding with upgrades despite existing build failures (per user instruction).
- Per-dependency tests will be run and logged; failures attributed to pre-existing errors when applicable.

---

**Date:** 2026-01-18 (updated)
**Project:** asupersync
**Language:** Rust

## Summary

- **Updated:** 11
- **Skipped:** 0
- **Failed:** 0
- **Needs attention:** 1 (bincode - unmaintained, kept at 1.3.3)

## Updates

### thiserror: 1.0 → 2.0
- **Breaking changes:**
  - Reserved identifiers like `type` must use `r#type` syntax in format strings
  - Trait bounds no longer inferred on fields shadowed by explicit named arguments
  - Direct dependency now required 