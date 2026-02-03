# Dependency Upgrade Log

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