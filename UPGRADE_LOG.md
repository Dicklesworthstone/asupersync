# Dependency Upgrade Log

## 2026-04-21 Upgrade Pass

**Toolchain:** nightly 1.97.0 (66da6cae1 2026-04-20) — refreshed locally and on ts2 rch worker.

### Semver-compatible refresh (via `cargo update`)

All crates with published minor/patch updates were bumped in `Cargo.lock` via `cargo update`. Key bumps: clap 4.6.0→4.6.1, hyper 1.8.1→1.9.0, io-uring 0.7.11→0.7.12, js-sys 0.3.91→0.3.95, libc 0.2.183→0.2.185, rustls 0.23.37→0.23.38, rustls-webpki 0.103.10→0.103.13, tokio (in tokio-compat shim) 1.50.0→1.52.1, toml 1.1.0→1.1.2, typenum 1.19→1.20, wasm-bindgen 0.2.114→0.2.118, wasm-bindgen-futures 0.4.64→0.4.68, web-sys 0.3.91→0.3.95, webpki-roots 1.0.6→1.0.7, winnow 1.0.0→1.0.2, zerocopy 0.8.47→0.8.48.

### Minor-version bumps (Cargo.toml edits)

Applied as one coordinated batch because the digest-0.11 group (sha1/sha2/hmac) must land together.

| Crate | From | To | Notes |
|-------|------|-----|-------|
| hashbrown | 0.15 | 0.17 | Skipped 0.16. MSRV 1.85. `get_many_mut` deprecated → `get_disjoint_mut`. |
| hmac | 0.12 | 0.13 | **digest-0.11 coordinated bump.** Added `use hmac::KeyInit;` at 3 call sites (`src/cx/macaroon.rs`, `src/security/key.rs`, `src/security/tag.rs`) because `Mac::new_from_slice` moved to the `KeyInit` trait. |
| lz4_flex | 0.12 | 0.13 | No API changes. Drop-in. Applied in both normal-deps and dev-deps. |
| rayon | 1.11 | 1.12 | Dev-dep. No API changes. |
| rusqlite | 0.38 | 0.39 | No breaking changes. Bundled SQLite now 3.51.3. |
| sha1 | 0.10 | 0.11 | **digest-0.11 coordinated bump.** |
| sha2 | 0.10 | 0.11 | **digest-0.11 coordinated bump.** `finalize()` returns `Array<u8, _>` instead of `GenericArray<u8, _>` — no longer impls `LowerHex`. Fixed three callsites that used `format!("{digest:x}")` (`tests/wasm_supply_chain_controls.rs::sha256_hex`, `tests/replay_e2e_suite.rs::trace_hash_hex`, `tests/conformance/raptorq_differential/src/fixture_loader.rs::calculate_hash`) to hex-encode manually via `write!(&mut out, "{byte:02x}", ...)`. |
| signal-hook | 0.3 | 0.4 | Only used on non-wasm platforms. No direct callsite breakage. |

Also relaxed the explicit `io-uring = "0.7.11"` pin to `"0.7"` so future patch bumps land via `cargo update`.

### Deferred

| Crate | Current | Available | Reason |
|-------|---------|-----------|--------|
| prost | 0.13 | 0.14 | Requires coordinated tonic 0.14 migration (new `tonic-prost` + `tonic-prost-build` crates, `Message` trait signature changes, repeated-box field reshaping). Out of scope for this pass. |
| time | 0.3.46 | 0.3.47 | Blocked by `time = { version = ">=0.3, <0.3.47", ... }` pin in root `Cargo.toml`. The pin is intentional; not reversing without explicit approval. |

### Verification

`cargo check --workspace --all-targets` on ts2 via rch passed green after the KeyInit-import batch and the sha2-hex-encoding batch.

---

**Date:** 2026-02-18
**Project:** asupersync
**Language:** Rust
**Manifest:** Cargo.toml (+ workspace members)

---

## Summary

| Metric | Count |
|--------|-------|
| **Total dependencies reviewed** | 9 |
| **Updated** | 8 |
| **Skipped** | 1 |
| **Failed (rolled back)** | 0 |
| **Requires attention** | 0 |

---

## Successfully Updated

### smallvec: 1.13 -> 1.15
- **Breaking:** None (minor)
- **Notes:** Pulled latest compatible patch in lockfile.

### tempfile: 3.17 -> 3.25
- **Breaking:** None (minor)
- **Notes:** Updated root + workspace dev/test usages.

### rustls-pki-types: 1.12 -> 1.14
- **Breaking:** None (minor)

### proptest: 1.6 -> 1.10
- **Breaking:** None (minor)
- **Notes:** Updated root and Franken crates.

### rayon: 1.10 -> 1.11
- **Breaking:** None (minor)

### toml (franken_decision dev-dep): 0.8 -> 1.0
- **Breaking:** Potential API differences
- **Migration:** No source changes required in current usage.

### bincode: 1.3 -> bincode-next 2.1 (serde mode)
- **Breaking:** Major API change
- **Migration:**
  - `bincode::serialize` -> `bincode::serde::encode_to_vec(..., bincode::config::legacy())`
  - `bincode::deserialize` -> `bincode::serde::decode_from_slice(..., bincode::config::legacy())`
- **Reason:** `bincode` 1.x unmaintained; `bincode` 3.0.0 is intentionally non-functional.

### Lockfile refresh
- Ran `cargo update` and refreshed workspace lockfile to latest compatible Rust nightly versions.

---

## Skipped

### bincode crate 3.0.0
- **Reason:** Upstream `bincode` 3.0.0 crate is intentionally non-functional (`compile_error!`).
- **Action:** Migrated to maintained `bincode-next` instead.

---

## Failed Updates (Rolled Back)

None.

---

## Requires Attention

None.

---

## Post-Upgrade Checklist

- [x] All tests/build checks passing for migration path (`cargo check --all-targets`)
- [x] Clippy strict pass (`cargo clippy --all-targets -- -D warnings`)
- [x] Formatting verified (`cargo fmt --check`)
- [ ] Full workspace test suite (`cargo test`) not run in this pass
- [x] Progress tracking file updated

---

## Commands Used

```bash
cargo update
cargo fmt
cargo fmt --check
rch exec -- cargo check --all-targets --quiet
rch exec -- cargo clippy --all-targets -- -D warnings
```
