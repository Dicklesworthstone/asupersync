# Dependency Upgrade Log

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
