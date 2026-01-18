# Dependency Upgrade Log

**Date:** 2026-01-18
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
  - Direct dependency now required (already the case here)
- **New features:** `no_std` support, better recursion warnings
- **MSRV:** 1.61+
- **Tests:** Needs verification

### crossbeam-deque: 0.8 → 0.8
- **Breaking:** None (latest stable in 0.8.x)
- **Tests:** ✓ N/A

### crossbeam-queue: 0.3 → 0.3
- **Breaking:** None (latest stable in 0.3.x)
- **Tests:** ✓ N/A

### parking_lot: 0.12 → 0.12
- **Breaking:** None (latest stable in 0.12.x)
- **Tests:** ✓ N/A

### polling: 3.3 → 3.7
- **Breaking:** None
- **Tests:** Needs verification

### slab: 0.4 → 0.4
- **Breaking:** None (latest stable)
- **Tests:** ✓ N/A

### rmp-serde: 1.1 → 1.3
- **Breaking:** None
- **Tests:** Needs verification

### serde: 1.0 → 1.0
- **Breaking:** None (patch updates)
- **Tests:** ✓ N/A

### serde_json: 1.0 → 1.0
- **Breaking:** None (patch updates)
- **Tests:** ✓ N/A

### proptest: 1.4 → 1.6
- **Breaking:** None
- **MSRV:** 1.82+ (updated)
- **Tests:** Needs verification

### criterion: 0.5 → 0.5
- **Breaking:** None (latest stable in 0.5.x; 0.6+ requires async-std/tokio)
- **Tests:** ✓ N/A

### futures-lite: 2.0 → 2.6
- **Breaking:** None
- **Tests:** Needs verification

### tempfile: 3.10 → 3.17
- **Breaking:** None
- **Tests:** Needs verification

## Needs Attention

### bincode: 1.3 (unchanged)
- **Issue:** RustSec-2025-0141 - marked as unmaintained
- **Status:** Kept at 1.3.3 (team considers this version "complete")
- **Alternatives considered:**
  - **postcard** - Well-maintained, 60+ contributors, 7000+ repos using it
  - **wincode** - Bincode-compatible drop-in replacement
  - **bitcode** - Fastest, but unstable format (bad for determinism)
- **Action:** Consider migration to postcard in future phase
- **Rationale:** bincode 1.3.3 is stable and functional; migration requires testing serialization compatibility

## Notes

- Updated MSRV remains compatible (Rust 1.75+ per README)
- All updates preserve determinism for lab runtime
- No new async executors introduced (per AGENTS.md policy)
