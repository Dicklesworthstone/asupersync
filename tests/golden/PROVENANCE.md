# Golden Artifact Provenance

This document describes how the golden artifacts in this directory were generated
and how to reproduce them when they become stale.

## Generation Date

Generated: 2026-05-23

## Toolchain

- Rust: 2024 nightly (see rust-toolchain.toml)
- Asupersync version: 0.1.0 (commit: 4a8c955d1)
- Platform: linux x86_64
- Dependencies: see Cargo.lock

## Artifacts

### Hot Path Modules (`hot_path/`)

#### RaptorQ Encoder Symbols
- **Files**: `raptorq_*.golden`
- **Generator**: `src/golden_artifacts_tests.rs::golden_raptorq_*`
- **Purpose**: Deterministic K/K' tables, systematic indices, repair symbols
- **Stability**: Deterministic (algorithm-derived)
- **Update trigger**: RaptorQ algorithm changes, RFC 6330 parameter adjustments

#### GF256 Multiplication Tables  
- **Files**: `gf256_*.golden`
- **Generator**: `src/golden_artifacts_tests.rs::golden_gf256_*`
- **Purpose**: Galois Field arithmetic lookup tables, primitive polynomials
- **Stability**: Deterministic (mathematical constants)
- **Update trigger**: GF(256) implementation changes, primitive polynomial changes

#### Trace Event Canonical Form
- **Files**: `trace_event_*.golden`
- **Generator**: `src/golden_artifacts_tests.rs::golden_trace_*`
- **Purpose**: Standardized trace log serialization formats
- **Stability**: Deterministic (canonical serialization)
- **Update trigger**: TraceEvent enum changes, serialization format changes

#### HPACK Encode Tables
- **Files**: `hpack_*.golden`  
- **Generator**: `src/golden_artifacts_tests.rs::golden_hpack_*`
- **Purpose**: HTTP/2 header compression lookup tables
- **Stability**: Deterministic (RFC 7541 standard)
- **Update trigger**: HPACK implementation changes, RFC 7541 table updates

## Regeneration Procedure

When golden artifacts become stale (test failures), follow this procedure:

### 1. Verify the Change is Intentional

```bash
# Run the failing tests to see the diff
cargo test golden_artifacts_tests --lib

# Examine specific differences  
diff tests/golden/hot_path/NAME.golden tests/golden/hot_path/NAME.actual
```

### 2. Update Goldens (if change is intentional)

```bash
# Regenerate ALL golden artifacts
UPDATE_GOLDENS=1 cargo test golden_artifacts_tests --lib

# Or regenerate specific artifact
UPDATE_GOLDENS=1 cargo test golden_raptorq_systematic_index_table --lib
```

### 3. Review and Commit

```bash
# Review EVERY change carefully
git diff tests/golden/

# Stage and commit with rationale
git add tests/golden/
git commit -m "Update golden artifacts: [specific reason]

- Affected: [list specific artifacts]  
- Trigger: [what changed to require update]
- Verified: [how you verified correctness]
"
```

## Validation

To verify golden artifacts are current:

```bash
# All golden tests must pass
cargo test golden_artifacts_tests --lib

# Check for stale .actual files (indicates recent failures)
find tests/golden -name "*.actual"
```

## Dependencies

The golden artifacts depend on:

- `src/raptorq/` modules (gf256.rs, rfc6330.rs, systematic.rs)
- `src/trace/` modules (event.rs, canonicalize.rs, compression.rs) 
- `src/http/h2/hpack.rs` module
- `serde_json` for JSON canonicalization
- `hex` crate for binary artifact encoding

## Cross-Platform Considerations

These artifacts use canonicalization to ensure cross-platform stability:

- Line endings normalized to Unix (LF)
- Trailing whitespace stripped
- Numeric outputs use deterministic formatting
- Binary outputs hex-encoded with consistent spacing

## Troubleshooting

**Golden file missing**: Run with `UPDATE_GOLDENS=1` to create, then review and commit.

**Platform-specific differences**: Check canonicalization in `GoldenTester::canonicalize()`.

**Non-deterministic output**: Verify test inputs are deterministic, add scrubbing if needed.

**Large diffs**: Consider if change is intentional or if test needs better isolation.