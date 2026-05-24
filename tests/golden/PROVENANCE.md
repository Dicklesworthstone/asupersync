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

## New Golden Artifacts (br-golden-6/7/8)

### br-golden-6: Observability Metrics JSON Serialization
- **File**: `hot_path/observability_metrics_json.golden`
- **Generator**: `src/golden_artifacts_tests.rs::golden_observability_metrics_json`
- **Purpose**: Deterministic JSON serialization for observability metrics structures
- **Stability**: Deterministic (scrubbed timestamps, fixed metric values)
- **Update trigger**: Metrics serialization format changes, MetricsCollector API changes
- **Command**: `UPDATE_GOLDENS=1 cargo test golden_observability_metrics_json`

### br-golden-7: Trace Event Canonical Bytes
- **File**: `hot_path/trace_event_canonical_bytes.golden`
- **Generator**: `src/golden_artifacts_tests.rs::golden_trace_event_canonical_bytes`
- **Purpose**: Canonical byte representation for trace events in deterministic format
- **Stability**: Deterministic (fixed trace IDs, event sequences, hex encoding)
- **Update trigger**: TraceEvent binary serialization changes, canonical format changes
- **Command**: `UPDATE_GOLDENS=1 cargo test golden_trace_event_canonical_bytes`

### br-golden-8: Evidence Chain Merkle Proof
- **File**: `hot_path/evidence_chain_merkle_proof.golden`
- **Generator**: `src/golden_artifacts_tests.rs::golden_evidence_chain_merkle_proof`
- **Purpose**: Merkle tree proof generation for evidence chains (forensic validation)
- **Stability**: Deterministic (fixed evidence entries, SHA256 algorithm)
- **Update trigger**: Evidence chain format changes, Merkle proof algorithm changes
- **Command**: `UPDATE_GOLDENS=1 cargo test golden_evidence_chain_merkle_proof`

These new golden tests ensure byte-for-byte regression detection for critical state snapshot artifacts that must maintain deterministic output for compliance and debugging purposes.

### br-golden-9: RaptorQ Decoder Trace
- **File**: `hot_path/raptorq_decoder_trace.golden`
- **Generator**: `src/golden_artifacts_tests.rs::golden_raptorq_decoder_trace`
- **Purpose**: Deterministic RaptorQ decoder progress trace with systematic/repair symbol processing
- **Stability**: Deterministic (fixed K/N parameters, gaussian elimination steps, back substitution)
- **Update trigger**: RaptorQ decoder algorithm changes, trace format changes
- **Command**: `UPDATE_GOLDENS=1 cargo test golden_raptorq_decoder_trace`

### br-golden-10: Supervision Restart Log Canonical Form
- **File**: `hot_path/supervision_restart_log.golden`
- **Generator**: `src/golden_artifacts_tests.rs::golden_supervision_restart_log`
- **Purpose**: Canonical supervision tree restart log format for debugging cascade failures
- **Stability**: Deterministic (fixed restart events, canonical tree ordering, scrubbed timestamps)
- **Update trigger**: Supervision restart format changes, tree analysis algorithm changes
- **Command**: `UPDATE_GOLDENS=1 cargo test golden_supervision_restart_log`

### br-golden-11: CLI Doctor Diagnostic Report Serialization
- **File**: `hot_path/cli_doctor_diagnostic_report.golden`
- **Generator**: `src/golden_artifacts_tests.rs::golden_cli_doctor_diagnostic_report`
- **Purpose**: Deterministic CLI doctor diagnostic report format for system health analysis
- **Stability**: Deterministic (fixed subsystem status, scrubbed dynamic values, canonical ordering)
- **Update trigger**: CLI doctor report format changes, diagnostic category changes
- **Command**: `UPDATE_GOLDENS=1 cargo test golden_cli_doctor_diagnostic_report`

These additional golden tests extend regression coverage to RaptorQ decoding traces, supervision restart cascades, and CLI diagnostic outputs - all critical for debugging deterministic behavior in production incidents.