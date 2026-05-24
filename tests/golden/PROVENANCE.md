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

### br-golden-12: Messaging Primitive Serialization Goldens
- **File**: `hot_path/messaging_primitive_serialization.golden`
- **Generator**: `src/golden_artifacts_tests.rs::golden_messaging_primitive_serialization`
- **Purpose**: Deterministic frame byte serialization for Kafka/NATS/Redis protocols
- **Stability**: Deterministic (fixed frame formats, hex encoding, protocol-specific delimiters)
- **Update trigger**: Messaging protocol frame format changes, serialization changes
- **Command**: `UPDATE_GOLDENS=1 cargo test golden_messaging_primitive_serialization`

### br-golden-13: Distributed Consistent Hash Ring State Goldens
- **File**: `hot_path/distributed_consistent_hash_ring.golden`
- **Generator**: `src/golden_artifacts_tests.rs::golden_distributed_consistent_hash_ring`
- **Purpose**: Deterministic consistent hash ring node distribution and key assignment
- **Stability**: Deterministic (fixed node weights, simple hash function, sorted virtual nodes)
- **Update trigger**: Consistent hashing algorithm changes, virtual node distribution changes
- **Command**: `UPDATE_GOLDENS=1 cargo test golden_distributed_consistent_hash_ring`

### br-golden-14: Runtime Config TOML Canonical Form Goldens
- **File**: `hot_path/runtime_config_toml_canonical.golden`
- **Generator**: `src/golden_artifacts_tests.rs::golden_runtime_config_toml_canonical`
- **Purpose**: Deterministic runtime configuration TOML serialization in canonical form
- **Stability**: Deterministic (sorted keys, canonical TOML format, fixed validation summary)
- **Update trigger**: Runtime config schema changes, TOML serialization format changes
- **Command**: `UPDATE_GOLDENS=1 cargo test golden_runtime_config_toml_canonical`

These final golden tests complete comprehensive coverage of messaging serialization, distributed system state, and configuration management - ensuring deterministic behavior across all major runtime subsystems.

### br-golden-15: TLS Handshake Transcript Bytes
- **File**: `hot_path/tls_handshake_transcript_bytes.golden`
- **Generator**: `src/golden_artifacts_tests.rs::golden_tls_handshake_transcript_bytes`
- **Purpose**: Deterministic TLS acceptor handshake transcript with complete message sequence
- **Stability**: Deterministic (fixed TLS 1.2 messages, hex encoding, deterministic random values)
- **Update trigger**: TLS handshake format changes, protocol version changes, cipher suite changes
- **Command**: `UPDATE_GOLDENS=1 cargo test golden_tls_handshake_transcript_bytes`

### br-golden-16: HTTP/H2 HPACK Encoded Table Bytes
- **File**: `hot_path/h2_hpack_encoded_table_bytes.golden`
- **Generator**: `src/golden_artifacts_tests.rs::golden_h2_hpack_encoded_table_bytes`
- **Purpose**: Deterministic HPACK static table and encoding examples per RFC 7541
- **Stability**: Deterministic (RFC 7541 static table, fixed encoding patterns, compression statistics)
- **Update trigger**: HPACK implementation changes, RFC 7541 table updates, encoding format changes
- **Command**: `UPDATE_GOLDENS=1 cargo test golden_h2_hpack_encoded_table_bytes`

### br-golden-17: Obligation E-Process E-Value Trajectory Bytes
- **File**: `hot_path/obligation_eprocess_trajectory_bytes.golden`
- **Generator**: `src/golden_artifacts_tests.rs::golden_obligation_eprocess_trajectory_bytes`
- **Purpose**: Deterministic e-process e-value trajectory for obligation leak detection
- **Stability**: Deterministic (fixed trajectory points, binary encoding, statistical analysis)
- **Update trigger**: E-process algorithm changes, trajectory format changes, statistical thresholds
- **Command**: `UPDATE_GOLDENS=1 cargo test golden_obligation_eprocess_trajectory_bytes`

These specialized golden tests ensure byte-for-byte regression detection for security-critical TLS handshakes, HTTP/2 compression efficiency, and statistical obligation leak detection - completing coverage of deterministic behavior verification across all network security and reliability subsystems.

### br-golden-18: Web HTTP Request Canonical Bytes + Session Cookie Hash
- **File**: `hot_path/web_http_request_canonical_bytes.golden`
- **Generator**: `src/golden_artifacts_tests.rs::golden_web_http_request_canonical_bytes`
- **Purpose**: Deterministic HTTP request canonical form with session cookie hash computation
- **Stability**: Deterministic (fixed HTTP headers, canonical form serialization, deterministic cookie hash)
- **Update trigger**: Web request format changes, session cookie algorithm changes, HTTP header canonicalization changes
- **Command**: `UPDATE_GOLDENS=1 cargo test golden_web_http_request_canonical_bytes`

### br-golden-19: FS Uring SQE/CQE Sequence Bytes
- **File**: `hot_path/fs_uring_sqe_cqe_sequence_bytes.golden`
- **Generator**: `src/golden_artifacts_tests.rs::golden_fs_uring_sqe_cqe_sequence_bytes`
- **Purpose**: Deterministic io_uring SQE/CQE structure pairs with operation sequence and completion verification
- **Stability**: Deterministic (fixed SQE structures, CQE results, operation ordering, binary encoding)
- **Update trigger**: io_uring structure changes, operation type changes, completion pairing algorithm changes
- **Command**: `UPDATE_GOLDENS=1 cargo test golden_fs_uring_sqe_cqe_sequence_bytes`

### br-golden-20: Codec Length Delimited Frame Bytes
- **File**: `hot_path/codec_length_delimited_frame_bytes.golden`
- **Generator**: `src/golden_artifacts_tests.rs::golden_codec_length_delimited_frame_bytes`
- **Purpose**: Deterministic length-delimited framing protocol with big-endian encoding and payload examples
- **Stability**: Deterministic (fixed frame structures, big-endian length encoding, deterministic payloads)
- **Update trigger**: Length-delimited format changes, encoding algorithm changes, frame boundary detection changes
- **Command**: `UPDATE_GOLDENS=1 cargo test golden_codec_length_delimited_frame_bytes`

These final golden tests complete comprehensive coverage of web request processing, filesystem I/O operations, and codec framing protocols - ensuring deterministic behavior across all major runtime subsystems for regression detection and cross-platform validation.