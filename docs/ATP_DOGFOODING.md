# ATP Dogfooding Guide (ATP-M2)

This document describes how to use ATP (Asupersync Transfer Protocol) for moving real Asupersync artifacts, implementing the ATP-M2 dogfood requirements.

## Overview

ATP dogfooding replaces traditional file copying with ATP transfers for real Asupersync artifacts including:
- Build artifacts and executables
- Test results and coverage reports  
- Fuzz corpora and test cases
- Proof bundles and audit artifacts
- Release assets and distribution bundles

## Quick Start

### Basic Dogfooding

```bash
# Run all dogfood workflows
scripts/atp_dogfood_coordinator.sh full

# Run specific workflows
scripts/atp_dogfood_coordinator.sh build-artifacts
scripts/atp_dogfood_coordinator.sh test-results
scripts/atp_dogfood_coordinator.sh fuzz-corpora
scripts/atp_dogfood_coordinator.sh proof-bundles

# Check transfer status
scripts/atp_dogfood_coordinator.sh status
```

### CI Integration

```bash
# Enable ATP dogfooding in CI
export ATP_DOGFOOD_ENABLED=true
export ATP_DOGFOOD_CI_MODE=optional

# Run CI workflows with ATP
scripts/ci/atp_dogfood_ci_integration.sh post-build
scripts/ci/atp_dogfood_ci_integration.sh post-test
```

### Dry Run Mode

```bash
# See what would be transferred without executing
scripts/atp_dogfood_coordinator.sh --dry-run build-artifacts
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ATP_DOGFOOD_ENABLED` | `false` | Enable ATP dogfooding |
| `ATP_DOGFOOD_PEER_ID` | `dogfood-$(hostname)` | ATP peer identifier |
| `ATP_DOGFOOD_RELAY` | `127.0.0.1:8080` | ATP relay endpoint |
| `ATP_DOGFOOD_PROOF_LEVEL` | `full` | Proof generation level |
| `ATP_DOGFOOD_CREATE_BEADS` | `true` | Create beads for failures |
| `ATP_DOGFOOD_CI_MODE` | `optional` | CI failure handling mode |

### Proof Levels

- **minimal**: Basic transfer verification
- **standard**: Integrity checks and metadata
- **full**: Complete audit trail with replay artifacts

### CI Modes

- **optional**: Fall back to traditional methods on ATP failure
- **required**: Fail CI if ATP dogfooding fails
- **disabled**: Never use ATP dogfooding

## Workflows

### Build Artifacts

Transfers compiled binaries, libraries, and build metadata:

```bash
scripts/atp_dogfood_coordinator.sh build-artifacts
```

**Artifacts transferred:**
- Release binaries (`target/release/`)
- Static libraries (`.rlib`, `.a` files)
- Build metadata (timings, commit info)

**Generated proofs:**
- Build duration and resource usage
- Compiler version and flags
- Git commit and dirty tree status

### Test Results

Transfers test output, coverage reports, and benchmarks:

```bash
scripts/atp_dogfood_coordinator.sh test-results
```

**Artifacts transferred:**
- JSON test results
- Coverage reports (LCOV, HTML)
- Benchmark data and baselines

**Generated proofs:**
- Test execution times
- Coverage percentages
- Pass/fail statistics

### Fuzz Corpora

Synchronizes fuzzing test cases and minimized inputs:

```bash
scripts/atp_dogfood_coordinator.sh fuzz-corpora
```

**Artifacts transferred:**
- Fuzz target corpora
- Minimized test cases
- Coverage-guided inputs

**Generated proofs:**
- Corpus size and diversity metrics
- Coverage expansion tracking
- Minimization effectiveness

### Proof Bundles

Archives verification artifacts and audit trails:

```bash
scripts/atp_dogfood_coordinator.sh proof-bundles
```

**Artifacts transferred:**
- ATP transfer proofs
- Verification certificates
- Audit and compliance reports

**Generated proofs:**
- Archive integrity verification
- Retention policy compliance
- Access control audit trail

## Proof and Replay Artifacts

Every dogfood transfer generates proof artifacts for audit and debugging:

### Proof Structure

```json
{
  "proof_version": "1.0",
  "session_id": "20260525_143022_hostname_12345",
  "timestamp": "2026-05-25T14:30:22Z",
  "component": "build-artifacts",
  "transfer_manifest": {
    "total_size": 15728640,
    "chunks": 15,
    "compression_ratio": 0.73,
    "deduplication_ratio": 0.12
  },
  "integrity_verification": {
    "hash_algorithm": "blake3",
    "content_hash": "blake3:abc123...",
    "chunk_hashes": ["blake3:def456...", "..."],
    "verification_status": "verified"
  },
  "metadata": {
    "build_duration": 127,
    "git_commit": "df04dc23f",
    "compiler_version": "rustc 1.75.0",
    "target_triple": "x86_64-unknown-linux-gnu"
  },
  "performance_metrics": {
    "transfer_duration_ms": 2340,
    "throughput_mbps": 53.7,
    "cpu_usage_percent": 12.4,
    "memory_usage_mb": 89.1
  }
}
```

### Replay Artifacts

Structured logs enable deterministic replay of transfers:

```jsonl
{"timestamp":"2026-05-25T14:30:22Z","event":"transfer_start","component":"build-artifacts","session_id":"20260525_143022"}
{"timestamp":"2026-05-25T14:30:22Z","event":"chunk_created","chunk_id":"chunk_001","size":1048576,"hash":"blake3:abc123"}
{"timestamp":"2026-05-25T14:30:24Z","event":"transfer_complete","status":"success","duration_ms":2340}
```

## Failure Handling

### Automatic Bead Creation

When transfers fail, dogfooding automatically creates beads with exact failure context:

```markdown
# ATP Dogfood Failure Report

## Failure Summary
- **Component**: build-artifacts
- **Session ID**: 20260525_143022_hostname_12345
- **Timestamp**: 2026-05-25 14:30:22 UTC
- **Details**: Exit code: 1, Duration: 45s, Bundle size: 15728640 bytes

## Proof Context
- **Log file**: artifacts/atp_dogfood_20260525_143022.log
- **Structured log**: artifacts/atp_dogfood_20260525_143022.log.jsonl
- **Session artifacts**: artifacts/*_20260525_143022_hostname_12345.*

## Environment
- **ATP Peer ID**: dogfood-hostname
- **ATP Relay**: 127.0.0.1:8080
- **Proof Level**: full
- **Target Dir**: /tmp/rch_target_atp_dogfood
```

### Manual Investigation

```bash
# Check session logs
grep "20260525_143022_hostname_12345" artifacts/atp_dogfood_20260525_143022.log

# Review structured events
jq '.session_id' artifacts/atp_dogfood_20260525_143022.log.jsonl

# Examine proof artifacts
find artifacts -name "*_20260525_143022_hostname_12345.*" -type f
```

## CI Integration Patterns

### GitHub Actions Example

```yaml
- name: Build with ATP Dogfooding
  env:
    ATP_DOGFOOD_ENABLED: true
    ATP_DOGFOOD_CI_MODE: optional
    CI_RUN_ID: ${{ github.run_id }}
  run: |
    scripts/ci/atp_dogfood_ci_integration.sh post-build
```

### Traditional CI Fallback

```bash
#!/bin/bash
# CI script with ATP dogfooding fallback

if scripts/ci/atp_dogfood_ci_integration.sh check; then
    echo "Using ATP dogfooding for artifacts"
    scripts/ci/atp_dogfood_ci_integration.sh post-build
else
    echo "ATP unavailable, using traditional artifact handling"
    cp -r target/release artifacts/
fi
```

## Performance Monitoring

### Transfer Metrics

Dogfooding collects comprehensive performance metrics:

- **Throughput**: Transfer speed in MB/s
- **Compression ratio**: Storage efficiency 
- **Deduplication ratio**: Cross-transfer chunk reuse
- **Latency**: End-to-end transfer time
- **Resource usage**: CPU, memory, network utilization

### Monitoring Commands

```bash
# Check recent transfer performance
jq '.performance_metrics' artifacts/*_proof_*.json

# Analyze transfer trends
grep "transfer_duration_ms" artifacts/*.log.jsonl | \
  jq -r '[.timestamp, .performance_metrics.transfer_duration_ms] | @csv'

# Review failure rates
grep '"level":"FAILURE"' artifacts/*.log.jsonl | wc -l
```

## Troubleshooting

### Common Issues

#### ATP CLI Not Found

```bash
# Check ATP installation
which atp || echo "ATP CLI not in PATH"

# Install ATP if missing (example)
cargo install --path . --bin atp
```

#### Relay Connection Failed

```bash
# Test relay connectivity
curl -f http://127.0.0.1:8080/health || echo "Relay unreachable"

# Check atpd daemon status
systemctl status atpd
```

#### Insufficient Permissions

```bash
# Check artifact directory permissions
ls -la artifacts/
mkdir -p artifacts && chmod 755 artifacts/
```

#### Disk Space Issues

```bash
# Check available space
df -h artifacts/

# Clean old proof artifacts
find artifacts -name "*_proof_*" -mtime +7 -delete
```

### Debug Modes

#### Verbose Logging

```bash
export ATP_LOG_LEVEL=debug
scripts/atp_dogfood_coordinator.sh build-artifacts
```

#### Structured Event Analysis

```bash
# Extract all events for a session
jq -r 'select(.session_id == "SESSION_ID")' artifacts/*.log.jsonl

# Find error events
jq -r 'select(.level == "FAILURE")' artifacts/*.log.jsonl
```

## Development Guide

### Adding New Artifact Types

1. Extend `atp_dogfood_coordinator.sh` with new dogfood function
2. Add corresponding CI integration in `atp_dogfood_ci_integration.sh`
3. Create integration tests in `tests/atp_dogfood_integration.rs`
4. Update this documentation

### Custom Proof Schemas

Proof artifacts use versioned JSON schemas for compatibility:

```json
{
  "proof_version": "1.0",
  "schema_url": "https://schemas.asupersync.dev/atp/proof/v1.json",
  "custom_fields": {
    "artifact_type": "custom",
    "validation_rules": ["rule1", "rule2"]
  }
}
```

### Testing Integration

```bash
# Run dogfood integration tests
cargo test -p asupersync --test atp_dogfood_integration

# Test specific workflows
cargo test -p asupersync --test atp_dogfood_integration test_dogfood_build_artifacts

# End-to-end workflow test
cargo test -p asupersync --test atp_dogfood_integration test_dogfood_end_to_end_workflow
```

## Security Considerations

### Proof Integrity

- All proofs use cryptographic hashes (Blake3) for integrity
- Transfer manifests prevent tampering
- Replay artifacts enable forensic analysis

### Access Control

- Capability-scoped transfers with explicit permissions
- Session isolation prevents cross-contamination
- Audit trails track all access and modifications

### Privacy

- Build metadata can be redacted via configuration
- Transfer logs exclude sensitive environment variables
- Proof bundles are encrypted for long-term storage

## Compliance

ATP dogfooding supports compliance requirements:

- **SOX**: Audit trails and immutable proof artifacts
- **GDPR**: Data retention policies and deletion capabilities  
- **ISO 27001**: Access control and incident response procedures
- **NIST**: Cryptographic standards and key management

## Related Documentation

- [ATP User Guide](ATP_USER_GUIDE.md) - Basic ATP operations
- [ATP CLI Reference](ATP_CLI_REFERENCE.md) - Command documentation
- [ATP Governance](../artifacts/ATP_GOVERNANCE.md) - Development process
- [Testing Guide](TESTING.md) - Test frameworks and procedures