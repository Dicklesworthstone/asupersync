# Distributed Snapshot Golden Snapshot Provenance

## How Golden Snapshots Are Generated

### Environment Requirements
- **Platform**: Any (snapshot format is platform-independent)
- **Rust Version**: Matches project MSRV (see Cargo.toml)
- **Dependencies**: Uses insta crate for snapshot testing

### Generation Commands
```bash
# Generate all snapshot files
cargo test --test golden_distributed_snapshot

# Review snapshots
cargo insta review

# Accept snapshots if correct
cargo insta accept
```

### Golden Snapshot Format
- **Format**: Debug representation of SnapshotFormatCapture structs
- **Content**: Original snapshots, hex-encoded serialized bytes, deserialization results
- **Binary Format**: Magic "SNAP" + version byte + deterministic little-endian encoding
- **Hash**: FNV-1a content hash for deduplication

### Validation Workflow
1. Run tests to generate/compare snapshots
2. Review snapshot changes via `cargo insta review`
3. Accept correct changes with `cargo insta accept`
4. Commit snapshot files with descriptive commit message

### Regeneration Triggers
- Changes to binary serialization format
- Updates to RegionSnapshot structure
- Changes to magic bytes or version
- Modifications to CRDT merge logic
- Wire protocol compatibility changes

### Last Generated
- **Date**: 2026-04-21
- **Test Suite**: golden_distributed_snapshot.rs
- **Format Version**: 1 (SNAP magic bytes)
- **Scenarios**: empty, simple_open, complex_closing, finalized, draining, all_task_states, maximum_complexity

### Test Scenarios

#### empty_region
- Minimal RegionSnapshot created via ::empty() constructor
- Tests baseline serialization with no tasks, children, or metadata

#### simple_open_region
- Basic open region with single task and child
- Tests typical active region state serialization

#### complex_closing_region
- Closing region with multiple tasks in different states
- Tests complex scenario with cancellation reason and full budget

#### finalized_region
- Closed region with no active tasks or children
- Tests end-of-lifecycle serialization format

#### draining_region
- Draining region with active cancellation
- Tests intermediate shutdown state serialization

#### all_task_states
- Region demonstrating all TaskState enum values
- Tests complete TaskState serialization coverage

#### maximum_complexity
- Maximally complex snapshot with boundary-condition values
- Tests large data sets, maximum values, and string handling

## Binary Format Stability

The distributed snapshot binary format is critical for consensus and replication:

1. **Magic Bytes**: Must remain "SNAP" for format detection
2. **Version Byte**: Must increment on breaking changes to wire format
3. **Field Ordering**: Little-endian encoding order must remain stable
4. **Optional Fields**: Presence flags (0/1) must maintain backward compatibility
5. **String Encoding**: UTF-8 with length prefix must remain consistent

## Usage Guidelines

When modifying snapshot serialization:
1. Run test suite to establish baseline
2. Make implementation changes
3. Re-run tests and review snapshot diffs carefully
4. Accept snapshots only if changes are intentional and protocol-compliant
5. Document breaking changes that affect distributed consensus

This ensures distributed snapshots maintain wire format compatibility across versions.