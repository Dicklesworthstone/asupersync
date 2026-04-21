# Diagnostic Forensic Dump Golden Snapshot Provenance

## How Golden Snapshots Are Generated

### Environment Requirements
- **Platform**: Any (diagnostics are platform-independent)
- **Rust Version**: Matches project MSRV (see Cargo.toml)
- **Dependencies**: Uses insta crate for snapshot testing

### Generation Commands
```bash
# Generate all snapshot files
cargo test --test golden_diagnostics_forensic_dump

# Review snapshots
cargo insta review

# Accept snapshots if correct
cargo insta accept
```

### Golden Snapshot Format
- **Format**: Debug representation of ForensicDump structs
- **Content**: Diagnostic explanations, leak reports, deadlock analysis
- **Normalization**: Timestamps normalized, IDs deterministic
- **Metadata**: Test scenario, counts, descriptions

### Validation Workflow
1. Run tests to generate/compare snapshots
2. Review snapshot changes via `cargo insta review`
3. Accept correct changes with `cargo insta accept`
4. Commit snapshot files with descriptive commit message

### Regeneration Triggers
- Changes to diagnostic output format
- Updates to Diagnostics implementation
- Changes to test scenarios
- Structural changes to explanation types

### Last Generated
- **Date**: 2026-04-19
- **Test Suite**: golden_diagnostics_forensic_dump.rs
- **Rust Version**: 1.97.0-nightly (e8e4541ff 2026-04-15)
- **Scenarios**: empty_runtime, minimal_runtime, complex_hierarchy, leaked_obligations, deadlock_scenario

### Test Scenarios

#### empty_runtime
- Empty RuntimeState with no regions, tasks, or obligations
- Tests diagnostic behavior with minimal state

#### minimal_runtime
- Single root region with no tasks
- Tests basic region analysis

#### complex_hierarchy
- Nested region hierarchy with various task states
- Tests complex scenario diagnostics

#### leaked_obligations
- Runtime with virtual time and aged obligations
- Tests obligation leak detection

#### deadlock_scenario
- Multiple blocked tasks across regions
- Tests deadlock detection algorithms

## File Structure

```
tests/snapshots/diagnostics/
├── PROVENANCE.md                    # This file
├── empty_runtime.snap               # Empty runtime scenario snapshot
├── minimal_runtime.snap             # Minimal runtime scenario snapshot
├── complex_hierarchy.snap           # Complex hierarchy scenario snapshot
├── leaked_obligations.snap          # Leaked obligations scenario snapshot
└── deadlock_scenario.snap          # Deadlock scenario snapshot
```

## Stability Considerations

The forensic dump format is designed for production debugging and must maintain stability:

1. **Field Order**: Diagnostics structs use deterministic field ordering
2. **ID Generation**: Test scenarios use deterministic IDs (starting from 1000)
3. **Timestamps**: Normalized to avoid flaky tests
4. **Sorting**: All collections sorted by ID for consistent output
5. **Classification**: Extract stable enum variants from complex reports

## Usage Guidelines

When modifying diagnostic output:
1. Run the test suite first to establish baseline
2. Make implementation changes
3. Re-run tests and review snapshot diffs
4. Accept snapshots only if changes are intentional and correct
5. Document breaking changes in commit message

This ensures the forensic dump format remains a reliable debugging tool across releases.