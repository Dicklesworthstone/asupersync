# BSD Kqueue Golden File Provenance

## How Golden Files Are Generated

### Environment Requirements
- **Platform**: macOS or FreeBSD (native kqueue support required)
- **Rust Version**: Matches project MSRV (see Cargo.toml)
- **System**: Clean system state (no interfering processes)

### Generation Commands
```bash
# Generate all golden files
UPDATE_GOLDENS=1 cargo test --test conformance_kqueue_bsd_events

# Generate specific test golden
UPDATE_GOLDENS=1 cargo test --test conformance_kqueue_bsd_events kqueue_ev_oneshot_fire_and_silence -- --exact

# Review changes after generation
git diff tests/golden/kqueue/
```

### Golden File Format
- **Format**: JSON with pretty-printing
- **Content**: CapturedEvent sequences with metadata
- **Fields**: token, ready_flags, sequence, timestamp_ns
- **Metadata**: Test name, BSD behavior, description, platform, input parameters

### Validation Workflow
1. Generate golden files on reference platform (macOS)
2. Review each golden file manually to verify correctness
3. Run tests without UPDATE_GOLDENS to verify they pass
4. Commit golden files to git with descriptive commit message

### Regeneration Triggers
- Changes to Interest flag mappings
- Updates to KqueueReactor implementation
- Changes to test scenarios or timing
- Platform upgrades that affect kqueue behavior

### Last Generated
- **Date**: 2026-04-18
- **Platform**: macOS (target platform for BSD conformance)
- **Rust Version**: 1.84.0 (or project MSRV)
- **Git Commit**: (to be filled when tests are run on actual BSD system)

### Platform-Specific Notes
- **macOS**: Primary reference platform for golden generation
- **FreeBSD**: May require separate golden files if behavior differs significantly
- **Linux/Windows**: Tests are conditionally compiled out