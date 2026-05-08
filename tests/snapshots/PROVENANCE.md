# RaptorQ Encoder Stability Golden Artifacts

## Purpose

These golden snapshots capture canonical RaptorQ encoder output to detect non-determinism and prevent regressions in encoder behavior. Any change in encoder output must be intentionally reviewed.

## Test Coverage

| Test | K | Symbol Size | Seed | Repair Count | Purpose |
|------|---|-------------|------|--------------|---------|
| `encoder_k10_seed12345678` | 10 | 64 | 0x12345678 | 5 | Small K baseline |
| `encoder_k100_seed_deadbeef` | 100 | 128 | 0xDEADBEEF | 10 | Medium K stability |
| `encoder_k1000_seed_cafebabe` | 1000 | 256 | 0xCAFEBABE | 15 | Large K performance case |
| `encoder_determinism_k50_seed42424242` | 50 | 64 | 0x42424242 | 8 | Multi-run determinism |
| `encoder_seed_*` | 25 | 64 | varies | 5 | Seed sensitivity verification |
| `encoder_rfc6330_parameters` | varies | varies | 0 | 1 | RFC 6330 parameter stability |
| `encoder_symbol_size_consistency` | 100 | 256 | 0x44444444 | 3 | Symbol size correctness |

## Golden Content Structure

Each golden snapshot contains:
- **config**: Test parameters (K, symbol_size, seed, repair_count)
- **source_symbols_hash**: Hash of deterministic source data for verification
- **repair_symbols**: Array of repair symbol data with ESI and hex-encoded bytes
- **params_summary**: RFC 6330 derived parameters (K', L, S, H, W)

## Determinism Properties

1. **Source symbols**: Generated deterministically from K and symbol_size using `(i * 37 + j * 13 + 7) % 256`
2. **Encoder seed**: Fixed per test case to ensure reproducible repair generation
3. **Repair symbols**: RFC 6330-compliant deterministic output for given seed
4. **Parameters**: RFC 6330 systematic index table lookup (deterministic for K)

## How to Update Goldens

When RaptorQ encoder behavior intentionally changes:

```bash
# Run tests to see what changed
rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_raptorq_encoder_stability_snapshots cargo test --test raptorq_encoder_stability

# Review changes interactively
rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_raptorq_encoder_stability_snapshots cargo insta review

# Or accept all changes (CAREFUL - review diffs first)
rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_raptorq_encoder_stability_snapshots cargo insta test --test raptorq_encoder_stability --accept-unseen

# Review the git diff before committing
git diff tests/snapshots/
git add tests/snapshots/
git commit -m "Update RaptorQ encoder goldens: [reason for change]"
```

## Expected Stability

- **High stability**: RFC 6330 parameter derivation, symbol size consistency
- **Medium stability**: Repair symbol content (changes with algorithm tweaks)
- **Deterministic**: All output should be identical across runs for same inputs

## Failure Scenarios

| Failure | Likely Cause | Action |
|---------|--------------|--------|
| Non-determinism | Race condition, uninitialized memory | Fix the bug |
| Parameter changes | RFC 6330 table modification | Review if intentional |
| Symbol content changes | Algorithm modification, GF(256) changes | Review if intentional |
| Symbol size mismatches | Buffer management bug | Fix the bug |

## Generation Environment

- **Rust version**: As of project rust-toolchain.toml
- **Encoder version**: asupersync v0.3.1+ with blocked elimination optimization
- **Test execution**: `rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_raptorq_encoder_stability_snapshots cargo test --test raptorq_encoder_stability`
- **Generated**: 2026-05-08 (bead asupersync-nerid1)
