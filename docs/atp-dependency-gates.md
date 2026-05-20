# ATP Dependency Audit Gates

## Overview

ATP-M5 implements dependency audit gates to enforce ATP's architectural constraints:

1. **No external QUIC stacks** in ATP/native core
2. **No Tokio runtime** in production paths
3. **Clean separation** between core and compatibility layers

## Implementation

### Scripts

- **`scripts/ci/check_banned_deps.py`** - General banned dependency checker
  - Uses `cargo metadata` for comprehensive dependency analysis
  - Context-aware allowances for dev/test/fuzz dependencies
  - Supports pattern matching for QUIC-related packages

- **`scripts/ci/check_atp_core_deps.sh`** - ATP-specific core validation
  - Validates workspace packages exclude banned dependencies
  - Tests production feature builds without test-internals
  - Excludes conformance and tokio-compat packages appropriately

- **`scripts/ci/audit_dependencies.sh`** - Comprehensive dependency audit
  - Security vulnerability scanning (with cargo-audit)
  - Duplicate dependency detection
  - Build timing and size analysis

### Proof Lanes

- **`dependency_audit`** - Full dependency audit with banned deps check
- **`atp_core_deps`** - ATP-specific core dependency validation

### Banned Dependencies

#### External QUIC Implementations
- `quinn`, `quiche`, `h3`, `h3-quinn`, `s2n-quic`
- Any package matching patterns: `.*-quic$`, `^quic-.*`, `.*-tokio$`

#### Conflicting Async Runtimes
- `tokio`, `tokio-util`, `tokio-stream` (in core only)
- `async-std`, `smol`, `glommio`

#### High-level Network Libraries
- `reqwest`, `hyper`, `warp`, `axum` (in core only)

### Allowed Contexts

Dependencies banned in core are permitted in:

- **asupersync-tokio-compat** - Explicit Tokio compatibility layer
- **examples/** - Example code and demonstrations
- **tests/** - Test and conformance code
- **dev-dependencies** - Development and testing dependencies
- **fuzz-feature** - Fuzzing infrastructure (intentionally includes tonic/tokio)
- **conformance** - Conformance testing against reference implementations

## Validation

### CI Integration

```bash
# Run dependency audit lane
scripts/ci/lanes/run_lane.sh --lane dependency_audit --platform linux --mode smoke

# Run ATP core validation
scripts/ci/lanes/run_lane.sh --lane atp_core_deps --platform linux --mode smoke
```

### Local Development

```bash
# Check for banned dependencies
cargo metadata --format-version 1 | python3 scripts/ci/check_banned_deps.py

# Validate ATP core dependencies
scripts/ci/check_atp_core_deps.sh

# Full dependency audit
scripts/ci/audit_dependencies.sh
```

## Artifacts

All dependency audits generate artifacts in `artifacts/audit/`:

- `banned-deps-report.json` - Banned dependency violations
- `dependency-metadata.json` - Full cargo metadata
- `dependency-tree.txt` - Human-readable dependency tree
- `dependency-report.json` - Analysis summary
- `atp-core-metadata.json` - Core feature dependency metadata

## Architecture Guarantees

1. **Production Runtime Purity**
   - Default and metrics features exclude Tokio
   - Native QUIC implementation (no external stacks)
   - Deterministic behavior in lab environments

2. **Compatibility Layer Isolation**
   - Tokio dependencies confined to asupersync-tokio-compat
   - External networking libraries in examples/tests only
   - Clear boundary between core and compatibility

3. **Development Flexibility**
   - Full dependency access in dev/test contexts
   - Conformance testing against reference implementations
   - Fuzzing infrastructure with necessary dependencies

This ensures ATP maintains its architectural discipline while providing practical compatibility and testing capabilities.