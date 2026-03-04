# Tokio Interop Support Matrix and Long-Term Policy

**Bead**: `asupersync-2oh2u.7.9` ([T7.9])
**Program**: `asupersync-2oh2u` ([TOKIO-REPLACE])
**Author**: SapphireHill (claude-code / opus-4.6)
**Date**: 2026-03-04
**Dependencies**: `asupersync-2oh2u.7.8` (adapter performance budgets)
**Purpose**: Ship a support matrix of tested external crates, supported feature subsets,
maintenance commitments, drift detection, and escalation policy for upstream breakages.

---

## 1. Scope

This document defines:
- Machine-readable support matrix for all in-scope Tokio-locked crates
- Feature subset support with explicit ownership and evidence links
- Maintenance commitments and compatibility window
- Breakage escalation policy for upstream releases
- Drift detection rules for CI enforcement

---

## 2. Support Tiers

### 2.1 Tier Definitions

| Tier | Label | Criteria | Commitment |
|------|-------|----------|------------|
| T1 | Critical | Impact >= 14.0, keystone for HTTP/web/gRPC | Full adapter, CI-gated, 72h breakage response |
| T2 | High | Impact 10.0–13.5, significant ecosystem reach | Full adapter, weekly CI, 1-week breakage response |
| T3 | Moderate | Impact 8.0–9.0, niche but meaningful | Partial adapter, monthly CI, best-effort response |
| T4 | Low | Impact 6.0–7.5, minimal coupling or near-free | Thin adapter or documentation only, quarterly CI |
| T5 | Minimal | Impact <= 4.0, trivial or out-of-scope | No adapter; document workaround if needed |

### 2.2 Tier Assignment

| Crate | Version | Impact Score | Tier | Adapter Module | Feature Gate |
|-------|---------|-------------|------|----------------|--------------|
| reqwest | 0.12.x | 22.5 | T1 | hyper_bridge + body_bridge | `hyper-bridge` |
| axum | 0.8.x | 17.5 | T1 | hyper_bridge + tower_bridge | `hyper-bridge`, `tower-bridge` |
| tonic | 0.13.x | 14.0 | T1 | hyper_bridge + tower_bridge + body_bridge | `hyper-bridge`, `tower-bridge` |
| sea-orm | 1.1.x | 13.5 | T2 | blocking | always |
| hyper | 1.6.x | 12.5 | T2 | hyper_bridge | `hyper-bridge` |
| bb8 | 0.9.x | 10.5 | T2 | blocking | always |
| sqlx | 0.8.x | 10.0 | T2 | blocking + io | always |
| rumqttc | 0.24.x | 9.0 | T3 | io | `tokio-io` |
| diesel-async | 0.5.x | 8.0 | T3 | blocking | always |
| tower | 0.5.x | 7.5 | T4 | tower_bridge | `tower-bridge` |
| rdkafka | 0.36.x | 7.5 | T4 | blocking | always |
| tower-http | 0.6.x | 6.0 | T4 | tower_bridge | `tower-bridge` |
| lapin | 3.0.x | 4.0 | T5 | — | — |
| deadpool | 0.12.x | 4.0 | T5 | — | — |

---

## 3. Feature Subset Support

### 3.1 Adapter Feature Gates

| Feature Gate | Modules Enabled | Required Dependencies |
|-------------|-----------------|----------------------|
| `hyper-bridge` | hyper_bridge, body_bridge | hyper 1.x, http, http-body, bytes |
| `tower-bridge` | tower_bridge | tower 0.4+ |
| `tokio-io` | io (Tokio trait impls) | tokio-util (io feature) |
| `full` | all of the above | all adapter deps |

### 3.2 Per-Crate Feature Support Matrix

| Crate | Supported Features | Unsupported Features | Evidence |
|-------|--------------------|---------------------|----------|
| reqwest | HTTP/1.1, HTTP/2, TLS, JSON, streaming bodies | WebSocket (planned), HTTP/3 (planned) | E-01 |
| axum | routing, extractors, middleware, state, WebSocket | — | E-02 |
| tonic | unary, server-streaming, client-streaming, bidirectional, compression, gRPC-web | reflection (planned) | E-03 |
| hyper | server conn, client conn, executor, timer | — | E-04 |
| tower | Service trait, Layer, ServiceBuilder | tower-test (planned) | E-05 |
| tower-http | cors, compression, tracing, auth | — | E-06 |
| sea-orm | async queries, migrations, transactions | — | E-07 |
| sqlx | pool, query, transaction, migrate | compile-time checking (requires direct tokio) | E-08 |
| bb8 | pool creation, connection lifecycle | — | E-09 |
| diesel-async | async queries via deadpool/bb8 | — | E-10 |
| rdkafka | producer, consumer, admin | StreamConsumer (requires tokio runtime) | E-11 |
| rumqttc | async client, event loop | — | E-12 |

### 3.3 Evidence Links

| Evidence ID | Description | Artifact |
|-------------|-------------|----------|
| E-01 | reqwest interop conformance | `tests/tokio_interop_conformance_suites.rs` |
| E-02 | axum routing/middleware interop | `tests/tokio_interop_conformance_suites.rs` |
| E-03 | tonic gRPC interop | `tests/tokio_interop_conformance_suites.rs` |
| E-04 | hyper v1 executor/timer/sleep | `tests/tokio_adapter_boundary_architecture.rs` |
| E-05 | tower Service adapter | `tests/tokio_adapter_boundary_correctness.rs` |
| E-06 | tower-http middleware | `tests/tokio_interop_conformance_suites.rs` |
| E-07 | sea-orm blocking bridge | `tests/tokio_interop_conformance_suites.rs` |
| E-08 | sqlx pool/query bridge | `tests/tokio_interop_conformance_suites.rs` |
| E-09 | bb8 pool lifecycle | `tests/tokio_interop_conformance_suites.rs` |
| E-10 | diesel-async bridge | `tests/tokio_interop_conformance_suites.rs` |
| E-11 | rdkafka producer/consumer | `tests/tokio_interop_conformance_suites.rs` |
| E-12 | rumqttc async client | `tests/tokio_interop_conformance_suites.rs` |

---

## 4. Invariant Preservation

Every supported crate interaction MUST preserve the five core invariants:

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| INV-1 | No ambient authority | Adapters receive `Cx` explicitly; no `tokio::runtime::Handle::current()` |
| INV-2 | Structured concurrency | Adapter-spawned tasks are region-owned; region close collects them |
| INV-3 | Cancellation is a protocol | `CancelAware` wraps adapter futures; request → drain → finalize |
| INV-4 | No obligation leaks | Resources tracked; region close releases all adapter obligations |
| INV-5 | Outcome severity lattice | Results map to Ok/Err/Cancelled/Panicked, not bare `Result` |

### 4.1 Relaxable Constraints

| ID | Constraint | Relaxation | Opt-In |
|----|-----------|-----------|--------|
| REL-1 | Capability narrowing | Adapter may use `cap::All` internally | Documented in module |
| REL-2 | Budget enforcement | Tokio futures ignore poll budgets | Warning logged |
| REL-3 | Deterministic replay | I/O through external crates is non-deterministic | Lab mode fallback |
| REL-4 | Cancel-safety | Some Tokio futures are not cancel-safe | Documented per crate |

---

## 5. Maintenance Commitments

### 5.1 Compatibility Window

| Parameter | Value |
|-----------|-------|
| Policy version | 1.0.0 |
| Compatibility line | 0.1.x |
| Minimum supported Rust | edition 2024 |
| Tokio compatibility range | 1.x (current: 1.43) |
| hyper compatibility range | 1.x (current: 1.6) |
| tower compatibility range | 0.4+ |

### 5.2 Version Pinning Policy

- **Adapter crate** (`asupersync-tokio-compat`): SemVer, patch releases for bugfixes
- **External crate versions**: pinned in `Cargo.toml` with `>=X.Y, <X.Z` ranges
- **Breaking upstream changes**: adapter updated within committed response window (see § 5.3)

### 5.3 Breakage Response Windows

| Tier | Response Window | Action |
|------|----------------|--------|
| T1 (Critical) | 72 hours | Hotfix adapter release; blocking bead if needed |
| T2 (High) | 1 week | Patch release with migration note |
| T3 (Moderate) | 2 weeks | Best-effort patch; may defer to next minor |
| T4 (Low) | 1 month | Quarterly maintenance cycle |
| T5 (Minimal) | No commitment | Document workaround |

---

## 6. Escalation Policy

### 6.1 Breakage Classification

| Severity | Description | Example |
|----------|-------------|---------|
| S1 | Adapter fails to compile | hyper changes `Executor` trait signature |
| S2 | Runtime panic or correctness bug | Timer resolution change breaks sleep semantics |
| S3 | Performance regression beyond NF28 budgets | Overhead exceeds hard ceiling |
| S4 | Deprecation warning or non-breaking API change | Method marked deprecated |

### 6.2 Escalation Flow

1. **Detection**: CI drift check or manual report
2. **Triage**: Classify severity (S1–S4), identify affected tier
3. **Assignment**: Owner from support matrix takes bead
4. **Fix**: Adapter patch within response window
5. **Verification**: CI green, conformance suites pass
6. **Release**: Patch version of `asupersync-tokio-compat`

### 6.3 Upstream Communication

- **S1/S2**: File issue on upstream crate if adapter cannot work around
- **S3**: File performance regression report with benchmark evidence
- **S4**: Track deprecation; plan migration in next minor release

---

## 7. Gap Ranking

### 7.1 Current Gaps

| Gap ID | Crate | Feature | Severity | Downstream Impact | Owner |
|--------|-------|---------|----------|-------------------|-------|
| G-01 | reqwest | WebSocket support | Medium | Limits real-time HTTP clients | T7 |
| G-02 | reqwest | HTTP/3 support | Low | Future capability; h3 track covers this | T4 |
| G-03 | tonic | gRPC reflection | Low | Development tooling only | T7 |
| G-04 | sqlx | Compile-time checking | Medium | Requires direct tokio dependency | T6 |
| G-05 | rdkafka | StreamConsumer | Medium | Requires tokio runtime handle | T6 |
| G-06 | tower | tower-test crate | Low | Testing convenience only | T7 |

### 7.2 Gap Rationale

Each gap is ranked by:
- **Downstream dependency**: How many end-user workflows are blocked
- **Workaround availability**: Can users achieve the same result via alternative path
- **Implementation effort**: Estimated adapter complexity

---

## 8. Drift Detection

### 8.1 CI Enforcement

The following checks run to prevent stale support claims:

| Check ID | Description | Frequency | Hard-Fail |
|----------|-------------|-----------|-----------|
| DC-01 | Adapter crate compiles with all feature gates | Every CI run | Yes |
| DC-02 | Conformance suite passes for all T1/T2 crates | Every CI run | Yes |
| DC-03 | External crate version range resolves | Weekly | Yes |
| DC-04 | Support matrix document freshness (< 30 days) | Weekly | Warning |
| DC-05 | Evidence links resolve to existing test files | Every CI run | Yes |
| DC-06 | Invariant gate scan (no tokio in core paths) | Every CI run | Yes |

### 8.2 Freshness Policy

- Support matrix MUST be reviewed and version-bumped at least monthly
- Stale matrix (> 30 days since last review) triggers DC-04 warning
- Stale matrix (> 60 days) triggers hard-fail

### 8.3 Drift Detection Rules

| Rule | Trigger | Action |
|------|---------|--------|
| DR-01 | External crate publishes new major version | Review support matrix; update or document gap |
| DR-02 | Adapter test failure on CI | Triage within 24h; assign owner |
| DR-03 | New crate appears in top-100 tokio dependents | Evaluate for inclusion in next review |
| DR-04 | Invariant violation detected in adapter code | Hard-fail; block release |

---

## 9. Machine-Readable Output

### 9.1 Support Matrix JSON Schema

The support matrix is published as `artifacts/tokio_interop_support_matrix.json` with schema:

```json
{
  "schema_version": "1.0.0",
  "bead_id": "asupersync-2oh2u.7.9",
  "generated_at": "<ISO-8601>",
  "compatibility_line": "0.1.x",
  "policy_version": "1.0.0",
  "tiers": {
    "T1": { "label": "Critical", "response_hours": 72 },
    "T2": { "label": "High", "response_hours": 168 },
    "T3": { "label": "Moderate", "response_hours": 336 },
    "T4": { "label": "Low", "response_hours": 720 },
    "T5": { "label": "Minimal", "response_hours": null }
  },
  "crates": [
    {
      "name": "<crate-name>",
      "version_range": "<semver-range>",
      "impact_score": 22.5,
      "tier": "T1",
      "adapter_modules": ["hyper_bridge", "body_bridge"],
      "feature_gates": ["hyper-bridge"],
      "supported_features": ["HTTP/1.1", "HTTP/2", "TLS"],
      "unsupported_features": ["WebSocket"],
      "evidence_id": "E-01",
      "evidence_path": "tests/tokio_interop_conformance_suites.rs",
      "owner_track": "T7",
      "invariants_preserved": ["INV-1", "INV-2", "INV-3", "INV-4", "INV-5"]
    }
  ],
  "gaps": [
    {
      "gap_id": "G-01",
      "crate": "<crate-name>",
      "feature": "<missing-feature>",
      "severity": "Medium",
      "downstream_impact": "<description>",
      "owner_track": "T7"
    }
  ],
  "drift_checks": [
    {
      "check_id": "DC-01",
      "description": "<description>",
      "frequency": "every_ci_run",
      "hard_fail": true
    }
  ]
}
```

---

## 10. Downstream Binding

| Downstream Bead | Binding |
|-----------------|---------|
| `asupersync-2oh2u.11.2` | Migration cookbooks consume support matrix for crate-specific guidance |
| `asupersync-2oh2u.10.9` | Readiness gate aggregator checks support matrix completeness |

---

## 11. Revision History

| Date | Author | Change |
|------|--------|--------|
| 2026-03-04 | SapphireHill | Initial creation; 14 crates, 5 tiers, 6 gaps, 6 drift checks |
