# RaptorQ Fountain Coding and Distributed Systems

## RaptorQ Overview

Source: `src/raptorq/`

RFC 6330 systematic RaptorQ codes: any K-of-N encoded symbols suffice to recover original K source symbols. In current Asupersync, treat this as a proof-carrying, fail-closed subsystem, not just an encoder/decoder API.

| Module | Purpose |
|--------|---------|
| `rfc6330.rs` | Standard-compliant parameter computation |
| `systematic.rs` | Systematic encoder/decoder |
| `gf256.rs` | GF(2^8) arithmetic (add, multiply, inversion) |
| `linalg.rs` | Matrix operations over GF(256) |
| `pipeline.rs` | Full sender/receiver pipelines with symbol authentication |
| `proof.rs` | Decode proof system for verifiable recovery |
| `decoder.rs` | Policy-driven deterministic decode planner |
| `test_log_schema.rs` | Hard-regime transitions and fallback recording |

### Decoder Policy Selection

Runtime policy can choose:
- Conservative baseline
- High-support-first
- Block-Schur low-rank hard-regime plans

Based on extracted matrix features. Hard-regime transitions recorded with reason labels.

### Dense-Factor Caching

Bounded capacity with hit/miss/eviction telemetry in decode stats.

### GF(256) Kernel Selection

Deterministic per-process selection. Policy snapshots for dual-lane fused operations. Optional SIMD acceleration via `simd-intrinsics` feature (AVX2/NEON).

### Validation

```bash
# Fast smoke
NO_PREFLIGHT=1 ./scripts/run_raptorq_e2e.sh --profile fast --bundle

# Full profile
NO_PREFLIGHT=1 ./scripts/run_raptorq_e2e.sh --profile full --bundle

# Forensics (includes repair_campaign perf smoke)
NO_PREFLIGHT=1 ./scripts/run_raptorq_e2e.sh --profile forensics --bundle
```

Outputs: `summary.json`, `scenarios.ndjson`, `validation_stages.ndjson`.

### Authentication Posture

RaptorQ transport must make the trust boundary explicit:

- Direct native QUIC/TLS data planes can rely on verified QUIC AEAD for symbols
  that stay inside the verified 1-RTT channel.
- Non-direct, non-QUIC, or cross-trust symbol paths must use explicit
  per-symbol authentication context.
- Secure defaults should fail closed when authentication context is missing or
  mismatched. Do not "opt out" except for a deliberately trusted transport path.

Useful anchors: `src/net/atp/transport_rq/mod.rs`,
`tests/atp_rq_symbol_auth_e2e_contract.rs`, and
`tests/atp_rq_decoding_secure_default.rs`-style secure-default tests when
present in the current tree.

ATP benchmark no-claim boundaries are part of the security story. Direct
QUIC/TLS paths can rely on verified 1-RTT AEAD for in-channel symbols, but
missing symbol-auth context, TLS-less native QUIC send paths, and unsupported
transport/auth combinations must fail closed. Current positive ATP claims are
matrix-cell scoped unless the full current matrix is fresh; insert/shift
re-sync byte savings, clean-large wins, or one encrypted mild-loss win do not
automatically prove lossy, encrypted-large, or cross-trust symbol safety.

## Distributed Primitives

Source: `src/remote.rs`, `src/distributed/`

### Named Remote Spawn

Not closure shipping. Named computations with serialized input:

```rust
spawn_remote(cx, RemoteCap::new(), ComputationName("my_task"), input)
```

### Lease Obligations

Leases are obligation-backed, participate in region close/quiescence.

### Idempotency Store

Deduplicates spawn retries with TTL-bounded records and conflict detection.

### Session-Typed Protocol

Origin/remote state machines validate legal spawn/ack/cancel/result/renewal transitions.

### Saga Compensations

Forward steps and compensations tracked as structured rollback flow.

```rust
let saga = Saga::new("transfer")
    .step("debit", debit_fn, compensate_debit)
    .step("credit", credit_fn, compensate_credit);
```

### Logical-Time Envelopes

Protocol messages carry logical clock metadata for causal correlation.

## Consistent Hashing

Source: `src/distributed/consistent_hash.rs`

Deterministic consistent hashing for stable assignment. No iteration-order landmines.

Used for assigning encoded symbols to replicas in snapshot distribution.

## Distributed Snapshots

Region state encoded via RaptorQ, symbols assigned via consistent hashing, recovery requires quorum of symbols from surviving nodes.

## Security Layer

Source: `src/security/`

Per-symbol authentication tags prevent Byzantine symbol injection. Integrates with RaptorQ pipeline.

Do not describe symbol authentication as optional polish. It is part of the
commit-safety story for untrusted symbol planes.

## Testing Distributed Logic

- Test quorum loss, recovery, and cancellation explicitly
- Use `VirtualTcp` for deterministic network behavior
- Use lab scenarios: `examples/scenarios/partition_heal.yaml`, `examples/scenarios/clock_skew_lease.yaml`
- Test idempotency and lease expiry under chaos
- Verify saga compensations fire correctly
- Use `src/lab/scenario.rs` for repeatable validation

## Distributed Model Summary

| Primitive | Source | Behavior |
|-----------|--------|----------|
| Remote spawn | `src/remote.rs` | Named, serialized, `RemoteCap`-gated |
| Leases | `src/remote.rs` | Obligation-backed, region-owned |
| Idempotency | `src/remote.rs` | TTL records, dedup retries |
| Sagas | `src/remote.rs` | Forward/compensate with structured rollback |
| Logical clocks | `src/trace/distributed/vclock.rs` | Lamport, Vector, Hybrid modes |
| Consistent hash | `src/distributed/consistent_hash.rs` | Deterministic, stable assignment |
| Sheaf checks | `src/trace/distributed/sheaf.rs` | Global consistency from local observations |
