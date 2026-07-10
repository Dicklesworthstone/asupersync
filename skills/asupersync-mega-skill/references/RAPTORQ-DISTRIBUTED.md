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
re-sync byte savings, clean-large wins, one encrypted mild-loss win, or the
`500M/broken/nocrypto` RQ win do not automatically prove encrypted-large,
tree-small, lossy-encrypted, full-matrix, or cross-trust symbol safety.

For the current RQ benchmark evidence, `MATRIX-207` made
`500M/broken/nocrypto` converge but fail closed on SHA, `MATRIX-208` fixed the
shard-absolute staging seed read and reached parity, and `MATRIX-209` banked
the scoped win with double-buffered encode-ahead. Residual rare
redundancy-recovered `InconsistentEquations` remain tracked under
`asupersync-c54to7`; cite the ledger before claiming anything broader.

## Multi-Donor Bonded Transfers

One receiver pulls a single object from N donors at once. Each donor is assigned a disjoint slice of the RaptorQ symbol stream (source + repair ESIs) and sprays it over UDP; the receiver decodes from the union. Fountain property ⇒ donors need no coordination beyond enrollment, and a dead donor's repair window is reallocated to survivors. Code: `src/net/atp/bonding/` (assignment, descriptor, handshake, receiver, `transport_select`, `derive`) + `src/net/atp/transport_rq/bonded.rs` (`receive_bonded` / `donate_bonded`).

**Fail-closed content agreement (the core invariant).** The descriptor (transfer-id, merkle root, per-entry object IDs, portable metadata commitment) is NEVER sent on the wire. Receiver and every donor derive it independently from their own local bytes via `bonding::derive_bonded_descriptor` (`MetadataPolicy::portable()`, `preserve_hardlinks: true`, `max_block_size` clamped ≥ `symbol_size`). Enrollment rejects on any transfer-id / merkle / metadata / symbol-size / max-block-size mismatch. A donor with drifted bytes cannot enroll ⇒ cannot corrupt the decode. Symbol-auth posture is the same deliberate fail-closed choice as single-source RaptorQ (`rq_auth_key_hex` / `--rq-allow-unauthenticated-lab`).

**CLI (receiver-orchestrated):**
```bash
atp bond-pull <src> <dest> --donors alice@h1,bob@h2 --advertise <ctrl-addr:port> \
  [--transport auto|tailscale|ssh|ip] [--rq-auth-key-hex HEX | --rq-allow-unauthenticated-lab]
```
`bond-pull` starts the in-process bonded receiver, SSH-launches one `bond-donate` leg per donor, waits for the SHA/merkle-verified commit. `bond-recv` (server) + `bond-donate` (each donor) are the manual halves. Per-donor path + the operator's `transport_preference` land in the `atp_bond_pull` JSON receipt.

**Transport selection** (`bonding::transport_select`): `select_donor_path(pref, &ReceiverEndpoints{direct,tailnet}, donor_on_tailnet) -> Option<DonorPathChoice{transport,dial}>`. `auto` prefers shared Tailscale (CGNAT `100.64.0.0/10`, detected via `detect_local_tailnet()` shelling `tailscale status --json`/`tailscale ip -4`) else direct IP; `ip`/`tailscale` force a family; `ssh` tunnels. In `run_bond_pull` the receiver always advertises `direct = Some(control)`, so a failed tailnet probe degrades to direct, never aborts. GOTCHA: the live `ssh -L` forward is stubbed (`z01bbr.8.3 H3`) — an ssh-selected leg reports its plan and falls back to a direct dial today. `PathKind::preference_rank` (`src/atp/path.rs`) is the injective total order (Tailscale < direct < relay < mailbox).

**SDK** (`asupersync::net::atp::sdk::BondedTransfer`): fluent builder mirroring the CLI flags (`expect_donors`/`listen`/`udp_bind`/`auth_key_hex`/`allow_unauthenticated_lab`/`symbol_size`/`max_block_size`/`repair_overhead`/`accept_timeout`). `receive(dest, local_src)` / `donate(src, control_addr)`. `.run(&cx) -> AtpOutcome<BondedReport>` (blocking) or `.spawn(&cx) -> AtpOutcome<BondedReceiveHandle>` (owned child; `control_addr()`, `next_progress() -> Option<BondedTransferProgress>`, `cancel()`, `wait_for_completion()`). Progress carries per-donor ingress, blocks_remaining, feedback_rounds, reallocated_repair_windows; `phase` reaches terminal `Completed` (success) or `Failed` (verification failure), with cancel/other errors signalled by stream-close + the join outcome. Cancel-correct: a cancelled `Cx` unwinds at the next checkpoint (one guards the instant before the irreversible commit) and commits nothing.

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
