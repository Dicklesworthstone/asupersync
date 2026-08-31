# RaptorQ Fountain Coding and Distributed Systems

## Table of Contents

- [RaptorQ Overview](#raptorq-overview)
- [Multi-Donor Bonded Transfers](#multi-donor-bonded-transfers)
- [Distributed Primitives](#distributed-primitives)
- [Consistent Hashing](#consistent-hashing)
- [Distributed Snapshots](#distributed-snapshots)
- [Security Layer](#security-layer)
- [Testing Distributed Logic](#testing-distributed-logic)
- [Distributed Model Summary](#distributed-model-summary)

## RaptorQ Overview

Source: `src/raptorq/`

RFC 6330 systematic RaptorQ codes recover K source symbols from a sufficiently
large linearly independent set of source/repair symbols. K received symbols
are not an unconditional guarantee: exact-rank solves can be deficient, so
production transfer policy normally sends repair overhead and reports
`InsufficientRank` honestly. Treat this as a proof-carrying subsystem, not just
an encoder/decoder API. The production `transport_rq` transport is fail-closed
by default; lower-level codec and pipeline APIs have separately configurable
policy and do not inherit that transport claim.

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

For repository proof, do not bypass preflight. Read live `AGENTS.md`,
`TESTING_FOR_AGENTS.md`, `artifacts/proof_lane_manifest_v1.json`, and the help
for `scripts/run_raptorq_e2e.sh`; run the exact declared lane through RCH. A
preflight-bypassed invocation is at most an explicitly labeled downstream or
harness smoke and cannot support repository proof.

Outputs: `summary.json`, `scenarios.ndjson`, `validation_stages.ndjson`.

### Authentication Posture

The production `transport_rq` transport makes the trust boundary explicit and
is fail-closed by default. Lower-level RaptorQ codec and pipeline callers must
select and validate their own authentication policy:

- The production `transport_rq` transport refuses to run on a default
  `RqConfig`: symbol-auth mode resolves to `MissingAuthenticationContext`, so
  `send_path` errors out before any network I/O and `receive_once` rejects
  the connection before any handshake or data transfer, unless the
  caller makes a deliberate choice — `with_symbol_auth(ctx)` (every UDP
  symbol signed and verified) or the explicit
  `allow_unauthenticated_for_trusted_transport()` opt-out for loopback/lab
  links (integrity-vs-manifest only). The handshake additionally rejects any
  posture mismatch between peers, in both directions.
- Native QUIC data planes now perform in-handshake X.509 verification (chain +
  hostname + signature, fail closed, no insecure skip-verify default) and
  protect control STREAM + symbol DATAGRAM packets with handshake-derived
  1-RTT keys. See `docs/quic_atp_threat_model.md` for the full threat table.

Anchors: `src/net/atp/transport_rq/mod.rs`,
`tests/atp_rq_symbol_auth_e2e_contract.rs` (transport truth), and
`tests/decoding_secure_default.rs` (config posture).

ATP no-claim boundaries are part of the security story. Authenticated mode on
`transport_rq` protects the UDP symbol plane ONLY: the TCP control channel and
manifest are still unauthenticated without TLS, and the sibling
`transport_tcp` transport has no per-symbol authentication at all
(integrity-vs-manifest only). Full Byzantine-injection prevention against an
active MITM requires `with_symbol_auth` AND an authenticated control
channel/manifest. Current positive ATP claims are matrix-cell scoped unless
the full current matrix is fresh; insert/shift re-sync byte savings,
clean-large wins, one encrypted mild-loss win, or the `500M/broken/nocrypto`
RQ win do not automatically prove encrypted-large, tree-small,
lossy-encrypted, full-matrix, or cross-trust symbol safety.

For the current RQ benchmark evidence, `MATRIX-207` made
`500M/broken/nocrypto` converge but fail closed on SHA, `MATRIX-208` fixed the
shard-absolute staging seed read and reached parity, and `MATRIX-209` banked
the scoped win with double-buffered encode-ahead. The residual rare
`InconsistentEquations` rejects were root-caused and closed under
`asupersync-c54to7` (2026-07-09): spec-expected RFC 6330 rank deficiency at
rank-K-exact solves, decoder core exonerated deterministically; the honest
label is now `RejectReason::InsufficientRank` (`src/decoding.rs`), with
`InconsistentEquations` reserved for the genuine-anomaly fallback. Cite the
ledger before claiming anything broader.

## Multi-Donor Bonded Transfers

One receiver pulls a single object from N donors at once. Each donor is assigned
a disjoint slice of the RaptorQ symbol stream (source + repair ESIs) and sprays
it over UDP; the receiver decodes from the union once it has sufficient rank.
Donors need no symbol-by-symbol coordination beyond enrollment, and a dead
donor's repair window can be reallocated to survivors. Code:
`src/net/atp/bonding/` (assignment, descriptor, handshake, receiver,
`transport_select`, `derive`) plus `src/net/atp/transport_rq/bonded.rs`
(`receive_bonded` / `donate_bonded`).

**Fail-closed content agreement (the core invariant).** Library/transport
enrollment does not send a descriptor as the agreement mechanism: receiver and
every donor derive transfer id, merkle root, object ids, and portable metadata
commitment independently from local bytes via
`bonding::derive_bonded_descriptor` (`MetadataPolicy::portable()`,
`preserve_hardlinks: true`, `max_block_size` clamped to at least
`symbol_size`). Enrollment rejects transfer-id, merkle, metadata, symbol-size,
or max-block-size mismatch. A drifted donor cannot enroll.

The CLI orchestration boundary is different: `atp bond-pull` SSH-runs the
hidden `__bond-descriptor` command on donor 0 and transports its descriptor
JSON back to seed the in-process receiver. Every donating peer still derives
its own descriptor and enrollment checks it, but the orchestrator must trust
and authenticate that SSH bootstrap path. Do not repeat the blanket claim that
the descriptor is "never sent on the wire." Symbol auth remains the same
deliberate fail-closed choice as single-source RaptorQ (`rq_auth_key_hex` /
`--rq-allow-unauthenticated-lab`).
The protected-stdin SSH key delivery, child-environment stripping, redaction,
and OpenSSH preflight live in `src/bin/atp.rs`, not the RaptorQ codec modules.

**CLI (receiver-orchestrated):**
```bash
atp bond-pull <src> <dest> --donors alice@h1,bob@h2 --advertise <ctrl-addr:port> \
  [--transport auto|tailscale|ssh|ip] [--rq-auth-key-hex HEX | --rq-allow-unauthenticated-lab]
```
`bond-pull` starts the in-process bonded receiver, SSH-launches one `bond-donate` leg per donor, waits for the SHA/merkle-verified commit. `bond-recv` (server) + `bond-donate` (each donor) are the manual halves. Per-donor path + the operator's `transport_preference` land in the `atp_bond_pull` JSON receipt.

**Transport selection** (`bonding::transport_select`): `select_donor_path(pref, &ReceiverEndpoints{direct,tailnet}, donor_on_tailnet) -> Option<DonorPathChoice{transport,dial}>`. `auto` prefers shared Tailscale (CGNAT `100.64.0.0/10`, detected via `detect_local_tailnet()` shelling `tailscale status --json`/`tailscale ip -4`) else direct IP; `ip`/`tailscale` force a family; `ssh` tunnels. In `run_bond_pull` the receiver always advertises `direct = Some(control)`, so a failed tailnet probe degrades to direct, never aborts. GOTCHA: the live `ssh -L` forward is stubbed (`z01bbr.8.3 H3`) — an ssh-selected leg reports its plan and falls back to a direct dial today. `PathKind::preference_rank` (`src/atp/path.rs`) is the injective total order (Tailscale < direct < relay < mailbox).

**SDK** (`asupersync::net::atp::sdk::BondedTransfer`): fluent builder mirroring
the CLI flags (`expect_donors`/`listen`/`udp_bind`/`auth_key_hex`/
`allow_unauthenticated_lab`/`symbol_size`/`max_block_size`/
`repair_overhead`/`accept_timeout`). Constructors are
`receive(dest, local_src)` and `donate(src, control_addr)`.
`run(self, &cx).await -> AtpOutcome<BondedReport>` is the in-task path;
`spawn(self, &cx) -> AtpOutcome<BondedReceiveHandle>` creates the owned
receiver child. Handle operations are asynchronous:
`control_addr(&mut self).await`, `next_progress(&mut self).await`,
`cancel(&self).await`, and consuming `wait_for_completion(self).await`.
Progress carries per-donor ingress, blocks remaining, feedback rounds, and
reallocated repair windows. Cancellation checks include the boundary before
irreversible commit.

## Distributed Primitives

Source: `src/remote.rs`, `src/distributed/`

Besides the remote protocol below, current public distributed modules include
PBFT/consensus, membership, anti-entropy, adaptive layout, computation schema,
recovery, and snapshot primitives. Their public existence does not supply
discovery, authenticated WAN transport, deployment, or a turnkey cluster.

### Named Remote Spawn

Not closure shipping. Named computations with serialized input, gated by the
`RemoteCap` on the `Cx` (fails with `RemoteError::NoCapability` otherwise):

```rust
let handle = spawn_remote(
    &cx,
    NodeId::new("worker-1"),
    ComputationName::new("my_task"),
    RemoteInput::new(serialized),
)?;
```

Returns a region-owned `RemoteHandle`; attached runtimes send protocol
messages, while a missing runtime fails closed to an explicit deterministic
fallback (no detached wall-clock work).

### Lease Obligations

Leases are obligation-backed, participate in region close/quiescence.

### Idempotency Store

Deduplicates spawn retries for the in-flight operation lifetime plus a
bounded terminal-result retention window, with conflict detection.

### Session-Typed Protocol

Origin/remote state machines validate legal spawn/ack/cancel/result/renewal transitions.

### Saga Compensations

Forward steps and compensations tracked as structured rollback flow. `step`
runs the forward action eagerly and registers its compensation; on failure,
registered compensations run in reverse order before it returns:

```rust
let mut saga = Saga::new();
saga.step("debit", || debit(), move || undo_debit(txn))?;
saga.step("credit", || credit(), move || undo_credit(txn))?;
```

### Logical-Time Envelopes

Protocol messages carry logical clock metadata for causal correlation.

### Transport Lifecycle Proof

The transport surface is separated from the protocol state machines. The
shipped proof tier includes both the deterministic virtual/lab baseline and a
production-transport-backed loopback proof: `tests/remote_transport_lifecycle_contract.rs`
drives a TCP-backed `RemoteRuntime` adapter over `asupersync::net::TcpListener`/`TcpStream`
through spawn/result, cancel before ack, cancel while running, lease
renewal/expiry, idempotency replay, send failure, receive EOF, malformed
envelope cleanup, delayed ack ordering, capability denial, and the
deterministic no-runtime fallback. No-claim boundary: discovery,
TLS/authentication, WAN retry policy, and a frozen production wire format
remain adapter-specific, not blanket core-runtime claims.

## Consistent Hashing

Source: `src/distributed/consistent_hash.rs`

Deterministic consistent hashing for stable assignment. No iteration-order landmines.

Used for assigning encoded symbols to replicas in snapshot distribution.

## Distributed Snapshots

Region state is encoded via RaptorQ and symbols are assigned through consistent
hashing. Recovery requires enough authenticated, mutually consistent symbols
to reach decode rank—not merely a node-count quorum or exactly K arrivals.

## Security Layer

Source: `src/security/`

Per-symbol authentication tags prevent Byzantine symbol injection on the
symbol plane. Integrates with the RaptorQ pipeline (`verify_auth`;
fail-closed — forged/contextless symbols are rejected).

Do not describe symbol authentication as optional polish. It is part of the
commit-safety story for untrusted symbol planes — but remember the no-claim
boundary above: symbol tags do not authenticate the TCP control
channel/manifest.

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
| Idempotency | `src/remote.rs` | Dedup retries; in-flight lifetime + bounded terminal retention |
| Sagas | `src/remote.rs` | Forward/compensate with structured rollback |
| Logical clocks | `src/trace/distributed/vclock.rs` | Lamport, Vector, Hybrid modes |
| Consistent hash | `src/distributed/consistent_hash.rs` | Deterministic, stable assignment |
| Sheaf checks | `src/trace/distributed/sheaf.rs` | Global consistency from local observations |
