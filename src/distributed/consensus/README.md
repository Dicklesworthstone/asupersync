# PBFT Consensus (experimental)

This module contains an **experimental** implementation of Practical Byzantine Fault Tolerance (PBFT) for the asupersync distributed runtime. Only the normal-case path is implemented. It is **not Byzantine-fault-tolerant yet**: do not rely on it for safety against a faulty primary or for liveness under primary failure. Nothing outside this module uses it.

## What exists

- **Normal-case three-phase protocol** (`pbft.rs`): pre-prepare, prepare and commit with 2f+1 quorums, then ordered application execution through `PbftExecution` and an explicit `PbftStateMachine`.
- **Authenticated transport, opt-in** (`authenticated.rs`): `AuthenticatedPbftNode` and `PbftAuthenticator` sign and verify replica traffic against an explicitly pinned static membership (`PbftMembership`). The legacy message APIs remain trusted, unsigned boundaries.
- **UDP transport** (`udp.rs`, not on wasm32): `UdpPbftTransport`.
- **Core types** (`types.rs`): `ReplicaId`, `ViewNumber`, `SequenceNumber`, `MessageDigest`, `ConsensusRequest`, `ConsensusBatch`, `ConsensusResponse`.

## What does not exist yet

- **View change / new view**: the handlers fail closed instead of electing a new primary. A faulty or failed primary stops progress.
- **Checkpoints, watermarks and log pruning**: the message logs grow without bound.
- **Durable recovery** and dynamic reconfiguration.

Authentication alone does not establish Byzantine fault tolerance. Completing view change and checkpoints is the prerequisite for the safety and liveness properties PBFT is known for. Tracked by `asupersync-v8mszr` (implementation) and `asupersync-bi2462.124` (whether PBFT continues).

## Protocol flow (normal case)

1. The primary assigns a sequence number to a request batch and broadcasts `PrePrepare`.
2. Replicas validate it and broadcast `Prepare`.
3. After 2f+1 matching `Prepare` messages, replicas broadcast `Commit`.
4. After 2f+1 matching `Commit` messages, replicas execute the batch in sequence order.

## Usage

Use `PbftExecution` with your own `PbftStateMachine` to execute requests on the normal-case path. See the rustdoc of `pbft::PbftExecution` and the module's tests for complete examples.

`PbftConsensus::submit` is **deprecated**: it forwards the request and then returns a fixed placeholder response (`b"consensus result"`, view 0, sequence 0). It does not wait for, or return, the replicated result. It remains exported only for compatibility.
