# ATP Architecture

ATP is the Asupersync Transfer Protocol. It is the repo-owned data movement
layer for verified object-graph transfer over native Asupersync transport
surfaces. The current implementation is intentionally split into testable model
layers before daemon, relay, mailbox, and SDK wiring depend on them.

## Current Status

The live source of truth is the code under `src/atp/` and `src/net/atp/`.
This document records the current implementation boundary; it is not a
replacement for Beads.

Implemented model surfaces:

- Object graph model, metadata policy, object ids, and graph validation:
  `src/atp/object.rs`.
- Manifest schema, chunking/compression/encryption policy records, Merkle roots,
  and graph commit semantics: `src/atp/manifest.rs`.
- Path graph candidate model, security properties, budgets, racing, snapshots,
  and terminal outcome taxonomy: `src/atp/path.rs`.
- Committed validation surfaces for object graphs, manifests, Merkle roots, and
  graph commits: `src/atp/object.rs` and `src/atp/manifest.rs`.
- Binary ATP frame definitions and codec: `src/net/atp/protocol/frames.rs`,
  `src/net/atp/protocol/codec.rs`, and `src/net/atp/protocol/varint.rs`.
- QUIC-frame model, packet assembly, transport parameters, and session
  negotiation state machine: `src/net/atp/protocol/quic_frames.rs`,
  `src/net/atp/protocol/packet_assembly.rs`,
  `src/net/atp/protocol/transport_params.rs`, and
  `src/net/atp/protocol/session.rs`.
- Native UDP endpoint contract for the QUIC path:
  `src/net/quic_native/endpoint.rs`.
- Platform capability diagnostics for disk and packaging policy:
  `src/fs/platform.rs` and `asupersync atp doctor --platform`.

## Non-Negotiable Boundaries

ATP must preserve the core Asupersync invariants:

- Every transfer task is region-owned; daemon and SDK integration must not
  introduce detached transfer work.
- Cancellation is a protocol. Transfer writers, relays, and mailbox workers
  must drain or emit fail-closed proof evidence before exposing data.
- Effects flow through explicit `Cx` capability boundaries. ATP code must not
  add ambient runtime, filesystem, network, or clock authority.
- Permits, leases, acknowledgements, sparse-file reservations, and relay grants
  are obligations. They must commit or abort.
- Lab and replay tests must remain deterministic for the model layers.
- Core ATP must not depend on Tokio, Hyper, Reqwest, Axum, async-std, smol, or
  external QUIC endpoint stacks. The QUIC path is native Asupersync code.

## Layer Map

### Data Model

`src/atp/object.rs` models ATP as object-graph movement, not file copying.
The core ids are `ContentId`, `ManifestId`, and `ObjectId`. Object kinds include
files, directories, streams, symlinks, and application-defined records.
`ObjectGraph::validate` checks child existence and cycles before manifest,
session, or transfer code trusts a graph.

`src/atp/manifest.rs` turns object graphs into versioned, canonical manifest
state. It records chunk plans, RaptorQ repair layout, compression policy,
encryption policy, capability policy, and graph commits. `MerkleRoot` is derived
from the graph and is the stable integrity anchor passed into session policy and
verification.

The committed manifest proof lane is `scripts/run_atp_manifest_e2e.sh`. It
exercises canonical serialization, SHA-256 Merkle roots, policy validation,
unknown-field handling, and graph commit semantics while routing every Cargo
call through `rch`.

### Verification

The committed exposure boundary is currently the object and manifest validation
surface. `ObjectGraph::validate`, `Manifest::validate`, and
`GraphCommit::validate` reject missing graph edges, cycles, unsupported manifest
versions, dangling roots or children, and commit-id mismatches before higher
transfer layers may expose data.

The tracker reserves the following verifier-stage taxonomy for chunk writers,
relays, mailbox consumers, proof bundles, and finalizers as those surfaces land:

- `chunk_hash`
- `object_content`
- `graph_merkle`
- `manifest`
- `commit`
- `repair_symbol`
- `proof_bundle`
- `finalizer`

Sparse writers, cache readers, relays, mailbox consumers, and SDK import paths
must use the committed validation surface now and the dedicated verifier stages
before exposing committed ATP data once those stages are part of `main`.

### Path Graph

`src/atp/path.rs` models routes as explicit candidates:

- LAN multicast
- Explicit public UDP
- Public IPv6
- NAT-punched UDP
- Tailscale/private-network path
- ATP relay over UDP
- ATP relay over TCP/TLS on port 443
- MASQUE/CONNECT-UDP-style relay
- Offline mailbox

Each candidate carries `PathSecurity`, `PathBudget`, evidence, and a terminal
`PathOutcome`. Direct, relay, and mailbox paths are comparable through the same
candidate/race model instead of ad hoc branch logic.

### Binary Protocol

`src/net/atp/protocol/frames.rs` defines ATP frame types and headers.
`src/net/atp/protocol/codec.rs` is the frame boundary codec. It uses ATP varints
from `src/net/atp/protocol/varint.rs`, validates version and frame size, and
preserves decoder state for partial frames.

Frame families are:

- Session establishment: handshake and capability exchange.
- Object transfer: manifest, request, data, complete, and object error.
- Path management: path update, challenge, response, and keep-alive.
- Control: cancel, protocol error, and close.

### Native QUIC Surface

ATP uses native Asupersync QUIC surfaces. It must not pull in external QUIC
endpoint crates. The current model layers are:

- QUIC frame encode/decode: `src/net/atp/protocol/quic_frames.rs`.
- Packet budget, packet-number-space filtering, frame prioritization, and packet
  assembly: `src/net/atp/protocol/packet_assembly.rs`.
- Transport parameter validation: `src/net/atp/protocol/transport_params.rs`.
- UDP endpoint batching, cancellation-aware receive, metrics, and shutdown:
  `src/net/quic_native/endpoint.rs`.

The endpoint contract is guarded by
`tests/atp_native_quic_endpoint_contract.rs` and
`artifacts/atp_native_quic_endpoint_contract_v1.json`.

### Session Negotiation

`src/net/atp/protocol/session.rs` is a deterministic state-machine model before
socket or daemon wiring. It validates peer identity, transfer nonces, manifest
binding, path scopes, capability grants, feature selection, replay rejection,
and downgrade warnings.

Session contexts are direct, relay, mailbox, and swarm. Feature negotiation uses
`FeatureSet` over repair, datagrams, compression, encryption policy, swarm,
mailbox, relay, H3 adapter, WebTransport adapter, MASQUE adapter, proof bundles,
and resume.

`tests/atp_session_negotiation.rs` is the public E2E contract for CLI, daemon,
SDK, relay, mailbox, swarm, and replay consumers. The script
`scripts/run_atp_session_negotiation_e2e.sh` wraps that lane and writes a
deterministic run directory under `target/atp-session-negotiation-e2e/`.

### Platform and Policy Feedback

`src/fs/platform.rs` reports host capabilities that ATP disk and packaging code
must account for: sparse files, preallocation, atomic rename, fsync durability,
path length, case sensitivity, symlink behavior, socket buffers, IPv6, router
assist, and service manager support.

`src/runtime/scheduler/autotuner.rs` is a pressure-feedback surface. ATP should
feed transfer hot-path observations into scheduler tuning through explicit
metrics rather than adding transfer-local scheduling heuristics.

## User-Facing Examples

CLI diagnostic:

```bash
asupersync atp doctor --platform
```

Daemon receive path:

```text
accept session -> validate grant -> validate manifest -> write quarantine data
-> validate graph/commit/finalizer evidence -> expose committed output
```

SDK send path:

```text
build ObjectGraph -> derive Manifest -> negotiate direct/relay/mailbox session
-> stream frames -> emit verification and replay evidence
```

Relay path:

```text
SessionContextKind::Relay requires AtpFeature::Relay, relay-safe capability
scope, and end-to-end encrypted payload bytes. Relay metadata is visible; object
bytes are not plaintext relay authority.
```

Mailbox path:

```text
SessionContextKind::Mailbox requires AtpFeature::Mailbox and uses the same
object, manifest, validation, and proof-bundle model. It may complete without
both peers being online at once.
```

Swarm path:

```text
SessionContextKind::Swarm requires AtpFeature::Swarm. Swarm workers may receive
object shards or repair symbols, but validation evidence remains the exposure
gate.
```

Replay path:

```text
session transcript hash + proof artifact + path trace id + verification
evidence -> deterministic replay/forensics bundle
```

## Proof Lanes

Use `rch` for every Cargo command in this repository.

Current ATP-focused proof commands:

```bash
rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_atp_all cargo check --all-targets
```

```bash
rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_atp_session cargo test --test atp_session_negotiation -- --nocapture
```

```bash
rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_atp_endpoint cargo test --test atp_native_quic_endpoint_contract -- --nocapture
```

```bash
rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_atp_fmt cargo fmt --check
```

Manifest E2E:

```bash
bash scripts/run_atp_manifest_e2e.sh
```

Session negotiation E2E:

```bash
rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_atp_session_e2e bash scripts/run_atp_session_negotiation_e2e.sh
```
