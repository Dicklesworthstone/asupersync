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
- Native QUIC packet-protection provider boundary and deterministic/TLS-backed
  proof lanes: `src/net/quic_native/tls.rs`.
- Platform capability diagnostics for disk and packaging policy:
  `src/atp/platform/mod.rs`, `src/atp/doctor/mod.rs`, and
  `asupersync atp doctor --platform`.

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

## ATP-M4 Implementation Ownership Contract

This section is the self-contained module-map contract for
`asupersync-w9xymh`. Its job is to keep ATP implementation work compatible
while multiple agents land independent slices on `main`. If a future change
adds, removes, or renames an ATP module family, update this section, the
contributor guide, and `tests/atp_module_map_contract.rs` in the same bead.

Status vocabulary:

- `committed`: tracked source exists on `main` and has a focused proof lane.
- `active`: a bead is in progress and may have dirty shared-main work; docs may
  describe the intended boundary but must not claim completion.
- `planned`: the module family is part of the ATP design but should not be used
  by callers until an implementation bead lands it with tests and proof logs.

Primary owner rule:

```text
one bead owns the semantic boundary for one module family
+ one exact file reservation set
+ one focused proof lane
+ one closeout note that names blockers or validation commands
```

This is the replacement for feature branches in ATP work. It gives future
agents a stable write boundary without violating the project rule that all work
happens on `main`.

### Current committed module inventory

| Boundary | Owner workstream | Committed files | Proof expectation | Why this belongs here |
| --- | --- | --- | --- | --- |
| ATP root and public model surface | `asupersync-l21xmv`, `asupersync-w9xymh` | `src/atp/mod.rs`, `src/net/atp/mod.rs` | module-map contract plus focused model tests | Keeps object, protocol, path, and proof surfaces discoverable without making callers depend on internal layout. |
| Object graph | `ATP-C`, `asupersync-bg83ig` | `src/atp/object.rs` | inline unit tests and manifest E2E | ATP moves verified object graphs; files and streams are front ends, not the primitive. |
| Manifest, Merkle, transform policy, graph commit | `ATP-C`, `asupersync-1iuqyc`, `asupersync-w5j10z` | `src/atp/manifest.rs` | `scripts/run_atp_manifest_e2e.sh` | Verification truth must be explicit about chunking, compression, encryption, repair, and proof semantics. |
| Verifier boundary | `ATP-D4`, `asupersync-fw1eg1` | `src/atp/verifier.rs` | verifier unit tests and future crash/finalizer lab scripts | The verifier is the gate that prevents corrupt chunks, lying relays, or bad repairs from becoming visible data. |
| Path candidate model | `ATP-F`, `asupersync-6cokae` | `src/atp/path.rs`, `src/net/atp/path/mod.rs` | path model tests and future NAT/path lab scripts | Connectivity is a graph of typed candidate edges, not direct-or-relay branching. |
| Platform capability facade and doctor output | `ATP-D1`, `asupersync-1tgbxe` | `src/atp/platform/mod.rs`, `src/atp/doctor/mod.rs`, `src/bin/asupersync.rs` | platform doctor tests and host capability probes | Disk, socket, service-manager, IPv6, and filesystem policy must be measured and explainable. |
| ATP binary protocol frames and codec | `ATP-B`, `asupersync-1ar9mg` | `src/net/atp/protocol/frames.rs`, `src/net/atp/protocol/codec.rs`, `src/net/atp/protocol/varint.rs` | codec round-trip, partial-frame, size-limit, and malformed-input tests | ATP application framing stays separate from QUIC packet mechanics and remains replayable in memory. |
| Protocol transcript, outcomes, and session negotiation | `ATP-B`, `asupersync-wvjjnz` | `src/net/atp/protocol/transcript.rs`, `src/net/atp/protocol/outcome.rs`, `src/net/atp/protocol/session.rs` | `tests/atp_session_negotiation.rs` and session E2E script | Authentication, capability grants, replay rejection, and downgrade policy happen before storage or relay authority. |
| QUIC frame and packet assembly model | `ATP-A`, `asupersync-zquziu` | `src/net/atp/protocol/quic_frames.rs`, `src/net/atp/protocol/packet_assembly.rs`, `src/net/atp/protocol/transport_params.rs` | frame/packet/transport-parameter unit tests | QUIC protocol state is internally owned; ATP must not delegate this to an external endpoint crate. |
| Native QUIC endpoint and UDP boundary | `ATP-A1`, `ATP-A11`, `asupersync-crscmn` | `src/net/quic_native/endpoint.rs` | `tests/atp_native_quic_endpoint_contract.rs` | Socket batching, cancellation-aware receive, shutdown, and endpoint metrics must stay Cx/region compatible. |
| Native QUIC packet protection and TLS provider boundary | `ATP-A3`, `asupersync-e8hst6` | `src/net/quic_native/tls.rs` | `tests/atp_quic_packet_protection.rs`, `scripts/run_atp_quic_packet_protection_e2e.sh` | QUIC owns state transitions; crypto providers own primitive operations without becoming external QUIC stacks. |
| Native QUIC connection, transport, streams, and forensic log | `ATP-A4`, `ATP-A6`, `ATP-A7`, `ATP-A10` | `src/net/quic_native/connection.rs`, `src/net/quic_native/transport.rs`, `src/net/quic_native/streams.rs`, `src/net/quic_native/forensic_log.rs` | QUIC transport/stream/loss tests, qlog-style replay artifacts | ATP needs flow control, ACK/loss, migration, key update, close/drain, and replay evidence as reusable transport assets. |
| Rendezvous and endpoint observation | `ATP-F3`, `asupersync-uh6u63` | `src/net/atp/rendezvous/mod.rs`, `src/net/atp/stun/mod.rs` | NAT classifier, signed-candidate, replay, quota, and cancellation tests | Peers behind routers need privacy-preserving candidate exchange before path racing can be honest. |
| Optional Tailscale path candidates | `ATP-F6`, `asupersync-92vqmc` | `src/net/atp/path/mod.rs`, `tailscale-path-provider` Cargo feature | fake-provider unit tests for prefer, disabled, provider failure, metrics, and proof summary | Tailnet reachability is an optional candidate source; it must not add a hard Tailscale dependency or block direct/relay/mailbox paths. |

### Planned module families and write boundaries

The design intentionally reserves the following module families even when their
full implementations are not committed yet. A bead may create one of these
modules only when it also lands unit tests, e2e or lab proof where applicable,
and a contributor-guide row.

| Planned boundary | Owner workstream | Intended modules | Required proof shape |
| --- | --- | --- | --- |
| Transfer actor and per-transfer ownership | `ATP-E1`, `asupersync-9yjgrz` | `src/atp/actor/`, `src/atp/transfer/` | state-machine tests for offer, accept, pause, cancel, resume, commit, restart, and no obligation leaks; actor e2e script with structured state-transition logs |
| ATP Transfer Brain and scheduler feedback | `ATP-E`, `ATP-E8` | `src/net/atp/quic/transfer_brain.rs`, scheduler/autotune adapters | deterministic scheduling tests for priority, hedging, backpressure, relay cost, disk pressure, repair ROI, and cancellation drain |
| ACK, loss, PTO, congestion, and anti-amplification | `ATP-A6`, `asupersync-51uf70` | `src/net/atp/loss/`, `src/net/atp/quic/recovery.rs`, `src/net/atp/quic/metrics.rs` | ACK range, RTT, PTO, persistent-congestion, anti-amplification, migration, and replay tests under deterministic network models |
| Chunking profiles | `ATP-C3`, `asupersync-9jgb8r` | `src/net/atp/chunk/` | fixed-size bulk, content-defined sync-tree, media prefix, sparse-image hole, artifact reproducibility, and rolling-stream manifest tests |
| Crash-safe disk writer and journal | `ATP-D2`, `ATP-D3`, `ATP-D5` | `src/atp/disk/`, `src/atp/journal/` | sparse/prealloc/fsync/atomic-rename tests plus crash injection around write, journal append, bitmap update, repair decode, and final rename |
| RaptorQ repair coordinator | `ATP-G2`, `asupersync-3ui2zb` | `src/atp/repair/` with existing `src/raptorq/` primitives | manifest-bound repair group tests, symbol authentication, K/K-prime boundaries, malicious peer rejection, decode proof entries, lossy/resume/swarm e2e |
| Path graph engine and relay adapters | `ATP-F`, `ATP-F5`, `ATP-F10` | `src/atp/path/`, `src/atp/relay/`, Tailscale candidate provider adapters, MASQUE-compatible relay adapter | direct/relay/Tailscale/mailbox path racing, loser drain, signed candidates, relay opacity, TCP/TLS 443 fallback, and path doctor logs |
| SDK facade | `ATP-B4`, `asupersync-sbk7th` | `src/net/atp/sdk/` or stable `src/atp/sdk/` facade | Cx-first send/receive/sync/stream tests, idempotent resume/cancel, backpressure, diagnostics, and docs examples |
| Daemon and identity | `ATP-H1`, `ATP-H2`, `ATP-H5`, `ATP-H6`, `ATP-H7` | `src/atp/daemon/`, `src/atp/identity/`, key store and peer directory modules | AppSpec lifecycle tests, stable PeerId/TransferId derivation, key rotation/revocation, receive preflight, quota, consent, and quarantine e2e |
| CLI and first-run UX | `ATP-I5`, `ATP-I6`, `ATP-B5` | `src/bin/asupersync.rs` ATP commands and packaging scripts | deterministic CLI output tests, share/pairing flows, service integration smoke, shell completions, and upgrade diagnostics |
| Offline mailbox | `ATP-J4` and mailbox follow-up beads | `src/atp/mailbox/` and relay storage policy modules | encrypted store-and-forward tests, tamper evidence, quota/retention, abuse resistance, privacy redaction, sender-offline and receiver-offline e2e |
| Swarm and cache-assisted transfer | swarm follow-up beads under ATP-H/ATP-G | `src/atp/swarm/`, cache and piece-picker modules | multi-source verified transfer tests, rarest/usefulness picking, malicious cache rejection, peer churn, relay cache, and repair-symbol usefulness logs |
| Lab, replay, benchmark cartel, and crashpacks | `ATP-L`, `ATP-N` | `src/atp/lab/`, replay/minimizer/crashpack modules, bench adapters | deterministic NAT/network/disk/adversary models, transfer oracle tests, replay minimization, scp/rsync/rclone/curl/http3 comparator scripts |
| Governance and dependency gates | `ATP-M`, `ATP-N`, `asupersync-jaghjr`, `asupersync-xvaftm` | docs, artifacts, dependency audit tests, no-external-QUIC gates | module-map contract, no-Tokio/default-graph checks, proof-lane manifest updates, and per-module Definition of Done enforcement |

### Boundary rules for new ATP modules

- New ATP modules must be introduced under the owner workstream named above or
  a bead that explicitly updates this contract first.
- Public effectful APIs must take `&Cx` first and preserve capability flow.
- Long-lived workers belong under supervised daemon/AppSpec topology; one
  transfer's mutable state belongs to one transfer actor or equivalent owned
  region.
- Protocol parsing, manifest validation, verification, repair, disk commit,
  and final exposure must remain separate stages with redaction-safe evidence.
- Native QUIC modules may use TLS primitives through the provider boundary, but
  may not import an external QUIC endpoint stack.
- Planned module names are reservations for architecture coherence, not claims
  that the implementation is complete.

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

The Tailscale candidate provider is feature-discoverable through the
dependency-free `tailscale-path-provider` Cargo feature. `--prefer tailscale`
selects the preference that ranks Tailscale candidates ahead of other non-relay
paths when provider output exists. `--no-tailscale` maps to the disabled policy
and ignores provider output. Both modes still use the same candidate metrics and
proof-summary surface as other paths; provider failure records a non-fatal
caveat instead of suppressing direct, NAT, relay, or mailbox candidates.

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
- Packet protection, header protection, key lifecycle, key update, and TLS
  provider boundary: `src/net/quic_native/tls.rs`.

The endpoint contract is guarded by
`tests/atp_native_quic_endpoint_contract.rs` and
`artifacts/atp_native_quic_endpoint_contract_v1.json`.

The packet-protection contract is guarded by
`tests/atp_quic_packet_protection.rs` and
`scripts/run_atp_quic_packet_protection_e2e.sh`.

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

`src/atp/platform/mod.rs` reports host capabilities that ATP disk and packaging
code must account for: sparse files, preallocation, atomic rename, fsync
durability, path length, case sensitivity, symlink behavior, socket buffers,
IPv6, router assist, and service manager support.

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
rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_atp_quic_protection cargo test -p asupersync --test atp_quic_packet_protection -- --nocapture
```

```bash
rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_atp_module_map cargo test -p asupersync --test atp_module_map_contract -- --nocapture
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
