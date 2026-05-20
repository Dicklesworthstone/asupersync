# ATP Contributor Guide

ATP work starts from Beads and lands on `main`. This guide maps tracker items to
the live code surface so implementation, docs, and proof work stay aligned.

## Startup Checklist

1. Read `AGENTS.md`, `README.md`, this guide, and `docs/atp_architecture.md`.
2. Inspect the bead with `br show <id> --json`.
3. Claim work with `br update <id> --status in_progress --json`.
4. Reserve exact files through MCP Agent Mail before editing.
5. Use `rch exec -- env CARGO_TARGET_DIR=... cargo ...` for every Cargo command.
6. Commit with the bead id or `br-build-repair` in the subject.

Do not create branches or worktrees. Do not delete files. Do not add external
QUIC crates or Tokio-runtime dependencies to core ATP.

## Tracker to Code Map

The authoritative module ownership contract lives in
`docs/atp_architecture.md#atp-m4-implementation-ownership-contract` and is
guarded by `tests/atp_module_map_contract.rs`. This guide is the working
checklist: before editing an ATP surface, identify the owner workstream, reserve
the listed files, and run or extend the listed proof lane.

| Workstream | Owner beads | Primary files | Proof surface |
| --- | --- | --- | --- |
| ATP root and public model surface | `asupersync-l21xmv`, `asupersync-w9xymh` | `src/atp/mod.rs`, `src/net/atp/mod.rs` | `tests/atp_module_map_contract.rs` |
| ATP object graph | `ATP-C`, `asupersync-bg83ig` | `src/atp/object.rs` | inline unit tests, rch all-target check |
| ATP manifest, Merkle roots, transforms, and graph commits | `ATP-C`, `asupersync-1iuqyc`, `asupersync-w5j10z` | `src/atp/manifest.rs` | inline unit tests, graph-commit validation tests, `scripts/run_atp_manifest_e2e.sh` |
| ATP verification boundary | `ATP-D4`, `asupersync-fw1eg1` | `src/atp/verifier.rs` plus object/manifest validators | verifier tests, finalizer/cancellation tests, future crash/finalizer lab scripts |
| ATP path candidate model | `ATP-F`, `asupersync-6cokae` | `src/atp/path.rs`, `src/net/atp/path/mod.rs` | inline unit tests, future NAT/path lab scripts |
| ATP binary frames, codec, varints | `ATP-B`, `asupersync-1ar9mg` | `src/net/atp/protocol/frames.rs`, `src/net/atp/protocol/codec.rs`, `src/net/atp/protocol/varint.rs` | codec round-trip, partial-frame, canonical-varint, size-limit, malformed-input tests |
| ATP transcript, outcomes, and session negotiation | `ATP-B`, `asupersync-wvjjnz` | `src/net/atp/protocol/transcript.rs`, `src/net/atp/protocol/outcome.rs`, `src/net/atp/protocol/session.rs` | `tests/atp_session_negotiation.rs`, `scripts/run_atp_session_negotiation_e2e.sh` |
| Native QUIC frames, packet assembly, transport parameters | `ATP-A`, `asupersync-zquziu` | `src/net/atp/protocol/quic_frames.rs`, `src/net/atp/protocol/packet_assembly.rs`, `src/net/atp/protocol/transport_params.rs` | frame, packet-budget, packet-number-space, duplicate-parameter, and malformed-peer tests |
| Native UDP endpoint | `ATP-A1`, `ATP-A11`, `asupersync-crscmn` | `src/net/quic_native/endpoint.rs` | `tests/atp_native_quic_endpoint_contract.rs` |
| Native QUIC packet protection and TLS provider boundary | `ATP-A3`, `asupersync-e8hst6` | `src/net/quic_native/tls.rs` | `tests/atp_quic_packet_protection.rs`, `scripts/run_atp_quic_packet_protection_e2e.sh` |
| Native QUIC connection, transport, streams, and forensic log | `ATP-A4`, `ATP-A6`, `ATP-A7`, `ATP-A10` | `src/net/quic_native/connection.rs`, `src/net/quic_native/transport.rs`, `src/net/quic_native/streams.rs`, `src/net/quic_native/forensic_log.rs` | QUIC transport/stream/loss tests, replay/qlog-style artifact checks |
| Rendezvous and endpoint observation | `ATP-F3`, `asupersync-uh6u63` | `src/net/atp/rendezvous/mod.rs`, `src/net/atp/stun/mod.rs` | NAT classifier, signed-candidate, quota, replay, and cancellation tests |
| Optional Tailscale path candidates | `ATP-F6`, `asupersync-92vqmc` | `src/net/atp/path/mod.rs`, `tailscale-path-provider` Cargo feature | fake-provider unit tests for prefer, disabled, provider failure, metrics, and proof summary |
| Platform policy and doctor | `ATP-D1`, `asupersync-1tgbxe` | `src/atp/platform/mod.rs`, `src/atp/doctor/mod.rs`, `src/bin/asupersync.rs` | `atp doctor --platform` tests |
| Transfer actor and ownership topology | `ATP-E1`, `asupersync-9yjgrz` | planned `src/atp/actor/`, `src/atp/transfer/` | actor state-machine tests and `scripts/run_atp_transfer_actor_e2e.sh` once committed |
| Chunking profiles | `ATP-C3`, `asupersync-9jgb8r` | planned `src/net/atp/chunk/` | bulk, sync-tree, media, sparse-image, artifact, and stream profile tests |
| ACK/loss/PTO/congestion feedback | `ATP-A6`, `asupersync-51uf70` | planned `src/net/atp/loss/`, `src/net/atp/quic/` | ACK/loss/PTO/congestion tests and deterministic network replay |
| RaptorQ repair coordinator | `ATP-G2`, `asupersync-3ui2zb` | planned `src/atp/repair/` plus existing `src/raptorq/` primitives | symbol-auth, K/K-prime, malicious-peer, decode-proof, resume/relay/swarm e2e |
| Crash-safe disk and journal | `ATP-D2`, `ATP-D3`, `ATP-D5` | planned `src/atp/disk/`, `src/atp/journal/` | sparse/prealloc/fsync/atomic-commit tests and crash/fault matrix |
| SDK facade | `ATP-B4`, `asupersync-sbk7th` | planned `src/net/atp/sdk/` or stable `src/atp/sdk/` facade | Cx-first send/receive/sync/stream tests, diagnostics, cancellation and resume e2e |
| Daemon, identity, peer directory, receive preflight | `ATP-H1`, `ATP-H2`, `ATP-H5`, `ATP-H6`, `ATP-H7` | planned `src/atp/daemon/`, `src/atp/identity/` | AppSpec lifecycle, PeerId/TransferId, key-store, quota, consent, quarantine tests |
| CLI, share/pairing, first-run packaging | `ATP-B5`, `ATP-I5`, `ATP-I6` | `src/bin/asupersync.rs`, packaging scripts | deterministic CLI output, share-code, service-integration, shell-completion, upgrade smoke tests |
| Mailbox, relay, Tailscale candidate, path doctor | `ATP-F5`, `ATP-F6`, `ATP-F10`, `ATP-J4` | planned relay/mailbox/path-provider modules plus optional Tailscale path provider | encrypted store-and-forward, relay opacity, TCP/TLS 443 fallback, Tailscale candidate selection, path-doctor e2e |
| Lab, replay, crashpacks, benchmark cartel | `ATP-L`, `ATP-N` | planned `src/atp/lab/`, replay/minimizer modules, benchmark adapters | deterministic NAT/network/disk/adversary models, transfer oracles, replay minimization, comparator scripts |
| Governance, dependency gates, Definition of Done | `ATP-M`, `ATP-N`, `asupersync-jaghjr`, `asupersync-xvaftm` | docs, artifacts, dependency-audit tests | module-map contract, no-external-QUIC checks, proof-lane manifest, unit/e2e/logging DoD |

If your intended file is not represented here, do not improvise a new subtree
silently. Update the ATP-M4 contract first, name the owning bead, explain the
Asupersync invariant it serves, and add a test or e2e proof command for that
boundary.

## Design Rules

- Model first. Add deterministic model types and fail-closed validation before
  connecting a CLI, daemon, relay, mailbox, or SDK path.
- Keep object movement graph-shaped. File and directory UX should compile down
  to `ObjectGraph`, `Manifest`, `MerkleRoot`, and validation stages.
- Use native Asupersync transport. External QUIC stacks are not allowed in core
  ATP; if an adapter is ever needed, keep it outside the runtime guarantee.
- Keep replay evidence redaction-safe. Peer ids, path ids, transcript hashes,
  and verification summaries can be logged; payload bytes and secrets cannot.
- Treat capability grants as obligations. A grant, lease, sparse writer
  reservation, or relay permission must have an explicit commit, abort, expiry,
  or rejection path.
- Prefer deterministic maps and ordered sets for canonical bytes and proof
  artifacts. Avoid iteration-order-dependent output.
- Preserve cancellation semantics. An interrupted transfer must not expose
  partially verified output.
- Public effectful APIs must take `&Cx` first. If a high-level convenience API
  exists later, keep the `&Cx` boundary beneath it and document the policy
  conversion point.
- Planned module names are reservations for architecture coherence, not proof
  that the implementation has landed. Do not claim a planned module as
  committed until source, unit tests, e2e or lab proof, and tracker closeout all
  exist.

## CLI, Daemon, SDK, Relay, Mailbox, Swarm, Replay

CLI work should start in `src/bin/asupersync.rs`. The currently wired ATP CLI
surface is:

```bash
asupersync atp doctor --platform
```

Daemon work should route through session negotiation, path selection, validation
stages, and disk policy. A daemon receive path should look like:

```text
ClientHello -> SessionPolicy -> CapabilityGrant -> AtpFrameCodec
-> Manifest -> graph/commit validation -> quarantine/write -> finalizer proof -> expose
```

SDK work should expose high-level send/receive builders while keeping the same
internal objects:

```text
files/directories -> ObjectGraph -> Manifest -> path race -> negotiated session
-> frame stream -> verification evidence
```

Relay work must use `SessionContextKind::Relay` and `AtpFeature::Relay`. A relay
may see timing and metadata, but payload bytes remain end-to-end encrypted and
verification remains peer-side.

Mailbox work must use `SessionContextKind::Mailbox` and
`AtpFeature::Mailbox`. Store-and-forward paths use the same manifest, proof, and
validation model as direct sessions.

Swarm work must use `SessionContextKind::Swarm` and `AtpFeature::Swarm`.
Verification remains the exposure boundary even when swarm workers carry shards
or repair symbols.

Replay work should preserve:

- Session transcript hash from `src/net/atp/protocol/transcript.rs`.
- Session proof artifact from `src/net/atp/protocol/session.rs`.
- Path trace id and candidate outcome from `src/atp/path.rs`.
- Verification evidence from object graph, manifest, commit, and future
  sparse-writer validation stages.
- Platform capability report from `src/atp/platform/mod.rs`.

## Proof Commands

Use focused commands while editing, then run the broad gate before committing
substantive ATP changes.

```bash
rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_atp_check cargo check --all-targets
```

```bash
rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_atp_fmt cargo fmt --check
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

For ATP E2E scripts, keep Cargo execution under `rch`. The manifest script
contains its own `rch exec` calls; the session script is run through an `rch`
wrapper, and packet-protection e2e uses the same pattern:

```bash
bash scripts/run_atp_manifest_e2e.sh
```

```bash
rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_atp_session_e2e bash scripts/run_atp_session_negotiation_e2e.sh
```

```bash
rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_atp_quic_protection_e2e bash scripts/run_atp_quic_packet_protection_e2e.sh
```

If `rch` refuses remote workers and falls back locally, preserve that exact
status in the handoff. Do not run bare Cargo outside `rch`.

## Documentation Updates

Update `docs/atp_architecture.md` when a workstream adds or removes a real code
surface. Update this contributor guide when a proof lane, file owner, CLI path,
or tracker-to-code mapping changes. Do not copy stale roadmap claims from Beads
without checking the code path first.
