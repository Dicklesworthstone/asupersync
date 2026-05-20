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

| Workstream | Primary files | Proof surface |
| --- | --- | --- |
| ATP object graph | `src/atp/object.rs` | inline unit tests, rch all-target check |
| ATP manifest and commits | `src/atp/manifest.rs` | inline unit tests, graph-commit validation tests |
| ATP path graph | `src/atp/path.rs` | inline unit tests |
| ATP verification boundary | `src/atp/object.rs`, `src/atp/manifest.rs` | object graph, manifest, and commit validation tests |
| ATP binary frames | `src/net/atp/protocol/frames.rs` | codec round-trip tests |
| ATP frame codec | `src/net/atp/protocol/codec.rs` | partial-frame and size-limit tests |
| ATP varints | `src/net/atp/protocol/varint.rs` | canonical length and partial decode tests |
| Native QUIC frames | `src/net/atp/protocol/quic_frames.rs` | frame round-trip tests |
| Packet assembly | `src/net/atp/protocol/packet_assembly.rs` | budget and packet-space tests |
| Transport parameters | `src/net/atp/protocol/transport_params.rs` | validation and duplicate tests |
| Session negotiation | `src/net/atp/protocol/session.rs` | `tests/atp_session_negotiation.rs` |
| Platform policy | `src/fs/platform.rs`, `src/bin/asupersync.rs` | `atp doctor --platform` tests |
| Native UDP endpoint | `src/net/quic_native/endpoint.rs` | `tests/atp_native_quic_endpoint_contract.rs` |
| Pressure feedback | `src/runtime/scheduler/autotuner.rs` | inline autotuner tests |

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

Swarm work must use `SessionContextKind::Swarm` and `AtpFeature::Swarm`. Swarm
workers may carry shards or repair symbols, but validation remains the exposure
boundary.

Replay work should preserve:

- Session transcript hash from `src/net/atp/protocol/transcript.rs`.
- Session proof artifact from `src/net/atp/protocol/session.rs`.
- Path trace id and candidate outcome from `src/atp/path.rs`.
- Verification evidence from object graph, manifest, commit, and future
  sparse-writer validation stages.
- Platform capability report from `src/fs/platform.rs`.

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

For session-negotiation E2E, keep Cargo execution under `rch`:

```bash
rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_atp_session_e2e bash scripts/run_atp_session_negotiation_e2e.sh
```

If `rch` refuses remote workers and falls back locally, preserve that exact
status in the handoff. Do not run bare Cargo outside `rch`.

## Documentation Updates

Update `docs/atp_architecture.md` when a workstream adds or removes a real code
surface. Update this contributor guide when a proof lane, file owner, CLI path,
or tracker-to-code mapping changes. Do not copy stale roadmap claims from Beads
without checking the code path first.
