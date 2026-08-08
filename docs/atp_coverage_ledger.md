# ATP Coverage Ledger

This ledger maps every ATP module to required unit/property/metamorphic tests and tracks implementation status. Updates required when modules are added/removed/renamed.

## Status Legend

- **TESTED**: Full test suite implemented and passing
- **PARTIAL**: Some tests implemented, gaps remain  
- **PLANNED**: Module exists, tests not yet implemented
- **MISSING**: Module planned but not yet implemented

## Core ATP Modules

### Data Model Layer

| Module | Status | Unit Tests | Property Tests | Metamorphic Tests | Edge Cases | Error Cases | Cancellation | Leak Check | Notes |
|--------|--------|------------|----------------|-------------------|------------|-------------|--------------|------------|-------|
| `src/atp/object.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Object graph validation, ContentId/ObjectId generation |
| `src/atp/manifest.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Merkle root computation, chunking policy, graph commits |
| `src/atp/path.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Path candidate racing, security properties, budgets |

### Verification Layer

| Module | Status | Unit Tests | Property Tests | Metamorphic Tests | Edge Cases | Error Cases | Cancellation | Leak Check | Notes |
|--------|--------|------------|----------------|-------------------|------------|-------------|--------------|------------|-------|
| `src/atp/verifier.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Proof validation, chunk authentication |
| `src/atp/proof/bundle.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Proof bundling, evidence chains |
| `src/atp/proof/mod.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Proof validation framework |

### Storage Layer  

| Module | Status | Unit Tests | Property Tests | Metamorphic Tests | Edge Cases | Error Cases | Cancellation | Leak Check | Notes |
|--------|--------|------------|----------------|-------------------|------------|-------------|--------------|------------|-------|
| `src/atp/writer.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Atomic writes, crash safety |
| `src/atp/stream_object.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Streaming object handling |

### Transfer Layer

| Module | Status | Unit Tests | Property Tests | Metamorphic Tests | Edge Cases | Error Cases | Cancellation | Leak Check | Notes |
|--------|--------|------------|----------------|-------------------|------------|-------------|--------------|------------|-------|
| `src/atp/actor/mod.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Transfer actor lifecycle |
| `src/atp/transfer/mod.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Transfer coordination |
| `src/atp/repair_receiver.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | RaptorQ repair handling |

### Platform Integration

| Module | Status | Unit Tests | Property Tests | Metamorphic Tests | Edge Cases | Error Cases | Cancellation | Leak Check | Notes |
|--------|--------|------------|----------------|-------------------|------------|-------------|--------------|------------|-------|
| `src/atp/platform/mod.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Platform capability detection |
| `src/atp/doctor/mod.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Diagnostic output, platform probes |
| `src/atp/sdk.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | SDK facade, public API |

## Network Protocol Modules

### Frame Protocol

| Module | Status | Unit Tests | Property Tests | Metamorphic Tests | Edge Cases | Error Cases | Cancellation | Leak Check | Notes |
|--------|--------|------------|----------------|-------------------|------------|-------------|--------------|------------|-------|
| `src/net/atp/protocol.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Protocol frame definitions |

### QUIC Native Implementation

| Module | Status | Unit Tests | Property Tests | Metamorphic Tests | Edge Cases | Error Cases | Cancellation | Leak Check | Notes |
|--------|--------|------------|----------------|-------------------|------------|-------------|--------------|------------|-------|
| `src/net/atp/h3/mod.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | HTTP/3 integration |
| `src/net/atp/h3/session.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | HTTP/3 session management |
| `src/net/atp/h3/stream.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | HTTP/3 stream handling |
| `src/net/atp/h3/codec.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | HTTP/3 frame encoding/decoding |
| `src/net/atp/h3/adapter.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | HTTP/3 adapter layer |

### Network Services

| Module | Status | Unit Tests | Property Tests | Metamorphic Tests | Edge Cases | Error Cases | Cancellation | Leak Check | Notes |
|--------|--------|------------|----------------|-------------------|------------|-------------|--------------|------------|-------|
| `src/net/atp/path/mod.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Path establishment and racing |
| `src/net/atp/rendezvous/mod.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Peer discovery and rendezvous |
| `src/net/atp/stun/mod.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | STUN protocol implementation |

### Loss and Recovery

| Module | Status | Unit Tests | Property Tests | Metamorphic Tests | Edge Cases | Error Cases | Cancellation | Leak Check | Notes |
|--------|--------|------------|----------------|-------------------|------------|-------------|--------------|------------|-------|
| `src/net/atp/loss/mod.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Loss detection framework |
| `src/net/atp/loss/detector.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Packet loss detection |
| `src/net/atp/loss/persistent_congestion.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Persistent congestion handling |

### Chunking and Content

| Module | Status | Unit Tests | Property Tests | Metamorphic Tests | Edge Cases | Error Cases | Cancellation | Leak Check | Notes |
|--------|--------|------------|----------------|-------------------|------------|-------------|--------------|------------|-------|
| `src/net/atp/chunk/mod.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Chunking strategy framework |
| `src/net/atp/chunk/profiles.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Chunking profile definitions |
| `src/net/atp/chunk/media.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Media-aware chunking |
| `src/net/atp/chunk/artifact.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Artifact reproducible chunking |
| `src/net/atp/chunk/dedupe.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Content deduplication |
| `src/net/atp/chunk/stream.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Streaming chunk processing |

### SDK Interface  

| Module | Status | Unit Tests | Property Tests | Metamorphic Tests | Edge Cases | Error Cases | Cancellation | Leak Check | Notes |
|--------|--------|------------|----------------|-------------------|------------|-------------|--------------|------------|-------|
| `src/net/atp/sdk/mod.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | SDK interface framework |
| `src/net/atp/sdk/session.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Session management API |
| `src/net/atp/sdk/transfer.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Transfer management API |
| `src/net/atp/sdk/stream.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Stream handling API |
| `src/net/atp/sdk/object.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Object manipulation API |
| `src/net/atp/sdk/diagnostics.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Diagnostic and monitoring API |

### Discovered ATP Modules

| Module | Status | Unit Tests | Property Tests | Metamorphic Tests | Edge Cases | Error Cases | Cancellation | Leak Check | Notes |
|--------|--------|------------|----------------|-------------------|------------|-------------|--------------|------------|-------|
| `src/atp/adapter.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/adaptive_raptorq.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/autotune.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/cache_seeding_integration_tests.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/cas.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/daemon_control.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/delta.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/delta_subchunk.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/early_usability_tests.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/mod.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/planner.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/repair_coordinator.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/repair_coordinator_integration_test.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/repair_roi.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/repair_scheduler.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/safety.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/slepian_wolf.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/telemetry.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/timing_security.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/transfer_actor.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/transfer_brain.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/transfer_integration_tests.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/upgrade_integration.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/cli/atp_user_journey.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/cli/atp_workflows.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/bonding.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/bonding/assignment.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/bonding/descriptor.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/bonding/esi.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/bonding/handshake.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/bonding/mod.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/bonding/receiver.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/bonding/transport_select.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/channel_bonding.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/chunk/bulk_file.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/chunk/cas.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/chunk/change_detect.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/chunk/delta_stream.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/chunk/reassembly.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/chunk/reconcile.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/chunk/sparse_image.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/chunk/sync_tree.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/compress/algorithms.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/compress/mod.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/compress/policy.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/compress/validation.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/crypto/mod.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/crypto/policy.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/datagram/beacons.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/datagram/congestion.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/datagram/frame.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/datagram/mod.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/datagram/probes.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/datagram/tests.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/datagram/transport.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/discovery/mod.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/handshake/key_schedule.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/handshake/mod.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/handshake/retry.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/handshake/state_machine.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/handshake/traces.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/handshake/transport_params.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/handshake/version_negotiation.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/mod.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/object/mod.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/ops/mod.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/protocol/byzantine_defense.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/protocol/codec.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/protocol/frames.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/protocol/mod.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/protocol/outcome.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/protocol/packet_assembly.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/protocol/quic_frames.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/protocol/resource_manager.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/protocol/session.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/protocol/transcript.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/protocol/transport_params.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/protocol/varint.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/quic/connection/mod.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/quic/metrics.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/quic/mod.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/quic/packet_protection.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/quic/recovery.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/quic/transfer_brain.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/relay/mod.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/sink/mod.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/sink/writer.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/streams/flow_control.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/streams/mod.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/streams/reassembly.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/streams/scheduler.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/streams/stream.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/test_utils.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/transport_common/compression.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/transport_common/filter.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/transport_common/metadata.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/transport_common/mirror.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/transport_common/mod.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/transport_common/multi_object.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/transport_common/multisource.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/transport_common/progress.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/transport_common/streaming.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/transport_quic/mod.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/transport_quic/native_link.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/transport_quic/symbol_datagram.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/transport_quic/symbol_envelope.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/transport_rq/adaptive.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/transport_rq/bonded.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/transport_rq/mod.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/transport_tcp/mod.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/udp/mod.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/adapter/integration_tests.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/adapter/masque.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/adapter/tcptls.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/adapter/webtransport.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/atpd/mod.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/atpd/state.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/benchmark/adapters.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/benchmark/mod.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/benchmark/profiles.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/benchmark/reports.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/benchmark/suite.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/cache/mod.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/cache/policy.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/cache/storage.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/cache/trust.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/diagnostics/mod.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/directory/mod.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/governance/config.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/governance/e2e_tests.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/governance/mod.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/grant/manager.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/grant/mod.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/grant/pairing.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/grant/storage.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/identity/mod.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/inbox/mod.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/journal/append_journal.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/journal/basic_tests.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/journal/chunk_bitmap.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/journal/commit_policy.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/journal/delta_cas.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/journal/mod.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/journal/platform_caps.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/journal/range_tracker.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/journal/recovery.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/journal/sparse_writer.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/journal/temp_management.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/journal/tests.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/lab/mod.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/logging/contract_validation_tests.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/logging/failure_bundle.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/logging/mod.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/logging/redaction.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/logging/replay_artifacts.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/logging/schema.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/logging/tests.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/mailbox/client.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/mailbox/encryption.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/mailbox/mod.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/mailbox/quota.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/mailbox/relay.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/mailbox/storage.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/policy/enforcement.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/policy/mod.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/policy/scope.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/policy/verification.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/profiles/mod.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/proof/replay.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/proof/serde_types.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/quota/mod.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/sdk/client.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/sdk/mod.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/seeding/mod.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/supervision/mod.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/swarm/coordinator.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/swarm/mod.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/swarm/peer_selection.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/swarm/piece_tracker.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/swarm/quality.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/swarm/strategy.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/sync/mod.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/verify/mod.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/dedupe.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/atp/reconcile.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/bonding/derive.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/sdk/bonded.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/transport_common/delta.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |
| `src/net/atp/transport_rq/transport_rq_tests.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | Discovered ATP module; detailed coverage pending |

## CLI Integration

| Module | Status | Unit Tests | Property Tests | Metamorphic Tests | Edge Cases | Error Cases | Cancellation | Leak Check | Notes |
|--------|--------|------------|----------------|-------------------|------------|-------------|--------------|------------|-------|
| `src/cli/atp_command_tree.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ATP CLI command structure |
| `src/cli/atp_config.rs` | PLANNED | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ATP configuration management |

## Test Requirements Summary

### Required Test Types by Module Type

**Protocol Codecs**: Round-trip properties, malformed input rejection, size limits
**Data Models**: Graph validation, integrity checks, hash determinism  
**Network Transport**: Flow control, connection lifecycle, graceful shutdown
**Verification**: Proof validation, signature verification, tamper detection
**State Machines**: Valid transitions, timeout handling, cleanup on termination
**Storage/Journal**: ACID properties, crash consistency, resource cleanup

### Coverage Targets

- **Unit Tests**: 95%+ line coverage, 100% public API coverage
- **Property Tests**: 10,000+ generated inputs per property
- **Integration Tests**: All major workflows and state transitions
- **Error Handling**: 100% error type coverage
- **Cancellation**: All async operations tested with arbitrary cancellation
- **Resource Leaks**: Zero tolerance for leaked handles/connections/memory

### Compliance Tracking

Total Modules: 227
- TESTED: 0 (0%)
- PARTIAL: 0 (0%) 
- PLANNED: 227 (100%)
- MISSING: 0 (0%)

**Critical Path Modules** (must be TESTED before any release):
1. `src/atp/object.rs` - Core data model
2. `src/atp/manifest.rs` - Transfer integrity
3. `src/atp/verifier.rs` - Security boundary
4. `src/atp/protocol.rs` - Protocol correctness
5. `src/atp/sdk.rs` - Public API surface

## Update Procedures

1. **Module Addition**: Add new row to appropriate section, set status to PLANNED
2. **Test Implementation**: Update checkmarks as tests are added
3. **Status Changes**: Update status when coverage thresholds are met
4. **Coverage Reports**: Run `scripts/atp_coverage_report.sh` to verify accuracy
5. **Release Gates**: All critical path modules must show TESTED status

## Integration with CI/CD

- **Pre-commit Hook**: Verify ledger is up-to-date with module changes
- **CI Pipeline**: Generate coverage reports and update ledger automatically
- **Release Blocker**: Any PLANNED status on critical path modules blocks release
- **Performance Tracking**: Benchmark results linked from Notes column
- **Documentation**: Test documentation linked from Notes column
