# PLAN_TO_PORT_QUIC_HTTP3_TO_RUST

## Objective

Build a first-class, memory-safe, native QUIC + HTTP/3 stack for Asupersync that:

- uses Asupersync runtime primitives (`Cx`, regions, cancellation protocol),
- preserves deterministic lab-runtime testability where feasible,
- has **no Tokio runtime dependency** in the implementation path.

## Non-Negotiables

- No line-by-line translation from any external codebase.
- No Tokio executor coupling in runtime-critical paths.
- Cancellation remains explicit and protocol-safe (request -> drain -> finalize).
- Memory safety by default (`#![deny(unsafe_code)]` remains effective in the new surface).

## Explicit Exclusions (This Plan)

- No temporary Tokio adapter shim in core transport code.
- No ambient global runtime handles.
- No backward-compatibility wrapper layer for prior QUIC experiments.

## Architecture Fit

### Required integration points

1. `Cx` checkpoint integration at all externally visible async boundaries.
2. Region-owned connection and stream lifecycles (no orphan drivers).
3. Obligation-aware send/ack/drain semantics for in-flight frames.
4. Lab-runtime determinism hooks for timers, packet scheduling, and fault injection.

### Layering target

1. `net::quic_core` (pure protocol data model + codecs + invariants)
2. `net::quic_transport` (connection state machine, loss recovery, congestion control)
3. `net::quic_tls` (TLS 1.3 handshake integration for QUIC crypto levels)
4. `http::h3_native` (HTTP/3 mapping on QUIC streams)

## Phase Plan

## Phase 0: Spec Extraction

- Extract normative behavior from RFC 9000/9001/9002/9114 into executable notes.
- Define a strict conformance matrix (must/should/may) for each transport feature.
- Produce fixture generation strategy for parser/encoder and state-machine checks.

## Phase 1: QUIC Transport Core

- Implement native, dependency-light protocol primitives:
  - QUIC varint codec
  - connection ID representation
  - packet number and packet header codecs (initial + short headers)
  - transport parameter TLV codec with unknown-parameter preservation
- Add exhaustive boundary tests for encode/decode round-trips.

## Phase 2: Handshake & Crypto Plumbing

- Integrate TLS 1.3 handshake states for Initial/Handshake/1-RTT key transitions.
- Add key phase rotation and packet protection interfaces.

## Phase 3: Connection State Machine

- Implement endpoint/connection lifecycle with explicit close semantics.
- Implement loss detection, PTO, ACK handling, packet number spaces.

## Phase 4: Streams + Flow Control

- Stream scheduler, receive reassembly, flow control windows, RESET/STOP_SENDING.
- Region-safe shutdown and cancellation semantics for stream tasks.

## Phase 5: HTTP/3 Native Layer

- Control stream and SETTINGS.
- Request/response stream mapping and body framing.
- QPACK strategy (initially static/minimal dynamic table if needed).

## Implementation Status (Native Runtime Path)

- ✅ Phase 0: Spec extraction artifacts are in-repo (`PLAN_TO_PORT_QUIC_HTTP3_TO_RUST.md`, `EXISTING_QUIC_HTTP3_STRUCTURE.md`).
- ✅ Phase 1: `net::quic_core` includes varints, packet headers, connection IDs, and transport-parameter preservation with boundary tests.
- ✅ Phase 2: `net::quic_native::tls` includes crypto-level progression, handshake confirmation, and key-phase rotation.
- ✅ Phase 3: `net::quic_native::transport` includes packet accounting, ACK/range handling, packet/time-threshold loss detection, PTO/backoff, and congestion-window state.
- ✅ Phase 4: `net::quic_native::streams` + `net::quic_native::connection` include stream lifecycle, out-of-order reassembly, connection/stream flow-control accounting, STOP_SENDING/RESET/FIN handling, and round-robin writable-stream selection.
- ✅ Phase 5: `http::h3_native` includes frame/settings codecs, request/response mapping, GOAWAY gating, uni-stream typing (control/push/QPACK), static-only QPACK policy enforcement, and static-table planning helpers.

## Remaining Frontier (Non-Blocking for Native Design Completion)

- Interop capture corpus against external stacks (black-box fixtures).
- Lab-runtime scenario harnesses that model network reordering/fault injection end-to-end.
- Full wire-level QPACK encoder/decoder (current runtime uses static-only planning + policy checks).

## Verification Strategy

1. Unit/property tests for codecs and state-machine invariants.
2. Deterministic lab-runtime scenario tests for cancellation and reordering.
3. Interop captures against external QUIC/H3 implementations as black-box references.
4. Performance/latency benchmarks for handshake, stream throughput, and tail latency.

## Success Criteria

- Native QUIC/H3 path compiles without Tokio runtime dependency.
- Phase 1 codecs are round-trip stable and reject malformed input.
- Follow-up phases can be implemented without redesigning Phase 1 interfaces.
