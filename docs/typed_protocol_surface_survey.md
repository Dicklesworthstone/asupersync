# Typed Protocol Surface Survey

Bead: `asupersync-typed-protocol-surfaces-cgulql.2`

Scope: select the first two typestate-hardening implementation surfaces beyond
the database transaction work already owned by the SERVER D5 lane. This survey is
source-free; implementation slices should claim the exact source paths before
touching them.

## Evidence Method

- Source scan for explicit runtime state machines, runtime rejection paths, and
  user-facing methods where Rust types could prevent invalid call order.
- Test scan for illegal-transition tests that can become the compile-fail
  matrix seed.
- `audit_index.jsonl` scan for prior bug history on candidate files.
- Existing typestate idioms checked in `src/obligation/session_types.rs`,
  `src/session.rs`, and the public integration docs.

## Ranking

| Rank | Surface | Decision | Evidence |
| --- | --- | --- | --- |
| 0 | Database transaction lifecycle | Exclude from this bead | Already owned by SERVER D5. Audit rows for `src/database/sqlite.rs` and `src/database/transaction.rs` show repeated transaction/drop/cancel-safety attention, so duplicate implementation here would collide rather than help. |
| 1 | WebSocket connection and close lifecycle | Select | Public send/recv/split API has runtime state gates for open, close-sent, close-received, and closed. Tests already assert data-after-close rejection and failed close-response retry behavior. Audit history includes WebSocket handshake injection and duplicate-header fixes plus close-code validation fixes, so this is a user-facing protocol surface with real bug history. |
| 2 | HTTP/2 stream state lifecycle | Select | `src/http/h2/stream.rs` publishes the RFC stream states and transitions as a runtime enum. It has a dense illegal-transition unit-test matrix for closed, half-closed, and idle cases. Audit history includes stream activation/concurrent-stream bugs and multiple H2 frame/connection fixes, making it a high-value compile-fail target. |
| 3 | RaptorQ sender/receiver builder | Survey only | The builder already uses typed generic parameters for transport/source shape and validates config before constructing pipelines. There is still runtime validation for missing required components, but this is a builder-completeness gap rather than a lifecycle protocol with recurring illegal-transition tests. |

## Selected Surface 1: WebSocket Connection Lifecycle

Candidate typed states:

- `Ws<Open>`: data, ping, pong, and close initiation are available.
- `Ws<CloseSent>`: only close-retry/flush and receive response are available.
- `Ws<CloseReceived>`: only echoed-close response flush and finalization are
  available.
- `Ws<Closed>`: no frame send/receive methods are available except inspection.

Runtime checks to retain under the typed layer:

- Close handshake state remains the source of truth for defense in depth.
- Frame codec validation still rejects invalid close payloads, masked/unmasked
  role violations, fragmented control frames, and oversized control frames.
- Dynamic escape hatch remains available for type-erased protocol dispatch and
  split-half ownership patterns.

Evidence anchors:

- `src/net/websocket/split.rs` exposes `is_open`, `is_closed`, `close_state`,
  and close initiation logic that branches on `CloseState`.
- `split_send_close_message_initiates_close_handshake` asserts a close send
  leaves the open state and rejects later data frames.
- `split_recv_keeps_close_received_state_if_response_send_fails` asserts failed
  close-response writes leave the handshake retryable instead of marking it
  closed.
- `audit_index.jsonl` has FIXED rows for `src/net/websocket/handshake.rs`,
  `src/net/websocket/close.rs`, and `src/net/websocket/frame.rs`, plus SOUND
  rows for the current close-handshake and frame-codec behavior.

Implementation handoff:

- Start with the split write side because it has the clearest illegal user call:
  `send(data)` after `send(close)`.
- Keep existing dynamic `WebSocket` and split types; add typed wrappers as
  zero-sized state markers over the existing machinery.
- Seed trybuild cases from the two named runtime tests above.

## Selected Surface 2: HTTP/2 Stream Lifecycle

Candidate typed states:

- `H2Stream<Idle>`: headers may open the stream; data is unavailable.
- `H2Stream<Open>`: headers/data in legal directions are available.
- `H2Stream<HalfClosedLocal>`: receive-side operations remain available; local
  data/header sends are unavailable.
- `H2Stream<HalfClosedRemote>`: send-side operations remain available; remote
  data/header receives are unavailable.
- `H2Stream<Closed>`: only inspection and pruning-related operations remain.

Runtime checks to retain under the typed layer:

- The existing `StreamState` enum and all H2 protocol errors remain as
  defense-in-depth for dynamic dispatch, peer input, and connection-level code.
- CONTINUATION/header-fragment validation remains runtime-only because it
  depends on peer bytes and accumulated header state.
- Dynamic escape hatch remains available for stream-store and connection paths
  that must process arbitrary peer frames.

Evidence anchors:

- `src/http/h2/stream.rs` documents the RFC stream-state diagram and exports the
  `StreamState` variants: idle, reserved local/remote, open, half-closed
  local/remote, and closed.
- `send_headers`, `recv_headers`, `send_data`, and `recv_data` perform runtime
  transition checks and return `STREAM_CLOSED` or `PROTOCOL_ERROR` on illegal
  state/call combinations.
- Illegal-transition tests already cover closed stream headers/data, half-closed
  send/receive misuse, and idle-stream data misuse.
- `audit_index.jsonl` has FIXED rows for `src/http/h2/stream.rs` and
  `src/http/h2/connection.rs`, including stream activation, GOAWAY boundary,
  and active stream accounting issues.

Implementation handoff:

- Start with a client-side typed stream wrapper; it narrows locally initiated
  send operations without changing peer-frame processing.
- Seed trybuild cases from the existing illegal-transition unit tests:
  `cannot_send_data_on_idle`, `cannot_send_data_on_half_closed_local`,
  `cannot_recv_data_on_half_closed_remote`, and closed-stream send/receive
  cases.
- Keep the typed wrapper opt-in until bench parity and compile-fail error text
  are committed.

## No-Claim Boundaries

This survey does not claim:

- compile-fail tests are present;
- zero-cost/bench parity is proven;
- source wrappers are implemented;
- dynamic runtime checks can be removed;
- broad workspace health or release readiness.
