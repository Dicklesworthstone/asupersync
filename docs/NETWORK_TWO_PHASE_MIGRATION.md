# Network Operations Two-Phase Effect Migration Guide

This guide tracks **asupersync-7hk6fr** and describes the native QUIC send
reservation API. Native QUIC now has a synchronous reserve/commit boundary on
both `NativeQuicConnection` and the public `QuicConnection` wrapper. The broader
ATP migration remains separate work.

## Native QUIC: reserve before handing over the payload

`reserve_stream_send(cx, stream, max_bytes)` checks cancellation, connection and
stream state, and both stream and connection flow-control windows. The caller
still owns its payload if reservation fails. A successful
`NativeQuicStreamSendPermit` exclusively borrows the connection until it is
committed, aborted, or dropped. That borrow prevents another operation from
spending the checked credit or changing the stream's state.

Reservation does not consume send credit or enqueue application bytes or FIN.
Dropping the permit or calling `abort()` has the same no-send result. A refused
reservation can enqueue the normal QUIC BLOCKED control notification so that the
peer can respond to the flow-control limit.

`commit(data, fin)` synchronously admits the actual payload and optional FIN to
the local send queue. It has no cancellation checkpoint, callback, or await
point. Cancellation requested after successful reservation does not revoke the
commit. Only the actual payload length consumes credit, so a shorter payload is
allowed and an empty FIN can be committed with zero byte credit.

An oversized payload is refused before queue or credit changes. The returned
`NativeQuicStreamSendError` owns the original `Bytes`; `into_parts()` recovers
both the reason and that exact payload for retry.

```rust
use asupersync::bytes::Bytes;
use asupersync::cx::Cx;
use asupersync::net::quic_native::{
    NativeQuicConnectionError, QuicConnection, StreamId,
};

fn enqueue(
    connection: &mut QuicConnection,
    cx: &Cx,
    stream: StreamId,
    payload: Bytes,
    fin: bool,
) -> Result<(), (NativeQuicConnectionError, Bytes)> {
    let permit = match connection.reserve_stream_send(cx, stream, payload.len()) {
        Ok(permit) => permit,
        Err(error) => return Err((error, payload)),
    };
    permit.commit(payload, fin).map_err(|error| error.into_parts())
}
```

### Backpressure and transport progress

This API reserves capacity already available in the state machine. On a
flow-control refusal, retain the payload, drive transport progress, and use
`poll_stream_send_capacity` before retrying. Do not hold a permit while waiting
for network I/O: it deliberately holds exclusive access to the connection.
Readiness can change before a subsequent reservation, so handle reservation
errors even after a readiness notification.

A successful commit records local admission. It does not establish packet
transmission, peer acknowledgement, application delivery, or durable storage.
The connection's existing packetization, retransmission, and transport-driving
APIs remain responsible for progress after admission.

### Compatibility and HTTP/3

Existing direct writer signatures remain available. Native QUIC's direct
writer delegates to the same checked reservation and commit engine, preserving
its cancellation ordering, stream-error precedence, and BLOCKED notifications.
Its legacy by-value error API still does not return an owned payload; callers
that need recovery should use the permit API above.

HTTP/3's existing `write_stream_after_checkpoint` path uses the same admission
engine. Its checkpoint remains outside the QPACK lock; the synchronous commit
does not invoke cancellation or user callbacks under that lock.

No raw pointers, detached callbacks, extra reservation counters, or changes to
public exhaustive configuration structs are needed. The connection borrow is
the reservation's lifetime and exclusivity guard.

### Regression coverage

Native connection tests cover dropped and aborted reservations, both credit
scopes, short commits, empty FIN, cancellation ordering, exact owned-payload
recovery, stream-state refusals, and BLOCKED notification deduplication.
`tests/quic_endpoint_api_roundtrip.rs` exercises the public API and pumps
committed frames to the peer to check byte equality and EOF. These tests are
the validation targets for the native QUIC portion of the migration.

## Remaining ATP migration

The original bead also names ATP H3 streams and sessions, SDK sinks, writers,
and streaming adapters. Those surfaces need separate lifetime-safe reservation
designs and behavioral tests. Read-side cancellation and complete network
effect coverage remain outside this native QUIC send implementation.

Preserve existing public signatures when adding those APIs, and use borrowing
or owned shared state to tie each permit to its owner. Do not capture pointers
to movable stream fields in detached callbacks. The earlier raw-pointer sketch
did not keep the stream alive or prevent concurrent queue mutation and has
been replaced by the concrete borrowing-based implementation above.

Future migrations must test ownership recovery, cancellation before and after
admission, bounded capacity, abandoned reservations, and the real transport
path. Keep local queue admission, wire progress, and peer delivery guarantees
distinct. The broader bead should remain open until those surfaces are covered.
