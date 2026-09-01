# ASUP-E509 - Client Body Stream Aborted

## Symptom

`[ASUP-E509]` is an operator diagnostic: the peer transport closed or reset
before a request or response body reached a synchronized terminal boundary.
The HTTP/1 connection is closed or the HTTP/2 stream is reset. An HTTP/3 stream
abort resets the affected QUIC request stream; a peer connection close instead
terminalizes its outstanding request ownership without attempting an impossible
post-close reset. The listener does not synthesize a response after a client
abort.

## Probable Causes

- The client disconnected or reset an HTTP/2 stream while work was in flight.
- An intermediary closed the connection before request-body EOF or response
  completion.

## Fix

- Correlate the coded log with request, stream, and peer identifiers.
- Retry only when the application can prove the operation is idempotent.
- Investigate intermediary and client timeouts when aborts cluster.

## Example

An HTTP/2 peer sends `RST_STREAM`, or an HTTP/3 peer resets its request stream,
during a produced response. The server logs `ASUP-E509`, cancels the producer,
and emits no fallback response body.

## Related

- `ASUP-E505`
- `ASUP-E508`
- `ASUP-E510`
