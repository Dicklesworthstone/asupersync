# ASUP-E510 - Response Producer Failed

## Symptom

`[ASUP-E510]` is an operator diagnostic: a produced response body returned an
error, panicked, closed without its required terminal action, or disagreed
with the bytes already emitted. After response-head commitment, HTTP/1 closes
and HTTP/2 resets the stream; neither protocol appends a fallback body. HTTP/3
likewise resets the affected QUIC request stream without a fallback body.

## Probable Causes

- The application producer returned an error or panicked.
- The producer omitted `finish`, emitted duplicate terminal state, or supplied
  trailers for an incompatible response body.
- Producer byte accounting disagreed with frames already committed.

## Fix

- Make the producer call `finish` or trailers exactly once after its final
  committed frame.
- Propagate application failures before committing the response head when a
  conventional error response is required.
- Use the coded operator event to correlate cleanup and application errors;
  do not parse transport text on the client.

## Example

An HTTP/1 chunked producer returns an error after the response head was
written. The server logs `ASUP-E510` and closes without writing the successful
zero-length terminal chunk.

## Related

- `ASUP-E509`
- `ASUP-E501`
