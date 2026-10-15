# ASUP-E203 - Receive Cancelled

## Symptom

`[ASUP-E203]` means a receive operation was cancelled before delivery could be
committed. Channel `RecvError::Cancelled` display text starts with this token
for MPSC, broadcast, oneshot, and watch receive paths.

## Probable Causes

- The caller's `Cx` was cancelled while waiting.
- A race loser was not drained before observing channel state.

## Fix

- Drain the losing receive future before reusing the channel.
- Confirm the receive path preserves queued data on cancellation.

## Example

A `select` branch that loses after polling a receive reports
`[ASUP-E203] receive operation cancelled`; drive the losing receive through its
cancel cleanup before the channel is reused.

## Related

- `ASUP-E201`
- `ASUP-E302`
