# ASUP-E203 - Receive Cancelled

## Symptom

`[ASUP-E203]` means a receive operation was cancelled before delivery could be
committed.

## Probable Causes

- The caller's `Cx` was cancelled while waiting.
- A race loser was not drained before observing channel state.

## Fix

- Drain the losing receive future before reusing the channel.
- Confirm the receive path preserves queued data on cancellation.

## Example

A `select` branch that loses after polling a receive must be driven through its
cancel cleanup before the channel is reused.

## Related

- `ASUP-E201`
- `ASUP-E302`
