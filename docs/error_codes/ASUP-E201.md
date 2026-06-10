# ASUP-E201 - Channel Closed

## Symptom

`[ASUP-E201]` means a send or receive operation observed a closed channel.

## Probable Causes

- All senders or receivers were dropped.
- A region closed before channel users finished.

## Fix

- Treat closure as normal shutdown if it follows region cancellation.
- If unexpected, inspect owner region lifetime and endpoint drops.

## Example

When a worker region closes, downstream receivers should usually convert closed
channel state into a cancellation outcome, not retry blindly.

## Related

- `ASUP-E203`
- `ASUP-E301`
