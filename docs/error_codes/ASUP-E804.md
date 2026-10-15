# ASUP-E804 - ATP Pacer Stall

## Symptom

`[ASUP-E804]` means an ATP receiver waited through the idle window without a
delivery sample while it still expected paced symbols. The failure is treated
as receiver-unresponsive or sender-silent progress loss, not as a successful
zero-byte completion.

## Probable Causes

- The sender stopped emitting symbols or keepalives while the receiver still
  had pending entries.
- A firewall, route change, or NAT binding dropped all data-plane packets after
  control-plane setup.
- Pacer configuration reacted to a bad bandwidth estimate and stopped making
  forward progress.

## Fix

- Check selected path, idle window, last delivery sample, and pacer rate at the
  time of failure.
- Retry on a different path if control traffic remains healthy but data-plane
  samples stop.
- Reduce pacer aggressiveness or reset the bandwidth estimate when stalls
  correlate with a rate change.

## Example

`[ASUP-E804] pacer stall: no delivery samples for 30s while 4 entries remained
pending`

## Related

- `ASUP-E801`
- `ASUP-E805`
