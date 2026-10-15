# ASUP-E701 - ATP Command Not Implemented

## Symptom

`[ASUP-E701]` appears when an ATP CLI command or SDK operation whose real
implementation is not yet wired is invoked. Examples include `atp sync`,
`atp mirror`, `atp watch`, `atp seed`, `atp resume`, `atp cancel`,
`atp transfer-status`, `atp bench`, and daemon-delegated SDK transfer/session
APIs that can reach an `atpd` socket but do not yet have a real daemon RPC
backing. The operation fails closed instead of simulating success or reporting
a retryable service outage.

## Probable Causes

- The invoked ATP subcommand or SDK call has no real transport or daemon backing
  yet.
- The operation needs durable transfer state from a running `atpd`, which the
  CLI or SDK cannot query yet.

## Fix

- Use `atp send <src> <host:port>` and `atp serve --listen <addr>` (or the
  standalone `atp` binary's `send`/`recv`/`serve`) for real, verified
  transfers today.
- Use `--dry-run` where supported to preview plans without claiming execution.
- For SDK callers, treat `[ASUP-E701]` as a wiring gap, not a transient daemon
  outage. Retrying the same daemon-delegated call will not make progress until
  the corresponding daemon RPC is implemented.
- Track `br-asupersync-qk02uw` follow-ups for wiring the remaining commands to
  the ATP-over-TCP transport and daemon state.

## Example

`asupersync atp sync ./dir peer:8472` exits non-zero with `[ASUP-E701]`
because directory diff/reconcile is not implemented; previously it printed a
fabricated success report while transferring nothing.

## Related

- `ASUP-E702`
