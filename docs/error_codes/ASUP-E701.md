# ASUP-E701 - ATP Command Not Implemented

## Symptom

`[ASUP-E701]` appears when an ATP CLI command whose real implementation is not
yet wired (for example `atp sync`, `atp mirror`, `atp watch`, `atp seed`,
`atp resume`, `atp cancel`, `atp transfer-status`, or `atp bench`) is invoked
without `--dry-run`. The command fails closed instead of simulating success.

## Probable Causes

- The invoked ATP subcommand has no real transport or daemon backing yet.
- The operation needs durable transfer state from a running `atpd`, which the
  CLI cannot query yet.

## Fix

- Use `atp send <src> <host:port>` and `atp serve --listen <addr>` (or the
  standalone `atp` binary's `send`/`recv`/`serve`) for real, verified
  transfers today.
- Use `--dry-run` where supported to preview plans without claiming execution.
- Track `br-asupersync-qk02uw` follow-ups for wiring the remaining commands to
  the ATP-over-TCP transport and daemon state.

## Example

`asupersync atp sync ./dir peer:8472` exits non-zero with `[ASUP-E701]`
because directory diff/reconcile is not implemented; previously it printed a
fabricated success report while transferring nothing.

## Related

- `ASUP-E702`
