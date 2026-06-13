# ASUP-E702 - ATP Transfer Listener Bind Failed

## Symptom

`[ASUP-E702]` appears when `atpd start` cannot bind its configured transfer
port (default `0.0.0.0:8472`). The daemon refuses to start: a transfer daemon
that is not listening for transfers must not run "healthy".

## Probable Causes

- Another process (often another `atpd` or `atp serve`) already holds the
  port.
- The configured bind address is not local to this host.
- Binding a privileged port (< 1024) without sufficient privileges.

## Fix

- Stop the conflicting listener or choose a different port with
  `atpd start --bind <addr:port>`.
- Verify the address belongs to a local interface (`ss -tlnp` shows current
  listeners).
- Use an unprivileged port or grant the needed capability.

## Example

If a previous daemon is still running, `atpd start --bind 0.0.0.0:8472` fails
with `[ASUP-E702] ... bind 0.0.0.0:8472: address in use`. Stop the old daemon
(`atpd stop`) and start again; on success the diagnostics endpoint reports the
actually-bound address in `transfer_listener_addr`.

## Related

- `ASUP-E701`
