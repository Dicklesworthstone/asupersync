# ASUP-E802 - ATP Capability Mismatch

## Symptom

`[ASUP-E802]` means an ATP peer did not advertise a required wire version or
transport capability for the requested data-plane mode. The diagnostic should
name the missing capability and both endpoint protocol versions when they are
known.

## Probable Causes

- Sender and receiver binaries were built from incompatible ATP protocol
  versions.
- A requested transport mode needs a feature the selected peer did not
  advertise.
- A fallback path was disabled even though the peer can only support the older
  mode.

## Fix

- Upgrade both endpoints to compatible binaries with the same advertised ATP
  capability set.
- Re-run with a lower transport mode only when that mode preserves the required
  integrity and verification guarantees.
- Keep the failing handshake receipt; it should include the missing capability
  and observed peer version.

## Example

`[ASUP-E802] peer capability mismatch: missing atp.rq.feedback.v2
(sender protocol 3, receiver protocol 2)`

## Related

- `ASUP-E803`
- `ASUP-E701`
