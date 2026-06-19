# ASUP-E805 - ATP Decode-Rank Stall

## Symptom

`[ASUP-E805]` means an ATP receiver accepted symbols for a pending entry but
decoder rank stopped advancing. This points at redundant symbols, repair-domain
drift, or a manifest/auth mismatch rather than pure packet loss.

## Probable Causes

- The sender emitted repair symbols that were valid but linearly redundant for
  the pending source block.
- Manifest hash, object id, entry index, or authentication domain drifted
  between sender and receiver.
- A source-block or repair-symbol metadata bug caused symbols to target the
  wrong decoder state.

## Fix

- Compare accepted-symbol count, rank deficit, manifest hash, object id, and
  auth domain for the stalled entry.
- Treat repeated rank stalls as fail-closed evidence; do not report transfer
  success until whole-object verification passes.
- Fall back to a full compatible transfer and preserve the stalled decoder
  receipt for the next source-level fix.

## Example

`[ASUP-E805] decode rank stalled for entry 7: accepted=96, rank=63,
source_symbols=64`

## Related

- `ASUP-E801`
- `ASUP-E804`
