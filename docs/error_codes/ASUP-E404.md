# ASUP-E404 - Snapshot Artifact Invalid

## Symptom

`[ASUP-E404]` means an owned `ASUPSNAP` runtime-state artifact could not be
encoded, decoded, or materialized safely. The diagnostic identifies the failed
magic, version, kind, flags, length, checksum, resource limit, structural
validation, or incremental-base check.

## Probable Causes

- The artifact is partial, corrupt, oversized, or from an unsupported future
  envelope or state-schema version.
- An incremental artifact was applied without its required base, or the base
  content hash does not match.
- Decoded state violates runtime referential, quiescence, timestamp, count, or
  depth invariants.

## Fix

- Preserve the rejected bytes and inspect the precise `[ASUP-E404]` suffix
  before retrying.
- Supply the exact validated base snapshot for an incremental artifact.
- For legacy schema-1 JSON, validate it first and use the explicit reversible
  migration workflow in `docs/runtime_snapshot_codec.md`.
- Keep the original source as a rollback anchor and install migrated bytes
  through `asupersync::fs::write_atomic`.

## Example

If the diagnostic reports a checksum mismatch, do not retry materialization or
replace an installed snapshot. Recover an intact copy from the rollback source,
then decode and validate that copy before installation.

## Related

- `ASUP-E401`
- `ASUP-E403`
- `docs/runtime_snapshot_codec.md`
