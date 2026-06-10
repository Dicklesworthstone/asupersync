# ASUP-E901 - Config Invalid

## Symptom

`[ASUP-E901]` means runtime or build configuration failed deterministic
validation.

## Probable Causes

- A numeric bound is internally inconsistent.
- A feature combination violates the supported proof-lane envelope.

## Fix

- Normalize dependent values before constructing runtime state.
- Map the failed claim to the proof-lane manifest before changing docs.

## Example

If `min_threads` exceeds `max_threads`, normalize the pair before creating the
blocking-pool configuration.

## Related

- `ASUP-E007`
- `ASUP-E403`
