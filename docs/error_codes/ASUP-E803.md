# ASUP-E803 - ATP Block-Size Mismatch

## Symptom

`[ASUP-E803]` means sender and receiver block-size planning disagreed for a
RaptorQ or QUIC transfer. The diagnostic should include the sender value,
receiver value, and minimum compatible build or protocol version if known.

## Probable Causes

- One endpoint is running an older block-size planner.
- The endpoints derived effective maximum block sizes from different manifest
  inputs.
- A CLI or config override forced incompatible symbol or block-size parameters.

## Fix

- Compare configured and effective block-size values from both endpoints.
- Upgrade the older endpoint or remove the incompatible override.
- Retry using a full compatible transfer mode if the mismatch is discovered
  during an incremental or optimized path.

## Example

`[ASUP-E803] ATP block-size mismatch: sender effective_max_block=8388608,
receiver effective_max_block=4194304, min_build=0.3.5`

## Related

- `ASUP-E802`
- `ASUP-E801`
