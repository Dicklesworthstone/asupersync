# ASUP-E105 - Obligation Drain Timeout

## Symptom

`[ASUP-E105]` means drain or recovery waited too long for obligation
resolution and aborted a stale reserved obligation.

## Probable Causes

- A holder task did not observe cancellation.
- A blocking section prevented finalizer progress.
- A remote replica retained a `Reserved` obligation past the recovery
  stale-timeout budget.

## Fix

- Inspect holder task, obligation kind, and age in the audit snapshot.
- Move blocking cleanup into a bounded drain path.
- For CRDT recovery, compare the stale-abort age against
  `RecoveryConfig::stale_timeout_ns` and verify the holder node either
  committed or aborted before partition heal.

## Example

`[ASUP-E105] stale-abort ObligationId(...) (age=5000ns)` means the
recovery governor observed an obligation in `Reserved` beyond its stale-timeout
budget and forced an abort so the ledger can converge.

## Related

- `ASUP-E101`
- `ASUP-E303`
