# ASUP-E801 - ATP RQ No Convergence

## Symptom

`[ASUP-E801]` means an ATP RaptorQ or QUIC fountain transfer exhausted its
feedback-round budget while one or more entries were still undecoded. The
error must report the number of attempted feedback rounds and the pending entry
count so an operator can distinguish ordinary loss from a deterministic
decode failure.

## Probable Causes

- The path dropped too many source or repair symbols before the configured
  feedback-round budget expired.
- Symbol authentication, manifest identity, or repair-domain metadata caused
  otherwise delivered symbols to be ignored.
- The repair overhead or max feedback round setting is too small for the
  observed path loss.

## Fix

- Inspect pending entry count, feedback round count, accepted-symbol count, and
  loss observations before retrying.
- Increase repair overhead or max feedback rounds only after ruling out
  authentication and manifest mismatch.
- If repeated retries fail with the same pending set, fall back to a full
  compatible transfer and preserve the failing receipt for analysis.

## Example

`[ASUP-E801] no convergence after 8 feedback rounds; 2 entries pending,
eps_hat=0.18`

## Related

- `ASUP-E804`
- `ASUP-E805`
