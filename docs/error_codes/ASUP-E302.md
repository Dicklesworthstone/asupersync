# ASUP-E302 - Race Loser Not Drained

## Symptom

`[ASUP-E302]` means a race combinator returned before fully draining losing
branches.

## Probable Causes

- The winner path forgot to await loser cancellation.
- A loser future held obligations after the race completed.

## Fix

- Cancel every losing branch and drive it to completion before returning.
- Assert zero obligation leaks after race completion in lab tests.

## Example

For `race(a, b)`, once `a` wins, request cancellation of `b` and continue
polling `b` until its cleanup completes.

Current invariant assertions lead with:

`[ASUP-E302] L-LOSER-DRAINED invariant violated: ...`

## Related

- `ASUP-E203`
- `ASUP-E301`
