# ASUP-E202 - Send Permit Leaked

## Symptom

`[ASUP-E202]` means a two-phase send permit was reserved but never committed or
aborted.

## Probable Causes

- Cancellation happened between reserve and send.
- The permit owner was dropped without abort cleanup.

## Fix

- Use the channel reserve/send guard pattern instead of manual flags.
- Add a test that cancels immediately after reserve.

## Example

If `reserve()` succeeds and the task is cancelled before `send()`, abort the
reservation before returning.

## Related

- `ASUP-E101`
- `ASUP-E104`
