# ASUP-E008 - Admission Slot Already Reserved

## Symptom

`[ASUP-E008]` means a spawn request tried to reuse a one-shot
`AdmittedTaskSlot` that another request had already reserved.

## Probable Causes

- Two spawn requests were constructed with the same admission slot.
- Caller code retained a slot after its original request was admitted or
  denied, then attached it to another request.

## Fix

- Create a fresh `AdmittedTaskSlot` alongside each `TaskHandle`.
- Treat the slot, handle, and request as one indivisible admission handshake;
  never pool or recycle the slot separately.

## Example

Allocate one slot for request A and a different slot for request B, even when
both requests target the same region and use the same budget.

## Related

- `ASUP-E001`
- `ASUP-E003`
