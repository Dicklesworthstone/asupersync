# ASUP-E102 - Obligation Double Resolve

## Symptom

`[ASUP-E102]` means one obligation was resolved more than once.

## Probable Causes

- Normal completion and cancellation cleanup both resolved the same token.
- A retry path reused an obligation id after resolution.

## Fix

- Make resolution ownership explicit at the owner boundary.
- Split token ownership so only one path can consume the obligation.

## Example

Use a single guard that owns the obligation token and exposes one consuming
`commit` or `abort` operation.

The central `Error` display for `ErrorKind::ObligationAlreadyResolved` starts
with:

```text
[ASUP-E102] ObligationAlreadyResolved
```

## Related

- `ASUP-E101`
- `ASUP-E104`
