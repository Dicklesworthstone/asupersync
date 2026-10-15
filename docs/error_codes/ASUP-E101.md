# ASUP-E101 - Obligation Leaked

## Symptom

`[ASUP-E101]` means an obligation reached leak handling without being committed
or aborted.

## Probable Causes

- A guard, permit, ack, or lease was dropped without resolving.
- A cancellation path skipped drain-phase cleanup.

## Fix

- Find the holder task and obligation kind in the audit snapshot.
- Ensure every acquire or reserve path has matching commit or abort cleanup.

## Example

If a send permit is reserved and cancellation wins before `send`, abort the
permit during drain so the channel does not report a leak.

The current graded obligation panic starts with:

```text
[ASUP-E101] OBLIGATION LEAKED
```

Typed obligation tokens use the same code and start with:

```text
[ASUP-E101] OBLIGATION TOKEN LEAKED
```

The central `Error` display for `ErrorKind::ObligationLeak` starts with:

```text
[ASUP-E101] ObligationLeak
```

Lab invariant reports include the holder facts needed for first-pass triage:

```text
[ASUP-E101] obligation leak: count=1 leaks=[obligation=ObligationId(...) kind=SendPermit holder=TaskId(...) region=RegionId(...)]
```

## Related

- `ASUP-E104`
- `ASUP-E202`
