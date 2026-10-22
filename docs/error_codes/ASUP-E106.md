# ASUP-E106 - Obligation Projection Inconsistent

## Symptom

`[ASUP-E106]` means an online check found disagreement between actual obligation
records, checked admission decisions, ticket identities, or region accounting.
The first typed fault remains in `obligation_conservation_report()` even after
later operations repair the immediate mismatch. A pending arena record prevents
the checked runtime from closing and reclaiming its region.

The lab enables these checks and includes faults in its run report and test
assertion. Native runtimes opt in with `enable_obligation_conservation_checks()`.

## Probable Causes

- A record disappeared or retained the wrong holder or region generation.
- A checked ticket lost its exact arena identity.
- Live quota or unapplied close-barrier accounting drifted.
- Cached close readiness incorrectly claimed zero pending obligations.

## Fix

Inspect the typed checkpoint and issue along with the exact region, obligation,
and ticket identities. Reproduce the reserve, handoff, and terminal sequence in
the lab, then repair the transition that lost ownership or accounting. Preserve
the latched evidence; clearing counters or forcing close can hide live work.

## Example

A `LiveCountMismatch { expected: 1, observed: 0 }` says the independently observed
arena and credit decisions still own one live obligation while the region's
admission counter claims none. `PendingAtClose` refuses reclamation when a
Reserved arena record survives a supposedly empty close barrier.

Queued checked Reserve/Handoff receipts produce explicit deferred coverage, not
this error. A terminal decision before terminal application is also valid: it
uses an unapplied barrier but no live quota. These checks cover current projection
consistency, not lifetime totals, queued-credit conservation, or unprojected
legacy unchecked posts.

## Related

- `ASUP-E101`
- `ASUP-E102`
- `ASUP-E105`
- [Machine registry](./registry.json)
