# ASUP-E010 - Spawn Batch Too Large

## Symptom

`[ASUP-E010]` means `Cx::spawn_batch`, `Cx::spawn_batch_in`, or
`JoinSet::spawn_all` received more than `asupersync::cx::MAX_SPAWN_BATCH_SIZE`
factories. The current limit is 1024. No member of the refused batch was
published, no factory was invoked, and no pending-spawn reservation remains.

## Probable Causes

- A producer submitted the entire workload in one batch.
- An iterator supplied an unbounded sequence. Batch collection reads at most
  the limit plus one element before refusing it.

## Fix

- Split the input into batches no larger than `MAX_SPAWN_BATCH_SIZE`.
- Collect existing task results before publishing another batch when the total
  live workload must stay bounded.
- Retain or reconstruct the input before calling if it must be retried: batch
  refusal consumes and drops the supplied factories and iterator.

## Example

Submit 1024 factories, join their returned handles, then submit the remaining
factories. This bounds producer work per call and lets the caller control the
total number of live children. Region admission quotas continue to apply to each
member; a quota denial resolves through that member's handle independently.

## Related

- `ASUP-E001` — no live or authorized spawn path.
- `ASUP-E003` — target region is closing or closed.
- `ASUP-E006` — an individual member was denied by the region's task quota.
