# ASUP-E904 - Semantic Lint Loop Checkpoint

## Symptom

`[ASUP-E904]` means an async infinite loop has no visible cancellation
checkpoint or bounded-progress evidence.

## Probable Causes

- A loop awaits repeatedly but never polls cancellation.
- A long-running task can starve region close and drain quiescence.

## Fix

- Add a `Cx` checkpoint, cancellation poll, or yield in the loop body.
- Use an allow marker only when another local invariant proves bounded progress.

## Example

Call a checkpoint before or after each awaited unit of loop work.

```text
[ASUP-E904] async infinite loop is missing an explicit cx checkpoint or cancellation poll
```

## Related

- `ASUP-E301`
- `ASUP-E402`
