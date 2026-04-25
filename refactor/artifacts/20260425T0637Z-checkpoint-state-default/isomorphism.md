# Isomorphism Proof: `CheckpointState` Default Delegation

## Change

Delegate `CheckpointState::new()` in `src/types/task_context.rs` to the
already-derived `Default` implementation.

## Preconditions

- `CheckpointState` derives `Default`.
- `CheckpointState` has three fields:
  `last_checkpoint: Option<Time>`, `last_message: Option<String>`, and
  `checkpoint_count: u64`.
- `Option<T>::default()` is `None`.
- `u64::default()` is `0`.

## Field Mapping

| Field | Previous `new()` value | Derived `Default` value |
| --- | --- | --- |
| `last_checkpoint` | `None` | `None` |
| `last_message` | `None` | `None` |
| `checkpoint_count` | `0` | `0` |

## Behavior Preservation

- `CheckpointState::new()` still returns a state with no recorded checkpoint.
- Existing call sites keep using `CheckpointState::new()`.
- Record/update methods are unchanged.
- Public API is unchanged.
