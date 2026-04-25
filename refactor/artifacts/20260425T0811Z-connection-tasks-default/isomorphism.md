# Isomorphism Proof: `ConnectionTasks` Derived Default

## Change

Derive `Default` for the private `ConnectionTasks` helper, construct it with
`ConnectionTasks::default()`, and remove its manual zero-value constructor.

## Preconditions

- `ConnectionTasks` has two fields: `handles` and `push_count`.
- `Vec::<JoinHandle<()>>::default()` is equivalent to `Vec::new()`.
- `u64::default()` is `0`.
- The only constructor call is in `Http1Listener::run` before any connection
  tasks are accepted.

## Field Mapping

| Field | Previous `new()` value | Derived `Default` value |
| --- | --- | --- |
| `handles` | `Vec::new()` | empty `Vec` |
| `push_count` | `0` | `0` |

## Behavior Preservation

- The listener run loop still starts with no tracked connection tasks.
- Periodic cleanup still starts from `push_count == 0` and triggers after the
  same wrapping increments.
- Task push, retain, panic isolation, and drain behavior are unchanged.
