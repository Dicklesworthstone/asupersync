# Isomorphism Proof: `PowerOfTwoChoices::new()` Delegates to Default

## Change

Replace the manual `PowerOfTwoChoices::new()` constructor body in
`src/service/load_balance.rs` with `Self::default()`.

## Preconditions

- `PowerOfTwoChoices` already derives `Default`.
- `PowerOfTwoChoices` has one field: `counter: AtomicUsize`.
- `AtomicUsize::default()` is equivalent to `AtomicUsize::new(0)`.

## Field Mapping

| Field | Manual `new()` value | Derived default value |
| --- | --- | --- |
| `counter` | `AtomicUsize::new(0)` | `AtomicUsize::default()` = `AtomicUsize::new(0)` |

## Behavior Preservation

- `PowerOfTwoChoices::new()` still returns a strategy whose scatter counter is
  zero.
- `pseudo_random()` still observes and increments the same atomic counter.
- Public constructor and strategy behavior are unchanged.
