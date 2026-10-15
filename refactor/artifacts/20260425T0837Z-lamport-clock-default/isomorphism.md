# Isomorphism Proof: Lamport Clock Default

## Change

Derive `Default` for `LamportClock`, make `new()` delegate to the derived
default, and remove the manual `Default` implementation.

## Preconditions

- `AtomicU64::default()` constructs the same zero-valued counter as
  `AtomicU64::new(0)`.
- `LamportClock::new()` previously constructed only that zero-valued counter.
- `Default::default()` for `LamportClock` had no side effects and only delegated
  to `LamportClock::new()`.

## Equivalence Contract

- Inputs covered: all `LamportClock::new()` and `LamportClock::default()`
  callsites.
- Ordering preserved: atomic ordering in `now`, `tick`, and `receive` is
  unchanged.
- Error semantics: overflow checks and panic messages in `tick` and `receive`
  are unchanged.
- Observable side effects: construction still creates a fresh zero counter with
  no logging, tracing, allocation, or shared state.

## Behavior Preservation

Fresh Lamport clocks still begin at time `0`, the first local tick still returns
`1`, and received-time merges still use the same counter state and atomic
compare-exchange loop.
