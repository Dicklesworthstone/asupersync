# Isomorphism Proof: `BodyKind` Size Hint Centralization

## Change

Move the duplicated `BodyKind` to `SizeHint` mapping in
`src/http/h1/stream.rs` into a private `BodyKind::size_hint()` helper, then use
that helper from both incoming and outgoing body channel constructors.

## Preconditions

- Both original constructors matched on the same copied `BodyKind` value.
- Both mappings returned `SizeHint::with_exact(0)` for `BodyKind::Empty`.
- Both mappings returned `SizeHint::with_exact(n)` for
  `BodyKind::ContentLength(n)`.
- Both mappings returned `SizeHint::default()` for `BodyKind::Chunked`.
- `BodyKind` is `Copy`, so calling `kind.size_hint()` does not change later
  uses of `kind`.

## Field Mapping

| Body kind | Previous constructor value | Helper value |
| --- | --- | --- |
| `Empty` | `SizeHint::with_exact(0)` | `SizeHint::with_exact(0)` |
| `ContentLength(n)` | `SizeHint::with_exact(n)` | `SizeHint::with_exact(*n)` |
| `Chunked` | `SizeHint::default()` | `SizeHint::default()` |

## Behavior Preservation

- `IncomingBody::channel_with_capacity` stores the same `size_hint` for every
  `BodyKind`.
- `OutgoingBody::channel_with_capacity` stores the same `size_hint` for every
  `BodyKind`.
- Body completion state, sender construction, channel capacity, and public API
  are unchanged.
- No ordering, error, RNG, or side-effect semantics are involved.
