# Isomorphism Proof: Prost Codec Constructor Delegation

## Change

Make `ProstCodec::new()` delegate to
`ProstCodec::with_max_size(DEFAULT_MAX_MESSAGE_SIZE)`.

## Preconditions

- `ProstCodec::new()` previously constructed the same fields as
  `ProstCodec::with_max_size(DEFAULT_MAX_MESSAGE_SIZE)`.
- `with_max_size(...)` only stores the provided limit and `PhantomData`.
- `DEFAULT_MAX_MESSAGE_SIZE` is the same constant previously written directly
  into `new()`.

## Equivalence Contract

- Inputs covered: `ProstCodec::new()`, `ProstCodec::default()`, custom
  `with_max_size(...)`, and existing tests that assert default/custom limits.
- Ordering preserved: no ordering-sensitive operations are involved in
  construction.
- Error semantics: encode/decode size checks and prost errors are unchanged.
- Observable side effects: construction still allocates nothing, performs no
  I/O, and emits no logs/traces.
- Type behavior: the type parameters remain represented only by `PhantomData`.

## Behavior Preservation

Default codecs still use `DEFAULT_MAX_MESSAGE_SIZE`, custom codecs still retain
their configured limit, and `Default::default()` still delegates through
`ProstCodec::new()`.

## Fresh-Eyes Test Correction

During verification, `test_prost_codec_unknown_fields` was found to encode a
`NestedMessage` and decode it as `TestMessage`. That is not an unknown-field
case because field 1 has incompatible message/string payload semantics. The
test fixture now appends a valid unknown varint field to an encoded
`TestMessage`, preserving the intended prost unknown-field skip assertion.
