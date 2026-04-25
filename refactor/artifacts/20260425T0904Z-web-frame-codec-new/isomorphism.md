# Isomorphism Proof: Web Frame Codec Constructor Delegation

## Change

Make `WebFrameCodec::new()` delegate to
`WebFrameCodec::with_max_size(DEFAULT_MAX_FRAME_SIZE)`.

## Preconditions

- `WebFrameCodec::new()` previously constructed only
  `max_frame_size: DEFAULT_MAX_FRAME_SIZE`.
- `WebFrameCodec::with_max_size(size)` stores only
  `max_frame_size: size`.
- `DEFAULT_MAX_FRAME_SIZE` is the same constant passed to the delegated
  constructor.

## Equivalence Contract

- Inputs covered: default `WebFrameCodec::new()` callsites and custom
  `with_max_size(...)` callsites.
- Ordering preserved: construction performs no ordering-sensitive work.
- Error semantics: oversized frame checks still compare against the same
  `max_frame_size`.
- Observable side effects: construction still allocates nothing, performs no
  I/O, and emits no logs/traces.

## Behavior Preservation

Default frame codecs still use `DEFAULT_MAX_FRAME_SIZE`, custom frame codecs
still use their provided max frame size, and encode/decode frame validation
logic is unchanged.
