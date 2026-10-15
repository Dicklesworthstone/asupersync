# Refactor Ledger: Prost Codec Constructor Delegation

## Scope

- Source: `src/grpc/protobuf.rs`
- Artifact directory:
  `refactor/artifacts/20260425T0849Z-prost-codec-clone/`

## Line Delta

- Source lines before: 525
- Source lines after: 516
- Source reduction: 9

## Candidate Score

- LOC saved: 2
- Confidence: 5
- Risk: 1
- Score: 10.0

## Proof Summary

`ProstCodec::new()` duplicated the exact field construction already expressed
by `with_max_size(DEFAULT_MAX_MESSAGE_SIZE)`. Delegation constructs the same
message-size limit and `PhantomData` marker.

Fresh-eyes verification also corrected the protobuf unknown-field test fixture:
it now appends an unknown varint field to an encoded `TestMessage` instead of
decoding an incompatible nested-message payload as a string field.

## Rejection Log

- Rejected deriving `Clone`: a direct rustc probe showed `#[derive(Clone)]` for
  a `PhantomData<(T, U)>` generic struct adds `T: Clone, U: Clone` bounds. The
  existing manual `Clone` implementation is intentionally unconditional, so
  deriving it would narrow the public API.

## Verification

- Passed: `rustfmt --edition 2024 --check src/grpc/protobuf.rs`
- Passed:
  `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-prost-clone-0849-check -p asupersync --lib`
- Passed:
  `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-prost-clone-0849-test -p asupersync --lib grpc::protobuf`
- Passed:
  `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-prost-clone-0849-clippy -p asupersync --lib -- -D warnings`

## Fresh-Eyes Review

- `ProstCodec::new()` now calls the same constructor path as custom limits with
  the same `DEFAULT_MAX_MESSAGE_SIZE` argument.
- Manual `Clone` remains in place because deriving it would add public API
  bounds on `T` and `U`.
- The unknown-field test now exercises a valid protobuf unknown field while
  asserting the known `name` and `value` fields survive decoding.
- Encode/decode size checks, prost error mapping, symmetric alias behavior, and
  custom max-size behavior are unchanged.
