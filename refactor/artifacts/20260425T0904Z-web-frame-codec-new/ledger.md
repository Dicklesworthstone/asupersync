# Refactor Ledger: Web Frame Codec Constructor Delegation

## Scope

- Source: `src/grpc/web.rs`
- Artifact directory:
  `refactor/artifacts/20260425T0904Z-web-frame-codec-new/`

## Line Delta

- Source lines before: 1097
- Source lines after: 1095
- Source reduction: 2

## Candidate Score

- LOC saved: 1
- Confidence: 5
- Risk: 1
- Score: 5.0

## Proof Summary

`WebFrameCodec::new()` duplicated the exact field construction represented by
`with_max_size(DEFAULT_MAX_FRAME_SIZE)`. Delegation preserves the stored default
limit and leaves frame encode/decode behavior unchanged.

## Verification

- Passed: `rustfmt --edition 2024 --check src/grpc/web.rs`
- Passed:
  `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-web-frame-new-0904-check -p asupersync --lib`
- Passed:
  `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-web-frame-new-0904-test -p asupersync --lib grpc::web::tests::test_data_frame_roundtrip`
- Passed:
  `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-web-frame-new-0904-clippy -p asupersync --lib -- -D warnings`

## Fresh-Eyes Review

- `WebFrameCodec::new()` now passes the same `DEFAULT_MAX_FRAME_SIZE` value to
  the custom-size constructor.
- `with_max_size(...)` remains the single field-initialization path and stores
  only `max_frame_size`.
- Data-frame encode/decode behavior, trailer handling, oversized-frame errors,
  and default/custom size distinction are unchanged.
