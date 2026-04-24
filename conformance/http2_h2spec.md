# HTTP/2 h2spec Status

Date: 2026-04-24
Bead: `asupersync-h8pga6`

## Status

`h2spec` is not installed in this checkout, so the full external conformance sweep could not be executed directly in this pass.

## Focused Work Shipped

This bead tightened the internal RFC 7540 stream-state conformance harness instead of leaving priority/dependency coverage as placeholder prose:

- `tests/conformance/h2_rfc7540/stream_tests.rs`
  - added executable assertions that `HEADERS`, `PRIORITY`, and `CONTINUATION` reject stream ID `0`
  - added executable assertions that self-dependent `PRIORITY` frames fail with stream-scoped `PROTOCOL_ERROR`
  - added executable assertions that valid root and non-root dependencies parse correctly
  - added executable assertions for exclusive-bit parsing, encoded weight preservation, and short `PRIORITY` frame `FRAME_SIZE_ERROR`

## Required External Follow-Up

Run `h2spec` against the HTTP/2 implementation once the tool is available and the shared tree is green enough to compile all targets:

- CONTINUATION sequencing / wrong-stream handling
- PRIORITY self-dependency / dependency loop behavior
- WINDOW_UPDATE zero-increment handling
- SETTINGS edge cases
- PING ACK timing

## Current Validation Blockers

Remote validation of this bead was attempted with:

- `rch exec -- cargo check --all-targets`
- `rch exec -- cargo test --lib h2`

The shared tree is currently blocked by unrelated existing compile failures outside the reserved HTTP/2 surface, including:

- `src/messaging/kafka_consumer.rs`
- `src/messaging/kafka.rs`
- `src/record/task.rs`
- `src/runtime/panic_isolation.rs`
