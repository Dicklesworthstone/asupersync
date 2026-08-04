# Owned LZ4 codec corpus and fuzz receipt

Bead: `asupersync-0h6myr.4.3`
Capability: `CAP-TRACE-LZ4`
Artifact: `artifacts/lz4_owned_codec_corpus_v1.json`

This A3 receipt covers the private safe codec introduced by A2. The frozen
container is `LZ4_SIZE_PREPENDED_BLOCK`: a four-byte little-endian decoded-size
prefix followed by one independent LZ4 block. It is not the LZ4 frame format.
Frames, dictionaries, block checksums, and content checksums remain unsupported.

## Independent corpus

The artifact retains six hand-authored valid vectors derived directly from the
LZ4 block specification. They cover empty and literal-only blocks, both literal
length-extension forms, overlapping match copy, match-length extension, and a
non-unit offset. The expected encoded and decoded hex was authored without
using `lz4_flex` as a generator. The incumbent is applied afterward as a
differential oracle.

Seventeen malformed vectors freeze truncation, container, offset, output-size,
and canonical end-condition categories. Four resource vectors cover complete
compressed input, advertised output, expansion ratio, and invalid limit
configuration. A deterministic mutation test visits every truncation boundary
and flips every bit of every retained valid vector under a 64 KiB test ceiling.

The property lane generates 256 payloads up to 32 KiB and checks:

- deterministic owned encoding;
- owned encode/decode round trips;
- incumbent decoding of owned bytes;
- owned decoding of incumbent 0.14.0 bytes.

The hidden `test-internals`/`fuzz` harness exposes only classified errors and
explicit ceilings. It is not a default public API and has no production caller.

## Current-version bounded fuzzing

The existing `fuzz_trace_compression` target now exercises the owned codec
instead of unrelated raw-block APIs. Its incumbent oracle is pinned exactly to
`lz4_flex` 0.14.0, closing the A1 0.13 version-drift risk. Every arbitrary
decode is bounded to 1 MiB compressed bytes, 1 MiB decoded bytes, and a 256:1
ratio. Encoding is limited to 256 KiB payloads and 512 KiB output. The smoke
receipt uses a 60-second run and a 2 GiB RSS limit. The admitted RCH run
completed 11,010,692 executions in 61 seconds with exit code 0 and 227 MiB
reported RSS.

Focused contract:

```bash
RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay --no-overlay -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR="${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_lz4_a3_contract" cargo test -p asupersync --test lz4_owned_codec_corpus_contract --features test-internals -- --nocapture
```

Bounded fuzz smoke:

```bash
RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay --no-overlay -- env CARGO_INCREMENTAL=0 RUSTFLAGS='-D warnings -C debuginfo=0 --cfg fuzzing' CARGO_TARGET_DIR="${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_lz4_a3_fuzz_run" cargo run --manifest-path fuzz/Cargo.toml --bin fuzz_trace_compression --release -- -max_total_time=60 -rss_limit_mb=2048 -max_len=1048576
```

This formulation links the `libfuzzer-sys` runner and exercises the target, but
does not use `cargo-fuzz` sanitizer or coverage instrumentation. The receipt is
execution smoke only; it makes no sanitizer or coverage claim.

The canonical CAP baseline remains a historical incumbent snapshot:
`EVD-TRACE-LZ4` still points to semantic trace filtering. A3 does not rewrite
that cross-program history. The `LZ4-EVD-A3-CORPUS` receipt is the scoped
successor for byte-codec evidence in this campaign.

## Handoff and no-claim boundary

A4 still owns retained v2/v3 ASUPERTRACE files, reader/replay/migration/CLI
journeys, ASUPERTRACE v3 SHA-256 behavior, and combined compressed plus
decompressed peak memory. A5 alone may authorize a serialized cutover.

No production cutover occurs here. This receipt does not prove historical
full-trace compatibility, performance, throughput, RSS, latency, broad
workspace health, release readiness, or oracle retirement. It does not cover
ATP, Kafka, HTTP compression, or another LZ4 capability. It grants no local
Cargo fallback and makes no sanitizer or coverage claim.
No permission to delete files is granted.
