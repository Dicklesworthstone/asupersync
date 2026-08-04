# LZ4 trace integration and measured go/no-go

Bead: `asupersync-0h6myr.4.4`
Capability: `CAP-TRACE-LZ4`

The retained corpus is
`tests/fixtures/lz4-trace-historical-corpus/v0.3.9.json`. The machine receipt
is `artifacts/lz4_trace_integration_go_no_go_v1.json`.

The current scoped verdict is `KEEP_INCUMBENT`. No production cutover occurs
in A4. No permission to delete files is granted.

## Integration boundary

The real `TraceWriter`, `TraceReader`, iterator, and migration paths now carry
a private codec selector. Every production constructor and the public
`migrate_trace_file` entry point selects `lz4_flex 0.14.0`, the incumbent. The
owned codec is reachable only through a doc-hidden harness compiled when both
`trace-compression` and `test-internals` are enabled. This lets A4 exercise the
real streaming, integrity, replay, migration, and CLI surfaces without
changing the production default or the persisted container.

The container remains `LZ4_SIZE_PREPENDED_BLOCK`: a four-byte little-endian
decoded-size prefix followed by one independent LZ4 block. `ASUPERTRACE` v3
header bytes, flags, SHA-256 integrity fields, streaming chunks, and accepted
trailing data are unchanged. This is not the LZ4 frame format. Dictionaries,
block checksums, and content checksums remain unsupported.

Rollback is immediate and local: remove the private selector and test-only
harness, returning the three production call sites to direct incumbent calls.
Existing artifacts require no migration because A4 does not change their
format. The retained corpus provides immutable bytes for regression checks.

## Retained and generated evidence

`tests/fixtures/lz4-trace-historical-corpus/v0.3.9.json` retains:

- a manually assembled `ASUPERTRACE` v2 container whose compressed block was
  emitted by pinned `lz4_flex 0.14.0`;
- a v0.3.9 `TraceWriter` `ASUPERTRACE` v3 artifact using the same incumbent;
- fixed semantic metadata and six replay events;
- exact byte length, hexadecimal bytes, producer, and SHA-256 for each file.

Both artifacts decode identically through incumbent and owned paths. The v2
artifact migrates to v3 through both paths without modifying its source, and
both migrated files cross-decode. Current large traces cross-decode, replay,
pass CLI `info`, strict `verify`, `events`, `diff`, and `compress` journeys,
and produce deterministic owned bytes. Dropping an owned writer after 64
events exercises the interrupted-writer boundary; both decoders recover the
same valid, bounded partial trace.

Malformed coverage freezes header and chunk truncation boundaries, zero and
oversized chunk lengths, oversized advertised output, SHA-256 event-stream
corruption, and the existing accepted-trailing-data behavior. Failures use
the existing typed `TraceFileError` diagnostics.

## Canonical scenarios

The dependency-sovereignty runner registers these exact scenario IDs:

- `lz4_trace_replay`
- `lz4_cross_version_artifact`
- `lz4_malformed_limits`

Each invokes the matching test in `tests/lz4_trace_integration_e2e.rs` with
`cli,test-internals,trace-compression`, a unique remote target directory, and
no local Cargo fallback. After the content commit, an individual scenario is:

```bash
RCH_REQUIRE_REMOTE=1 bash scripts/run_dependency_sovereignty_e2e.sh --scenario lz4_trace_replay
```

The direct focused lane is:

```bash
RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay --no-overlay -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR="${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_lz4_a4_integration" cargo test -p asupersync --test lz4_trace_integration_e2e --features cli,test-internals,trace-compression -- --nocapture --test-threads=1
```

## Measurement and verdict

The bounded probe uses 64 iterations over canonical serialized replay-event
frames. It records payload and encoded sizes, encode/decode elapsed
nanoseconds, compressed-plus-decompressed block bytes, process `VmHWM`, remote
worker identity, and CPU model in
`artifacts/lz4_trace_integration_go_no_go_v1.json`. The probe is a named-host
comparison, not a portable benchmark or an allocation profiler.

The A4 verdict is `KEEP_INCUMBENT`. A5 must not authorize cutover until it
resolves or explicitly disposes all of these blockers:

- `CompressionMode::Lz4 { level }` still does not preserve or apply `level`;
- `CompressionMode::Auto` still serializes as byte `1` without exercising its
  documented threshold;
- the persisted compression byte cannot retain Lz4 level or Auto intent;
- the current timing receipt is from one remote host and one test-profile run;
- the receipt has a process RSS high-water mark but no allocation-count
  instrumentation;
- ATP LZ4 call sites are outside this trace-capability experiment.

## No-claim boundary

This A4 packet proves only the retained corpus, shadow integration, scenario
registration, focused compatibility/replay/CLI/malformed tests, bounded
interrupted-writer behavior, and the recorded named-host probe. It does not
prove production cutover, dependency removal, allocator behavior, portable
performance improvement, p50/p95/p999 latency, broad workspace health,
release readiness, live RCH fleet health, frame/dictionary/checksum support,
or ATP replacement. It grants no local Cargo fallback and no permission to
delete files.
