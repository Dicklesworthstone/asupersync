# LZ4 surface and artifact inventory

<!-- BEGIN LZ4 SURFACE ARTIFACT INVENTORY -->

This is the operator-readable companion to
`artifacts/lz4_surface_artifact_inventory_v1.json`. It freezes the
`CAP-TRACE-LZ4` baseline for `asupersync-0h6myr.4.1` at revision
`a4a92df81109afa362814c4e0638afcbe16424d0`.

The A1 decision is `REPLACE_EXPERIMENT_AUTHORIZED`, not a production
cutover. A2 may build a strictly safe isolated codec against the exact block
contract below. `lz4_flex` remains the production codec and differential
oracle unless A5 later proves every required row and serializes a cutover.
A1 changes no source, manifest, feature, format, or dependency behavior.

## What the trace format actually stores

The persisted trace container is `ASUPERTRACE`. The current version is 3;
readers accept versions 1 through 3. Version 1 has no compression byte and
cannot be compressed. Version 2 introduced the compression byte. Version 3
adds SHA-256 digests for metadata and the canonical uncompressed event-frame
stream.

Compression byte `1` means a sequence of:

1. a little-endian `u32` compressed-chunk length;
2. a `lz4_flex` size-prepended block, whose first four bytes are the
   little-endian uncompressed length;
3. canonical event frames in the decompressed payload.

The machine label for this codec container is
`LZ4_SIZE_PREPENDED_BLOCK`. This is not the LZ4 frame format. The trace
format does not accept or emit LZ4 frame headers, dictionaries, block
checksums, content checksums, or an LZ4-frame content-size field. Registry
prose that says “block/frame” is
therefore broader than the implementation. The A1 freeze is the narrower
observed size-prepended block contract; adding frame behavior would be a
separate format decision.

Version 3's SHA-256 event digest covers the canonical uncompressed event
frames. It is independent of the exact compressed bytes. Semantic replay
equivalence is necessary, but an experimental encoder must also remain
readable by the incumbent and preserve every container boundary and
diagnostic.

## Production call-site census

There are eight production API calls in four source files.

| ID | Owner | Path | Incumbent API | Responsibility |
| --- | --- | --- | --- | --- |
| `LZ4-CS-TRACE-WRITE` | `CAP-TRACE-LZ4` | `src/trace/file.rs` | `compress_prepend_size` | Encode a buffered canonical event-frame chunk. |
| `LZ4-CS-TRACE-READ` | `CAP-TRACE-LZ4` | `src/trace/file.rs` | `decompress_size_prepended` | Refill `TraceReader` after compressed/output-size guards. |
| `LZ4-CS-TRACE-ITER` | `CAP-TRACE-LZ4` | `src/trace/file.rs` | `decompress_size_prepended` | Refill the independent iterator buffer under the same guards. |
| `LZ4-CS-ATP-MANIFEST-SIZE` | cross-campaign | `src/atp/manifest.rs` | `compress_prepend_size` | Measure actual compressed content length for policy. |
| `LZ4-CS-ATP-COMPRESS` | cross-campaign | `src/net/atp/compress/mod.rs` | `compress_prepend_size` | Encode ATP payloads. |
| `LZ4-CS-ATP-DECOMPRESS` | cross-campaign | `src/net/atp/compress/mod.rs` | `decompress_size_prepended` | Decode ATP payloads and then compare expected size. |
| `LZ4-CS-ATP-ADAPTER-COMPRESS` | cross-campaign | `src/net/atp/compress/algorithms.rs` | `compress_prepend_size` | Generic ATP adapter encode. |
| `LZ4-CS-ATP-ADAPTER-DECOMPRESS` | cross-campaign | `src/net/atp/compress/algorithms.rs` | `decompress_size_prepended` | Generic ATP adapter decode and post-check. |

The five ATP calls are inventory obligations, not migration authority for
the trace campaign. A trace-only cutover cannot remove the root dependency
while ATP still uses it. The HTTP/ATP compression terminal owns those
journeys.

Inline tests use the incumbent to construct two trace bomb fixtures and one
ATP size-mismatch fixture. The excluded fuzz workspace exercises raw and
size-prepended block APIs, but its manifest requests `lz4_flex` 0.13 while
production resolves 0.14.0. Its `Cargo.lock` is ignored and cannot serve as
clean-HEAD evidence; a local observation resolved 0.13.1. The current
`tracing_overhead` Criterion bench uses public trace writer/reader APIs
rather than calling the codec directly.

## Public and operator-visible behavior

The public trace surface includes `CompressionMode::None`,
`CompressionMode::Lz4 { level }`, `CompressionMode::Auto`,
`TraceFileConfig::with_compression`, and a public `chunk_size`. The CLI adds
`trace compress INPUT OUTPUT --level -1..=16`, plus info, replay, diff,
export, and migration journeys that all consume compressed artifacts through
`TraceReader`.

Without `trace-compression`, compressed input must return
`CompressionNotAvailable`. It may not be skipped or treated as an unknown
uncompressed format.

Two accepted-looking configuration surfaces do not currently control the
codec:

- `Lz4 { level }` validates and reports `-1..=16`, but the writer always
  calls `compress_prepend_size`; it never passes or interprets the level.
- `Auto` is documented as a 1 MiB threshold, but it is always treated as
  compressed and `AUTO_COMPRESSION_THRESHOLD` is not used by the runtime.

Both `Lz4` and `Auto` persist compression byte `1`; readers reconstruct
`Lz4 { level: 1 }`. Requested level and Auto intent are not persisted.
A4 owns the compatibility decision. A2 must not silently “fix” these public
semantics while implementing the isolated codec.

## Resource envelope

The observed trace limits are:

- default writer chunk: 64 KiB;
- documented but unused Auto threshold: 1 MiB;
- maximum compressed chunk: 64 MiB;
- maximum advertised decompressed chunk: 64 MiB;
- maximum single event: 16 MiB;
- maximum metadata: 1 MiB;
- bounded `load_all` preallocation: 10 million events.

The writer holds the uncompressed event buffer and then allocates the
compressed output vector. Each reader allocates the bounded compressed chunk,
checks the embedded four-byte output length, and then allocates/replaces its
decompressed vector. These constants establish individual limits, not a
measured combined peak. A4 must capture peak memory and recovery behavior at
the boundaries.

The ATP decode paths compare their caller-supplied expected size only after
the incumbent has allocated and decoded the advertised size-prepended block.
That cross-campaign resource question is routed to the HTTP/ATP compression
campaign.

## Dependency and trust baseline

The root optional normal edge and root dev edge both resolve
`lz4_flex` 0.14.0. The excluded fuzz workspace requests the 0.13 line and
has no tracked lockfile; the local ignored lockfile observed 0.13.1.

The marginal ledger has twelve normal measurements and four dev
measurements across `cli`, `trace-compression`, and
`workspace-dev-build-audit`, for Linux x86-64, Windows x86-64, Apple
Silicon, and wasm32.

For isolated `cli` and `trace-compression` profiles, removing the normal edge
removes two package versions: `lz4_flex` and `twox-hash`. The full workspace
dev audit reports a zero marginal because verification edges retain the
dependency. The ledger class is `SAFE-OWN` and records no marginal native
code. Those are planning facts, not cutover authority.

## Representative baseline

The existing 10,000-event Criterion lanes ran remotely on RCH worker
`ovh-a`, job `29948224668172532`, against the pinned revision:

| Lane | Median |
| --- | ---: |
| write uncompressed | 1.1274 ms |
| write LZ4 | 1.0666 ms |
| read uncompressed | 1.6170 ms |
| read LZ4 | 1.6767 ms |

The LZ4 write median was about 0.946 times the uncompressed median and the
LZ4 read median about 1.037 times the uncompressed median in this one sample.
It used 100 Criterion samples and 10,000 identical `TaskScheduled` events.
The existing bench does not emit file-size ratio or RSS. CPU model
introspection was unavailable through the admitted RCH receipt.

This is single-worker planning evidence. It is not a threshold, a
performance-improvement claim, a memory measurement, or a no-regression
gate. The checked contract includes a deterministic in-memory payload probe
for reproducible byte ratios; A4 still owns representative trace
distributions, multi-host performance, memory, and acceptance thresholds.

## Evidence gaps and routing

Every gap is explicit:

| Gap | Finding | Owner |
| --- | --- | --- |
| `LZ4-GAP-01` | Public level is not consumed by the codec. | A4 |
| `LZ4-GAP-02` | Auto threshold is documented but unused. | A4 |
| `LZ4-GAP-03` | Persisted byte `1` loses level/Auto intent. | A4 |
| `LZ4-GAP-04` | Registry says block/frame; trace is block-only. | A1 format freeze |
| `LZ4-GAP-05` | Registered `EVD-TRACE-LZ4` fixture tests event filtering, not LZ4 bytes. | A3 |
| `LZ4-GAP-06` | Fuzz requests unlocked 0.13 versus production 0.14.0. | A3 |
| `LZ4-GAP-07` | No retained historical compressed trace corpus is registered. | A4 |
| `LZ4-GAP-08` | Three declared canonical LZ4 scenarios are not registered. | A4 |
| `LZ4-GAP-09` | Combined peak compressed/decompressed memory is unmeasured. | A4 |
| `LZ4-GAP-10` | Five ATP production calls sit outside the trace capability. | DEFLATE/HTTP A7 |
| `LZ4-GAP-11` | ATP expected-size checks occur after decode allocation. | DEFLATE A6 |

A2 owns the safe block codec. A3 owns independent vectors, differential and
property evidence, current-version fuzzing, and minimized failures. A4 owns
historical artifacts, trace/CLI/replay/migration integration, canonical E2E,
memory, and performance. A5 alone may serialize a production/manifest
cutover or emit KEEP.

## A5 terminal decision

The checked terminal packet is
[`artifacts/lz4_final_signoff_v1.json`](../artifacts/lz4_final_signoff_v1.json),
with operator guidance in
[`docs/lz4_final_signoff.md`](./lz4_final_signoff.md). Its verdict is
`KEEP_INCUMBENT_NO_CUTOVER`.

A2 and A3 establish scoped safe block-codec correctness. A4 establishes
retained v2/v3 trace compatibility, real writer/reader/migration/replay/CLI
journeys, bounded malformed behavior, and a named-host comparison. Those
results do not satisfy the serialized replacement gate:

- public level and Auto semantics remain unresolved;
- the owned probe encoded 50.292% slower and decoded 105.505% slower on the
  retained named host, despite a 2.476% smaller block;
- allocation-count and portable performance evidence remain absent;
- the incumbent remains the differential oracle and production default; and
- five ATP production call sites sit outside `CAP-TRACE-LZ4`.

A5 therefore leaves `Cargo.toml`, `Cargo.lock`, persisted trace bytes,
production constructor selection, public modes, diagnostics, and all accepted
artifacts unchanged. The terminal packet is a durable KEEP receipt, not a
partial switch or a deferred hidden cutover.

## Gate and rollback

`REPLACE_EXPERIMENT_AUTHORIZED` means only that A2 may construct an isolated
strictly safe implementation of the frozen size-prepended block contract.
It does not authorize a production call-site switch. Any new call site,
source-pin drift, format change, weakened limit, lost diagnostic, expanded
frame/dictionary/checksum scope, unowned ATP impact, or attempted pre-A5
cutover returns the campaign to `KEEP_INCUMBENT`.

## No-claim boundary

This inventory does not prove an owned codec, independent vector parity,
fuzz convergence, arbitrary historical compatibility, cross-version
interoperability, real replay E2E, peak memory, performance improvement,
broad workspace health, release readiness, or live fleet availability. It
does not authorize changing `Cargo.toml`, `Cargo.lock`, production source,
features, the trace format, ATP compression, or removing `lz4_flex`.
It grants no permission to delete files.

<!-- END LZ4 SURFACE ARTIFACT INVENTORY -->
