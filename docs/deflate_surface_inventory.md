# DEFLATE surface and backend inventory

This runbook owns the terminal A1 inventory for `asupersync-0h6myr.5.1`
and `CAP-HTTP-COMPRESSION`. The machine-readable authority is
`artifacts/deflate_surface_inventory_v1.json`.

## Decision

The verdict is `KEEP_INCUMBENT`. This bead makes no production source change,
does not authorize an owned codec, and does not authorize removing `flate2`.

The result is not a generic preference for dependencies. It follows from the
current observable surface:

- four public constructors accept `flate2::Compression`;
- HTTP exposes streaming gzip and deflate codecs;
- gRPC and OTLP put gzip bytes on the wire;
- ATP cache and mailbox storage persist gzip bytes in versioned envelopes; and
- ATP manifests compute gzip size metadata while the public ATP transport
  helper remains unwired.

Production payload distributions, cross-implementation service receipts, and
several target cells are still absent. Those gaps make a replacement decision
speculative.

## Dependency and backend

`compression = ["dep:flate2", "dep:brotli"]` selects the optional normal
`flate2 = "1.1"` edge. An unconditional dev-dependency of the same version
keeps reference and test consumers available. The lockfile resolves flate2
1.1.9 to its default `rust_backend`, backed by miniz_oxide 0.8.9,
crc32fast 1.5.0, adler2 2.0.1, and simd-adler32 0.3.10.

There is no C backend, system compression library, native build script, or
host-selected codec in the checked compression profile. Removing flate2 would
not remove crc32fast because the runtime uses it directly. miniz_oxide also
appears under optional backtrace lockfile scope, so the artifact records a
compression-profile delta rather than claiming whole-workspace package
removal.

RCH admitted a clean default check and a clean compression all-target check on
x86_64 Linux. The browser-target attempt stopped because that worker lacked the
Rust target; Apple and Windows were not run. RCH refuses `cargo tree` because
it is not a compilation command, and the remote-only policy forbids local
fallback, so the graph receipt is explicitly a no-claim.

## Exact format scope

Gzip is RFC 1952 and every producer creates one member per logical unit: an
HTTP stream, gRPC message, ATP object or storage chunk, persisted payload, or
OTLP request. The HTTP decoder explicitly rejects concatenated members. Other
read-adapter callers are single-member consumers but do not all prove uniform
trailing-data rejection.

The HTTP `deflate` implementation is raw RFC 1951. The empty stream vector is
`03 00`, and both the implementation and differential tests use
`DeflateEncoder` / `DeflateDecoder`. There is no direct `ZlibEncoder` or
`ZlibDecoder` use and no preset-dictionary API. A source comment says the
stream is zlib wrapped, which disagrees with the shipped bytes. This inventory
freezes the bytes; changing to RFC 1950 needs separate interoperability
authority.

HTTP encoder state persists across input chunks. Gzip and raw-deflate
compression do not force a synchronization flush after every chunk; `finish`
finalizes the stream and is idempotent. The HTTP decoders write and flush each
input chunk, preserve state, finalize on `finish`, enforce caller-selected
output limits, and reject use after an error. gRPC, ATP, persistence, manifest,
and OTLP call sites are one-shot.

## Live owners

The live production inventory is:

- `src/http/compress.rs`: public streaming gzip and raw-deflate codecs;
- `src/grpc/codec.rs`: per-message gzip hooks and framing limits;
- `src/net/atp/transport_common/compression.rs`: public gzip pre-encode policy
  and reversible descriptor with no production transport caller;
- `src/atp/cache/storage.rs`: `ASUPCACHE\0` version 1, codec 1;
- `src/atp/mailbox/storage.rs`: `ASUPMBX1` version 1, compressed flag;
- `src/atp/manifest.rs`: in-memory gzip `CompressionMetadata` calculation;
- `src/observability/otel.rs`: optional gzip OTLP HTTP bodies; and
- the two HTTP middleware consumers in `src/web/`.

The deterministic exporter inside `src/observability/metrics.rs` is test-only.
The similarly named directory `src/net/atp/compress/` remains orphaned: no
module declares it, so its engine and adapters are neither live implementation
nor coverage.

Two adjacent APIs are not flate2 replacement scope. WebSocket builders accept
and retain the `permessage-deflate` extension string but implement no RFC 7692
transform. Kafka exposes `Compression::Gzip`, but librdkafka owns those record
batch bytes and their decode behavior.

## Limits and persisted compatibility

HTTP middleware defaults to a 16 MiB maximum compressed response, while the
streaming types also permit an explicit unlimited `None`. gRPC defaults to a
4 MiB directional message limit and checks both encoded frames and inflated
messages.

ATP transport defaults to a 1024-byte minimum input, 64 bytes of absolute
savings, and 500 basis points of relative savings. Restore validates the
encoded size, declared original size, caller limit, actual output size, and
overflow.

The cache attempts level-6 gzip only above 1024 bytes and retains it only when
the payload plus its 60-byte envelope is smaller. The envelope carries original
and encoded lengths plus a SHA-256 plaintext digest. Its decoder currently
trusts the declared original length for allocation, and raw content that starts
with the full envelope magic has no escaping rule. Mailbox storage applies
level-6 gzip above 1024 bytes per chunk, keeps only smaller output, and then
optionally encrypts it. Its default chunk size is 1 MiB, and the envelope
carries lengths, digest, nonce, and tag. The declared original length is checked
against that chunk size, but `read_to_end` can grow past it before exact length
is rejected.

The manifest does not store compressed bytes. It stores algorithm, level,
original size, compressed size, and ratio, with gzip levels capped at 9 during
the size calculation.

## Payload evidence

The checked repository has deterministic fixtures from empty input through
16 KiB, including tiny expansion cases, repetitive payloads, pseudo-random
payloads, chunk widths of 5/7/10 bytes, gRPC payload fields through 4 KiB, a
7168-byte cache payload, a 10,752-byte ATP transport payload, and a 520-byte
manifest payload.

These are fixture shapes, not a production distribution. There is no checked
histogram for live HTTP, gRPC, ATP, cache, mailbox, or OTLP traffic and no
admitted throughput, latency, ratio, CPU, or memory baseline. The cold remote
compile durations are retained only as proof-lane provenance.

## Evidence conflicts and exit blockers

The capability registry says the baseline is planned, while the capability
baseline artifact says executable complete. The named service scenario is not
registered, and the real-service fixture matrix remains externally blocked.
The registry also omits ATP transport, cache, mailbox, manifest, and OTLP
owners that directly call flate2.

Several files named as real HTTP compression E2E tests are not declared by the
crate and contain stale or simulated transforms. They are source fixtures, not
execution evidence.

Before reconsidering KEEP, a separately approved effort must:

1. adjudicate raw RFC 1951 versus RFC 1950 zlib behavior for the HTTP token;
2. decide zlib-wrapper, dictionary, member, and trailing-data scope;
3. bound cache and mailbox allocation and resolve cache raw-magic collisions;
4. decide whether the unwired ATP transform and WebSocket extension
   advertisement should remain public;
5. preserve all public, wire, persisted, limit, feature-off, and error
   contracts enumerated in the machine artifact;
6. collect real payload distributions and bounded resource/performance
   measurements;
7. run independent producers and consumers through a registered real-service
   scenario on every required platform; and
8. preserve Brotli independently rather than treating DEFLATE parity as a
   substitute.

## Verification

All Cargo validation is remote-only and uses a clean overlay. The focused
contract checks the terminal verdict, manifest/lock resolution, exact owner
set, format and persistence scope, profile receipts, no-claim boundaries,
source hashes, and these runbook markers. Formatting uses standalone
`rustfmt`; JSON syntax uses `jq empty`; whitespace uses `git diff --check`.

## Rollback and no-claim boundary

This bead adds an inventory artifact, contract, runbook, and artifact
allowlist only. Rolling it back means reverting those evidence surfaces. It
does not change production behavior, persisted bytes, or the dependency graph.

The result does not prove release readiness, broad workspace health,
interoperability, production performance, every target, zlib support,
dictionary support, uniform trailing-data handling, owned-codec feasibility,
WebSocket compression, local Kafka gzip behavior, persisted-decoder allocation
safety, or permission to remove either flate2 or Brotli.
