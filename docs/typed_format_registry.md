# Typed format registry

The canonical A1 inventory is
[`artifacts/typed_format_registry_v1.json`](../artifacts/typed_format_registry_v1.json).
It covers `CAP-SERDE-GENERIC` and `CAP-PERSISTED-TRACE-SNAPSHOT` for
`asupersync-5z2scg.3.1`.

This is an evidence registry under accepted
[`DEP-ADR-001`](./adr/dep_plan_adr_001_serde_generic_formats.md), not a new
format decision. The accepted decision remains additive coexistence:

- generic `SerdeCodec` stays on the incumbent JSON, MessagePack, and Bincode
  backends;
- arbitrary downstream `T: Serialize` and `T: DeserializeOwned` stay
  first-class;
- `SerializationFormat::Custom`, byte `255`, and downstream codec injection
  stay public;
- persisted replacement or cutover stays blocked pending evidence.

No row in the registry authorizes removing a dependency, discriminant, public
symbol, reader, artifact, or format.

## How completeness is enforced

The registry combines two coverage mechanisms.

First, it lexically scans every Rust source file in these roots:

`src`, `tests`, `examples`, `benches`, `conformance`,
`asupersync-browser-core`, `asupersync-wasm`, `franken_kernel`,
`franken_evidence`, `franken_decision`, `frankenlab`,
`drop_unwrap_finder`, and `fuzz`.

It pins literal counts for:

- `serde_json::`
- `rmp_serde::`
- `bincode::`
- `SerializationFormat::`
- `SerdeCodec`
- `SerializationFormat::Custom`

Those counts include comments, macros, and inline tests. That makes them a
fail-closed change detector rather than a semantic claim. The contract itself
is excluded from its scan so the baseline does not recursively count its own
implementation.

Second, every production persisted or public/generic use gets an explicit row
with:

- source owner;
- writers and downstream readers;
- exact-byte versus semantic compatibility;
- canonical-order behavior;
- resource bounds;
- version owner;
- public error behavior;
- migration status;
- corpus provenance;
- an evidence state and no-claim boundary.

The broad scan catches a new direct call anywhere. The explicit rows prevent a
high-risk persisted call from hiding behind an aggregate count.

## Compatibility vocabulary

`EXACT_BYTES` means existing accepted bytes remain readability-sensitive.
Changing the encoder, dependency configuration, header, length framing, field
order used as hash input, or backend can be a compatibility break.

`SEMANTIC` means equivalent decoded values are required. JSON whitespace,
object-member order, pretty versus compact output, and backend-specific map
encoding are not implied stable unless a narrower row says otherwise.

`DOWNSTREAM_DEFINED` applies to `SerializationFormat::Custom`. The typed-symbol
envelope is owned by Asupersync; the payload format, payload version, ordering,
and codec resource behavior belong to the injected downstream implementation.

`UNKNOWN_BLOCKING` is not a softer compatibility class. It means design or
cutover must stop until the named owner produces the missing evidence.

## Generic public formats

| Format | Header byte | Generic contract | Persisted concern |
|---|---:|---|---|
| MessagePack | `1` | Semantic arbitrary-Serde round trip through `rmp-serde` | Trace and replay bytes are accepted persisted artifacts |
| Bincode | `2` | Semantic arbitrary-Serde round trip through the `bincode-next` package | Typed payloads and distributed vector clocks use `config::legacy()` |
| JSON | `3` | Semantic arbitrary-Serde round trip through `serde_json` | Versioned JSON families and lab snapshot hash input need surface-specific review |
| Custom | `255` | Downstream `Serializer<T>` / `Deserializer<T>` | Payload compatibility is downstream-defined; the current standalone non-Serde fixture is not broad replacement parity |

`SerdeCodec` intentionally rejects `Custom`. The isolated baseline consumer
implements `Serializer<ConsumerOpaque>` and `Deserializer<ConsumerOpaque>`,
round-trips format byte `255`, rejects malformed input, and fences an explicit
typed-symbol version. That proves the public injection path for one current
non-Serde downstream type. It does not generalize the downstream payload's
ordering, resource, or migration policy.

The generic JSON, MessagePack, and Bincode helpers do not impose a global input
byte limit. A typed-symbol envelope applies its own payload limit, and trace or
snapshot readers apply their own framing and allocation limits. A proposed
replacement must not infer one format-wide resource contract from a bounded
container.

## A6 generic MessagePack/Bincode decision

`asupersync-5z2scg.3.6` evaluates the two binary generic dependencies
independently. Both receive a measured `KEEP` decision:

| Format | Exact incumbent | Decision | Measured ownership surface | Current exact golden |
|---|---|---|---:|---:|
| MessagePack | `rmp-serde 1.3.1` | `KEEP` | 3,207 Rust lines under the crate's `src` tree; direct closure `rmp` and `serde` | 71 bytes |
| Bincode | `bincode-next 3.1.1` with `bincode::config::legacy()` | `KEEP` | 18,992 Rust lines under `src`, including a 1,564-line owned Serde bridge; derive/encoding closure `bincode_derive-next`, `pastey`, `rapidhash`, `serde`, `unty-next`, and `virtue-next` | 102 bytes |

The standalone locked downstream fixture exercises the complete accepted owned
Serde model for both formats: unit and unit structs; newtype, tuple, tuple
struct, and ordinary structs; every enum variant shape; booleans; every signed
and unsigned integer width including 128-bit values; exact-bit `f32` and `f64`
boundaries including negative zero, infinity, and NaN; chars, Unicode strings,
Serde byte buffers, options, sequences, string-key and numeric-key maps, nested
containers, and owned recursion. It also preserves a forced custom-serializer
reason, rejects one-byte truncation, proves recovery on the next decode, records
the incumbent behavior of accepting trailing bytes, and round-trips a 1 MiB
owned byte buffer plus 128 recursive levels.

The current `ConsumerRecord::boundary_fixture()` bytes are pinned as:

- MessagePack:
  `95cfffffffffffffffff81a7426f756e646564cfffffffffffffffff82a0a0a7756e69636f6465ac4772c3bcc39f6520f09fa6809600017fcc80ccfeccffd38000000000000000`
- Bincode legacy:
  `ffffffffffffffff02000000ffffffffffffffff0200000000000000000000000000000000000000000000000700000000000000756e69636f64650c000000000000004772c3bcc39f6520f09fa680060000000000000000017f80feff010000000000000080`

These goldens freeze the current downstream payload under the exact lockfile;
they are not prior-release trace, replay, typed-symbol, or distributed-snapshot
artifacts. `SerdeCodec` requires `DeserializeOwned`, so borrowed output is
outside the public contract. Bincode is not self-describing, so
`deserialize_any` is outside its accepted model. Neither backend canonicalizes
unordered-map iteration, and raw `SerdeCodec` has no global byte or depth cap;
the enclosing persisted containers continue to own those limits.

Full replacement would require differential, property, fuzz, diagnostic,
resource, and downstream ergonomic parity across this entire general-purpose
surface. A finite project-schema codec cannot satisfy that gate. The measured
ownership cost is disproportionate, so the pure-Rust incumbents and their public
`SerializationFormat::{MessagePack,Bincode}` variants remain. A6 changes no
production source, dependency, public variant, discriminant, persisted format,
or migration policy.

## Typed-symbol envelope

The exact typed-symbol header is 27 bytes:

| Offset | Width | Field |
|---:|---:|---|
| 0 | 4 | magic `TSYM` |
| 4 | 2 | schema version, little endian |
| 6 | 8 | type id, little endian |
| 14 | 1 | format discriminant |
| 15 | 8 | schema hash, little endian |
| 23 | 4 | payload length, little endian |

The type id and schema hash depend on Rust `type_name::<T>()`; the schema hash
also includes the declared version. They use SHA-256 with distinct
`asupersync.typed-symbol.*.v1` domain strings. Each input component is framed by
its little-endian `u64` byte length, and the stored `u64` is the first eight
digest bytes interpreted little endian. Typed-symbol-derived object IDs use the
same framing under their own domain and consume the first sixteen digest bytes.
This is deterministic across processes and does not depend on runtime hash-map
seeds. Renaming a type or changing the version can therefore invalidate
existing artifacts even if the Serde data model is unchanged. There is no
registered rename alias or historical generic-payload migrator.

The payload must fit within `DEFAULT_SYMBOL_SIZE - 27` and a `u32` length. The
single-symbol reader requires the envelope length to exactly equal the declared
header plus payload length; truncation and trailing bytes are corruption. The
multi-symbol encoder preserves the total unpadded payload length in every
header, including a one-symbol sentinel for an empty payload, while the RaptorQ
layer owns per-symbol padding and its existing object/block bounds. Empty
sentinels are accepted only as zero-filled source symbol `0:0`; altered padding
or metadata is corruption. The header is canonical. Arbitrary payload maps are
not globally canonical.

`TYPED_SYMBOL_VERSION` selects version `1` by default. Default readers reject
any other version with a typed version-mismatch error. Callers that own another
schema version must select the same explicit version on the encoder and decoder
or on `try_from_symbol_with_version`; version selection never silently falls
back. Unknown format bytes, type IDs, and schema hashes have distinct errors.
`SerializationFormat::{MessagePack,Bincode,Json,Custom}` retain discriminants
`1`, `2`, `3`, and `255`. Custom serializers and deserializers can operate on
non-Serde downstream types through both the single-symbol convenience and
multi-symbol pipelines.

Published v0.3.9 used a different, build-sensitive Rust `TypeId`-based header
identity. The A7 compatibility boundary does not weaken current default
admission. `TypedSymbol::try_from_legacy_symbol` requires an exact
`LegacyTypedSymbolIdentity` tuple—version, type id, and schema hash—from a
trusted release-provenanced manifest. Copying those values from untrusted input
would be self-attestation and is explicitly outside the contract. After
admission, callers decode the generic MessagePack or Bincode payload and write a
separate current stable-header artifact while retaining the v0.3.9 source as the
rollback anchor.

## Persisted surface map

### Trace and replay

The trace stack uses an owned `ASUPERTRACE` container at file version `3` with
MessagePack metadata/events, optional LZ4 chunks, and two SHA-256 integrity
fields. The metadata digest covers its exact MessagePack bytes. The event
digest covers the canonical uncompressed sequence of each little-endian length
prefix followed by its MessagePack event bytes, so ordinary and compressed
readers validate the same logical stream. The current bounds are:

- metadata: 1 MiB;
- event: 16 MiB;
- compressed or declared uncompressed chunk: 64 MiB;
- event preallocation: 10,000,000.

Writers emit only v3. The ordinary, streaming, and integrity readers reject
future or malformed versions and admit the supported v1/v2 container layouts.
The raw-record compatibility inspector admits uncompressed v1/v2/v3 framing
and deliberately rejects compressed input; ordinary `TraceReader` remains the
compression-capable admission path. Embedded replay metadata must exactly match
replay schema version `1`; ordinary reads reject unknown events without
skipping. Diagnostic code can explicitly inspect a rejected raw record through
`CompatReader::read_event_compat`, but that path is not replay admission.

`migrate_trace_file` and `asupersync trace migrate INPUT OUTPUT` stream a
legacy v1/v2 trace into a sibling staging file, sync it, and atomically publish
a distinct, non-existing v3 destination. They preserve event order and count,
keep the source untouched as the rollback anchor, reject an already-current
source, and fail if any event lacks a lossless mapping. Truncation, checksum
failure, output collision, or path/disk failure cannot expose a partial
destination; staging is cleaned after a failed soft operation.
`recover_trace_prefix` has an explicit caller event bound and returns
`Complete`, `Partial`, or `LimitReached`; corruption is a terminal receipt and
is never skipped. A partial/limited v3 receipt contains only a structurally
decoded prefix: because v3 authenticates the complete canonical event stream,
only `Complete` is checksum admission.

The A7 corpus comes from the published `asupersync 0.3.9` writer pinned by tag,
commit, Cargo registry source, and crates.io checksum. It includes an exact
four-event v2 trace, a 4,096-event v2 trace captured as a digest plus locked
writer recipe, and an exact replay-schema-1 MessagePack blob. The committed
typed-symbol headers are immutable captures: their v0.3.9 `TypeId` and
`DefaultHasher` fields are exact evidence for that capture but cannot be
regenerated byte-for-byte in another build. The locked fixture instead masks
only those two documented header fields, proves the remaining framing and
payload stable, and separately admits and decodes the exact committed bytes
with their recorded provenance tuples. All other corpus artifacts regenerate
exactly. The current
ordinary and streaming readers consume the published trace; migration produces
v3 with unchanged event semantics; replay is deterministic; and the current
`info`, `events`, `verify`, `diff`, `migrate`, `export --format ndjson`, and
`compress` CLI paths all execute over the retained fixtures. Malformed headers,
truncation, unknown versions, current checksum corruption, existing output, and
path/disk failure fail closed.

Trace consumers include the ordinary, compatibility, streaming, and integrity
readers; replay/integrity E2E tests; checksum-bearing current-v3 and structured
legacy-v2 fuzz inputs; and trace CLI commands in `src/bin/asupersync.rs`. The A7
evidence proves only the exact pinned v0.3.9 artifacts and recorded semantics,
not every earlier release, arbitrary third-party files, or performance.

### Distributed snapshots

Distributed `RegionSnapshot` bytes use owned `SNAP` framing at exact version
`2`. The vector-clock field uses the `bincode-next` package through the local
`bincode` alias with `bincode::config::legacy()`. The artifact also includes
SHA-256 content integrity and a versioned authentication domain.

The reader enforces owned length bounds and rejects arena indices above
1,000,000 or generations above 10,000 before reconstructing handles.

Current fuzz seeds and textual Insta snapshots remain registered. The A7 corpus
adds a raw published-v0.3.9 empty `SNAP` v2 artifact that the current reader
decodes and reserializes exactly. That boundary case does not prove authenticated
non-empty state or other release versions.

### JSON artifacts

JSON does not have one project-wide compatibility policy. The registry separates
these families:

- trace crash packs;
- ATP crash packs, proof bundles, and evidence ledgers;
- browser trace schemas;
- golden trace reports;
- incident, divergence, and replay reports;
- lab scenario and explorer output;
- `RestorableSnapshot` content-hash input.

Most are semantic JSON contracts. `RestorableSnapshot` is different. It now has
an owned `ASUPSNAP` envelope at version `1`, an inner state schema at version
`2`, deterministic full and incremental payloads, SHA-256 payload integrity,
explicit count/depth/byte limits, and leading `[ASUP-E404]` diagnostics.

The schema-1 legacy JSON reader preserves the original caller-order FNV-1a hash
rule. Schema 2 canonicalizes regions, tasks, task obligation IDs, obligations,
and recent events before hashing and encoding; lifecycle histories retain
recorded order. Migration is explicit and reversible: the original source stays
as the rollback anchor and the migrated target is installed separately through
the cancel-safe atomic write boundary. A7 commits the published-v0.3.9 raw
schema-1 JSON snapshot and proves current decoding, explicit schema-2 promotion,
checksum/version failures, cancellation before atomic commit, disk/path failure,
target preservation, and rollback-source preservation. See
[`runtime_snapshot_codec.md`](./runtime_snapshot_codec.md).

YAML remains an adjacent accepted lab-scenario surface. This registry does not
authorize narrowing scenarios to JSON.

## Corpus register

The contract pins corpus file count, byte count, and an aggregate digest. The
aggregate is the SHA-256 of sorted lines:

```text
<sha256 of file bytes>  <repository-relative path>\n
```

| Corpus | Files | Bytes | Classification |
|---|---:|---:|---|
| typed-symbol parser fuzz corpus | 28 | 667 | current parser corpus only |
| distributed-snapshot fuzz seeds | 5 | 278 | current malformed/boundary corpus only |
| distributed-snapshot Insta snapshots | 8 | 32,955 | semantic current snapshots |
| crashpack-to-repro fixtures | 10 | 21,599 | semantic current fixtures |
| published v0.3.9 typed-format corpus | 1 | 6,617 | immutable version-provenanced capture plus locked reproducibility recipe and build-sensitive typed-header boundary |

A current corpus without an emitting release, dependency version, schema
version, and external/downstream provenance cannot be promoted to a historical
compatibility corpus.

## Blocking evidence owners

A6 closes the arbitrary-Serde MessagePack/Bincode evidence gap with independent
`KEEP` receipts, current payload goldens, and the locked downstream fixture.
A7 closes its two historical-evidence blockers with the published v0.3.9 corpus,
locked dual-version writer/reader fixture, and the canonical no-mock current CLI
journey. The external historical-artifact consumer is therefore
`HISTORICAL_CORPUS_VERIFIED` for `asupersync-5z2scg.3.7`.

This is evidence closure, not cutover authority. The registry still records
`persisted_cutover_state: BLOCKED_PENDING_EVIDENCE`; A5 owns the aggregate
same-or-better decision and may still emit `KEEP`. The A7 corpus proves only its
exact pinned release, artifacts, boundary payloads, semantics, and tool paths.

These scoped evidence receipts are not permission to delete an affected surface.

## Validation

The focused contract is
[`tests/typed_format_registry_contract.rs`](../tests/typed_format_registry_contract.rs).
Run it through the remote clean-overlay lane:

```bash
RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay \
  --overlay-path tests/fixtures/dependency-capability-baseline-consumer/src/lib.rs \
  --overlay-path tests/fixtures/dependency-capability-baseline-consumer/Cargo.lock \
  --overlay-path src/types/typed_symbol.rs \
  --overlay-path src/types/mod.rs \
  --overlay-path src/trace/file.rs \
  --overlay-path tests/fixtures/typed-format-cross-version-consumer/Cargo.toml \
  --overlay-path tests/fixtures/typed-format-cross-version-consumer/Cargo.lock \
  --overlay-path tests/fixtures/typed-format-cross-version-consumer/src/lib.rs \
  --overlay-path tests/fixtures/typed-format-cross-version-consumer/src/bin/capture.rs \
  --overlay-path tests/fixtures/typed-format-historical-corpus/v0.3.9.json \
  --overlay-path tests/typed_format_cross_version_e2e.rs \
  --overlay-path scripts/run_dependency_sovereignty_e2e.sh \
  --overlay-path artifacts/typed_format_registry_v1.json \
  --overlay-path docs/typed_format_registry.md \
  --overlay-path tests/typed_format_registry_contract.rs \
  -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  RUSTFLAGS='-D warnings -C debuginfo=0' \
  CARGO_TARGET_DIR="${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_typed_format_registry_a7" \
  cargo test -p asupersync --test typed_format_registry_contract -- --nocapture
```

This proves registry structure, accepted-ADR mapping, live dependency pins,
scan counts, direct backend paths, source pins, corpus aggregates, public
generic invariants, independent binary-format `KEEP` receipts, exact current
payload goldens and fixture markers, persisted-row completeness, downstream
ownership, published-v0.3.9 provenance/byte-manifest structure, resolved A7
blockers, and documentation markers.

It does not execute serialization round trips, fuzzing, migration, historical
readers, CLI E2E, broad workspace tests, benchmarks, release checks, dependency
removal, format removal, or cutover.
