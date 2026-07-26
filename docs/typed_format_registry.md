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
legacy v1/v2 trace into a distinct, non-existing v3 destination. They preserve
event order and count, keep the source untouched as the rollback anchor, reject
an already-current source, and fail if any event lacks a lossless mapping.
`recover_trace_prefix` has an explicit caller event bound and returns
`Complete`, `Partial`, or `LimitReached`; corruption is a terminal receipt and
is never skipped. A partial/limited v3 receipt contains only a structurally
decoded prefix: because v3 authenticates the complete canonical event stream,
only `Complete` is checksum admission.

The maintained no-mock A4 E2E synthesizes exact v2 container framing over the
current replay schema, exercises ordinary and streaming legacy readers,
migrates to v3, preserves the source digest, completes deterministic replay,
and proves a bounded truncated-prefix receipt. This is current migration
evidence, not a committed artifact emitted by an earlier release. There is no
committed prior-release trace, raw replay blob, or streaming trace byte corpus,
so broad historical release readability remains `UNKNOWN_BLOCKING`.

Trace consumers include the ordinary, compatibility, streaming, and integrity
readers; replay/integrity E2E tests; checksum-bearing current-v3 and structured
legacy-v2 fuzz inputs; and trace CLI commands in `src/bin/asupersync.rs`. A
reachable reader or synthesized legacy container is not proof that external
historical bytes were exercised.

### Distributed snapshots

Distributed `RegionSnapshot` bytes use owned `SNAP` framing at exact version
`2`. The vector-clock field uses the `bincode-next` package through the local
`bincode` alias with `bincode::config::legacy()`. The artifact also includes
SHA-256 content integrity and a versioned authentication domain.

The reader enforces owned length bounds and rejects arena indices above
1,000,000 or generations above 10,000 before reconstructing handles.

Current fuzz seeds and textual Insta snapshots are registered. The textual
snapshots are semantic evidence, not raw complete `SNAP` or Bincode byte
goldens. No prior-version reader or version-provenanced raw artifact exists.

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
the cancel-safe atomic write boundary. The byte golden and migration E2E are
current-corpus evidence, not an external historical corpus. See
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
| historical trace/replay/stream corpus | 0 | 0 | missing, blocking |

A current corpus without an emitting release, dependency version, schema
version, and external/downstream provenance cannot be promoted to a historical
compatibility corpus.

## Blocking evidence owners

The registry intentionally keeps three blockers open:

1. `asupersync-5z2scg.3.6` owns version-provenanced byte goldens for typed
   symbols, MessagePack trace/replay, Bincode legacy payloads, and full
   distributed snapshots.
2. `asupersync-5z2scg.3.7` owns no-mock cross-version readers and CLI E2E over
   committed historical artifacts.
3. `asupersync-5z2scg.3.6` owns broad arbitrary-Serde MessagePack/Bincode
   data-model, resource, and downstream-consumer evidence. The current
   standalone Custom injection fixture does not prove generic replacement
   parity.

The external historical-artifact consumer row also remains
`UNKNOWN_BLOCKING`; `.3.7` must close that consumer evidence gap before
historical-readability claims.

These are evidence gaps, not permission to delete the affected surface.

## Validation

The focused contract is
[`tests/typed_format_registry_contract.rs`](../tests/typed_format_registry_contract.rs).
Run it through the remote clean-overlay lane:

```bash
RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay \
  --overlay-path src/trace/file.rs \
  --overlay-path src/trace/compat.rs \
  --overlay-path src/trace/integrity.rs \
  --overlay-path src/trace/mod.rs \
  --overlay-path src/bin/asupersync.rs \
  --overlay-path tests/property_trace_schema.rs \
  --overlay-path tests/replay_e2e_suite.rs \
  --overlay-path tests/trace_file_parsing_property_fuzz.rs \
  --overlay-path fuzz/fuzz_targets/trace_file_parsing.rs \
  --overlay-path fuzz/fuzz_targets/trace_integrity.rs \
  --overlay-path fuzz/fuzz_targets/trace_streaming.rs \
  --overlay-path artifacts/typed_format_registry_v1.json \
  --overlay-path docs/typed_format_registry.md \
  --overlay-path docs/replay-debugging.md \
  --overlay-path tests/typed_format_registry_contract.rs \
  -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  RUSTFLAGS='-D warnings -C debuginfo=0' \
  CARGO_TARGET_DIR="${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_typed_format_registry_a4" \
  cargo test -p asupersync --test typed_format_registry_contract -- --nocapture
```

This proves registry structure, accepted-ADR mapping, live dependency pins,
scan counts, direct backend paths, source pins, corpus aggregates, public
generic invariants, persisted-row completeness, downstream ownership,
fail-closed unknowns, and documentation markers.

It does not execute serialization round trips, fuzzing, migration, historical
readers, CLI E2E, broad workspace tests, benchmarks, release checks, dependency
removal, format removal, or cutover.
