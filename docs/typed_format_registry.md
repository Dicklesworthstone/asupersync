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
| Custom | `255` | Downstream `Serializer<T>` / `Deserializer<T>` | Payload compatibility is downstream-defined; no real standalone codec fixture exists |

`SerdeCodec` intentionally rejects `Custom`. That establishes the division of
responsibility but does not prove custom-codec interoperability.

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
also includes the declared version. Renaming a type or changing the version can
therefore invalidate existing artifacts even if the Serde data model is
unchanged. There is no registered rename alias or historical generic-payload
migrator.

The payload must fit within `DEFAULT_SYMBOL_SIZE - 27` and a `u32` length. The
header is canonical. Arbitrary payload maps are not globally canonical.

## Persisted surface map

### Trace and replay

The trace stack uses an owned `ASUPERTRACE` container at file version `2` with
MessagePack metadata/events and optional LZ4 chunks. The current bounds are:

- metadata: 1 MiB;
- event: 16 MiB;
- compressed or declared uncompressed chunk: 64 MiB;
- event preallocation: 10,000,000.

The container reader rejects future file versions but admits older container
versions. Embedded replay metadata must exactly match replay schema version
`1`. The compatibility module has migration architecture, but its minimum
supported replay schema currently equals the current schema. There is no
committed prior-release trace, raw replay blob, or streaming trace byte corpus.
Accordingly, historical readability and migration remain
`UNKNOWN_BLOCKING`.

Trace consumers include the ordinary, compatibility, streaming, and integrity
readers; replay/integrity E2E tests; fuzz targets; and trace CLI commands in
`src/bin/asupersync.rs`. A reachable reader is not proof that historical bytes
were exercised.

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

Most are semantic JSON contracts. `RestorableSnapshot` is different:
`serde_json::to_vec` output is fed byte-by-byte into its FNV-1a content hash.
That makes field order and JSON byte production compatibility-sensitive even
though no standalone JSON snapshot file is exposed. Adding an unordered
container there requires explicit canonicalization or a version/migration
decision.

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

The registry intentionally keeps four blockers open:

1. `asupersync-5z2scg.3.6` owns version-provenanced byte goldens for typed
   symbols, MessagePack trace/replay, Bincode legacy payloads, and full
   distributed snapshots.
2. `asupersync-5z2scg.3.7` owns no-mock cross-version readers and CLI E2E over
   committed historical artifacts.
3. `asupersync-5z2scg.3.3` owns a real standalone downstream custom codec and
   broad arbitrary-Serde data-model/resource evidence.
4. External historical artifact consumers have no current receipt or owner;
   `.3.7` must close that gap before historical-readability claims.

These are evidence gaps, not permission to delete the affected surface.

## Validation

The focused contract is
[`tests/typed_format_registry_contract.rs`](../tests/typed_format_registry_contract.rs).
Run it through the remote clean-overlay lane:

```bash
RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay \
  --overlay-path artifacts/typed_format_registry_v1.json \
  --overlay-path docs/typed_format_registry.md \
  --overlay-path tests/typed_format_registry_contract.rs \
  -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  RUSTFLAGS='-D warnings -C debuginfo=0' \
  CARGO_TARGET_DIR="${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_typed_format_registry_a1" \
  cargo test -p asupersync --test typed_format_registry_contract -- --nocapture
```

This proves registry structure, accepted-ADR mapping, live dependency pins,
scan counts, direct backend paths, source pins, corpus aggregates, public
generic invariants, persisted-row completeness, downstream ownership,
fail-closed unknowns, and documentation markers.

It does not execute serialization round trips, fuzzing, migration, historical
readers, CLI E2E, broad workspace tests, benchmarks, release checks, dependency
removal, format removal, or cutover.
