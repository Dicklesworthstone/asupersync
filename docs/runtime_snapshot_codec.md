# Runtime snapshot codec

The owned runtime-state artifact is a versioned `ASUPSNAP` envelope implemented
by `src/lab/snapshot_restore.rs`. It preserves every field in
`RuntimeSnapshot`:

- timestamp;
- regions, tasks, and obligations;
- recent trace events;
- finalizer lifecycle history;
- loser-drain history.

This artifact is additive. It does not replace or reinterpret the distributed
`SNAP` version 2 format in `src/distributed/snapshot.rs`, trace files, replay
blobs, or the generic JSON, MessagePack, Bincode, and Custom typed-symbol
formats.

## Envelope version 1

Every newly encoded artifact has a fixed 52-byte header:

| Offset | Width | Field |
|---:|---:|---|
| 0 | 8 | ASCII magic `ASUPSNAP` |
| 8 | 2 | envelope version `1`, little endian |
| 10 | 1 | kind: `0` full, `1` incremental |
| 11 | 1 | reserved flags, currently exactly `0` |
| 12 | 8 | payload byte length, little endian |
| 20 | 32 | SHA-256 of the exact payload bytes |
| 52 | variable | compact JSON payload |

The decoder rejects unknown magic, unsupported versions or kinds, non-zero
flags, integer overflow, truncation, trailing bytes, checksum mismatch, and
malformed JSON. Every public codec diagnostic starts with `[ASUP-E404]` and is
documented in the error-code registry.

`SNAPSHOT_ARTIFACT_VERSION` versions the outer envelope. The inner
`RestorableSnapshot::SCHEMA_VERSION` versions runtime-state meaning. They are
independent compatibility boundaries.

## State schema and deterministic bytes

Schema version 2 is the current state schema. The reader's supported state
schema window is `[1, 2]`.

Schema version 1 is the legacy raw-JSON representation. Its FNV-1a content hash
includes the schema version and the original caller-provided vector order.
That rule is retained exactly so existing schema-1 JSON can still be validated.

Schema version 2 canonicalizes before hashing and encoding:

- regions by `(index, generation)`;
- tasks by `(index, generation)`;
- every task's obligation IDs by `(index, generation)`;
- obligations by `(index, generation)`;
- recent events by `(sequence, time, event schema version)`.

Finalizer and loser-drain histories remain in their recorded order because the
order is part of their lifecycle and oracle meaning. JSON struct field order is
frozen by the schema-2 byte golden. The outer SHA-256 authenticates payload
bytes; the inner FNV-1a hash identifies state for compatibility and
incremental-base fencing.

## Full and incremental artifacts

A full artifact carries one complete `RestorableSnapshot`.

An incremental artifact identifies its required base by the base content hash
and carries:

- target schema version, target content hash, and target timestamp;
- sorted region, task, and obligation upserts;
- sorted region, task, and obligation removals;
- the complete target recent-event window;
- the complete target finalizer history;
- the complete target loser-drain history.

Entity tables use keyed upserts/removals. Ordered histories are replaced as
whole values instead of using order-sensitive splice instructions. Applying a
delta requires an explicit base, rejects a mismatched base hash, canonicalizes
the result, recomputes the target hash, and then runs structural and resource
validation. A delta therefore cannot silently attach to a different snapshot.

## Admission limits

`SnapshotLimits::DEFAULT` admits at most:

| Resource | Limit |
|---|---:|
| complete artifact | 64 MiB |
| regions | 1,000,000 |
| tasks | 1,000,000 |
| obligations | 1,000,000 |
| recent events | 10,000,000 |
| finalizer history records | 1,000,000 |
| loser-drain history records | 1,000,000 |
| region-tree depth | 4,096 |

The complete-byte limit is checked before JSON decoding. Collection limits are
checked after decoding, and complete state plus depth limits are checked again
after incremental materialization. Callers may supply a narrower
`SnapshotLimits` value.

## Reversible migration and atomic installation

Legacy input is detected only when the first non-whitespace byte is `{`.
The reader parses and validates that input using the schema-1 hash rule. It does
not silently rewrite or promote the state. `migrate_to_current` is the explicit
boundary that produces canonical schema-2 state.

A migration operator must:

1. read and retain the original bytes or source path as the rollback anchor;
2. decode, validate, and explicitly migrate the source;
3. encode a full schema-2 `ASUPSNAP` artifact;
4. install it at a distinct target through `asupersync::fs::write_atomic`;
5. reopen and validate the installed artifact before changing any external
   pointer to it.

The codec owns bytes and validation; the existing filesystem primitive owns
cancel-safe staging and atomic replacement. Cancellation before its commit
boundary leaves the prior target intact. The source is never deleted or
rewritten by this workflow. Partial and corrupt inputs are rejected before
installation.

## Proof lane

The focused no-mock E2E covers the fixed byte golden, legacy schema-1 read and
explicit migration, full and incremental state equivalence, every top-level
runtime snapshot field, property-generated ordering/delta cases, malformed and
bounded inputs, rollback-source preservation, partial/corrupt files, and
deterministic cancellation at the atomic-write staging boundary.

```bash
RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay \
  --overlay-path src/lab/snapshot_restore.rs \
  --overlay-path src/lab/mod.rs \
  --overlay-path tests/runtime_snapshot_codec_e2e.rs \
  -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  RUSTFLAGS='-D warnings -C debuginfo=0' \
  CARGO_TARGET_DIR="${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_snapshot_codec_a3_e2e" \
  cargo test -p asupersync --test runtime_snapshot_codec_e2e \
    --features test-internals -- --nocapture
```

This lane does not prove an external historical corpus, trace/replay migration,
distributed `SNAP` compatibility, performance improvement, broad workspace
health, dependency or format removal, production cutover, or the A7
cross-version CLI suite. Generic codecs remain KEEP under `DEP-ADR-001`.
