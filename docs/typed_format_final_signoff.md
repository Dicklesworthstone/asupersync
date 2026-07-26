# Typed-Format Terminal Signoff

This is the operator guide for `asupersync-5z2scg.3.5`. The checked machine
packet is
[`artifacts/typed_format_final_signoff_v1.json`](../artifacts/typed_format_final_signoff_v1.json),
and its focused verifier is
[`tests/typed_format_final_signoff_contract.rs`](../tests/typed_format_final_signoff_contract.rs).

The terminal verdict is
`KEEP_INCUMBENTS_WITH_SCOPED_PERSISTED_PARITY`. It satisfies the typed-format
terminal node with an explicit per-codec decision. It does not authorize a
dependency or format cutover.

## Decision

| Capability or backend | Verdict | Reason |
|---|---|---|
| `CAP-SERDE-GENERIC` | `KEEP_INCUMBENT` | A finite project schema cannot replace unrestricted downstream Serde values, visitors, diagnostics, resource behavior, and custom codec injection. |
| `rmp-serde 1.3.1` | `KEEP` | The locked fixture preserves the accepted generic MessagePack model and exact current golden; no owned replacement establishes complete parity. |
| `bincode-next 3.1.1` | `KEEP` | The generic model and `bincode::config::legacy()` persisted-byte contract remain required; no owned replacement establishes complete parity. |
| `CAP-PERSISTED-TRACE-SNAPSHOT` | `PASS_SCOPED_ADDITIVE_OWNERSHIP_KEEP_BACKENDS` | Current schemas and the exact published-v0.3.9 corpus pass migration, replay, CLI, malformed-input, atomicity, and rollback evidence without replacing generic backends. |

`SerializationFormat::{MessagePack,Bincode,Json,Custom}`, their discriminants,
`SerdeCodec`, and downstream `Serializer<T>` / `Deserializer<T>` injection all
remain public. `Cargo.toml` and `Cargo.lock` retain both binary incumbents at
their checked versions and checksums.

## Evidence join

The signoff joins the six closed evidence children:

- A1: row-level registry, source pins, corpus inventory, and fail-closed
  evidence states;
- A2: deterministic bounded typed-symbol framing and explicit version
  admission;
- A3: versioned `ASUPSNAP` full/incremental artifacts, legacy promotion,
  integrity, limits, cancellation-safe publication, and rollback;
- A4: checksummed trace v3, legacy trace migration, bounded streaming, and
  deterministic replay;
- A6: independent MessagePack and Bincode `KEEP` receipts with a locked
  arbitrary-Serde downstream fixture and exact current payload goldens;
- A7: a locked published-v0.3.9/current dual-version fixture plus the current
  migration, replay, trace CLI, malformed, cancellation, disk-failure,
  atomicity, cleanup, and rollback journey.

Every source contract in the machine packet is content-pinned by SHA-256. The
focused verifier also reads `.beads/issues.jsonl` and refuses signoff if a child
is not closed.

## Registry reconciliation

The terminal packet requires the live registry to retain:

- 4 format profiles;
- 13 persisted/tool surfaces;
- 6 downstream consumers;
- 5 corpora;
- 2 independent generic dependency decisions;
- 48 source pins; and
- 3 direct production backend files.

Seven persisted/tool rows have exact pinned historical evidence, five are
current-corpus only, and one remains a baseline surface. Every row must retain
a non-empty evidence state and an explicit no-claim boundary. Current-only
evidence is never promoted to historical proof.

That partition matters. The published-v0.3.9 corpus proves its exact artifacts
and semantics, not every old release or arbitrary third-party data. The
current-only JSON families remain accepted and supported, but they do not
become replacement evidence merely because the binary paths are stronger.

## Fuzz and replacement boundary

The registry and source tree retain bounded fuzz assets for typed symbols,
trace files, trace streaming, replay events, trace integrity, restorable
snapshots, and distributed snapshots. Several semantic JSON families remain
focused-test/current-corpus only.

That is an `EXPLICIT_KEEP_BLOCKER`, not a green result. A `REPLACE` verdict
would require a complete differential, property, bounded-fuzz,
diagnostic, resource, downstream, historical, migration, graph, and rollback
packet for the affected backend. A5 therefore emits `KEEP`; it does not paper
over the missing replacement-grade evidence.

## Rollback

No manifest rollback is needed because A5 changes no dependency, feature,
public variant, discriminant, or production backend.

Artifact migration retains a stronger rule: the source remains untouched as
the rollback anchor, a distinct target is staged and atomically published, an
existing destination is refused, and failed staging files are cleaned. A
future replacement proposal must produce a new terminal receipt against fresh
registry, graph, corpus, downstream, and rollback evidence.

## Canonical validation

Run the focused structural contract through an exact clean overlay:

```bash
RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay \
  --overlay-path artifacts/typed_format_final_signoff_v1.json \
  --overlay-path docs/typed_format_final_signoff.md \
  --overlay-path docs/typed_format_registry.md \
  --overlay-path tests/typed_format_final_signoff_contract.rs \
  --overlay-path scripts/run_dependency_sovereignty_e2e.sh \
  -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  RUSTFLAGS='-D warnings -C debuginfo=0' \
  CARGO_TARGET_DIR="${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_typed_format_final_signoff" \
  cargo test -p asupersync --test typed_format_final_signoff_contract -- --nocapture
```

After committing the exact source state, run the canonical terminal scenario:

```bash
RCH_REQUIRE_REMOTE=1 DEPENDENCY_SOVEREIGNTY_TIMEOUT=1200 \
  bash scripts/run_dependency_sovereignty_e2e.sh \
    --scenario dep-sovereignty-asupersync_5z2scg_3_5_66765b43947e
```

The scenario executes the locked arbitrary-Serde/custom-codec downstream
fixture, the locked published-v0.3.9/current fixture, and the typed registry,
runtime snapshot, replay, cross-version CLI, and terminal signoff tests. It
retains the dependency-sovereignty summary, NDJSON, per-step logs, environment,
RCH worker, feature, cleanup, and exact replay command receipts.

## No-claim boundary

This signoff proves checked child closure, source-pin integrity, registry-row
reconciliation, live Cargo/lock/public-surface preservation, independent
per-codec `KEEP` decisions, scoped published-v0.3.9 migration/replay/CLI
evidence, explicit replacement gaps, and rollback policy.

It does not authorize dependency removal, format removal, public/API/feature/
protocol/diagnostic narrowing, or deletion of artifacts. It does not prove
arbitrary historical compatibility, unordered-map byte canonicality,
borrowed-output or `deserialize_any` support, a global raw-codec resource
bound, performance improvement, no regression, release readiness, broad
workspace health, live RCH fleet availability, or local Cargo fallback.
