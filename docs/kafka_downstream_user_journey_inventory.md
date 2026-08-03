# Kafka downstream and user-journey inventory

<!-- BEGIN KAFKA K0.3 DOWNSTREAM INVENTORY -->

This document is the human companion to
`artifacts/kafka_downstream_user_journey_inventory_v1.json`. It freezes the
repository-local, static K0.3 census for
`asupersync-dep-p7-kafka-removal-sarszu.1.3` at revision
`ae22e710d87412b38e546b32e9702106619481d5`.

The result is conservative: the incumbent remains `KEEP_INCUMBENT` under
`KEEP_UNTIL_PARITY`. Local absence, stale tests, and unrun external searches do
not permit removal of `rdkafka`, `librdkafka`, the `kafka` feature, public API,
behavior, capability, or files.

## Authority

<!-- KAFKA-K0-3-AUTHORITY -->

| Coordinate | Owner or state |
|---|---|
| Capability | `CAP-KAFKA` |
| K0.1 source inventory | `asupersync-dep-p7-kafka-removal-sarszu.1.1` |
| K0.2 semantic inventory | `asupersync-dep-p7-kafka-removal-sarszu.1.2` |
| K0.3 downstream inventory | `asupersync-dep-p7-kafka-removal-sarszu.1.3` |
| K0.4 broker provenance | `asupersync-dep-p7-kafka-removal-sarszu.1.4` |
| K0.5 terminal inventory | `asupersync-dep-p7-kafka-removal-sarszu.1.5` |
| Downstream docs implementation | `asupersync-dep-p7-kafka-removal-sarszu.2.10.5` |
| Verification/oracle | `asupersync-dep-p7-kafka-removal-sarszu.2.12.5` |
| Real-broker E2E | `asupersync-dep-p7-kafka-removal-sarszu.2.13.6` |
| Claim-time refresh | `asupersync-dep-p7-kafka-removal-sarszu.2.14.1` |
| Conditional cutover | `asupersync-dep-p7-kafka-removal-sarszu.2.15` |
| Current action | `KEEP_INCUMBENT` |
| Migration eligible | No |
| Static receipt state | Live-filesystem occurrence receipt; not yet a complete Git-tree receipt |

K0.1 owns source reachability and K0.2 owns semantics. K0.3 joins those
authorities to local consumers, documentation, examples, fixtures, compilation
profiles, platform cells, and user journeys. It does not replace either
upstream inventory.

Evidence classification has independent dimensions. `WIRED`, `NOT_RUN`,
`REAL_BROKER_CAPABLE`, and `CURRENT_SOURCE_PINNED` can all describe the same
row. Keeping them separate prevents a wired target from becoming broker proof
merely because its source exists.

## Repository-local census

<!-- KAFKA-K0-3-LOCAL-CENSUS -->

The current case-insensitive path-or-content receipt covers 245 live-workspace
paths under its declared roots. Its sorted newline path-map SHA-256 is
`9c815cfcba11f5345e7abced6b0afa21bfb650f9bb280e71bb3da74ebbb55089`.
Control roots, peer scratch paths, build output, and this packet's three files
are explicitly excluded.

This occurrence receipt is not a Git-tree census at the baseline revision. The
current verifier walks the live filesystem, and its declared roots omit
`examples/`. Untracked files can therefore enter the live set, tracked files
missing from the workspace can disappear, and the receipt cannot establish a
tracked-example absence. `CURRENT_SOURCE_PINNED` remains valid only for the
individually hashed source pins. A terminal refresh must enumerate the exact
baseline Git tree, materialize the path-to-disposition map, and include
`examples/` and its metadata.

The unchanged machine packet currently has 61 byte-and-record-count source
pins, 25 file-level local inventory rows, 13 documentation-claim groups, 17
compilation profiles, eight platform/feature cells, and 12 user journeys.
Those are machine-snapshot counts, not a terminal completeness claim. Static
review identified the atomic cases and additional claim groups below. Until
the machine packet and contract carry the same stable IDs and joins, their
coverage receipt remains non-terminal.

### Public topology

The public native modules are not gated by the Kafka feature. Without the
feature, the first-party facade remains visible and broker operations fail
closed. With the feature, private backend fields and operations select
`rdkafka`. On wasm, the messaging module is absent without Kafka and forcing
Kafka is a declared compile error.

The K0.1 join covers all 30 public-symbol groups. The K0.2 join covers all 97
semantic rows. Symbols and semantics referenced by detailed local rows are
classified as local use, documentation-only use, or fixture-only use. Every
remaining row is explicitly subject to claim-time consumer synthesis; it does
not disappear from the inventory and cannot become removal evidence.

### Root tests are not ordinary downstream builds

Root integration tests gain `test-internals` through the root dev-dependency on
the conformance crate and the conformance crate's dependency back on
asupersync. Consequently, a root test that uses deterministic builders or test
utilities is a root-internal profile, not proof of what an independent default
consumer can compile.

The separate workspace at
`tests/fixtures/downstream-consumer-proof/Cargo.toml` is the maintained external
fixture. Its Kafka test covers only the default, no-Kafka, fail-closed producer
boundary. The mapped proof status is `yellow_frontier` / `rerun-required`.
There is no maintained feature-enabled Kafka compile or runtime target in that
fixture.

The separate
`tests/fixtures/dependency-capability-baseline-consumer/` workspace is also not
Kafka evidence. Its feature table and source contain no Kafka feature or public
Kafka API use even though generic dependency-verification planning can point
Kafka-family work at that fixture. This planned/mismatched boundary is
`KAFKA-K0-3-FIX-002`, `PLANNED`, `NOT_RUN`, and owned by
`asupersync-dep-p7-kafka-removal-sarszu.2.14.1`.

### Active local surfaces

| Surface | Wiring | Current evidence | Important boundary |
|---|---|---|---|
| Offset conformance | Wired | Mixed: deterministic no-feature plus real-backend-capable feature paths; not run here | Feature-enabled relations force the real backend against ambient localhost and can return early |
| Broker-parity conformance | Wired | Default gate and diagnostic only | No live Kafka broker journey |
| Messaging E2E producer/consumer | Wired | Real-broker capable, not run | Ambient/default endpoint; no immutable fixture |
| T6 DP-14 | Wired test source | Real-broker capable, not run | Canonical T6 runner does not enable Kafka |
| `kafka_real_broker` | Explicit Cargo target | Real-broker capable, not run | Opt-in gate and successful skip paths |
| Offset property/retry audits | Wired | Deterministic/source-only | Not broker semantics |
| Producer fail-closed audit | Wired and reused by external fixture | Default-feature boundary | No feature-enabled backend |
| SASL audit | Wired | Synthetic/error mapping | No authenticated broker |
| Compression test | Wired | Configuration-only | No wire, codec, deterministic-broker, or real-broker round trip |
| Rebalance lifecycle | Wired | Broker intent, not run | Returns successfully when setup fails; no-feature branch is a sentinel |
| T6 and migration matrices | Wired | Config/error/source checks | No broker |
| RecordBatch and parser suites | Wired or declared | Wire-codec only | A codec is not a client |

The explicit `kafka_real_broker` target contains real producer, consumer,
transaction, rebalance, recovery-shaped, payment, and replay scenarios. Seven
named broker tests return successfully when `REAL_KAFKA_TESTS` is absent. The
proof helpers can also record skip outcomes, and successful source paths can
retain broker version `unknown`. The source is therefore
`REAL_BROKER_CAPABLE`, not a `REAL_BROKER_RECEIPT`.

#### Atomic broker and E2E cases

The file-level broker and E2E rows are source groups, not atomic test receipts.
The human inventory assigns these stable case IDs; every case is `NOT_RUN` in
this packet and requires machine-artifact reconciliation:

| Stable ID | Source case | Journey links | Evidence/disposition | Owner |
|---|---|---|---|---|
| `KAFKA-K0-3-CASE-001` | `tests/integration/kafka_real_broker.rs:1095`, producer delivery metadata | produce | `REAL_BROKER_CAPABLE` / `BLOCKED` | `asupersync-dep-p7-kafka-removal-sarszu.2.13.6` |
| `KAFKA-K0-3-CASE-002` | `:1170`, produce-consume round trip | produce, consume-group, real-broker-proof | `REAL_BROKER_CAPABLE` / `BLOCKED` | `asupersync-dep-p7-kafka-removal-sarszu.2.13.6` |
| `KAFKA-K0-3-CASE-003` | `:1306`, exactly-once transaction | transaction, real-broker-proof | `REAL_BROKER_CAPABLE` / `BLOCKED` | `asupersync-dep-p7-kafka-removal-sarszu.2.13.6` |
| `KAFKA-K0-3-CASE-004` | `:1401`, group rebalance | consume-group, rebalance, real-broker-proof | `REAL_BROKER_CAPABLE` / `BLOCKED` | `asupersync-dep-p7-kafka-removal-sarszu.2.13.6` |
| `KAFKA-K0-3-CASE-005` | `:1489`, recovery-shaped load | broker-recovery, real-broker-proof | `REAL_BROKER_CAPABLE` / `OVERCLAIM`; no broker restart | `asupersync-dep-p7-kafka-removal-sarszu.2.13.6` |
| `KAFKA-K0-3-CASE-006` | `:1590`, payment delivery | payment-delivery, produce, consume-group | `REAL_BROKER_CAPABLE` / `BLOCKED` | `asupersync-dep-p7-kafka-removal-sarszu.2.13.6` |
| `KAFKA-K0-3-CASE-007` | `:1755`, close-without-commit replay | replay-without-commit, consume-group | `REAL_BROKER_CAPABLE` / `BLOCKED` | `asupersync-dep-p7-kafka-removal-sarszu.2.13.6` |
| `KAFKA-K0-3-CASE-008` | `tests/e2e_messaging.rs:401-492`, consumer lifecycle case | consume-group | `REAL_BROKER_CAPABLE` / `BLOCKED`; ambient endpoint | `asupersync-dep-p7-kafka-removal-sarszu.2.13.6` |
| `KAFKA-K0-3-CASE-009` | `tests/e2e_messaging.rs:401-492`, producer acknowledgement case | produce | `REAL_BROKER_CAPABLE` / `BLOCKED`; ambient endpoint | `asupersync-dep-p7-kafka-removal-sarszu.2.13.6` |

#### Atomic offset cases

The offset source mixes a deterministic feature-disabled boundary with a
feature-enabled `force_real_kafka(true)` path. It is therefore not globally
`DETERMINISTIC_ONLY`:

| Stable ID | Source case | Journey links | Evidence/disposition | Owner |
|---|---|---|---|---|
| `KAFKA-K0-3-CASE-010` | `tests/conformance/kafka_offsets.rs:84`, no-feature consumer boundary | feature-disabled | `DETERMINISTIC_ONLY` / `CURRENT` | `asupersync-dep-p7-kafka-removal-sarszu.2.12.5` |
| `KAFKA-K0-3-CASE-011` | `:158`, MR1 monotonic commits | consume-group | `REAL_BROKER_CAPABLE` / `CURRENT` | `asupersync-dep-p7-kafka-removal-sarszu.2.12.5` |
| `KAFKA-K0-3-CASE-012` | `:249`, MR2 idempotent commit | consume-group | `REAL_BROKER_CAPABLE` / `CURRENT` | `asupersync-dep-p7-kafka-removal-sarszu.2.12.5` |
| `KAFKA-K0-3-CASE-013` | `:322`, MR3 retention | consume-group | `REAL_BROKER_CAPABLE` / `OVERCLAIM`; no expiry proof | `asupersync-dep-p7-kafka-removal-sarszu.2.12.5` |
| `KAFKA-K0-3-CASE-014` | `:402`, MR4 rebalance preservation | consume-group, rebalance | `REAL_BROKER_CAPABLE` / `CURRENT` | `asupersync-dep-p7-kafka-removal-sarszu.2.12.5` |
| `KAFKA-K0-3-CASE-015` | `:490`, MR5 transactional wording | consume-group, transaction | `REAL_BROKER_CAPABLE` / `OVERCLAIM`; ordinary commits only | `asupersync-dep-p7-kafka-removal-sarszu.2.12.5` |
| `KAFKA-K0-3-CASE-016` | `:621`, aggregate relations | consume-group | `REAL_BROKER_CAPABLE` / `OVERCLAIM`; successful skip is possible | `asupersync-dep-p7-kafka-removal-sarszu.2.12.5` |

The canonical real-service matrix is authoritative for current fixture
readiness. Its oldest-supported plaintext, newest-supported plaintext, and
SASL/TLS Kafka cells are all `BLOCKED_EXTERNAL`: the repository names mutable
container tags, permits ambient bootstrap endpoints, and has no approved
version/security range or immutable service identity.

### Dormant and simulated sources

Four tracked `src/real_*kafka*` files and `src/subsystem_mutation_testing.rs`
have no crate-module or Cargo-target wiring:

- `src/real_http_h2_server_messaging_kafka_e2e_tests.rs` uses a local
  deterministic producer model.
- `src/real_kafka_consumer_group_rebalance_e2e_tests.rs` models subscription,
  fetch, and rebalance and imports Tokio.
- `src/real_messaging_kafka_trace_event_integration_e2e_tests.rs` uses stale
  Kafka and trace API names.
- `src/real_net_tls_connector_messaging_kafka_integration_e2e_tests.rs` uses
  stale Kafka/TLS API names and a simulated rekey path.
- `src/subsystem_mutation_testing.rs` uses nonexistent Kafka facade names and
  stale builders.

These rows are `UNWIRED`, `STALE`, `NOT_RUN`, and
`MOCK_OR_SIMULATED`. Their filenames and comments are not evidence.

Pure Kafka models in the messaging metamorphic/conformance files, Kafka-named
OpenTelemetry attributes, standalone RecordBatch code, parser targets, policy
artifacts, and snapshots are also not incumbent-client consumers. They remain
visible through explicit non-consumer dispositions.

### Examples and documentation

There is no tracked Kafka or rdkafka use under `examples/`. The reference-app
template and Wave 2 example evidence both describe a future real-broker recipe;
the evidence row has an empty example path and an unsupported/pending verdict.
That is a synthesis gap, not deletion evidence.

Current, source-pinned documentation includes the optional-feature status,
`KEEP_INCUMBENT` policy, `RERUN_REQUIRED` compile profiles, and
`BLOCKED_EXTERNAL` service cells. The census also routes these stale or
historical claims:

- `src/messaging/kafka_consumer.rs` names nonexistent singular
  `commit_offset`; the method is `commit_offsets`.
- The compression file calls configuration checks a broker/wire round trip.
- The rebalance file documents a no-feature deterministic flow and environment
  variable its code does not implement.
- The real-broker README makes broad lifecycle, CI, security, and performance
  claims without an immutable retained receipt.
- HTTP/H2 Kafka documentation calls an unwired deterministic model authentic
  integration.
- T6 documentation calls DP-14 enforced although the canonical runner enables
  only database features.
- The Tokio T6 migration pack uses a stale transactional constructor.
- The database/messaging migration contract omits current `Cx` arguments and
  awaits and uses stale aliases and signatures.
- RecordBatch vectors claim librdkafka provenance without immutable metadata;
  one vector source describes bytes as still to be filled.
- The SASL audit reimplements a local classifier instead of exercising the
  private backend mapper.
- Older gap, retry, readiness, interop, limitation, and security documents are
  stale or explicitly historical. Their old versions, error counts,
  source anchors, PASS scores, and performance claims do not override the
  current blocked baseline.

## Compilation profiles and platform cells

<!-- KAFKA-K0-3-COMPILE-CELLS -->

All 13 K0.1 profiles are mapped exactly once, then augmented with the external
default fixture, sparse-Kafka matrix profile, Kafka-plus-test-internals no-run
profile, and the root-integration dev-cycle profile.

| Coordinate | Current evidence state |
|---|---|
| Linux sparse Kafka compile | `RERUN_REQUIRED` |
| Linux Kafka + test-internals no-run | `RERUN_REQUIRED`; compile-only by definition |
| Linux real-service runtime | `BLOCKED_EXTERNAL` |
| macOS Kafka compile/link | `UNKNOWN` |
| Windows Kafka compile/link | `UNKNOWN` |
| wasm without Kafka | Source declares messaging absent |
| wasm with Kafka | Source declares compile error |

The manifest edge is not target-scoped, but that does not establish that
non-Linux native targets compile or link. The maintained cross-platform
umbrella excludes Kafka. No cross-compilation, link, runtime, or performance
claim follows from this static packet.

## User journeys

<!-- KAFKA-K0-3-JOURNEYS -->

| Journey | Local coverage | Current terminal status |
|---|---|---|
| Feature-disabled facade | Maintained separate-workspace fixture | `NOT_RUN` / rerun required |
| Produce and delivery metadata | Local E2E and opt-in broker target | `BLOCKED_EXTERNAL` for broker semantics |
| Transaction begin/send/commit | Opt-in broker target; stale migration snippet | `BLOCKED_EXTERNAL` |
| Consumer group, poll, commit, seek, rebalance | Deterministic relations plus opt-in target | `BLOCKED_EXTERNAL` |
| TLS/SASL secure connect | API and error/source checks | Security cells `BLOCKED_EXTERNAL` |
| Real-broker retained proof | Runner and target source exist | No immutable receipt |
| Compression | Config identity only | Codec/wire behavior not established |
| Rebalance lifecycle | Skip-prone feature test and unwired model | No broker receipt |
| Error taxonomy | Deterministic type/classifier checks | No broker mapping receipt |
| Tokio migration | Maintained prose with routed stale calls | No compile receipt |
| HTTP backpressure to Kafka | Unwired deterministic model | Stale/mock only |
| Trace correlation | Unwired obsolete source | Stale/mock only |

No journey is promoted beyond the evidence it actually has. In particular,
`REAL_BROKER_CAPABLE`, `PROOF_ONLY`, `MOCK_OR_SIMULATED`, `WIRE_CODEC_ONLY`,
and `COMPILE_ONLY` cannot satisfy `REAL_BROKER_RECEIPT`.

## Evidence truth table

<!-- KAFKA-K0-3-EVIDENCE -->

| Evidence | Class | Execution | What it establishes |
|---|---|---|---|
| K0.3 source census | `STATIC_SOURCE` | Static inspection complete | Local paths, wiring, claims, owners, and blockers |
| Downstream default fixture | `COMPILE_ONLY` | `NOT_RUN` | Mapped no-feature boundary only |
| `kafka_real_broker` target | `REAL_BROKER_CAPABLE` | `NOT_RUN` | Source and wiring exist |
| Broker parity runner | `PROOF_ONLY` | `NOT_RUN` | Planned orchestration/schema |
| Real-service fixture matrix | `PLANNED` | `BLOCKED` | Missing immutable version/security fixture |
| Unwired real-prefixed sources | `MOCK_OR_SIMULATED` | `NOT_RUN` | Historical intent only |

A valid real-broker receipt must identify the exact source revision, execution
time, exact command, broker version, immutable service identity, retained
artifacts and hashes, cleanup, and a non-skip terminal result. This packet
contains no such receipt.

## External downstream population

<!-- KAFKA-K0-3-EXTERNAL-UNKNOWN -->

No external search ran during this static pass. Each domain is therefore
`NOT_RUN` and `UNKNOWN`, with a nullable result count and an empty result and
provenance list:

- registry alias `Kafka-users`;
- registry alias `consumer-portfolio`;
- maintained FrankenSuite repositories;
- GitHub and public code indexes;
- crates.io reverse dependencies and package metadata.

The machine artifact records exact intended query terms and the capture date.
An unrun search is never encoded as zero results. Even a later, properly
executed public search returning zero cannot authorize removal by itself.

## K14.1 claim-time refresh

<!-- KAFKA-K0-3-K14-HANDOFF -->

`asupersync-dep-p7-kafka-removal-sarszu.2.14.1` must refresh this inventory at
claim time before any migration or cutover decision. The current counts are
explicitly non-authoritative at that future claim time.

The refresh must cover the repository, workspace, FrankenSuite, identified
maintained consumers, package indexes, and public code search. It must retain
exact queries, dates, repository revisions, owners, and immutable provenance;
resolve aliases or preserve owned `UNKNOWN`; synthesize consumers for unused
public combinations; rerun maintained compile profiles; and require immutable,
non-skip broker receipts for broker claims.

Unknowns and regressions block migration. The refresh may not authorize file
deletion on its own.

## No-claim boundary

<!-- KAFKA-K0-3-NO-CLAIMS -->

This packet proves only the enumerated, source-pinned repository-local static
inventory at its baseline revision. Its creation session recorded no compiler,
formatter, test, runtime, broker, fuzz, external-search, or network execution.

It does not prove broker interoperability, supported broker versions,
authentication, TLS/SASL behavior, cancellation correctness, transaction
fencing, credential redaction, compression availability, performance, broad
workspace health, release readiness, or migration eligibility.

It provides no permission to remove or narrow a dependency, feature, public
API, capability, behavior, file, platform, fixture, test, or journey.

<!-- END KAFKA K0.3 DOWNSTREAM INVENTORY -->
