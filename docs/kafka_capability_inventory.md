# Kafka capability inventory

<!-- BEGIN KAFKA CAPABILITY INVENTORY -->

This document is the human companion to
`artifacts/kafka_capability_inventory_v1.json`. Together they freeze the K0.1
incumbent source, Cargo, export, cfg, and reachable-backend surface for
`asupersync-dep-p7-kafka-removal-sarszu.1.1`. The original authority baseline is
`2d811170e956966e960db122a0d634a5b60c56e0`; the source inventory was reviewed
against the release candidate on 2026-09-09. Current pins and counts include
the additive incumbent changes below and do not claim those bytes existed at
the original baseline. The artifact retains the historical public census.

The governing decision remains `DEP-ADR-009`: keep the incumbent Kafka client
until independently owned parity evidence exists. This packet does not permit
dependency exit, API removal, behavior changes, or export changes.

## Authority and ownership

| Coordinate | Value |
|---|---|
| Capability | `CAP-KAFKA` |
| Registry disposition | `KEEP_UNTIL_PARITY` |
| Current action | `KEEP_INCUMBENT` |
| K0.1 source inventory | `asupersync-dep-p7-kafka-removal-sarszu.1.1` |
| K0.2 semantic inventory | `asupersync-dep-p7-kafka-removal-sarszu.1.2` |
| K0.3 downstream inventory | `asupersync-dep-p7-kafka-removal-sarszu.1.3` |
| K0.4 broker provenance | `asupersync-dep-p7-kafka-removal-sarszu.1.4` |
| K0.5 terminal inventory | `asupersync-dep-p7-kafka-removal-sarszu.1.5` |
| Conditional cutover | `asupersync-dep-p7-kafka-removal-sarszu.2.15` |

The capability registry names both primary source owners and the root manifest:

- `src/messaging/kafka.rs`
- `src/messaging/kafka_consumer.rs`
- `Cargo.toml`

It also points to the machine inventory. The K0 prefix mapping now resolves
`asupersync-dep-p7-kafka-removal-sarszu.1.*` to `CAP-KAFKA`, and the corrected
graph snapshot contains 425 dep-plan issues, 358 non-epic work items, and 109
mapping rules.

## Dependency identity

The root `kafka` feature contains only `dep:rdkafka`. The dependency is an
optional, unconditional normal edge with manifest requirement `0.39` and
`default-features = false`.

The checked root lock resolves:

| Package | Version |
|---|---|
| `rdkafka` | `0.39.0` |
| `rdkafka-sys` | `4.10.0+2.12.1` |

The locked `rdkafka-sys` row names `libc`, `num_enum`, and `pkg-config`. Neither
primary Kafka source imports `rdkafka_sys`, declares direct native FFI, or
contains an unsafe block. Those facts identify source ownership only; they do
not establish the native library identity or optional codec/auth availability.

`fuzz/Cargo.toml` does not enable the Kafka feature. Its lockfile was absent
from the historical baseline but is now tracked and separately pinned. This
establishes source availability only, not fuzz execution or broker parity.

## Module and export topology

`asupersync::messaging` exists only on native targets. Within it, the `kafka`
and `kafka_consumer` modules are present even when the Kafka feature is off.
The Kafka feature selects real backend fields and operations; it does not gate
the public modules themselves.

The messaging facade exports exactly these 17 names:

`Acks`, `AutoOffsetReset`, `Compression`, `IsolationLevel`, `KafkaConsumer`,
`KafkaConsumerConfig`, `KafkaConsumerRecord`, `KafkaError`, `KafkaProducer`,
`KafkaRebalanceProtocol`, `KafkaRebalanceStats`,
`ProducerConfig`, `RecordMetadata`, `TopicPartitionOffset`, `Transaction`,
`TransactionalConfig`, and `TransactionalProducer`.

There are no crate-root Kafka reexports. General module-only public names are
`BrokerBackend`, `KafkaClient`, `KafkaConsumerTrait`,
`KafkaFeatureRequirement`, `KafkaSaslConfig`, `KafkaSaslMechanism`,
`KafkaSecurityConfig`, `KafkaTlsConfig`, `RebalanceResult`, and
`TransientConsumerError`. Additional
module-only names are cfg-sensitive deterministic/real backend types, test
controls, and parser helpers; the machine artifact records each group and its
cfg expression.

The frozen public census contains:

| Measure | Count |
|---|---:|
| Syntactic top-level public declarations | 40 |
| Unique top-level public paths | 39 |
| Stable symbol groups | 33 |
| Syntactic public inherent methods | 104 |
| Unique public inherent method paths | 100 |
| Public trait methods | 5 |
| Syntactic public fields | 69 |
| Crate-private record fields included above | 6 |
| Downstream-visible public fields | 63 |

The machine inventory assigns `KPR-PUB-001` through `KPR-PUB-023` to the
producer/transaction/client source and `KCO-PUB-001` through `KCO-PUB-010` to
the consumer source. Every row records declarations, cfg ownership, facade
aliases, fields, variants, and methods.

## Current incumbent additions

Producer and consumer configurations now expose `with_property`,
`set_property`, and `extra_properties`. They preserve raw-key insertion order
and replace repeated values in place; typed librdkafka setters are applied
after raw properties. These additions do not change the `kafka` feature edge.

Configuration Debug now hides every raw property value while retaining keys
and typed settings. Native configuration rejection retains its error category
and diagnostic key but omits the rejected value and free-form description.
Explicit property accessors still return original values; no secure-erasure
or comprehensive upstream-error sanitation claim follows.

The consumer now exposes rebalance protocol and callback counters through
`rebalance_protocol` and `rebalance_stats`. The two non-exhaustive result types
are also exported by the messaging facade. `last_transient_error` returns a
module-only `TransientConsumerError` with first/last runtime time and a
saturating occurrence count. Its current informational code is
`UnknownTopicOrPartition`; other broker errors remain errors.

The real consumer backend uses a configured eager/cooperative callback and
bounded normal polling when leaving a group through close or Drop. Cooperative
close avoids the eager unassign API. Producer flush yields through its runtime
timer while `ThreadedProducer` polls in the background. This source review does
not establish broker execution or replace the independent lifecycle and
downstream evidence lanes.

## Compilation profiles

| Profile | Reachable surface | Backend state |
|---|---|---|
| Native default release | Facade present and fail-closed | No broker operations |
| Native default debug | Facade plus debug-only bypass setter | No broker operations |
| Native Kafka release/debug | Facade present | Real `rdkafka` backend |
| Unit test without Kafka | Intended deterministic surface; cfg mismatch routed | Deterministic intended |
| Unit test with Kafka | Facade present | Real or local state selected by force flag |
| Downstream without Kafka | Facade present and fail-closed | No broker operations |
| Downstream `test-internals` without Kafka | Facade and harness present | Explicit deterministic opt-in |
| Excluded fuzz workspace | Parser hooks and harness present | No `rdkafka` edge |
| Cross-platform CI umbrella | Facade and test internals present | Kafka excluded |
| Native all-features | Facade present | Real `rdkafka` backend |
| Wasm without Kafka | Messaging module absent | Not applicable |
| Wasm with Kafka | Explicit compile refusal | Not applicable |

These are static reachability coordinates. They are not compiler-run receipts.

## Backend ownership

With the Kafka feature enabled, `src/messaging/kafka.rs` owns producer delivery,
transactions, security mapping, and the parallel `KafkaClient` metadata path.
`src/messaging/kafka_consumer.rs` owns group subscription, assignment,
rebalance snapshots, polling, offset storage/commit, seeking, and close.

Without the feature, ordinary downstream builds retain configuration and
facade types but fail broker operations with `KafkaError::FeatureDisabled`.
Valid optional producer and transactional constructors can still create local
objects. Producer lifecycle accessors and consumer state/config accessors
remain local operations.

The deterministic broker is a test quarantine, not a Kafka implementation. It
is compiled only without the Kafka feature and with crate tests or
`test-internals`. Downstream use requires explicit deterministic-broker opt-in.
It models topic/partition vectors and synthetic offsets; it deliberately omits
the broker protocol, durability, replication, real compression, transaction
fencing, and group coordination.

## Routed findings

K0.1 found and routed 15 source-level facts instead of changing behavior:

| Finding | Owner |
|---|---|
| Default no-Kafka unit helper and test-control cfg mismatch | `asupersync-dep-p7-kafka-removal-sarszu.2.10.1` |
| Debug-build visibility of the insecure-transport test setter | K0.2 |
| No-feature `KafkaClient` descriptor/operation asymmetry | K0.2 |
| Deterministic producer/consumer/client admission asymmetry | K0.2 |
| Parallel client/backend-trait family overlaps primary consumer API | `asupersync-dep-p7-kafka-removal-sarszu.2.10.1` |
| Facade omissions, including `RebalanceResult` | `asupersync-dep-p7-kafka-removal-sarszu.2.10.1` |
| `max_poll_records` is validated but not behaviorally mapped | K0.2 |
| Consumer docs name a nonexistent singular commit method | K0.3 |
| Tracked real-consumer rebalance source has no target/module wiring | K0.3 |
| Native link, codec, and auth availability remain unestablished | K0.4 |
| Parser compression mapping cannot produce `Zstd` | `asupersync-dep-p7-kafka-removal-sarszu.2.12.3` |
| Consumer retries apply only to synchronous offset commit | K0.2 |
| Producer notification has no observed waiter | K0.2 |
| Parallel consumer trait exposes diagnostics but no consumer operations | `asupersync-dep-p7-kafka-removal-sarszu.2.10.1` |
| Historical missing excluded-workspace lockfile; now tracked, execution still separate | K0.4 |

Here K0.2, K0.3, and K0.4 mean the exact owner IDs in the authority table. The
machine artifact carries a stable ID, full finding, and exact owner for every
row.

## Static contract

`tests/kafka_capability_inventory_contract.rs` is the paired fail-closed static
contract. It checks identity and authority, exact source pins, dependency
coordinates, compilation-profile and public-symbol sets, export topology,
backend/cfg/no-feature inventories, routed ownership, registry reconciliation,
documentation markers, and explicit no-claim boundaries. It performs no
external process, network, timing, broker, or environment-dependent work.

## No-claim boundary

This K0.1 packet proves only the enumerated source, feature, export, cfg, and
backend reachability coordinates. It does not prove configuration defaults or
operational semantics (K0.2), downstream journeys (K0.3), broker/native
provenance (K0.4), or the terminal K0 baseline disposition (K0.5).

It also does not prove protocol correctness, broker interoperability,
cancellation correctness, credential/transport completeness, performance,
broad workspace health, release readiness, or permission to remove `rdkafka`,
`librdkafka`, the `kafka` feature, any public API, or any behavior.

<!-- END KAFKA CAPABILITY INVENTORY -->
