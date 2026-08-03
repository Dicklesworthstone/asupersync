# Kafka K1.3 public API and migration contract

<!-- BEGIN KAFKA K1.3 PUBLIC API CONTRACT -->

This document is the operator-readable companion to
`artifacts/kafka_k1_public_api_contract_v1.json`. It records the static K1.3
policy packet for
`asupersync-dep-p7-kafka-removal-sarszu.2.1.3`.

K1.3 freezes the accepted producer, consumer, transaction, configuration,
default, error, helper, explicit-absence, and downstream-migration contract
behind the existing first-party Kafka facade. It does not implement a native
client or prove that any behavior works. The governing disposition remains
`KEEP_INCUMBENT`, and K15 remains the sole conditional cutover authority.

## Authority and scope

The packet is rooted in the closed K1.1 namespace authority and imports the
accepted K0 public, semantic, and journey rows without rewriting them:

- `artifacts/kafka_k1_obligation_index_v1.json` supplies the K1 authority,
  namespace, exposure model, and owner boundaries;
- `artifacts/kafka_k0_baseline_disposition_v1.json` supplies the aggregate K0
  `KEEP_INCUMBENT` disposition;
- `artifacts/kafka_capability_inventory_v1.json` owns the public symbol rows;
- `artifacts/kafka_incumbent_semantics_matrix_v1.json` owns configuration,
  enum, operation, helper, shared-semantic, absence, and routed-finding rows;
- `artifacts/kafka_downstream_user_journey_inventory_v1.json` owns the fifteen
  journey rows and their current evidence states; and
- `docs/adr/dep_plan_adr_009_kafka_client.md`, the producer and consumer
  sources, the messaging facade, and `Cargo.toml` remain byte-pinned inputs.

The K1.3 baseline revision is
`816cb7f89a881656f639c734d0aa4795300738c7`. The capability registry still
requires `KEEP_UNTIL_PARITY`. Dependency exit, feature removal, API removal,
capability removal, file deletion, production wiring, oracle retirement, and
cutover are all forbidden by this packet.

## Exact coverage

The core contract contains exactly 129 rows:

| Core domain | Rows | Disposition |
|---|---:|---|
| Public symbols | 30 | `PRESERVE` |
| Configuration, enum, operation, and helper semantics | 97 | `PRESERVE` |
| Explicit absences | 2 | `ADDITIVE_GAP` |

The core projection emits
`domain<TAB>stable_id<TAB>disposition`, bytewise sorts unique rows, and appends
one LF per row. Its SHA-256 is
`f1ebad598d91e38b86206686c8d35ec6f013bbf93cd422f4b68308fbf89efb7a`.

The supporting contract contains exactly 50 rows:

| Supporting domain | Rows | Disposition |
|---|---:|---|
| Shared-semantic keys | 12 | `PRESERVE` |
| Downstream user journeys | 15 | `PRESERVE` |
| Routed semantic findings | 23 | `REVIEWED_EVOLUTION_INPUT` |

The supporting projection uses the same tuple and newline rules. Its SHA-256
is `1deac57a9c2330e41f67afccffb2353998e5719f3663ba39bde926090f262265`.
The exact 179-row union has SHA-256
`36c6470809d8f8ed98291f0265db34d6003462889c730d1c029cf84690126cc3`.

These counts are contract coverage, not runtime coverage. Missing, extra,
duplicate, changed, or unowned rows fail closed and leave the incumbent in
place.

## Two independent axes: disposition and gate state

K1.3 deliberately keeps two decisions separate:

1. **Contract disposition** records what the current accepted surface means.
   Present public, semantic, shared, and journey rows are `PRESERVE`; absent
   required capabilities are `ADDITIVE_GAP`; routed findings are
   `REVIEWED_EVOLUTION_INPUT`.
2. **Gate state** records whether later implementation, independent
   verification, real-service evidence, claim-time refresh, or aggregate
   approval is still missing. Such a row remains `BLOCKING` even when its
   current contract disposition is `PRESERVE`.

`PRESERVE` therefore does not mean implemented, tested, supported by a native
backend, or eligible for migration. Conversely, a blocking gate does not
license silent narrowing of the accepted incumbent behavior. A future
`REVIEWED_EVOLUTION` must name current behavior, target behavior, migration
impact, implementation owner, independent verifier, and terminal receipt.

Unknown usage remains identified, owned by K14.1, and migration-blocking. No
planned, static, compile-only, local-model, deterministic-only, mock,
proof-only, opt-in, or silent-skip evidence is promoted by this document.

## Public API, exposure, and aliases

All 30 K0.1 public symbol groups remain accepted inputs. Their complete
canonical-row digest is
`18ba7fa4a9db025263b9df4ae5ce5f36641ca5e9334d4eeaf8fd64b2bb66e4f2`.
K1.3 preserves public declarations, fields, variants, methods, module-public
names, facade exports, and facade aliases rather than reducing the contract to
the facade alone.

| Exposure class | Rows |
|---|---:|
| `FACADE` | 15 |
| `MODULE_PUBLIC` | 12 |
| `CFG_TEST_ONLY` | 2 |
| `CFG_FUZZING` | 1 |
| `PRIVATE` | 0 |

The `symbol_id<TAB>exposure_class` projection digest is
`cec04b907f94b381e8c1e4e9c38a5cdee6d0d89508f52aab5f2c92eab15fb70f`.
The fifteen facade-export rows have digest
`8a63a3ae3410057e3aedcd063187e491529cd0bb978804c7cc41a8bffb9a7e5e`.

Two facade exports intentionally rename their module-public types:

| Stable row | Module-public name | Facade name |
|---|---|---|
| `KCO-PUB-003` | `ConsumerConfig` | `KafkaConsumerConfig` |
| `KCO-PUB-006` | `ConsumerRecord` | `KafkaConsumerRecord` |

Their exact projection digest is
`eee9f608a39846d1df1ec81a830c0f7b079667a09f923a3a398c2cdd64ca1fb1`.
An alias is an additional accepted path; it cannot erase, replace, or silently
rename its module-public authority row.

`KPR-PUB-022` remains one public group containing mutually exclusive same-name
`KafkaClient` definitions for `feature=kafka` and `not(feature=kafka)`. It is
not two contract definitions. `KPR-PUB-002` and `KPR-PUB-021` remain
test-scoped. `KPR-PUB-023` remains exposed only through test, fuzz, or
`cfg(fuzzing)` admission.

## Cfg and compilation profiles

The profile contract freezes thirteen K0.1 compilation profiles, seventeen
K0.2 semantic profile groups, and exactly 97 semantic-to-profile memberships.
Their respective digests are:

- compilation-profile ID set:
  `882b6f73ee7c5abfe73080804fcd082c05dddd9c4002ee61ff9336f0a0d439eb`;
- canonical compilation-profile rows:
  `8a2b2437daa7b2b4c8189875502bf5d4b049d6c9ce408d390279deaf8d8b5815`;
- semantic profile-group ID set:
  `7bb8ea31cc9a88c8f068f6a18a8656a1eea52056229aa11302ffb7f9473b938c`;
- canonical semantic profile-group rows:
  `75bedc39680e2df6ea1be48212fa6a0f9c397767cab43dcae769d29e99526c29`;
- semantic membership projection:
  `60e296aa42497ee03292a481dd867919b873eb309cecbfbc7877e9338fe47925`.

The native no-feature facade remains present. Broker-directed operations fail
closed through typed outcomes unless an exact test or test-internals rule
admits deterministic behavior. Deterministic broker helpers retain their
individual test and test-internals distinctions, including the release
test-internals guard. Parser helpers remain limited to test, `cfg(fuzzing)`, or
`feature=fuzz`; `test-internals` alone does not expose them.

Debug-only insecure-transport setters currently compile under
`cfg(any(test, debug_assertions))`. That source truth is preserved while its
conflict with the ADR's test-only wording remains blocking. Wasm without Kafka
keeps the messaging module absent, and wasm with Kafka remains a hard
compile-error profile until an explicit reviewed evolution changes the
contract.

## Configuration, defaults, and shared semantics

The 97 semantic rows consist of 43 configuration fields, seven enum rows,
38 operations, and nine callable helpers. Every row retains its accepted and
rejected values, broker mapping, success and error outcomes, retry and timeout
rules, cancellation and shutdown rules, resource bounds, credential/payload
rules, source anchor, and owner routes. Their combined canonical-row digest is
`d19103e0fb6dd8b291405b1925c15d14cfacdf970901c766c10e06fcdbd7beab`.

Four headline invariants are explicit:

- `KPR-CFG-006`: `ProducerConfig.enable_idempotence` defaults to `true`.
  This preserves a configuration default; it does not prove effective broker
  idempotence or deterministic deduplication.
- `KCO-CFG-007`: `ConsumerConfig.enable_auto_commit` defaults to `false` and
  manual commit. The public opt-in and deterministic divergence remain
  reviewed-evolution inputs.
- `KCO-OP-005`: rebalance remains caller-driven.
  `KafkaConsumer::rebalance` accepts the next assignment and returns
  `RebalanceResult` with assigned, revoked, and generation fields.
- The native no-feature types remain available, and broker-directed operations
  preserve their exact typed `KafkaError::FeatureDisabled` ordering rules.

The twelve shared-semantic keys—auto-commit opt-in, caller-driven rebalance,
cancellation, errors, idempotence, manual-commit default, no-feature behavior,
observability, remote-plaintext policy, resources, secret redaction, and
shutdown—remain `PRESERVE`. Their ID-set digest is
`92ab055d5d14e4971daf298e54c9f5036ecf71c490d579270f4789b889fc86a5`.

## Errors and operation outcomes

The public `KafkaError` contract retains these twelve variants:

`Io`, `Protocol`, `Broker`, `QueueFull`,
`MessageTooLarge{size,max_size}`, `InvalidTopic`, `Transaction`, `Cancelled`,
`PolledAfterCompletion`, `Config`, `Authentication`, and `FeatureDisabled`.

It also retains `is_transient`, `is_connection_error`, `is_capacity_error`,
`is_timeout`, and `is_retryable`. Delivery, transaction, rebalance, poll,
commit, seek, close, and accessor outcomes remain exactly those recorded by
the K0.2 operation rows until K10.3 records reviewed interfaces and independent
terminal evidence verifies them.

This is `PRESERVE_CURRENT_AND_REQUIRE_REVIEWED_EVOLUTION`, not an endorsement
of every incumbent error. Coarse string-bearing errors, classifier mismatches,
rejected-value exposure, ambiguous completion states, and absent `ASUP-E`
registry integration remain blocking inputs. K10.3 owns typed outcomes, K10.4
owns telemetry privacy and redaction, and K12.5 owns independent verification.

## Explicit additive gaps

The two accepted absences are not permission to define parity around missing
capability:

| Absence | Current state | Required route |
|---|---|---|
| `KAFKA-ABS-001` transactional consumer-offset enrollment | `ABSENT_NOT_PARITY` | additive implementation K6.3, verification K13.3 |
| `KAFKA-ABS-002` Kafka administration API | `ABSENT_NOT_PARITY` | K10.1 API disposition; implementation remains unallocated until that decision; verification K12.5 |

Both remain blocking. Absence authorizes neither capability removal nor a
parity claim. The canonical source-row digest is
`9892212d2641f933ded02b730993ff3c81f21ea65f7565b74b4a038b5a69afc5`.

## Recorded authority conflicts

Five conflicts are retained without silently normalizing source truth:

| Conflict | Accepted current state | Owners and gate |
|---|---|---|
| Consumer auto-commit policy | defaults false, but the public config permits true; the real path honors opt-in while deterministic poll ignores it | K9, K10.2, K11.2; blocking reviewed evolution |
| Insecure transport bypass cfg | setters compile under `cfg(any(test, debug_assertions))`, including ordinary downstream debug builds | K10.2, K12.4; blocking reviewed evolution |
| Credential redaction and zeroization | SASL wrapper passwords redact and zeroize on wrapper drop; TLS key passwords are cloneable strings and rejected native values can reach public errors | K3.2, K3.3, K10.4, K12.4; blocking reviewed evolution |
| Downstream inventory status | the local static/call-site inventory is complete, but external search remains `NOT_RUN` and `UNKNOWN` | K10.5 and K14.1; blocking claim-time refresh |
| Consumer commit method documentation | singular `commit_offset` does not exist; the API is `KafkaConsumer::commit_offsets` | K10.5; blocking documentation repair |

The resolution rule is uniform: preserve accepted K0/source truth, retain the
conflicting claim as evidence, route reviewed evolution to named owners, and
keep migration blocked.

## Journeys and usage evidence

All fifteen K0.3 user journeys remain `PRESERVE` with their exact ordered entry
points, evidence class, execution state, and owner. Their ID-set digest is
`c5a9f1947a5ecf55898c61414bb39bf753cd236fe33157083994acd63176367f`,
and their canonical-row digest is
`3124cf3daff343142b56bbadceba66f8d0fb21862f771957e667f4d6c393260f`.

Journey linkage is usage evidence, not completeness proof:

| Usage view | Total rows | Known local | Unknown | Journey edges |
|---|---:|---:|---:|---:|
| Public symbols | 30 | 17 | 13 | 109 |
| Semantic rows | 97 | 45 | 52 | 216 |

The public and semantic journey-edge digests are, respectively,
`2dc041692d554c03a1e123ba9e720967bf88288e402ebdc0ec7ddfe7a821f43a`
and
`d48356bc797bf7af527f4e77915ae45bf6c442fa178f99a14f7350e7b42ffae9`.
K1.3 therefore freezes all 30 public and all 97 semantic rows independently;
it does not mistake the 17 and 45 journey-linked subsets for complete API
coverage. Unknown usage and every unexecuted or blocked journey remain
migration-blocking until their named owners supply admitted evidence.

## Exact migration and ownership order

The migration sequence is fixed:

| Order | Owner | Required handoff |
|---:|---|---|
| 1 | K1.3 | freeze current public, config/default, error, helper, absence, and migration policy; completed by this packet |
| 2 | K1.5 | aggregate K1.2, K1.3, and K1.4 into the static `KEEP_INCUMBENT` gate |
| 3 | K5, K6, K7, K8, K9, and K10 | realize producer, transaction, fetch, group/rebalance, offset, API/config/error/privacy/docs/migration obligations |
| 4 | K12.5 | independently verify accepted API, cfg, error, absence, and migration coverage |
| 5 | K13.6 | retain terminal, identified real-service receipts for broker-capable journeys |
| 6 | K14.1 | refresh downstream and external usage at claim time; `UNKNOWN` remains blocking |
| 7 | K15 | make the sole conditional cutover decision after every accepted gate is satisfied |

Within K10, K10.1 owns API and compile ergonomics, K10.2 owns configuration
and defaults, K10.3 owns typed errors and outcomes, K10.4 owns telemetry,
privacy, and redaction, and K10.5 owns documentation and downstream migration.
The 23 routed findings contain 62 exact owner edges with projection digest
`1e4aea3a7dbe623f8e4c2c51b5bb5edbdec3e6ac0b002f5261d79edbcbc4a860`.
No row is unowned.

## Standalone owner boundaries

K1.3 does not absorb or close these incumbent-maintenance beads:

- `asupersync-messaging-resp3-kafka-commit-o9ujbk`, the incumbent
  `commit_offsets` worker-blocking compatibility input;
- `asupersync-o82yd7`, the feature-lane coverage and environment-gated
  real-broker decision; and
- `asupersync-ne8jdw`, the mixed cold-module review that includes Kafka flush
  worker blocking.

Their evidence may feed later Kafka gates, but their ownership and closure
remain independent.

## Static-only validation boundary

This packet was authored and checked through static JSON parsing, exact hashes,
counts, joins, source inspection, tracker inspection, and documentation
markers only. No compiler, formatter, linter, test, fuzz target, broker,
service, container, runtime program, network operation, RCH lane, or remote job
was run for K1.3. The artifact and this document retain no dynamic execution
receipt and make no dynamic claim.

## No-claim boundary

This K1.3 packet proves only its checked-in static input pins, exact row counts
and projections, preservation dispositions, profile and alias contracts,
recorded authority conflicts, owner routing, migration order, and fail-closed
gate state. It does not prove:

- compilation, formatting, linting, tests, fuzzing, runtime execution, broker
  contact, external search, network behavior, service health, container
  behavior, remote execution, or live RCH availability;
- Kafka request/response coverage, protocol correctness, version negotiation,
  downgrade, flexible tags, broker interoperability, codec availability, or
  oldest/current broker support;
- delivery certainty, effective idempotence, exactly-once behavior,
  transaction atomicity, group ownership, rebalance correctness, offset
  durability, cancellation, shutdown, recovery, teardown, or residue cleanup;
- complete credential redaction or zeroization, safe error payloads, stable
  `ASUP-E` integration, observability completeness, resource bounds,
  backpressure, performance, reliability, release readiness, broad workspace
  health, migration readiness, or absence of defects; or
- production wiring, oracle retirement, dependency/feature/API/capability
  removal, file deletion, standalone-bead closure, or cutover.

Any missing, extra, duplicate, changed, unowned, unknown, or regressed accepted
row leaves the disposition at `KEEP_INCUMBENT`.

<!-- END KAFKA K1.3 PUBLIC API CONTRACT -->
