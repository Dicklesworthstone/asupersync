# Kafka broker fixture provenance matrix

<!-- BEGIN KAFKA K0.4 BROKER FIXTURE PROVENANCE -->

The K0.4 disposition is `KEEP_INCUMBENT`. Rust packages and repository
fixtures are statically pinned, but there is no actual native-library build
receipt, immutable broker identity, accepted API range, codec availability
receipt, authenticated broker receipt, restart or injected-fault receipt, or
terminal cleanup evidence. Absent terminal evidence is represented by
`execution_state=NOT_RUN`, or by `truth_class=BLOCKED_EXTERNAL`,
`knowledge_state=BLOCKED`, and `execution_state=BLOCKED`; it is never a
passing skip.

This document is the human companion to
`artifacts/kafka_broker_fixture_provenance_matrix_v1.json` for
`asupersync-dep-p7-kafka-removal-sarszu.1.4`. It records incumbent evidence
truth only. It neither runs a lane nor changes any Kafka behavior.

## Authority and ownership

| Authority | Exact owner | K0.4 use |
|---|---|---|
| Capability and dependency decision | `CAP-KAFKA`; `DEP-ADR-009` | Requires `KEEP_UNTIL_PARITY` / `KEEP_INCUMBENT`. |
| Broker and fixture provenance | `asupersync-dep-p7-kafka-removal-sarszu.1.4` (K0.4) | Owns this source-pinned inventory and its explicit unknowns. |
| Wire versions and negotiation | `asupersync-dep-p7-kafka-removal-sarszu.2.2` (K2) | Owns accepted broker/API ranges, schemas, negotiation, correlation, and protocol signoff. |
| RecordBatch and five codecs | `asupersync-dep-p7-kafka-removal-sarszu.2.4` (K4) | Owns exact bytes, CRC32C, codec budgets, and five-mode interoperability. |
| Independent evidence | `asupersync-dep-p7-kafka-removal-sarszu.2.12` (K12) | Owns independent corpora, models, fuzz evidence, and security review. |
| Real-service evidence | `asupersync-dep-p7-kafka-removal-sarszu.2.13` (K13) | Owns pinned brokers, authentication, faults, restart, teardown, replay, and terminal interop receipts. |
| Claim-time refresh | `asupersync-dep-p7-kafka-removal-sarszu.2.14.1` (K14.1) | Must repeat the downstream and fixture census immediately before migration. |
| Conditional cutover | `asupersync-dep-p7-kafka-removal-sarszu.2.15` (K15) | Is the only authority that may consider removing `rdkafka`/`librdkafka`, after every gate is satisfied. |

Parent epics organize ownership; they are not evidence. Later work must cite a
terminal child receipt, not infer completion from an epic's status.

## Evidence truth model

| Human label | Exact machine mapping | Admission rule and current Kafka evidence |
|---|---|---|
| Real receipt | `evidence_class=REAL_BROKER_RECEIPT`, `truth_class=REAL_BROKER_RECEIPT`, `execution_state=PASS` | Requires a retained terminal artifact from an immutably identified broker with exact client/native/host identity and cleanup reconciliation. None exists. |
| Real-capable, blocked | `evidence_class=REAL_BROKER_CAPABLE`, `truth_class=BLOCKED_EXTERNAL`, `knowledge_state=BLOCKED`, `execution_state=BLOCKED` | Source can contact a broker, but immutable broker identity and a retained terminal run are absent. This covers the opt-in real suite and localhost-capable tests. |
| Deterministic/local model | `evidence_class=LOCAL_MODEL_ONLY`, `truth_class=LOCAL_MODEL_ONLY`, `execution_state=NOT_RUN` | Covers local state, self-roundtrip, property, and parser behavior without an external broker. |
| Compile only | `evidence_class=COMPILE_ONLY`, `execution_state=NOT_RUN` | Checks feature/API reachability but no broker behavior. This covers downstream consumer fixtures and static contracts. |
| Proof only | `evidence_class=PROOF_ONLY`, `execution_state=NOT_RUN` | Defines a command, schema, or report shape without an accepted execution artifact. |
| Historical/stale | `evidence_class=HISTORICAL` with `truth_class=STALE_CONTRADICTED` or `OVERCLAIM` | Describes an earlier policy/source state or a contradicted claim, not current execution evidence. |
| Planned mutable proposal | `evidence_class=PLANNED`, `truth_class=UNPINNED`, `knowledge_state=KNOWN`, `execution_state=NOT_RUN` | Records a current proposal whose external coordinates remain mutable and which has not been executed. |
| Planned blocked cell | `evidence_class=PLANNED`, `truth_class=BLOCKED_EXTERNAL`, `knowledge_state=BLOCKED`, `execution_state=BLOCKED` | Names a required cell whose immutable service or terminal receipt is absent. |
| Unsupported | `execution_state=UNSUPPORTED` | Taxonomy-only state for a platform that cannot expose a required capability; no K0.4 matrix row currently uses it. |
| Mock/simulated | `evidence_class=MOCK_OR_SIMULATED`, `truth_class=LOCAL_MODEL_ONLY`, `execution_state=NOT_RUN` | A local substitute exercises orchestration or state only. |
| Static current source | `evidence_class=STATIC_SOURCE`, with the row-specific canonical `truth_class` | Pins a current source fact without promoting it to runtime evidence. |

The human labels are explanatory aliases only. Consumers must use the exact
machine fields in the middle column; they are not additional enum values.
Domain-vector rows carry `truth_class`, `knowledge_state`, and
`execution_state`; the separately bounded `evidence_claims` rows carry
`evidence_class`.

Compilation, source reachability, a command declaration, a mutable image tag,
an ambient developer broker, a silently skipped test, or an in-process model
cannot be promoted to `REAL_BROKER_RECEIPT` or `ACTUAL_BINARY_RECEIPT`.

## Dependency identity is not native build identity

The checked root manifest and lockfile establish these Rust package
coordinates:

| Surface | Static coordinate |
|---|---|
| Root feature | `Cargo.toml`: `kafka = ["dep:rdkafka"]` |
| Rust wrapper | `rdkafka 0.39.0`, checksum `d7956f9ac12b5712e50372d9749a3102f4810a8d42481c5eae3748d36d585bcf` |
| Native sys crate | `rdkafka-sys 4.10.0+2.12.1`, checksum `e234cf318915c1059d4921ef7f75616b5219b10b46e9f3a511a15eb4b56a3f77` |
| Dependency features | `rdkafka` has `default-features = false`; the root `kafka` feature enables no dependency-specific codec, SSL, SASL, or dynamic-link feature. |

The checked `rdkafka-sys` source therefore describes an expected bundled
`librdkafka 2.12.1` build path. With the selected features it disables SSL,
GSSAPI, zlib, Zstd, and external LZ4; its source configuration retains built-in
Snappy and internal LZ4. That is static build-script reachability, not proof of
what bytes were compiled or linked in any executable.

An acceptable native receipt must record the exact `librdkafka` binary or
archive SHA-256, runtime-reported version, enabled feature/build flags, static
or dynamic linkage, compiler and linker identity, build image or worker
identity, target triple, OS/architecture/kernel/libc, and the consuming binary
SHA-256. The lockfile and package-source checksums alone prove none of those
facts.

## Broker and API-version cells

| Cell | Current truth | Required owner |
|---|---|---|
| Oldest supported broker | `truth_class=BLOCKED_EXTERNAL`, `knowledge_state=BLOCKED`, `execution_state=BLOCKED`; no version or immutable image/binary digest is approved. | K2.1, K13.1 |
| Current supported broker | `truth_class=BLOCKED_EXTERNAL`, `knowledge_state=BLOCKED`, `execution_state=BLOCKED`; no version or immutable image/binary digest is approved. | K2.1, K13.1 |
| Mixed/rolling-version cluster | `truth_class=BLOCKED_EXTERNAL`, `knowledge_state=BLOCKED`, `execution_state=BLOCKED`; no controller/coordinator failover or downgrade evidence exists. | K13.5 |
| `ApiVersions` negotiation | `truth_class=UNKNOWN`, `knowledge_state=BLOCKED`, `execution_state=BLOCKED`; local models contain synthetic maxima, not accepted incumbent ranges. | K2.1, K2.4, K2.5 |
| Request/response API keys and versions | `truth_class=WIRE_CODEC_ONLY`, `knowledge_state=UNKNOWN`, `execution_state=NOT_RUN`; no broker-produced range receipt, unsupported-version response, or fallback receipt exists. | K2.1, K2.3, K2.5 |
| Flexible versions and unknown tagged fields | Deterministic parser/model coverage only. | K2.3, K12.1 |
| Correlation, stream reuse, and recovery | Deterministic/proof-only; no hostile or restarted broker receipt. | K2.4, K13.5 |

`scripts/provision_kafka_test_env.rs` proposes mutable
`confluentinc/cp-kafka:7.4.0` and
`confluentinc/cp-zookeeper:7.4.0` tags. It creates one plaintext broker with
broker ID 1, replication factor 1, three partitions, and ZooKeeper. A mutable
Confluent platform tag is not an immutable Apache Kafka broker coordinate, and
the proposal records neither actual broker version nor image digest, cluster
ID, API range, broker configuration hash, logs, or terminal residue.

## RecordBatch and codec cells

The public `Compression` surface exposes all five modes. Each remains an
independent acceptance obligation.

| Mode | Static incumbent truth | Missing receipt and owner |
|---|---|---|
| `None` | Public mapping exists; no native codec is needed. | No broker-produced/consumed RecordBatch receipt. K4.1, K12.1, K13.2. |
| `Gzip` | Public mapping exists; the default vendored package-source configuration disables zlib. | Availability and bidirectional oldest/current broker evidence are absent. K4.2, K4.3, K12.1/K12.3, K13.2. |
| `Snappy` | Public mapping exists; the default vendored package-source configuration is Snappy-capable. | Actual linked capability, Kafka framing, and broker/cross-language evidence are absent. K4.2, K4.5.4, K12.1/K12.3, K13.2. |
| `Lz4` | Public mapping exists; the default vendored package-source configuration disables external LZ4 while retaining an internal implementation. | Actual linked capability and Kafka framing/version interoperability are absent. K4.2, K4.4, K12.1/K12.3, K13.2. |
| `Zstd` | Public mapping exists; the default vendored package-source configuration disables Zstd. | Availability and bidirectional oldest/current broker evidence are absent. K4.2, K4.6.7, K12.1/K12.3, K13.2. |

Every mode still needs produce and consume directions, oldest and current
brokers, independent clients, supported Linux architectures, supported non-
Linux hosts, empty/boundary/malformed inputs, bomb/output/time limits, and
input/output hashes. Unsupported host/codec combinations must be explicit;
they cannot disappear from the matrix.

## Transport and authentication cells

| Cell | Current truth | Required owner |
|---|---|---|
| Loopback plaintext | `truth_class=CONFIG_ONLY`, `knowledge_state=KNOWN`, `execution_state=NOT_RUN`; a mutable single-broker proposal and ambient-host tests exist, but no retained terminal receipt does. | K13.1, K13.2 |
| TLS with valid CA and hostname | `truth_class=CONFIG_ONLY`, `knowledge_state=UNKNOWN`, `execution_state=NOT_RUN`; public configuration exists, but the default vendored package-source configuration disables SSL. | K12.4, K13.5 |
| `SASL_SSL` + `SCRAM-SHA-256` | `truth_class=CONFIG_ONLY`, `knowledge_state=UNKNOWN`, `execution_state=NOT_RUN`; no enabled native capability or authenticated receipt exists. | K12.4, K13.5 |
| `SASL_SSL` + `SCRAM-SHA-512` | `truth_class=CONFIG_ONLY`, `knowledge_state=UNKNOWN`, `execution_state=NOT_RUN`; no enabled native capability or authenticated receipt exists. | K12.4, K13.5 |
| Wrong password / unknown user | `truth_class=BLOCKED_EXTERNAL`, `knowledge_state=BLOCKED`, `execution_state=BLOCKED`; no real negative handshake or stable normalized outcome exists. | K12.4, K13.5 |
| Mechanism mismatch | `truth_class=BLOCKED_EXTERNAL`, `knowledge_state=BLOCKED`, `execution_state=BLOCKED`; no real negative handshake exists. | K12.4, K13.5 |
| Untrusted CA / hostname mismatch / expired certificate | `truth_class=BLOCKED_EXTERNAL`, `knowledge_state=BLOCKED`, `execution_state=BLOCKED`; no real negative transport receipt exists. | K12.4, K13.5 |
| Client-certificate/key mismatch and mTLS policy | `truth_class=BLOCKED_EXTERNAL`, `knowledge_state=BLOCKED`, `execution_state=BLOCKED`; support expectation remains unestablished. | K12.4, K13.5 |
| Credential and log redaction | `truth_class=BLOCKED_EXTERNAL`, `knowledge_state=BLOCKED`, `execution_state=BLOCKED`; static/simulated checks provide no retained broker/process log redaction scan. | K12.4, K13.6 |

`tests/integration/kafka_real_broker.rs` labels a receipt `sasl` when any
`KAFKA_SASL_USERNAME`, `KAFKA_SASL_PASSWORD`, or `KAFKA_SASL_MECHANISM`
variable is present, but it does not apply those values to
`KafkaSecurityConfig`. That label is not authentication evidence.

## Topology, failure, cancellation, restart, and teardown

| Required cell | Current truth | Required owner |
|---|---|---|
| Multi-broker, multi-partition replication | `truth_class=BLOCKED_EXTERNAL`, `knowledge_state=BLOCKED`, `execution_state=BLOCKED`; the proposal is one broker with RF1 and the required topology remains unknown. | K13.1, K13.2 |
| Producer acks, ordering, idempotence, and broker retry | Local/static or ambient-broker-capable only; no accepted receipt. | K13.2 |
| Transaction commit/abort, `read_committed`, fencing, and atomic offsets | Real-capable and deterministic fragments exist; no accepted receipt. | K12.2, K13.3 |
| Consumer-group eager/cooperative/static membership and partition ownership | Real-capable/simulated fragments exist; no multi-client receipt. | K12.2, K13.4 |
| Slow handler, heartbeat/session timeout, max-poll, and rejoin | `NOT_RUN`. | K13.4 |
| Broker kill/restart and client recovery | `truth_class=BLOCKED_EXTERNAL`, `knowledge_state=BLOCKED`, `execution_state=BLOCKED`; no exact fault point or recovery boundary exists. | K13.3, K13.5 |
| Controller/coordinator failover and rolling upgrade | `truth_class=BLOCKED_EXTERNAL`, `knowledge_state=BLOCKED`, `execution_state=BLOCKED`. | K13.5 |
| Network partition, DNS failure, TLS failure, and reconnect | Simulated taxonomy only; no deterministic external fault receipt. | K13.5 |
| Cancellation during send, poll, commit, transaction, and rebalance | `truth_class=BLOCKED_EXTERNAL`, `knowledge_state=BLOCKED`, `execution_state=BLOCKED`; local fragments provide no broker-side outcome/reconciliation receipt. | K12.2, K13.3/K13.4 |
| Topic/client/process/container/volume cleanup | No retained reverse-order, idempotent terminal cleanup evidence. | K13.1, K13.6 |
| Failure-path teardown and retry | The proposal has no failure trap or orphan receipt. | K13.1, K13.6 |

For ambiguous operations, a receipt must identify the cancellation point and
reconcile the broker-visible outcome after reconnect or restart. Process exit
alone is not evidence of quiescence or absence of orphaned work.

## Environment and retained provenance

The current real suite uses `REAL_KAFKA_TESTS=true` and
`KAFKA_BOOTSTRAP_SERVERS`, defaults to `localhost:29092`, and blocks only a
specific production hostname or `NODE_ENV=production`. The proof runner also
uses `ASUPERSYNC_KAFKA_BROKER_PARITY_PROOF_DIR`,
`ASUPERSYNC_KAFKA_BROKER_PARITY_BEAD_ID`,
`ASUPERSYNC_KAFKA_BROKER_PARITY_INCLUDE_OFFSET_ACK_PROOF`, and
`ASUPERSYNC_KAFKA_BROKER_PARITY_INCLUDE_RESILIENCE_PROOF`. These are gates and
output controls, not service identity.

Every accepted K13 receipt must retain:

- full source revision, dirty/overlay path set, Cargo manifest and lock hashes,
  Rust package checksums, feature set, consuming binary hash, and actual native
  link/build identity;
- immutable broker and auxiliary-service image or binary digests, vendor and
  broker versions, cluster ID, topology, configuration hash, negotiated API
  versions, listeners, and semantic readiness result;
- host OS, architecture, kernel, libc, target triple, compiler/linker, Rust
  toolchain, worker/build-image identity, and resource envelope;
- stable capability, bead, scenario, step, broker, API, codec, security, and
  fault IDs; both client-to-broker directions where applicable;
- certificate/public-key fingerprints and validity metadata, SASL mechanism
  and principal identity without credentials, plus a canary-based redaction
  result;
- exact command/replay metadata, start/end times, terminal exit status,
  normalized outcomes, payload and artifact hashes, and per-process logs; and
- pre/post resource inventory covering topics, clients, workers, sockets,
  ports, processes, containers, volumes, temporary directories, and
  credentials, including idempotent teardown retry and zero-residue result.

Secrets and message payloads must be redacted according to the scenario policy.
An ambient bootstrap address without these identities remains
`evidence_class=REAL_BROKER_CAPABLE`, `truth_class=BLOCKED_EXTERNAL`,
`knowledge_state=BLOCKED`, and `execution_state=BLOCKED`.

## Exact fixture census and revisions

The K0.4 machine matrix enumerates 67 exact paths. Its canonical exact-path
digest is
`d9542095b391dbd44a0f8d855d6cfb87e41b981642430a0de662a2965ad26db0`.
Each sorted path has a stable `KAFKA-K0-4-FIXTURE-NNN` row that resolves to
exactly one source pin and one of eight classification profiles. The partition
is 48 live-byte-checked K0.3 inherited pins plus 19 K0.4 direct fixture pins;
the separate K0.3 authority pin is intentionally outside the fixture set.
Profiles retain the exact truth/evidence/execution class, environment,
executable owner, refresh owner, and limitation for every row.
The K0.3 anchor artifact
`artifacts/kafka_downstream_user_journey_inventory_v1.json` has SHA-256
`52f8dc9a2695a170b14c85c9b29b6e60f95e05bd013d3d9db0dab8d94a1ced09`
and freezes baseline/authority revision
`ae22e710d87412b38e546b32e9702106619481d5`. The K0.4 static census was
reconciled at revision `012c13714db267a4fba928db9f900b70d6c1d25a`.

The frozen declaration and case census is:

| Surface | Exact count and truth |
|---|---|
| Kafka-related declaration groups | 35 groups. |
| Rust test declarations | 888 `#[test]` plus 48 `#[tokio::test]`, 936 total. |
| Journey-focused atomic cases | 16 cases. |
| Kafka fuzz targets | Seven registered targets; compilation is not execution. |
| Tracked Kafka parser seeds | Seven exact seed paths, all lacking independent origin/version provenance. |
| RecordBatch local tests | 17 self-roundtrip/local-model tests; no independent broker receipt. |
| Real-broker integration tests | 12 declarations total: seven named real-broker-capable cases plus five static/proof-row declarations; none has an accepted receipt. |

The seven tracked seeds are:

- `fuzz/corpus/kafka_protocol/api_versions_tagged_fields`
- `fuzz/corpus/kafka_protocol/invalid_api_version_header`
- `fuzz/corpus/kafka_protocol/oversized_request_frame`
- `fuzz/corpus/kafka_response_frames/empty`
- `fuzz/corpus/kafka_response_frames/error_response`
- `fuzz/corpus/kafka_response_frames/malformed_length`
- `fuzz/corpus/kafka_response_frames/success_response`

The 17 RecordBatch tests are split across
`conformance/src/kafka_record_batch_v2.rs` (3),
`tests/conformance/kafka_record_batch_v2/golden_tests.rs` (11),
`tests/conformance/kafka_record_batch_v2/mod.rs` (2), and
`tests/kafka_record_batch_v2_integration.rs` (1). All ten
`expected_encoded` vectors in
`tests/conformance/kafka_record_batch_v2/test_vectors.rs` are empty.
`tests/conformance/kafka_record_batch_v2/format.rs` uses
`crc32fast::hash`, not retained independent Kafka-v2 CRC32C golden bytes.
These tests are deterministic local evidence, not a versioned external oracle.

Key current source pins are retained so drift is visible:

| Path | SHA-256 | Lines |
|---|---|---:|
| `Cargo.toml` | `e998db4199267aa7166b67e36e69db213c2f755cebd6e6e91bb5a7e35204e0f3` | 1057 |
| `Cargo.lock` | `e0be65699715c92ae75dbc96292635e4d0aec7ef6f404c8a85793b9e58b98946` | 4666 |
| `src/messaging/kafka.rs` | `5fe763229f2940793bf79739718afc20002ac40b614c35ff0ea475d45fb5aaf1` | 4335 |
| `src/messaging/kafka_consumer.rs` | `82646e24d6e8ebdc07f5ea3a283f681b59855b952e5f86adf575ddc04ee6f61d` | 2757 |
| `tests/integration/kafka_real_broker.rs` | `f12b3e131f2376617dd6d876dfc09bbffe368f749f1ff25d606d2f0631b204f7` | 1883 |
| `scripts/kafka_broker_parity_proof_runner.sh` | `656a5f812adf8209c5942b7b43243c46c899f9ff0f6e089163814217ce5ec451` | 440 |
| `scripts/provision_kafka_test_env.rs` | `55da137faa1c826985e9c1dfaf1484df9457b4ab152730ed1de5a094ef40e569` | 376 |
| `.github/no_mock_policy.json` | `a2b2ca01bab322c0e15a47e091da0f585a647cceaff3abfd5a60035c6a024593` | 611 |
| `.github/workflows/fuzz.yml` | `f7ff28d27b2872f9c400a25d59bb70ca54da036e67580c5cd7ef27fbca435134` | 365 |

## Source contradictions and overclaims

- `tests/integration/kafka_real_broker.rs` is opt-in, silently returns when its
  gate is absent, defaults to an ambient localhost broker, emits broker version
  `unknown`/`unavailable`, and has no retained terminal receipt.
- `tests/messaging_kafka_compression_roundtrip.rs` checks enum/config identity;
  it does not create a producer or prove broker compression roundtrip.
- `tests/messaging_kafka_rebalance_lifecycle.rs` names `KAFKA_BOOTSTRAP` in its
  documentation but does not read it, and its feature-on cases can return after
  construction or subscription failure.
- `tests/kafka_sasl_authentication_audit.rs` exercises simulated strings and
  error classification, not a broker authentication handshake.
- `src/real_http_h2_server_messaging_kafka_e2e_tests.rs`,
  `src/real_kafka_consumer_group_rebalance_e2e_tests.rs`,
  `src/real_messaging_kafka_trace_event_integration_e2e_tests.rs`, and
  `src/real_net_tls_connector_messaging_kafka_integration_e2e_tests.rs` are
  simulated and/or unwired; “real” in a filename is not evidence.
- `.github/no_mock_policy.json` Kafka stub waivers expired on 2026-06-30.
- `.github/workflows/fuzz.yml` compiles all fuzz binaries, but scheduled and
  on-demand execution selects only `kafka_protocol` and provisions no broker.
- `scripts/kafka_broker_parity_proof_runner.sh` declares receipt fields and
  scenarios but has no accepted retained run. A declared proof command is
  `PROOF_ONLY`.
- `tests/fixtures/downstream-consumer-proof` verifies a default/fail-closed
  Kafka surface; it is compile/static proof, not backend evidence.

## Owned unknowns and later routing

| Owned unknown | Fail-closed state | Later owner |
|---|---|---|
| Exact oldest/current broker versions, API keys/ranges, fallback, and flexible versions | `UNKNOWN` | K2.1/K2.4/K2.5; K13.1/K13.5/K13.6 |
| Actual linked native bytes and enabled codec/auth features on each supported host | `UNKNOWN` | K4.2/K4.7; K13.1/K13.6 |
| Independent RecordBatch/CRC32C and versioned protocol bytes | `UNKNOWN` | K4.1; K12.1/K12.3 |
| None/Gzip/Snappy/Lz4/Zstd bidirectional broker interoperability | `BLOCKED_EXTERNAL` | K4.3/K4.4/K4.5.4/K4.6.7/K4.7; K13.2 |
| TLS and SCRAM-256/512 success plus all negative authentication cells | `BLOCKED_EXTERNAL` | K12.4; K13.5 |
| Transaction, group, offset, and ownership behavior | `execution_state=NOT_RUN` for current source fragments | K12.2; K13.3/K13.4 |
| Cancellation and ambiguous-outcome reconciliation | `truth_class=BLOCKED_EXTERNAL`, `knowledge_state=BLOCKED`, `execution_state=BLOCKED` | K12.2; K13.3/K13.4 |
| Multi-version, failover, network partition, broker restart, and rolling upgrade | `BLOCKED_EXTERNAL` | K13.5 |
| Pinned service lifecycle, retained logs, redaction, replay, and zero-residue teardown | `BLOCKED_EXTERNAL` | K13.1/K13.6 |
| Current downstream/fixture usage at migration time | `UNKNOWN` pending K14.1 refresh | K14.1 |
| Dependency/native cutover eligibility | `KEEP_INCUMBENT` | K15 only |

These are accounted unknowns, not missing rows. Any new unowned cell blocks the
K0.5 aggregate and later migration.

## Refresh handoff

K14.1 must rerun the exact-path census at claim time, recompute the path digest
and every source pin, enumerate new local and maintained external consumers,
and join every reachable public/config/security/platform combination to a
compile fixture and a real K13 journey. It must ingest only terminal K12/K13
artifacts whose source, package, native, broker, host, scenario, log, redaction,
replay, and cleanup identities validate. Drift, unavailable external search,
new unsupported platforms, expired evidence, or an unmatched consumer remains
owned `UNKNOWN` and blocks migration.

K15 must preserve `KEEP_INCUMBENT` unless the refreshed K14.1 matrix and the
terminal K2, K4, K12, and K13 receipts establish same-or-better behavior for
every accepted row. Neither this inventory nor a later compile-only green lane
can authorize cutover.

## No-claim boundary

K0.4 performed static repository, tracker, manifest, lockfile, source, corpus,
fixture, script, policy, and workflow inspection only. It ran no Cargo, RCH,
compiler, formatter, test, fuzzer, broker, container, network, service, or
remote lane.

K0.4 starts no broker, process, container, or network.
It does not prove native linkage or broker interoperability.
It does not authorize migration, removal, or deletion.

This packet does not prove an actual native build or link, codec availability,
Kafka protocol correctness, accepted broker/API compatibility, RecordBatch
correctness, compression interoperability, TLS or SASL authentication,
transaction or group semantics, cancellation correctness, restart or fault
recovery, teardown or leak freedom, CI health, performance, broad workspace
health, release readiness, or permission to remove or change the Kafka feature,
public API, `rdkafka`, or `librdkafka`.

<!-- END KAFKA K0.4 BROKER FIXTURE PROVENANCE -->
