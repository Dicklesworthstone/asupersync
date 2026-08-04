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
| Static receipt state | Complete baseline Git-tree static inventory, exact five-tier path partition, exhaustive test/call-site candidate identity accounting, and exhaustive documentation-claim identity/ownership partition; semantic resolution and migration remain blocked |

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

The case-insensitive path-or-content receipt covers 245 tracked paths at the
named baseline revision under its declared roots, including `examples/`. Its
sorted newline path-map SHA-256 is
`9c815cfcba11f5345e7abced6b0afa21bfb650f9bb280e71bb3da74ebbb55089`.
Control roots, peer scratch paths, build output, and this packet's three files
are explicitly excluded, and the receipt does not claim the current worktree.

Five disposition groups partition the baseline exactly once, in this strict
precedence order: `LOCAL_ROW_REFERENCED`,
`DOCUMENTATION_CLAIM_REFERENCED`, `CALL_SITE_REFERENCED`,
`NON_CONSUMER_DISPOSITIONED`, then `POLICY_OR_CONTEXT_RETAINED`. Their counts
are respectively 30, 31, 5, 17, and 162 paths. A call-site path enters the
third tier only when it has a current, stale, or unresolved K0 candidate and is
absent from the two higher-precedence tiers. Collision-only paths do not enter
that tier. Its five exact paths are
`fuzz/fuzz_targets/kafka_produce_response.rs`,
`fuzz/fuzz_targets/kafka_protocol.rs`,
`fuzz/fuzz_targets/kafka_protocol_parser.rs`,
`fuzz/fuzz_targets/kafka_response_frames.rs`, and
`src/messaging/kafka.rs`. The five path sets are pairwise disjoint and their
union is the exact 245-path baseline receipt. This is inventory accounting:
neither the call-site tier nor the retained tier proves runtime behavior or
absence of downstream consumers.

The machine packet contains 225 byte-and-record-count source pins, 15 local
consumers, 34 local inventory rows, 31 documentation claims, 17 compilation
profiles, eight platform/feature cells, 15 user journeys, six evidence claims,
seven external search rows, eight owned unknowns, 23 routed gaps, and 16 atomic
cases. Its 35-row `test_declaration_group_classifications` array owns and
classifies all 936 named declarations: 888 exact `#[test]` declarations and 48
exact `#[tokio::test]` declarations. Sixteen declarations have explicit atomic
overrides; the other 920 inherit the evidence and disposition of their exact
path-and-source-pin group. This makes the K0.3 static inventory receipt
complete, but it does not make the capability migration eligible.

### Documentation-claim occurrence census

The declared documentation-candidate selector retains, in the existing
baseline path-array order, every `.md`, `.json`, `.jsonl`, `.yml`, and `.snap`
path. That produces 149 actual surfaces: 90 Markdown, 55 JSON, one JSONL, one
YAML, and two snapshot files. `examples/` is represented separately as one
owned virtual exact-absence surface, for 150 stable surface identities in all.
The actual path-list SHA-256 is
`092daf94a5e428430bc2e6fab7a13a30649aca53e30680c300f9eb76cbbfec67`.
The 149 derived actual `surface-id<TAB>path` tuples have SHA-256
`94ccd2b31c37be2c9a899d9d33cdcabc794f035107f1ca69615dbc0cc633082e`;
after appending the virtual surface, the 150-row surface-ID/path tuple SHA-256
is `71d1cc5d04e71d3005d4449a11758af96d4d787f28bb63ec86102f902ce32970`.

Surface IDs are derived without duplicating the path array:
`KAFKA-K0-3-DOC-SURFACE-{three-digit ordinal}`. Every actual surface joins to
exactly one source pin, a fixed owner and refresh owner, its canonical claim
rows, and its literal occurrence set. The stable surface-ID/path/source-pin
tuple digest, including the virtual absence anchor, is
`24425b9d52e7f82a2f0ae596ba4a17ea55c4fdb565ca8f5b8998f334e6d6fb74`.
That digest is reproducible without inventing a source pin: actual rows
serialize `surface-id<TAB>path<TAB>source-pin-id`, while virtual surface 150
serializes
`KAFKA-K0-3-DOC-SURFACE-150<TAB>examples/<TAB>EXACT_BASELINE_ABSENCE`.
Rows are surface-ID ordered and LF-terminated. The explicit
`source_pin_digest_token` value `EXACT_BASELINE_ABSENCE` is a serialization
sentinel only; it is not a source pin or evidence of external absence.

The case-insensitive, non-overlapping content scan finds 8,636 literal Kafka
occurrences on 7,307 distinct matching lines. An occurrence ID has the form
`KAFKA-K0-3-DOC-OCC-{surface}-L{line}-M{within-line ordinal}`. The exact
path/line/match-ordinal tuple SHA-256 is
`1045749285eb5a01933adfee3bd79dc34ed30f2e7cd1b7117caab51c89043dbc`;
the matching-line tuple SHA-256 is
`93d84baac784b880d19fc7c790a19488d1c62547aadbce1ce5056582dafb7545`;
and the corresponding occurrence-ID-list SHA-256 is
`577ca40dd5f40101a2c4bdca225fcb6930ed2925353a1419404adc0ca5e30b3d`.

Thirty-one explicit canonical projection groups link the 31 curated claim
rows to 37 exact occurrences. For each actual surface, a deterministic
set-difference group owns every other occurrence. Seven surfaces have no
remainder; the other 142 remainder groups contain 8,599 occurrences. The 173
canonical occurrence-ID list has SHA-256
`96dcbefec213d04a2a8f29e5255bf8ca1b55b229c993b9997f28c3209365c5ab`;
the owned-unresolved occurrence-ID list has SHA-256
`db4e006cdb3cde6fee615f3d64753df484c0848474dcd68a412ab055b0ffced0`;
and the 173 group IDs have SHA-256
`5e36b023be812fd3887b84af75d46e7b220c0138317b2a4face21917bdf180dd`.
The canonical and remainder groups are pairwise disjoint and their union is
the full 8,636-occurrence set.

This makes the declared occurrence identity, locator, ownership, and partition
census exhaustive. It does **not** make semantic classification exhaustive:
all 8,599 remainder occurrences are `OWNED_UNRESOLVED_CLAIM`, `UNKNOWN`, and
migration-blocking. They are not collapsed into a context-only bucket and do
not become broker, parity, migration, or removal evidence. Likewise, the
virtual `examples/` row proves only exact local baseline absence; it says
nothing about generated, untracked, external, or downstream examples and does
not authorize removal.

### Test-declaration census

The declaration census has 35 source-pinned groups and 936 exact declarations.
After a trimmed line equal to `#[test]`, the ordinary scanner permits only
blank lines or zero or more non-test Rust attribute lines, then requires the
first other nonempty line to match optional `pub` plus `fn NAME(`. The
alternate scanner applies the same intervening-line rule after an exact
`#[tokio::test]`, then requires optional `pub` plus `async fn NAME(`.
Consecutive test attributes, any other intervening line, an unresolved
binding, or end-of-file fails closed. Each declaration row records the
function-signature line. Tokio rows additionally record the attribute kind and
exact attribute line.

The 48 Tokio declarations comprise five in
`src/real_kafka_consumer_group_rebalance_e2e_tests.rs`, three in
`src/real_messaging_kafka_trace_event_integration_e2e_tests.rs`, and 40 in
`src/subsystem_mutation_testing.rs`. The sorted, LF-terminated
`path<TAB>attribute-line<TAB>tokio::test<TAB>function-name` tuple SHA-256 is
`c21dd6b0021dc189e82e6a3cf95dd37f1cddb100cf9688595fbe7a969b09b80d`.
The 16 explicit atomic case rows override their group classifications; the
other 920 declarations inherit their exact group's classification. Neither
identity nor inherited classification is per-test execution or per-test
migration analysis.

### Public topology

The public native modules are not gated by the Kafka feature. Without the
feature, the first-party facade remains visible and broker operations fail
closed. With the feature, private backend fields and operations select
`rdkafka`. On wasm, the messaging module is absent without Kafka and forcing
Kafka is a declared compile error.

The K0.1 join covers all 30 public-symbol groups. The K0.2 join covers all 97
semantic rows. The machine joins are exact inverses, not one-way hints: a local
row's `journey_ids` equal precisely the journey rows whose `local_row_ids`
contain it, and its `k0_2_semantic_ids` equal precisely the K0.2 disposition
rows whose `local_row_ids` contain it. Atomic-case backreferences are likewise
exact in both directions. Symbols and semantics referenced by detailed local
rows are classified as local use, documentation-only use, or fixture-only use.

The legacy local-row view still has 13 K0.1 and 52 K0.2 usage rows explicitly
`UNKNOWN`. Separately, after resolved current and stale call-site joins, nine
K0.1 IDs have no resolved invocation in the declared grammar:
`KPR-PUB-007`, `KPR-PUB-009`, and `KPR-PUB-016` through `KPR-PUB-022`.
Twenty-two K0.2 IDs have no resolved invocation:
`KPR-CFG-009`, `KPR-CFG-010`, `KPR-CFG-014`, `KPR-CFG-016` through
`KPR-CFG-020`, `KPR-CFG-022`, `KAFKA-ENUM-001`, `KAFKA-ENUM-004`,
`KAFKA-ENUM-005`, `KPR-HLP-002`, `KPR-HLP-004`, `KPR-HLP-005`, and
`KPR-OP-015` through `KPR-OP-021`. Absence from this call-shaped grammar is not
proof of no non-call use. All of these rows remain preserved and require K14
consumer synthesis; none can become removal evidence.

### Call-site candidate census

The declared Rust candidate grammar contains 48 path groups and 1,363 stable
candidate identities. The site-kind partition is 501 associated calls, 654
instance-method calls, 137 trait-method projections, 23 struct-literal
constructions, 40 free-function calls, and eight context-inferred default
calls. Stable IDs use exact byte/line-column ranges where available and pinned
line, callee, and same-line ordinal for macro-token, binding-only,
context-inferred, and provider-test candidates. The sorted call-site ID-set
SHA-256 is
`27ac17b660888d65f1d6a92c924becec669a96b4b1c09795450c89a350aabe2c`;
the sorted 48-path set SHA-256 is
`612152c18e6daff98c7d0c3c7d907df8aa7100a8bab45e88a701d08588718d9c`.

Candidate identity is deliberately broader than "Kafka call." Of the 1,363
nodes, 1,097 are K0 call-shaped candidates: 1,063 resolve to the current K0
surface, 26 resolve to stale unwired K0 surfaces, and eight are unresolved
stale candidates. The other 266 are explicit exclusions and are not Kafka
calls: 232 name collisions, 31 pattern-only spellings, and three
comment/string spellings. Every candidate belongs to exactly one path group
and one resolution state; a resolved node carries a K0.1 ID, and it carries
K0.2 IDs exactly when its explicit no-K0.2 reason is null.

Two independently reproducible receipts guard the cases most likely to escape
an ordinary syntax walk. Outside the provider implementation, the exact helper
names `fuzz_parse_delivery_result`, `fuzz_parse_kafka_error_response`,
`fuzz_parse_response_metadata`, and `fuzz_validate_response_frame` produce 35
sorted
`path<TAB>line<TAB>callee<TAB>same-line-ordinal` tuples with SHA-256
`a2c49e5cb2519afa11a2d29bee72d97c60532292b2817f725466683b3a93a777`.
Inside the provider test regions, lines 2725–4335 of
`src/messaging/kafka.rs` contribute 341 candidates and lines 1673–2757 of
`src/messaging/kafka_consumer.rs` contribute 294. The 635 sorted
`candidate-kind<TAB>path<TAB>line<TAB>candidate-token<TAB>same-line-ordinal`
tuples have SHA-256
`1c1f5c263973f83026f7a4235cbe21252de23b4f22ba8833d5fd433659a2e255`.
The provider kind partition is 254 associated candidates, 249 public-method
candidates, 106 trait projections, 12 struct constructions, six inferred
defaults, five free-function calls, and three UFCS trait projections. Those
provider candidates resolve as 509 current K0 nodes, 92 name collisions, 31
pattern-only spellings, and three comment/string spellings. Provider declaration
and implementation regions before those line ranges remain excluded from the
downstream candidate census.

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
The machine inventory assigns these stable IDs to exact declarations; every
case is `NOT_RUN`. These explicit case rows take precedence over their
declaration-group classifications:

| Stable ID | Source case | Journey links | Evidence/disposition | Owner |
|---|---|---|---|---|
| `KAFKA-K0-3-CASE-001` | `tests/integration/kafka_real_broker.rs:1095`, producer delivery metadata | produce, real-broker-proof | `REAL_BROKER_CAPABLE` / `BLOCKED` | `asupersync-dep-p7-kafka-removal-sarszu.2.13.6` |
| `KAFKA-K0-3-CASE-002` | `:1170`, produce-consume round trip | produce, consume-group, real-broker-proof | `REAL_BROKER_CAPABLE` / `BLOCKED` | `asupersync-dep-p7-kafka-removal-sarszu.2.13.6` |
| `KAFKA-K0-3-CASE-003` | `:1306`, exactly-once transaction | transaction, real-broker-proof | `REAL_BROKER_CAPABLE` / `BLOCKED` | `asupersync-dep-p7-kafka-removal-sarszu.2.13.6` |
| `KAFKA-K0-3-CASE-004` | `:1401`, group rebalance | consume-group, rebalance, real-broker-proof | `REAL_BROKER_CAPABLE` / `BLOCKED` | `asupersync-dep-p7-kafka-removal-sarszu.2.13.6` |
| `KAFKA-K0-3-CASE-005` | `:1489`, recovery-shaped load | broker-recovery, real-broker-proof | `REAL_BROKER_CAPABLE` / `BLOCKED`; no broker restart | `asupersync-dep-p7-kafka-removal-sarszu.2.13.6` |
| `KAFKA-K0-3-CASE-006` | `:1590`, payment delivery | consume-group, payment-delivery, produce, real-broker-proof | `REAL_BROKER_CAPABLE` / `BLOCKED` | `asupersync-dep-p7-kafka-removal-sarszu.2.13.6` |
| `KAFKA-K0-3-CASE-007` | `:1755`, close-without-commit replay | consume-group, replay-without-commit, real-broker-proof | `REAL_BROKER_CAPABLE` / `BLOCKED` | `asupersync-dep-p7-kafka-removal-sarszu.2.13.6` |
| `KAFKA-K0-3-CASE-008` | `tests/e2e_messaging.rs:403`, consumer lifecycle case | consume-group | `REAL_BROKER_CAPABLE` / `PLANNED`; ambient endpoint | `asupersync-dep-p7-kafka-removal-sarszu.2.13.6` |
| `KAFKA-K0-3-CASE-009` | `tests/e2e_messaging.rs:462`, producer acknowledgement case | produce | `REAL_BROKER_CAPABLE` / `PLANNED`; ambient endpoint | `asupersync-dep-p7-kafka-removal-sarszu.2.13.6` |

#### Atomic offset cases

The offset source mixes a deterministic feature-disabled boundary with a
feature-enabled `force_real_kafka(true)` path. It is therefore not globally
`DETERMINISTIC_ONLY`:

| Stable ID | Source case | Journey links | Evidence/disposition | Owner |
|---|---|---|---|---|
| `KAFKA-K0-3-CASE-010` | `tests/conformance/kafka_offsets.rs:84`, no-feature consumer boundary | feature-disabled, consume-group | `DETERMINISTIC_ONLY` / `CURRENT` | `asupersync-dep-p7-kafka-removal-sarszu.2.12.5` |
| `KAFKA-K0-3-CASE-011` | `:158`, MR1 monotonic commits | consume-group | `REAL_BROKER_CAPABLE` / `PLANNED` | `asupersync-dep-p7-kafka-removal-sarszu.2.12.5` |
| `KAFKA-K0-3-CASE-012` | `:249`, MR2 idempotent commit | consume-group | `REAL_BROKER_CAPABLE` / `PLANNED` | `asupersync-dep-p7-kafka-removal-sarszu.2.12.5` |
| `KAFKA-K0-3-CASE-013` | `:322`, MR3 retention | consume-group, replay-without-commit | `REAL_BROKER_CAPABLE` / `OVERCLAIM`; no expiry proof | `asupersync-dep-p7-kafka-removal-sarszu.2.12.5` |
| `KAFKA-K0-3-CASE-014` | `:402`, MR4 rebalance preservation | consume-group, rebalance | `REAL_BROKER_CAPABLE` / `PLANNED` | `asupersync-dep-p7-kafka-removal-sarszu.2.12.5` |
| `KAFKA-K0-3-CASE-015` | `:490`, MR5 transactional wording | consume-group, transaction | `REAL_BROKER_CAPABLE` / `OVERCLAIM`; ordinary commits only | `asupersync-dep-p7-kafka-removal-sarszu.2.12.5` |
| `KAFKA-K0-3-CASE-016` | `:621`, aggregate relations | transaction, consume-group, rebalance | `REAL_BROKER_CAPABLE` / `OVERCLAIM`; successful skip is possible | `asupersync-dep-p7-kafka-removal-sarszu.2.12.5` |

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
OpenTelemetry attributes, and standalone RecordBatch code are not
incumbent-client consumers and remain visible through explicit non-consumer
dispositions. Four response-parser fuzz paths and the provider test path are
instead retained in the higher-precedence `CALL_SITE_REFERENCED` tier because
they contain resolved helper or K0 candidates. Other policy artifacts and
snapshots remain conservatively retained; a filename or vocabulary match is
not a call.

### Examples and documentation

The baseline Git-tree receipt includes `examples/` and finds no tracked Kafka or
rdkafka path-or-content match there. Neither the examples metadata nor the
reference-app inventory supplies an implemented RA-06 example. The
reference-app template and Wave 2 evidence describe only a future real-broker
recipe; the evidence row has an empty example path and an unsupported/pending
verdict. The proven baseline absence remains a synthesis gap, not deletion
evidence, and says nothing about external examples.

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

The following concrete fixture, policy, golden, and documentation claims remain
individually visible rather than disappearing behind a generic occurrence
digest. All of these stable IDs are classified and source-pinned in the machine
artifact:

| Stable claim ID | Source and finding | Classification | Owner |
|---|---|---|---|
| `KAFKA-K0-3-DOC-CLAIM-014` | `artifacts/dependency_api_adr_registry_v1.json:5069-5085` labels macOS and Windows supported, while current compile/link evidence is `UNKNOWN` | `PLANNED` / `OVERCLAIM` | `asupersync-dep-p7-kafka-removal-sarszu.2.10.5`; refresh `.2.14.1` |
| `KAFKA-K0-3-DOC-CLAIM-015` | Generic baseline-consumer fixture is mapped by planning but contains no Kafka feature or API use | `PLANNED` / `OVERCLAIM` | `asupersync-dep-p7-kafka-removal-sarszu.2.14.1` |
| `KAFKA-K0-3-DOC-CLAIM-016` | `tests/golden/PROVENANCE.md:184-190` names an absent retained golden; `src/golden_artifacts_tests.rs:1031-1128` hand-builds two vectors and claims compatibility | `WIRE_CODEC_ONLY` / `OVERCLAIM` | `asupersync-dep-p7-kafka-removal-sarszu.2.12.3` |
| `KAFKA-K0-3-DOC-CLAIM-017` | `.github/no_mock_policy.json:561-579` keeps two Kafka phase-0-stub waivers active after their 2026-06-30 expiry | `HISTORICAL` / `STALE` | `asupersync-dep-p7-kafka-removal-sarszu.2.10.5` |
| `KAFKA-K0-3-DOC-CLAIM-018` | `docs/tokio_db_messaging_integration_contract.md:133-166` defines delivery/error intent only | `STATIC_SOURCE` / `PLANNED` | `asupersync-dep-p7-kafka-removal-sarszu.2.10.5` |
| `KAFKA-K0-3-DOC-CLAIM-019` | `docs/tokio_db_messaging_unit_test_matrix_contract.md:108-117,157-161,242-244` covers config/error tests, not a broker | `DETERMINISTIC_ONLY` / `CURRENT` | `asupersync-dep-p7-kafka-removal-sarszu.2.12.5` |
| `KAFKA-K0-3-DOC-CLAIM-020` | `docs/tokio_external_validation_benchmark_packs.md:74-76` defines BM-10 without a retained result | `PLANNED` | `asupersync-dep-p7-kafka-removal-sarszu.2.10.5` |
| `KAFKA-K0-3-DOC-CLAIM-021` | `docs/tokio_replacement_claim_rfc.md:155-188` distinguishes a scheme from results but later asserts unsupported readiness percentages | `HISTORICAL` / `OVERCLAIM` | `asupersync-dep-p7-kafka-removal-sarszu.2.10.5` |
| `KAFKA-K0-3-DOC-CLAIM-022` | `docs/tokio_functional_parity_contracts.md:297-299` states required producer/consumer/group behavior | `PLANNED` | `asupersync-dep-p7-kafka-removal-sarszu.2.10.5` |
| `KAFKA-K0-3-DOC-CLAIM-023` | `docs/tokio_nonfunctional_closure_criteria.md:258-260` states planned thresholds | `PLANNED` | `asupersync-dep-p7-kafka-removal-sarszu.2.10.5` |
| `KAFKA-K0-3-DOC-CLAIM-024` | `docs/tokio_capability_evidence_map.md:229-235` is an older partial inventory | `HISTORICAL` | `asupersync-dep-p7-kafka-removal-sarszu.2.10.5` |
| `KAFKA-K0-3-DOC-CLAIM-025` | `docs/tokio_interop_target_ranking.md:307-309` is integration planning, not proof | `HISTORICAL` / `PLANNED` | `asupersync-dep-p7-kafka-removal-sarszu.2.10.5` |
| `KAFKA-K0-3-DOC-CLAIM-026` | `docs/tokio_migration_cookbooks.md:330-373` supplies prose-only mapping, rebalance, and rollback guidance | `STATIC_SOURCE` / `PLANNED` | `asupersync-dep-p7-kafka-removal-sarszu.2.10.5` |
| `KAFKA-K0-3-DOC-CLAIM-027` | `docs/tokio_replacement_roadmap.md:199-201` is historical planning | `HISTORICAL` | `asupersync-dep-p7-kafka-removal-sarszu.2.10.5` |
| `KAFKA-K0-3-DOC-CLAIM-028` | `artifacts/adapter_certification_matrix_v1.json:187-227,315` is XFAIL/broker-reference-partial and uses local RecordBatch evidence | `WIRE_CODEC_ONLY` / `BLOCKED` | `asupersync-dep-p7-kafka-removal-sarszu.2.12.3` |
| `KAFKA-K0-3-DOC-CLAIM-029` | Real-broker README scenario list omits payment and replay cases | `STATIC_SOURCE` / `STALE` | `asupersync-dep-p7-kafka-removal-sarszu.2.10.5` |
| `KAFKA-K0-3-DOC-CLAIM-030` | Real-broker README shows a CI lane that no tracked workflow wires | `PLANNED` / `OVERCLAIM` | `asupersync-dep-p7-kafka-removal-sarszu.2.10.5` |
| `KAFKA-K0-3-DOC-CLAIM-031` | Real-broker sample output and performance baseline are illustrative and unretained | `PLANNED` / `OVERCLAIM` | `asupersync-dep-p7-kafka-removal-sarszu.2.10.5` |

The Tokio T6 migration row itself is `STATIC_SOURCE` / `OVERCLAIM`, not a
current executable journey: its transaction constructor is stale, and the
public consumer export is `KafkaConsumerConfig`, not the JetStream
`ConsumerConfig` exported at the same module level.

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

The canonical six journey IDs and semantics come from the source-pinned
`artifacts/dependency_api_adr_registry_v1.json:5110-5135`. The machine artifact
joins all six exact IDs and descriptions to that authority and preserves the
current public aliases, including `KafkaConsumerConfig`.

| Journey | Required semantics and local coverage | Current terminal status |
|---|---|---|
| `kfk-journey-feature-disabled` | Producer and consumer types remain compilable without Kafka; both broker-operation families return typed `FeatureDisabled`. The external fixture currently exercises only the producer; `CASE-010` covers the root-internal consumer boundary | `NOT_RUN` / rerun required; no backend claim |
| `kfk-journey-produce` | Produce records with headers, receive delivery metadata, and preserve idempotence-on-by-default; `CASE-001`, `CASE-002`, `CASE-006`, and `CASE-009` | Broker semantics `BLOCKED_EXTERNAL` |
| `kfk-journey-transaction` | Configure, begin, send, commit or abort; retain the drop guard against dangling transactions; `CASE-003`, `CASE-015`, and `CASE-016`, plus an invalid migration snippet | `BLOCKED_EXTERNAL` |
| `kfk-journey-consume-group` | Join a group, receive assignment generation and revocation information, poll, commit the next offset, seek, rebalance, and close; `CASE-002`, `CASE-004`, `CASE-006`–`CASE-008`, and `CASE-010`–`CASE-016` | `BLOCKED_EXTERNAL` |
| `kfk-journey-secure-connect` | TLS or SCRAM-over-SSL plus refusal of plaintext non-loopback downgrade; current rows are API and synthetic error checks only | Security cells `BLOCKED_EXTERNAL` |
| `kfk-journey-real-broker-proof` | Retain immutable, non-skip round-trip, exactly-once, rebalance, recovery, and cleanup evidence against an identified broker; `CASE-001`–`CASE-007` | No immutable receipt |
| `kfk-journey-compression-config` | Config identity only | Codec/wire behavior not established |
| `kfk-journey-rebalance` | `CASE-004`, `CASE-014`, and `CASE-016`, plus a skip-prone feature test and unwired model | No broker receipt |
| `kfk-journey-error-taxonomy` | Deterministic type and local-classifier checks | No private-backend mapping receipt |
| `kfk-journey-migration` | Prose with stale transaction constructor and alias/signature gaps | No compile receipt |
| `kfk-journey-http-publish` | Unwired deterministic model | Stale/mock only |
| `kfk-journey-observability` | Unwired obsolete source | Stale/mock only |
| `kfk-journey-broker-recovery` | `CASE-005` exercises recovery-shaped load but does not restart a broker | `BLOCKED_EXTERNAL`; no retained receipt |
| `kfk-journey-payment-delivery` | `CASE-006` payment-delivery path | `BLOCKED_EXTERNAL` |
| `kfk-journey-replay-without-commit` | `CASE-007` closes without commit and expects replay; `CASE-013` supplies only an overstated retention relation | `BLOCKED_EXTERNAL` |

No journey is promoted beyond the evidence it actually has. In particular,
`REAL_BROKER_CAPABLE`, `PROOF_ONLY`, `MOCK_OR_SIMULATED`, `WIRE_CODEC_ONLY`,
and `COMPILE_ONLY` cannot satisfy `REAL_BROKER_RECEIPT`.

## Evidence truth table

<!-- KAFKA-K0-3-EVIDENCE -->

| Evidence | Class | Execution | What it establishes |
|---|---|---|---|
| K0.3 pinned-row review | `STATIC_SOURCE` | `PASS` | Complete baseline inventory of paths, wiring, claims, owners, blockers, and joins |
| Baseline occurrence partition | `STATIC_SOURCE` | Receipt recorded | All 245 tracked matches assigned exactly once across five tiers: 30 / 31 / 5 / 17 / 162 |
| Test declaration classification | `STATIC_SOURCE` | Receipt recorded | All 936 declarations classified through 35 owned groups: 888 `#[test]`, 48 `#[tokio::test]`, 16 atomic overrides, and 920 inherited classifications |
| Call-site candidate census | `STATIC_SOURCE` | Receipt recorded | 1,363 candidate identities in 48 groups: 1,097 K0 call-shaped nodes and 266 explicit non-call exclusions |
| Documentation occurrence census | `STATIC_SOURCE` | Receipt recorded | 8,636 exact occurrences have stable identities and owners; 8,599 remain semantically `UNKNOWN` |
| Downstream default fixture | `COMPILE_ONLY` | `NOT_RUN` | Mapped no-feature producer behavior only |
| Generic baseline-consumer fixture | `PLANNED` | `BLOCKED` | Contains no Kafka feature or API use |
| `kafka_real_broker` target | `REAL_BROKER_CAPABLE` | `NOT_RUN` | Source and wiring exist |
| Broker parity runner | `PROOF_ONLY` | `NOT_RUN` | Planned orchestration/schema |
| Real-service fixture matrix | `PLANNED` | `BLOCKED` | Missing immutable version/security fixture |
| Messaging serialization golden | `WIRE_CODEC_ONLY` | `BLOCKED` | Hand-authored bytes; named retained golden absent |
| Adapter certification Kafka row | `WIRE_CODEC_ONLY` | `BLOCKED` | XFAIL/broker-reference-partial, not a client journey |
| Kafka phase-0 no-mock waivers | `HISTORICAL` | `NOT_RUN` | Active labels are expired and stale |
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
- `FrankenSuite`;
- GitHub and public code indexes;
- crates.io reverse dependencies and package metadata;
- public documentation, tutorials, snippets, and examples;
- private organization code, package, artifact, and deployment indexes.

The machine artifact records exact intended query terms and the capture date.
An unrun search is never encoded as zero results. Even a later, properly
executed public search returning zero cannot authorize removal by itself.

## K14.1 claim-time refresh

<!-- KAFKA-K0-3-K14-HANDOFF -->

`asupersync-dep-p7-kafka-removal-sarszu.2.14.1` must refresh this inventory at
claim time before any migration or cutover decision. The current counts are
explicitly non-authoritative at that future claim time.

The refresh must cover the exact Git tree, workspace, examples and metadata,
FrankenSuite, identified maintained consumers, GitHub and public code indexes,
crates.io reverse dependencies and package metadata, public documentation,
tutorials, snippets, and examples, and private organization code, package,
artifact, and deployment indexes.
It must retain exact queries, dates, repository revisions, owners, and
immutable provenance; resolve aliases or preserve owned `UNKNOWN`; materialize
atomic test/call-site and path-to-disposition joins; synthesize consumers for
unused public combinations; rerun maintained compile profiles; and require
immutable, non-skip broker receipts for broker claims.

Unknowns and regressions block migration. The refresh may not authorize file
deletion on its own.

## No-claim boundary

<!-- KAFKA-K0-3-NO-CLAIMS -->

This packet proves only the source-pinned repository-local static downstream,
documentation, fixture, profile, cell, and journey census at the named baseline
revision. Within that boundary it accounts for 225 byte-pinned sources, the
exact 245-path five-tier Git-tree partition, all local rows and claims, all
profile/cell/journey joins, 1,363 declared call-site candidates, and 936 named
test declarations in 35 groups. The 16 atomic classifications override their
groups; the other 920 declarations inherit group classification. Inventory
completeness does not promote group-level evidence or authorize migration.

The call-site census proves candidate identity and ownership, not that every
candidate is a Kafka call. Its 1,097 call-shaped nodes include 26 stale unwired
and eight unresolved-stale nodes; its other 266 nodes are explicit lexical
exclusions. Pattern-only and comment/string spellings are not calls. Unit enum
paths, imports, type annotations, ordinary field reads, untyped
context-inferred defaults, and methods outside the declared receiver-binding
paths remain outside this grammar. `CALL_SITE_REFERENCED` is therefore a path
accounting tier, not runtime or migration evidence.

Migration remains blocked by nine K0.1 and 22 K0.2 IDs without resolved
invocations in the declared grammar, eight unresolved-stale candidates, 162
conservatively retained policy/context paths, 920 declarations without
individual atomic migration analysis, 8,599 documentation occurrences with
owned but `UNKNOWN` semantics, seven unrun and unknown external domains, and
15 real-broker-capable cases without immutable receipts. The separate legacy
local-row view also preserves 13 `UNKNOWN` K0.1 and 52 `UNKNOWN` K0.2 usage
rows. `PRESERVE_AND_RECHECK_AT_K14` means unknown use is neither proof of local
use nor proof of no local use.

The 149 actual documentation surfaces plus the virtual `examples/` surface
make the declared documentation identity-and-ownership census exhaustive, not
its semantic classification. The explicit `EXACT_BASELINE_ABSENCE` token is
only the virtual row's reproducible digest sentinel. The 31 canonical
projections classify 37 exact occurrences; the remaining 8,599 occurrences
are not context-only, broker, parity, migration, or removal evidence. The
virtual absence says nothing about untracked, generated, external,
consumer-repository, or downstream examples.

The artifact records no compiler, formatter, test, runtime, broker,
external-search, or network execution from its creation session. It does not
prove broker interoperability, supported broker versions, authentication,
TLS/SASL behavior, cancellation correctness, transaction fencing, credential
redaction, codec or compression availability, performance, broad workspace
health, release readiness, migration eligibility, a feature-enabled downstream
compile, individual atomic migration analysis of every declaration, or
per-test execution.

Neither a path-map count or hash, a source filename containing `real`, a wired
test target or declared runner, a successful skip, a deterministic model, a
mock, parser, codec, source audit, sample README receipt, hand-authored golden,
XFAIL adapter row, planned benchmark, nor compile-only profile is a
`REAL_BROKER_RECEIPT`. The external downstream population is `UNKNOWN`, not
zero. `NOT_RUN`, `UNKNOWN`, stale, missing, and unpinned rows remain blockers
even when no local or public consumer is discovered.

No absence, zero local example count, stale source, unrun search, or candidate
exclusion authorizes removal. This packet provides no permission to remove or
narrow `rdkafka`, `librdkafka`, the `kafka` feature, a public API, capability,
behavior, file, platform, fixture, test, or journey.

<!-- END KAFKA K0.3 DOWNSTREAM INVENTORY -->
