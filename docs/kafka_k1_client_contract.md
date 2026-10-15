# Kafka K1 client contract

<!-- BEGIN KAFKA K1 CLIENT CONTRACT -->

This document is the operator-readable companion to
`artifacts/kafka_k1_obligation_index_v1.json`. It records the first bounded
slice of the Kafka K1 contract campaign:
`asupersync-dep-p7-kafka-removal-sarszu.2.1.1`.

K1.1 is a static authority and namespace receipt. It does not implement a
Kafka client, execute a broker, or establish parity. Its purpose is to prevent
later work from narrowing the accepted contract, inventing support from local
models, losing an owner, or treating a repeated reference as a second
definition.

The governing disposition remains `KEEP_INCUMBENT`. The native epic is an
additive investigation only. K15 remains the sole conditional cutover owner.

## Current source review

The 2026-09-09 review under `asupersync-ghxhvm` reconciles current source pins
and projections with the reviewed K0 packets. The original capture date,
baseline revisions, execution limitations, and owner handoffs remain historical;
the review does not place current source bytes at those earlier revisions.
Later-child completion flags describe the original K1.1 handoff, rather than
the present tracker status of each child.

Nine primary definitions were added: the tracked fuzz lockfile, public
`RebalanceStats`, `KafkaRebalanceProtocol`, and `TransientConsumerError` groups,
and five semantic rows for raw producer/consumer properties, the rebalance
protocol enum, and consumer diagnostic operations. The eight public/semantic
additions also have K0.3 references. No accepted definition was removed.
The first two diagnostic types have facade exports; `TransientConsumerError`
remains public only within its module. Private redaction helpers do not add
public API obligations.

Raw configuration values are now hidden from configuration Debug and native
configuration rejection errors. Explicit property accessors still return
the original values. This source review does not prove broker authentication
or credential erasure.

Twelve K0.3 usage-knowledge rows changed from `UNKNOWN` to
`KNOWN_LOCAL_REFERENCES`, reducing the selected low-evidence projection from
446 to 434. Those rows retain synthesis, preservation, and K14.1 ownership;
they are local source references, not execution receipts. The reviewed reverse
join associates the isolation-level test with `KCO-CFG-013`; `KCO-CFG-010`
(fetch-minimum bytes) remains unknown. No broker or execution state was promoted.

## K1 decomposition

The former 1,920-minute K1 leaf mixed five separate authorities. The tracker
now represents them as bounded children whose estimates still total exactly
1,920 minutes.

| Child | Minutes | Authority |
|---|---:|---|
| K1.1 | 300 | K0.5 import, stable namespace, exposure projection, definition/reference joins, drift ledger |
| K1.2 | 420 | required broker/API-version/security policy, negotiation, downgrade, fallback, protocol binding |
| K1.3 | 420 | public API, configuration, defaults, errors, explicit absences, behavior evolution, migration |
| K1.4 | 420 | Cx ownership, resource bounds, backpressure, timeouts, cancellation, shutdown, accounting |
| K1.5 | 360 | evidence-vector joins, coexistence, shadow classification, rollback, approvals, aggregate KEEP gate |

K1.2, K1.3, and K1.4 depend on K1.1. K1.5 depends on all three. The K2 epic
consumes K1.5; K2.1 consumes K1.2; K2.2 consumes both K2.1 and K1.5. This lets
schema work follow its exact policy input while preventing codec implementation
from outrunning the complete K1 contract.

The tracker projection covers K1, its five children, K2, K2.1, and K2.2. It
serializes issue ID, issue type, estimate, parent, and blocking dependencies.
The nine-row SHA-256 is
`6ea2a9c24adbe6c1618be0e946116e71c20a4ed2bfefde2459f17534cfd53372`.

## Authority chain

K1 imports exactly one K0 aggregate authority:
`artifacts/kafka_k0_baseline_disposition_v1.json`. The four K0 child artifacts
remain the row authorities named and byte-pinned by that aggregate; K1.1 does
not duplicate their large row bodies.

The dedicated K0.5 artifact, document, and contract source are pinned by exact
bytes, logical-record counts, and SHA-256. K1.1 additionally pins the governing
ADR document and the current producer, consumer, facade, manifest, and
RecordBatch overlap sources. The K1 claim-time revision is
`03dea9e1556eac3d60a393a61bbcf875d49a96dd`. It is distinct from every imported
K0 child baseline revision.

The large capability and ADR registries are pinned by selected canonical rows,
not by unrelated container bytes:

- the `CAP-KAFKA` capability row;
- the two `CAP-KAFKA` terminal-owner remaps;
- the planned `J-USER-KAFKA` journey-inventory row;
- the `DEP-ADR-009` roster row;
- the full `DEP-ADR-009` decision row; and
- the matching known-loss fixture.

Each selected object is recursively key-sorted and compactly serialized. Multi-
row projections are bytewise sorted. Every record ends with one LF.

The capability authority still says `KEEP_UNTIL_PARITY`; the current action is
`KEEP_INCUMBENT`. All dependency, feature, API, capability, file-deletion,
production-wiring, oracle-retirement, and cutover permissions remain false.

## Full K0 definition/reference census

The reviewed K0.5 canonical census contains 1,047 selected rows:

| Class | Count | Meaning |
|---|---:|---|
| Primary definitions | 912 | one typed K0 stage/collection/ID definition each |
| Core definitions | 901 | primary definitions excluding contradiction inputs |
| Contradiction inputs | 11 | K0.4 source contradictions retained as input facts |
| Sanctioned authority references | 135 | 33 K0.3 public dispositions plus 102 K0.3 semantic dispositions |

The 912 primary definitions are unique both as typed tuples and raw IDs. Their
typed-tuple digest is
`cb03e74dd5a207aaf082664741fb629d4330bcec76a3edd0958969c6a064b729`.
The 901 core and 11 contradiction digests are, respectively,
`cf110029938e34e3830462a68441d3f678708137242c69a40657aa1e107a01d1`
and
`60a656176b398a9b045b8c5cc1c2f2cede611683d3330c2a519a70ebf9bb72f0`.

The 135 sanctioned repeated raw IDs have ID-set digest
`90457aa8811909a088df43b6f0984b1b8cc262afd5e113f80bc8fcbfdf3bf76e`
and authority-to-reference mapping digest
`83a474e63511cb717689f5f5c9d7206bca7752ebd44c642e277eb0d423d057aa`.
No other definition collision is permitted.

K0.5 also owns 32 aggregate identifiers outside the child 912/135 census:
two canonicalization IDs, six exact-join IDs, twelve unknown-selector IDs,
seven aggregate-claim IDs, and five terminal-gate IDs. Their
`collection<TAB>id` projection digest is
`b37d690dd8293c23a0ed2449bcd019864341f97fe0651798583602804da2fd45`.
These receipt identifiers remain separate from both the child definition
census and the K1 obligation projection.

This selected universe is not every field whose key happens to end in `_id`.
Nested atomic sites, documentation projection groups, scope IDs, K0.5-owned
receipt IDs, and typed reference fields stay outside the primary census for
their declared reasons. K1.1 does not inflate the 912 count with them.

## Exact K1 obligation projection

The K1 contract-obligation projection is narrower than the full K0 census and
is independently frozen. It contains 287 unique rows:

| Domain | Rows |
|---|---:|
| Public symbols | 33 |
| Configuration, enum, operation, and helper semantics | 102 |
| Previously un-IDed K0.2 shared-semantic keys | 12 |
| Explicit absences | 2 |
| Downstream journeys | 15 |
| Fixture vectors | 36 |
| Routed gaps and findings | 87 |

Of those rows, 275 are already stable K0 definitions. The 12
`shared_semantics` object keys were never members of the 912 stable-ID census,
so K1.1 assigns `KAFKA-K1-SHARED-001` through
`KAFKA-K1-SHARED-012` without rewriting K0 history.

For the normalized domain projection, all seven K0.4 vector collections use the
collection name `fixture_vectors`. Its digest is
`59e1ae49f670b9a817c610864ef1b19250657acacf828bef5fc1faceece9084b`.
The source-precise projection retains the seven original collection names and
has digest
`e84e9b969c38366e8e260ea60ca4536f213e51fee02eebb17282f2a201fdbf06`.
Both project `stage<TAB>collection<TAB>id`, bytewise sort unique rows, and append
one LF per row.

The 12 K1-assigned shared-obligation rows separately bind stable K1 IDs to the
original K0.2 object keys, their K1 policy owner, and their protocol-binding
policy. Their projection digest is
`0c50366802e6fbe8d8c2eccfebcd60a20d7daeed1f0304741ee464fb368a717f`.

## Named views and external references

Named views make important subdomains independently checkable without claiming
that overlapping counts add to 912. They cover public symbols, semantic rows,
shared semantics, explicit absences, compilation profiles, downstream journeys,
vectors, fixtures, fixture profiles, environments, and the combined routed
gaps/findings set.

The two explicit absences remain contract obligations:

- `KAFKA-ABS-001`: transactional consumer-offset enrollment; and
- `KAFKA-ABS-002`: Kafka administration API.

They are additive or blocking gaps, not permission to define parity around
today's incomplete surface.

Cross-authority references are kept outside the K0.5 912/135 census:

- six `DEP-ADR-009` journey IDs are exact references to six of K0.3's fifteen
  journey definitions;
- four `CAP-KAFKA` scenario IDs are repeated by the ADR evidence section and
  remain `BASELINE_PLANNED`; and
- `J-USER-KAFKA` is a planned capability-registry inventory row, not executed
  journey evidence.

## Public exposure classes

Lexical `pub` is not one exposure class. K1.1 classifies the 33 K0.1 public
symbol groups as follows:

| Exposure | Count |
|---|---:|
| `FACADE` | 17 |
| `MODULE_PUBLIC` | 13 |
| `CFG_TEST_ONLY` | 2 |
| `CFG_FUZZING` | 1 |
| `PRIVATE` | 0 |

A non-empty K0.1 `facade_exports` array is `FACADE`. KPR-PUB-002 and
KPR-PUB-021 are `CFG_TEST_ONLY`; KPR-PUB-023 is `CFG_FUZZING`; the remaining
rows are `MODULE_PUBLIC`. `PRIVATE` is reserved for later implementation-only
rows and is absent from this public projection.

The bytewise-sorted `symbol_id<TAB>exposure_class` projection digest is
`e5ab5243ac66474b0df051b5716dcdbe9239bc17742c2c5a154094e157786e23`.

## Protocol-binding model

K1.1 defines the allowed binding vocabulary without pretending all rows already
have exact message mappings:

- `MESSAGE_SET`: binds to Kafka request/response messages; exact keys and
  versions belong to K1.2 and K2.1;
- `LOCAL_ONLY`: client-side state or behavior with no fake wire message;
- `CONFIG_MAPPING`: configuration mapped into transport, protocol, security, or
  local policy;
- `ABSENT_GAP`: an accepted obligation absent today;
- `INVENTORY_ONLY`: source, profile, fixture, environment, or evidence
  inventory; and
- `REFERENCE_ONLY`: a typed join that does not redefine its authority row.

Full row-level assignment remains
`BLOCKING_PENDING_K1_2_TO_K1_4`. K1.1 therefore sets
`protocol_binding_assignment_complete=false`. That incomplete later phase does
not make K1.1 incomplete; it prevents K1.1 from stealing later authority or
inventing message bindings.

## Low-evidence states stay low

K1.1 recursively inventories exact low-evidence scalar states across all four
K0 child artifacts. The projection contains 434 unique JSON-path rows:

| State | Count |
|---|---:|
| `UNKNOWN` | 85 |
| `BLOCKED` | 77 |
| `BLOCKED_EXTERNAL` | 15 |
| `NOT_RUN` | 225 |
| `UNPINNED` | 6 |
| `LOCAL_MODEL_ONLY` | 6 |
| `WIRE_CODEC_ONLY` | 20 |

K0.1 and K0.2 contribute zero selected scalar states, K0.3 contributes 302,
and K0.4 contributes 132. Each record is canonical JSON containing child,
exact JSON path, and state. The projection digest is
`288cf0c438852ea0c184c2339c8bf00e69a682a71d6d58bcffed9420b01d6c5c`.

None may become `SUPPORTED`, `PASS`, `EXECUTED`, a real-broker receipt, an
actual-binary receipt, or migration evidence without separately admitted
terminal evidence.

## Owners and collision boundaries

K0.5 retains 267 source-pin rows over 248 unique paths, 87 route rows, 126 route
owner edges, and 49 unique owners. It records no conflicting source overlap,
missing owner, unowned route, or unresolved internal K0 handoff.

The original capture recorded three open incumbent-maintenance beads as
independent inputs rather than silent K1 scope absorption:

- `asupersync-messaging-resp3-kafka-commit-o9ujbk` for the incumbent
  `commit_offsets` worker-blocking defect;
- `asupersync-o82yd7` for feature-lane coverage and the env-gated real-broker
  decision; and
- `asupersync-ne8jdw` for a mixed cold-module review that includes Kafka flush
  worker blocking.

K1.1 neither closes nor absorbs those beads.

## Validation boundary

`tests/kafka_k1_client_contract.rs` is a checked-in static validator for the
packet. It is designed to validate exact input pins, selected registry rows,
the full definition/reference census, the 287-row obligation projection, the
434-row low-evidence-state projection, exposure classes, tracker topology,
owner handoffs, documentation markers, and fail-closed negative mutations.

The original K1.1 capture records no execution receipt for that Rust contract.
Later focused contract runs are recorded separately under the release bead.
JSON parsing, hashes,
counts, joins, and source inspection performed while authoring this packet are
static evidence only. A future execution of the contract must not be described
as broker, protocol, runtime, security, performance, or broad workspace proof.

## No-claim boundary

This K1.1 receipt does not prove:

- compilation, formatting, tests, fuzzing, runtime execution, broker contact,
  external search, network behavior, service health, containers, or remote
  execution;
- Kafka protocol correctness, request/response completeness, `ApiVersions`
  negotiation, downgrade/fallback behavior, flexible-tag handling, or any
  oldest/current broker range;
- native linkage, selected binary identity, codec availability, RecordBatch or
  compression correctness, or broker interoperability;
- TLS, SASL, credential, delivery, idempotence, transaction, consumer-group,
  offset, rebalance, cancellation, shutdown, fault, restart, teardown, or
  residue correctness;
- resource bounds, backpressure, performance, reliability, release readiness,
  broad workspace health, migration readiness, or absence of defects; or
- production wiring, shadow equivalence, rollback readiness, oracle retirement,
  dependency/feature/API/capability removal, file deletion, or cutover.

Any missing, extra, duplicate, unowned, invalidly referenced, promoted, or
regressed accepted row leaves the disposition at `KEEP_INCUMBENT`.

<!-- END KAFKA K1 CLIENT CONTRACT -->
