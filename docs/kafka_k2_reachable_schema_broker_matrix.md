# Kafka K2.1 reachable schema and broker matrix

<!-- BEGIN KAFKA K2.1 REACHABLE SCHEMA BROKER MATRIX -->

This document is the human-readable companion to
`artifacts/kafka_k2_reachable_schema_broker_matrix_v1.json` for
`asupersync-dep-p7-kafka-removal-sarszu.2.2.1`.

The packet freezes a static 22-key reachability frontier and the normative
source identities needed to finish K2.1. It deliberately does not close K2.1:
no numeric range is accepted, no field or error projection is complete, and no
oldest/current broker profile is admitted. K2.2 therefore remains blocked.

## Outcome

K1.2 defined a minimum semantic seed of 20 API keys. Static inspection of the
pinned `rdkafka-sys 4.10.0+2.12.1` package, which contains librdkafka 2.12.1,
found two additional conditionally reachable keys:

- `GetTelemetrySubscriptions` (71); and
- `PushTelemetry` (72).

The incumbent configuration defaults `enable.metrics.push` to true. Its broker
selection and telemetry sources can issue both requests when the negotiated
broker capabilities permit them. These are reachability findings, not evidence
that a broker accepted the requests or requested telemetry.

The selected frontier excludes the admin API family because the shipped
Asupersync Kafka facade has no admin surface. It also excludes
`ConsumerGroupHeartbeat` (68): the incumbent defaults to the classic group
protocol and the facade exposes no override. `ConsumerGroupDescribe` (69) is
admin-only in the pinned incumbent. Additive admin parity remains owned by
K10.1.

## Authorities

Repository authority is byte-pinned in the JSON packet: the root manifest and
lockfile, producer and consumer sources, K1.2 policy, K1.5 aggregate gate, K0.4
broker-provenance baseline, and K1.3 public-surface contract.

The normative current schema source is Apache Kafka tag `4.3.1`, dereferenced
to commit `26b251a451ce941d3d7a55e6487bcb7f16b5ad48`. Historical broker candidates
are source-identified at `0.8.0`, `0.11.0.2`, and `1.0.0`. A source tag and
commit are not a runnable broker identity or an interoperability receipt.

The 22 request/response source pairs are selected from Apache Kafka's
`clients/src/main/resources/common/message` directory at that immutable current
commit. At the pinned commit, the packet records the Git blob object ID and
payload byte count for all 44 selected current request/response files. The
canonical root tree was complete rather than truncated, and the sorted
path/object-ID/size projection is independently pinned by SHA-256.

Those Git object IDs cover the Git blob header plus exact payload bytes; they
are not per-file raw-byte SHA-256 security attestations. This establishes
current-source object identity only. It does not project fields, defaults,
errors, accepted versions, historical schema coverage, or broker behavior.

## Reachable API frontier

`Client max` is an independent incumbent cross-check. `Apache range` comes
from the selected Apache 4.3.1 message schema. `Candidate intersection` is
mechanically readable review input only; it is not an accepted range. `Flex`
is the first flexible version, or `none` when the schema has no flexible
version.

| Key | API | Reachability | Client max | Apache range | Candidate intersection | Flex | Accepted |
|---:|---|---|---:|---|---|---:|---|
| 0 | `Produce` | explicit | 10 | 3-13 | 3-10 | 9 | none |
| 1 | `Fetch` | explicit | 16 | 4-18 | 4-16 | 12 | none |
| 2 | `ListOffsets` | explicit | 7 | 1-11 | 1-7 | 6 | none |
| 3 | `Metadata` | explicit | 13 | 0-13 | 0-13 | 9 | none |
| 8 | `OffsetCommit` | explicit | 9 | 2-10 | 2-9 | 8 | none |
| 9 | `OffsetFetch` | explicit | 9 | 1-10 | 1-9 | 6 | none |
| 10 | `FindCoordinator` | explicit | 2 | 0-6 | 0-2 | 3 | none |
| 11 | `JoinGroup` | explicit | 5 | 0-9 | 0-5 | 6 | none |
| 12 | `Heartbeat` | explicit | 3 | 0-4 | 0-3 | 4 | none |
| 13 | `LeaveGroup` | explicit | 1 | 0-5 | 0-1 | 4 | none |
| 14 | `SyncGroup` | explicit | 3 | 0-5 | 0-3 | 4 | none |
| 17 | `SaslHandshake` | explicit, native-capability blocked | 1 | 0-1 | 0-1 | none | none |
| 18 | `ApiVersions` | explicit | 3 | 0-4 | 0-3 | 3 | none |
| 22 | `InitProducerId` | explicit | 4 | 0-6 | 0-4 | 2 | none |
| 23 | `OffsetForLeaderEpoch` | explicit | 2 | 2-4 | 2 | 4 | none |
| 24 | `AddPartitionsToTxn` | explicit | 0 | 0-5 | 0 | 3 | none |
| 25 | `AddOffsetsToTxn` | required additive, absent | 0 | 0-4 | 0 | 3 | none |
| 26 | `EndTxn` | explicit | 1 | 0-5 | 0-1 | 3 | none |
| 28 | `TxnOffsetCommit` | required additive, absent | 3 | 0-5 | 0-3 | 3 | none |
| 36 | `SaslAuthenticate` | explicit, native-capability blocked | 1 | 0-2 | 0-1 | 2 | none |
| 71 | `GetTelemetrySubscriptions` | implicit default telemetry | 0 | 0 | 0 | 0 | none |
| 72 | `PushTelemetry` | implicit default telemetry | 0 | 0 | 0 | 0 | none |

## Header selection

The static schema selection reaches request header v1 with response header v0
for classic encodings, and generally request header v2 with response header v1
for flexible encodings. `ApiVersions` is the required exception: its flexible
body retains response header v0 so older clients can parse the response.
Request header v0 remains required by the broader K1.2 policy but is not reached
by the selected request families and versions. Header selection remains a
candidate until exact accepted numeric ranges are reviewed.

## Broker candidates

Four profiles are source-identified but blocked:

| Profile | Candidate | Intended scope | Admission |
|---|---|---|---|
| Basic legacy | 0.8.0 | explicit non-idempotent producer and legacy fetch | blocked |
| Default idempotence floor | 0.11.0.2 | default producer, idempotence, transactions | blocked |
| Wrapped authentication floor | 1.0.0 | wrapped authentication exchange | blocked |
| Current | 4.3.1 | current supported release at capture | blocked |

Admission requires immutable runnable identities plus oldest/current schema
probe receipts containing negotiated capabilities and normalized request and
response fingerprints. None is present in this packet.

## Why the existing runner is nonterminal

`scripts/kafka_broker_parity_proof_runner.sh` is retained unchanged and was not
executed for this packet. Static inspection found that it permits skipped rows,
can report an unknown or unavailable broker version, and does not emit the
normalized request/response fingerprints required for an immutable
oldest/current pair. Its output cannot close K2.1 as written.

## Remaining closure work

K2.1 remains open until all of the following are complete:

1. Project the 44 selected current schema bodies whose Git blob identities are
   pinned here, and pin and project the historical request and response
   structures required by each oldest-broker candidate.
2. Project every field path, order, type, version interval, default,
   nullability, compact encoding, tagged version, and tag identifier.
3. Project every reachable protocol error and its reviewed downgrade or
   fail-closed action.
4. Adjudicate candidate intersections into explicit accepted numeric ranges.
5. Retain immutable oldest/current broker identities and terminal schema-probe
   receipts.
6. Independently cross-check the field and error projections without treating
   the incumbent implementation as normative.

## Validation and claim boundary

This pass used repository inspection, exact byte/hash inventory, official
source identity lookup, and an independent incumbent-source cross-check only.
It ran no compiler, formatter, test, broker, service, container, protocol
session, or remote job.

The packet does not prove schema completeness, broker interoperability,
runtime correctness, production support, migration readiness, dependency
removal, release readiness, performance, or broad workspace health. It does
not authorize K2.2 or any production wiring.

<!-- END KAFKA K2.1 REACHABLE SCHEMA BROKER MATRIX -->
