# Kafka K2.1 reachable schema and broker matrix

<!-- BEGIN KAFKA K2.1 REACHABLE SCHEMA BROKER MATRIX -->

This document is the human-readable companion to
`artifacts/kafka_k2_reachable_schema_broker_matrix_v1.json` for
`asupersync-dep-p7-kafka-removal-sarszu.2.2.1`.

The packet freezes a static 22-key reachability frontier and the normative
source identities needed to finish K2.1. It now also contains a bounded,
partial body projection: 39 field rows cover `ApiVersions` plus the two
authentication APIs across current and applicable historical profiles. Ten
source-established outcome-membership rows cover authentication only. It
deliberately does not close K2.1: no numeric range is accepted, no
full-frontier field or error projection is complete, and no oldest/current
broker profile is admitted. K2.2 therefore remains blocked.

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
current-source object identity only. The API 18 and authentication slices below
project only bounded candidate body fields, defaults, tree metadata, and
authentication outcome membership. They do not establish a complete
field/default/error matrix, accepted versions, broker behavior, or
interoperability.

The three historical candidate profiles now have profile-scoped source-object
receipts as well. Kafka changed its schema-authority model across these
releases, so the packet records the native declaration form instead of
pretending that modern per-message JSON existed historically:

| Candidate | Declaration model | Profile API rows | Source objects | Bytes |
|---|---|---|---:|---:|
| 0.8.0 | Scala write/parse methods plus the classic envelope and legacy message set | keys 0-3 at v0 | 22 | 95,596 |
| 0.11.0.2 | central Java `Protocol` schema arrays plus headers/type encodings | nine idempotent/transaction profile keys, the API 18 v0-1 body tree, plus a structured API 23 full-frontier blocker | 10 | 210,904 |
| 1.0.0 | per-request Java schema arrays plus headers/type encodings | `SaslHandshake` 0-1 and `SaslAuthenticate` 0 | 14 | 118,304 |

Each receipt pins the canonical root tree, confirms the recursive tree was not
truncated, and separately hashes the sorted path/object-ID/size and
path/semantic-role projections. The 46 profile/path rows resolve to 44 distinct
blob object IDs because two unchanged files recur across the 0.11.0.2 and 1.0.0
profiles. These are candidate source-provenance rows only. They neither select
an oldest supported broker nor establish complete current-facade coverage.

Nine additional projection-support source rows pin the current message-format
semantics, generated field-default resolver and assignment logic, error
registry, handshake request wrapper, two current response wrappers, and current
and historical dedicated authentication handlers. Their 239,139 source bytes
are identity evidence for the bounded API 18 and authentication field, default,
and outcome rows below; they are not executable broker evidence.

The 0.11.0.2 audit also exposes a concrete incompatibility outside its narrow
producer profile. A structured blocker row records broker minimum/maximum v0
and incumbent minimum/maximum v2 for `OffsetForLeaderEpoch`; because broker
maximum is below incumbent minimum, the intersection is empty. Thus 0.11.0.2
cannot be promoted to full current-facade support from this static source
packet.

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
candidate until exact accepted numeric ranges are reviewed. The field
projection rows below are body-only: shared request and response header fields
are not duplicated into each message tree, and the API 18 response-header-v0
exception remains explicit in the separate header contract.

## Partial body projection

### API 18 negotiation body

Twenty-four rows project the complete body-field tree declared for API 18 by
the current 4.3.1 schema and the historical 0.11.0.2 candidate. The historical
request schemas for v0-v1 are empty, so they correctly produce no request field
row. The current request fields begin at v3 and remain ignorable, while their
generated object defaults are recorded across the current message domain
without claiming that an absent wire field was decoded.

| Profile | Direction | Top-level body fields | Named-struct children | Source versions |
|---|---|---|---|---|
| 4.3.1 current | request | `ClientSoftwareName`, `ClientSoftwareVersion` | none | 3-4 |
| 4.3.1 current | response | `ErrorCode`, `ApiKeys`, `ThrottleTimeMs`, `SupportedFeatures`, `FinalizedFeaturesEpoch`, `FinalizedFeatures`, `ZkMigrationReady` | `ApiVersion`: `ApiKey`, `MinVersion`, `MaxVersion`; `SupportedFeatureKey`: `Name`, `MinVersion`, `MaxVersion`; `FinalizedFeatureKey`: `Name`, `MaxVersionLevel`, `MinVersionLevel` | field-specific subsets of 0-4 |
| 0.11.0.2 historical | request | none | none | empty schemas at 0-1 |
| 0.11.0.2 historical | response | `ErrorCode`, `ApiVersions`, `ThrottleTimeMs` | `API_VERSIONS_V0`: `ApiKey`, `MinVersion`, `MaxVersion` | field-specific subsets of 0-1 |

Each child row carries a `parent_row_id`; `field_order` is sibling-local rather
than globally flattened. Named arrays retain their exact source-declared nested
type, and current map-key metadata is preserved on the API key and two feature
name children. Child versions are the intersection of the child declaration,
the owning message, and every ancestor array.

For current v3-v4, the request strings, named arrays, and feature-name strings
use compact encodings. Every flexible owning body struct has a tag buffer. The
four tagged response fields retain their source IDs: `SupportedFeatures` is 0,
`FinalizedFeaturesEpoch` is 1, `FinalizedFeatures` is 2, and
`ZkMigrationReady` is 3. The separately selected API 18 response header remains
v0 for every body version and is not represented as a body child.

Current generated defaults are recorded as empty strings, empty arrays, or
numeric zero according to type, except for the two explicit response literals:
`FinalizedFeaturesEpoch=-1` and `ZkMigrationReady=false`. The historical
0.11.0.2 `Struct` fields remain required with no default. These rows establish
source-schema structure only: API 18 error/fallback semantics, negotiation
downgrade policy, accepted ranges, and broker execution remain unprojected.

### Authentication fields and outcomes

The populated field rows cover current Kafka 4.3.1 API 17 v0-1 and API 36
v0-2, plus historical Kafka 1.0.0 API 17 v0-1 and API 36 v0. Projecting the
current API 36 source-only v2 form does not expand the incumbent candidate
intersection of v0-1 or accept any production version. Source field names are
retained alongside stable canonical field IDs so the modern and historical
spellings can be compared without treating either spelling as the wire
contract.

| Profile | API/direction | Projected body fields | Projected versions |
|---|---|---|---|
| 4.3.1 current | 17 request | `Mechanism` | 0-1 |
| 4.3.1 current | 17 response | `ErrorCode`, `Mechanisms` | 0-1 |
| 4.3.1 current | 36 request | `AuthBytes` | 0-2; compact at 2 |
| 4.3.1 current | 36 response | `ErrorCode`, nullable `ErrorMessage`, `AuthBytes`, `SessionLifetimeMs` | 0-2; lifetime starts at 1; variable-length fields compact at 2 |
| 1.0.0 historical | 17 request | `mechanism` | 0-1 |
| 1.0.0 historical | 17 response | `error_code`, `enabled_mechanisms` | 0-1 |
| 1.0.0 historical | 36 request | `sasl_auth_bytes` | 0 |
| 1.0.0 historical | 36 response | `error_code`, nullable `error_message`, `sasl_auth_bytes` | 0 |

The authentication rows preserve order, logical/wire type, array element type, nullability,
explicit schema-default presence, effective default or required-field absence,
projected compact/tag state, sensitivity, and nested-payload disposition.
`SessionLifetimeMs` is the sole authentication field with an explicit schema
literal (`0`). The separate effective-default columns prevent schema-declaration
absence from being confused with generated or legacy `Struct` behavior:

| Profile | Fields | Effective default or missing-field behavior |
|---|---|---|
| 4.3.1 current | `Mechanism`, `ErrorMessage` | generated non-null empty string (`""`) |
| 4.3.1 current | `ErrorCode` | generated integer zero |
| 4.3.1 current | `Mechanisms` | generated empty string list |
| 4.3.1 current | `AuthBytes` | generated empty byte sequence (`0x`) |
| 4.3.1 current | `SessionLifetimeMs` | explicit schema zero applied by generated data logic across v0-2; the field itself is present only in v1-2 |
| 1.0.0 historical | six non-nullable API 17/36 fields | required with no default; unset lookup is rejected |
| 1.0.0 historical | nullable `error_message` | unset `Struct` lookup resolves to null, without an explicit schema default |

The historical provenance chain retains the wrapper declaration plus `Field`,
`Type` (and `ArrayOf` for mechanisms), and `Struct`, so the nullability result
consumed by unset lookup is source-backed rather than inferred from the field
name.

Current `ErrorMessage` is deliberately the sharp edge: nullable wire versions
permit an explicit null value, but nullability alone does not make null the
generated default. Its omitted schema default resolves to an empty string. The
historical nullable field instead falls back to null through `Struct` lookup.
The historical two-argument `SaslAuthenticateResponse` convenience overload
supplies empty response authentication bytes, but that wrapper choice is not a
schema default and is not generalized to the other required fields.

Effective-default version intervals identify the source-profile domain of the
constructor or unset-field rule; they do not mean decoding ignores a value that
is present on the wire.

API 36 source v2 is now projected as a flexible message: its variable-length
fields use compact encodings, every request and response body ends in a tag
buffer, and the schema declares no tagged field IDs. This source-only expansion
does not change the incumbent v0-1 candidate intersection, admit v2, or establish
runtime handling. The nested mechanism payload carried in `AuthBytes` remains
unprojected.

The ten outcome rows are source-established memberships, not a closed
wire enum:

| Profile | API | Projected outcomes |
|---|---:|---|
| current and historical | 17 | `NONE=0`, `UNSUPPORTED_SASL_MECHANISM=33`, `ILLEGAL_SASL_STATE=34` |
| current and historical | 36 | `NONE=0`, `SASL_AUTHENTICATION_FAILED=58` |

For API 17, the dedicated handler establishes codes 0 and 33 directly and
emits code 34 through its illegal-state exception-to-handshake-response path.
For API 36, the canonical error registries and dedicated handlers establish
code 58. Both
current and historical response-wrapper comments instead contain stale code 57,
so the packet retains 57 as a source-conflict annotation while preserving 58 as
the canonical code. Retry and downgrade actions remain unprojected and blocking.

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

1. Extend the partial API 18 and authentication-body projection across the other 19
   reachable APIs and any historical profile selected by broker-floor
   adjudication; pin each additional interpretation source.
2. Complete every remaining reachable body and header path, order, type,
   version interval, effective default, nullability, compact encoding, tagged
   version, and tag identifier beyond the projected API 18 and authentication
   slices.
3. Extend the ten authentication outcome memberships into exhaustive reachable
   error projections with reviewed retry, downgrade, or fail-closed action.
4. Adjudicate candidate intersections into explicit accepted numeric ranges.
5. Retain immutable oldest/current broker identities and terminal schema-probe
   receipts.
6. Extend the independent official-source cross-check beyond the API 18 and
   authentication-body slices without treating the incumbent implementation as
   normative.

## Validation and claim boundary

This pass used repository inspection, exact byte/hash inventory, current and
historical official-source reviews, and an independent incumbent-source
cross-check only. It ran no compiler, formatter, test, broker, service,
container, protocol session, or remote job.

Git blob object IDs establish source-object identity, not per-file raw-byte
SHA-256 security attestations. Historical range rows are source-derived
candidate overlaps; none is an accepted production range or downgrade policy.

The packet does not prove full schema or error completeness, defaults outside
the 39 API 18 and authentication-body rows, API 18 error/fallback behavior,
exhaustive wrapper or call-site value behavior, acceptance or runtime handling
of current API 18 v4 or API 36 v2, broker interoperability, runtime correctness,
production support, migration readiness, dependency removal, release readiness,
performance, or broad workspace health. It does not authorize K2.2 or any
production wiring.

<!-- END KAFKA K2.1 REACHABLE SCHEMA BROKER MATRIX -->
