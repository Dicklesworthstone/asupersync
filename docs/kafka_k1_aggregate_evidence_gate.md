# Kafka K1 aggregate evidence, coexistence, and rollback gate

<!-- KAFKA_K1_5_AGGREGATE_EVIDENCE_GATE_V1:START -->

This document describes the static K1.5 authority packet for `CAP-KAFKA` and
`DEP-ADR-009`. The machine-readable source of truth is
`artifacts/kafka_k1_aggregate_evidence_gate_v1.json`.

The successful K1.5 disposition is `KEEP_INCUMBENT`. It means the four K1
definition and policy packets have been pinned, joined, and routed well enough
for downstream contract work to begin. It is not permission to wire a native
client, run a shadow lane, remove `rdkafka` or `librdkafka`, retire an oracle,
delete a file, or cut over production behavior.

## Scope and authority

K1.5 consumes the exact artifact, document, and checked-in contract-source
bytes from K1.1 through K1.4. There are 12 direct inputs:

| Stage | Static packet | Accepted role |
|---|---|---|
| K1.1 | `kafka-k1-obligation-index-v1` | sole obligation namespace and definition authority |
| K1.2 | `kafka-k1-protocol-security-support-policy-v1` | protocol, security, and support policy input |
| K1.3 | `kafka-k1-public-api-contract-v1` | API, configuration, error, profile, and migration policy |
| K1.4 | `kafka-k1-resource-lifecycle-contract-v1` | resource, lifecycle, transition, and ownership overlay |

The children expose 51 source-pin rows covering 24 unique paths. Thirteen paths
are repeated across children, and the repeated hashes agree. K1.5 does not
redefine any child obligation. The K1.1 tuple remains the sole definition; all
later rows are typed references or overlays.

## Lineage and conflict adjudication

The aggregate records four cross-child reconciliation conflicts instead of
silently normalizing them:

1. K1.2 is the sole child carrying producer label
   `dependency-sovereignty-rev5`; the other K1 children use
   `asupersync-ir2uf0`. The aggregate retains the literal, excludes
   `program_id` from obligation identity, claims no identity consistency, and
   keeps migration blocked.
2. K1.2 pins K1.3 even though the two tracker nodes are siblings. The pin is
   treated as a redundant, undeclared byte dependency with zero semantic and
   zero completion authority. Its bytes must still agree with the direct K1.3
   child receipt.
3. The K1.2 FETCH, GROUP, and OFFSETS groups have coarse, cross-domain
   authority-row membership. K1.5 preserves their historical bytes and applies
   an explicit row-typed routing overlay.
4. Child-local completion snapshots were captured at different times, and K1.3
   intentionally preserves five reviewed-evolution conflicts. Current child
   closure is checked independently; historical booleans are not forced to
   agree.

All four cross-child reconciliation rows are accounted for, but two rows still
block migration: producer-label variance and the preserved K1.3 blockers. The
five K1.3 conflict IDs, owners, and exact `BLOCKING_*` states remain first-class
child blockers. Aggregate completion does not resolve them.

The current capability registry includes both producer and consumer source
owners plus `Cargo.toml`. Historical gap `KFK-GAP-01` is retained as resolved
provenance, not presented as a current source-owner omission.

## Exact child joins

The seven K1.1 obligation partitions remain exact and disjoint:

| Domain | Rows |
|---|---:|
| public symbols | 30 |
| semantic rows | 97 |
| shared semantic keys | 12 |
| explicit absences | 2 |
| downstream journeys | 15 |
| executable vectors | 36 |
| routed gaps and findings | 87 |
| **Total** | **279** |

The 12 shared semantic keys retain the exact policy split: two owned by K1.2,
seven by K1.3, and three by K1.4. K1.5 is only the aggregate join owner; it does
not introduce a second policy owner.

The K1.3/K1.4 semantic join is also exact:

- 43 `RESOURCE` rows;
- 26 `RESOURCE_AND_LIFECYCLE` rows;
- 28 `CONTEXT_ONLY_NOT_A_DISTINCT_LONG_LIVED_OPERATION` rows;
- 61 expanded configuration-to-resource edges;
- 119 expanded lifecycle-semantic target edges; and
- zero context-only direct resource or lifecycle references.

The packet freezes both expanded edge digests and their tab-separated canonical
projection rules. A missing, duplicate, extra, or unresolved edge keeps the
incumbent.

## Row-typed protocol adjudication

Group-level `binding_kind` is not row-level semantic proof. K1.5 therefore
types every one of the 52 historical authority-row edges across all ten K1.2
groups with one of the six K1.1 kinds:

- `MESSAGE_SET`;
- `CONFIG_MAPPING`;
- `LOCAL_ONLY`;
- `ABSENT_GAP`;
- `INVENTORY_ONLY`; or
- `REFERENCE_ONLY`.

Only `MESSAGE_SET` rows may inherit Kafka message names. Configuration rows,
enums, fixture unknowns, local accessors, and explicit absences cannot be
turned into invented wire coverage by belonging to a nonempty group.

Three membership overlays correct K1.5 routing:

- FETCH binds poll as `MESSAGE_SET`, position as `LOCAL_ONLY`, fetch controls as
  `CONFIG_MAPPING`, and enum context as `REFERENCE_ONLY`.
- GROUP binds subscribe, poll, and close as message-bearing; caller-driven
  rebalance and accessors remain local; group controls remain configuration.
- OFFSETS binds poll and commit as message-bearing; offset values, seek, and
  accessors remain local; manual-commit controls remain configuration.

The original group rows remain pinned as `superseded_authority_rows`. The
overlay changes K1.5 evidence routing only; it does not rewrite the K1.2 child
or prove protocol execution.

Two zero-message-set group gaps remain explicit. METADATA and SASL name future
messages but carry no direct message-authority semantic row. They remain
blocking evidence gaps rather than receiving a fabricated passing edge. Exact
per-row/per-message attribution remains downstream K2.1 work and is not claimed
complete by K1.5.

`KAFKA-ABS-001` and `KAFKA-ABS-002` stay `ABSENT_GAP`. Transactional
consumer-offset enrollment routes to its exact implementation, disposition,
and verification owners. The unallocated administration API routes only to the
K10.1 API decision and K12.5 verification owners. Neither absence inherits a
coarse group state owner or real-service scenario.

## Evidence namespace and routing

K1.5 preserves the exact K0.4 evidence namespace reached through K1.1 and the
K0 aggregate:

| Inventory | Count | State |
|---|---:|---|
| executable vectors | 36 | 13 known, 12 unknown, 11 blocked; zero executed |
| fixtures | 67 | inventory only |
| fixture classification profiles | 8 | inventory only |
| environments | 8 | inventory only |

The 36 vectors retain the exact 3/5/7/5/6/4/6 category split for locked
dependency, native build, broker/API version, compression, transport/auth,
topology, and fault/lifecycle evidence. Every vector ID maps to required
evidence classes, applicable real-service scenarios, and category terminal
gates. Its exact K0.4 executable and refresh owners remain authoritative.

The six evidence classes are unit/component, executable model,
property/metamorphic, bounded fuzz, independent corpus/security, and pinned
real service. Each of the ten capability routes accounts for all six classes:
route-local owner fields cover the first four, K12.5 is the independent
terminal, and nonempty K13 scenarios plus K13.6 cover real service. Planned,
unknown, blocked, static, local-model, compile-only, or silent-skip states do
not count as execution.

The 87 routed gaps retain K1.1's exact 126 owner edges and 49-owner set. The
aggregate references that ledger; it does not replace the many-to-many routing
with one terminal owner.

## Feature coexistence

The incumbent feature remains `kafka`. No native feature identifier has been
allocated. Seven policy profiles partition the exact 13 K1.3 compilation
profiles:

- three native/downstream no-Kafka profiles;
- three incumbent-Kafka profiles, including all-features;
- four unit/test-internals/cross-platform test profiles;
- one excluded fuzz-workspace profile;
- two wasm profiles, preserving both the no-Kafka absence and the
  with-Kafka hard compile error; and
- zero current members for future native-only and both-enabled profiles.

The existing no-feature typed facade and `feature=kafka` incumbent behavior are
preserved exactly. A future implementation may not overload `kafka`, silently
substitute a backend, infer a native test/fuzz/wasm lane, or enable both
implementations before explicit feature allocation and owner-approved graph
work.

## Shadow classification

The 38 K0.2 operation semantics have an exact, duplicate-free operational
partition: 19 local/accessor rows, four resource constructors, one stateful
poll, ten mutators, and four lifecycle/ambiguity rows.

They also map exactly once to the declared shadow policy classes. Resource
construction has its own observe-only class because client, connection,
credential, transaction, thread/task, and teardown ownership is not a broker
read. Poll is isolated side-effecting because it advances consumer/session
state. Offset commit is duplicate-forbidden; seek is isolated-canary state.
Flush, close, and drop recovery are non-comparable lifecycle operations.

The classification uses the maximum effect across accepted profiles. Local
accessors may compare only against a frozen snapshot or identical replay; live
same-target dual execution is not authorized. Per-operation K14.3 owner
routing remains pending, so the exact partition is policy, not admission.

## Stop and rollback rules

Twelve stop conditions cover authority drift, provenance, semantic divergence,
protocol faults, ambiguous effects, ownership loss, resource limits, privacy,
duplicate effects, teardown, security, and performance evidence. Any trigger
fences the native lane and retains the incumbent.

Seven rollback cases cover local work, broker reads, produce delivery,
transactions, groups, offsets, and security/resource residue. Rollback never
means blind replay. Ambiguous delivery, transaction, assignment, or offset
state must be reconciled by its named owner before identity reuse or incumbent
resumption.

No rollback is currently required because K1.5 changes no production path.
The rollback taxonomy remains a prerequisite for any future isolated lane.

## Static receipt and no-claim boundary

The artifact records exact byte/record/SHA-256 pins, exact set and expanded-edge
digests, and 17 independently recomputable projection scopes. Duplicate IDs and
count drift are rejected before hashing so canonicalization cannot hide an
inserted duplicate.

This work session used static JSON, text, file, tracker, and Git inspection
only. No compiler, formatter, linter, test process, fuzz harness, benchmark,
runtime, broker, service, container, network workload, remote compilation job,
or dynamic validation was executed. The checked-in Rust contract is source for
a later authorized validation lane; its presence is not a green test receipt.

Accordingly, K1.5 proves no Kafka protocol correctness, runtime ownership,
broker interoperability, security behavior, performance, no-regression result,
release readiness, broad workspace health, or absence of defects. K15 remains
the sole conditional cutover owner, and any future GO proposal requires a new
serialized decision.

<!-- KAFKA_K1_5_AGGREGATE_EVIDENCE_GATE_V1:END -->
