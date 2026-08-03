# Kafka K1.2 protocol and connection policy

<!-- BEGIN KAFKA K1.2 PROTOCOL SECURITY SUPPORT POLICY -->

This document is the operator-readable companion to
`artifacts/kafka_k1_protocol_security_support_policy_v1.json`. It freezes the
static K1.2 policy packet for
`asupersync-dep-p7-kafka-removal-sarszu.2.1.2`.

K1.2 says what a future first-party Kafka implementation must cover and who
must produce the evidence. It does not claim that the implementation, the
native dependency, or any broker currently satisfies the policy. The governing
disposition remains `KEEP_INCUMBENT`; K15 remains the only conditional cutover
authority.

## Authority and baseline

The packet is rooted in the closed K1.1 namespace authority and the accepted
K0 evidence. Its baseline revision is
`f3a02fe6e6e5d0dca6db91204fcf2da53c22a5c7`.

The fifteen byte-pinned inputs include:

- the K1 obligation index and K1.1 client-contract document and verifier;
- the K0 aggregate disposition, broker-provenance matrix, and incumbent
  semantics matrix;
- the closed K1.3 public API contract;
- ADR DEP-ADR-009;
- the producer and consumer sources;
- the root manifest and lockfile;
- the opt-in broker fixture, local authentication audit, and checked protocol
  model.

Separately, the verifier performs an unpinned, identity-only lookup in
`.beads/issues.jsonl` to confirm that all 36 unique owner and terminal-gate
references exist. Tracker status, title, description, and mutable workflow
fields are not K1.2 authority and are not included among the fifteen byte-pinned
inputs.

The imported K0 views remain independent authorities. K1.2 does not rewrite
their seven broker/API-version vectors, six transport/authentication vectors,
nine owned unknowns, 26 routed gaps, or security-enum semantics. Exact counts
and sorted-ID digests are recorded in the artifact so missing, added,
duplicated, or changed authority rows fail closed.

## Required state is not current support

Every policy row carries both a `required_state` and a
`current_evidence_state`.

`required_state` is the target contract. `current_evidence_state` records what
static inspection observes in the checked repository. `UNKNOWN`, `BLOCKED`, `BLOCKED_EXTERNAL`,
`UNPINNED`, `WIRE_CODEC_ONLY`, `CONFIG_ONLY`, `LOCAL_MODEL_ONLY`, `PROOF_ONLY`,
`STATIC_SOURCE`, and `ROUTED_GAP` are all migration-blocking states. The policy
also treats `NOT_RUN` as blocking if it appears in a later refreshed packet.
Static declarations, configuration mappings, package-source expectations,
mutable tags, local models, and planned checks are not broker or
interoperability receipts.

No cell is promoted to `SUPPORTED`. The artifact records no current real-broker
receipt and no current actual-native-binary receipt.

## Exact policy coverage

The contract contains exactly 90 unique cells:

| Domain | Cells | Purpose |
|---|---:|---|
| Broker support | 6 | oldest/current/mixed topology, negotiated intersection, reconnect identity, provenance |
| Semantic API keys | 20 | minimum request/response families needed by accepted journeys |
| Headers | 5 | request v0-v2 and response v0-v1 |
| Flexible encodings | 8 | compact forms, unsigned varints, tag rules, bounds, downgrade |
| Negotiation transitions | 10 | connect, success, failure, correlation, disconnect, reconnect, drift |
| Transport policy | 8 | local/remote transport, trust, client identity, mechanisms, bypass |
| Credential handling | 8 | trust/certificate/key material, identities, native copies, diagnostics |
| Negative authentication | 15 | invalid identity, trust, proof, parameter bounds, downgrade, and disclosure cells |
| Protocol binding groups | 10 | producer, idempotence, transactions, fetch, groups, offsets, metadata, connection layers, local model |

All rows name an implementation owner, an independent verification owner, and
terminal gates. Broker-dependent rows also name a real-service owner. Missing,
extra, duplicate, changed, unsupported, or unowned rows preserve the incumbent.

The current-evidence distribution is:

| State | Cells |
|---|---:|
| `BLOCKED` | 10 |
| `BLOCKED_EXTERNAL` | 20 |
| `CONFIG_ONLY` | 12 |
| `LOCAL_MODEL_ONLY` | 1 |
| `ROUTED_GAP` | 2 |
| `STATIC_SOURCE` | 7 |
| `UNKNOWN` | 25 |
| `UNPINNED` | 1 |
| `WIRE_CODEC_ONLY` | 12 |

These are inventory counts, not pass counts.

Every broker, API, header, flexible-encoding, negotiation, transport,
credential, and negative cell carries a non-empty `source_authority_ids` join.
Every protocol-binding group carries a non-empty `authority_rows` join. The
verifier resolves those tokens against the pinned K1.1, K0.4, K0.2, and K1.3
JSON authorities plus the governing ADR ID. The direct K1.2 assignments
`KAFKA-K1-SHARED-009` (remote plaintext) and `KAFKA-K1-SHARED-011` (secret
redaction) are retained explicitly. K0.4 unknowns for package selection and the
immutable authenticated fixture remain linked and blocking rather than being
silently omitted.

## Broker and version policy

Six broker cells require independently pinned evidence for the oldest accepted
broker, the current accepted broker, a mixed-version rolling cluster, the
broker/client API intersection, reconnect or broker-identity changes, and the
complete client/native/host/broker/configuration provenance tuple.

No oldest or current broker version is accepted by this packet. Mutable service
tags and ambient endpoints are explicitly insufficient. K13.1 owns a pinned
service harness, K13.5 owns the connection-security and fault matrix, K13.6
owns the real-service terminal, and K12.5 owns the independent terminal.

K2.1 owns exact reachable schema and numeric range closure. The minimum
semantic set contains these twenty API keys:

| Key | Name | Current evidence | Accepted range |
|---:|---|---|---|
| 0 | `Produce` | `WIRE_CODEC_ONLY` | none |
| 1 | `Fetch` | `WIRE_CODEC_ONLY` | none |
| 2 | `ListOffsets` | `UNKNOWN` | none |
| 3 | `Metadata` | `WIRE_CODEC_ONLY` | none |
| 8 | `OffsetCommit` | `UNKNOWN` | none |
| 9 | `OffsetFetch` | `UNKNOWN` | none |
| 10 | `FindCoordinator` | `UNKNOWN` | none |
| 11 | `JoinGroup` | `UNKNOWN` | none |
| 12 | `Heartbeat` | `UNKNOWN` | none |
| 13 | `LeaveGroup` | `UNKNOWN` | none |
| 14 | `SyncGroup` | `UNKNOWN` | none |
| 17 | `SaslHandshake` | `CONFIG_ONLY` | none |
| 18 | `ApiVersions` | `WIRE_CODEC_ONLY` | none |
| 22 | `InitProducerId` | `WIRE_CODEC_ONLY` | none |
| 23 | `OffsetForLeaderEpoch` | `UNKNOWN` | none |
| 24 | `AddPartitionsToTxn` | `UNKNOWN` | none |
| 25 | `AddOffsetsToTxn` | `BLOCKED` | none |
| 26 | `EndTxn` | `UNKNOWN` | none |
| 28 | `TxnOffsetCommit` | `BLOCKED` | none |
| 36 | `SaslAuthenticate` | `CONFIG_ONLY` | none |

This list is a minimum semantic seed, not reachability closure. At claim time,
K2.1 must trace the incumbent and every accepted public journey. Every
additional key reached through metadata, coordination, idempotence,
transactions, fetch, groups, offsets, connection setup, telemetry, or recovery
becomes required.

The checked local model contains five numeric maxima. They are deliberately
stored under `local_model_maxima`, marked non-normative, and excluded from all
accepted production ranges. They cannot be cited as broker support or response
compatibility.

## Header and flexible-encoding policy

The header matrix requires request headers v0, v1, and v2 and response headers
v0 and v1. Selection must be schema-derived. Correlation identity must be
validated before dispatch, and nullable client identity must not be silently
normalized into a different header contract.

The flexible-encoding matrix requires bounded compact strings, compact bytes,
compact arrays, unsigned-varint lengths, strictly ordered and unique tags,
bounded nested tag sections, preservation or explicit rejection of unknown
tags, and a reviewed downgrade path. K2.2 owns bounded primitives; K2.3 owns
versioned schemas, flexible thresholds, and tag semantics; K2.5 owns the
protocol terminal.

Wire-only parser or encoder coverage does not prove a request/response pair,
semantic compatibility, stream recovery, or broker support.

## Negotiation and reconnect state

The ten transition cells define a fail-closed connection state machine:

1. A new connection starts without reusable negotiated state.
2. The client establishes the broker/client intersection before ordinary
   traffic.
3. Unsupported negotiation, no intersection, contradictory ranges, and
   unsupported selected versions fail closed.
4. Every response must match the expected correlation identity.
5. Disconnect invalidates connection-scoped negotiation state.
6. Reconnect renegotiates, including when the endpoint string is unchanged.
7. Range drift and flexible-to-classic fallback require an exact reviewed
   transition; silent decrement or reinterpretation is forbidden.

K2.4 owns negotiation, correlation, reconnect, and reusable-stream recovery.
K2.1 still owns the exact schema and range inputs to those transitions.

## Connection and credential policy

Loopback plaintext remains an accepted local-development mode. Remote plaintext
is refused. Encrypted transport requires trust and hostname verification;
client-certificate authentication requires a matching certificate and key.
The accepted username/password mechanisms are the two configured SCRAM modes
over encrypted transport. Username/password authentication over plaintext is
forbidden.

The checked source currently records configuration shapes and a narrow set of
static guards only. It does not prove native-library capabilities, a completed
handshake, trust validation, client-certificate authentication, or successful
username/password authentication. The insecure-bypass source is deliberately
retained as a routed policy conflict because it is wider than the ADR's
test-only wording.

Credential rows cover trust locations, certificate locations, private-key
locations and bytes, private-key passwords, usernames, password wrappers,
dependency/native copies, and all credential-bearing diagnostics. The target
rule is no secret material in `Debug`, `Display`, errors, traces, receipts,
arguments, environment projections, or retained configuration, with an
explicit lifetime and zeroization disposition for every owned or copied secret
buffer.

Current source evidence is intentionally narrower: selected wrappers redact
and zeroize on wrapper drop, while private-key password storage and native
error propagation remain blocking. K3.2 owns transport implementation, K3.3
owns authentication implementation, K10.4 owns telemetry privacy and
redaction, and K12.4 owns independent review.

## Negative cells

Fifteen explicit negative cells retain invalid user identity, invalid secret,
unsupported mechanism, untrusted issuer, name mismatch, invalid certificate
time, missing client certificate, certificate/key mismatch, invalid key
password, malformed exchange, invalid server proof, downgrade attempt,
secret-canary disclosure, a salt shorter than eight bytes, and an iteration
count outside `4096..=65536`.

The policy requires these failures before broker-visible application effects,
with redacted diagnostics and without silently converting an authentication
failure into a retry loop or a weaker connection mode. The K13.5 real-service
matrix and K12.4 independent review must supply terminal evidence; local
configuration or synthetic checks do not.

## Ownership and terminal gates

| Concern | Implementation owner | Independent or terminal owner |
|---|---|---|
| Reachable keys, schemas, exact ranges | K2.1 | K2.5 / K12.5 |
| Bounded primitives | K2.2 | K2.5 / K12.1 |
| Versioned schemas and flexible encodings | K2.3 | K2.5 / K12.1 |
| Negotiation, correlation, reconnect | K2.4 | K2.5 / K12.5 |
| Connectivity and provenance | K3.1 | K3.5 / K13.6 |
| Encrypted transport | K3.2 | K3.5 / K12.4 / K13.5 |
| Username/password authentication | K3.3 | K3.5 / K12.4 / K13.5 |
| Metadata and routing | K3.4 | K3.5 / K13.6 |
| Claim-time drift refresh | K14.1 | K1.5 / K15 |
| Conditional cutover | K15 only | all required terminal receipts |

The protocol-binding groups connect producer, idempotence, transaction, fetch,
group, offset, and metadata behavior to the exact semantic API rows. Connection
and local-model groups remain separately classified so configuration or local
model evidence cannot masquerade as broker protocol evidence.

## Static validation and no-claim boundary

The companion verifier is
`tests/kafka_k1_protocol_security_support_policy_contract.rs`. It is designed
to check exact input pins, authority views, policy-cell schema, unique IDs,
required/current-state separation, exact key coverage, absent accepted ranges,
owner and gate completeness, source markers, documentation markers, and
fail-closed mutations.

This packet was produced and inspected statically. It does not claim compiler,
formatter, lint, test, model, broker, container, service, network, or remote-job
execution. It does not establish protocol correctness, interoperability,
connection success, authentication success, credential lifetime correctness,
delivery, transactions, group behavior, recovery, performance, release
readiness, broad workspace health, or absence of defects.

It authorizes no production wiring, migration, cutover, dependency exit,
feature/API/capability removal, oracle retirement, or file deletion. Any
missing, extra, duplicate, changed, unowned, unknown, unsupported, or regressed
cell leaves `KEEP_INCUMBENT` in force.

<!-- END KAFKA K1.2 PROTOCOL SECURITY SUPPORT POLICY -->
