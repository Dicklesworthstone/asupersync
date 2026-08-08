# Kafka K1.4 Cx resource and lifecycle ownership contract

<!-- BEGIN KAFKA K1.4 RESOURCE LIFECYCLE CONTRACT -->

This document is the operator-readable companion to
`artifacts/kafka_k1_resource_lifecycle_contract_v1.json`. It freezes the
static K1.4 contract for
`asupersync-dep-p7-kafka-removal-sarszu.2.1.4`.

K1.4 describes the resource and lifecycle policy a future first-party Kafka
implementation must satisfy. It does not claim that the current wrapper, the
native dependency, or a broker satisfies that policy. The governing
disposition remains `KEEP_INCUMBENT`; K1.5 still owns the aggregate static
gate, and K15 remains the only conditional cutover authority.

## Authority and baseline

The packet is rooted at claim commit
`4b99ef71dbb1b7adbfbef4a3a9a4c2377fcbd6dd` and byte-pins fifteen inputs:

- the K1.1 authority artifact, document, and static contract source;
- the closed K1.2 protocol/security policy and K1.3 public API contract;
- the K0.5 aggregate, K0.2 incumbent semantics, and K0.4 broker/fault
  provenance artifacts;
- ADR DEP-ADR-009;
- the producer/transaction and consumer sources;
- the blocking bridge and Cx blocking-pool sources;
- the root manifest and lockfile.

The tracker remains an unpinned identity lookup. Mutable bead status, comments,
titles, and timestamps are not K1.4 evidence.

K1.1 assigns exactly three shared obligations to K1.4:

| Obligation | Source key | Binding |
|---|---|---|
| `KAFKA-K1-SHARED-003` | `cancellation_model` | `LOCAL_ONLY` |
| `KAFKA-K1-SHARED-010` | `resource_model` | `LOCAL_ONLY` |
| `KAFKA-K1-SHARED-012` | `shutdown_model` | `LOCAL_ONLY` |

The packet also preserves all 97 K0.2 semantic rows. Forty-three
configuration rows are classified as resource authority and 26 operation rows
as direct resource-and-lifecycle authority. The remaining 28 rows—seven enums,
nine helpers, nine accessors/diagnostics, two validators, and one value
constructor—are context that does not itself acquire a distinct long-lived
owner. Context-only does not discard those rows' retry, timeout, cancellation,
shutdown, or resource-bound facts.

K1.2's ten negotiation transitions and ten protocol-binding groups remain
cross-slice target-policy context. They are not exhaustive lifecycle coverage:
the binding groups omit important direct operations such as poll, subscribe,
rebalance, close, commit, seek, and offset accessors. K1.4 therefore resolves
K0.2 semantic IDs directly rather than treating a nonempty K1.2 binding group
as lifecycle proof.

## Current evidence is not required native policy

Every resource row separates current incumbent evidence from required native
policy. The current and required sides each name a unit, default, minimum, and
maximum-or-hard-cap field. A null number is accepted only with an explicit
blocking state. It never means zero, safe unlimited behavior, supported, or
dependency parity.

The current-state vocabulary deliberately distinguishes:

- exact source defaults or Rust type domains that are not admission policies;
- configured broker hints that do not cap local allocation;
- inert fields that do not affect the current operation;
- locally unbounded collections, queues, waiters, strings, or bytes;
- process-global model state that is not Cx-owned;
- dependency-owned quantities that static source cannot enumerate; and
- intended state-machine limits that current races do not enforce.

Required numeric values remain blocking where downstream owners have not yet
frozen them. K1.4 does not guess a connection count, request cap, queue size,
batch budget, partition count, task limit, or diagnostic-retention policy.
Two one-unit limits are frozen here: one live transaction handle per
transactional producer, and the broker-operation mutex's inherent one-holder
exclusion. Current source does not prove the transaction-handle cap under
concurrent begin and recovery, while the mutex's aggregate waiter population
remains unfrozen.

Accordingly, `required_numeric_policy_complete` is false even though the K1.4
static inventory itself is complete. A null required value must carry an exact
blocking state and remains work for its named downstream owner.

## Exact resource coverage

The artifact contains 42 unique resource rows. Each row names its unit,
current and required numeric fields, admission outcome, owner scope, combined
backpressure/overflow behavior, release point, accounting invariant,
implementation owner, independent verification owner, terminal gates, and
blocking state.

All 43 K0.2 configuration semantics have an explicit machine binding to at
least one resource row. Sixteen composite resource classes also have
43 per-unit limit dimensions, so a bytes cap cannot stand in for an entry-count
cap and a worker cap cannot stand in for a pending-task cap.

| ID | Resource class | Current numeric state | Primary implementation owner |
|---|---|---|---|
| `K1R-001` | Broker connections | Dependency-owned unknown | K3.1 |
| `K1R-002` | In-flight requests and correlations | Dependency-owned / first-party model absent | K3.1 |
| `K1R-003` | Metadata, routing, and coordinator cache | Dependency-owned unknown | K3.4 |
| `K1R-004` | Producer payload bytes | Exact 1 MiB default and minimum 1; no policy maximum | K5.1 |
| `K1R-005` | Topic, key, headers, and framing | Locally unbounded | K5.1 |
| `K1R-006` | Producer batch target | 16 KiB hint; no local accumulator cap | K5.2 |
| `K1R-007` | Producer delivery queue | Dependency-owned unknown | K5.2 |
| `K1R-008` | Producer retry attempts | Default 3; `u32` domain, not total-work bound | K5.4 |
| `K1R-009` | Producer request timer | Default 30 seconds; not an end-to-end deadline | K5.3 |
| `K1R-010` | Producer active operations | Uncapped admission over wrapping platform-width `AtomicUsize` | K11.1 |
| `K1R-011` | Deterministic retained records | Unbounded process-global test model | K11.1 |
| `K1R-012` | Transaction handles | Intended single active handle; not race-safe | K6.1 |
| `K1R-013` | Transaction staged records | Unbounded local model and dependency queue | K6.1 |
| `K1R-014` | Transaction coordinator, partitions, offsets | Dependency-owned or absent | K6.3 |
| `K1R-015` | Subscription topics | Locally unbounded | K8.3 |
| `K1R-016` | Group assignment and rebalance state | Unbounded collections; saturating generation | K8.3 |
| `K1R-017` | Buffered poll outcome | One slot with overwrite-loss risk | K7.3 |
| `K1R-018` | Copied fetched-record memory | Broker hints, no local copy cap | K7.3 |
| `K1R-019` | Offset commit batch | Nonempty minimum; caller-sized and uncapped | K9 |
| `K1R-020` | Offset and position maps | Unbounded with stale-entry retention | K9 |
| `K1R-021` | Consumer retry attempts | Default 3; no total-time cap | K9 |
| `K1R-022` | Cx blocking-pool pending tasks | Finite workers, unbounded pending queue | K11.1 |
| `K1R-023` | Fallback blocking threads | 256 global spawned-thread cap, not Cx ownership | K11.1 |
| `K1R-024` | Fallback blocking waiters | Unbounded and not operation-Cx cancellable | K11.1 |
| `K1R-025` | Retained configuration, errors, diagnostics | Unbounded local/dependency state | K10.4 |
| `K1R-026` | Native threads, callbacks, queues, tasks | Dependency-owned unknown | K11.1 |
| `K1R-027` | Producer linger timer | Default 5ms; full `u64` domain; dependency-owned batching | K5.2 |
| `K1R-028` | Producer retry backoff timer | Default first delay 5ms; per-delay cap 250ms; no total deadline | K5.4 |
| `K1R-029` | Producer flush/close caller deadline | Caller supplied; no source default or hard cap | K5.3 |
| `K1R-030` | Producer flush/close poll slice | No default; positive range starts at 1ns and caps at 10ms | K5.3 |
| `K1R-031` | Transaction timeout | Default 60s; excludes queue and fallback wait | K6.1 |
| `K1R-032` | Consumer session timeout | Default 45s; saturated native mapping; no relation check | K8.5 |
| `K1R-033` | Consumer heartbeat interval | Default 3s; dependency-owned timer | K8.5 |
| `K1R-034` | Consumer commit retry backoff | Default first delay 3s; 5s cap; truncating conversion | K9 |
| `K1R-035` | Consumer auto-commit interval | Default 5s; timer inert by default, dependency-owned when enabled | K9 |
| `K1R-036` | Consumer fetch wait | Default 500ms; not the caller poll deadline | K10.2 |
| `K1R-037` | Consumer poll caller deadline | Caller supplied; excludes queue and mutex wait | K7.3 |
| `K1R-038` | Consumer broker poll slice | Fixed maximum 50ms after admission | K7.3 |
| `K1R-039` | Consumer seek timeout | Fixed 1s native timeout; excludes admission wait | K9 |
| `K1R-040` | Diagnostic client session timeout | Fixed 6s dependency setting; not Cx-owned | K10.2 |
| `K1R-041` | Diagnostic client consumer slot | Exact one-slot maximum with unbounded topic bytes | K10.1 |
| `K1R-042` | Consumer broker-operation mutex holders/waiters | One holder; aggregate waiters unknown because inline execution bypasses the 256 spawned-thread counter | K11.1 |

These counts are inventory, not proof that a limit is safe or effective.

## Numeric facts and non-facts

The checked source establishes a small set of concrete values:

- producer `max_message_size` defaults to 1,048,576 bytes and rejects zero;
- producer `batch_size` defaults to 16,384 bytes and rejects zero;
- producer retries default to 3, and request timeout defaults to 30 seconds;
- producer linger defaults to 5 milliseconds, drives retry backoff, and each
  wrapper delay caps at 250 milliseconds without one total retry deadline;
- transaction timeout defaults to 60 seconds, but does not cover every queue or
  begin phase;
- consumer session timeout defaults to 45 seconds, heartbeat to 3 seconds,
  auto-commit interval to 5 seconds, fetch wait to 500 milliseconds, and
  consumer retries to 3;
- consumer fetch hints default to 1-byte minimum and 52,428,800-byte maximum;
- consumer broker poll slices cap at 50 milliseconds only after queue and
  mutex admission, while the caller deadline is a separate resource;
- seek passes a fixed one-second timeout to the dependency; and
- the diagnostic KafkaClient retains at most one topic-aware consumer and
  hard-codes its session timeout to 6 seconds; and
- the process-global fallback bridge caps successfully spawned threads at 256.

Those values do not establish complete bounds:

- the producer payload cap excludes topic, key, headers, framing, batch
  aggregate, queue entries, and retained deterministic storage;
- `batch_size` is a dependency configuration hint, not a first-party bounded
  accumulator;
- `max_poll_records=500` is validated but inert; the wrapper returns at most
  one record and does not use this field as a queue or memory cap;
- fetch byte settings are broker request hints, not local copied-record or
  header-memory caps;
- the 256 fallback-thread cap does not cap accepted jobs or waiting callers;
- a finite retry counter without one total deadline does not bound total work;
  and
- Rust integer or `Duration` domains are not reviewed admission limits.

## Admission, backpressure, and overflow

The `overflow_behavior` field records both incumbent backpressure and overflow
behavior. Current outcomes include immediate dependency rejection, retry,
unbounded allocation, unbounded waiting, silent one-slot replacement, inline
execution after thread-spawn failure, or dependency-unknown behavior.

None of those is silently promoted to the required target. The target must
freeze whether each saturated resource waits, rejects, sheds, splits, flushes,
transfers ownership, or returns a typed capacity outcome. That decision must be
bounded by the same Cx deadline and cancellation contract as the operation
that requested admission.

The current producer exposes `QueueFull` after dependency behavior and wrapper
retry, but does not own a queue permit. The consumer admits unlimited poll
callers to one shared outcome slot. The Cx blocking pool has finite workers but
an uncapped pending queue. The fallback bridge limits running spawned threads,
not waiters. Native consumer operations also serialize behind one `broker_ops`
mutex. Successfully spawned closures share the process-global 256-thread
ceiling, but OS spawn failure decrements that counter before running the
closure inline; the aggregate mutex population therefore has no frozen cap.
An unbounded caller population can also wait earlier for thread slots. These
are distinct resources with distinct owners.

## Cx ownership, release, and accounting

The resource contract requires:

1. every admitted resource to acquire exactly one owner;
2. every ownership transfer to retain the same charge and certainty receipt;
3. every definitive terminal state to release exactly once;
4. every ambiguous terminal state to install a named residue or recovery
   owner rather than decrementing accounting as if work never happened; and
5. Cx quiescence to require the balance of operations, tasks, jobs, waiters,
   threads, timers, callbacks, queues, records, transactions, group state,
   offsets, and diagnostics to be terminally resolved.

Dependency-owned and process-global incumbent resources fail this native
ownership rule. A local RAII decrement, callback, object drop, or collection
clear is useful evidence about one layer, not a complete Cx accounting proof.

## Lifecycle state coverage

The artifact contains 19 lifecycle rows and exactly 133 transition cells.
Each row has an explicit state set and exactly one transition for each required
1. `timeout`
2. `cancellation`
3. `shutdown`
4. `panic`
5. `retry`
6. `restart`
7. `ambiguous_outcome`

Each transition names source states, current destination states, the current
rule and certainty, the required target state, an owner, and a blocking gate.
Success and error alternatives are represented in each operation's state set;
the seven cross-cutting dimensions cannot erase or silently reinterpret them.

| ID | Lifecycle operation | Dominant current gap | Primary owner |
|---|---|---|---|
| `K1L-001` | Producer construction/lifetime | Dependency resources lack Cx ownership | K3.1 |
| `K1L-002` | Producer send/delivery | Cancellation after enqueue is delivery-ambiguous | K5.3 |
| `K1L-003` | Producer flush | Slice budget is not a stable elapsed barrier | K11.2 |
| `K1L-004` | Producer close | Closed does not prove drained/quiescent | K11.1 |
| `K1L-005` | Transactional producer construction | No close or residue receipt | K6.2 |
| `K1L-006` | Begin and recovery | Non-single-flight work can strand `Active` | K6.1 |
| `K1L-007` | Transaction send/delivery | Cancelled record may still complete | K6.1 |
| `K1L-008` | Commit | Commit outcome can be broker-ambiguous | K6.1 |
| `K1L-009` | Abort | Abort outcome can be broker-ambiguous | K6.1 |
| `K1L-010` | Unfinished transaction drop | Recovery marker is in-memory and race-sensitive | K6.4 |
| `K1L-011` | Consumer construction/lifetime | Dependency resources lack Cx ownership | K3.1 |
| `K1L-012` | Subscribe | Backend and local state can diverge | K8.3 |
| `K1L-013` | Rebalance | Partition ownership transfer is not fenced | K8.3 |
| `K1L-014` | Poll | Shared slot can transfer or overwrite outcomes | K7.3 |
| `K1L-015` | Commit offsets | Broker commit can outlive caller certainty | K9 |
| `K1L-016` | Seek | Broker and local cursor can diverge | K7.4 |
| `K1L-017` | Consumer close | Cleanup is fail-once and not joined | K11.1 |
| `K1L-018` | Diagnostic consumer lifetime | Async-shaped wrapper has no Cx or close | K10.1 |
| `K1L-019` | Auto-commit/heartbeat background state | Dependency tasks and effects lack first-party receipts | K8.5 |

Four rows are `DEPENDENCY_OWNED_UNKNOWN`, fourteen are `ROUTED_GAP`, and one
is a `STATIC_SOURCE_GAP`. None is a pass state.

## Timeout, cancellation, and certainty

An entry checkpoint is not cancellation completion. Once a broker-visible
call, blocking closure, dependency queue entry, delivery callback, or local
post-effect continuation may have started, the operation must distinguish:

- definitely no effect;
- definitely completed effect;
- definitely failed effect; and
- unknown or partially transferred effect with a named recovery owner.

The current send path can return cancellation after enqueue while the callback
later completes. Transaction commit or abort can continue after its future is
dropped. Subscribe, rebalance, commit, and seek can mutate the backend while a
local continuation is skipped. Poll can leave a completed outcome for another
caller, return after close, or overwrite an unconsumed outcome. K1.4 preserves
all of these as blocking ambiguous states.

Retry counts and timeouts must compose into one operation budget. Queue wait,
blocking-pool wait, fallback-thread wait, mutex acquisition, dependency work,
backoff, callback delivery, and local continuation all consume the same
deadline. No phase may silently reset it.

## Panic, shutdown, restart, and quiescence

The required shutdown order is:

1. fence new admission;
2. join operation owners;
3. resolve or transfer outcome certainty;
4. release or transfer all resource owners;
5. drain background tasks and dependency state; and
6. declare quiescence only after the ledger balances.

Current source does not establish that order. Producer close marks closed
before drain. Consumer close marks closed before cleanup, does not join
concurrent callers, and cannot retry cleanup after failure or future drop.
TransactionalProducer has no close. Native background threads, queues,
callbacks, heartbeats, and commits are dependency-owned.

Panic handling must preserve the same ownership and certainty invariants as an
ordinary error. Restart must consume persisted or independently reconstructed
delivery, transaction, group, assignment, cursor, offset, and residue state.
Missing persistent state is `UNKNOWN`, not evidence that nothing survived.

A closed flag, dropped handle, empty map, dependency callback, deterministic
model state, or statically balanced graph does not prove quiescence.

## Owners and terminal gates

Implementation realization is routed across K3 through K10:

- K3 owns Cx connectivity, pooling, metadata, transport, and authentication;
- K5 owns bounded producer admission, delivery certainty, retry, and
  idempotence;
- K6 owns transactions, fencing, atomic offsets, ambiguity, and recovery;
- K7 owns bounded fetch flow, cursors, isolation, and seek recovery;
- K8 owns group membership, assignment, rebalance, heartbeat, and session
  lifecycle;
- K9 owns commit, offset, restart, and recovery policy; and
- K10 owns validated numeric configuration, typed outcomes, diagnostics,
  cardinality, privacy, and public ergonomics.

K11.1 owns the executable resource ledger, K11.2 the cancellation/timeout and
certainty model, K11.3 deterministic panic/shutdown/restart/quiescence proof,
and K11.4 the real-broker lifecycle receipt. K12.5 and K13.6 remain independent
and real-service terminal gates. K14.1 owns claim-time refresh. K15 alone may
make a conditional cutover decision.

K1.4 is intentionally not added to the global proof manifest or proof-status
snapshot. K1.1 through K1.3 are also local static policy packets; K1.5 owns
their aggregate static evidence vector. Registering K1.4 alone as a global
proof lane would overstate its scope.

## Static validation and no-claim boundary

The companion Rust contract reads checked-in bytes only. It is designed to
fail closed on input drift, missing or duplicate resource or lifecycle IDs,
semantic coverage drift, unresolved authority or tracker IDs, invalid numeric
fields, missing transition dimensions, invalid state references, weakened
accounting or owner fields, ambiguous-to-definitive promotion, changed
canonical projections, semantic-to-resource binding drift, composite-unit
dimension drift, permission flips, marker drift, or no-claim drift.

This K1.4 packet proves only the checked-in static input pins, resource and
lifecycle schema, explicit current gaps, owner routing, canonical projections,
and fail-closed disposition recorded in the artifact.

It does not prove compilation, formatting, linting, tests, fuzzing, runtime
execution, broker contact, external search, network behavior, service health,
container behavior, remote execution, or live RCH availability.

It does not prove that configured values are broker-enforced; effective
resource bounds; admission or backpressure correctness; timeout, cancellation,
panic, shutdown, retry, or restart correctness; delivery, transaction, group,
offset, or correlation certainty; release accounting; leak freedom; residue
cleanup; or quiescence.

It does not prove protocol correctness, interoperability, security, privacy,
performance, throughput, latency, memory, reliability, release readiness,
broad workspace health, or absence of defects.

It does not authorize production wiring, shadow traffic, oracle retirement,
migration, dependency or feature removal, API or capability removal, file
deletion, or cutover.

<!-- END KAFKA K1.4 RESOURCE LIFECYCLE CONTRACT -->
