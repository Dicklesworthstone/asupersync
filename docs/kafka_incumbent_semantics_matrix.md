# Kafka incumbent semantics matrix

<!-- BEGIN KAFKA INCUMBENT SEMANTICS MATRIX -->

This document is the human companion to
`artifacts/kafka_incumbent_semantics_matrix_v1.json`. Together they freeze the
current Kafka configuration, operation, outcome, lifecycle, security, and
no-feature semantics for
`asupersync-dep-p7-kafka-removal-sarszu.1.2` at revision
`b4997e8fe4de098a5a30ff468418460b59ca414a`.

This is incumbent truth, not a future API design. The governing decision is
still `DEP-ADR-009`: keep `rdkafka` until independently owned parity evidence
exists. Nothing in this packet permits dependency exit, API removal, behavior
changes, or a parity claim.

## Authority and coverage

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

The packet pins `src/messaging/kafka.rs`,
`src/messaging/kafka_consumer.rs`, `src/runtime/spawn_blocking.rs`,
`src/runtime/blocking_pool.rs`, the K0.1 artifact and document, the Kafka ADR,
and the capability registry by SHA-256 and record count.

Its static coverage is exact:

| Surface | Rows |
|---|---:|
| Configuration fields | 43 |
| Public enum semantics | 7 |
| Operational capability rows | 38 |
| Unique public methods covered exactly once | 96 |
| Additional reachable trait operations | 3 |
| Total explicit public entry points | 99 |
| Public callable test/fuzz helpers | 9 |
| Explicit missing capabilities | 2 |
| Routed semantic findings | 23 |

Every configuration, enum, operation, and callable-helper row records a stable
ID, a public-entry-point list (possibly empty), source anchor and owner, cfg/visibility, default,
accepted and rejected values, broker mapping, success and error outcome, retry
and timeout rule, cancellation and shutdown disposition, resource bound,
credential or payload handling, and exact gap owner.

For configuration rows, `surface` is the exact field access path. A public
field is itself a direct entry point even when it has no builder. Every private
field names at least one public writer in `public_entry_points`; that rule keeps
the private SASL password and cfg-gated admission flags from becoming implicit.

## Incumbent truth at a glance

### Producer delivery

`KafkaProducer::send` and `send_with_headers` validate cancellation, topic,
payload length, and closed state before selecting the backend. The local size
limit covers payload bytes only; it excludes topic, key, headers, framing,
batch aggregate, native queue storage, and deterministic global storage.

The wrapper retries only immediate retryable enqueue failures, for at most
`retries + 1` attempts. It also passes `retries` to librdkafka. Delivery
callback errors do not re-enter the wrapper retry loop. A successful result is
callback-derived `RecordMetadata`, even with `Acks::None`. Native timestamp
conversion collapses create-time and log-append-time kinds to optional
milliseconds and maps their `-1` values plus unavailable timestamps to `None`.
An immediate native invalid/unknown-topic rejection has no message and becomes
`InvalidTopic("unknown")`; the delivery-callback path retains the message topic.

Deterministic success returns the original topic, explicit partition or zero
(`send_with_headers` always uses zero), offset equal to the pre-push
topic/partition vector length with `i64::MAX` saturation, and no timestamp.
Its critical-topic matcher is case-sensitive. In debug/test a matching
single-record send writes exactly
``WARNING: publishing to critical topic '{topic}' using deterministic Kafka harness. This is safe only in test environments.``
to stderr. Batch transaction commit bypasses that matcher and emits no
per-topic warning. In release `test-internals`, critical and noncritical sends
hit distinct topic-specific and general panic diagnostics recorded verbatim in
the artifact; neither is a `KafkaError` outcome.

Cancellation after native enqueue cannot retract the record. The delivery
receiver returns `Cancelled` and discards a later callback, so the broker
outcome is not known through the current type. There is no obligation ledger
or typed sent/acknowledged/ambiguous state.

Native producer/transaction error mapping is exact. `ClientConfig` keeps only
its rejected value in `Config`; producer `QueueFull` stays typed, invalid or
unknown topic becomes `InvalidTopic`, and other production codes become
`Broker` from their debug form. Cancelled stays typed. Every other native
error becomes `Authentication` only when its display text contains one of the
seven literal probes frozen in the artifact; otherwise it becomes `Broker`.
The primary-consumer mapper keeps cancelled typed, formats `ClientConfig`
description/key/value into `Config`, maps client creation/subscription to
`Config`, and collapses every other error to `Broker` display text.

### Batching, backpressure, and flush

Batching is configuration mapping to `batch.size`, `linger.ms`, and
`compression.type`; the repository does not own a bounded batch queue.
Backpressure is dependency queue rejection. `QueueFull` receives bounded local
retries, but no record/byte permit, reservation, or two-phase admission exists.

`flush` watches the wrapper active-operation counter and the native in-flight
count in polling slices. It directly invokes a blocking native poll slice from
the async function. The implementation subtracts each requested slice from a
remaining budget without reading a clock, so the source establishes a
poll-slice budget rather than elapsed-deadline accounting. Exhaustion becomes
a string-valued `Broker` error, which the classifiers call
connection/transient/retryable and do not recognize as a timeout. Concurrent
sends are not fenced by public flush, so it is not a stable submission barrier.
Close is different: its closed flag plus the double-checked active-operation
reservation fences new sends while draining admitted ones. The existing
`op_notify` is not observed by the flush loop.

### Producer shutdown

`close` stores `closed = true` before draining. Cancellation or timeout after
that store leaves the producer closed with uncertain drain state. A later
close can retry internal draining, while public `flush` and new sends reject a
closed producer. `is_closed()` reports only the local flag; it does not prove a
successful drain. Close delegates the same `flush_inner` requested-slice
subtraction as public flush; its timeout argument is not source-proven elapsed
deadline accounting, and exhaustion is the same string-valued `Broker` error.
There is no explicit drop-drain contract.

### Transactions and idempotence

The public transactional phase machine is represented internally by `Idle`,
`Active`, `Finalizing`, and `NeedsAbortRecovery`. It has no `Fenced`, `Fatal`,
`Ambiguous`, or `Closed` public state.

`TransactionalConfig.transaction_timeout` defaults to 60 seconds and accepts
every `Duration`, including zero. An empty transaction ID is rejected, while a
whitespace-only, duplicate, or arbitrarily long ID is accepted locally.

The transactional native client always writes `enable.idempotence=true`, even
when its retained public `ProducerConfig` says false. The `config()` accessor
can therefore disagree with the effective native setting. Deterministic
transactions do not deduplicate.

Transaction initialization and recovery are not single-flight. Concurrent
Idle begins can duplicate native initialization before local activation
rejects one. More seriously, concurrent recovery begins can both start abort:
a later recovery completion can overwrite another caller's new `Active` phase
with `Idle`, admit a second handle, or let a later failure leave `Idle` while
an earlier handle is still active. Begin also marks `Active` before awaiting
native begin and constructs the `Transaction` handle only afterward. Dropping
that future in the intervening window can strand `Active` with no handle or
Drop hook, leaving later begin calls stuck at `transaction already active`.

Commit and abort consume the handle. A native failure records
`NeedsAbortRecovery`, and a later `begin_transaction` is the only recovery
trigger. Dropping an unfinished handle marks that recovery state but performs
no immediate broker abort only while the current shared phase is `Active` or
`Finalizing`; if a concurrent recovery has clobbered it to `Idle`, dropping the
unfinished handle leaves it `Idle`. Native abort moves through `Finalizing`,
whereas the no-feature abort branch moves directly from `Active` to `Idle`.
Duplicate live handles can both pass the separate active check before either
marks `Finalizing`, so native commit, abort, or mixed finalization calls can
both execute; a deterministic loser can poison the winner's `Finalizing`
phase through its unfinished Drop. Native transaction send has a separate
active check and can enqueue or complete during/after another handle's
finalization; deterministic send rechecks `Active` under its staging lock and
can reject that race instead. If the producer is never reused, no explicit
cleanup occurs.

Transaction blocking calls prefer the configured `Cx` pool. Its worker count
is capped, but pending work enters an uncapped queue; dropping the await skips
queued work or discards an already-running result. Worker-spawn failure with no
live worker can retain accepted work indefinitely, before the configured
recovery, initialization, commit, or abort timeout starts. Native begin has no
caller timeout.
A pool shutdown/enqueue race can surface as the bridge panic
`blocking operation ended without producing a result`, and a native closure
panic is resumed into the awaiting task.
Without a pool, the 256-thread fallback and inline-on-thread-spawn-failure
rules described below apply. Neither route observes later `Cx` cancellation
inside an executing native call.

Transactional consumer-offset enrollment is absent. There is no
`send_offsets_to_transaction` equivalent, so manual consumer commit plus a
producer transaction is not consume-process-produce exactly-once.

### Consumer subscription and rebalance

`KafkaConsumer::subscribe` trims, deduplicates, and sorts topics. It retains
the local committed-offset map while clearing positions and rebalance state.
The real path clears assignments until a later snapshot; deterministic mode
assigns partition zero.

`KafkaConsumer::rebalance` is caller-driven explicit assignment replacement,
not a librdkafka `ConsumerContext` rebalance callback. Empty input unassigns
everything. Every successful call increments the local generation, including
a no-op assignment. That counter is not a Kafka coordinator generation and is
not reset by close.

Close does not fence an already-admitted real-broker subscribe. If close wins
the broker lock and cleans up first, the pending subscribe can subsequently
re-subscribe the backend, fail its post-await local closed check, and return
`Config`; no second cleanup repairs that backend state.

### Poll, isolation, and payload ownership

`poll` returns at most one record. `max_poll_records` is validated but has no
broker mapping or local behavioral use. Native polling runs in at most 50ms
blocking slices and checks Cx between slices, not during one slice. Caller
timeout expires as `Ok(None)`.

All real-backend polls share one `buffered_outcome` slot. A slice writes that
slot before its caller resumes, so cancellation or post-first-iteration
deadline expiry can leave a record, error, or snapshot for a later poll.
Concurrent slices can overwrite an unconsumed outcome before either caller
takes it, silently removing it from application observation even when the
auto-commit path already stored the offset. A real poll can also consume a
message and discard it when offset storage or later snapshot capture fails;
auto-store may already have succeeded before the snapshot error. Snapshot
position updates keep only nonnegative absolute offsets, so other broker
offset forms can leave an absent or stale local position.

The wrapper copies topic, key, payload, and every header. Missing payload is
converted to empty bytes, and a missing header value is converted to empty
bytes, losing both null-versus-empty distinctions. Timestamp conversion also
collapses create-time versus log-append-time identity to optional milliseconds
and maps their `-1` values plus unavailable timestamps to `None`. No local
record, payload, header-count, or header-byte cap exists.

`ReadCommitted` is delegated as an `isolation.level` client setting. The
deterministic path does not model transactions or isolation. Static source is
therefore not isolation proof.

### Manual and automatic offsets

Manual commit is the default: `enable_auto_commit` is false. In that mode,
poll does not store or commit an offset. `commit_offsets` sends the exact
caller-supplied value, so the caller supplies Kafka's next-to-read offset after
successful application processing.

On the real-broker path, explicitly enabling auto commit leaves
`enable.auto.offset.store` false but makes poll call
`store_offset_from_message` before returning the record. Librdkafka later
commits it. A commit before completed processing creates a loss window, while
a crash before the delayed commit can still redeliver; this is not a strict
at-most-once guarantee.

The deterministic path ignores `enable_auto_commit`: poll advances only its
local read position, never updates `committed_offsets`, and has no background
commit. Manual `commit_offsets` remains the only deterministic commit-cache
update.

Only synchronous `commit_offsets` uses `ConsumerConfig.retries`. Poll,
subscribe, rebalance, seek, and close do not. Consumer runtime mapping
collapses nearly every dependency error to `Broker`, so an authentication or
otherwise nonretryable class can lose its identity before commit retry
classification.

The commit retry base is not a fully bounded conversion: source takes
`heartbeat_interval.as_millis().max(1) as u64`, then uses saturating
multiplication and a 5-second cap. Durations above `u64::MAX` milliseconds
truncate before that cap and can even yield a zero delay.

All three poll backends convert the caller timeout by clamping
`Duration::as_nanos()` to `u64::MAX` before adding it to the current instant.
Timeouts above that roughly 584.5-year nanosecond horizon therefore share the
same effective value, and the instant addition can saturate further.

The `committed_offset` accessor is a local explicit-commit cache. It neither
queries the broker nor reflects auto-commit progress.

### Seek and consumer shutdown

Seek accepts absolute nonnegative offsets for subscribed, assigned
topic-partitions and uses a hard-coded one-second native timeout. It does not
retry. A broker-success/close race can return a local error after broker state
has changed.

Consumer close marks the atomic closed flag before backend unassignment. If
unassign fails, local state is not cleared, waiters are not notified, and a
later close short-circuits instead of retrying cleanup. Close performs no
offset flush. It also leaves the rebalance generation and buffered outcome in
place. Concurrent close calls are not joined: a second call can return `Ok`
while the first is still awaiting cleanup or before the first later fails.
Dropping the first close after the closed swap can prevent backend cleanup from
starting or can let it finish while permanently skipping local map clearing
and waiter notification. Every later close still short-circuits.
`is_closed() == true` and a repeated close returning `Ok` are not cleanup
proof.

The uncleared poll slot is observable in a race: an already-admitted real poll
can finish after close, consume that buffered outcome without another open
check, apply its snapshot, repopulate local state, and return a record after
the closed flag was set.

### Security and secrets

The default security mode is plaintext. Without the private bypass, plaintext
is allowed only for endpoints whose extracted, trimmed host is
ASCII-case-insensitive `localhost`, an IPv4 loopback, `::1`, or an
IPv4-mapped IPv6 whose mapped IPv4 is loopback. A leading `[` selects text
through the first `]` and ignores any suffix; otherwise the last `:` splits
host from an unchecked suffix. Missing brackets, non-loopback, and unparseable
hosts fail, but endpoint and port grammar are not otherwise validated. TLS
maps to `security.protocol=ssl`; SASL maps to
`sasl_ssl` and exposes only SCRAM-SHA-256 and SCRAM-SHA-512. SASL over
plaintext is absent.

The bypass field defaults false, but its public setter is compiled under
`any(test, debug_assertions)`. Ordinary downstream debug builds can therefore
enable remote plaintext; describing the setter as strictly test-only would be
incorrect.

TLS path and password strings have no local emptiness, pairing, filesystem, or
length validation. The TLS key password is private and Debug-redacted, but it
is an ordinary cloneable `String` without zeroization. The SASL password uses
a private `ZeroizeOnDrop` wrapper and Debug redaction. That proves wrapper-drop
behavior only; it does not prove erasure of allocator history, client-config,
rdkafka, or librdkafka copies. Upstream authentication strings retained in
`KafkaError` are not sanitized. Native `ClientConfig` failures can also carry
the rejected value: producer, primary-consumer, and parallel-client mappings
expose that value without redaction, so a rejected `sasl.password` or
`ssl.key.password` can appear in public error Display/Debug.

### Blocking bridge and consumer ordering

Real consumer broker calls use the process-global fallback blocking-thread
bridge directly. Transaction begin/commit/abort prefer the `Cx` blocking pool
and use that fallback only when no pool handle exists. The pool caps workers
but admits an uncapped pending queue; queued cancellation skips work, executing
cancellation only discards its result, shutdown rejection becomes a bridge
panic, and worker-spawn failure with no live worker can retain accepted work
indefinitely. The fallback counter caps successfully spawned threads at 256,
not waiting callers; saturation yields without consulting the operation `Cx`,
dropping the await does not stop an already-started closure, and OS-thread
spawn failure executes the blocking broker closure inline on the async worker.
Closure panics are resumed from either bridge or propagate directly through
inline fallback.

No-feature deterministic publication and reads instead use a process-global
`parking_lot` broker mutex synchronously. Once past an operation's checkpoint,
mutex wait and work under that lock do not observe `Cx`. Batch commit can hold
the lock for work proportional to its unbounded record and byte aggregate;
deterministic poll repeatedly clones/scans the complete assignment set and
performs allocated topic-key lookups under the broker lock.

The consumer's broker lock serializes only each blocking dependency call.
Local state is applied after the await, outside that lock, so concurrent
subscribe, rebalance, commit, or seek continuations can land in an order that
differs from broker effects. An older buffered poll snapshot can also be
applied after a newer subscription, rebalance, or seek and can restore stale
assignments or return an old-topic/revoked record. Those operations do not
clear `buffered_outcome`.

The deterministic `poll_cursor` is likewise retained by subscribe, rebalance,
and close. After assignment membership changes it is reduced modulo the new
sorted assignment length, so the first partition polled depends on prior poll
history.

The separate diagnostic `KafkaClient::consumer` is an `async fn` with no
await or `Cx`: native client creation and subscription run synchronously on
the polling thread. Its derived group trims `client_id` but preserves the
original trim-validated topic, including surrounding whitespace, for the
group, subscription, cached topic, and exact same-topic comparison.

## Exact configuration index

### Producer, security, and transaction fields

| ID | Surface | Default or incumbent rule |
|---|---|---|
| `KPR-CFG-001` | `ProducerConfig.bootstrap_servers` | `localhost:9092`; vector only must be nonempty |
| `KPR-CFG-002` | `ProducerConfig.client_id` | `None`; arbitrary string |
| `KPR-CFG-003` | `ProducerConfig.batch_size` | 16,384; must be nonzero |
| `KPR-CFG-004` | `ProducerConfig.linger_ms` | 5ms; also local retry-backoff base |
| `KPR-CFG-005` | `ProducerConfig.compression` | `None`; five enum variants |
| `KPR-CFG-006` | `ProducerConfig.enable_idempotence` | true; no cross-field validation |
| `KPR-CFG-007` | `ProducerConfig.acks` | `All` |
| `KPR-CFG-008` | `ProducerConfig.retries` | 3; immediate enqueue plus native policy |
| `KPR-CFG-009` | `ProducerConfig.request_timeout` | 30s; public field, no builder |
| `KPR-CFG-010` | `ProducerConfig.max_message_size` | 1MiB; payload-only local bound |
| `KPR-CFG-011` | `ProducerConfig.security` | plaintext |
| `KPR-CFG-012` | `ProducerConfig.feature_requirement` | optional |
| `KPR-CFG-013` | insecure transport bypass | false; debug/test public setter |
| `KPR-CFG-014` | deterministic broker admission | stored false; crate tests bypass it automatically |
| `KPR-CFG-015` | TLS CA location | absent |
| `KPR-CFG-016` | TLS certificate location | absent |
| `KPR-CFG-017` | TLS key location | absent |
| `KPR-CFG-018` | TLS key password | absent; redacted, not zeroized |
| `KPR-CFG-019` | SASL mechanism | constructor selects SCRAM-256 or SCRAM-512 |
| `KPR-CFG-020` | SASL username | no default; trim-nonempty |
| `KPR-CFG-021` | SASL password | no default; trim-nonempty; wrapper-zeroized |
| `KPR-CFG-022` | SASL nested TLS | empty TLS config |
| `KPR-CFG-023` | transactional producer config | caller-supplied |
| `KPR-CFG-024` | transaction ID | caller-supplied; exactly empty rejected |
| `KPR-CFG-025` | transaction timeout | 60s; no local bound |

### Consumer fields

| ID | Surface | Default or incumbent rule |
|---|---|---|
| `KCO-CFG-001` | bootstrap servers | `localhost:9092`; vector only must be nonempty |
| `KCO-CFG-002` | group ID | `asupersync-default`; trim-nonempty |
| `KCO-CFG-003` | client ID | `None`; arbitrary string |
| `KCO-CFG-004` | session timeout | 45s; no relationship validation |
| `KCO-CFG-005` | heartbeat interval | 3s; also commit-retry base |
| `KCO-CFG-006` | auto offset reset | `Latest` |
| `KCO-CFG-007` | enable auto commit | false; manual commit default |
| `KCO-CFG-008` | auto commit interval | 5s |
| `KCO-CFG-009` | max poll records | 500; behaviorally inert |
| `KCO-CFG-010` | fetch minimum bytes | 1 |
| `KCO-CFG-011` | fetch maximum bytes | 50MiB broker hint, not local record cap |
| `KCO-CFG-012` | fetch maximum wait | 500ms |
| `KCO-CFG-013` | isolation level | `ReadUncommitted` |
| `KCO-CFG-014` | security | plaintext |
| `KCO-CFG-015` | force real Kafka | false; unit-test selector only |
| `KCO-CFG-016` | retries | 3; synchronous commit only |
| `KCO-CFG-017` | insecure transport bypass | false; debug/test public setter |
| `KCO-CFG-018` | deterministic broker admission | stored false; crate tests bypass it automatically |

## Operational index

The machine artifact carries the complete outcome columns, and the full
configuration/enum/operation matrix covers all 96 K0.1 public methods exactly
once. This compact index shows the 38 operational rows, including three
additional KafkaError trait entry points and the automatic unfinished-
transaction drop lifecycle.

| Range | Surface family |
|---|---|
| `KPR-OP-001` | five `KafkaError` classifiers plus three explicit trait entry points: `Display`, `Error::source`, and `From<io::Error>` |
| `KPR-OP-002` | producer validation |
| `KPR-OP-003`–`KPR-OP-008` | producer construction, send, flush, close, and accessors |
| `KPR-OP-009`–`KPR-OP-014` | transactional construction, begin, send, commit, abort, and accessors |
| `KPR-OP-015`–`KPR-OP-016` | backend and diagnostic-consumer traits |
| `KPR-OP-017`–`KPR-OP-020` | parallel `KafkaClient` family |
| `KPR-OP-021` | automatic unfinished-transaction drop recovery hook |
| `KCO-OP-001` | consumer validation |
| `KCO-OP-002` | topic/partition/offset construction |
| `KCO-OP-003`–`KCO-OP-009` | consumer construction, subscribe, rebalance, poll, commit, seek, close |
| `KCO-OP-010`–`KCO-OP-017` | consumer config/state/cursor accessors |

The seven enum rows are `KAFKA-ENUM-001` through `KAFKA-ENUM-007`. The nine
cfg-sensitive helper rows are `KPR-HLP-001` through `KPR-HLP-009`; they cover
the deterministic broker controls, the two `From<u8>` conversions, and four
ad hoc parser helpers.

Those parser helpers are corpus scaffolding, not Kafka wire parsers. Notably,
the `Compression::from(u8)` helper uses modulo four and never produces `Zstd`.

## No-feature and deterministic profiles

The artifact's 17 profile-disposition groups cover all 97 configuration, enum,
operation, and helper semantic IDs exactly once. This keeps profile behavior
explicit without pretending that every local accessor has the same outcome as
an operation that reads or writes deterministic broker storage.

The no-feature error and configuration diagnostics are frozen exactly. The
artifact records all twelve `KafkaError` display templates, Io-only
`Error::source` chaining, and `From<io::Error>` wrapping. In particular,
`KafkaError::FeatureDisabled` displays ``Kafka is unavailable: the `kafka` cargo feature is not enabled in this build``. `kafka_feature_diagnostic()`
returns one of `Kafka cargo feature is enabled; real broker integration is
available`, `Kafka cargo feature is optional for this config and is not
enabled; non-test broker operations return FeatureDisabled`, or `Kafka cargo
feature is required by this config but is not enabled; rebuild with --features
kafka`.

| Profile | Exact behavior |
|---|---|
| Ordinary downstream no-feature | Ordinary configuration, enums, validation, classifiers, and local accessors remain; four admission fields/setters retain their row-specific test/debug cfg gates. Optional producer and transaction objects plus a consumer can construct. Producer send, transaction begin, and primary-consumer subscribe/rebalance/poll/commit/seek return `FeatureDisabled`. Because begin fails, transaction send/commit/abort branches are unreachable through this public profile. Producer/consumer close and local accessors retain their row-specific local behavior. |
| No-feature crate unit test | Deterministic broker operations are automatically admitted. A producer send and a consumer poll that enters its deterministic read/wait path access process-global record storage; transaction send stages locally and commit publishes the staged batch. |
| Kafka-feature crate unit test | Producer and transaction operations use the real backend. `force_real_kafka=false` gives the primary consumer a unit-local `None` backend: subscription/assignment/cursor state works, but poll never reads deterministic records. `force_real_kafka=true` constructs the real consumer. |
| No-feature debug `test-internals` | Explicit per-config opt-in admits `KafkaProducer` send, transaction begin, and primary-consumer backend operations. Once begin returns a handle, transaction send/commit/abort do not recheck producer admission. Parser helpers still require their separate test, `cfg(fuzzing)`, or fuzz-feature cfg. |
| No-feature release `test-internals` | Only calls that reach the guarded process-global record store fail via the production panic guard: an explicitly admitted producer send, an explicitly admitted consumer poll that enters its deterministic read/wait path, end-offset inspection, and a nonempty transaction commit after admitted begin. Transaction begin/send/abort/drop, an empty commit, primary-consumer local-state operations, and local accessors do not hit that guard; operations on an existing transaction handle do not recheck producer admission. |
| Parallel no-feature `KafkaClient` | Backend descriptor says deterministic; `consumer()` validates the topic first, constructs its diagnostic consumer only under crate `cfg(test)`, and returns `FeatureDisabled` after successful validation in every non-test build, including release `test-internals`. |

The K0.2 audit also corrects one K0.1 profile interpretation: workspace tests
feature-unify `test-internals` through the conformance dev-dependency. The live
owner for that feature-unification issue is `asupersync-z2kt29`. K0.1's source
and export pins remain valid; this correction is about the effective workspace
test profile.

The release `test-internals` profile is distinct: controls compile, but a call
that reaches deterministic broker storage triggers the production panic guard.

## Explicit absences

| ID | Missing capability | Disposition / implementation owner |
|---|---|---|
| `KAFKA-ABS-001` | transactional consumer-offset enrollment | K12.5 disposition; K6.3 implementation; K13.3 verification |
| `KAFKA-ABS-002` | topic/partition/ACL/group/broker administration | K12.5 disposition; K10.1 API-contract owner; no shipped surface |

These are blocking absences, not implicit rows and not parity. The artifact
uses full bead IDs for every owner.

## Static contract

`tests/kafka_incumbent_semantics_matrix_contract.rs` is the paired fail-closed
static contract. It checks identity and authority, exact source pins, exact
row counts and key sets, unique IDs, field coverage, exact-once coverage of all
96 K0.1 public methods plus three KafkaError trait operations, the exact
entry-to-row/source-owner/source-anchor digest and declaration boundaries,
the source-owner/source-anchor digest for all 97 semantic rows, the exact
source-pin identity/path/count/hash/role map, complete artifact/document byte
digests, exact-once profile disposition for all 97 semantic rows, helper
coverage, explicit absences, 23 routed owned gaps,
no-feature/manual-commit/idempotence/rebalance/security/shutdown markers, this
document's markers, and explicit no-claim boundaries.

The contract performs no external process, network, broker, timing, or
environment-dependent work. It has not been executed in the static-only
session that created this packet. This packet does not prove compilation.

## No-claim boundary

This packet proves only source-pinned incumbent semantic inventory. It does
not prove compilation, test success, broker interoperability, native library
availability, protocol correctness, cancellation correctness, durability,
isolation, idempotent duplicate suppression, performance, security, release
readiness, broad workspace health, or live infrastructure health.

The deterministic broker and parser hooks are not Kafka parity. The packet
does not turn `ReadCommitted` configuration into isolation proof, does not
turn an idempotence setting into deduplication proof, and does not turn the
missing transaction-offset or admin surfaces into shipped capability.

This packet does not permit removing `rdkafka`, librdkafka, the `kafka`
feature, any public API, or incumbent behavior.

<!-- END KAFKA INCUMBENT SEMANTICS MATRIX -->
