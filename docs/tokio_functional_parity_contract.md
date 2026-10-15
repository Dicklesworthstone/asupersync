# Tokio Functional Parity Contract

**Bead**: `asupersync-2oh2u.1.2.1` ([T1.2.a])  
**Author**: FuchsiaGate (codex-cli / gpt-5-codex)  
**Date**: 2026-03-03  
**Parent docs**:
- `docs/tokio_ecosystem_capability_inventory.md` (T1.1.a)
- `docs/tokio_capability_evidence_map.md` (T1.1.b)
- `docs/tokio_capability_risk_register.md` (T1.1.c)

---

## 1. Purpose

Define domain-level functional parity contracts required for truthful Tokio-ecosystem replacement claims. Each domain contract is intentionally normative and directly convertible into conformance tests.

This document covers functional behavior only. Performance/resource/reliability thresholds are handled by T1.2.b (`asupersync-2oh2u.1.2.3`), and evidence policy/checklists are handled by T1.2.c (`asupersync-2oh2u.1.2.5`).

---

## 2. Normative Language

- `MUST`: non-negotiable replacement requirement.
- `SHOULD`: expected default; deviation requires explicit rationale and test evidence.
- `MAY`: optional capability; if exposed, behavior MUST still preserve core invariants.

---

## 3. Global Invariants (Apply to Every Domain)

All domain contracts below are constrained by these invariants:

1. `G1` Structured ownership: every spawned unit of concurrent work MUST be owned by exactly one region/scope.
2. `G2` Cancellation protocol: cancellation MUST follow request -> drain -> finalize; no silent-drop semantics.
3. `G3` Loser drain: race/select losers MUST be canceled and drained to completion.
4. `G4` Obligation closure: permits/acks/leases MUST commit or abort; no obligation leaks.
5. `G5` Capability security: effectful operations MUST require explicit capability flow through `Cx`.
6. `G6` Region close quiescence: region close MUST imply no live children and finalizers complete.

---

## 4. Domain Contracts

### D1. Runtime and Task Execution

**Tokio surfaces**: `tokio::runtime`, `tokio::task`, runtime builders.  
**Asupersync surfaces**: `runtime/*`, `cx/*`, `record/*`.

#### API Semantics

1. `D1-FUNC-01` Spawning APIs MUST return handles with explicit completion outcomes (`Ok/Err/Cancelled/Panicked` equivalent semantics).
2. `D1-FUNC-02` Runtime builder/config APIs MUST expose deterministic defaults and explicit override behavior.
3. `D1-FUNC-03` Blocking work paths MUST be isolated from async scheduler fairness guarantees.

#### Cancellation

1. `D1-CANCEL-01` Canceling a task handle MUST be idempotent and observable.
2. `D1-CANCEL-02` Parent cancellation MUST propagate to all children within owning scope.

#### Error Handling

1. `D1-ERR-01` Spawn/join failures MUST preserve typed error context (task id, region id, reason class).
2. `D1-ERR-02` Panic paths MUST remain contained and reportable without global runtime corruption.

#### Backpressure

1. `D1-BP-01` Runtime queues MUST expose bounded behavior or explicit overload policy.
2. `D1-BP-02` Overload behavior MUST be deterministic under identical schedule + inputs.

#### Shutdown

1. `D1-SHUT-01` Runtime shutdown MUST drain in-flight work according to cancellation protocol.
2. `D1-SHUT-02` Shutdown completion MUST imply no leaked tasks, obligations, or finalizers.

### D2. Structured Concurrency, Cancellation, and Obligations

**Tokio surfaces**: `JoinSet`, `CancellationToken` patterns, `select!`-driven cancellation.  
**Asupersync surfaces**: `cx/scope.rs`, `cancel/*`, `obligation/*`.

#### API Semantics

1. `D2-FUNC-01` Scope/region APIs MUST make parent-child ownership explicit.
2. `D2-FUNC-02` Race/join combinators MUST define winner/loser semantics explicitly.

#### Cancellation

1. `D2-CANCEL-01` Every cancel request MUST enter a drain phase before finalization.
2. `D2-CANCEL-02` Repeated cancel requests MUST not produce duplicate side effects.

#### Error Handling

1. `D2-ERR-01` Cancellation-cause attribution MUST preserve source and propagation path.
2. `D2-ERR-02` Obligation-close failures MUST include remediation context.

#### Backpressure

1. `D2-BP-01` Scope admission MUST reject or defer work when obligation budgets are exhausted.
2. `D2-BP-02` Cancellation storms MUST not produce unbounded cleanup debt.

#### Shutdown

1. `D2-SHUT-01` Region close MUST block until all child drains and finalizers complete.
2. `D2-SHUT-02` Scope teardown MUST leave zero live obligation records.

### D3. Channels and Synchronization Primitives

**Tokio surfaces**: `mpsc`, `oneshot`, `broadcast`, `watch`, `Mutex`, `RwLock`, `Semaphore`, `Notify`, `Barrier`, `OnceCell`.  
**Asupersync surfaces**: `channel/*`, `sync/*`.

#### API Semantics

1. `D3-FUNC-01` Channel send/recv semantics MUST be deterministic for identical interleavings.
2. `D3-FUNC-02` Sync primitives MUST provide documented fairness/ordering semantics.
3. `D3-FUNC-03` Two-phase reserve/commit APIs MUST preserve data on canceled senders.

#### Cancellation

1. `D3-CANCEL-01` Canceling blocked send/recv/wait operations MUST not lose committed data.
2. `D3-CANCEL-02` Waiter cancellation MUST cleanly unregister wakeups.

#### Error Handling

1. `D3-ERR-01` Closed-channel and poisoned-state equivalents MUST be explicitly classified.
2. `D3-ERR-02` API errors MUST distinguish cancellation from structural closure.

#### Backpressure

1. `D3-BP-01` Bounded channels MUST enforce hard capacity contracts.
2. `D3-BP-02` Contended sync primitives MUST expose bounded wakeup behavior without starvation regressions.

#### Shutdown

1. `D3-SHUT-01` Channel close MUST wake blocked operations with deterministic terminal outcomes.
2. `D3-SHUT-02` Primitive teardown MUST not leave parked waiters.

### D4. Time, Timers, and Scheduling Primitives

**Tokio surfaces**: `sleep`, `timeout`, `interval`, time wheel internals.  
**Asupersync surfaces**: `time/*`, `runtime/timer.rs`, `lab/virtual_time_wheel.rs`.

#### API Semantics

1. `D4-FUNC-01` Sleep/timeout/interval semantics MUST define clock source and drift policy.
2. `D4-FUNC-02` Timer APIs MUST support deterministic virtual-time execution in lab mode.

#### Cancellation

1. `D4-CANCEL-01` Canceling timers MUST unregister pending wakeups exactly once.
2. `D4-CANCEL-02` Timeout cancellation MUST not spuriously complete underlying operation.

#### Error Handling

1. `D4-ERR-01` Timeout outcome MUST be distinguishable from operation error and external cancellation.
2. `D4-ERR-02` Invalid timer configuration MUST fail fast with structured diagnostics.

#### Backpressure

1. `D4-BP-01` Timer wheel overload MUST have explicit drop/defer policy.
2. `D4-BP-02` High timer cardinality MUST not violate scheduler fairness invariants.

#### Shutdown

1. `D4-SHUT-01` Timer subsystem shutdown MUST resolve or cancel all pending timers deterministically.
2. `D4-SHUT-02` No orphan timer callbacks may execute after runtime close.

### D5. Async I/O, Codec, and Buffer Semantics

**Tokio surfaces**: `tokio::io::*`, `tokio-util::codec`, `bytes::*`.  
**Asupersync surfaces**: `io/*`, `codec/*`, `bytes/*`.

#### API Semantics

1. `D5-FUNC-01` Read/write traits MUST preserve partial-read/partial-write semantics identical to async I/O norms.
2. `D5-FUNC-02` Codec framing MUST define split/merge/EOF boundaries unambiguously.
3. `D5-FUNC-03` Buffer APIs MUST preserve zero-copy guarantees where claimed.

#### Cancellation

1. `D5-CANCEL-01` Canceled I/O ops MUST not report success for non-committed bytes.
2. `D5-CANCEL-02` Canceled frame decode MUST leave stream in recoverable state or report terminal framing error class.

#### Error Handling

1. `D5-ERR-01` Transport errors, decode errors, and cancellation MUST be disjoint classes.
2. `D5-ERR-02` EOF semantics MUST be consistent across buffered and unbuffered adapters.

#### Backpressure

1. `D5-BP-01` Writers MUST propagate downstream capacity pressure without unbounded buffering.
2. `D5-BP-02` Codec layer MUST expose bounded frame limits and rejection behavior.

#### Shutdown

1. `D5-SHUT-01` Flush+close semantics MUST define commit point for buffered data.
2. `D5-SHUT-02` Split halves MUST converge to terminal state without deadlock.

### D6. Networking Core (Reactor, DNS, TCP/UDP/Unix, TLS)

**Tokio surfaces**: `tokio::net`, resolver stacks, `tokio-rustls`.  
**Asupersync surfaces**: `runtime/reactor/*`, `net/*`, `tls/*`.

#### API Semantics

1. `D6-FUNC-01` Socket lifecycle MUST define bind/connect/listen/accept behavior and state transitions.
2. `D6-FUNC-02` DNS resolution APIs MUST define cache and TTL behavior.
3. `D6-FUNC-03` TLS handshake APIs MUST define ALPN, cert validation, and auth-mode semantics.

#### Cancellation

1. `D6-CANCEL-01` Canceling connect/accept/resolve/handshake MUST not leak descriptors or handshake state.
2. `D6-CANCEL-02` Mid-flight cancellation MUST preserve deterministic terminal socket state classification.

#### Error Handling

1. `D6-ERR-01` DNS, transport, TLS, and cancellation errors MUST be separable.
2. `D6-ERR-02` Retryable vs terminal network failures MUST be explicitly tagged.

#### Backpressure

1. `D6-BP-01` Accept loops MUST include explicit admission/overload handling.
2. `D6-BP-02` TLS and socket write paths MUST propagate peer/app-level flow control pressure.

#### Shutdown

1. `D6-SHUT-01` Listener shutdown MUST stop new accepts and drain in-flight connections per policy.
2. `D6-SHUT-02` Reactor shutdown MUST leave no active registrations.

### D7. Protocol Stack (HTTP/1, HTTP/2, WebSocket, QUIC/H3 when enabled)

**Tokio surfaces**: `hyper`, `h2`, `tokio-tungstenite`, QUIC/H3 ecosystem crates.  
**Asupersync surfaces**: `http/*`, `net/websocket/*`, `net/quic*`, `http/h3*`.

#### API Semantics

1. `D7-FUNC-01` HTTP request/response state machines MUST preserve protocol conformance per version.
2. `D7-FUNC-02` Streamed body semantics MUST define ordering, trailers, and terminal conditions.
3. `D7-FUNC-03` WebSocket frame and close handshake semantics MUST be explicit.
4. `D7-FUNC-04` QUIC/H3 APIs (if enabled) MUST document capability subset and unsupported RFC surface.

#### Cancellation

1. `D7-CANCEL-01` Canceling request/stream operations MUST drain protocol losers and release flow-control credit correctly.
2. `D7-CANCEL-02` Connection-level cancellation MUST produce deterministic stream termination outcomes.

#### Error Handling

1. `D7-ERR-01` Protocol violations MUST be distinguishable from transport failures.
2. `D7-ERR-02` Version negotiation failures MUST provide structured classification.

#### Backpressure

1. `D7-BP-01` HTTP/2 and QUIC stream/window flow control MUST be enforced as hard constraints.
2. `D7-BP-02` Server request admission MUST include overload policy with explicit response behavior.

#### Shutdown

1. `D7-SHUT-01` Graceful shutdown MUST complete in-flight requests within configured budget or return explicit terminal status.
2. `D7-SHUT-02` Abrupt shutdown MUST still preserve deterministic traceability of unfinished streams.

### D8. Framework and Service Layer (Web, gRPC, Middleware, Routing)

**Tokio surfaces**: `axum`, `warp`, `tonic`, `tower*`.  
**Asupersync surfaces**: `web/*`, `grpc/*`, `service/*`, `transport/*`.

#### API Semantics

1. `D8-FUNC-01` Routing and extraction contracts MUST define match precedence and failure response semantics.
2. `D8-FUNC-02` Middleware/layer composition MUST preserve ordering and cancellation propagation.
3. `D8-FUNC-03` gRPC unary/stream semantics MUST define deadline/status/trailer behavior.

#### Cancellation

1. `D8-CANCEL-01` Request-scoped cancellation MUST terminate downstream handlers/interceptors without orphan work.
2. `D8-CANCEL-02` Streaming RPC cancellation MUST drain partial pipeline state.

#### Error Handling

1. `D8-ERR-01` Handler errors MUST map to deterministic transport/protocol status classes.
2. `D8-ERR-02` Middleware failures MUST preserve causal chain in diagnostics.

#### Backpressure

1. `D8-BP-01` Concurrency and rate-limit layers MUST enforce explicit admission contracts.
2. `D8-BP-02` Streaming handlers MUST not bypass bounded queues.

#### Shutdown

1. `D8-SHUT-01` Graceful server stop MUST stop new admissions and finish/drain active requests per policy.
2. `D8-SHUT-02` gRPC and HTTP shared transports MUST coordinate consistent shutdown outcomes.

### D9. Data and Messaging Clients (Postgres/MySQL/SQLite/Redis/NATS/Kafka)

**Tokio surfaces**: `sqlx`, `tokio-postgres`, `mysql_async`, `redis`, `async-nats`, `rdkafka` ecosystems.  
**Asupersync surfaces**: `database/*`, `messaging/*`.

#### API Semantics

1. `D9-FUNC-01` Connection/session lifecycle MUST define establishment, auth, transaction/consumer setup, and teardown states.
2. `D9-FUNC-02` Query/publish/consume APIs MUST define delivery and acknowledgment semantics.
3. `D9-FUNC-03` Retries and idempotency behavior MUST be explicit per operation class.

#### Cancellation

1. `D9-CANCEL-01` Canceling requests or consumer loops MUST leave protocol/session state valid or terminal with explicit reason.
2. `D9-CANCEL-02` Transactional cancellation MUST define rollback/abort guarantees.

#### Error Handling

1. `D9-ERR-01` Application errors, protocol errors, and transport errors MUST be separate.
2. `D9-ERR-02` Retriable classification MUST be explicit and deterministic.

#### Backpressure

1. `D9-BP-01` Producer and consumer flow control MUST be bounded and observable.
2. `D9-BP-02` Connection pool limits and queueing behavior MUST be explicit.

#### Shutdown

1. `D9-SHUT-01` Shutdown MUST flush/commit/abort according to operation class with no silent loss.
2. `D9-SHUT-02` Consumer shutdown MUST define offset/ack checkpoint semantics.

### D10. Filesystem, Process, and Signal Capabilities

**Tokio surfaces**: `tokio::fs`, `tokio::process`, `tokio::signal`.  
**Asupersync surfaces**: `fs/*`, `process/*`, `signal/*`.

#### API Semantics

1. `D10-FUNC-01` File operations MUST define atomicity guarantees and platform caveats.
2. `D10-FUNC-02` Process APIs MUST define spawn/stdin-stdout-stderr/wait/exit contracts.
3. `D10-FUNC-03` Signal APIs MUST define subscription and delivery semantics by platform.

#### Cancellation

1. `D10-CANCEL-01` Canceling filesystem/process waits MUST preserve resource ownership guarantees.
2. `D10-CANCEL-02` Signal subscription cancellation MUST not leak handlers.

#### Error Handling

1. `D10-ERR-01` OS errors MUST preserve errno/status-class context.
2. `D10-ERR-02` Cancellation MUST not be conflated with process failure/exit statuses.

#### Backpressure

1. `D10-BP-01` File and process I/O pipes MUST define bounded buffering semantics.
2. `D10-BP-02` Signal queues MUST define overflow behavior.

#### Shutdown

1. `D10-SHUT-01` Process-group shutdown MUST define grace -> force escalation policy.
2. `D10-SHUT-02` Runtime shutdown MUST clean signal registrations and child-process trackers.

### D11. Deterministic Testing, Tracing, and Observability

**Tokio surfaces**: ecosystem testing/tracing crates (`tracing`, ad hoc test harnesses).  
**Asupersync surfaces**: `lab/*`, `trace/*`, `observability/*`, `conformance/*`.

#### API Semantics

1. `D11-FUNC-01` Lab runtime MUST provide deterministic scheduling/time controls.
2. `D11-FUNC-02` Trace APIs MUST produce replayable artifacts with stable schema versioning.
3. `D11-FUNC-03` Observability APIs MUST preserve structured field contracts.

#### Cancellation

1. `D11-CANCEL-01` Trace/log pipelines MUST record cancellation causality and drain/finalize phases.
2. `D11-CANCEL-02` Test harness cancellation MUST preserve reproducible diagnostics.

#### Error Handling

1. `D11-ERR-01` Replay divergence MUST emit machine-checkable delta classification.
2. `D11-ERR-02` Missing/invalid diagnostics MUST fail contract tests explicitly.

#### Backpressure

1. `D11-BP-01` Trace sinks MUST expose bounded buffering policy.
2. `D11-BP-02` High-volume diagnostics MUST degrade predictably without silent schema breakage.

#### Shutdown

1. `D11-SHUT-01` Trace/metrics exporters MUST flush or explicitly report dropped records.
2. `D11-SHUT-02` End-of-run artifacts MUST include replay pointers and provenance.

### D12. Interoperability and Adapter Boundaries

**Tokio surfaces**: Tokio-locked third-party ecosystems (`reqwest`, `sqlx`, `sea-orm`, `lapin`, etc.).  
**Asupersync surfaces**: planned T7 adapter boundaries and compatibility crates.

#### API Semantics

1. `D12-FUNC-01` Adapter boundaries MUST isolate Tokio assumptions outside Asupersync core runtime.
2. `D12-FUNC-02` Compatibility shims MUST declare supported subset and unsupported paths explicitly.

#### Cancellation

1. `D12-CANCEL-01` Adapter cancellation semantics MUST map to Asupersync protocol without silent drops.
2. `D12-CANCEL-02` Cross-runtime bridge teardown MUST be idempotent.

#### Error Handling

1. `D12-ERR-01` Adapter errors MUST include translation context (source stack, mapped class, remediation).
2. `D12-ERR-02` Unsupported feature use MUST fail fast with explicit contract violation.

#### Backpressure

1. `D12-BP-01` Bridge queues MUST be bounded and observable.
2. `D12-BP-02` Adapter throughput collapse MUST surface overload signals instead of hidden latency growth.

#### Shutdown

1. `D12-SHUT-01` Adapter shutdown MUST preserve both-side resource closure and context cleanup.
2. `D12-SHUT-02` No bridge-owned task may survive parent region closure.

---

## 5. Conformance-Test Conversion Rules

For each requirement ID above:

1. Create at least one deterministic unit/conformance test that asserts the requirement on success path and at least one failure/cancellation edge.
2. Name tests with requirement IDs for traceability (example: `d7_cancel_01_loser_streams_are_drained`).
3. Emit structured logs containing:
   - `contract_domain`
   - `requirement_id`
   - `scenario_id`
   - `seed_or_trace_id`
   - `outcome_class`
4. On failure, output a one-command repro and stable artifact pointer.

---

## 6. Explicit Non-Goals (for this document)

1. No quantitative SLO or throughput targets (owned by T1.2.b).
2. No sign-off checklist policy (owned by T1.2.c).
3. No adapter implementation details (owned by T7 implementation beads).

---

## 7. Domain Definition-of-Done Synthesis (T1.2 Parent)

This section consolidates T1.2.a (functional contracts), T1.2.b (non-functional
closure thresholds), and T1.2.c (evidence checklist) into one domain-level
sign-off matrix for the parent bead `asupersync-2oh2u.1.2`.

### 7.1 Domain Closure Matrix

| Capability Domain | Functional Contract Scope | Non-Functional Gate Families | Evidence Rows | Closure Rule |
|-------------------|---------------------------|------------------------------|---------------|--------------|
| Runtime | `D1`, `D2`, `D3`, `D4` | `NF01`-`NF05` | `F01`-`F05` | All linked `D*` MUST requirements pass conformance (`E1`), linked `NF*` hard ceilings pass (or approved deferred waiver), and all `M` evidence categories in linked `F*` rows are complete. |
| Async I/O + Codec + Buffers | `D5` | `NF06`-`NF09` | `F06`-`F09` | Same as above, scoped to `D5` semantics and `F06`-`F09` evidence rows. |
| Filesystem / Process / Signal | `D10` | `NF21`-`NF23` | `F21`-`F23` | `D10` MUST requirements verified; `NF21`-`NF23` ceilings met for in-scope surfaces; all mandatory evidence from `F21`-`F23` rows present. |
| Networking Core + Protocol Stack | `D6`, `D7` | `NF10`-`NF15` | `F10`-`F15` | `D6`/`D7` MUST requirements verified (including cancellation/error semantics), network/protocol `NF*` gates met, and evidence rows `F10`-`F15` complete. |
| Web Framework / Middleware | `D8` (web/middleware clauses) | `NF16` | `F16` | Web-specific `D8` MUST requirements pass; `NF16` gates meet hard ceilings; all mandatory `F16` evidence complete. |
| gRPC | `D8` (gRPC clauses) | `NF17` | `F17` | gRPC `D8` MUST requirements and stream cancellation semantics pass; `NF17` gates and mandatory `F17` evidence complete. |
| Database Clients | `D9` (Postgres/MySQL/SQLite clauses) | `NF18` | `F18` | DB-related `D9` MUST requirements pass; `NF18` gates and mandatory `F18` evidence complete. |
| Messaging Clients | `D9` (Redis/NATS/Kafka clauses) | `NF19` | `F19` | Messaging-related `D9` MUST requirements pass; `NF19` gates and mandatory `F19` evidence complete. |
| Interop Adapters | `D12` | `NF28` | `F28` | `D12` adapter boundary requirements pass, interop `NF28` gates satisfy thresholds/deferred policy, and `F28` mandatory evidence is complete. |
| Observability + Deterministic Replay | `D11` | `NF25`, `NF26` | `F25`, `F26` | `D11` MUST requirements pass including replay determinism, observability/lab `NF*` gates pass, and `F25`/`F26` mandatory evidence is complete. |

### 7.2 Machine-Readable Mapping

```yaml
dod_domain_map:
  runtime:
    functional_contracts: [D1, D2, D3, D4]
    nonfunctional_families: [NF01, NF02, NF03, NF04, NF05]
    evidence_rows: [F01, F02, F03, F04, F05]
  io_codec_buffers:
    functional_contracts: [D5]
    nonfunctional_families: [NF06, NF07, NF08, NF09]
    evidence_rows: [F06, F07, F08, F09]
  fs_process_signal:
    functional_contracts: [D10]
    nonfunctional_families: [NF21, NF22, NF23]
    evidence_rows: [F21, F22, F23]
  networking_protocol:
    functional_contracts: [D6, D7]
    nonfunctional_families: [NF10, NF11, NF12, NF13, NF14, NF15]
    evidence_rows: [F10, F11, F12, F13, F14, F15]
  web:
    functional_contracts: [D8]
    nonfunctional_families: [NF16]
    evidence_rows: [F16]
  grpc:
    functional_contracts: [D8]
    nonfunctional_families: [NF17]
    evidence_rows: [F17]
  database:
    functional_contracts: [D9]
    nonfunctional_families: [NF18]
    evidence_rows: [F18]
  messaging:
    functional_contracts: [D9]
    nonfunctional_families: [NF19]
    evidence_rows: [F19]
  interop:
    functional_contracts: [D12]
    nonfunctional_families: [NF28]
    evidence_rows: [F28]
  observability:
    functional_contracts: [D11]
    nonfunctional_families: [NF25, NF26]
    evidence_rows: [F25, F26]
```

### 7.3 Cross-Document References

- Non-functional thresholds: `docs/tokio_nonfunctional_closure_criteria.md`
- Evidence policy/checklists: `docs/tokio_evidence_checklist.md`
- Executable contract gates: `docs/tokio_executable_conformance_contracts.md`

## 8. Revision History

| Date | Author | Change |
|------|--------|--------|
| 2026-03-03 | FuchsiaGate | Initial functional parity contract baseline (T1.2.a) |
| 2026-03-03 | DustySnow | Added T1.2 parent DoD synthesis matrix + machine-readable domain mapping across functional/non-functional/evidence gates. |
