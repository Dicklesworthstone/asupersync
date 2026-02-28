# WASM Platform Trait Seams Contract

Contract ID: `wasm-platform-seams-v1`
Bead: `asupersync-umelq.4.1`

## Purpose

Define explicit seam contracts between Asupersync runtime semantics and host/platform mechanics so native and browser backends can vary without semantic drift.

## Non-Negotiable Runtime Invariants

1. Structured concurrency ownership remains tree-shaped.
2. Region close implies quiescence.
3. Cancellation remains `request -> drain -> finalize`.
4. Obligation accounting remains linear (commit or abort, no leaks).
5. No ambient authority is introduced at seam boundaries.
6. Deterministic replay remains possible under lab instrumentation.

## Seam Catalog

## 1. `SchedulerSeam`

### Responsibilities

- Admit runnable tasks into lane-aware scheduling.
- Apply deterministic tie-breaking for equivalent priority/deadline candidates.
- Emit dispatch decisions with stable ordering metadata.

### Preconditions

- Task identity, region identity, and budget are present.
- Cancellation state is up to date at dispatch boundary.
- Lane metadata (`cancel`, `timed`, `ready`) is attached.

### Postconditions

- Exactly one dispatch decision is returned per poll cycle.
- Returned decision includes lane, task id, and tie-break basis.
- Any deferred task remains represented in scheduler state.

### Invariant Preservation Rules

- `cancel` lane may preempt others but fairness bound must hold.
- Local `!Send` tasks cannot migrate across workers.
- Dispatch must never detach tasks from region ownership graph.

### Failure Semantics

- Capacity saturation returns explicit backpressure signal (no silent drop).
- Invalid task identity returns deterministic contract failure.

## 2. `TimeSeam`

### Responsibilities

- Provide monotonic time source abstraction.
- Register/cancel wake deadlines.
- Surface clock progression events for tracing and replay.

### Preconditions

- Deadline values are normalized to runtime time domain.
- Timer registration has stable task/region ownership references.

### Postconditions

- Timer operations are idempotent by `(task_id, timer_id, generation)`.
- Cancellation of timer obligation cannot leak wake handles.

### Invariant Preservation Rules

- Virtual-time mode must remain deterministic under fixed seed.
- Wall-clock mode must not reorder same-tick deadlines nondeterministically.

### Failure Semantics

- Expired timer with missing owner returns typed orphan-timer error.
- Backend timer-wheel overflow must produce explicit promotion event.

## 3. `IoSeam`

### Responsibilities

- Register I/O interests and wake corresponding tasks.
- Preserve token generation safety to avoid stale wakeups.
- Route readiness events through capability-scoped context.

### Preconditions

- Registration includes token, interest mask, and ownership metadata.
- Source handle validity is checked at registration time.

### Postconditions

- Readiness delivery is at-most-once per registration epoch.
- Deregistration leaves no live waiter in obligation tables.

### Invariant Preservation Rules

- Token reuse increments generation and invalidates stale events.
- Unknown token events are diagnostic signals, not panic paths.
- I/O callbacks must not bypass cancellation checkpoints.

### Failure Semantics

- Backend-specific registration errors map to stable runtime error classes.
- Closed-handle race is treated as already-cleaned when safe.

## 4. `WakeupSeam`

### Responsibilities

- Coordinate local and foreign wakeups.
- Deduplicate wakes without losing runnable transitions.

### Preconditions

- Wake target task id exists or is marked terminal.
- Wake source metadata is attached for diagnostics.

### Postconditions

- Duplicate wake requests do not create duplicate queue entries.
- Legitimate wake requests are not dropped during dedup.

### Invariant Preservation Rules

- Idle-to-active transition remains linearizable.
- Wake ordering metadata is stable under deterministic lab replay.

### Failure Semantics

- Unknown wake target yields typed stale-wake event with provenance.

## 5. `AuthoritySeam`

### Responsibilities

- Restrict host/browser capabilities to explicit tokens.
- Validate scope/authority of operations (network, storage, entropy, timers).

### Preconditions

- Every effect request carries capability context.
- Capability token verification path is deterministic and auditable.

### Postconditions

- Unauthorized requests fail closed with explicit denial reason.
- Authorized requests record capability lineage in trace metadata.

### Invariant Preservation Rules

- No effect path can execute without capability evidence.
- Capability narrowing cannot escalate permissions.

### Failure Semantics

- Invalid capability yields deterministic authorization error.
- Expired capability yields renewal-required path, not implicit fallback.

## Cross-Seam Conformance Rules

1. Every seam call must emit contract event fields:
- `seam_name`
- `operation`
- `task_id`
- `region_id`
- `contract_phase` (`pre`, `post`, `fail`)
- `decision_hash`
- `causal_clock`

2. Failure events must include:
- `error_class`
- `error_origin`
- `repro_hint`
- `transition_required` (bool)

3. Replay alignment requires:
- deterministic ordering key
- stable schema version
- monotonic sequence id

## Deterministic Unit Fixture Matrix

- `seam.scheduler.fairness_bound`
- `seam.scheduler.cancel_preemption_limit`
- `seam.time.timer_cancel_idempotence`
- `seam.time.deadline_ordering_stability`
- `seam.io.token_generation_staleness`
- `seam.io.unknown_token_nonpanic`
- `seam.wakeup.dedup_no_loss`
- `seam.authority.no_ambient_escalation`

Each fixture must provide:
- fixed seed
- initial state snapshot
- operation sequence
- expected post-state + emitted event sequence

## Native-vs-Browser Parity E2E Matrix

For each scenario, run native backend and browser-adapter stub backend, then compare:
- terminal `Outcome`
- cancellation phase transitions
- obligation closure set
- contract event sequence fingerprint

Required scenario families:
- cancellation race under timer pressure
- late wakeup after timer cancellation
- I/O readiness burst with dedup pressure
- authority denial and recovery path

## CI Gate Expectations

Contract conformance is CI-blocking when:
- any seam fixture fails deterministic expected output,
- native/browser parity fingerprints diverge for required scenarios,
- contract event schema is missing required fields.

CI artifacts must include:
- deterministic repro command,
- failing fixture id,
- event-log excerpt,
- backend profile metadata.
