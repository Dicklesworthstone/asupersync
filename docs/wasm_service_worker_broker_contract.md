# Service-Worker Bounded Broker, Persistence, and Downgrade Contract

Contract ID: `wasm-service-worker-broker-contract-v1`  
Bead: `asupersync-n6kwt.7.1`  
Resolution bead: `asupersync-9r5lmo`
Support class: `broker/coordinator-only`
Depends on: `asupersync-2jhnk.6.1`, `asupersync-3ak5y`

## Purpose

Define the authoritative contract for the Browser Edition service-worker
bounded broker lane without pretending that lane has shipped as a direct
runtime.

The service worker is only admissible as a bounded broker/orchestration surface.
It is not a general-purpose always-alive runtime, and it must never silently
inherit dedicated-worker semantics.

This contract answers:

1. which broker responsibilities are allowed,
2. which durable state must survive worker termination,
3. how restart reconciliation and capability re-establishment work,
4. which downgrade reasons are mandatory,
5. why the current support class is broker/coordinator-only,
6. which non-goals stay explicit even after promotion work begins.

## Product Support Decision

As of `asupersync-9r5lmo`, service-worker direct runtime is classified as
`broker/coordinator-only`. The supported service-worker surface is bounded
broker registration, restartable work descriptors, durable handoff, and
downgrade evidence. Direct `BrowserRuntime` creation inside
`ServiceWorkerGlobalScope` remains fail-closed.

The reason is structural, not just missing glue code: browsers may terminate a
service worker between lifecycle events, so volatile service-worker memory
cannot own asupersync regions, obligations, scheduler state, or authoritative
runtime leases. A future direct-runtime attempt must be a new owner bead with
proof for browser-lifetime region ownership, cancellation, drain/finalize,
durable replay, and no silent remapping to browser main-thread or
dedicated-worker lanes.

## Current Truthful Runtime Status

The live tree still fail-closes service-worker direct runtime today:

- `@asupersync/browser` detects service-worker-like hosts in
  `packages/browser/src/index.ts` and returns
  `reason = "service_worker_not_yet_shipped"` with guidance to keep
  orchestration at the application boundary.
- `src/runtime/builder.rs` detects `ServiceWorkerGlobalScope`, but maps it to
  `BrowserRuntimeSupportReason::ServiceWorkerNotYetShipped` and
  `BrowserExecutionReasonCode::ServiceWorkerDirectRuntimeNotShipped`.
- The execution ladder therefore remains fail-closed for service-worker direct
  runtime. This document is the current support contract for bounded
  brokering, not a direct-runtime support claim.

At the same time, the Browser Edition package now exposes a bounded broker API
that keeps this direct-runtime denial intact:

- `detectBrowserServiceWorkerBrokerSupport()` reports whether the service-worker
  broker prerequisites are available without claiming that direct runtime is
  supported in `ServiceWorkerGlobalScope`.
- `BrowserServiceWorkerBrokerStore` and
  `createBrowserServiceWorkerBrokerStore()` persist explicit broker
  registration manifests, pending work descriptors, and durable handoff
  records.
- `registerBroker()`, `persistBrokerWork()`, and `persistDurableHandoff()`
  keep `requested_lane = "lane.browser.service_worker.broker"` and force the
  fallback target to stay on a dedicated worker, browser main thread, or
  explicit bridge-only path.
- `listDurableHandoffs()` enumerates persisted handoff records from the broker
  namespace in newest-first order so restart reconciliation can replay the most
  recent downgrade or resume decision without guessing.
- durable broker records use stable broker-local keys:
  `__service_worker_broker_registration__`,
  `broker_work:<broker_work_id>`, and
  `broker_handoff:<broker_work_id>` inside the
  `service_worker_broker_v1` namespace.

The downgrade promise is non-negotiable: browser reclaim, missing storage,
scope drift, or capability mismatch may change the selected lane, but must not
quietly widen the support claim.

## Bounded Broker Law

### Allowed broker responsibilities

The bounded service-worker broker lane may:

- serialize fetch/push/sync/notification ingress into explicit broker work
  descriptors before any restartable progress is claimed,
- persist durable broker manifests before claiming restartable progress,
- hand work off to a dedicated worker, browser main thread, or explicit
  bridge-only adapter,
- emit downgrade diagnostics, replay-friendly summaries, and evidence/artifact
  records tied to the durable broker state,
- reconcile durable descriptors after restart and either resume, downgrade, or
  abort them explicitly.

### Forbidden expansions

The bounded service-worker broker lane may not:

- behave like a general-purpose always-alive runtime,
- run arbitrary application tasks as if `ServiceWorkerGlobalScope` had
  dedicated-worker parity,
- keep authoritative leases, obligations, or scheduler state only in volatile
  service-worker memory,
- become an unbounded queue or broker-of-last-resort for unsupported hosts.

## Admission Tuple And Broker Identity

A service-worker broker is scoped by the tuple:

`(origin, registration_scope, app_namespace, app_version_major, broker_protocol_version, run_profile)`

Admission rules:

- exact `origin` and `registration_scope` match are required,
- exact `app_namespace` match is required,
- exact `app_version_major` match is required unless a future compatibility
  manifest explicitly widens the join set,
- exact `broker_protocol_version` match is required,
- `run_profile` must not mix incompatible policy/evidence expectations such as
  `smoke` and `nightly`.

Every durable broker descriptor must carry:

- `broker_work_id`,
- `source_event_kind`,
- `artifact_namespace`,
- `idempotency_key`,
- `capability_manifest_version`,
- `requested_lane`,
- `fallback_lane`,
- `lease_epoch`.

These fields exist so restart reconciliation can be mechanical rather than
best-effort folklore.

## Lifecycle And Restart Reconciliation

The broker lifecycle is:

1. `cold_start`
2. `validating_scope`
3. `reconciling_durable_state`
4. `brokering`
5. `draining`
6. `quiescent`
7. `terminated`

Required interpretation:

- `cold_start`: the browser activated the worker, but no support claim has been
  made yet.
- `validating_scope`: registration scope, namespace, version, and durable-store
  prerequisites are checked.
- `reconciling_durable_state`: persisted descriptors, artifacts, and downgrade
  journals are loaded and classified.
- `brokering`: the worker may mediate admitted browser events, but only through
  explicit broker descriptors and downgrade-aware handoff.
- `draining`: no new restartable work is admitted; in-flight descriptors are
  being handed off, finalized, downgraded, or aborted explicitly.
- `quiescent`: no admitted restartable work remains unresolved and no ephemeral
  state is needed for semantic correctness.
- `terminated`: the worker exited voluntarily, crashed, or was reclaimed by the
  browser.

Restart reconciliation law:

- capabilities are re-established explicitly after activation; in-memory
  authority never silently survives worker death,
- resume is allowed only when the durable descriptor and the new capability
  snapshot still match,
- reconciliation must choose one terminal action per descriptor:
  `resume_in_place`, `downgrade_to_dedicated_worker`,
  `downgrade_to_browser_main_thread`, `downgrade_to_bridge_only`, or
  `abort_with_explicit_reason`,
- stale descriptors whose namespace, protocol, or capability contract no longer
  matches must fail closed instead of being guessed forward.

## Ephemeral Broker State Versus Durable State

### Ephemeral broker state

Ephemeral broker state lives only in service-worker memory and may disappear at
any time:

- active `FetchEvent` / `PushEvent` / background-sync handler state,
- transient response/body streaming buffers,
- live `Client` handle snapshots and wakeups,
- in-memory backoff counters and debounce timers,
- short-lived retry bookkeeping that has not yet been durably recorded.

### Durable state

Durable state must live in an explicit external substrate such as
IndexedDB-backed BrowserStorage / BrowserArtifactStore:

- broker registration manifests for the admission tuple,
- pending broker work descriptors and idempotency keys,
- artifact manifests and retained evidence indexes,
- replay bundles and crashpack metadata,
- restart reconciliation journal and downgrade audit records.

Recommended durable key layout:

- `__service_worker_broker_registration__` for the current admission tuple and
  registration manifest,
- `broker_work:<broker_work_id>` for pending broker work descriptors,
- `broker_handoff:<broker_work_id>` for durable handoff and downgrade records,
- all scoped under the `service_worker_broker_v1` namespace so replay tooling
  can enumerate and sort records deterministically.

The service-worker broker owns no irreplaceable authoritative state. If a fact
must survive browser reclaim or worker termination, it must already be durable
before the service-worker lane may claim restartable behavior.

## Capability Re-Establishment

Capability re-establishment must compare durable broker descriptors against the
new host snapshot:

- browser event capabilities currently available to the worker,
- durable storage availability and backend selection,
- `capability_manifest_version`,
- `requested_lane` versus the current truthful downgrade ladder,
- `lease_epoch` and idempotency expectations for outstanding descriptors.

If any of those checks fail, the broker must downgrade or abort. It must not
recreate ambient capability from stale durable metadata.

## Mandatory Downgrade Reasons

The following conditions force immediate downgrade or explicit abort instead of
partial support:

- `service_worker_api_missing`
- `service_worker_registration_scope_mismatch`
- `service_worker_controller_missing_when_required`
- `app_namespace_mismatch`
- `app_version_major_mismatch`
- `broker_protocol_version_mismatch`
- `durable_store_unavailable_for_restartable_profile`
- `capability_manifest_mismatch_on_restart`
- `background_event_kind_outside_broker_contract`
- `broker_bootstrap_failure`
- `broker_restart_reconciliation_failed`
- `worker_reclaimed_by_browser`
- `lane_health_demoted`

Downgrade rules:

- downgrade chooses the next truthful lower lane: dedicated worker first when
  available, then browser main thread, then an explicit bridge-only path,
- downgrade must emit an explicit reason code and repro guidance,
- unsupported browsers stay unsupported; they do not receive partial success,
- the broker must never leave callers in a "maybe resumed, maybe dropped" state.

## Security And Authority Boundaries

- Service-worker event authority does not become ambient publish authority.
- Durable broker descriptors are replay material, not capability tokens.
- Capability-bearing handles must be re-established explicitly after restart.
- Restart reconciliation may read durable artifacts, but must not silently
  resurrect expired leases, obligations, or ownership.
- Background-event admission must stay scoped to the declared broker tuple and
  explicit downgrade law.

## Explicit Non-Goals

- pretending arbitrary application scopes may live indefinitely inside the
  service worker,
- executing ordinary runtime tasks in the service worker as if it were a
  dedicated worker,
- storing authoritative runtime state only in service-worker memory,
- silent promotion from unsupported hosts into partially functional brokering,
- unbounded offline queueing without explicit durable policy and quota law,
- claiming service-worker and shared-worker parity from one shared policy blob.

## Validation

Contract validation:

```bash
rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_wasm_service_worker_broker_docs cargo test --test wasm_service_worker_broker_contract -- --nocapture
```

Related host-ladder validation:

```bash
rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_wasm_service_worker_broker_docs cargo test --test wasm_browser_feasibility_matrix -- --nocapture
```

Maintained browser-run lifecycle validation:

```bash
PATH=/usr/bin:$PATH bash scripts/validate_service_worker_broker_consumer.sh
```

## Cross-References

- `packages/browser/src/index.ts`
- `src/runtime/builder.rs`
- `docs/WASM.md`
- `docs/integration.md`
- `tests/wasm_browser_feasibility_matrix.rs`
- `tests/fixtures/service-worker-broker-consumer/`
- `scripts/validate_service_worker_broker_consumer.sh`
