# SharedWorker Tenancy, Lifecycle, and Downgrade Contract

Contract ID: `wasm-shared-worker-tenancy-lifecycle-v1`  
Bead: `asupersync-n6kwt.6.1`  
Validation bead: `asupersync-n6kwt.6.3`  
Depends on: `asupersync-2jhnk.6.1`

## Purpose

Define the authoritative contract for the bounded SharedWorker coordinator
Browser Edition lane without pretending that coordinator ownership is direct
runtime support inside `SharedWorkerGlobalScope`.

This contract answers:

1. which browsing contexts may join the same coordinator,
2. how app/version namespaces are partitioned,
3. which client identity and lifecycle facts must be tracked,
4. how quiescence and coordinator loss map to downgrade,
5. which state is ephemeral coordinator state versus durable external state.

The point of the bounded SharedWorker lane is explicit same-origin multi-tab
reuse and coordinator-pool amortization without changing the semantic floor.
Crash recovery, client churn, version mismatch, and browser reclaim are treated
as first-class downgrade cases, not as edge conditions that silently widen
Browser Edition claims.

## Current Truthful Runtime Status

The live tree classifies SharedWorker direct runtime as
broker/coordinator-only:

- `@asupersync/browser` only ships browser main-thread and dedicated-worker
  direct-runtime lanes.
- `src/runtime/builder.rs` detects `SharedWorkerGlobalScope`, but maps it to
  `BrowserRuntimeSupportReason::SharedWorkerNotYetShipped` and
  `BrowserExecutionReasonCode::SharedWorkerDirectRuntimeNotShipped`.
- `@asupersync/browser` exposes a bounded coordinator helper for browser
  main-thread or dedicated-worker callers to negotiate a same-origin
  SharedWorker coordinator, attach explicit per-client ports, detect protocol
  or feature mismatch, and downgrade mechanically.
- This document is therefore a present coordinator contract and a direct-runtime
  non-support claim.

The downgrade promise is non-negotiable: SharedWorker disappearance, host
policy denial, or namespace mismatch may change execution strategy and
diagnostics, but must not silently widen the semantic claim.

Direct runtime can only be reconsidered by a future owner bead that proves the
shared-worker host can own regions, obligations, scheduler state, cancellation,
drain/finalize, replay evidence, client fanout, and durable recovery without
silent remapping to browser main-thread or dedicated-worker lanes.

## Admission And Tenancy Law

A SharedWorker coordinator is scoped by the tuple:

`(origin, app_namespace, app_version_major, coordinator_protocol_version, run_profile)`

Admission rules:

- same-origin only; cross-origin federation is out of scope,
- exact `app_namespace` match is required,
- exact `app_version_major` match is required unless a future compatibility
  manifest explicitly widens the join set,
- exact `coordinator_protocol_version` match is required,
- `run_profile` must not mix incompatible lanes such as `smoke` and `nightly`
  when their artifact or retention policies differ materially.

The coordinator may multiplex multiple clients only when all admission fields
match. Version drift or profile drift is an immediate downgrade trigger rather
than a best-effort partial join.

## Client Identity And Registration

Every joining client must register a bounded identity record with the
coordinator:

- `client_instance_id`: stable for the lifetime of the attached port/session,
- `client_epoch`: increments when a browser context reconnects after reload or
  crash recovery,
- `client_kind`: browser tab, iframe, dedicated worker, or other admitted
  same-origin browsing context,
- `client_started_at_ms`: monotonic diagnostic timestamp,
- `client_capability_summary`: explicit declared capabilities for this join,
- `client_artifact_namespace`: where durable artifacts and replay bundles are
  stored outside coordinator memory.

Client identity is for liveness, ownership, and downgrade reasoning. It is not
ambient publish authority and must not bypass the existing capability model.

Port/session registration rules:

- registration is explicit and idempotent for the same
  `client_instance_id` + `client_epoch`,
- stale epochs must be rejected or replaced deterministically,
- reconnect may recover durable artifacts, but it must not recover abandoned
  in-memory authority implicitly,
- client churn (tab close, reload, reconnect, or worker restart) is expected
  steady-state behavior and must remain diagnosable through explicit join and
  detach events,
- coordinator-side state that depends on the client must be removed when the
  port closes or the client is declared lost.

## Lifecycle And Quiescence

The coordinator lifecycle is:

1. `bootstrapping`
2. `joining`
3. `active`
4. `draining`
5. `quiescent`
6. `terminated`

Required interpretation:

- `bootstrapping`: construct coordinator-local state and validate namespace,
  version, and durable-store prerequisites.
- `joining`: accept or reject client registration without yet promising stable
  reuse.
- `active`: at least one registered client is present and the coordinator may
  serve admitted work for that tenancy tuple.
- `draining`: no new work is admitted; outstanding coordinator-owned work is
  being finalized or downgraded.
- `quiescent`: no registered clients remain, no coordinator-owned obligations
  remain unresolved, and no ephemeral state is required for semantic
  correctness.
- `terminated`: the coordinator has exited voluntarily, crashed, or been
  reclaimed by the browser.

Quiescence law:

- coordinator quiescence means "no live clients + no unresolved
  coordinator-owned obligations + no undrained ephemeral queues",
- quiescence is not durability; anything that must survive `terminated` must
  already live outside the SharedWorker,
- coordinator loss is never treated as impossible or exceptional for semantic correctness; it is a first-class downgrade input.

## Ephemeral Versus Durable State

### Ephemeral coordinator state

Ephemeral coordinator state lives only in SharedWorker memory and is assumed to
disappear at any time:

- live port registry and `client_instance_id` membership,
- in-memory routing tables or session maps for the admitted tenancy tuple,
- short-lived scheduler queues, wakeups, and lane-health counters,
- transient batching buffers,
- in-memory replay assembly buffers that have not yet been flushed durably.

### Durable state

Durable state must survive coordinator loss and therefore must live in an
explicit external substrate such as IndexedDB-backed artifacts:

- artifact manifests and retained evidence indexes,
- replay bundles and crashpack metadata,
- compatibility manifests or namespace-version admission metadata,
- resumable work descriptors whose survival is part of the product contract,
- operator-visible summaries needed after coordinator loss.

The SharedWorker coordinator owns no irreplaceable authoritative state. If a
piece of state is semantically required after coordinator loss, it must already
be durable before the lane may claim recovery.

## Mandatory Downgrade Reasons

The following conditions force immediate downgrade instead of partial support:

- `shared_worker_api_missing`
- `origin_not_same_origin_or_opaque`
- `app_namespace_mismatch`
- `app_version_major_mismatch`
- `coordinator_protocol_version_mismatch`
- `durable_store_unavailable_for_recovery_required_profile`
- `registration_schema_mismatch`
- `coordinator_bootstrap_failure`
- `coordinator_crash_or_browser_reclaim`
- `operator_policy_disabled_shared_worker_lane`
- `lane_health_demoted`

Downgrade rules:

- downgrade chooses the next truthful lower lane, typically dedicated worker,
  browser main thread, or an explicit bridge-only path depending on host and
  packaging surface,
- downgrade must emit an explicit reason code and repro guidance,
- downgrade must not leave the caller in a "maybe shared worker, maybe not"
  limbo state,
- unsupported browsers stay unsupported; they do not receive partial success.

## Security And Authority Boundaries

- SharedWorker reuse never relaxes the existing capability model.
- Client identity does not become ambient authority.
- Cross-tab or cross-frame sharing is same-origin and namespace-scoped only.
- Capability-bearing handles must be re-established explicitly after restart.
- Break-glass recovery may read durable artifacts, but must not silently
  resurrect expired in-memory leases or obligations.

## Explicit Non-Goals

- cross-origin SharedWorker federation
- treating SharedWorker lifetime as durable process lifetime
- storing authoritative runtime state only in SharedWorker memory
- silent promotion from unsupported hosts into a SharedWorker lane
- claiming service-worker and shared-worker parity from one shared policy blob
- bypassing explicit downgrade because "the coordinator usually stays alive"

## Validation

Contract validation:

```bash
rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_wasm_shared_worker_tenancy_docs cargo test --test wasm_shared_worker_tenancy_lifecycle_contract -- --nocapture
```

Browser-run proof / artifact bundle:

```bash
PATH=/usr/bin:$PATH bash scripts/validate_shared_worker_consumer.sh
```

The maintained browser-run validator leaves `summary.json` and
`browser-run.json` under `target/e2e-results/shared_worker_consumer/<timestamp>/`
and currently proves:

- same-origin multi-page reuse on one coordinator name,
- clean rejoin after client churn and explicit detach cleanup,
- protocol-version mismatch fallback,
- crash-before-handshake fallback, and
- reconnect after that crash path by starting a fresh coordinator on the same
  worker name.

Related host-ladder validation:

```bash
rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_wasm_shared_worker_tenancy_docs cargo test --test wasm_browser_feasibility_matrix -- --nocapture
```

## Cross-References

- `src/runtime/builder.rs`
- `docs/WASM.md`
- `docs/integration.md`
- `tests/wasm_browser_feasibility_matrix.rs`
