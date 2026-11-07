# WASM React Reference Patterns

Bead: `asupersync-umelq.10.5`

This document defines the canonical React integration patterns for the WASM
Browser Edition surface and maps each pattern to deterministic harness
scenarios in `tests/react_wasm_strictmode_harness.rs`.

Cross-framework canonical example index:
`docs/wasm_canonical_examples.md`.

## Scope

The reference catalog covers:

1. Task groups with explicit cancellation UX.
2. Bounded retry after transient failures.
3. Bulkhead isolation across independently scoped work.
4. Tracing-hook diagnostic transitions for replay/debug flows.

All scenarios must preserve the runtime invariants:

- no leaked tasks or scopes,
- cancelled losers are drained before teardown,
- cancellation is explicit and observable,
- structured logs contain stable scenario IDs and replay metadata.

## Scenario Catalog

| Scenario ID | Pattern | Intent | Deterministic Assertions |
| --- | --- | --- | --- |
| `react_ref.task_group_cancel` | task group + cancel UX | User cancel on one grouped task drains cleanly while sibling completion remains valid. | cancel count and join count stay balanced; group scope closes leak-free. |
| `react_ref.retry_after_transient_failure` | retry | Two transient failures followed by success with bounded retry attempts. | `retry_attempts=3`, `recoverable_failures=2`, final outcome is success. |
| `react_ref.bulkhead_isolation` | bulkhead | Overload cancellation in one bulkhead does not block the sibling bulkhead path. | one cancellation, sibling success, independent scope closure. |
| `react_ref.tracing_hook_transition` | tracing hook | Emit stable hook transition diagnostics for troubleshooting and replay pointers. | hook transition is legal (`active -> cleanup`) and fields are deterministic. |

## Structured Logging Contract

Each scenario emits deterministic fields with these required keys:

- `scenario_id`
- `pattern`
- `outcome`
- `retry_attempts`
- `recoverable_failures`
- `cancel_count`
- `join_count`
- `notes`

Tracing-hook entries additionally include:

- `hook_kind`
- `from_phase`
- `to_phase`
- `label`
- `handles_count`
- `detail`

## Reproduction Commands

Run the full reference-pattern harness:

```bash
rch exec -- env CARGO_TARGET_DIR=/tmp/rch-target-umelq105 cargo test --test react_wasm_strictmode_harness -- --nocapture
```

Run only the reference catalog deterministic test:

```bash
rch exec -- env CARGO_TARGET_DIR=/tmp/rch-target-umelq105 cargo test --test react_wasm_strictmode_harness reference_pattern_catalog_scenarios_are_deterministic_and_leak_free -- --nocapture
```

Run lint/format gates for touched surface:

```bash
rch exec -- env CARGO_TARGET_DIR=/tmp/rch-target-umelq105 cargo check --all-targets
rch exec -- env CARGO_TARGET_DIR=/tmp/rch-target-umelq105 cargo clippy --all-targets -- -D warnings
rch exec -- env CARGO_TARGET_DIR=/tmp/rch-target-umelq105 cargo fmt --check
```

## Awaitable React ownership cleanup

The provider and scope hooks use the browser SDK's asynchronous owner close.
Unmount, StrictMode effect replay, runtime-option replacement and scope-label
replacement request cancellation and retain the previous owner until its fetch
cleanup and ABI close finish. A replacement is allocated only after that
retirement succeeds. During a render that changes the runtime request, the
context hides the previous runtime before the new effect runs.

The existing `useReactRuntimeContext()`, `useReactScope()` and scope
`close(): void` interfaces remain available. For an explicit completion boundary,
use the additive lifecycle hooks:

```tsx
import {
  type ReactCleanupReport,
  ReactRuntimeProvider,
  useReactRuntimeLifecycle,
  useReactScopeLifecycle,
} from "@asupersync/react";

const refusedCleanups = new Set<ReactCleanupReport>();

function recordCleanup(report: ReactCleanupReport): void {
  if (report.outcome.outcome !== "ok") refusedCleanups.add(report);
}

function WorkControls() {
  const runtime = useReactRuntimeLifecycle();
  const work = useReactScopeLifecycle({
    label: "results",
    onCleanup: recordCleanup,
  });

  async function stopWork(): Promise<void> {
    const report = await work.closeAsync();
    if (report.outcome.outcome === "ok") {
      // All fetches owned by this scope have drained and its close succeeded.
    }
  }

  async function stopRuntime(): Promise<void> {
    const report = await runtime.closeAsync();
    if (report.outcome.outcome !== "ok") recordCleanup(report);
  }

  return (
    <>
      <button onClick={() => void stopWork()}>Stop work</button>
      <button onClick={() => void stopRuntime()}>Stop runtime</button>
    </>
  );
}

// Keep a grant object stable while its policy is unchanged. Replace the object
// when changing authority so the provider drains and replaces the old owner.
const fetchAuthority = {
  allowedOrigins: ["https://api.example.test"],
  allowedMethods: ["GET" as const],
  allowCredentials: false,
  maxHeaderCount: 4,
};

<ReactRuntimeProvider
  runtimeOptions={{ fetchAuthority }}
  onCleanup={recordCleanup}
>
  <WorkControls />
</ReactRuntimeProvider>;
```

React itself does not await effect cleanup. `onCleanup` receives the actual
completion report, including after unmount, so it should record the result
outside a component that has already unmounted. Reports use the latest committed
observer at completion, including when the observer changes during a pending
drain. Changing only an observer does not replace the runtime or scope, and an
uncommitted render does not change the recipient. Observer exceptions do not
interrupt resource cleanup. `closeAsync()` resolves the same kind of report;
an `ok` outcome means the selected owners were retired, while a refused close
keeps their handles and reports a nonzero `retainedOwners` count.

Each report has `retry(): Promise<ReactCleanupReport>`. After correcting a
retryable failure, await that method and inspect its outcome. It retries only
the report's original owners; an old report cannot close a newer runtime or
scope. A successful retry does not implicitly reopen work. Call the provider's
`reload()`, or change scope inputs, to request another generation afterward.
A host cleanup promise that never settles also keeps cleanup pending; the
adapter cannot force host completion or treat a refused ABI close as success.

Provider retirement closes registered hook scopes before the runtime. Hooks
stop exposing the retiring owner on the relevant render. A caller that retains
the raw `BrowserRuntime` can still create independent work while a child drain
is pending, before the runtime's own SDK close begins. That later runtime close
sweeps the independent descendants too. This is a final-retirement guarantee,
not an immediate SDK-wide admission fence during the child-first stage.

`fetchAuthority` identity participates in provider replacement. Consumer
versions are compared by major/minor values; undefined and null retain the
SDK's same default behavior. Equivalent option objects with the same authority
do not restart a runtime solely because the outer object changed.

### Behavioral regression harness

```bash
node --unhandled-rejections=strict --experimental-vm-modules --test \
  --test-concurrency=1 scripts/test_react_owned_fetch_lifecycle.mjs
```

The Node 24+ harness loads the complete React adapter, browser SDK, fetch
adapter and core sources. It uses native WHATWG streams, an explicit React hook
dispatcher double, and an intentional WASM ABI owner/task ledger. Cases hold a
response-body cancellation open to check that teardown and replacement wait;
they also cover authority rotation, StrictMode replay, late bootstrap,
refusal/retry, unmount liveness and independent raw-runtime descendants.
Selected bootstrap fault cases defer or reject the factory before allocation.

This evidence covers the adapter/SDK host boundary. It does not execute React's
renderer, a browser engine, or compiled Rust/WASM. The existing Rust reference
harness remains a separate deterministic model. To compare an untouched old
adapter, set `ASUPERSYNC_REACT_SOURCE` and select the `REACT-UNMOUNT` and
`REACT-AUTHORITY` cases with Node's `--test-name-pattern` option.

This extends the lifecycle work tracked by `asupersync-umelq.10.1` and
`asupersync-umelq.10.2`, together with semantic-option stability from
`asupersync-3qv04.17`. Those completed beads are historical context, not new
closure claims. The behavior implements the browser plan's component
unmount/cancel/drain boundary in section 12.2.
