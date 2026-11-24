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


## Application tasks with automatic cancellation and drain

`useReactTask(work, dependencies, options?)` is the application-task hook from
the browser plan's section 12.1. Each committed invocation gets a dedicated
SDK child scope and a real `RegionHandle.runTask` ledger entry. The callback
receives `(signal, scope)` and may return any JavaScript value or promise,
including values that cannot be serialized through the WASM ABI.

```tsx
import {
  ReactRuntimeProvider,
  useReactTask,
  type ReactCleanupReport,
} from "@asupersync/react";

function recordTaskCleanup(report: ReactCleanupReport): void {
  if (report.outcome.outcome !== "ok") {
    // Keep the report somewhere outside an unmounted component. After fixing
    // the failure, await report.retry() and inspect the new report.
    console.error("Task cleanup needs attention", report);
  }
}

function DocumentPreview({ url }: { url: string }) {
  const task = useReactTask(async (signal) => {
    const response = await fetch(url, { signal });
    if (!response.ok) throw new Error("HTTP " + response.status);
    return response.text();
  }, [url], { label: "document-preview", onCleanup: recordTaskCleanup });

  return (
    <section>
      <button
        disabled={task.status !== "running"}
        onClick={() => void task.cancel()}
      >
        Cancel
      </button>
      {task.status === "running" && <p>Loading…</p>}
      {task.status === "cancelling" && <p>Finishing cancellation…</p>}
      {task.outcome?.outcome === "cancelled" && <p>Cancelled.</p>}
      {task.outcome?.outcome === "ok" && <pre>{task.outcome.value}</pre>}
      {task.outcome?.outcome === "panicked" && <p>The operation failed.</p>}
      {task.outcome?.outcome === "err" && <p>The runtime refused the operation.</p>}
      {task.cleanup && task.cleanup.outcome.outcome !== "ok"
        && <p>Resource cleanup needs attention.</p>}
    </section>
  );
}

<ReactRuntimeProvider>
  <DocumentPreview url="/api/document" />
</ReactRuntimeProvider>;
```

The example uses native fetch with its native authority and the task's abort
signal. For the SDK's explicit fetch grants, bounded response reads, stream
pipes or other owned integrations, use the callback's second argument:
`scope.fetch(...)`, `scope.pipeTo(...)`, or another SDK scope operation.
The dedicated task scope also owns descendants created through that scope.
Its automatic close cancels and drains outstanding descendants before the
hook publishes a terminal result.

Dependencies follow `useEffect` semantics. Include every reactive value used
by `work`; changing a dependency starts a new invocation after the old one
retires. Changing only an inline callback or cleanup-observer identity does
not restart work. Scope label, ABI version, provider runtime and `enabled`
also participate in invocation identity. With `enabled: false`, the hook
retires its previous invocation and returns to `idle`. Changing it back to
`true` requests a new invocation.

No callback runs during rendering. StrictMode effect replay retires obsolete
generations before starting their replacements. Changed dependencies hide the
old outcome during the render-to-effect gap. Late completion of an old or
unmounted generation cannot publish into the current component. Cancellation
of one task leaves sibling hooks running.

`task.cancel()` requests cancellation of the hook's current invocation and
returns a `Promise<ReactCleanupReport>`. While draining, status is
`cancelling`; after the callback and its scope's cleanup attempt finish,
status is `settled`. An idle hook with no admitted invocation has nothing to
cancel. A rejected or thrown callback becomes a `panicked` outcome. A
cancelled callback remains cancelled even if its abort handler returns a value.

The callback outcome and cleanup report are separate. A successful body can
coexist with a refused owner close; inspect `task.cleanup.outcome` and retain
its report for retry. A refusal keeps the owner, blocks replacement work,
and does not rerun the body. `report.retry()` targets only that report's
original owners. It cannot cancel a later invocation, and it does not
implicitly restart application work. Calling `task.cancel()` after settlement
also retries outstanding cleanup without rerunning the callback.

Return all asynchronous work that must be joined. A callback that ignores
abort and never settles keeps retirement pending. Do not await
`task.cancel()`, the supplied scope's `closeAsync()`, or an ancestor's
`closeAsync()` from inside the callback: those boundaries must join that same
callback promise. Request cancellation from an event handler or another
external owner, and let the callback observe its signal.

### Real React and packaged-WASM task harness

The task integration harness uses React's actual renderer, the complete
adapter and SDK sources, native Node AbortController and Web Streams, and
the checked-in JavaScript/WASM ownership ledger. Its only ABI interception
is the deliberately refused scope close in the refusal/retry case.

```bash
npm install --prefix /tmp/asupersync-react-tests --no-save react@19 react-test-renderer@19

ASUPERSYNC_REACT_TEST_ROOT=/tmp/asupersync-react-tests \
  node --unhandled-rejections=strict --experimental-vm-modules --test \
  --test-concurrency=1 scripts/test_react_tasks_wasm.mjs
```

The eight scenarios cover StrictMode and exact values, dependency replacement
and stale-result suppression, unmount with pending callback and child-stream
cleanup, sibling cancellation isolation, disabled and pre-admission work,
refused cleanup and generation-safe retry, successful callback results waiting
for child cleanup, and hostile callback rejection. This is a Node integration
harness, not browser-engine execution or a Rust rebuild. It supplements the
existing deterministic hook-dispatcher harness above.
