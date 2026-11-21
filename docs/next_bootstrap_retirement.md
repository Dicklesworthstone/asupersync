# Next.js bootstrap ownership through navigation and cleanup

`NextClientBootstrapAdapter` retains each runtime generation until its scope and
runtime have successfully closed. A generation is recorded before its bootstrap
factory runs, so a late runtime cannot be forgotten after navigation, hydration
recovery, cache revalidation, hot reload, or component teardown.

The existing synchronous methods keep their event return types and hide the old
runtime and scope immediately. They initiate cleanup. `initializeRuntime()` and
`ensureRuntimeReady()` wait for earlier closing generations before allocating a
replacement runtime. Concurrent initialization still shares one attempt.

```ts
const adapter = createNextBootstrapAdapter({ initialRouteSegment: "/inbox" });
const opened = await adapter.ensureRuntimeReady();
if (opened.outcome !== "ok") throw new Error(formatOutcomeFailure(opened));

// Work belongs to opened.value, including fetches and native stream pipelines.
adapter.navigate("hard_navigation", "/archive");
const replacement = await adapter.ensureRuntimeReady();
// Replacement allocation waited for the old scope's native cleanup and ABI close.
```

## Explicit cleanup receipts

`closeAsync(reason?)` and `retire(reason?)` return `Promise<Outcome<void>>`. They
detach and invalidate the current generation and join the owners captured by
that call, including a pending bootstrap that has not returned its runtime yet.
The default reason is `"manual_close"`. A non-string reason refuses without
initiating cleanup.

```ts
const cleanup = await adapter.closeAsync("client boundary unmounted");
if (cleanup.outcome !== "ok") {
  reportCleanupFailure(cleanup);
}
```

Success is an independent cleanup receipt. An invalidated initialization still
returns its cancellation outcome, even when its late runtime retires cleanly.
The synchronous `close()` event is a request receipt; it is not a native drain
barrier. Use an async receipt when subsequent work depends on completed cleanup.

For current Browser Edition owners, the adapter awaits `scope.closeAsync()`
before calling `runtime.closeAsync()`. Refused child cleanup retains the parent.
The close functions and consumer ABI versions are captured with their owners,
and a completed child is not closed again while retrying its parent. Older
providers without `closeAsync()` use their synchronous close receipt and retain
their existing callback order; they provide only their own close guarantees.

## Failure and retry

Failed owners remain privately retained after public handles disappear. A
replacement initialization returns the cached cleanup failure without allocating
another runtime or automatically retrying the failed close. The caller can make
an explicit retry when the failed condition is recoverable:

```ts
const retry = await adapter.retire("retry retained owner cleanup");
if (retry.outcome === "ok") {
  const replacement = await adapter.ensureRuntimeReady();
  // Handle this new initialization's Outcome independently.
}
```

Concurrent cleanup calls join the same in-flight work for each captured owner.
An explicit call may retry a failure that was already observed before that call;
it does not hide a new failure by immediately invoking cleanup twice. The
adapter preserves the underlying owner's stricter rules: a rejected native
cleanup hook remains a failure when that owner cannot prove successful recovery.
Host operations that never settle keep their retirement pending.

## Validation boundary

The focused integration suite is
`scripts/test_next_owned_lifecycle_wasm.mjs`. It executes the Next adapter and
Browser SDK with the checked-in generated JavaScript/WASM ledger and native Node
streams. Controlled factory publication and ABI refusal expose delayed-owner
and retry behavior without replacing the owner handles. The existing bootstrap
lifecycle suite covers phase transitions, event compatibility and reentrancy.
These tests do not execute a Next renderer, browser engine, or Rust rebuild.
