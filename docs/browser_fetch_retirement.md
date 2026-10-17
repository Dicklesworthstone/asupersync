# Explicit fetch retirement, separate from the request outcome

SDK-created `FetchStreamHandle`s now provide `retire(reason?)`. It is a one-way
cleanup operation usable even while the response stream is locked. The existing
`cancel()` and `closed` still report the request's original terminal Outcome.
Retirement instead reports observed cleanup and local admission release.

```ts
const admitted = scope.fetch({ url });
if (admitted.outcome !== "ok") throw new Error("request admission refused");
const handle = admitted.value;
try {
  const response = await handle.response();
  // Handle response or transport failure; consume the body when appropriate.
} finally {
  // SDK manager handles implement this. Older/third-party handles may not.
  if (handle.retire) {
    const cleanup = await handle.retire("operation finished");
    if (cleanup.outcome !== "ok") reportCleanupFailure(cleanup);
  } else {
    await handle.cancel("operation finished");
  }
}
const operation = await handle.closed;
```

A failed connection can have an `err` operation Outcome and an `ok` retirement
receipt: the request failed, but its tracked work retired. An intentional
cancellation normally has `cancelled` on `closed` and `ok` on `retire()`. Conversely,
a rejected cleanup callback or refused task publication produces a failing
retirement receipt even when `closed` retains the earlier cancellation.

## Ownership and barriers

The first valid retirement call installs a memoized promise before calling task
or host code. Reentrant and repeated calls share it. A non-string reason refuses
without cancelling anything or inspecting presentation hooks. A failed retirement
is not automatically retried, and later scope teardown does not rewrite its
memoized evidence. Retiring one handle does not cancel siblings or mutate a
caller-supplied parent signal.

If still active, retirement requests cancellation and stops host I/O even when
that cancellation admission is refused. It joins launch, response disposal,
admitted reads, response/upload cancellation, and terminal publication before
returning. A refused ordinary `cancel()` remains retryable as before; it does
not become a one-way retirement unless the caller invokes `retire()`.

Observed abort, source cancellation, reader-release, late-response disposal,
upload-cleanup, cancellation-admission, and task-publication failures are kept
separately from the operation's original Outcome. Cleanup diagnostics do not
format thrown cleanup payloads. Cancelling an already errored native reader
rejects with its stored source error without invoking the cancellation callback;
that error alone is not evidence of failed cleanup. A different cancellation
error, or a callback rejection from a stream closed by cancellation, is a cleanup
failure.

The optional interface method preserves structural compatibility with older
handles. A missing method is not proof of successful retirement. No new task,
executor, request, timer, retry, or network authority is created. Application or
remote effects already performed are not undone.

## Limits of this receipt

This is the existing SDK manager's host-work and local-credit boundary, not a
stronger certificate from the core task ABI. That ABI returns a terminal Outcome
rather than a separate publication acknowledgement. An identical non-success
error echo remains indistinguishable from an identical ABI refusal; the existing
`sameTerminal` decision has not been changed. Actual owner closure remains the
independent ledger barrier. Do not use this API to silently suppress failures in
header quorum/race selection or to claim that a scope is closed.

Native input cancellation does not join arbitrary work hidden inside a producer;
producer-specific completion contracts remain necessary. Nonsettling host work
keeps retirement pending. Server-side disconnection, remote acknowledgement,
application rollback, cross-browser equivalence, and a wall-clock bound are not
promised by this receipt. Local task-credit release can occur before the retirement
caller reads a failing cleanup receipt, just as with the previous `closed` API.

## Execution evidence

Run on Node with TypeScript stripping:

```sh
node --experimental-vm-modules --test scripts/test_browser_fetch_retirement.mjs
```

The 24 regressions execute the complete actual fetch manager and upload owner,
not extracted copies. Native Streams, request validation, authority checks and
real loopback HTTP execute; the core task ABI is explicitly doubled. Custom host
readers provide independent pending-read/cancellation and release-failure gates.
The pre-feature control sets `ASUPERSYNC_FETCH_SOURCE` to the original `fetch.ts`
and runs the same expectations through its `cancel()` fallback, with a separate
assertion requiring `retire()` itself. It is a compatibility/feature control, not
a claim that every failed old expectation was an existing API bug.

The isolated strict TypeScript check uses 5.8.3 and declaration fixtures, not the
repository-pinned 6.0.3 full package check. Full SDK/Rust/WASM, cross-browser and
repository release lanes are separate, unrun validation boundaries.

## Selection joins the retirement receipt

`firstAcceptableFetchResponse` and `quorumFetchResponses` now join `retire()` for
every non-selected member that supplies it. Native reader cancellation and the
independent retirement operation start in parallel; both, plus `closed`, must
settle before successful body ownership can transfer. A retirement failure is
observed promptly, so it can trigger the proposed winner's cleanup while another
loser is still parked. The winner's retirement method is not called on success.

The optional method is validated and snapshotted with its original receiver
before body acquisition. A malformed method refuses setup without taking reader
ownership. Replacing a handle's method afterward cannot replace the operation
selection owns. Invalid, non-void-success, thrown, or rejected retirement receipts
fail closed; arbitrary rejection causes and formatting hooks are not trusted.
An explicit non-success retirement receipt participates in the same monotone
`panicked > cancelled > err` aggregation as the existing cleanup outcomes.
Within one member, an equally severe operation receipt keeps its own cause: a
refused task publication reports the refusal, not the retirement receipt's
generic "terminal publication failed". The retirement receipt replaces it only
when stronger. Selection, race/join, batches and record streams all apply this,
and a failed retirement still fences admission as soon as it is observed.

This strengthens failure reporting, not transport tolerance. An `ok` retirement
receipt does NOT suppress an `err`, `cancelled`, or `panicked` operation receipt.
Older handles without the method retain the prior native-cancellation/`closed`
behavior. The task-ABI ambiguity above is unchanged, so a failed peer can still
fail a quorum even when other peers could satisfy the header count. There is no
new retry, replacement request, body prefetch, or automatic scope closure.

The selection integration lane is:

```sh
node --experimental-vm-modules --test scripts/test_browser_fetch_retirement.mjs scripts/test_browser_fetch_selection_retirement.mjs scripts/test_browser_fetch_selection_outcomes.mjs
```

The 20 new integration tests exercise both actual public selection entry points
with the actual fetch manager, independently gated native/retirement receipts,
malformed providers, same-member failure strengthening, legacy handles, reentrant
cancellation and native loopback HTTP. The 24 manager tests and 36 unchanged
selection-outcome regressions remain green in the same invocation (80 tests).
The core task ABI and some deliberately malformed/gated providers remain doubles.
Full SDK, pinned TypeScript, Rust/WASM and cross-browser coverage remain separate.
