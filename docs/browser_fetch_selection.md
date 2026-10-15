# Selecting acceptable owned fetch responses

`@asupersync/browser/selection` adds `firstAcceptableFetchResponse` and
`quorumFetchResponses` for fetch handles that their original scopes have already
admitted. Unlike a raw header race, a fast HTTP 503 need not beat a later HTTP 200.
Unlike `Promise.any`, these operations do not leave losing bodies owned but undrained.

```ts
import { quorumFetchResponses } from "@asupersync/browser/selection";

// handles: distinct FetchStreamHandle values from explicitly authorized scopes.
const admitted = quorumFetchResponses(handles, 2, {
  accept: (response) => response.status >= 200 && response.status < 300,
});
if (admitted.outcome !== "ok") {
  // Setup did not cancel the inputs. Their original caller must clean them up.
  // A body converted before refusal remains accessible through toReadableStream().
  throw new Error(admitted.outcome === "err" ? admitted.failure.message : "selection setup refused");
}
const selected = await admitted.value.result;
// Non-ok results arrive only after owned cleanup. Handle all four Outcome forms.
if (selected.outcome === "ok") {
  // Exactly two entries, sorted by original input index, not response order.
  // Each entry has { index, response, fetch, body }. No body bytes were read.
  // Consume or cancel EVERY returned body, then await each entry.fetch.closed.
}
```

Selection admits no new request, task, timer, retry, or network authority. HTTP 2xx
is the default acceptance policy. Custom predicates are synchronous and receive
bounded, frozen metadata snapshots. A promise or other non-boolean return is an
error. Rejected headers are cancelled promptly; when too few candidates remain,
all remaining work is retired without waiting for more headers. Up to 64 inputs
are supported; `required` must be an integer from one through the input count.

The first acceptable observations establish the selection. Bodies are returned
in input order after **every non-selected fetch settles cleanup**. Slow cleanup
keeps the result pending. Caller cancellation, an accepted body's failure during
cleanup, and cleanup/publication refusals retire the proposed winners too. Native
scope cancellation remains effective even when all headers are parked. Cleanup
panics take precedence over ordinary errors; equal-severity cleanup failures use
input order. `cancel()` is idempotent and becomes inert after successful transfer.

This is a **header quorum**, not replica agreement, response-body verification,
automatic retry, or network-error-tolerant failover. Non-ok transport/task receipts
fail the whole selection. The public fetch contract does not distinguish transport
failure from cleanup/publication failure; guessing would hide ownership failures.
Cancellation cannot undo already-transmitted effects. A host that never settles
cannot be forcibly drained, so the cleanup barrier remains pending honestly.

## Executed coverage

`node --experimental-vm-modules --test scripts/test_browser_fetch_selection.mjs`
executes the actual TypeScript selection source with native WHATWG Streams. Fetch
handles and terminal receipts are explicit doubles. One test uses native fetch
against a real loopback HTTP server and witnesses disposal of a rejected 503
response before consuming the selected 200 body. This is not task-ABI, Rust/WASM,
or full-package integration evidence. The runner prints the tested source hash.

Targeted negative controls that omit the loser-drain barrier or fail to cancel a
proposed winner are rejected by the corresponding slow-cleanup tests.

## Cancelling a selection through an AbortSignal

Both entry points accept an optional borrowed native signal:

```ts
const controller = new AbortController();
const admitted = quorumFetchResponses(handles, 2, { signal: controller.signal });
// Later, while headers or loser cleanup are pending:
controller.abort();
// When admitted.outcome === "ok", await admitted.value.result for the drain barrier.
```

A pre-aborted signal drains the acquired inputs without invoking their response
methods or the acceptance predicate. Refused setup still leaves cleanup with the
original caller. Aborting during loser cleanup retires the proposed winners too;
neither result nor cancel reports completion before owned cleanup settles.

A supplied signal must be an unmodified same-realm native AbortSignal, with native
AbortSignal.any support. Subclasses, foreign-realm signals and overridden
aborted/reason accessors are outside the supported boundary. A private dependent
signal prevents a caller's earlier stopImmediatePropagation listener from hiding
an abort. The adapter does not invoke an overridden addEventListener method or
format an arbitrary abort reason; it reports a fixed typed cancellation message.

The group never aborts the supplied signal. Its listener is detached at settlement,
and aborts after successful transfer do not reclaim caller-owned winners. Null
is equivalent to omission; hosts lacking AbortSignal.any can still use selection
without a signal. Selection creates no timer: a deadline may be supplied explicitly
by the caller through a timeout signal. A timeout requests cancellation but cannot
force a nonsettling host to finish cleanup.
