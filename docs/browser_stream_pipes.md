# Region-owned browser stream pipelines

`RegionHandle.pipeTo(readable, writable, options)` transfers existing native
WHATWG stream endpoints into one region-owned pipeline. It uses native
`ReadableStream.pipeTo` for backpressure and error propagation, while the SDK
owns the operation through the existing WASM task ledger. A region's
`closeAsync()` waits for its pipelines and descendant pipelines before releasing
the owner.

```ts
import { unwrapOutcome } from "@asupersync/browser";

// Obtain source and destination through the application's existing authority.
// Both must be unlocked native streams from the SDK's JavaScript realm.
const scope = unwrapOutcome(runtime.enterScope("copy-stream"));
const pipe = unwrapOutcome(scope.pipeTo(source, destination));

try {
  const outcome = await pipe.closed;
  unwrapOutcome(outcome);
} finally {
  // Cancels any remaining owned work and waits for actual host cleanup.
  unwrapOutcome(await scope.closeAsync());
}
```

## Automatic asynchronous scopes

`BrowserRuntime.withScopeAsync()` creates a child scope, runs its callback,
and awaits asynchronous owner cleanup before returning. A region has the same
method for nested child scopes. This makes the cleanup barrier part of the
application's normal control flow:

```ts
const result = await runtime.withScopeAsync(async scope => {
  const pipe = unwrapOutcome(scope.pipeTo(source, destination, { signal }));
  return await pipe.closed;
}, { label: "copy-stream" });
unwrapOutcome(result);
```

When the callback finishes early, its still-active fetches, message receivers,
WebSockets, and stream pipes are cancelled and drained before the helper
settles. A pending native write or asynchronous abort keeps the helper pending.
Use `scope.withScopeAsync()` for independently bracketed nested work. If the
callback or an ancestor already completed SDK closure of the child, the helper
recognizes that successful cleanup instead of closing the invalidated handle
again. An invalid-handle error alone is never treated as proof of cleanup.
The helper does not close the runtime or unrelated sibling scopes.

After successful cleanup, the helper returns the exact callback `Outcome`
object, including `err`, `cancelled`, or `panicked` outcomes. A thrown value or
promise rejection is rethrown unchanged, including rejection with `undefined`.
Cleanup uses a private owner snapshot and frozen ABI version, so mutating the
callback's scope fields cannot redirect its cleanup to a different region.

If cleanup is refused, the helper rejects with `BrowserScopeCleanupError`:

| Property | Meaning |
| --- | --- |
| `code` | `ASUPERSYNC_BROWSER_SCOPE_CLEANUP_FAILED` |
| `cleanupOutcome` | The exact non-success cleanup receipt. |
| `bodyCompletion` | `{ kind: "returned", outcome }` or `{ kind: "threw", error }`, preserving the original callback completion. |
| `scope` | An independent handle to the child for an explicit `closeAsync()` retry. |

The three detailed properties are readonly and non-enumerable. Ordinary error
serialization does not expose the scope's authority token or callback payload.
The helper makes one cleanup attempt; it does not silently retry a refusal or
replace a failed cleanup with the callback's successful result.

```ts
import { BrowserScopeCleanupError } from "@asupersync/browser";

try {
  await runtime.withScopeAsync(runApplicationWork);
} catch (error) {
  if (error instanceof BrowserScopeCleanupError) {
    // Inspect both failures, repair the reported condition, then retry explicitly.
    const retry = await error.scope.closeAsync();
    unwrapOutcome(retry);
    // A successful retry does not erase the original body/cleanup result.
  }
  throw error;
}
```

## Ownership and data flow

Admission reserves one ABI task before invoking host piping. The native call
acquires both stream locks before the successful handle is returned. The
caller then stops reading, writing, closing, or aborting those endpoints. A
locked endpoint, an unavailable owner, invalid options, or a refused task
admission leaves both endpoints with the caller. An already-aborted supplied
signal returns a cancelled outcome without admitting a task or touching the
streams.

Chunks keep their native identity and ordering: byte arrays, strings, and other
values are not converted or copied. Native destination backpressure controls
source consumption. The adapter does not add read-ahead, a byte limit, or a
whole-process memory bound. Source queues, destination queues, transforms,
`tee()` queues, and the application's retained values remain outside its
ownership and memory claims. Data already written is never rolled back.

On source EOF, native piping closes the destination and waits for its close
promise. A source error aborts the destination; a destination error cancels the
source. The pipe's terminal outcome is published only after the native pipe
promise settles and its locks are released. Source/sink failures are reported
with a stable diagnostic instead of evaluating arbitrary host error formatting.

## Cancellation and retirement

The handle has three lifecycle operations:

| Operation | Meaning |
| --- | --- |
| `closed` | The first operation/publication outcome after native settlement. |
| `cancel(reason?)` | Request cancellation and await native cleanup plus task publication. |
| `retire(reason?)` | Await a separate cleanup receipt; explicitly retry refused task cancellation or terminal publication. |

Cancellation aborts native piping and waits for pending writes, source
cancellation, and destination abort. Repeated requests do not duplicate those
host effects. Invalid cancellation reasons fail without changing the operation.
A pending host promise can keep cleanup pending indefinitely; the SDK does not
declare quiescence or invent a close deadline while that work remains live.

An optional `signal` is a borrowed native `AbortSignal`. The SDK observes a
private dependent signal, so an earlier caller listener cannot suppress the
notification. Cancelling the pipe never aborts the caller's signal. The SDK
removes its own listener after native settlement.

ABI cancellation or terminal-publication refusal leaves the task and the SDK's
endpoint reservation owned. `retire()` or a later `closeAsync()` retries the
refused step. The first `closed` outcome is immutable; a successful retry does
not rewrite the historical refusal. As with adjacent SDK adapters, an identical
non-success ABI echo cannot independently prove ledger retirement: the actual
owner-close barrier remains authoritative.

A rejecting native cancel/abort callback is surfaced as a failure of the
in-flight retirement attempt. If the pipe nevertheless reaches native
settlement, releases its locks, and publishes its terminal task successfully,
a subsequent owner close can finish. This does not turn the earlier cleanup
failure into successful cancellation.

## Scope and runtime shutdown

`scope.closeAsync()` fences new descendant admission, requests cancellation of
all owned resources, and joins their retirement before invoking the ABI owner
barrier. Nested scopes participate; unrelated sibling scopes remain live.
`runtime.closeAsync()` applies the same behavior across its root scopes.

The existing synchronous `close()` and `withScope()` APIs retain their existing
behavior. Use `withScopeAsync()` or explicit asynchronous owner closure for host
resources that require draining. Existing standalone `BrowserReadableStream` and
`BrowserWritableStream` byte helpers also retain their contracts.

Passing endpoints transfers existing host capabilities; this API opens no
network connection and grants no new network or storage authority. It does not
expose the Rust `AsyncRead`/`AsyncWrite` browser-core bridge or claim Rust
executor dispatch.

## Behavioral validation

```sh
node --unhandled-rejections=strict --experimental-vm-modules --test \
  scripts/test_browser_stream_pipe.mjs \
  scripts/test_browser_message_regions_wasm.mjs \
  scripts/test_browser_scope_async.mjs
```

The first suite executes the actual TypeScript manager with native Node
WHATWG streams and explicit fault-injection task adapters. The other suites
execute the actual SDK with the checked-in generated JavaScript/WASM handle ledger;
scope-refusal cases replace only the explicit ABI refusal under test.
They cover pending-write witnesses, asynchronous cancel/abort/close barriers,
task counts, nested ownership, signal handling, refusal and retry, endpoint
exclusivity, and reentrant admission/publication. These are native Node and
checked-in WASM receipts, not a Rust rebuild or browser-engine execution.
