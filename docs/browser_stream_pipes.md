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
WebSockets, WebTransport sessions, and stream pipes are cancelled and drained before the helper
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

Cancellation aborts native piping. Successful cancellation waits for pending
writes, source cancellation, and destination abort; failed native cleanup remains
a failure. Repeated requests do not duplicate those
host effects. Invalid cancellation reasons fail without changing the operation.
A pending host promise can keep cleanup pending indefinitely; the SDK does not
declare quiescence or invent a close deadline while that work remains live.

If cancellation races a rejecting write, some native `pipeTo` implementations
reject and release their locks without invoking the source's cancellation hook.
After that failed native settlement, the owned pipe explicitly requests native
source cancellation and destination abort, and waits for both operations before
publishing its task. This cancels an otherwise-open producer and keeps its
cleanup owned. A competing endpoint lock is a cleanup refusal that retains
ownership for an explicit retirement retry. The original pipe failure remains
an error even when this additional cleanup succeeds.

Native terminal states still constrain recovery: aborting an already-errored
writable cannot replay its underlying sink's skipped `abort` callback, and a
terminal stream cannot expose an earlier cleanup promise the host stopped
awaiting. Sinks that own external resources must drain them on a rejecting write;
the owned WebSocket writable adapter does this. A native cleanup rejection is
never evidence that an inaccessible underlying callback finished successfully.

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

## Bounded byte transfers

Use `RegionHandle.pipeBytesTo(readable, writable, options)` when a transfer
requires an explicit byte budget and progress receipts. Both endpoints must be
unlocked native streams from the SDK's JavaScript realm; the source must produce
`Uint8Array` chunks. The application supplies these existing stream capabilities
and stops using both endpoints after admission succeeds.

```ts
const result = await runtime.withScopeAsync(async scope => {
  const pipe = unwrapOutcome(scope.pipeBytesTo(source, destination, {
    maxChunkBytes: 64 * 1024,
    maxBytes: 8 * 1024 * 1024,
    signal,
  }));

  const outcome = await pipe.completed;
  // Available after failure or cancellation as well as after success.
  console.log(pipe.progress()); // { bytesWritten, chunksWritten }
  return outcome;
}, { label: "bounded-byte-copy" });
const transferred = unwrapOutcome(result);
```

| Option | Default | Accepted values |
| --- | --- | --- |
| `maxChunkBytes` | 1,048,576 bytes (1 MiB) | Safe integers from 1 through 16,777,216 (16 MiB). |
| `maxBytes` | `Number.MAX_SAFE_INTEGER` | Safe integers from 0 through `Number.MAX_SAFE_INTEGER`. |
| `signal` | None | An unmodified native `AbortSignal` from the same realm, or `null`. |

The defaults are exported as `BROWSER_BYTE_PIPE_LIMITS`. Invalid options, locked
endpoints, an unavailable owner, or refused task admission produce a non-success
outcome before the adapter acquires stream locks. An already-aborted signal
returns a cancelled outcome without admitting a task.

The adapter awaits destination readiness before every source read and awaits
each write before reading again. Each accepted chunk is copied into an exact-size
owned byte array. A source subarray contributes only its own byte range, and
later mutation of the source array cannot change an in-flight write. Oversized
chunks, non-byte values, detached views, and a chunk that would exceed the total
budget are refused before that chunk reaches the destination. Oversized chunks
are rejected rather than split; earlier successful writes remain committed.
Empty chunks are permitted, including when `maxBytes` is zero. The pump yields
to a host event turn after each 64 completed writes so an always-ready source
cannot indefinitely starve timer or signal cancellation.

This bounds the adapter's one owned chunk copy and total admitted byte count.
It does not bound source allocations, preexisting source/destination queues,
transforms, or application-retained data. A producer can allocate an oversized
chunk before the adapter sees and rejects it. No network connection, network
grant, Rust I/O bridge, or Rust executor dispatch is created by this method.

| Handle member | Meaning |
| --- | --- |
| `completed` | The first transfer or retirement result; success contains `{ bytesWritten, chunksWritten }`. |
| `progress()` | A fresh frozen snapshot of fulfilled native writes, including writes completed during cancellation. |
| `cancel(reason?)` | Cancel active work and await a separate cleanup/publication receipt. |
| `retire(reason?)` | Cancel any still-active work, or retry refused task cancellation, terminal publication, or lock release. |

Progress counts native write promises that fulfilled. It does not prove remote
delivery, storage durability, or rollback of a failed transfer. Pending writes
and native destination close remain part of the cleanup barrier. Cancellation
starts source cancellation and destination abortion before awaiting either, so
one side's cleanup can depend on the other side starting. Repeated requests do
not duplicate those effects, restart copying, or rewrite the first `completed`
receipt.

The byte adapter retains the original native cleanup promises. If source
cancellation or destination abortion rejects, later retirement and owner-close
attempts continue to report failure and retain the task; calling native cleanup
again cannot establish that the original failed cleanup completed. ABI refusal
and lock-release failure can be retried explicitly. An ambiguous host lock
acquisition that throws without returning a reader/writer also remains owned.
Endpoint reservations are shared with generic `pipeTo`, so either adapter
continues to exclude the other while cleanup or task publication remains owned,
even after native locks have been released.

`scope.closeAsync()`, `runtime.closeAsync()`, and `withScopeAsync()` drain byte
transfers alongside generic pipelines and the owner's other resources. The
existing generic `pipeTo` retains its chunk-preserving API and `closed` receipt;
`pipeBytesTo` is the additive API for bounded copies and byte progress.

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

The bounded-byte suites exercise the actual manager and the SDK against the
checked-in WASM ledger:

```sh
node --unhandled-rejections=strict --experimental-vm-modules --test \
  scripts/test_browser_byte_pipe.mjs \
  scripts/test_browser_byte_pipe_wasm.mjs
```

They additionally cover exact copied views, byte budgets, immutable progress,
timer cancellation of always-ready sources, original cleanup-failure retention,
ambiguous lock acquisition, and endpoint exclusivity across both pipe adapters.
