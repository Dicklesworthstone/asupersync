# Bounded, scope-owned fetch batches

`mapFetches` is exported from `@asupersync/browser/batch`. Unlike the
header race/join helpers, it **admits** requests through a supplied SDK Scope.
It never calls ambient `fetch` or creates another runtime task.

```ts
import { mapFetches } from "@asupersync/browser/batch";

// scope was created with explicit fetchAuthority for these URLs/methods.
const admitted = mapFetches(
  scope,
  urls.map(url => ({ url })),
  async ({ body, response, signal }) => {
    if (response.status !== 200) throw new Error("unexpected response");
    // The body is exclusive, backpressured, and cancelled on batch shutdown.
    // Pass signal to other cooperative work this consumer awaits.
    signal.throwIfAborted();
    return new Response(body).json();
  },
  { concurrency: 4 },
);
if (admitted.outcome !== "ok") throw new Error("batch setup refused");
const batch = admitted.value;
const result = await batch.result;
// A UI teardown handler can instead await batch.cancel("view closed").
```

## Parent cancellation and caller-owned deadlines

Pass `signal` alongside `concurrency` to connect a batch to a view, operation,
or service's cancellation boundary. For example, replace the options above with:

```ts
{
  concurrency: 4,
  signal: AbortSignal.any([viewController.signal, AbortSignal.timeout(5_000)]),
}
```

The signal stops queued admission synchronously, notifies active consumers,
cancels owned bodies, and waits for all admitted consumers and cleanup before
settling `batch.result`. A pre-aborted signal starts no requests. Empty input
still succeeds with a valid pre-aborted signal. `null` is equivalent to omission.
This is cooperative cancellation, not forced termination of consumer code.

Signals must be unmodified same-realm native `AbortSignal` objects; signal use
requires native `AbortSignal.any` and `EventTarget`. A private dependent signal
prevents an earlier caller listener using `stopImmediatePropagation()` from
suppressing cancellation. Arbitrary abort reasons are not inspected or copied
into diagnostics: the cancellation message is `fetch batch cancelled by signal`.
The first same-severity stop reason wins, including races with `batch.cancel()`.
The observer is detached at settlement; later aborts cannot reclaim delivered
values. Manual cancellation never aborts the supplied signal. Calls without a
signal keep their existing host requirements. The batch itself creates no timer;
the timeout in the example is explicitly owned by the caller.

## The slot is a lifecycle, not a header count

There are at most `concurrency` active members (default 4, range 1..64).
A member owns its slot through scope admission, header arrival, the entire
consumer promise, body cleanup, and fetch task terminal publication. Only
then can the next queued request start. This lets a batch larger than the
runtime's 64-request cap progress without admitting all requests at once.
Existing unrelated work still shares that runtime cap; a scope admission
refusal stops this batch rather than spinning, retrying, or cancelling other
work to make room.

Success returns a frozen array in **input order**, not completion order.
Result payloads use ordinary JavaScript identity and are not deep-frozen.
Each consumer receives its index, response metadata, an exclusive native
`ReadableStream<Uint8Array>`, and a private batch-controlled `AbortSignal`.
Native Response parsing, decoding transforms and `pipeTo` work on that body.
Returning from the consumer before EOF cancels unread bytes and waits for
cleanup. Do not retain the body or launch detached work from the consumer.
HTTP error statuses are ordinary responses; the consumer decides which to
reject. A consumer throw/rejection becomes a `panicked` batch Outcome, without
copying the thrown payload into diagnostics.

The first observed admission, transport, or consumer failure fences queued
admission and starts active cancellations in parallel. Idle response-body
errors are observed even when the consumer is not reading. Batch cancellation
is idempotent and also fences admission synchronously. It never aborts a
caller-supplied request signal. Cancellation before the first scheduling
microtask makes zero requests. An empty batch is an immediate success identity.
After terminal completion, cancel is inert and returns the settled outcome.

The batch does not abandon consumer promises: consumers doing work outside
body reads must observe their supplied signal, and must not await their own
batch result/cancel barrier. Shutdown waits for every admitted consumer and
fetch cleanup. A host or consumer that never settles keeps shutdown pending;
this is not forced termination or a bounded wall-clock guarantee. Cancellation
cannot undo transmitted POSTs or other side effects.

Task cancellation/publication refusals are failures, not successes. Throughout
drain, stronger failures replace weaker ones: `panicked > cancelled > err`.
Expected member cancellation is cleanup, not a new owner failure. Rethrowing a
batch-owned body/signal error preserves its Outcome; genuine consumer exceptions
remain panics. Same-severity cleanup ties use input order. This composite
Outcome does not rewrite the existing fetch tasks' own terminal outcomes.

The scope's `fetch` must return its admission Outcome synchronously, as the
SDK Scope does. A promise, such as an `async` adapter's, is refused and fails
the batch; whatever that promise later admits is still cancelled and joined
before `result` settles. A malformed Outcome from the scope or from a fetch
handle (response, stream conversion, cancellation receipt or terminal
publication) fails closed as `internal_failure`. `result` and `cancel()` never
reject.

## Resource and ownership boundaries

The array is bounded to 100,000 requests and is snapshotted during setup.
Request option objects and body objects are **not** cloned or consumed then:
the SDK validates them at their individual admission boundary. Do not mutate
queued options. Unstarted upload bodies stay with the caller; stopping a batch
does not acquire or cancel those sources.

The adapter pulls only on consumer demand and adds no body read-ahead. The
underlying fetch's per-chunk, upload and response limits still apply. The
request array and result array take O(request count) slots; user payload size,
consumer-side buffering, browser/network buffers, and downstream/tee queues
are not covered by the batch's concurrency limit. No retries or deadline timer
are added. Per-request `timeoutMs` starts when that request is admitted, not
when the batch was created.

## Validation

Run `node --experimental-vm-modules --test scripts/test_browser_fetch_batch.mjs`
on Node 22.13+ (TypeScript stripping). The harness uses the actual fetch manager
and batch implementation, native streams, and loopback HTTP; task ABI calls
are explicitly doubled. Native browser checks and strict TypeScript are also
recorded in the session's verification bundle. These are not Rust/WASM or
full-workspace integration receipts.

The parent-signal lane is
`node --experimental-vm-modules --test scripts/test_browser_fetch_batch_signal.mjs`.
It executes the actual batch TypeScript, native Streams/signals, and real
loopback HTTP cancellation, with explicit scope/handle/terminal and request-limit
doubles. It does not execute the SDK task ABI or certify browser/WASM integration.
Set `ASUPERSYNC_FETCH_BATCH_SOURCE` to a pre-feature source file for negative
controls. TypeScript stripping is not a strict typecheck; run the package's
existing typecheck and full SDK suite separately.
