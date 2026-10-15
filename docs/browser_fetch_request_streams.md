# Incremental request input for fetch batches

`streamMapFetches` and `tryStreamMapFetches`, exported from
`@asupersync/browser/batch`, accept either the existing request array or a native
`ReadableStream<BrowserFetchOptions>`. Stream input does not need its total length
in advance, and the adapter does not collect it into an array.

```ts
import { streamMapFetches } from "@asupersync/browser/batch";

// Explicit, authorized scope and caller-created request producer.
// requests: ReadableStream<BrowserFetchOptions>
const admitted = streamMapFetches(
  scope,
  requests,
  async ({ body, signal }) => {
    signal.throwIfAborted();
    return new Response(body).text();
  },
  { concurrency: 4, maxRequests: 1_000_000, signal: shutdownSignal },
);
if (admitted.outcome !== "ok") throw new Error("batch setup refused");
const batch = admitted.value;
try {
  for await (const { index, value } of batch.results) {
    await persistResult(index, value);
  }
} finally {
  await batch.cancel("request pipeline finished");
}
const terminal = await batch.closed;
```

Use `tryStreamMapFetches` when the consumer returns a checked `Outcome<T>` rather
than an ordinary value. The existing collection APIs `mapFetches` and
`tryMapFetches` still require arrays. No additional authority, runtime task,
timer, retry, or network client is introduced: every request goes through the
supplied scope's existing synchronous admission API.

## Backpressure includes request production

A worker reserves its slot before requesting an input. There is at most one
pending native input read at a time, no separate descriptor queue in the
adapter, and at most `concurrency` worker-owned requests/results. Each worker
keeps its slot through scope admission, consumer completion, body cleanup,
terminal publication, and output acceptance. With a zero-high-water-mark input
producer, withholding output demand therefore also stops source pulls once all
slots are occupied.

`index` is zero-based input order; delivery remains completion order. Successful
native input closure does not discard its queued descriptors or pending output.
An idle source error stops the pipeline even when every worker is waiting to
publish a result. An input error is sanitized to `internal_failure`; arbitrary
exception causes, messages, and presentation hooks are not trusted.

`maxRequests` applies only to stream input. It defaults to 100,000 and accepts a
positive safe integer, including a larger explicitly chosen bound. Exact-limit
EOF succeeds. One further descriptor is read to distinguish excess input from
EOF, but is never admitted; the batch fails and cancels the source. Array input
retains its existing fixed 100,000-entry cap and snapshot behavior.

The bound is on adapter-retained work, not bytes. A source's own queue, native
network buffers, user payload size, producer lookahead, and downstream/tee
queues remain outside it. Read results while waiting for `closed`: waiting only
for `closed` on a nonempty backpressured pipeline can intentionally stall it.

## Ownership and cancellation

Successful setup acquires the native input reader exclusively. Invalid options,
missing host support, a non-native source, or an already-locked source are
refused without reading or cancelling input. A later setup refusal releases any
acquired lock. Input methods are native captured intrinsics, not source-object
overrides. Do not use another reader while the batch owns input.

Manual cancellation, a parent abort, output iteration exit, or pipeline failure
fences admission first. It cancels the input alongside active fetches, releases
output publication waits, and joins the initiating input-cancellation promise
as well as all consumers and fetch cleanup before publishing `closed`. The
input lock is released at final settlement. Repeated cancellation is idempotent.
A pre-aborted parent cancels input without a source read: unlike an empty array,
an input stream is not probed merely to discover whether it would be empty.

Native cancellation is not a producer-task join. It does not prove that arbitrary
producer code has stopped, that a hidden pending `pull` computation has settled,
or that external producer resources are closed. That producer must expose and
honor its own ownership/cleanup contract. The producer/caller remains responsible
for queued and unadmitted upload bodies, including an item arriving concurrently
with cancellation or the over-limit descriptor. The batch does not inspect or
acquire those bodies before scope admission. Already-admitted remote effects
and already-delivered output cannot be rolled back.

Source cancellation rejection is a cleanup failure. Existing severity ordering
is preserved (`panicked > cancelled > err`); member cleanup ties use input order,
with input-source cleanup ordered after member indices. See also
`browser_fetch_batch_streams.md` for output lock-release and cancellation details.

## Execution evidence

Run:

```sh
node --experimental-vm-modules --test scripts/test_browser_fetch_batch_input.mjs scripts/test_browser_fetch_batch_stream.mjs
```

The request-input tests execute actual batch TypeScript and native Streams. They
exercise gated production, cancellation and cleanup, input/output backpressure,
limits, malformed sources, and a real loopback HTTP request-descriptor stream
whose cancellation disconnects both the input connection and an active fetched
peer. Scope/fetch-handle/task accounting and imported limits are explicit doubles;
this is not full SDK, Rust/WASM or cross-browser certification. Set
`ASUPERSYNC_FETCH_BATCH_SOURCE` to the pre-feature source for a negative control.

## Joining an explicitly owned producer

A raw native stream has no independent producer-completion receipt. For a
multi-stage producer whose owned work outlives native EOF or cancellation, pass a
`FetchBatchRequestSource` instead:

```ts
const requestSource = {
  readable: requestDescriptors, // ReadableStream<BrowserFetchOptions>
  closed: producer.closed,     // Promise<Outcome<void>> for ALL producer work
  cancel: reason => producer.cancel(reason), // works while readable is locked
};
const admitted = streamMapFetches(scope, requestSource, consume, { concurrency: 4 });
```

Successful setup transfers exclusive reader ownership and responsibility for
joining that source's `closed` receipt. Invalid/locked source refusal leaves
cleanup with its caller. The source's readable, cancellation method and terminal
promise are snapshotted before lock acquisition. Cancellation retains its
original receiver; mutating source properties afterward does not replace the
owned operation. A raw native stream's similarly named custom properties are
not treated as a producer contract.

Native EOF is not enough to settle the batch: it also waits for the producer's
checked `closed` receipt. A successful producer receipt does not discard
unconsumed native input. An idle producer failure immediately fences admission
and retires active work, even if no request read is pending. Producer failure
can still replace proposed success after native EOF; it cannot roll back
already-delivered values or remote effects.

On stop, the batch starts native-reader cancellation and the independent owner
`cancel` method in parallel, and joins BOTH receipts plus producer `closed` and
all admitted fetch work. The owner method must be idempotent, work while its
readable is locked, and not await this downstream batch's own `closed`/`cancel`
barrier. Native stream cancellation may already call the same underlying owner;
source implementations must tolerate that. The batch cannot enforce truth of a
producer's completion claim or force a nonsettling producer to retire.

Typed producer terminal/cancellation Outcomes are validated and copied. A stream
error's arbitrary `cause` is never accepted as a producer receipt. Genuine
producer errors and panics participate in `panicked > cancelled > err`; expected
producer cancellation during downstream retirement does not hide a consumer's
application error. A source fault observed before retirement can be resolved to
the producer's authoritative cancellation instead of a generic input error.
Malformed or rejected receipts are `internal_failure`, not successful retirement.

The additional lane is:

```sh
node --experimental-vm-modules --test scripts/test_browser_fetch_batch_source_owner.mjs
```

It includes independently gated native cancellation, owner cancellation and
producer completion, typed failure propagation, callback snapshot/reentrancy
checks, and two actual batch-driver stages connected through a native transform.
The two-stage cases execute the upstream batch's real `closed`/`cancel` logic;
the underlying scope/fetch/task adapters remain explicit doubles.
