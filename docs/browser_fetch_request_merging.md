# Bounded, owned request-source merging

`mergeFetchRequestSources`, exported from `@asupersync/browser/pipeline`,
combines up to 64 native request streams or explicitly owned request producers.
It returns a `FetchBatchRequestSource` that can be passed directly to the
streaming batch APIs. It does not admit a fetch, gain authority, or create a
runtime task, pipe pump, retry loop or timer.

```ts
import { mapFetchRequests, mergeFetchRequestSources } from "@asupersync/browser/pipeline";
import { streamMapFetches } from "@asupersync/browser/batch";

// feedA/feedB are already-authorized record owners, e.g. JSON-lines decoders.
const a = mapFetchRequests(feedA, record => requestForRecord(record));
const b = mapFetchRequests(feedB, record => requestForRecord(record));
if (a.outcome !== "ok" || b.outcome !== "ok") {
  // A partially successful setup still owns its successfully acquired inputs.
  await Promise.all([
    a.outcome === "ok" ? a.value.cancel() : undefined,
    b.outcome === "ok" ? b.value.cancel() : undefined,
  ]);
  throw new Error("mapping setup refused");
}
const merged = mergeFetchRequestSources([a.value, b.value]);
if (merged.outcome !== "ok") {
  await Promise.all([a.value.cancel(), b.value.cancel()]);
  throw new Error("merge setup refused");
}
const admitted = streamMapFetches(scope, merged.value,
  async ({ body }) => new Response(body).text(), { concurrency: 4 });
if (admitted.outcome !== "ok") {
  await merged.value.cancel();
  throw new Error("batch setup refused");
}
try {
  for await (const { index, value } of admitted.value.results) {
    await persistResult(index, value);
  }
} finally {
  await admitted.value.cancel();
}
const terminal = await admitted.value.closed;
```

The batch's `index` is arrival order from the merge, not an index into the
source array. Preserve any application identity in the descriptor or other
caller-managed metadata. Cross-source timing does not define a stable ordering.

## Backpressure and ordering

Setup acquires input locks but reads no descriptors. The first output pull
starts one read per source. A source keeps its credit through its outstanding
read or unread result. No source has more than one such item, and an emitted
source is not refilled without another output pull. Ready peers are queued in
observation order; a newly ready source cannot bypass peers already waiting.
Each source's own order is preserved, and a parked first source cannot block a
ready second source. This is readiness-driven fan-in, not input concatenation
or ordered cross-source joining.

A zero-high-water-mark output adds no adapter backlog beyond those credits.
Native reader lock release is not cancellation: one already pending output pull
can accept a descriptor into the native output queue after its reader detaches.
That descriptor remains available to a replacement reader. Source queues,
mapper windows, network buffers, arbitrary payload size and downstream/tee
queues are separate. Composing bounded stages does not make their bounds one
shared global quota. An empty merge succeeds without waiting for output demand.

## Ownership and complete shutdown

The source list is snapshotted using indexed access, not its custom iterator.
Raw native streams use captured native reader operations; arbitrary owner-like
properties on those streams are ignored. Explicit owners have their readable,
cancel method and checked completion promise captured before locks are acquired.
The cancel method retains its original receiver. Duplicate sources, aliased
readables, missing receipts, locked inputs and over-limit arrays are refused.
If acquiring a later lock fails, earlier acquired locks are released without
reading or cancelling their sources. Refused setup cannot later react to a
source error by cancelling work whose ownership was returned.

Success requires every source's native EOF, delivery of queued descriptors and
all explicit producer completion receipts. Successful producer completion does
not discard unread source data. Failures are observed even without output
read demand. Any failure or cancellation stops reads/output and discards queued
references. Native cancellation and owner cancellation start independently for
every source; shutdown joins them, outstanding native read promises, and every
producer completion receipt. Ordinary iteration exit and `pipeTo` destination
failure use the same drain. Native output closure during cancellation is NOT
that drain: await the initiating cancellation promise or `closed`.

Outcomes strengthen as `Panicked > Cancelled > Err`. Expected retirement
cancellation does not erase an originating application error. For a failed
native read, the checked source receipt can replace its provisional internal
error; arbitrary exception `.cause` or presentation hooks are never consulted.
A stronger cleanup failure wins; equal-severity cleanup ties use source input
order, with a same-source terminal receipt preferred over an ordinary native
cancellation refusal. Errors are frozen snapshots, not mutable provider objects.

Cancellation does not acquire or cancel unadmitted upload bodies. Those bodies
and discarded source items remain their producer/caller's responsibility.
Already delivered descriptors or network effects are not rollback. A raw native
stream does not prove hidden producer work has stopped; an explicitly owned
producer must make its own `closed` truthful, cancellation idempotent and usable
while locked. Its cleanup must never wait for this merge's own completion.
Nonsettling producers can keep shutdown pending; there is no forced termination
or elapsed-time bound.

## Validation boundary

The implementation was exercised with actual merge and mapping code, native
Streams, and loopback HTTP with server-observed disconnection of two feeds.
Producer receipts and HTTP adapters were explicit doubles except cases composing
actual mapping owners. The supplemental merge tests and failure-control logs
are in the implementation session's delivery bundle; the test-file upload was
blocked, so those new tests are not yet committed or part of repository CI.
The existing mapping/flat-map/parallel/signal suites remain unchanged.

These results are not full SDK task-ABI, batch-driver, Rust/WASM, cross-browser
or release evidence. Run the repository's package typecheck and integration
lanes separately; the isolated source typecheck used declaration fixtures.
