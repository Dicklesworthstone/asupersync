# Backpressured fetch-batch results

`streamMapFetches` and `tryStreamMapFetches` are exported by
`@asupersync/browser/batch`. They process requests through the same explicit
scope, member lifecycle and cancellation driver as `mapFetches` and
`tryMapFetches`, but deliver completed results incrementally instead of retaining
an array of every result.

```ts
import { tryStreamMapFetches } from "@asupersync/browser/batch";

const admitted = tryStreamMapFetches(
  scope,
  requests,
  async ({ index, body, response }) => {
    if (response.status !== 200) {
      return { outcome: "err", failure: {
        code: "decode_failure", recoverability: "permanent",
        message: "unexpected HTTP status",
      } };
    }
    return { outcome: "ok", value: {
      requestIndex: index,
      text: await new Response(body).text(),
    } };
  },
  { concurrency: 4, signal: viewController.signal },
);
if (admitted.outcome !== "ok") throw new Error("streaming batch refused");
const pipeline = admitted.value;
try {
  for await (const { index, value } of pipeline.results) {
    await persist(index, value); // A slow sink backpressures request admission.
  }
} finally {
  // Also safe after successful completion; it cannot reclaim delivered values.
  await pipeline.cancel("result consumer exited");
}
const terminal = await pipeline.closed;
```

## The delivery boundary

Each result is a frozen `{ index, value }` record. `index` identifies the input
request; results are delivered in **completion order**, not input order. A slow
first request does not hold up other completed requests. The value itself keeps
its identity and is not cloned or deep-frozen. `streamMapFetches` accepts ordinary
values; `tryStreamMapFetches` checks and unwraps explicit consumer Outcomes.
Existing array-returning APIs are unchanged, including legacy Outcome-shaped
values being ordinary data to `mapFetches`.

A worker offers its result only after its consumer has returned and its body
cleanup and fetch terminal publication have settled successfully. It then holds
its admission slot until the output stream accepts that result in response to a
read. At most `concurrency` workers can wait to publish. The native stream has a
zero high-water mark. If a pending reader releases its lock, a single already
in-flight pull can still enqueue its result for the next reader. Neither that
result nor the source position is lost.

This bounds **internally pending result count**, not payload bytes or all memory.
The input array is still snapshotted, up to 100,000 requests. Consumer values can
be arbitrarily large; application retention, multiple queued read promises,
`tee`, downstream queues and browser/network buffering are outside this bound.
Each member's existing upload/response limits still apply. There is no new fetch
authority, runtime task, timer, retry or additional executor.

## Cancellation and partial success

Consume results while the pipeline is active, or cancel it. Awaiting `closed`
without reading a nonempty result stream intentionally waits on backpressure.
A consumer callback must not await its own pipeline's `closed` or result stream.
Do not return or retain the live body from a consumer; its lifecycle ends when
the consumer and cleanup finish.

Manual cancellation, parent-signal abort, output cancellation, ordinary
async-iteration exit, and `pipeTo` sink failure all fence queued admission and
release workers waiting to publish. Unread results are discarded. Every admitted
consumer and host/body cleanup still drains. Consumers parked outside body reads
must cooperate with their provided signal; nonsettling work keeps shutdown
pending. Unstarted request bodies remain caller-owned.

On producer failure, the output stream errors **after** the full drain. Its error
has the final frozen Outcome in `cause`; `closed` always resolves to that Outcome
rather than rejecting. Stronger late failures remain visible as
`Panicked > Cancelled > Err`. Already delivered values and remote side effects
are not rolled back, so a failed stream can have a successful delivered prefix.

Native `ReadableStream.cancel()` closes the stream immediately, before its
underlying cancellation finishes. That immediate EOF is not a cleanup receipt:
await the initiating `cancel()`/iterator-return/`pipeTo` promise or `pipeline.closed`.
Result-stream cancellation rejects for a final error or panic, while ordinary
cancellation succeeds; `closed` retains the full typed result in either case.
Releasing a reader lock is not cancellation. `values({ preventCancel: true })`
and `pipeTo(..., { preventCancel: true })` intentionally retain ownership; their
caller must resume reading or explicitly cancel the pipeline.

## Focused verification

Run:

```sh
node --experimental-vm-modules --test scripts/test_browser_fetch_batch_stream.mjs
```

The suite runs actual batch TypeScript with native Streams/signals and a real
loopback HTTP early-exit scenario. Scope admission, fetch-handle receipts, task
accounting and the imported request limit are explicit doubles. This is not full
SDK, Rust/WASM, cross-browser or package-pinned TypeScript validation. The source
can be overridden with `ASUPERSYNC_FETCH_BATCH_SOURCE` for negative controls.
