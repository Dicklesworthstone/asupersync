# Bounded parallel request mapping

All four `@asupersync/browser/pipeline` mapping functions accept an optional
`concurrency` setting: `mapFetchRequests`, `tryMapFetchRequests`,
`flatMapFetchRequests`, and `tryFlatMapFetchRequests`. It defaults to **1**,
preserving the existing serial, demand-driven behavior. Choose an integer in
**1..64** to overlap asynchronous mapping work without an unbounded reorder queue.

```ts
import { tryMapFetchRequests } from "@asupersync/browser/pipeline";
import { tryStreamMapFetches } from "@asupersync/browser/batch";

// records is a native stream or an explicitly owned record producer.
// authorizeRecord is caller-owned async work that observes its supplied signal
// and returns an Outcome<BrowserFetchOptions | null>.
const mapped = tryMapFetchRequests(records, authorizeRecord, {
  concurrency: 4,
  maxInputs: 100_000,
});
if (mapped.outcome !== "ok") throw new Error("mapping setup refused");
const admitted = tryStreamMapFetches(scope, mapped.value, consumeResponse, {
  concurrency: 8,
  signal: shutdownSignal,
});
if (admitted.outcome !== "ok") {
  await mapped.value.cancel("downstream setup refused");
  throw new Error("fetch setup refused");
}
const batch = admitted.value;
try {
  for await (const { index, value } of batch.results) {
    await persistResult(index, value);
  }
} finally {
  await batch.cancel("pipeline finished");
}
const terminal = await batch.closed;
```

The mapping and fetch stages have separate concurrency limits. Mapping creates
no network authority, runtime task, dependency or timer. Each downstream request
still passes through the supplied scope's admission policy. Mapper-side effects
remain the caller's responsibility; parallel execution does not roll them back.

## One credit follows a complete input record

A mapping slot is reserved **before** reading the input. It remains occupied
while the mapper is running and while its resulting request descriptors await
output demand. The window includes pending input, active mappers and completed
but unread results. There is only one native input read in flight, even when
many mappers are active. Before the first output pull, no input is read.

Output order is input order, independent of mapper completion order. Flat-map
siblings retain their array order. A slow early mapper can delay later output,
but cannot permit more than `concurrency` slots to accumulate. A pending read of
a later input does not block delivery of an already-ready earlier result.

A flat-map expansion holds its slot until its last descriptor is accepted.
`maxRequestsPerInput` still defaults to 64 and is limited to 1,024; every expansion
is validated and snapshotted before any member is emitted. At most
`concurrency * maxRequestsPerInput` descriptor references are retained in mapping
slots. Native in-flight output pulls, producer/downstream queues, payload bytes,
mapper allocations and arbitrary work hidden inside callbacks are outside this
bound. Releasing an output-reader lock is not cancellation; one already-started
native pull may still accept a descriptor.

No new input is pulled without outstanding output demand. Reads already reserved
for that demand can settle later and run their mapper. Completed empty expansions
or filtered records retain their ordered slot until earlier records are consumed.
A mapper returns `null` (or an empty expansion) to filter an input; filtered
records still count toward `maxInputs` and retain their physical mapper index.
An excess input is read to distinguish it from exact-limit EOF but is never
passed to the mapper. In parallel mode this refusal can occur while earlier
admitted mappers are still running; they are joined, not abandoned.

## Shutdown is a join, not a stream-close notification

The first failure fences new input/mapping and output, clears unread descriptor
references, and signals every admitted mapper. Failure is observed when it
occurs, even at a later index whose output is waiting behind another mapper.
Native input cancellation and explicit producer cancellation start in parallel.
Final publication joins every admitted mapper, the native read, both cancellation
operations and the source owner's independent `closed` receipt. Native EOF alone
is not producer retirement.

Late failures can strengthen shutdown as `panicked > cancelled > err`. The first
equal-severity cause is retained, except for the existing replacement of a
provisional native input error by its checked producer failure. Real exceptions
remain sanitized panics; rethrowing this mapping stage's own signal error retains
its typed cancellation. Already-delivered descriptors and remote effects are
not rolled back. Unadmitted body resources remain with the producer/mapper.

Concurrency is opt-in. Mappers that depend on sequential side effects must keep
`concurrency: 1`. Every mapper must observe its signal where needed and must not
await this stage's own `closed` or cancellation barrier. An uncooperative mapper
or producer can keep shutdown pending; no wall-clock termination bound is added.

## Validation

```sh
node --experimental-vm-modules --test scripts/test_browser_fetch_request_map.mjs scripts/test_browser_fetch_request_parallel.mjs
```

The new suite executes the actual TypeScript with native Streams and includes
real loopback HTTP mappers whose responses remain gated until multiple requests
arrive. Producer receipts in focused fixtures are explicit doubles; the two-stage
test uses another actual mapping owner. These tests do not certify the full SDK
task ABI, Rust/WASM, cross-browser behavior, performance or payload-byte bounds.
`ASUPERSYNC_REQUEST_MAP_SOURCE` selects an exact pre-feature source for controls.
TypeScript stripping is not a typecheck; the package's pinned typecheck is a
separate validation requirement.

## Parent cancellation and caller-owned deadlines

Every mapping function also accepts `signal?: AbortSignal | null`, independent
of whether a downstream fetch batch has been attached. The same parent can be
supplied to multiple stages:

```ts
const mapped = tryFlatMapFetchRequests(records, expandAuthorizedRecord, {
  concurrency: 4,
  maxRequestsPerInput: 16,
  signal: AbortSignal.any([shutdownSignal, AbortSignal.timeout(5_000)]),
});
```

The deadline signal above is explicitly caller-created; mapping creates no timer.
A parent abort stops new input reads, mapper invocations and descriptor output,
signals every admitted mapper, and joins their settlement and all producer
cleanup. It works without output demand, with a parked native input read, and
while waiting for the producer after native EOF. A valid pre-aborted parent
still transfers ownership on successful setup and cancels that source without
reading it. Invalid configuration or locked-source refusal leaves input with
the caller, even if the parent is already aborted.

Use an unmodified same-realm native `AbortSignal`. Signal use requires native
`AbortSignal.any` and `EventTarget`; calls without a signal retain their existing
host requirements. A private dependent signal prevents earlier parent listeners
using `stopImmediatePropagation()` from suppressing cancellation. Customized
`aborted`/`reason` accessors are refused before native composition. Arbitrary
abort reasons are not inspected or printed: the stable cancellation message is
`request mapping cancelled by signal`.

Manual cancellation never aborts the parent. Its observer is removed at final
settlement, so a later parent abort cannot reclaim delivered descriptors or
restart cleanup. During drain, a late panic can still strengthen cancellation;
equal-severity manual/parent stops retain the first cause. A mapper that catches
a host's abort exception can call its supplied `signal.throwIfAborted()` to
propagate this mapping stage's typed cancellation rather than a new panic.

The signal lane is:

```sh
node --experimental-vm-modules --test scripts/test_browser_fetch_request_map_signal.mjs
```

It includes real parallel native-fetch requests, body-read suspension, parent
abort, mapper settlement and server-observed disconnections. The full focused
regression run includes that lane, the parallel lane, and the two existing
mapping/flat-map suites. It remains scoped evidence, not full SDK, task-ABI,
Rust/WASM or cross-browser certification.
