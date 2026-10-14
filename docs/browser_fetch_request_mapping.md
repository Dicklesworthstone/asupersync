# Owned transformation of records into fetch requests

`@asupersync/browser/pipeline` exports `mapFetchRequests` and
`tryMapFetchRequests`. They turn an incrementally produced record stream into a
`FetchBatchRequestSource`, directly usable by `streamMapFetches` or
`tryStreamMapFetches`. They do not start requests or acquire network authority.

Unlike a bare `pipeThrough()` result, this stage has an explicit `closed`
receipt that includes the actual asynchronous mapper and its owned producer.
Native stream cancellation alone is not a join of arbitrary pending producer
work. See the WHATWG Streams cancellation and piping algorithms:
https://streams.spec.whatwg.org/#rs-cancel
https://streams.spec.whatwg.org/#rs-pipe-through

## Connect an NDJSON feed to an authorized batch

```ts
import { jsonLines } from "@asupersync/browser/streams";
import { tryMapFetchRequests } from "@asupersync/browser/pipeline";
import { streamMapFetches } from "@asupersync/browser/batch";

// feed is an already admitted, scope-owned FetchStreamHandle.
const records = jsonLines(feed);
if (records.outcome !== "ok") throw new Error("record setup refused");
const requests = tryMapFetchRequests(records.value, ({ value }, index, signal) => {
  signal.throwIfAborted();
  if (!value || typeof value !== "object" || !("id" in value)
      || typeof value.id !== "string") {
    return { outcome: "err", failure: {
      code: "decode_failure", recoverability: "permanent",
      message: `invalid request record ${index}`,
    } };
  }
  return { outcome: "ok", value: {
    url: `https://api.example.test/items/${encodeURIComponent(value.id)}`,
  } };
});
if (requests.outcome !== "ok") {
  await records.value.cancel("mapping setup refused");
  throw new Error("mapping setup refused");
}
const admitted = streamMapFetches(scope, requests.value,
  async ({ body }) => new Response(body).text(),
  { concurrency: 4, signal: shutdownSignal });
if (admitted.outcome !== "ok") {
  await requests.value.cancel("batch setup refused");
  throw new Error("batch setup refused");
}
try {
  for await (const { index, value } of admitted.value.results) {
    await persist(index, value);
  }
} finally {
  await admitted.value.cancel("pipeline complete");
}
const terminal = await admitted.value.closed;
```

`mapFetchRequests` accepts an ordinary request value or a promise of one.
`tryMapFetchRequests` accepts a checked `Outcome` (or promise), so validation
failures do not have to be thrown panics. Successful `null` skips an input;
`index` counts every physical input, including skipped records. This is not an
HTTP retry, schema validator, or request admission API: the downstream scope
still validates URLs, methods, authority and bodies when it admits each request.

## Pulling, ownership and shutdown

There is at most one active input read/mapper, invoked only on output demand.
The output has zero high-water mark and no independent pump. The next input is
not read after producing a descriptor until another output pull is requested.
The mapper receives a private cancellation signal for its own cooperative work.

An owned source has `{ readable, closed, cancel }`, matching the record decoders.
It must report all producer work in `closed`, and its idempotent `cancel` must
work while its readable is locked. A raw native `ReadableStream<T>` is also
accepted, but provides no independent producer-completion guarantee. Overridden
native read/cancel methods and owner-like properties on raw streams are ignored.

Setup snapshots the owned source's methods and terminal receipt before reader
acquisition. Refusal does not read or cancel input and leaves ownership with the
caller. Successful setup owns the reader and producer's completion obligation.
Even after native EOF, `closed` waits for the producer receipt. A successful
producer receipt does not discard unconsumed records.

Cancellation fences output before callbacks, notifies the mapper, and starts
native cancellation and owner cancellation in parallel. Settlement waits for
the active mapper, both cancellation operations and the source's `closed`.
Late mapper failures participate in `panicked > cancelled > err`; equal-severity
causes retain the first observed cause. Expected source retirement cancellation
does not hide a typed application failure. Arbitrary exception `cause` getters
are not trusted; genuine mapper exceptions become sanitized panics. Rethrowing
this mapper's own signal reason preserves its cancellation outcome.

Native output cancellation closes the readable immediately, but its cancellation
promise and this stage's `closed` remain full cleanup barriers. Manual `cancel`
also works while output is locked. An ordinary iterator break or `pipeTo` sink
failure propagates upstream cancellation. After settlement, cancellation is inert.
Never have a mapper or source await this stage's own `closed`/`cancel`; that is a
join cycle. Nonsettling or dishonest producers cannot be forcibly retired.

The default `maxInputs` is 100,000, including skipped records. A supplied bound
must be a positive safe integer. Exact-limit EOF succeeds; an excess input is
read to detect overflow but is never mapped. Request descriptors retain identity
and their fields/bodies are not inspected here. Undelivered descriptors, skipped
records, producer lookahead and unadmitted upload bodies remain the producer or
mapper's responsibility. Already-delivered requests and remote effects cannot be
rolled back. This is an adapter work-count bound, not a payload-byte, downstream
queue, wall-clock, or event-loop responsiveness guarantee. Consume or cancel the
output rather than waiting for `closed` without output demand.

## Validation

```sh
node --experimental-vm-modules --test scripts/test_browser_fetch_request_map.mjs
```

The lane runs actual mapping TypeScript and native Streams, with explicit
producer receipt doubles. Its HTTP case uses native fetch over real loopback
HTTP and waits for server-observed disconnection before publishing producer
completion. Separate gates witness active mapper, native cancel, owner cancel
and producer-completion waits. `ASUPERSYNC_REQUEST_MAP_SOURCE` selects an exact
alternate source for negative controls. Type stripping is not a typecheck;
repository-pinned TypeScript, full SDK, Rust/WASM and cross-browser validation
remain separate lanes. Existing dependency/export governance pins are not
silently regenerated by this feature.
