# Owned browser response records

`@asupersync/browser/streams` decodes an **existing scope-owned fetch**. It does
not create a separate connection, runtime task, timer, or background pump.
Original fetch authority, request options, upload handling, byte limits,
deadlines, `AbortSignal`, and scope/runtime cancellation remain in force.

## Server-Sent Events

```ts
import { serverSentEvents } from "@asupersync/browser/streams";

// `scope` belongs to a BrowserRuntime with an explicit grant for this origin,
// method and header count. The adapter adds no headers on the caller's behalf.
const started = scope.fetch({
  url: "https://api.example.test/events",
  method: "POST",
  headers: { "content-type": "application/json" },
  body: new TextEncoder().encode(JSON.stringify({ topic: "updates" })),
  timeoutMs: 60_000,
  maxResponseBytes: 16_777_216,
});
if (started.outcome !== "ok") throw new Error("fetch admission refused");

const decoded = serverSentEvents(started.value, {
  maxLineBytes: 65_536,
  maxEventChars: 1_048_576,
});
if (decoded.outcome !== "ok") {
  // Setup refusal has not acquired a record-stream owner. The existing fetch
  // is still the caller's responsibility; await its cancellation or consume it.
  await started.value.cancel("event decoder setup refused");
  throw new Error("event decoder setup refused");
}
const events = decoded.value;
try {
  const reader = events.readable.getReader();
  try {
    for (;;) {
      const next = await reader.read();
      if (next.done) break;
      console.log(next.value.type, next.value.data, next.value.lastEventId);
    }
  } finally {
    // Unlike readable.cancel(), events.cancel() also works with a locked reader.
    await events.cancel("consumer finished");
    reader.releaseLock();
  }
} finally {
  const terminal = await events.closed;
  // Check this receipt, including an ABI refusal. It covers parsing and host
  // cleanup; fetch.closed alone can precede consumption of already-read bytes.
  console.log(terminal);
}
```

The native stream also supports `pipeTo`, `pipeThrough` and asynchronous
iteration where the host exposes those APIs. Early iterator exit cancels the
fetch and awaits owned cleanup. Native consumer cancellation makes its read
side appear closed immediately; the initiating cancellation promise and
`events.closed` are the cleanup barriers, not an EOF read or a second native
cancel on an already closed stream. `events.cancel()` is idempotent and always
returns its cleanup barrier.

The decoder requires HTTP 200 and a single `text/event-stream` media type
(parameters and case variations are allowed). It implements WHATWG event-stream
wire rules: UTF-8 replacement decoding, one leading BOM, CR/LF/CRLF, multiline
data, default event types, persistent IDs, empty ID reset, NUL-ID rejection,
comments and unknown fields, and incomplete-event discard at EOF.

`lastEventId` reflects the last **blank-line dispatch boundary**, including
ID-only blocks. An ID in an unfinished EOF block is not committed. `retry` is
`null` or the exact last digit-only field as a string, retaining integers larger
than JavaScript's numeric range without truncation. This module does **not**
reconnect, follow redirects, synthesize `Last-Event-ID`, interpret `[DONE]`, parse
event payloads as JSON, or guarantee replay/deduplication. The caller must make
any next request explicitly through its granted scope.

The adapter retains at most one fetch chunk, a bounded raw-byte line, one
bounded event-data buffer, and bounded ID/type/retry strings. It emits one event
per pull and does not parse the next event or prefetch the next chunk after
that emission. `maxLineBytes` excludes delimiters. `maxEventChars` counts UTF-16
code units in data values plus each appended LF, including the final LF removed
for dispatch. Defaults are 64 KiB and 1 Mi code units; configurable upper limits
are 1 MiB and 16 Mi code units. Original fetch total-response and chunk limits
still apply. Browser/network buffers and caller/downstream/tee queues are not
part of this envelope.

A protocol or parsing error cancels and drains the fetch before surfacing an
error with its typed Outcome in `error.cause`. ABI cancellation/publication
refusals are surfaced rather than converted into successful completion. Parser
failures are adapter outcomes; the existing task still reports its own fetch
cancellation or terminal outcome. A host operation that never settles cannot
be forcibly drained by JavaScript.

## Verification

Run `node --experimental-vm-modules --test scripts/test_browser_fetch_events.mjs`
with Node 22.13 or newer. Tests load the actual SDK modules with native Streams
and include real localhost HTTP. Their task ABI is an explicit double, not a
Rust/WASM integration receipt. WHATWG parsing reference:
https://html.spec.whatwg.org/multipage/server-sent-events.html#parsing-an-event-stream
