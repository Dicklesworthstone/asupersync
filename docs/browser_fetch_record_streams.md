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

## JSON-lines / NDJSON

```ts
import { jsonLines } from "@asupersync/browser/streams";

// After scope.fetch(...) returns an owned FetchStreamHandle:
const decoded = jsonLines(fetchHandle, {
  maxLineBytes: 1_048_576,
  maxRecords: 100_000,
  allowEmptyLines: true,
  allowFinalRecord: false,
});
if (decoded.outcome !== "ok") {
  await fetchHandle.cancel("JSON-lines setup refused");
  throw new Error("JSON-lines setup refused");
}
const records = decoded.value;
try {
  const reader = records.readable.getReader();
  try {
    for (;;) {
      const item = await reader.read();
      if (item.done) break;
      // value is unknown: validate against your application schema here.
      console.log(item.value.lineNumber, item.value.value);
    }
  } finally {
    await records.cancel("consumer finished");
    reader.releaseLock();
  }
} finally {
  console.log(await records.closed);
}
```

Requires HTTP 200 and `application/x-ndjson` (or the `application/ndjson`
alias). An `application/json` response is not silently reinterpreted as
NDJSON. LF and CRLF delimit records; bare CR inside a record is rejected.
UTF-8 errors are fatal rather than replacement-decoded. One leading BOM is
tolerated. Physical line numbers include empty lines, which are skipped by
default and may be rejected with `allowEmptyLines: false`. Whitespace-only
lines are not considered empty.

Every record must end in LF by default: even an apparently valid JSON value
without its final delimiter is a truncation error. `allowFinalRecord: true`
explicitly permits that one complete final value, but never invalid JSON.
This cannot detect a producer that truncates exactly at a record boundary;
it is not a completeness signature or transaction protocol. Previously emitted
records cannot be rolled back if a later record fails.

`maxLineBytes` defaults to 1 MiB and may be configured up to 16 MiB. It counts
raw bytes before LF, including the optional preceding CR. `maxRecords` defaults
to 1,000,000 and counts emitted records, not empty lines. No array of decoded
records is retained: each pull emits at most one `{ lineNumber, value }`.
The line wrapper is frozen; its parsed value belongs to the caller and is not
retained by the parser. `null`, primitives, arrays and objects are all valid
values. Parsing uses native `JSON.parse` semantics, including duplicate-key
handling and number precision; it does not promise lossless large integers or
schema validation. Parse error messages contain line numbers, not payload
excerpts that could expose credentials or application data.

The ownership, backpressure and cancellation rules above apply unchanged.
Record failure drains the original fetch before surfacing, including when
source cleanup is slow. A task-publication refusal is never converted into a
successful parsing outcome. Protocol reference: https://github.com/ndjson/ndjson-spec

## Verification

Run `node --experimental-vm-modules --test scripts/test_browser_fetch_events.mjs`
with Node 22.13 or newer. Tests load the actual SDK modules with native Streams
and include real localhost HTTP. Their task ABI is an explicit double, not a
Rust/WASM integration receipt. WHATWG parsing reference:
https://html.spec.whatwg.org/multipage/server-sent-events.html#parsing-an-event-stream
