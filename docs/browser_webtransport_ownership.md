# Awaited browser WebTransport ownership

`RegionHandle.openWebTransport()` admits one capability-gated native session
under an SDK region. Its datagrams and reliable byte streams share that session
and its WASM task handle. Use asynchronous shutdown to await host cleanup and
accepted task retirement:

| Method | Result |
| --- | --- |
| `closeAsync(options?, consumerVersion?)` | `Promise<BrowserOutcome<void>>` |
| `cancelAsync(tokenOrKind, message?, consumerVersion?)` | `Promise<BrowserOutcome<void>>` |

`closeAsync` accepts `{ closeCode?, reason? }`. `cancelAsync` accepts a
`CancellationToken` or a cancellation-kind string; a token supplies its own
message. Both return a cleanup receipt: intentional cancellation can retire
successfully and produce `Outcome.ok(undefined)`.

## A scope owns the complete workflow

With an existing `BrowserRuntime`, bracket a session and its reliable streams:

```ts
import { Outcome, unwrapOutcome } from "@asupersync/browser";

const result = await runtime.withScopeAsync(async scope => {
  const session = unwrapOutcome(scope.openWebTransport(
    "https://transport.example.test/session",
  ));
  unwrapOutcome(await session.ready());
  const stream = unwrapOutcome(await session.openStream());
  unwrapOutcome(await stream.write(new TextEncoder().encode("request\n")));
  unwrapOutcome(await stream.finish());

  // Interpret the response according to the application's protocol.
  const response = unwrapOutcome(await stream.read());
  return Outcome.ok(response);
}, { label: "transport-request" });
const response = unwrapOutcome(result);
```

`withScopeAsync` closes the session and any remaining stream halves before
returning the callback's exact outcome or rethrowing its exact rejection.
`RegionHandle.withScopeAsync` provides the same behavior for nested child work.
An explicit `scope.closeAsync()` drains its descendant sessions;
`runtime.closeAsync()` applies the barrier across the runtime. Unrelated sibling
regions remain live when a child closes.

A failed cleanup makes the bracket reject with `BrowserScopeCleanupError`.
Its `cleanupOutcome`, `bodyCompletion`, and independent `scope` retry handle
preserve both the cleanup evidence and the callback completion. Resolve the
reported condition before explicitly calling `error.scope.closeAsync()`.
See [asynchronous scope brackets](browser_stream_pipes.md#automatic-asynchronous-scopes)
for the complete error contract.

## What successful cleanup waits for

The asynchronous barrier covers all SDK-owned parts of the session:

- Connection closure observed through the captured native `closed` promise.
- Admitted datagram reads and writes, reader cancellation, and writer abortion.
- Active reliable streams and their pending reads, writes, and finalization.
- Pending stream creation or acceptance, including cleanup of late endpoints.
- Acquired incoming collection readers and successful release of owned locks.
- Accepted ABI cancellation, where needed, and matching terminal publication.

Cancellation starts across owned resources before waiting for any one host
cleanup hook. Native backpressure remains effective: an in-flight write or
asynchronous abort keeps shutdown pending. A host promise that never settles
can keep the barrier pending indefinitely; there is no fabricated completion
deadline. Application-created promises and unaccepted host-owned endpoints
remain outside this ownership boundary.

Closing during handshake stops waiting callers and suppresses later datagram
lock acquisition. A stream creation already submitted to the host remains
owned until its result settles and any late endpoint is cleaned up.

The synchronous `close()` and `cancel()` methods retain their terminal-outcome
contracts. Pending host cleanup remains tracked after synchronous session or
owner closure, with the original ancestry captured before handles are released.
A later asynchronous owner drain can therefore find it even after a child
scope's ledger handle has been invalidated. An invalid handle alone never
establishes successful host cleanup.

## Failure and explicit retry

Overlapping asynchronous shutdown calls share one attempt. Its first cleanup
or publication failure remains visible to that caller; the SDK does not replace
it with an immediate retry. Ownership stays retained while cleanup or task
retirement is unresolved.

A later explicit `closeAsync`, `cancelAsync`, or owner `closeAsync` can retry
failed lock releases and refused ABI publication. It does not repeat accepted
task cancellation or settled native cancel/abort operations. A rejecting native
cleanup hook is reported by the first attempt; if the operation has settled and
all locks release, a subsequent explicit attempt can finish retirement.

An acquisition that throws after potentially hiding an acquired lock cannot
be certified by retrying other known locks. Missing trustworthy connection-close
evidence likewise remains a permanent cleanup failure. Such failures cannot
be converted into success merely by repeating shutdown.

The shared reliable-stream manager exposes three complementary receipts:

| Receipt | Meaning |
| --- | --- |
| `whenClosed(state)` | Original owner outcome after the initial cleanup attempts settle. |
| `whenRetired(state)` | Shared immutable historical receipt; an observed cleanup failure remains sticky after any later retry. |
| `drainCleanup(state)` | Separate explicit cleanup attempt; reports failures and retries retained known locks on subsequent calls. |

These manager receipts cover reliable streams. The SDK adds datagram cleanup,
connection closure, and task retirement. Existing `stream.closed` outcomes also
retain their original terminal meaning after a successful cleanup retry.

## Bounds and verification

Admission bounds remain 65,536 bytes per datagram, 256 queued/admitted datagrams
and 1,048,576 queued bytes per session. Reliable streams share 64 slots across
live endpoints, pending admissions, and retained cleanup uncertainty; each write
admits at most 1,048,576 bytes. Browser/network queues and caller-retained values
are separate. Fulfilled writes acknowledge host acceptance; applications define
their own peer acknowledgements and durability guarantees.

```sh
node --unhandled-rejections=strict --experimental-vm-modules --test \
  scripts/test_browser_webtransport_ownership_wasm.mjs \
  scripts/test_browser_webtransport_cleanup.mjs \
  scripts/test_browser_webtransport_lifecycle.mjs
```

The ownership suite executes the actual SDK and checked-in generated WASM
ledger with native Node WHATWG streams and a controlled WebTransport host.
Explicit refusal cases intercept only the ABI operation under test. The other
suites exercise the shared manager and host facade. These receipts cover host
ownership, locking, backpressure, failure and retry; they do not rebuild Rust,
execute a browser engine, or verify live HTTP/3 interoperability.
