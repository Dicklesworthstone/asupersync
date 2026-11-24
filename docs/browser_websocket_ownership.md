# Owned asynchronous browser WebSockets

`RegionHandle.adoptWebSocket(socket, options)` transfers a connecting or open
native WebSocket into an existing SDK region. It adds awaitable opening, sending
and receiving, a bounded inbox, native stream consumption, and a complete asynchronous
cleanup barrier. It does not create a connection or grant network authority.
The existing `openWebSocket` and low-level WebSocket ABI remain unchanged.

```ts
// Create the connection using the application's existing network authority.
const nativeSocket = new WebSocket("wss://api.example.test/updates", ["updates.v1"]);
const adopted = scope.adoptWebSocket(nativeSocket, {
  maxQueuedMessages: 64,
  maxQueuedBytes: 4 * 1024 * 1024,
  maxMessageBytes: 1024 * 1024,
  maxSendBufferedBytes: 1024 * 1024,
  signal: viewController.signal,
});
if (adopted.outcome !== "ok") {
  nativeSocket.close(); // Refused admission leaves the socket with its caller.
  throw new Error("WebSocket adoption refused");
}
const socket = adopted.value;
try {
  const opened = await socket.opened;
  if (opened.outcome !== "ok") throw new Error("WebSocket opening failed");
  const sent = socket.send(JSON.stringify({ subscribe: "updates" }));
  if (sent.outcome !== "ok") throw new Error("WebSocket send refused");
  for (;;) {
    const received = await socket.receive();
    if (received.outcome !== "ok") throw new Error("WebSocket receive failed");
    if (received.value.done) break;
    await applyUpdate(received.value.value); // string or Uint8Array
  }
} finally {
  const retired = await socket.retire("view finished");
  if (retired.outcome !== "ok") {
    // Ownership is retained. Retry retirement once the reported host/ABI
    // refusal can be resolved; do not report a successful scope shutdown.
    reportCleanupFailure(retired);
  }
}
const closed = await scope.closeAsync();
```

## Ownership and lifecycle

Adoption accepts an unmodified same-realm native WebSocket in `CONNECTING` or
`OPEN`. Options, host support and region admission are checked before ownership
is transferred. Invalid options, a closed/closing socket, duplicate adoption,
or task-admission refusal leaves the socket untouched. Once adoption succeeds,
the caller must stop using the raw socket, including its listeners, `send`,
`close` and `binaryType`. SDK ownership cannot prevent another holder of that
native reference from violating this contract. The SDK sets binary messages to
`arraybuffer` and copies each admitted binary message into its own Uint8Array.

`opened` resolves with the negotiated `protocol` and `extensions`, or a typed
failure/cancellation. `receive()` permits only one pending call: a second call
is refused without stealing the first call's message. Messages retain their
arrival order. Normal remote close preserves already-queued messages for
consumption before EOF. A transport error, abnormal close, overflow or active
cancellation discards unread messages and produces a typed failure after the
native socket and task retire.

`closed` is the first terminal publication receipt. `retire()` separately
reports whether cleanup and task release succeeded, so an intentional
`Cancelled` operation can have successful retirement. Failed task cancellation,
listener removal or terminal publication retains the SDK ownership record.
An explicit `retire()` or region `closeAsync()` retries the failed step without
repeating already-accepted cancellation or an already-requested native close.
The original `closed` receipt remains unchanged after a successful retry.

`cancel(reason)` discards unread output and requests owned cancellation.
`close({ code, reason })` requests a graceful handshake; valid codes are 1000 or
3000–4999, with at most 123 UTF-8 bytes in the reason. An abnormal handshake
cannot become successful merely because `close()` was requested. Cancellation
during a pending graceful close strengthens its terminal outcome. Closing before
the connection opens cannot report a successful `opened` receipt.

Native `close()` only starts a handshake. Successful retirement requires native
`CLOSED` observation, listener cleanup and accepted ABI task publication. A
missing close observer is retried; a close event already missed during failed
installation can be recovered from the captured native `readyState` getter.
`CLOSING` never counts as completed cleanup. There is no timer that fabricates
quiescence: a peer/host that never finishes closing can keep retirement pending.
An explicit caller deadline signal requests cancellation but cannot force a
browser WebSocket to terminate.

Region and runtime `closeAsync()` cancel sockets in parallel with owned fetches
and message receivers, join all cleanup, then call the existing ABI owner-close
barrier. Synchronous `close()` retains its existing behavior and is not an
asynchronous socket-cleanup receipt.

## Bounds and send admission

Defaults are 64 queued messages, 4 MiB of queued bytes, 1 MiB per message and
1 MiB of native send buffering. The configurable maxima are 4,096 messages,
64 MiB queued bytes, 16 MiB per message and 64 MiB send buffering. Limits must
be positive safe integers. Empty messages consume message-count credit; strings
are charged by UTF-8 bytes, including surrogate pairs and replacement encoding.
Binary lengths use native buffer accessors rather than shadowable properties.
Oversized incoming messages are refused before making the adapter's binary copy.

The browser WebSocket API provides no receive backpressure. Exceeding either
inbox cap fails and closes this owned socket; messages are not silently dropped
while presenting success. Browser/network buffers, caller-retained values and
downstream queues are outside these bounds.

`send(string | Uint8Array)` is synchronous and requires an open, active socket.
It refuses a message exceeding `maxMessageBytes`, or one whose byte length plus
native `bufferedAmount` exceeds `maxSendBufferedBytes`. It creates no send queue
or polling timer. A successful send means the native host accepted the message;
it is not a peer acknowledgement or a transport-level flow-control guarantee.
Applications needing retries or acknowledgements supply their own protocol.

`sendWhenReady(string | Uint8Array)` returns a `Promise<Outcome<void>>` and waits
for room under that same native send-buffer cap. Await `opened` before sending.
Use it to pace a producer without implementing a polling loop in application
code:

```ts
for await (const message of outgoingMessages) {
  const sent = await socket.sendWhenReady(message);
  if (sent.outcome !== "ok") {
    reportSendFailure(sent);
    break;
  }
}
```

Only one send may wait at a time; a competing call is refused rather than added
to an unbounded queue. A pending binary message is copied into a right-sized
snapshot, so later mutation of the caller's array cannot change the admitted
bytes or retain a large backing buffer through a small subview. Strings are
immutable and charged by UTF-8 length. A message that can never fit under either
configured limit is refused immediately.

The adapter owns at most one host timer while waiting for `bufferedAmount` to
fall. Hosts without usable timers can still use synchronous `send()`; they
cannot wait for send credit. Closing, cancellation, and transport failure retire
the pending send and its timer. A settled send remains a local native-buffer
admission receipt, not proof that the peer received or committed the message.
Continue to await `closed` or successful `retire()` for socket cleanup.

## Native Streams and parent cancellation

`toReadableStream()` returns a memoized zero-high-water-mark
`ReadableStream<string | Uint8Array>`. Conversion transfers receive ownership;
subsequent manual `receive()` calls are refused. Conversion is refused while a
manual receive is pending. An ordinary async-iterator break or `pipeTo` sink
failure cancels the socket and joins retirement. Cancellation/publication
failures reject native cancellation with the structured Outcome in
`error.cause`.

Native stream cancellation marks its read side closed immediately. Await the
initiating cancellation/iterator/pipe promise or `retire()` for cleanup; a
second native cancel or an EOF read is not a replacement cleanup barrier.
An already-pending native pull can retain one delivered message after its reader
releases the lock. It remains available to the next reader. Additional caller
read promises, downstream transforms and `tee` queues are caller-owned.

An optional unmodified same-realm native AbortSignal is borrowed through a
private `AbortSignal.any` dependent signal. Earlier caller listeners cannot
suppress cancellation. Arbitrary abort reasons are neither inspected nor
formatted, and manual cancellation never aborts the caller's signal. The signal
listener is removed before task publication.

## Focused validation

```sh
node --unhandled-rejections=strict --experimental-vm-modules --test scripts/test_browser_websocket_ownership.mjs
node --unhandled-rejections=strict --experimental-vm-modules --test scripts/test_browser_message_regions_wasm.mjs
```

The ownership suite executes the actual TypeScript manager with native
EventTarget/Streams, controlled host failures and explicit task-receipt doubles.
It also exchanges exact text/binary messages with Node's native WebSocket and
an independent local HTTP-upgrade peer that withholds its close response. The
SDK region suite uses the checked-in generated JavaScript/WASM ABI. These lanes
do not rebuild Rust, run a browser engine, or prove Rust executor dispatch.
This implements the capsule/close-finalization behavior in the browser plan's
sections 9.1 and 9.3 without changing the stable ledger ABI.
