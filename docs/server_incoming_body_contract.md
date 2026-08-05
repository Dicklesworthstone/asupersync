# Server incoming-body foundation contract

<!-- BEGIN SERVER INCOMING BODY CONTRACT -->

Bead: `asupersync-server-stack-hardening-eeexl1.6.1`

Canonical artifact: `artifacts/server_incoming_body_contract_v1.json`

Status: static foundation authored; partial BODY-2 H1 scaffold source progress is
recorded below; executable validation and live integration are unrun. The BODY-2
bead remains open.

## Purpose and authority

This packet freezes the current request-body pipeline and defines the ownership,
budget, terminal-state, and connection-reuse contract that later H1, H2, and web
integration work must implement. The foundation itself authorizes no production
source change; the separately owned BODY-2 follow-on records partial source work
below without widening that authority.

The authority boundary is intentionally narrow:

- define one single-consumer incoming request body;
- reuse `http::body::Body` and `Limited`, while treating `StreamBody` as a landed
  reference adapter rather than the authoritative incoming type;
- preserve the current 10 MiB JSON and raw-body defaults and 2 MiB form default;
- require checked total, frame, decoder, and queue accounting;
- define explicit EOF, error, cancellation, client-abort, and consumer-drop states;
- assign unread-body cleanup and connection reuse to the protocol driver;
- leave emitted ASUP error-code allocation to a later implementation change; and
- keep tracker closure pending until the Rust contract receives executable validation.

## Current architecture

The reusable abstractions and the live server path are currently separate.

| Layer | Current representation | Live behavior | Foundation gap |
|---|---|---|---|
| Generic body | `Body`, `Frame`, `SizeHint` | Poll-based data/trailer frames | Not owned by live request dispatch |
| Stream adapter | `StreamBody<S>` | Converts a frame stream into `Body` | Not the incoming request type |
| Size adapter | `Limited<B>` | Decrements a data-byte allowance | Not wrapped around one shared incoming body |
| H1 scaffold | `IncomingBody` plus `IncomingBodyWriter` | Bounded frame-count channel and fixed/chunked parsing; explicit producer completion is distinguished from premature disconnect, incoming arithmetic is checked before mutation, and a fixed-length size hint decreases on delivery | Errors still use `HttpError`; no queue-byte permits, consumer-drop signal, already-terminal repoll error, protocol cleanup/reuse, obligation/telemetry integration, or live dispatch |
| H1 live path | `Http1Codec` to `h1::types::Request` | Applies the body cap, then completes a `Vec<u8>` body before dispatch | No concurrent handoff; prospective body and trailer accounting uses saturating addition |
| H2 live path | pending headers plus `Vec<u8>` per stream | Uses saturating prospective addition against a configured per-stream cap (16 MiB by default), resets an over-cap stream with `ENHANCE_YOUR_CALM`, and otherwise dispatches after `END_STREAM` | No incremental handler consumption, surfaced trailers, or connection-wide aggregate body budget |
| Web request | `web::extract::Request` | Owns cloneable `Bytes` | Conflicts with sole-consumer ownership |
| Handler/router | `Handler::call(&Cx, Request)` | Moves a complete request into the handler | No head/body split |
| Retry middleware | cloned buffered `Request` | Redispatches the same materialized body | A live body needs bounded replay prepared before first dispatch or retry refusal |
| Extractor limits | `BodyLimits` | Checks `Content-Length` and buffered bytes | Cannot bound pre-dispatch buffering |
| Multipart | contiguous buffered parse | Applies aggregate, part-count, per-part body/header, request-time, and idle-time limits after materialization | No bounded asynchronous collector; timing currently reads wall time directly |
| Web response | buffered `Bytes` | Materializes response bodies | Explicitly outside BODY-1 |
| Request region | `ServerRequestRegion` | Owns handler budget and terminal outcome | Starts after protocol body assembly |

The source-fingerprinted matrix in the artifact is authoritative. In particular,
the mere presence of `IncomingBody`, `StreamBody`, or `Limited` is not evidence that
live handlers receive body frames incrementally.

## BODY-2 static H1 scaffold progress

The follow-on bead `asupersync-server-stack-hardening-eeexl1.6.2` has one bounded
source-only increment based on revision
`1620c55e5a3d139e7fb39b1c5e545055e3841541`. `IncomingBodyWriter` now stores a
compact producer terminal reason before releasing its final sender. The consumer
therefore treats explicit framing completion as EOF and a producer that disappears
while framing remains open as `HttpError::BodyChannelClosed`. Writer-generated
framing, limit, header, and cancellation failures retain their matching reason for
the consumer after any already-queued frames are delivered.

Incoming buffer, accepted body-byte, and trailer-byte totals are checked against
overflow and their configured limit before the corresponding mutation. Fixed
`Content-Length` size hints decrease only as frames are delivered and reach exact
zero at completion or terminal failure. Inline cases were authored for declining
size hints, premature producer drop, completed trailer-free chunked input, queued
data followed by a framing failure, and whole-frame refusal at the body limit.
Those cases have not been compiled or run.

This remains partial scaffold progress. The public error is still `HttpError`,
unclassified producer failures collapse to `BodyChannelClosed`, and a poll after a
terminal result returns ordinary end-of-stream rather than `AlreadyTerminal`.
There is no independent queue-byte permit budget, consumer-drop notification,
request-budget cancellation bridge, bounded drain-or-close/reuse policy,
obligation or terminal telemetry integration, or live H1 handler dispatch.

## Public ownership contract

The proposed public value is `IncomingRequestBody`, implementing
`crate::http::body::Body<Data = BytesCursor, Error = IncomingBodyError>`. Both names
are contract names, not claims that the types have landed.

`StreamBody` remains a useful generic adapter, but its underlying `None` is ordinary
EOF and it does not own producer completion, consumer-drop notification, or the
body obligation. The public incoming type therefore does not have to wrap it. The
existing H1 `IncomingBody` must be replaced or generalized into the one public
incoming type; a second coexisting public incoming-body authority is forbidden.
The concrete type is `Send + Unpin + 'static`, allowing the existing `Limited<B>`
implementation to wrap it. `Sync` is not required for a single consumer; BODY-3
must remove any `Sync` bound from the final body-consuming extractor while retaining
`Send`.

`IncomingBodyError` is also concrete rather than an opaque placeholder. It carries
typed framing detail and offset, observed/limit/source values for a limit refusal,
the exact `CancelKind`, source-disconnect and transport detail, checked-accounting
operands, and an already-terminal repoll variant. Consumer drop is a Drop-side
obligation handoff; it is not a frame-poll error.

Ownership is split as follows:

| Obligation | Sole owner |
|---|---|
| Produce validated protocol frames | H1 connection driver or H2 stream driver |
| Consume body frames | Exactly one handler or extractor chain |
| Enforce request budget and cancellation | Request `Cx` derived for `ServerRequestRegion` |
| Drain unread bytes and decide reuse | Protocol driver |
| Emit terminal receipt | Protocol driver carrying request-region correlation |

The request head and body are split once. `IncomingRequestBody` is not cloneable.
Moving it transfers the consumer obligation. Dropping it before EOF produces an
explicit `CONSUMER_DROPPED` signal; it is not silently interpreted as successful
completion. No body operation may obtain ambient authority outside the request
`Cx`.

## Terminal-state contract

The body lifecycle begins only after request-head framing is valid and the declared
length passes server and route admission. A pre-body header, declared-length,
deadline, cancellation, or transport failure may use a stable request-level
mapping, but it creates no `IncomingRequestBody`, no body obligation, and no
`http.incoming_body.terminal` receipt. `CREATED` transitions to `OPEN` when the
sole-consumer handoff begins. `OPEN` has five body-terminal outcomes:

| Terminal state | Cause | Poll result |
|---|---|---|
| `EOF` | Producer explicitly completes framing and queued frames are observed | `None` |
| `ERROR` | Framing, source, or inner-body failure | Typed error; repoll fails closed without polling the producer |
| `LIMIT_EXCEEDED` | Checked frame, decoder, queue, or total-budget refusal | Typed error; repoll fails closed without polling the producer |
| `CANCELLED` | Request budget or request `Cx` cancellation | Typed error; repoll fails closed without polling the producer |
| `CLIENT_ABORTED` | Peer reset or lost transport | Typed error; repoll fails closed without polling the producer |

An internal producer disconnect before explicit framing completion is `ERROR`, not
EOF. At most one trailers frame may follow all data frames. Protocol adapters do
not enqueue zero-length data frames.

`CONSUMER_DROPPED` is a cleanup handoff, not obligation completion. Cleanup entry
is explicit for every terminal or handoff state: EOF needs none; H1 errors and
client abort require closure; H1 limit/cancellation may drain only while framing
is synchronized and every bound applies; H2 stream-scoped error, limit, cancellation,
or drop may reset; and any connection-scoped H2 failure closes. A client abort
never starts a drain or reset handshake. The exactly-once terminal receipt and
body-obligation resolution occur only after that protocol-owned decision. The
fail-closed repoll rule intentionally matches `Limited`'s existing post-failure
model.

## Frame, queue, and total budgets

The initial integration contract retains the existing bounded H1 scaffold values
while making every bound independently enforceable:

| Budget | Contract value |
|---|---:|
| Maximum data frame | 65,536 bytes |
| Queue capacity | 8 frames |
| Queue byte capacity | 524,288 bytes |
| Decoder partial-buffer capacity | 262,144 bytes |
| Trailer capacity | 16,384 bytes |
| Default protocol total | 16,777,216 bytes |
| Proposed H1 unread-body cleanup | 8 frames, 524,288 bytes, and 500 ms |
| Proposed H2 reset-in-flight cleanup | 8 frames, 524,288 bytes, and 500 ms |

The 500-ms values are proposed initial body-cleanup values derived from the landed
handler-future drain grace. They are not evidence that live unread-body cleanup is
currently enforced.

The effective total is the minimum of the protocol/server hard cap,
`RequestBodyLimitMiddleware` or route policy, the selected extractor cap, and any
applicable request quota. Byte and frame capacity must be reserved with checked
arithmetic before a frame is enqueued. Permits represent only in-flight queued
data: ownership transfers exactly once on dequeue, every terminal path releases
residual permits exactly once, and a refused frame retains none.

Trailer size is deterministic per protocol. H1 counts each validated trailer line's
field-section octets plus its CRLF, excluding the final empty line. H2 counts decoded
name octets plus value octets plus 32 octets per field, never compressed wire size.
The same checked metric applies to both the queue-byte cap and independent 16 KiB
trailer cap. Saturating accounting is forbidden because it loses evidence that a
bound was crossed. A refused frame is never partially delivered, and no unbounded
side queue is permitted.

Before live H2 integration, its assigned owner must also define finite connection-level
in-flight byte and frame caps. A connection coordinator must reserve connection and
stream capacity atomically, or release one before waiting for the other; aggregate
pressure uses protocol flow control, and cancellation releases both scopes exactly
once. Per-stream bounds alone are not a connection-memory bound.

Server and route limits bind before body handoff. A selected extractor may only
monotonically tighten that bound before its collector consumes; it can never relax
an upstream cap. If a newly selected cap is below bytes already received, delivered,
or queued, the body transitions to `LIMIT_EXCEEDED` and the protocol driver performs
its bounded cleanup policy.

The existing extractor defaults remain:

- JSON: 10 MiB;
- raw bytes: 10 MiB; and
- form: 2 MiB.

The existing multipart defaults are also recorded rather than changed: 16 MiB
aggregate, 8 MiB per part, 8 KiB part headers, 1,024 parts, a 30-second request
timeout, and a 5-second idle timeout. Multipart remains a contiguous buffered parse
in this foundation; no incremental parsing claim is made.

Lowering the JSON or raw default requires explicit owner approval and is outside
this foundation.

## Size hints

For a validated `Content-Length`, the hint is the exact remaining byte count and
decreases only after a data frame is committed to the consumer. For chunked input,
the lower bound is zero and the upper bound is the remaining effective total when
representable. EOF reports exact zero. A hint is advisory and never substitutes
for admission checks.

## Cancellation, abort, drain, and reuse

Head acceptance, protocol production, queue reservation, and handler consumption
share the derived request budget. Once that budget expires or its `Cx` is cancelled,
cleanup cannot reuse it. Cancellation closes the handoff, records remaining
obligations, and transfers cleanup to a separate protocol-owned grace capped by
connection and shutdown authority. Cleanup is strictly bounded and cannot run as a
detached task.

`IncomingBodyError` preserves the exact `CancelKind`. `Timeout` and `Deadline`
map to `BODY-REQUEST-DEADLINE`; `PollQuota`, `CostBudget`, and
`ResourceUnavailable` map to `BODY-RESOURCE-EXHAUSTED`; the remaining runtime
cancellation kinds map to `BODY-CANCELLED` while retaining their kind. Transport
loss maps directly to `BODY-CLIENT-ABORTED`, not to a synthetic cancellation kind.
The landed 499 value is only the existing web cancellation telemetry representation;
it is neither an HTTP response status nor universal across cancellation kinds.

H1 reuse is allowed only after normal EOF or after the driver reaches explicit EOF
within the 8-frame, 524,288-byte, and 500-ms unread-body budgets. If any budget
expires, framing fails, the total limit is crossed, source state is ambiguous, or
the client aborts, the H1 connection closes.

H2 normal EOF completes the stream. Early consumer drop resets the affected stream;
while reset completion is pending, at most 8 frames and 524,288 DATA octets may be
accepted and discarded. Exhausting either bound, a connection-scoped failure, or
failed stream cleanup closes the connection. Reuse also requires valid connection
state.

Handlers can consume or drop their body. They cannot declare a connection reusable.

## Stable error mapping

The artifact fixes nine mapping identifiers and tags each as pre-body, open-body,
or both. Pre-body mappings never imply that a body obligation existed:

- `BODY-LIMIT-EXCEEDED` maps existing limit variants to 413 when safely writable,
  followed by bounded H1 drain-or-close or the legal H2 cancel/reset action;
- `BODY-FRAMING-INVALID` maps current length, transfer, chunk, ambiguity, trailer
  policy, trailer-size, header syntax, and invalid header name/value variants to 400;
- `BODY-CANCELLED` has no synthetic response status; the existing 499 value remains
  scoped to the landed web telemetry representation;
- `BODY-REQUEST-DEADLINE` preserves the existing `ASUP-E501` semantics and 503
  response when writable;
- `BODY-RESOURCE-EXHAUSTED` retains poll-quota, cost-budget, or resource-unavailable
  cancellation identity and maps to 503 when safely writable;
- `BODY-SOURCE-DISCONNECTED` has no distinct landed variant and is a terminal
  internal producer failure, never EOF;
- `BODY-CLIENT-ABORTED` records an outcome without synthesizing a response;
- `BODY-ACCOUNTING-OVERFLOW` fails before enqueue; and
- `BODY-CONSUMER-DROPPED` invokes protocol cleanup but also lacks a distinct landed
  variant.

`HttpError::BodyChannelClosed` remains ambiguous: producer-side code uses it for
missing sender and full/disconnected sends, and the partial BODY-2 scaffold also
uses it for premature or unclassified producer termination. The receiver no longer
turns that termination into EOF, but the contracted typed source-disconnect and
consumer-drop outcomes are still required before live integration.

These IDs are artifact-level contract identifiers. `ASUP-E501` is an already-live
request-deadline code; this foundation allocates no new ASUP code. Before later
source code emits another incoming-body failure to agents or operators, that change
must allocate an owner-reviewed `ASUP-E5xx` registry row, add its standard
documentation page, and emit the exact leading token.

## Telemetry contract

The protocol driver is the single terminal-event emitter and carries request-region
correlation plus the final cleanup/reuse decision. The event is
`http.incoming_body.terminal`. It records request, connection, stream, and region
identity; protocol and terminal state; declared length and contributing limit
sources; received, delivered, queued, unread, discarded, and drained bytes/frames;
queue high-water marks; cleanup budgets/result; reuse decision/reason; obligation
outcome; mapping ID; and cancellation kind. One body obligation is created and
resolved or aborted exactly once, after cleanup when cleanup is required. Timing
comes from request/runtime time and logical ticks, never a body-local wall clock.
Telemetry must not record body content or raw authorization/cookie headers.

Every schema key is present. Null is distinct from zero: H1 has a null `stream_id`;
chunked or otherwise unknown length has a null `declared_length`; unknown unread
transport bytes have null `unread_bytes`; normal EOF has a null `mapping_id`;
non-cancellation has a null `cancel_kind`; and drain fields are null unless drain
or reset actually ran. Every non-EOF body terminal or cleanup-handoff receipt uses
exactly one mapping ID.

At the final receipt, admitted DATA bytes equal delivered plus discarded DATA bytes,
and admitted trailers satisfy the same equation under the protocol-specific metric.
Received frames equal delivered plus discarded frames. Refused bytes and frames are
tracked separately and excluded from received totals; drain counters are subsets of
discarded counters. Transport bytes not yet admitted are not invented, and an
unknown unread amount remains null.

No incoming-body terminal receipt is present in the live path today.

## Direct migration order

The project does not require a compatibility shim. Later children should cut over
the real types directly in this order:

1. connect the H1 producer to the single body handoff;
2. connect H2 DATA and trailer production to per-stream handoff;
3. replace buffered web request ownership and update handler/router boundaries;
4. adapt JSON, form, and raw extractors to bounded collection through `Limited`;
5. keep Multipart as bounded whole-body collection under its retained 16 MiB cap
   until BODY-5 lands its incremental state machine;
6. make retry middleware reject a live non-replayable body or consume a bounded
   replayable body prepared before first dispatch;
7. add terminal telemetry and registry-backed diagnostics; and
8. run focused protocol, cancellation, limit, and integration evidence.

BODY-2 explicitly owns H1 ingress. No current BODY child explicitly owns H2
incoming-body integration, so that implementation must receive an explicit owner
before any live H2 integration claim is made.

## Evidence status and no-claim boundary

The artifact parses, its source hashes and anchors were checked statically, and a
Rust contract accompanies this document. The BODY-2 inline cases listed above were
authored but not run. No executable project command was run for this packet.

Therefore this packet does not claim:

- that handlers receive a streaming request body;
- lower memory use or improved performance;
- protocol, cancellation, or runtime correctness;
- live H1/H2 interoperability;
- a configured or landed H2 connection-level aggregate body budget;
- response streaming or incremental multipart parsing;
- broad server-stack or workspace health;
- an allocated ASUP error code; or
- completion of the foundation or BODY-2 bead.

The bead must remain open until the remaining ownership, queue-budget, cleanup,
live-dispatch, and executable-validation work is admitted and recorded.

<!-- END SERVER INCOMING BODY CONTRACT -->
