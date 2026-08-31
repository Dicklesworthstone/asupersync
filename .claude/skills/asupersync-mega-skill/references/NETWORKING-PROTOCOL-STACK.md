# Networking and Protocol Stack

Asupersync ships native networking from raw sockets through application
protocols. Cancellation behavior is operation-specific: check the concrete
read, write, handshake, close, or drain contract instead of applying a blanket
"cancel-safe stack" label.

## Table of Contents

- [Reactor and I/O](#reactor-and-io)
- [TCP](#tcp)
- [UDP](#udp)
- [Unix Sockets](#unix-sockets)
- [DNS](#dns)
- [WebSocket](#websocket)
- [HTTP/1.1](#http11)
- [HTTP/2](#http2)
- [Connection Pooling](#connection-pooling)
- [Response Compression](#response-compression)
- [TLS](#tls)
- [QUIC and HTTP/3](#quic-and-http3)
- [ATP Object Transfer](#atp-object-transfer)
- [Transport Layer](#transport-layer)
- [Bytes](#bytes)
- [Codec](#codec)
- [gRPC](#grpc)
- [Web Framework](#web-framework)
- [Service Layer](#service-layer)
- [Cancellation and Security Across the Stack](#cancellation-and-security-across-the-stack)

## Reactor and I/O

### Reactor Backends

Source: `src/runtime/reactor/`

The exported reactor contract is narrower than the directory listing. Verify
the live export graph before promising platform parity.

| Export | Platform / role | Current caveat |
|--------|-----------------|----------------|
| `EpollReactor` | Linux primary path | Full shipped readiness/mode surface used by the native runtime |
| `IoUringReactor` | Linux with `io-uring`; intentional `Unsupported` without it | Feature-gated helper path, not a blanket replacement for epoll |
| `KqueueReactor` | BSD-family targets | Rejects `Interest::DISPATCH` and `Interest::PRIORITY` |
| `IocpReactor` | Windows | Currently accepts only `READABLE` / `WRITABLE` |
| `BrowserReactor` | `wasm32` browser contexts | Browser-hosted, capability-bounded, not native socket parity |
| `LabReactor` | Deterministic tests | Lab/runtime proof surface, not production I/O |

Historical or platform-specific files under `src/runtime/reactor/` are not
automatically part of the live public export graph.

### I/O Driver

Source: `src/runtime/io_driver.rs`

- Registrations are RAII-backed; deregistration treats `NotFound` as already-cleaned
- Token slabs are generation-tagged (blocks stale-token wakeups after reuse)
- Unknown tokens logged instead of panic (diagnostics under fault conditions)
- Oneshot waker semantics: reactor disarms interest after each readiness event, stream re-arms explicitly

### epoll Specifics

- Edge-triggered and edge-oneshot modes
- Explicit PRIORITY/HUP/ERROR propagation
- Stale fd/token cleanup on `ENOENT` and closed-fd conditions (including fd-reuse edge cases)

### io_uring Specifics

- Timeout expiry (`ETIME`) handled as timeout, not failure
- Stale completions for deregistered tokens ignored

## TCP

Source: `src/net/tcp/`

- `TcpStream`, `TcpListener`, split reader/writer halves
- Registered with I/O reactor, oneshot waker semantics
- `VirtualTcp` (`src/net/tcp/virtual_tcp.rs`): deterministic in-memory TCP
  analogue for lab tests; it does not prove native reactor or kernel-socket
  behavior
- Driverless Windows embedding waits for a concrete kernel-writable event via a
  private reactor and retains a bounded `WSAENOTCONN` settling floor. External
  executors must not treat early `getpeername()` success as proof that Winsock
  completed the connection.

## UDP

Source: `src/net/udp.rs`

Async UDP with atomic-datagram send semantics: cancelling a pending send does
not partially send a datagram, while cancelling receive can discard a datagram
that arrived concurrently. The public socket methods do not accept `&Cx`;
they consult the current installed `Cx` when available, so do not describe UDP
as an explicit-capability boundary.

## Unix Sockets

Source: `src/net/unix/`

Unix domain sockets with stream and datagram support.

## DNS

Source: `src/net/dns/`

Async DNS resolution with address-family selection.

## WebSocket

Source: `src/net/websocket/`

RFC 6455: handshake, binary/text frames, ping/pong, close frames with status codes. Split reader/writer for concurrent send/receive within same region.

Conformance status: `tests/conformance` keeps both the extension-negotiation
suite and the broader directory-backed RFC 6455 suite live (framing, masking,
control frames, close, error handling, fragmentation) against the production
parser and handshake surfaces. Runtime cancellation/integration behavior is
covered by the focused `tests/e2e_websocket.rs` and `tests/e2e/websocket/`
lanes, not by the byte-level harness alone.

v0.4.4: pending close writes honor the explicit caller `Cx`. Once a Close
frame enters `CloseSent`, explicit-`Cx` close operations return typed
interruption instead of stranding an aborted task on a pending transport
write; the connection owner can fail a partially written close
deterministically.

## HTTP/1.1

Source: `src/http/h1/`

- Chunked transfer encoding
- Connection keep-alive
- Streaming request/response bodies
- Integration with connection pool
- Bodies fail closed on incomplete termination (v0.4.0)
- Streaming request bodies execute under the request-region capability context:
  backpressure waits, cancellation, budgets, and body-channel limits observe
  the request lifetime, not the connection lifetime (v0.4.4)
- Connection reuse after an unread segmented body requires a bounded
  framing-aware drain (explicit frame/byte/time bounds); malformed, truncated,
  over-limit, or cancelled drains close the connection fail-closed (v0.4.4)
- Config: `Http1Config` plus additive `Http1StreamingConfig`
  (`src/http/h1/server.rs`)

## HTTP/2

Source: `src/http/h2/`

- Frame parsing
- HPACK header compression
- Flow control
- Stream multiplexing over single connection

## Connection Pooling

Source: `src/http/pool.rs`

The high-level pooled `http::Client` is an alias of the HTTP/1
`h1::HttpClient`; its pool and keep-alive management are HTTP/1 client
machinery. HTTP/2 has native frame, stream, flow-control, listener, and
connection machinery, but the current source does not wire it into a shared
H1/H2 high-level client pool. Do not claim pooled H2 client support without new
source and execution evidence.

## Response Compression

Source: `src/http/compress.rs`

Response compression middleware. Actual gzip/deflate/Brotli encoding support
requires the `compression` feature even though the layer type is public.

## TLS

Source: `src/tls/`

Wraps `rustls` for TLS 1.2/1.3:

| Feature Flag | Root Certs |
|-------------|------------|
| `tls` | Bring your own |
| `tls-native-roots` | OS trust store |
| `tls-webpki-roots` | Mozilla WebPKI bundle |

TLS handshakes are not cancel-safe. If cancellation interrupts a handshake,
drop the connection rather than trying to reuse it. Once the handshake
completes, reads and writes inherit the cancellation boundaries of the
underlying I/O operations (`src/tls/mod.rs`).

## QUIC and HTTP/3

Source: `src/net/quic_core/`, `src/net/quic_native/`, `src/http/h3_native.rs`

The low-level native modules are public on native targets even without rollout
features. `quic` enables the curated `net::quic` alias; `http3` implies `quic`
and enables the curated `http::h3` alias. These are still
requirement-driven—do not promise generic QUIC/H3 interoperability merely
from module availability.

High-value current anchors:

- native QUIC/TLS handshake and packet protection in `src/net/quic_native/`;
  the native TLS path runs a `rustls::quic` handshake driver with
  in-handshake X.509 chain, hostname, signature, and time checks against
  configured roots — untrusted-root, wrong-hostname, expired-certificate,
  and unverified-identity paths fail closed, and there is deliberately no
  insecure skip-verify default (scope: README QUIC row,
  `docs/quic_atp_threat_model.md`)
- fail-closed replay and anti-amplification tests
- HTTP/3/QPACK under `src/http/h3_native.rs`: default static-only QPACK,
  opt-in dynamic QPACK field-section and instruction-stream state machine
  (support matrix: `artifacts/http3_qpack_support_matrix_v1.json`)
- ATP-over-QUIC/H3 paths under `src/net/atp/`

Native ATP-over-QUIC control frames and the transfer manifest ride the
verified handshake-derived 1-RTT STREAM path; direct single-connection
RaptorQ symbols ride verified 1-RTT DATAGRAM packets and rely on QUIC AEAD
authentication. Non-direct, non-QUIC, or cross-trust RaptorQ symbol planes
retain explicit per-symbol auth posture.

Current fail-closed boundaries to preserve:

- direct QUIC/TLS may use `TransportAuthenticated` symbols only inside the
  verified 1-RTT channel,
- missing symbol authentication is a distinct mode, not a silent downgrade,
- TLS-less native QUIC send paths must fail closed,
- unsupported transport/auth combinations should surface typed `NotImplemented`
  style errors rather than pretending to send.

v0.4.7 tightened the state-mutation order and memory bounds:

- handshake duplicate detection, path state, and RTT/BDP input advance only
  after packet authentication,
- CRYPTO and stream reassembly cap both payload bytes and disjoint range/node
  metadata; a byte cap alone does not stop tiny-fragment amplification,
- limit/conflict rejection occurs before mutating accepted reassembly state,
- ATP validates FIN/final size before duplicate trimming, so a duplicate FIN
  may establish the final offset while a contradiction fails closed.

These are correctness/security properties, not blanket QUIC/H3 interoperability
or performance evidence.

## ATP Object Transfer

Source: `src/net/atp/`, `docs/atp_architecture.md`,
`docs/quic_atp_threat_model.md`, `scripts/atp_bench/`

ATP is governed by matrix evidence, not isolated success. Claims against rsync
must cite current matrix-cell runs with:

- tuned rsync baseline,
- release `atp`,
- crypto-symmetric conditions,
- SHA/tamper fail-closed checks,
- rate-capped links,
- timing plus byte evidence.

Known active frontiers include reliable clean-source streaming, authenticated
control-source frames, QUIC pacing/congestion, large-object clean wins,
delta/resync planning, and no-claim boundaries for cells that remain blocked.

Matrix cells, measurements, and conclusions are volatile. Read
`docs/atp_rq_beat_rsync_ledger.md` and the current benchmark artifacts at the
time of the claim. Preserve their exact scenario, date, baseline, security
mode, validity status, and no-claim boundary. A historical win, source landing,
`sha_ok`, or isolated matched-pair improvement is not evidence that ATP beats
rsync across other sizes, loss regimes, tree workloads, or encryption modes.

Two stable operator rules come from ATP acceptance work: every listen/receive
path needs a bounded accept or idle watchdog, and RQ secrets must travel through
protected input rather than argv, environment dumps, or logs. The watchdog bead
`asupersync-2qas9c` remains open and unshipped. The RQ SSH secret-delivery bead
`asupersync-dax0vn` is closed and shipped in v0.4.9: commit
`515d96e7f` uses bounded protected stdin, removes the key environment from
bootstrap subprocesses, redacts captured output, and fails closed on
stdin-diverting OpenSSH configuration. The legacy `--rq-auth-key-hex` spelling
remains supported; prefer `--rq-auth-key-stdin` for caller-provided secrets.

## Transport Layer

Source: `src/transport/`

Low-level delivery behavior above raw sockets and below protocol clients:

| Module | Purpose |
|--------|---------|
| `router.rs` | Endpoint health, routing state, atomics, RAII connection guards |
| `aggregator.rs` | Multipath symbol intake, dedup windows, reorder handling |
| `sink.rs` | Queued waiters with atomic flags, `Waker::will_wake` dedup |
| `stream.rs` | Queued waiters with explicit wakeup bookkeeping |

Shared channel close paths wake both send and receive waiters (no stranded operations).

## Bytes

Source: `src/bytes/`

Zero-copy buffer types: `Bytes`, `BytesMut`, `Buf`, `BufMut`, and
`BytesCursor`. `Buf::copy_to_bytes` is the public extraction hook; buffer types
with shared backing storage should override it instead of forcing protocol
parsers through temporary `Vec` allocations.

## Codec

Source: `src/codec/`

Encoding/decoding primitives and framing layer. Used by HTTP, WebSocket, gRPC, and database wire protocols.

## gRPC

Source: `src/grpc/`

Native gRPC client/server with health checks. `CallContext::with_cx(...)` for capability-scoped handlers.

## Web Framework

Source: `src/web/`

Router, extractors, middleware, request-region isolation, bounded SSE
(`Sse`/`StreamingSse`). Request-as-region pattern for structured concurrency
per request. Deliberately bounded native primitives, not axum/warp/tower-http
parity (see the README coverage-map paragraph for the exact boundary).

## Service Layer

Source: `src/service/`

`ServiceBuilder` has convenience methods for timeout, load shed, concurrency
limit, rate limit, and retry. Buffer, hedge, load balancing, circuit breaking,
and reconnect exist as explicit composable native layers/services. Optional
Tower adapter via `tower` feature.

## Cancellation and Security Across the Stack

- Propagate region budgets and explicit `Cx` through operations that accept
  them; do not infer a budget check where the API has none.
- Cancellation is operation-specific. Atomic datagrams, partial byte-stream
  reads/writes, TLS handshakes, WebSocket close, request-body drain, and QUIC
  state transitions have different commit and cleanup boundaries.
- A clean drain is a tested property of a concrete operation, not a universal
  consequence of requesting cancellation.
- Use VirtualTcp for deterministic protocol logic, but use native runtime tests
  for reactor, kernel-socket, worker-wakeup, and real transport cancellation.
- Apply two-phase semantics only where an API actually exposes reserve/commit.
- Security-sensitive paths should fail closed on tampered bytes, wrong
  certificate/hostname, replay, or missing authentication; cite the relevant
  protocol test or threat model for the specific claim.
