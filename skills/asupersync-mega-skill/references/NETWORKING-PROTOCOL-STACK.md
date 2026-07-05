# Networking and Protocol Stack

Asupersync ships a cancel-safe networking stack from raw sockets through application protocols. Every layer participates in structured concurrency.

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
- `VirtualTcp` (`src/net/tcp/virtual_tcp.rs`): fully in-memory TCP for lab tests, same API, deterministic

## UDP

Source: `src/net/udp.rs`

Async UDP with send/receive and cancellation safety.

## Unix Sockets

Source: `src/net/unix/`

Unix domain sockets with stream and datagram support.

## DNS

Source: `src/net/dns/`

Async DNS resolution with address-family selection.

## WebSocket

Source: `src/net/websocket/`

RFC 6455: handshake, binary/text frames, ping/pong, close frames with status codes. Split reader/writer for concurrent send/receive within same region.

## HTTP/1.1

Source: `src/http/h1/`

- Chunked transfer encoding
- Connection keep-alive
- Streaming request/response bodies
- Integration with connection pool

## HTTP/2

Source: `src/http/h2/`

- Frame parsing
- HPACK header compression
- Flow control
- Stream multiplexing over single connection
- Integration with connection pool

## Connection Pooling

Source: `src/http/pool.rs`

Shared connection pool for HTTP/1.1 and HTTP/2 with keep-alive management.

## Response Compression

Source: `src/http/compress.rs`

Optional response compression middleware.

## TLS

Source: `src/tls/`

Wraps `rustls` for TLS 1.2/1.3:

| Feature Flag | Root Certs |
|-------------|------------|
| `tls` | Bring your own |
| `tls-native-roots` | OS trust store |
| `tls-webpki-roots` | Mozilla WebPKI bundle |

## QUIC and HTTP/3

Source: `src/net/quic_core/`, `src/net/quic_native/`, `src/http/h3_native.rs`

Feature-gated native surfaces are active, but still requirement-driven. Do not
promise generic QUIC/H3 interoperability without checking the exact protocol
need, feature set, and tests.

High-value current anchors:

- native QUIC/TLS handshake and packet protection in `src/net/quic_native/`
- fail-closed X.509, hostname, signature, replay, and anti-amplification tests
- HTTP/3/QPACK bounds and H3 adapter work under `src/http/h3_native.rs`
- ATP-over-QUIC/H3 paths under `src/net/atp/`

Direct native QUIC/TLS paths rely on QUIC AEAD authentication once the verified
1-RTT channel is established. Non-direct, non-QUIC, or cross-trust RaptorQ
symbol paths still need explicit symbol-auth posture.

Current fail-closed boundaries to preserve:

- direct QUIC/TLS may use `TransportAuthenticated` symbols only inside the
  verified 1-RTT channel,
- missing symbol authentication is a distinct mode, not a silent downgrade,
- TLS-less native QUIC send paths must fail closed,
- unsupported transport/auth combinations should surface typed `NotImplemented`
  style errors rather than pretending to send.

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

Current encrypted QUIC frontier (refresh before citing):

- landed zero-copy receive pump, in-place AEAD unprotect, ACK fast path,
  inc-hash-on-receive, bounded sender queues, release-on-ACK retention, and
  delivery-clocked source-stream pacing;
- `Buf::copy_to_bytes` plus `BytesCursor` zero-copy override are now part of the
  protocol hot-path story;
- retransmit-frame coalescing, requeue ordering fixes, and conservative
  QUIC recovery drain-cap tuning landed, but absolute pacer scheduling was
  re-refuted;
- scoped positive claim: `50M/good/encrypted` beats tuned rsync-ssh in current
  evidence, and `5G/perfect/encrypted` completes byte-identical after being
  previously impossible;
- no-claim boundary: `500M/perfect/encrypted` still loses on speed,
  `50M/bad/encrypted` still needs a rate-climb/cliff-recovery mechanism, and
  5G encrypted peak RSS remains a follow-up.

Current RQ/nocrypto frontier (MATRIX-207..211, July 2026):

- `MATRIX-207` landed the convergence-control stack for
  `500M/broken/nocrypto`: arrival-evidence pacing loss, rank-stall congestion
  only when arrivals corroborate wire loss, lower round-0 FEC overhead, sparse
  residual source requests, and expected-loss-aware recommendations. It was
  not banked because the cell reached fail-closed SHA mismatch.
- `MATRIX-208` fixed the decode-integrity root cause by reading FEC seeds from
  the shared staging fragment at shard-absolute offsets. That made the cell
  sha-ok 3/3 but only statistical parity with tuned rsync.
- `MATRIX-209` banked exactly one new ATP win:
  `500M/broken/nocrypto` atp median 564.77s, sha-ok 3/3 plus a confirming
  fourth rep, versus tuned rsync median 574.46s. The winning lever was
  double-buffered encode-ahead in the RQ spray; bounded token-bucket schedule
  credit stayed as hygiene after its speed hypothesis was refuted.
- `MATRIX-211` one-shot packed-member commit batching is a candidate landing
  for tree/small-file commit-write overhead. It needs quiet-box A/B matrix
  evidence before any performance win is claimed.

Do not generalize the RQ `500M/broken/nocrypto` win to encrypted-large,
tree-small, cross-trust symbol safety, or whole-matrix success.

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

Router, extractors, middleware, request-region isolation. Request-as-region pattern for structured concurrency per request.

## Service Layer

Source: `src/service/`

`ServiceBuilder` with middleware: timeout, load_shed, concurrency_limit, rate_limit, retry. Optional Tower adapter via `tower` feature.

## Cancel Safety Across the Stack

All networking layers respect:
- Region budgets for reads/writes
- Cancellation drains connections cleanly
- Lab runtime substitutes virtual TCP for deterministic network testing
- Two-phase semantics where applicable (send permits on channels)
- Security posture is fail-closed: tampered bytes, wrong cert/hostname, replay,
  and unauthenticated symbol paths must reject before commit.
