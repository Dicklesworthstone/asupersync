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

Current matrix evidence (ledger through `MATRIX-235`, 2026-07-10; refresh
`docs/atp_rq_beat_rsync_ledger.md` before citing):

- Nocrypto (`atp-rq-lab` vs tuned rsyncd) is a banked board-level win:
  `MATRIX-212` swept 56 rows (55 valid rows all sha-ok; one benign
  port-collision exclusion) and `MATRIX-231` closed the last clean-path gaps
  (`500M/perfect` 0.881x, `5G/perfect` win); tree/small floors stay
  marginal. The `500M/broken/nocrypto` win (`MATRIX-209`,
  564.77s vs 574.46s) no longer carries a correctness asterisk —
  `MATRIX-230` closed the residual `InconsistentEquations` as spec-expected
  RaptorQ rank deficiency.
- Encrypted (`atp-quic-tls13` vs rsync-over-ssh aes128gcm) is fully measured
  (25/25 cells, `MATRIX-216`) and the lossy sub-board is all-wins
  (`MATRIX-221`). Remaining rsync-favored territory is clean-path large +
  tree-perfect floors, root-caused to sender duty-cycle: ~11% link-bound
  honest ceiling on clean-large, a separate ~1.3-1.6x bound on tree-perfect
  (`MATRIX-232/233`).
- Receiver RSS is bounded (<=18MB at every size; the 5G receiver went
  882MB -> 12MB, `MATRIX-213/216`).
- `MATRIX-235` native-link pacing rework showed large matched-pair gains
  (encrypted `500M/perfect` -19.5%, `50M/perfect` -58%) but had no
  contemporaneous rsync bar; it is a landed improvement, not a banked flip.
- Refuted levers (do not re-chase): receipt-clocked flow-control credit, BBR
  startup shapes, >2MiB window raise, receiver ACK cadence, encrypted-tree
  wakeup reduction (`MATRIX-222..229`, `MATRIX-234`).

Do not generalize board-level nocrypto/lossy wins to encrypted clean-path
large cells or headline "beats rsync everywhere" claims; the duty-cycle
ceiling and shared-box tree noise are documented open bounds.

Since then: v0.4.1 fixed ATP progress Streams to poll with their creation
`Cx` (preserving sender wake registration and cancellation observation); the
July-August commits after the ledger's last entry are correctness/hardening
landings, not new benchmark evidence.

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

`ServiceBuilder` with middleware: timeout, load_shed, concurrency_limit, rate_limit, retry. Optional Tower adapter via `tower` feature.

## Cancel Safety Across the Stack

All networking layers respect:
- Region budgets for reads/writes
- Cancellation drains connections cleanly
- Cancel-safety is operation-specific: atomic datagram sends and covered
  two-phase/adapter surfaces state their guarantees, while partial byte-stream
  operations such as `read_exact`/`write_all` retain their documented
  cancellation boundaries
- Lab runtime substitutes virtual TCP for deterministic network testing
- Two-phase semantics where applicable (send permits on channels)
- Security posture is fail-closed: tampered bytes, wrong cert/hostname, replay,
  and unauthenticated symbol paths must reject before commit.
