# Security Review and Threat Model

Status: draft
Last updated: 2026-02-01
Owner: bd-2827

## Scope

This document covers security risks and mitigations for the Asupersync runtime and
its protocol stack, with focus on:

- Runtime core (scheduler, cancellation, obligations, trace)
- TLS integration and crypto hygiene
- HTTP/1.1, HTTP/2, gRPC, WebSocket protocol handling
- Messaging clients (Redis, NATS, Kafka)
- Deterministic lab runtime and replay tooling

## Non-goals

- OS kernel security, CPU micro-architecture attacks
- Supply-chain policy beyond basic dependency hygiene
- Full formal verification (tracked separately)

## Assets and Security Goals

Primary assets and goals:

- Correctness invariants: structured concurrency, no orphan tasks, no obligation leaks
- Cancellation correctness: request -> drain -> finalize, bounded cleanup
- Protocol safety: no uncontrolled memory/CPU growth, fail-safe parsing
- Integrity of traces and diagnostics (no corrupted replay data)
- Confidentiality of TLS sessions and protected data in transit
- Deterministic testing: reproducible traces, no ambient randomness

## Trust Boundaries

- Untrusted network input: all protocol decoders, stream parsers, and framing
- Runtime boundary: user code is untrusted and may misbehave
- Cancellation boundary: drop-based cancellation is not trusted to be safe
- External dependencies: crates with unsafe internals may contain vulnerabilities

## Attacker Models

- Remote unauthenticated attacker: malformed protocol inputs, DoS via resource exhaustion
- Remote authenticated attacker: protocol misuse, request smuggling, stream abuse
- Local attacker (same host): abuse of file paths, permissions, or local sockets
- Malicious library user: misuse of APIs, intentional invariant violations

## Threats and Mitigations by Component

### Runtime Core

Threats:
- Task starvation or scheduler deadlock (lost wakeups, cancel lane monopoly)
- Obligation leaks causing resource retention
- Budget bypass leading to unbounded work

Mitigations:
- Scheduler invariants and tests (lost wakeup, duplicate scheduling)
- Obligation tracking (reserve/commit/abort) with leak detection
- Budget propagation and checkpoint enforcement

### Cancellation Protocol

Threats:
- Silent drops of in-flight effects
- Unbounded cleanup on cancel

Mitigations:
- Two-phase effects for critical primitives
- Cancellation protocol: request -> drain -> finalize
- Lab runtime oracles: quiescence, obligation leak, loser drain

### TLS

Threats:
- Weak cipher negotiation or missing ALPN
- Invalid certificate acceptance
- Missing client auth options (mTLS)

Mitigations:
- rustls integration with explicit configuration
- ALPN negotiation required for HTTP/2 and gRPC
- Separate tasks for TLS conformance and mTLS

### HTTP/2

Threats:
- HPACK memory/CPU exhaustion
- Incomplete CONTINUATION sequences (connection-level DoS)
- PUSH_PROMISE abuse (resource leaks, stream ID exhaustion)
- Stream dependency violations

Mitigations:
- HPACK bounds, Huffman validation, recursion limits
- Continuation deadline and header block size caps
- Strict stream state machine checks
- Tests for flow control, SETTINGS, and GOAWAY

### gRPC

Threats:
- Oversized frames or metadata
- Stream reset abuse
- Inconsistent status mapping

Mitigations:
- Frame size caps and strict header validation
- Explicit status mapping from Outcome to gRPC codes
- Conformance and interop tests

### WebSocket

Threats:
- Incomplete close handshake leading to resource leaks
- Missing masking validation for client -> server frames
- Fragmentation abuse

Mitigations:
- RFC 6455 close handshake implementation
- Masking enforcement
- Message size caps and fragmentation limits

### Messaging Clients (Redis/NATS/Kafka)

Threats:
- Unbounded buffer growth in codecs
- Protocol state desync on partial frames
- Cancel-sensitive operations leaking resources

Mitigations:
- Incremental decoders with size limits
- Connection pool health checks
- Cancel-correct send/recv semantics

## Security Invariants (Must Hold)

- No unbounded allocations from untrusted input
- Protocol parsers are total: reject invalid input without panics
- All obligations resolved before task completion
- Cancellation does not drop committed effects
- Trace and replay must be deterministic and tamper-evident

## Testing Plan (Security-Focused)

Unit tests:
- Parser boundary tests for HTTP/2, HPACK, WebSocket, gRPC
- Obligation leak detection on task completion
- TLS configuration validation

Fuzz tests:
- HTTP/2 frame sequences
- HPACK header blocks
- WebSocket frame parser
- gRPC frame decoder

E2E tests:
- Protocol conformance suites where available
- Cancellation under load with structured logging

Lab runtime tests:
- Deterministic scheduling + oracle verification for security invariants

## Security Test Matrix (Current Coverage)

The table below maps key security invariants to existing tests and fuzz targets.
Gaps are listed in the "Open Items" section.

| Invariant / Threat | Current Coverage | Notes |
| --- | --- | --- |
| Structured concurrency, region close => quiescence | `tests/region_lifecycle_conformance.rs`, `tests/integration_e2e.rs` | Region + task lifecycle invariants |
| No obligation leaks | `tests/integration_e2e.rs`, `tests/io_e2e.rs`, `tests/e2e/combinator/cancel_correctness/obligation_cleanup.rs` | Obligation safety across join/race + I/O |
| Losers are drained after races | `tests/e2e/combinator/cancel_correctness/loser_drain.rs`, `tests/e2e_combinator.rs` | Race cancellation + drain behavior |
| Cancellation protocol (request -> drain -> finalize) | `tests/cancellation_conformance.rs`, `tests/cancel_attribution.rs`, `tests/integration_e2e.rs` | Cancellation correctness in core flows |
| Deterministic lab runtime | `tests/lab_determinism.rs`, `tests/lab_execution.rs`, `tests/dpor_exploration.rs` | Determinism + schedule exploration |
| HTTP/1 parsing safety | `tests/http_verification.rs`, `fuzz/fuzz_targets/http1_request.rs`, `fuzz/fuzz_targets/http1_response.rs` | Parser bounds + fuzzing |
| HTTP/2 frame safety | `src/http/h2/connection.rs` (unit tests), `fuzz/fuzz_targets/http2_frame.rs` | Frame-level robustness |
| HPACK decoding safety | `fuzz/fuzz_targets/hpack_decode.rs` | Size bounds + parser totality |
| WebSocket correctness | `tests/e2e_websocket.rs`, `src/web/debug.rs` (stub) | Protocol tests, more needed |
| gRPC framing and status safety | `tests/grpc_verification.rs` | Mapping + framing checks |
| Network primitives hardening | `tests/net_tcp.rs`, `tests/net_udp.rs`, `tests/net_unix.rs`, `tests/net_verification.rs` | Nonblocking and error paths |
| File system safety | `tests/fs_verification.rs`, `tests/io_cancellation.rs` | File ops + cancel behavior |
| Security primitives | `tests/security/*.rs` | Auth/context/key/tag/property tests |
| Trace/replay integrity | `tests/replay_debugging.rs` | Trace format + replay sanity |

## Per-Protocol Size Limits (Current Defaults)

Documented size limits should be enforced at the codec or framing layer and be
configurable where appropriate. Current defaults:

- HTTP/1.1:
  - `src/http/h1/codec.rs`: `DEFAULT_MAX_HEADERS_SIZE` = 64 KiB, `DEFAULT_MAX_BODY_SIZE` = 16 MiB
  - `src/http/h1/codec.rs`: `MAX_HEADERS` = 128, `MAX_REQUEST_LINE` = 8192 bytes
  - `src/http/h1/client.rs`: same defaults for client decode
- HTTP/2:
  - `src/http/h2/settings.rs`: `DEFAULT_MAX_FRAME_SIZE` = 16384
  - `src/http/h2/settings.rs`: `DEFAULT_MAX_HEADER_LIST_SIZE` = 65536
  - `src/http/h2/settings.rs`: `DEFAULT_CONTINUATION_TIMEOUT_MS` = 5000
  - `src/http/h2/stream.rs`: `HEADER_FRAGMENT_MULTIPLIER` = 4 (fragment limit = 4x header list)
  - `src/http/h2/connection.rs`: HPACK decoder max header list size set from settings
- gRPC:
  - `src/grpc/codec.rs`: `DEFAULT_MAX_MESSAGE_SIZE` = 4 MiB
  - `src/grpc/server.rs` + `src/grpc/client.rs`: `max_recv_message_size` / `max_send_message_size` default 4 MiB
- WebSocket:
  - `src/net/websocket/frame.rs`: `FrameCodec::DEFAULT_MAX_PAYLOAD_SIZE` = 16 MiB
  - `src/net/websocket/client.rs`: `WebSocketConfig` defaults: `max_frame_size` = 16 MiB, `max_message_size` = 64 MiB

## Fuzzing in CI (Current Targets)

Fuzz targets are documented in `fuzz/README.md` and wired into
`.github/workflows/fuzz.yml` for scheduled runs:

- `fuzz_http1_request` (HTTP/1 request parser)
- `fuzz_http1_response` (HTTP/1 response parser)
- `fuzz_hpack_decode` (HPACK decoder)
- `fuzz_http2_frame` (HTTP/2 frame parser)
- `fuzz_interest_flags` (reactor interest flags)

CI should run at least the critical targets with a bounded time budget, e.g.:

```
cargo +nightly fuzz run fuzz_http2_frame -- -max_total_time=300
cargo +nightly fuzz run fuzz_hpack_decode -- -max_total_time=300
```

Missing fuzz targets to add: WebSocket frame parser and gRPC message framing.

## Threat Model Checklist for New Protocol Modules

- Define explicit size limits (frame/header/message) with safe defaults
- Validate all state transitions; reject invalid sequences early
- Bound allocations derived from untrusted input
- Ensure cancellation-safe cleanup for in-flight operations
- Add deterministic lab tests covering edge cases
- Add a fuzz target + seeds and wire into CI
- Emit structured trace events for protocol errors (no stdout/stderr)

## Observability Requirements

- Emit structured trace events for security-relevant failures
- Record reasons for protocol errors (without leaking secrets)
- Never write to stdout/stderr in core runtime paths

## Open Items (bd-2827)

- Add fuzz targets for WebSocket frame parsing and gRPC message framing
  - Tracked in `bd-1p2e` (WebSocket conformance + fuzz)
  - Tracked in `bd-27sd` (gRPC conformance + interop)
