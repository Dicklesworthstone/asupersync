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

## Observability Requirements

- Emit structured trace events for security-relevant failures
- Record reasons for protocol errors (without leaking secrets)
- Never write to stdout/stderr in core runtime paths

## Open Items (bd-2827)

- Add a test matrix mapping security invariants to test files
- Ensure per-protocol fuzz targets exist and run in CI
- Create a threat model checklist for new protocol modules

