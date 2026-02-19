# EXISTING_QUIC_HTTP3_STRUCTURE

## Purpose

This document captures the protocol structure and behavioral contract needed to implement native QUIC + HTTP/3 in Asupersync, without inheriting executor/runtime assumptions from external stacks.

## Primary Normative Sources

- RFC 9000 (QUIC transport)
- RFC 9001 (QUIC-TLS)
- RFC 9002 (loss detection and congestion control)
- RFC 9114 (HTTP/3)
- RFC 9204 (QPACK)

## Implemented Native Scope Snapshot

## Core transport model (`net::quic_core`)

1. Variable-length integer codec (QUIC varint, up to 2^62-1)
2. Connection ID type (0..=20 bytes)
3. Packet number representation (u64 storage, truncated wire widths)
4. Packet header codecs:
   - Long header: Initial (plus type envelope)
   - Short header: 1-RTT shape
5. Transport parameter codec:
   - Known parameter decoding/encoding
   - unknown parameter preservation for forward compatibility

## Stream/transport runtime model (`net::quic_native`)

1. TLS crypto-level progression (`Initial` → `Handshake` → `OneRtt`) and handshake confirmation gate
2. Key-update and peer key-phase transition handling
3. Connection lifecycle (`Idle`/`Handshaking`/`Established`/`Draining`/`Closed`)
4. ACK processing with packet-number ranges, packet/time-threshold loss detection, PTO backoff
5. Congestion-window state tracking (cwnd/ssthresh) with explicit send-admissibility check
6. Stream table with:
   - local/remote stream lifecycle
   - per-stream and connection-level flow control
   - out-of-order receive reassembly
   - STOP_SENDING / STOP_RECEIVING / RESET_STREAM / final-size invariants
   - round-robin writable stream selection

## HTTP/3 model (`http::h3_native`)

1. HTTP/3 frame and SETTINGS codecs
2. Control stream protocol checks (SETTINGS-first, duplicate guard, GOAWAY tracking)
3. Request stream state machine (HEADERS/DATA/trailers ordering)
4. Unidirectional stream type registry (control/push/qpack-encoder/qpack-decoder)
5. Static-only QPACK policy enforcement + static-table planning helpers for request/response heads

## Required invariants

- Varint encoding length must match value range.
- Decode must reject truncated buffers and impossible forms.
- Connection IDs longer than 20 bytes are invalid.
- Header decode must preserve packet-number byte width.
- Transport parameters must round-trip unknown entries byte-for-byte.
- Stream reassembly must only advance contiguous receive offset and preserve final-size constraints.
- Connection and stream flow control must reject overrun deterministically.
- HTTP/3 control/push/QPACK stream typing must reject duplicate or mismapped stream usage.

## Intentional deferments

- Header protection and payload encryption backend binding
- Retry and version-negotiation packet full-path handling
- Full wire-level QPACK encoder/decoder stream instruction layer
- Interop capture suite and deterministic lab-runtime packet-fault scenarios

## Existing Repository Signals

- `src/net/quic/` and `src/http/h3/` exist as prior experiment surfaces.
- `Cargo.toml` intentionally does not expose production QUIC/H3 features today.
- Current task is native-first core extraction and implementation, not dependency reenabling.

## Behavioral Contract for the Native Core

The Phase 1 core should be:

1. Pure and deterministic over byte slices.
2. Runtime-agnostic (no async executor assumptions).
3. Memory-safe and explicit in error states.
4. Small enough to fuzz and property-test exhaustively.

## Test Fixture Requirements (for follow-up conformance)

1. Varint boundary fixtures:
   - 0, 63, 64, 16383, 16384, 2^30-1, 2^30, 2^62-1
2. Packet header fixtures:
   - valid Initial/Short forms
   - truncated and malformed headers
3. Transport parameter fixtures:
   - known-only sets
   - mixed known+unknown
   - duplicate and length-corrupt entries

## Output

Native QUIC + HTTP/3 protocol/runtime substrate in:
- `src/net/quic_core/mod.rs`
- `src/net/quic_native/{tls,transport,streams,connection}.rs`
- `src/http/h3_native.rs`
