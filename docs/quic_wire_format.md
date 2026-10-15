# QUIC frame wire format (ATP-over-QUIC data plane)

> Bead: `asupersync-arq-quic-epic-b0k8qo.9.6` ("H6"). Conformance harness:
> [`tests/quic_frame_codec_wire_conformance.rs`](../tests/quic_frame_codec_wire_conformance.rs).
> Source of truth: [`src/net/atp/protocol/quic_frames.rs`](../src/net/atp/protocol/quic_frames.rs).

This document specifies the transport-frame wire format that the native QUIC
data plane (`quic_native`) encodes and decodes. It is the byte-level contract
the conformance harness pins; if the codec changes, the harness fails and this
doc must be updated in lockstep.

## Varints (RFC 9000 §16)

Every length, identifier, and most numeric fields are QUIC variable-length
integers. The two most-significant bits of the first byte select the size class:

| First-byte prefix | Total bytes | Value range |
|-------------------|-------------|-------------|
| `0b00` (`0x00`)   | 1           | `0 .. 63` |
| `0b01` (`0x40`)   | 2           | `64 .. 16383` |
| `0b10` (`0x80`)   | 4           | `16384 .. 2³⁰−1` |
| `0b11` (`0xC0`)   | 8           | `2³⁰ .. 2⁶²−1` |

The harness pins each size-class boundary (`0, 63, 64, 16383, 16384, 2³⁰−1,
2³⁰, 2⁶²−1`) on a varint field and asserts the exact encoded length.

## Supported frame types

The codec (`QuicFrame` / `QuicFrameType`) implements the bounded set below.
Frame types not in this table — including `NEW_TOKEN` (`0x07`),
`NEW_CONNECTION_ID` (`0x18`), and `RETIRE_CONNECTION_ID` (`0x19`) — are **not
decoded** and fail closed with `QuicFrameError::UnknownFrameType`; decoding never
panics on arbitrary input.

| Code point(s) | Frame | Wire layout (after the type varint) |
|---------------|-------|-------------------------------------|
| `0x00`        | PADDING | a run of `0x00` bytes; decode collapses consecutive zeros into `Padding { length }` |
| `0x01`        | PING | (empty) |
| `0x02`        | ACK | `largest_acked`, `ack_delay`, `ack_range_count`, `first_ack_range`, then `ack_range_count` × (`gap`, `ack_range_length`) |
| `0x03`        | ACK+ECN | as `0x02`, then `ect0`, `ect1`, `ecn_ce` |
| `0x04`        | RESET_STREAM | `stream_id`, `error_code`, `final_size` |
| `0x05`        | STOP_SENDING | `stream_id`, `error_code` |
| `0x06`        | CRYPTO | `offset`, `length`, then `length` data bytes |
| `0x08..=0x0f` | STREAM | `stream_id`, [`offset` if OFF], [`length` if LEN], then data. Flag bits on the type byte: `0x04` OFF, `0x02` LEN, `0x01` FIN |
| `0x10`        | MAX_DATA | `maximum_data` |
| `0x11`        | MAX_STREAM_DATA | `stream_id`, `maximum_stream_data` |
| `0x12`/`0x13` | MAX_STREAMS | `maximum_streams` (bidi `0x12` / uni `0x13`) |
| `0x14`        | DATA_BLOCKED | `maximum_data` |
| `0x15`        | STREAM_DATA_BLOCKED | `stream_id`, `maximum_stream_data` |
| `0x16`/`0x17` | STREAMS_BLOCKED | `maximum_streams` (bidi `0x16` / uni `0x17`) |
| `0x1a`        | PATH_CHALLENGE | 8 raw bytes (no length prefix) |
| `0x1b`        | PATH_RESPONSE | 8 raw bytes (no length prefix) |
| `0x1c`        | CONNECTION_CLOSE (QUIC) | `error_code`, `frame_type`, `reason_length`, reason bytes |
| `0x1d`        | CONNECTION_CLOSE (app) | `error_code`, `reason_length`, reason bytes |
| `0x1e`        | HANDSHAKE_DONE | (empty) |
| `0x30`/`0x31` | DATAGRAM (RFC 9221) | `0x31` = explicit `length` prefix then payload (self-delimiting); `0x30` = payload runs to end of packet. The encoder always emits `0x31`. |

### STREAM frame flag bits

The STREAM type byte is `0x08` plus optional flags:

```
0x08 | (OFF ? 0x04 : 0) | (LEN ? 0x02 : 0) | (FIN ? 0x01 : 0)
```

The encoder sets LEN whenever the payload is non-empty (so the frame is
self-delimiting and can be followed by other frames). A STREAM frame with no LEN
bit consumes the rest of the packet, so it must be the last frame.

### CONNECTION_CLOSE forms

The QUIC form (`0x1c`) carries the triggering `frame_type`; the application form
(`0x1d`) omits it. `QuicFrame::ConnectionClose { frame_type: Some(..) }` encodes
as `0x1c`; `None` encodes as `0x1d`.

## Error model (fail closed)

Decoding returns `Result<Option<QuicFrame>, QuicFrameError>`:

* `Ok(None)` — the buffer was empty (clean end of packet payload);
* `Ok(Some(frame))` — a frame was parsed and the cursor advanced;
* `Err(QuicFrameError::UnexpectedEof)` — a field or declared payload ran past the
  end of the buffer (no over-allocation: `remaining()` is checked before copying);
* `Err(QuicFrameError::UnknownFrameType(code))` — an unsupported type byte;
* `Err(QuicFrameError::PayloadTooLarge { size })` / `InvalidFormat(..)` /
  `VarInt(..)` — other malformed inputs.

The decoder is total over arbitrary bytes: it never panics and always either
makes forward progress or returns an error (see
[`tests/quic_frame_decode_robustness.rs`](../tests/quic_frame_decode_robustness.rs)).

## RaptorQ-over-QUIC symbol envelope

A single RaptorQ symbol is carried inside one QUIC DATAGRAM frame (RFC 9221). The
`transport_quic` adapter (`asupersync-arq-quic-epic-b0k8qo.2`) frames it with the
header below — implemented by
[`src/net/atp/transport_quic/symbol_envelope.rs`](../src/net/atp/transport_quic/symbol_envelope.rs)
(`QuicSymbolEnvelope`) and pinned by
[`tests/atp_quic_symbol_envelope_conformance.rs`](../tests/atp_quic_symbol_envelope_conformance.rs).
The schema mirrors the proven `transport_rq` UDP symbol datagram so the
RaptorQ-over-QUIC and RaptorQ-over-UDP planes share the same symbol-routing
fields; only the magic differs (`"ATQS"` vs `transport_rq`'s `"ATRQ"`) so a
datagram misdelivered from the wrong transport fails closed instead of being
misparsed.

| Offset | Size | Field | Notes |
|--------|------|-------|-------|
| 0  | 4  | magic         | `0x41545153` (`"ATQS"`) |
| 4  | 8  | transfer_tag  | `u64`; demuxes transfers multiplexed on a reused connection |
| 12 | 4  | entry         | `u32`; manifest entry index |
| 16 | 1  | sbn           | `u8`; RaptorQ source block number |
| 17 | 4  | esi           | `u32`; RaptorQ encoding symbol id |
| 21 | 1  | repair        | `u8` ∈ {0, 1}; 0 = source symbol, 1 = repair symbol |
| 22 | 2  | payload_len   | `u16`; symbol payload length |
| 24 | 32 | auth_tag      | optional; present iff the receiver requires per-symbol auth |
| .. | N  | payload       | exactly `payload_len` bytes |

The header is 24 bytes (`ENVELOPE_HEADER_LEN`), or 56 bytes
(`AUTH_ENVELOPE_HEADER_LEN`) with the authentication tag. `decode` is total and
**fails closed**: a wrong magic (`BadMagic`), a short buffer (`TooShort`), a
declared length that does not match the datagram (`LengthMismatch` — the contract
is exact-length, so trailing bytes are rejected), an out-of-range repair flag
(`InvalidRepairFlag`), or an auth-posture mismatch (the 32 tag bytes are counted
as payload, so the length check rejects it) all return a typed error and never
panic; `encode` fails closed (`PayloadTooLarge`) on a payload larger than the
`u16` length field.

The B2/B3 sender/receiver coroutines (`asupersync-arq-quic-epic-b0k8qo.2.2` /
`.2.3`) map a `crate::types::symbol::Symbol` to/from these fields and call
`encode` / `decode`. The conformance harness pins the golden header layout,
round-trip across source/repair and ±auth, the empty and `u16::MAX` payload
boundaries, every fail-closed negative, and metamorphic field-sensitivity.

### Canonical symbol-envelope vector

The H6 conformance harness also pins this authenticated vector so the optional
tag offset cannot drift:

| Field | Value |
|-------|-------|
| `magic` | `ATQS` |
| `transfer_tag` | `0x0102030405060708` |
| `entry` | `0x0a0b0c0d` |
| `sbn` | `0x0e` |
| `esi` | `0x0f101112` |
| `repair` | `1` |
| `payload_len` | `2` |
| `auth_tag` | `00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f` |
| `payload` | ASCII `rq` |

Hex bytes:

```text
41 54 51 53 01 02 03 04 05 06 07 08 0a 0b 0c 0d
0e 0f 10 11 12 01 00 02 00 01 02 03 04 05 06 07
08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17
18 19 1a 1b 1c 1d 1e 1f 72 71
```
