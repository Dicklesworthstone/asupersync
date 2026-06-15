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

## RaptorQ-over-QUIC symbol envelope (TBD — Phase B)

The application-level framing of a RaptorQ symbol *inside* a DATAGRAM payload —
the symbol header (block id, ESI, manifest correlation, auth tag) — is owned by
the `transport_quic` adapter (Phase B, `asupersync-arq-quic-epic-b0k8qo.2`),
which does not exist yet. It will mirror the `transport_rq` symbol envelope. When
it lands, its schema and a conformance harness for it belong in this document and
alongside the frame harness. Until then this file specifies only the RFC 9000
transport-frame layer that carries those payloads.
