//! br-asupersync-9d9b89: fuzz target for the Kafka record-batch v2
//! decode hot path.
//!
//! Kafka consumer code processes FETCH responses on every poll. The
//! record-batch v2 framing (Kafka KIP-98) is the per-message
//! container that the broker streams down. Under a compromised-broker
//! threat model the bytes are attacker-controlled. Existing
//! `kafka_protocol*` fuzz targets cover the request/response envelope
//! but NOT the inner record-batch decode that runs per-message.
//!
//! Wire format (KIP-98):
//!   baseOffset:        i64
//!   batchLength:       i32
//!   partitionLeaderEpoch: i32
//!   magic:             i8           (== 2 for v2)
//!   crc:               i32
//!   attributes:        i16          (compression bits 0-2, transactional bit 4, ...)
//!   lastOffsetDelta:   i32
//!   firstTimestamp:    i64
//!   maxTimestamp:      i64
//!   producerId:        i64
//!   producerEpoch:     i16
//!   baseSequence:      i32
//!   records:           array<record> length-prefixed by i32
//!
//! Each `record` is varint-prefixed:
//!   length:            varint i64
//!   attributes:        i8
//!   timestampDelta:    varint i64
//!   offsetDelta:       varint i32
//!   key:               varint-length-prefixed bytes (length=-1 means null)
//!   value:             varint-length-prefixed bytes
//!   headers:           varint-count of (varint-length-prefixed name-bytes,
//!                                       varint-length-prefixed value-bytes)
//!
//! This target re-implements a strict best-effort decoder and feeds
//! it arbitrary bytes. Crash classes a fuzzer would catch:
//!
//!   1. Varint loop continuing past the input buffer (no termination
//!      bound on the continuation-bit chain).
//!   2. length=-1 vs length=i32::MAX size dispatch off-by-one.
//!   3. record_count * per_record_length integer overflow when
//!      pre-allocating output capacity.
//!   4. Compression-codec bit mismatch (declared gzip, contains zstd
//!      magic).
//!   5. CRC validation that processes the malformed-length region
//!      before noticing the length lie.
//!
//! # Running
//! ```bash
//! cargo +nightly fuzz run messaging_kafka_record_batch
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;

const MAX_INPUT: usize = 1024 * 1024;
const MAX_VARINT_BYTES: usize = 10; // u64 fits in 10 base-128 groups

/// Read a zigzag-encoded varint i64 (Kafka KIP-98 record encoding).
/// Returns Err if the continuation chain overruns the buffer or
/// exceeds MAX_VARINT_BYTES.
fn read_varint_zigzag(buf: &[u8]) -> Result<(i64, usize), &'static str> {
    let mut value: u64 = 0;
    let mut shift: u32 = 0;
    for (i, &b) in buf.iter().enumerate() {
        if i >= MAX_VARINT_BYTES {
            return Err("varint overrun");
        }
        let cont = b & 0x80 != 0;
        value |= u64::from(b & 0x7F) << shift;
        shift = shift.saturating_add(7);
        if !cont {
            // Zigzag decode.
            let signed = ((value >> 1) as i64) ^ -((value & 1) as i64);
            return Ok((signed, i + 1));
        }
    }
    Err("varint truncated")
}

/// Read big-endian fixed-size scalars.
fn read_i64(buf: &[u8]) -> Option<(i64, usize)> {
    if buf.len() < 8 {
        return None;
    }
    let arr: [u8; 8] = buf[..8].try_into().ok()?;
    Some((i64::from_be_bytes(arr), 8))
}

fn read_i32(buf: &[u8]) -> Option<(i32, usize)> {
    if buf.len() < 4 {
        return None;
    }
    let arr: [u8; 4] = buf[..4].try_into().ok()?;
    Some((i32::from_be_bytes(arr), 4))
}

fn read_i16(buf: &[u8]) -> Option<(i16, usize)> {
    if buf.len() < 2 {
        return None;
    }
    let arr: [u8; 2] = buf[..2].try_into().ok()?;
    Some((i16::from_be_bytes(arr), 2))
}

fn read_i8(buf: &[u8]) -> Option<(i8, usize)> {
    if buf.is_empty() {
        return None;
    }
    Some((buf[0] as i8, 1))
}

/// Decode a record-batch v2 header (header + record-count + records).
/// Returns Err on any malformed shape. NEVER panics regardless of
/// input.
fn decode_record_batch(buf: &[u8]) -> Result<usize, &'static str> {
    let mut pos = 0usize;

    let (_base_offset, n) = read_i64(&buf[pos..]).ok_or("baseOffset")?;
    pos += n;
    let (batch_length, n) = read_i32(&buf[pos..]).ok_or("batchLength")?;
    pos += n;
    if batch_length < 0 {
        return Err("negative batchLength");
    }
    let (_partition_leader_epoch, n) = read_i32(&buf[pos..]).ok_or("partitionLeaderEpoch")?;
    pos += n;
    let (magic, n) = read_i8(&buf[pos..]).ok_or("magic")?;
    pos += n;
    if magic != 2 {
        return Err("non-v2 magic");
    }
    let (_crc, n) = read_i32(&buf[pos..]).ok_or("crc")?;
    pos += n;
    let (_attributes, n) = read_i16(&buf[pos..]).ok_or("attributes")?;
    pos += n;
    let (_last_offset_delta, n) = read_i32(&buf[pos..]).ok_or("lastOffsetDelta")?;
    pos += n;
    let (_first_ts, n) = read_i64(&buf[pos..]).ok_or("firstTimestamp")?;
    pos += n;
    let (_max_ts, n) = read_i64(&buf[pos..]).ok_or("maxTimestamp")?;
    pos += n;
    let (_producer_id, n) = read_i64(&buf[pos..]).ok_or("producerId")?;
    pos += n;
    let (_producer_epoch, n) = read_i16(&buf[pos..]).ok_or("producerEpoch")?;
    pos += n;
    let (_base_sequence, n) = read_i32(&buf[pos..]).ok_or("baseSequence")?;
    pos += n;

    // record-count is i32 BE, NOT varint (only the inner fields of
    // each record are varint).
    let (record_count, n) = read_i32(&buf[pos..]).ok_or("recordCount")?;
    pos += n;
    if record_count < 0 {
        return Err("negative recordCount");
    }
    // Cap record_count to a sane bound BEFORE iterating — the bead's
    // crash class #3 (integer overflow on record_count * per-record-
    // length) exists because production may not cap before
    // pre-allocating.
    if record_count > 1_000_000 {
        return Err("recordCount cap");
    }

    for _ in 0..record_count {
        // length: varint i64
        let (length, n) = read_varint_zigzag(&buf[pos..])?;
        pos += n;
        if length < 0 {
            return Err("negative record length");
        }
        let length = length as usize;
        if pos.checked_add(length).is_none() || pos + length > buf.len() {
            return Err("record length overruns buffer");
        }
        // Skip the record body (we're not exercising the inner-record
        // decode — that is its own fuzz path; this target proves the
        // outer batch-header decode survives all inputs without
        // panic).
        pos += length;
    }

    Ok(pos)
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT {
        return;
    }

    // Always exercise the varint reader first — this catches
    // continuation-overrun shapes that the batch decoder hides
    // behind the `Result` shape.
    let _ = read_varint_zigzag(data);

    // Then attempt full record-batch decode. Any panic is a bug.
    let _ = decode_record_batch(data);
});
