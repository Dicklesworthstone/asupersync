//! V2 persistence retains strict I/O poll order, including pending attempts.

use super::super::OrderedEffect;
use super::super::gate::{Entry, OrderTape};
use super::super::pending::PendingRequest;
use super::{
    CHECKSUM, ENTRY_BYTES, HEADER, MAGIC, OrderedRecordedSession, OrderedSessionBytes,
    OrderedSessionDecodeLimits, OrderedSessionTapeError, RecordedSession, add, decode_entry,
    encode_entry, mul, put, size,
};
use crate::io::replay::IoOperation;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

pub(super) const VERSION: u32 = 2;
const DOMAIN: &[u8] = b"asupersync.ordered-session.v2";
// V1's 17 bytes + pending flag + extent + slice count + SHA-256.
const POLL_ENTRY_BYTES: usize = 66;

fn checksum(bytes: &[u8]) -> [u8; CHECKSUM] {
    let mut hash = Sha256::new();
    hash.update(DOMAIN);
    hash.update(bytes);
    hash.finalize().into()
}

fn decode_poll_entry(bytes: &[u8]) -> Result<Entry, OrderedSessionTapeError> {
    if bytes.len() != POLL_ENTRY_BYTES {
        return Err(OrderedSessionTapeError::Truncated);
    }
    let mut entry = decode_entry(&bytes[..ENTRY_BYTES])?;
    match bytes[ENTRY_BYTES] {
        0 if bytes[18..].iter().all(|byte| *byte == 0) => {}
        1 => {
            let OrderedEffect::Io(operation) = entry.effect else {
                return Err(OrderedSessionTapeError::Format);
            };
            let mut request = PendingRequest {
                extent: size(&bytes[18..26])?,
                slices: size(&bytes[26..34])?,
                digest: [0; 32],
            };
            request.digest.copy_from_slice(&bytes[34..66]);
            if !request.valid_for(operation) {
                return Err(OrderedSessionTapeError::Format);
            }
            entry.pending = Some(request);
        }
        _ => return Err(OrderedSessionTapeError::Format),
    }
    Ok(entry)
}

pub(super) fn encode(
    tape: &OrderedRecordedSession,
    max_encoded_bytes: usize,
) -> Result<OrderedSessionBytes, OrderedSessionTapeError> {
    if !tape.order.poll_aware || !tape.order.covers(&tape.components) {
        return Err(OrderedSessionTapeError::Coverage);
    }
    let overhead = add(HEADER + CHECKSUM, mul(tape.effects(), POLL_ENTRY_BYTES)?)?;
    let remaining = max_encoded_bytes
        .checked_sub(overhead)
        .ok_or(OrderedSessionTapeError::Limit("encoded bytes"))?;
    let components = tape.components.to_canonical_bytes(remaining)?;
    let length = add(overhead, components.as_ref().len())?;
    let mut out = OrderedSessionBytes(Vec::new());
    out.0
        .try_reserve_exact(length)
        .map_err(|_| OrderedSessionTapeError::Allocation)?;
    out.0.extend_from_slice(MAGIC);
    out.0.extend_from_slice(&VERSION.to_le_bytes());
    put(&mut out.0, components.as_ref().len())?;
    put(&mut out.0, tape.effects())?;
    out.0.extend_from_slice(components.as_ref());
    for entry in &tape.order.entries {
        encode_entry(&mut out.0, entry)?;
        if let Some(request) = &entry.pending {
            out.0.push(1);
            put(&mut out.0, request.extent)?;
            put(&mut out.0, request.slices)?;
            out.0.extend_from_slice(&request.digest);
        } else {
            out.0
                .extend_from_slice(&[0; POLL_ENTRY_BYTES - ENTRY_BYTES]);
        }
    }
    let mut digest = checksum(&out.0);
    out.0.extend_from_slice(&digest);
    digest.zeroize();
    debug_assert_eq!(out.0.len(), length);
    Ok(out)
}

pub(super) fn decode(
    bytes: &[u8],
    limits: OrderedSessionDecodeLimits,
) -> Result<OrderedRecordedSession, OrderedSessionTapeError> {
    if bytes.len() > limits.max_encoded_bytes {
        return Err(OrderedSessionTapeError::Limit("encoded bytes"));
    }
    if bytes.len() < HEADER + CHECKSUM {
        return Err(OrderedSessionTapeError::Truncated);
    }
    if &bytes[..8] != MAGIC || bytes[8..12] != VERSION.to_le_bytes() {
        return Err(OrderedSessionTapeError::Format);
    }
    let component_len = size(&bytes[12..20])?;
    let count = size(&bytes[20..28])?;
    if count > limits.max_effects {
        return Err(OrderedSessionTapeError::Limit("effects"));
    }
    if mul(count, std::mem::size_of::<Entry>())? > limits.max_order_bytes {
        return Err(OrderedSessionTapeError::Limit("order bytes"));
    }
    if component_len > limits.components.max_encoded_bytes {
        return Err(OrderedSessionTapeError::Limit("component bytes"));
    }
    let order_start = add(HEADER, component_len)?;
    let body_end = add(order_start, mul(count, POLL_ENTRY_BYTES)?)?;
    let length = add(body_end, CHECKSUM)?;
    if bytes.len() < length {
        return Err(OrderedSessionTapeError::Truncated);
    }
    if bytes.len() > length {
        return Err(OrderedSessionTapeError::TrailingData);
    }
    let mut expected = checksum(&bytes[..body_end]);
    let matches = expected.as_slice() == &bytes[body_end..];
    expected.zeroize();
    if !matches {
        return Err(OrderedSessionTapeError::Checksum);
    }
    let raw_order = &bytes[order_start..body_end];
    let mut pending_write_bytes = 0usize;
    for chunk in raw_order.chunks_exact(POLL_ENTRY_BYTES) {
        let entry = decode_poll_entry(chunk)?;
        if let Some(request) = &entry.pending {
            if request.slices > limits.components.io.capture.max_vectored_slices {
                return Err(OrderedSessionTapeError::Limit("pending vectored slices"));
            }
            if matches!(
                entry.effect,
                OrderedEffect::Io(IoOperation::Write | IoOperation::WriteVectored)
            ) {
                pending_write_bytes = add(pending_write_bytes, request.extent)?;
                if pending_write_bytes > limits.components.io.capture.max_write_bytes {
                    return Err(OrderedSessionTapeError::Limit("pending write bytes"));
                }
            }
        }
    }
    // Validate all pending metadata/hash-work bounds BEFORE nested allocation.
    // Hashes are compared to the consumer's offered bytes during replay, not to
    // invented write payloads. This checksum does not authenticate a producer.
    let components =
        RecordedSession::from_canonical_bytes(&bytes[HEADER..order_start], limits.components)?;
    let mut order = OrderTape {
        entries: Vec::new(),
        poll_aware: true,
    };
    order
        .entries
        .try_reserve_exact(count)
        .map_err(|_| OrderedSessionTapeError::Allocation)?;
    for chunk in raw_order.chunks_exact(POLL_ENTRY_BYTES) {
        order.entries.push(decode_poll_entry(chunk)?);
    }
    if !order.covers(&components) {
        return Err(OrderedSessionTapeError::Coverage);
    }
    Ok(OrderedRecordedSession { components, order })
}

#[cfg(test)]
mod tests;
