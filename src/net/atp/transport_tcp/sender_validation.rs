//! Bind peer control decisions and completion claims to this TCP transfer.
//!
//! These checks reject stale negotiation and internally inconsistent receipts.
//! A peer that fabricates consistent claims is still untrusted: this adds no
//! authenticated transport, signed proof, or independent remote-storage audit.

use super::{
    DeltaObjectRequest, DeltaWireMode, MAX_FRAME_SIZE, ReceiveReceipt, TransferConfig,
    TransferManifest, TransportError,
};
use std::collections::BTreeSet;

/// Refuse sender buffer sizes that cannot fit an uncompressed ObjectData frame.
/// This runs before source discovery or the first data-sized allocation.
pub(super) fn validate_config(config: &TransferConfig) -> Result<(), TransportError> {
    let frame_limit = usize::try_from(MAX_FRAME_SIZE)
        .unwrap_or(usize::MAX)
        .saturating_sub(12);
    if config.chunk_size == 0 || config.chunk_size > frame_limit {
        return Err(TransportError::Frame(format!(
            "TCP chunk_size {} is outside 1..={frame_limit}",
            config.chunk_size
        )));
    }
    Ok(())
}

/// Validate the peer's selected transfer mode against the exact manifest sent.
pub(super) fn validate_request(
    manifest: &TransferManifest,
    request: &DeltaObjectRequest,
) -> Result<(), TransportError> {
    let expected_root = manifest
        .delta_manifest
        .as_ref()
        .map_or("", |delta| delta.merkle_root_hex.as_str());
    if request.sender_merkle_root_hex != expected_root {
        return Err(TransportError::Frame(
            "ObjectRequest does not name this sender's delta manifest".into(),
        ));
    }

    match request.mode {
        DeltaWireMode::FullObject => {
            if !request.missing_chunks.is_empty() {
                return Err(TransportError::Frame(
                    "full ObjectRequest must not contain missing-chunk descriptors".into(),
                ));
            }
        }
        DeltaWireMode::DeltaChunks => {
            let delta = manifest.delta_manifest.as_ref().ok_or_else(|| {
                TransportError::Frame("receiver requested delta without sender manifest".into())
            })?;
            // The send loop and subsequent receipt check use missing_bytes.
            // Bind it to payload lengths before either can repeat a peer's
            // invented count as independent evidence of what was sent. Count
            // each requested location, even when several have the same content.
            let bytes = request.missing_chunks.iter().try_fold(0_u64, |bytes, chunk| {
                bytes.checked_add(chunk.size_bytes).ok_or_else(|| {
                    TransportError::Frame("delta ObjectRequest byte count overflows u64".into())
                })
            })?;
            if bytes != request.missing_bytes {
                return Err(TransportError::Frame(format!(
                    "delta ObjectRequest declares {} missing bytes but requests {bytes}",
                    request.missing_bytes,
                )));
            }
            if request.missing_chunks.len() > delta.chunks.len() {
                return Err(TransportError::Frame(
                    "delta ObjectRequest contains more chunks than the sender manifest".into(),
                ));
            }
            // Borrow complete wire descriptors instead of cloning peer paths
            // and digests. Index/path/stream-offset edits must not authorize a
            // different descriptor with a coincidentally matching payload key.
            let advertised: BTreeSet<_> = delta.chunks.iter().collect();
            let requested: BTreeSet<_> = request.missing_chunks.iter().collect();
            if requested.len() != request.missing_chunks.len() {
                return Err(TransportError::Frame(
                    "delta ObjectRequest contains duplicate missing chunks".into(),
                ));
            }
            if !requested.is_subset(&advertised) {
                return Err(TransportError::Frame(
                    "delta ObjectRequest asks for a chunk outside the sender manifest".into(),
                ));
            }
        }
        DeltaWireMode::AlreadyInSync => {
            if manifest.delta_manifest.is_none()
                || request.receiver_merkle_root_hex.as_deref() != Some(expected_root)
                || request.missing_bytes != 0
                || !request.missing_chunks.is_empty()
            {
                return Err(TransportError::Frame(
                    "already-in-sync ObjectRequest lacks matching roots or declares missing data"
                        .into(),
                ));
            }
        }
    }
    Ok(())
}

/// Validate that a successful peer receipt is internally consistent with the
/// payload frames this sender actually completed.
pub(super) fn validate_receipt(
    manifest: &TransferManifest,
    bytes_sent: u64,
    receipt: &ReceiveReceipt,
) -> Result<(), TransportError> {
    if !receipt.committed {
        return Err(TransportError::Integrity(
            receipt
                .reason
                .clone()
                .unwrap_or_else(|| "receiver did not commit".to_string()),
        ));
    }
    if !receipt.sha_ok || !receipt.merkle_ok {
        return Err(TransportError::Integrity(
            "receiver claimed commit without successful SHA-256 and Merkle verification".into(),
        ));
    }
    if receipt.bytes_received != bytes_sent {
        return Err(TransportError::Integrity(format!(
            "receiver receipt byte count {} does not match sent byte count {bytes_sent}",
            receipt.bytes_received,
        )));
    }
    let expected_files = u32::try_from(manifest.entries.len())
        .map_err(|_| TransportError::Frame("sender manifest file count exceeds u32::MAX".into()))?;
    if receipt.files != expected_files {
        return Err(TransportError::Integrity(format!(
            "receiver receipt file count {} does not match manifest entry count {expected_files}",
            receipt.files,
        )));
    }
    Ok(())
}

#[cfg(test)]
#[path = "sender_validation_inline_tests.rs"]
mod tests;
