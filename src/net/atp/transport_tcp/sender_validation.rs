//! Bind peer control decisions and completion claims to this TCP transfer.
//!
//! These checks reject stale negotiation and internally inconsistent receipts.
//! A peer that fabricates consistent claims is still untrusted: this adds no
//! authenticated transport, signed proof, or independent remote-storage audit.

use super::{
    DeltaObjectRequest, DeltaWireMode, ReceiveReceipt, TransferManifest, TransportError,
};

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
            if manifest.delta_manifest.is_none() {
                return Err(TransportError::Frame(
                    "receiver requested delta without sender manifest".into(),
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
mod tests {
    use super::*;
    use crate::net::atp::transport_common::{DeltaManifestWire, DeltaObjectRequest};

    fn manifest(with_delta: bool) -> TransferManifest {
        TransferManifest {
            transfer_id: "t".into(),
            root_name: "r".into(),
            is_directory: true,
            total_bytes: 0,
            merkle_root_hex: "11".repeat(32),
            metadata_root_hex: None,
            directory_metadata: None,
            entries: Vec::new(),
            delta_manifest: with_delta.then(|| DeltaManifestWire {
                schema: "schema".into(),
                tree_id: "tree".into(),
                chunk_size: 4096,
                total_size_bytes: 0,
                merkle_root_hex: "22".repeat(32),
                chunks: Vec::new(),
            }),
        }
    }

    fn full_request(manifest: &TransferManifest) -> DeltaObjectRequest {
        DeltaObjectRequest::full(
            manifest
                .delta_manifest
                .as_ref()
                .map_or("", |delta| delta.merkle_root_hex.as_str()),
            None,
            "fallback",
        )
    }

    fn receipt() -> ReceiveReceipt {
        ReceiveReceipt {
            committed: true,
            bytes_received: 0,
            files: 0,
            sha_ok: true,
            merkle_ok: true,
            symbols_accepted: 0,
            feedback_rounds: 0,
            decode_count: 0,
            decode_micros: 0,
            reason: None,
            committed_paths: Vec::new(),
        }
    }

    #[test]
    fn request_root_is_bound_to_sent_delta_manifest() {
        for with_delta in [false, true] {
            let manifest = manifest(with_delta);
            let request = full_request(&manifest);
            validate_request(&manifest, &request).unwrap();
            let mut wrong = request;
            wrong.sender_merkle_root_hex = "ff".repeat(32);
            assert!(validate_request(&manifest, &wrong).is_err());
        }
    }

    #[test]
    fn noop_requires_matching_roots_and_no_missing_data() {
        let manifest = manifest(true);
        let mut request = full_request(&manifest);
        request.mode = DeltaWireMode::AlreadyInSync;
        request.receiver_merkle_root_hex = Some(request.sender_merkle_root_hex.clone());
        validate_request(&manifest, &request).unwrap();

        request.missing_bytes = 1;
        assert!(validate_request(&manifest, &request).is_err());
    }

    #[test]
    fn full_mode_rejects_range_instructions() {
        let manifest = manifest(true);
        let mut request = full_request(&manifest);
        request.missing_chunks.push(
            manifest
                .delta_manifest
                .as_ref()
                .and_then(|delta| delta.chunks.first())
                .cloned()
                .unwrap_or_else(|| crate::net::atp::transport_common::DeltaChunkWire {
                    index: 0,
                    entry_index: 0,
                    rel_path: "x".into(),
                    entry_offset: 0,
                    stream_offset: 0,
                    size_bytes: 1,
                    content_id_hex: "00".repeat(32),
                }),
        );
        assert!(validate_request(&manifest, &request).is_err());
    }

    #[test]
    fn receipt_requires_integrity_flags_and_exact_counts() {
        let manifest = manifest(false);
        validate_receipt(&manifest, 0, &receipt()).unwrap();

        let mut bad = receipt();
        bad.sha_ok = false;
        assert!(validate_receipt(&manifest, 0, &bad).is_err());

        let mut bad = receipt();
        bad.bytes_received = 1;
        assert!(validate_receipt(&manifest, 0, &bad).is_err());

        let mut bad = receipt();
        bad.files = 1;
        assert!(validate_receipt(&manifest, 0, &bad).is_err());
    }

    #[test]
    fn negative_receipt_preserves_peer_reason() {
        let manifest = manifest(false);
        let mut bad = receipt();
        bad.committed = false;
        bad.reason = Some("per-entry SHA-256 mismatch".into());
        assert!(matches!(
            validate_receipt(&manifest, 0, &bad),
            Err(TransportError::Integrity(message))
                if message == "per-entry SHA-256 mismatch"
        ));
    }
}
