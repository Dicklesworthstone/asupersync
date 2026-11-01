//! Explicitly negotiated chunk reuse over the native QUIC control stream.
//!
//! Fixed and authenticated CDC manifests share the bounded transfer mechanics.
//! The existing fixed manifest and bound request/proof envelopes stay unchanged.
//! Only peers that opt in and verify the manifest capability may select this
//! mode. Its raw ObjectData payload is chunk index, target offset, then bytes;
//! the v1 receive window is fixed so old Hello/request JSON needs no new fields.

use super::{
    AuthMode, AuthenticatedSymbol, AuthenticationTag, ContentId, DeltaChunkWire,
    DeltaObjectRequest, DeltaWireMode, Frame, FrameType, ProtocolVersion,
    QUIC_DELTA_MAX_MANIFEST_CHUNKS, QuicDeltaProof, QuicDeltaSessionContext,
    QuicTransportError, ReceiveReceipt, SecurityContext, TransferManifest,
    quic_decode_delta_root, quic_delta_manifest_entry,
};
#[cfg(feature = "tls")]
use super::{
    BTreeMap, CasChunkRef, Cx, Digest, EntryDigest, Path, PathBuf, PersistentChunkManifest,
    QuicConfig, Sha256, flat_merkle_root_from_digests,
};
use serde::{Deserialize, Serialize};

pub(super) const OFFER_EXTENSION: u16 = 0x5152;
const OFFER_KEY: &[u8] = b"atp-quic-fixed-delta-chunks-256k-v1";
const CDC_OFFER_KEY: &[u8] = b"atp-quic-cdc-delta-chunks-64k-v1";
const TREE_OFFER_KEY: &[u8] = b"atp-quic-whole-file-tree-delta-v1";
const SELECTOR: &str = "authenticated_fixed_delta_chunks_v1";

fn offer_key(manifest: &TransferManifest) -> &'static [u8] {
    if super::tree_delta::is_tree(manifest) {
        TREE_OFFER_KEY
    } else if super::delta_cdc::is_cdc(manifest) {
        CDC_OFFER_KEY
    } else {
        OFFER_KEY
    }
}

fn selector(manifest: &TransferManifest) -> &'static str {
    if super::tree_delta::is_tree(manifest) {
        super::tree_delta::SELECTOR
    } else if super::delta_cdc::is_cdc(manifest) {
        super::delta_cdc::SELECTOR
    } else {
        SELECTOR
    }
}
pub(super) const DATA_FRAGMENT_BYTES: usize = 64 * 1024;
#[cfg(feature = "tls")]
pub(super) const STREAM_WINDOW_BYTES: u64 = 256 * 1024;
const DATA_HEADER_BYTES: usize = 12;

pub(super) fn advertise(
    frame: &mut Frame,
    context: &SecurityContext,
    session: QuicDeltaSessionContext,
    manifest: &TransferManifest,
) -> Result<(), QuicTransportError> {
    if context.mode() != AuthMode::Strict {
        return Err(QuicTransportError::Config(
            "QUIC changed chunks require strict delta authentication".to_string(),
        ));
    }
    // The existing canonical symbol commits both nonces, destination, transfer
    // and the complete manifest. A separate key commits this exact capability.
    let symbol = super::quic_delta_manifest_auth_symbol(session, manifest)?;
    let tag = context.derive_context(offer_key(manifest)).sign_symbol_tag(&symbol);
    frame.header.extensions.insert(OFFER_EXTENSION, tag.as_bytes().to_vec());
    Ok(())
}

pub(super) fn offered(
    frame: &Frame,
    context: &SecurityContext,
    session: QuicDeltaSessionContext,
    manifest: &TransferManifest,
) -> Result<bool, QuicTransportError> {
    let Some(bytes) = frame.header.extensions.get(&OFFER_EXTENSION) else {
        return Ok(false);
    };
    let tag = bytes.as_slice().try_into().map_err(|_| {
        QuicTransportError::HandshakeRejected(
            "malformed QUIC changed-chunk capability proof".to_string(),
        )
    })?;
    let symbol = super::quic_delta_manifest_auth_symbol(session, manifest)?;
    let mut authenticated = AuthenticatedSymbol::from_parts(
        symbol, AuthenticationTag::from_bytes(tag),
    );
    if context.mode() != AuthMode::Strict
        || context.derive_context(offer_key(manifest))
            .verify_authenticated_symbol(&mut authenticated).is_err()
        || !authenticated.is_verified()
    {
        return Err(QuicTransportError::HandshakeRejected(
            "QUIC changed-chunk capability authentication failed".to_string(),
        ));
    }
    Ok(true)
}

pub(super) fn validate_request(
    manifest: &TransferManifest,
    request: &DeltaObjectRequest,
) -> Result<(), QuicTransportError> {
    let tree = super::tree_delta::is_tree(manifest);
    if tree {
        super::tree_delta::validate_manifest(manifest)?;
    }
    let delta = manifest.delta_manifest.as_ref().ok_or_else(|| {
        QuicTransportError::Control("changed-chunk request has no delta manifest".to_string())
    })?;
    if (!tree && quic_delta_manifest_entry(manifest).is_none())
        || request.mode != DeltaWireMode::DeltaChunks
        || request.fallback_reason.as_deref() != Some(selector(manifest))
        || request.sender_merkle_root_hex != delta.merkle_root_hex
        || request.receiver_merkle_root_hex.is_none()
        || request.shared_chunks == 0
        || request.missing_bytes >= delta.total_size_bytes
        || request.stale_chunks > QUIC_DELTA_MAX_MANIFEST_CHUNKS
    {
        return Err(QuicTransportError::Control(
            "malformed QUIC changed-chunk request".to_string(),
        ));
    }
    quic_decode_delta_root(
        request.receiver_merkle_root_hex.as_deref().expect("checked receiver root"),
        "QUIC changed-chunk receiver root",
    )?;
    let mut last_index = None;
    let mut missing_bytes = 0u64;
    for chunk in &request.missing_chunks {
        let index = usize::try_from(chunk.index)
            .map_err(|_| QuicTransportError::Control("delta chunk index overflow".to_string()))?;
        if delta.chunks.get(index) != Some(chunk)
            || last_index.is_some_and(|last| chunk.index <= last)
        {
            return Err(QuicTransportError::Control(
                "QUIC changed-chunk request is not an ordered manifest subset".to_string(),
            ));
        }
        last_index = Some(chunk.index);
        missing_bytes = missing_bytes.checked_add(chunk.size_bytes).ok_or_else(|| {
            QuicTransportError::Control("changed-chunk byte count overflow".to_string())
        })?;
    }
    let missing_count = u64::try_from(request.missing_chunks.len())
        .map_err(|_| QuicTransportError::Control("changed-chunk count overflow".to_string()))?;
    if missing_bytes != request.missing_bytes
        || missing_count.checked_add(request.shared_chunks)
            != u64::try_from(delta.chunks.len()).ok()
    {
        return Err(QuicTransportError::Control(
            "QUIC changed-chunk accounting does not cover the manifest".to_string(),
        ));
    }
    Ok(())
}

#[cfg(feature = "tls")]
pub(super) struct ReusableRange {
    pub(super) path: PathBuf,
    pub(super) offset: u64,
    pub(super) size: u64,
}

#[cfg(feature = "tls")]
pub(super) struct ReceivePlan {
    pub(super) request: DeltaObjectRequest,
    pub(super) baseline: PathBuf,
    // Repeated target chunks may use the same verified baseline range.
    pub(super) reusable: BTreeMap<String, ReusableRange>,
}

#[cfg(feature = "tls")]
fn persistent_manifest(
    manifest: &TransferManifest,
) -> Result<PersistentChunkManifest, QuicTransportError> {
    let delta = manifest.delta_manifest.as_ref().ok_or_else(|| {
        QuicTransportError::Control("changed chunks require a delta manifest".to_string())
    })?;
    let chunks = delta.chunks.iter().map(|chunk| {
        Ok(CasChunkRef {
            index: chunk.index,
            byte_offset: chunk.stream_offset,
            size_bytes: chunk.size_bytes,
            content_id: ContentId::new(quic_decode_delta_root(
                &chunk.content_id_hex, "delta chunk content id",
            )?),
        })
    }).collect::<Result<Vec<_>, QuicTransportError>>()?;
    PersistentChunkManifest::new(delta.tree_id.clone(), chunks)
        .map_err(|error| QuicTransportError::Control(format!("build sender chunk manifest: {error}")))
}

#[cfg(feature = "tls")]
pub(super) fn io_error(cx: &Cx, error: std::io::Error) -> QuicTransportError {
    if cx.checkpoint().is_err() {
        QuicTransportError::Cancelled
    } else {
        error.into()
    }
}

/// Called only after the challenged manifest and capability are authenticated.
/// The baseline index and one read buffer are bounded independently of the
/// destination file's size. Content-id/length diffing reuses moved chunks too.
#[cfg(feature = "tls")]
pub(super) async fn plan(
    cx: &Cx,
    dest_dir: &Path,
    config: &QuicConfig,
    manifest: &TransferManifest,
) -> Result<Option<ReceivePlan>, QuicTransportError> {
    if super::tree_delta::is_tree(manifest) {
        return super::tree_delta::plan(cx, dest_dir, config, manifest).await;
    }
    cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
    let delta = manifest.delta_manifest.as_ref().ok_or_else(|| {
        QuicTransportError::Control("cannot plan changed chunks without a manifest".to_string())
    })?;
    let Some(entry) = quic_delta_manifest_entry(manifest) else {
        return Ok(None);
    };
    let baseline = super::quic_safe_base_for_root_name(dest_dir, &manifest.root_name)?;
    super::reject_quic_destination_symlink_prefix(&baseline, &baseline).await?;
    let metadata = match crate::fs::symlink_metadata(&baseline).await {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io_error(cx, error)),
    };
    let chunk_size = u64::try_from(delta.chunk_size)
        .map_err(|_| QuicTransportError::Control("delta chunk size overflow".to_string()))?;
    let content_defined = super::delta_cdc::is_cdc(manifest);
    if chunk_size == 0 || !metadata.is_file() || metadata.len() == 0
        || metadata.len() > config.max_transfer_bytes
        || (content_defined && !super::delta_cdc::size_may_fit(metadata.len()))
        || (!content_defined
            && metadata.len().div_ceil(chunk_size) > QUIC_DELTA_MAX_MANIFEST_CHUNKS)
    {
        return Ok(None);
    }
    let file = crate::fs::File::open(&baseline).await.map_err(|error| io_error(cx, error))?;
    let mut reader = super::delta_cdc::ChunkReader::new(file, delta.chunk_size, content_defined);
    let mut chunks = Vec::new();
    let mut reusable = BTreeMap::new();
    let mut offset = 0u64;
    let mut sha256 = Sha256::new();
    let mut whole_content_id = ContentId::streaming();
    loop {
        cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
        let Some(bytes) = reader.next_chunk().await.map_err(|error| io_error(cx, error))? else {
            break;
        };
        let size_bytes = u64::try_from(bytes.len())
            .map_err(|_| QuicTransportError::Control("baseline chunk size overflow".to_string()))?;
        let end = offset.checked_add(size_bytes)
            .ok_or_else(|| QuicTransportError::Control("baseline size overflow".to_string()))?;
        if end > metadata.len()
            || u64::try_from(chunks.len()).unwrap_or(u64::MAX) >= QUIC_DELTA_MAX_MANIFEST_CHUNKS
        {
            return Ok(None);
        }
        sha256.update(bytes);
        whole_content_id.update(bytes);
        let content_id = ContentId::from_bytes(bytes);
        reusable.entry(content_id.to_hex()).or_insert(ReusableRange {
            path: baseline.clone(), offset, size: size_bytes,
        });
        chunks.push(CasChunkRef {
            index: u32::try_from(chunks.len())
                .map_err(|_| QuicTransportError::Control("baseline chunk count overflow".to_string()))?,
            byte_offset: offset,
            size_bytes,
            content_id,
        });
        offset = end;
    }
    if offset != metadata.len() {
        return Ok(None);
    }
    super::reject_quic_destination_symlink_prefix(&baseline, &baseline).await?;
    let receiver_tree = flat_merkle_root_from_digests(&[EntryDigest {
        rel_path: entry.rel_path.clone(),
        size: offset,
        content_id: crate::atp::object::ObjectId::content(whole_content_id.finalize()),
        content_sha256: sha256.finalize().into(),
    }]);
    let receiver = PersistentChunkManifest::new(receiver_tree, chunks).map_err(|error| {
        QuicTransportError::Control(format!("build QUIC baseline manifest: {error}"))
    })?;
    let diff = persistent_manifest(manifest)?.diff_against(&receiver);
    if diff.shared_chunks == 0 || diff.missing_bytes >= delta.total_size_bytes {
        return Ok(None);
    }
    let request = DeltaObjectRequest {
        mode: DeltaWireMode::DeltaChunks,
        fallback_reason: Some(selector(manifest).to_string()),
        sender_merkle_root_hex: delta.merkle_root_hex.clone(),
        receiver_merkle_root_hex: Some(receiver.merkle_root.to_hex()),
        missing_bytes: diff.missing_bytes,
        shared_chunks: diff.shared_chunks,
        stale_chunks: u64::try_from(diff.stale_chunks.len()).unwrap_or(u64::MAX),
        missing_chunks: diff.missing_chunks.iter().map(|chunk| {
            delta.chunks.get(chunk.index as usize).cloned().ok_or_else(|| {
                QuicTransportError::Control("chunk diff selected an absent manifest entry".to_string())
            })
        }).collect::<Result<Vec<_>, _>>()?,
    };
    validate_request(manifest, &request)?;
    Ok(Some(ReceivePlan { request, baseline, reusable }))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Complete {
    pub(super) bytes_sent: u64,
    pub(super) chunks_sent: u64,
}

pub(super) fn data_frame(
    chunk: &DeltaChunkWire,
    relative_offset: u64,
    bytes: &[u8],
) -> Result<Frame, QuicTransportError> {
    let offset = chunk.entry_offset.checked_add(relative_offset)
        .ok_or_else(|| QuicTransportError::Control("changed-chunk offset overflow".to_string()))?;
    let mut payload = Vec::with_capacity(DATA_HEADER_BYTES + bytes.len());
    payload.extend_from_slice(&chunk.index.to_be_bytes());
    payload.extend_from_slice(&offset.to_be_bytes());
    payload.extend_from_slice(bytes);
    Frame::new(ProtocolVersion::CURRENT, FrameType::ObjectData, payload)
        .map_err(|error| QuicTransportError::Frame(error.to_string()))
}

pub(super) fn checked_data<'a>(
    frame: &'a Frame,
    chunk: &DeltaChunkWire,
    relative_offset: u64,
) -> Result<&'a [u8], QuicTransportError> {
    let payload = frame.payload();
    if frame.frame_type() != FrameType::ObjectData
        || payload.len() < DATA_HEADER_BYTES
        || !frame.header.extensions.is_empty()
    {
        return Err(QuicTransportError::Frame(
            "expected one raw changed-chunk ObjectData frame".to_string(),
        ));
    }
    let index = u32::from_be_bytes(payload[..4].try_into().expect("chunk index width"));
    let offset = u64::from_be_bytes(payload[4..DATA_HEADER_BYTES].try_into().expect("chunk offset width"));
    let bytes = &payload[DATA_HEADER_BYTES..];
    let remaining = chunk.size_bytes.checked_sub(relative_offset).ok_or_else(|| {
        QuicTransportError::Integrity("changed-chunk data exceeds the requested chunk".to_string())
    })?;
    let expected = remaining.min(DATA_FRAGMENT_BYTES as u64);
    if index != chunk.index || chunk.entry_offset.checked_add(relative_offset) != Some(offset)
        || expected == 0 || u64::try_from(bytes.len()).ok() != Some(expected)
    {
        return Err(QuicTransportError::Integrity(
            "changed-chunk data differs from the next requested manifest range".to_string(),
        ));
    }
    Ok(bytes)
}

pub(super) fn verify_bytes(
    chunk: &DeltaChunkWire,
    bytes: &[u8],
    label: &str,
) -> Result<(), QuicTransportError> {
    if u64::try_from(bytes.len()).ok() != Some(chunk.size_bytes)
        || ContentId::from_bytes(bytes).to_hex() != chunk.content_id_hex
    {
        return Err(QuicTransportError::Integrity(format!(
            "{label} differs from its committed chunk",
        )));
    }
    Ok(())
}

pub(super) fn validate_complete(
    complete: &Complete,
    request: &DeltaObjectRequest,
) -> Result<(), QuicTransportError> {
    if complete.bytes_sent != request.missing_bytes
        || complete.chunks_sent != u64::try_from(request.missing_chunks.len()).unwrap_or(u64::MAX)
    {
        return Err(QuicTransportError::Integrity(
            "QUIC changed-chunk completion count mismatch".to_string(),
        ));
    }
    Ok(())
}

pub(super) fn validate_proof(
    proof: QuicDeltaProof,
    session: QuicDeltaSessionContext,
    manifest: &TransferManifest,
    request: &DeltaObjectRequest,
) -> Result<ReceiveReceipt, QuicTransportError> {
    super::validate_quic_delta_proof_binding(&proof, session, manifest)?;
    if !proof.receipt.committed {
        return Err(QuicTransportError::Integrity(
            super::validate_quic_delta_refusal(proof, session, manifest)?,
        ));
    }
    let receipt = proof.receipt;
    let files = if super::tree_delta::is_tree(manifest) {
        super::manifest_logical_files(manifest)
    } else {
        1
    };
    let expected_paths = usize::try_from(files).unwrap_or(usize::MAX);
    if !receipt.sha_ok || !receipt.merkle_ok
        || receipt.bytes_received != request.missing_bytes || receipt.files != files
        || receipt.symbols_accepted != 0 || receipt.feedback_rounds != 0
        || receipt.decode_count != 0 || receipt.decode_micros != 0
        || receipt.reason.is_some() || receipt.committed_paths.len() != expected_paths
        || receipt.committed_paths.iter().any(String::is_empty)
        || receipt.committed_paths.iter().collect::<std::collections::BTreeSet<_>>().len()
            != expected_paths
    {
        return Err(QuicTransportError::Integrity(
            "receiver did not prove the complete QUIC changed-chunk reconstruction".to_string(),
        ));
    }
    Ok(receipt)
}

#[cfg(test)]
#[path = "delta_chunks_tests.rs"]
mod tests;
