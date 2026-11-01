//! Bounded whole-logical-file reuse for native QUIC directory transfers.
//!
//! Packed members keep their original entry offsets. The existing persistent
//! content manifest plans reuse; the native receiver rebuilds every entry in
//! owned staging before ordinary hash, metadata and durability verification.

use super::{
    CasChunkRef, ContentId, DeltaManifestWire, EntryMetadata, FileKind,
    PersistentChunkManifest, QUIC_DELTA_MAX_MANIFEST_CHUNKS, QuicTransportError,
    TransferManifest, quic_decode_delta_root,
};
#[cfg(any(feature = "tls", test))]
use super::{
    AsyncReadExt, AuthMode, AuthenticatedSymbol, AuthenticationTag, Cx,
    DeltaChunkWire, Digest, Frame, FrameType, ObjectId, Path, QuicConfig,
    QuicHello, QuicHelloAck, QuicPreparedSource, SecurityContext, Sha256,
    Symbol, SymbolId, SymbolKind, TransferNonce,
};

pub(super) const MANIFEST_SCHEMA: &str = "asupersync.atp.quic.tree-file-manifest.v1";
pub(super) const DATA_FRAGMENT_BYTES: usize = 64 * 1024;
#[cfg(any(feature = "tls", test))]
pub(super) const SELECTOR: &str = "authenticated_whole_file_tree_delta_v1";
#[cfg(any(feature = "tls", test))]
pub(super) const HELLO_EXTENSION: u16 = 0x5155;
#[cfg(any(feature = "tls", test))]
pub(super) const ACK_EXTENSION: u16 = 0x5156;

pub(super) fn is_tree(manifest: &TransferManifest) -> bool {
    manifest.delta_manifest.as_ref().is_some_and(|delta| delta.schema == MANIFEST_SCHEMA)
}

struct LogicalFile<'a> {
    entry_index: u32,
    rel_path: &'a str,
    entry_offset: u64,
    size: u64,
    #[cfg(any(feature = "tls", test))]
    sha256_hex: &'a str,
}

fn regular(metadata: Option<&EntryMetadata>) -> bool {
    let metadata = metadata.cloned().unwrap_or_default();
    matches!(metadata.file_kind, FileKind::Regular)
        && metadata.hardlink_target.is_none()
        && metadata.symlink_target.is_none()
        && metadata.symlink_target_info.is_none()
}

fn logical_files(manifest: &TransferManifest) -> Result<Vec<LogicalFile<'_>>, QuicTransportError> {
    if !manifest.is_directory || manifest.total_bytes == 0 {
        return Err(QuicTransportError::Source("tree delta requires a nonempty directory transfer".to_string()));
    }
    let mut files = Vec::new();
    for entry in &manifest.entries {
        if entry.members.is_empty() {
            let metadata = entry.metadata.clone().unwrap_or_default();
            if matches!(metadata.file_kind, FileKind::Directory)
                && entry.size == 0
                && metadata.hardlink_target.is_none()
                && metadata.symlink_target.is_none()
                && metadata.symlink_target_info.is_none()
            {
                continue;
            }
            if !regular(entry.metadata.as_ref()) {
                return Err(QuicTransportError::Source("tree delta supports regular files and directories".to_string()));
            }
            if entry.size != 0 {
                files.push(LogicalFile {
                    entry_index: entry.index, rel_path: &entry.rel_path,
                    entry_offset: 0, size: entry.size,
                    #[cfg(any(feature = "tls", test))]
                    sha256_hex: &entry.sha256_hex,
                });
            }
        } else {
            for member in &entry.members {
                if !regular(member.metadata.as_ref()) {
                    return Err(QuicTransportError::Source("tree delta pack contains a non-regular member".to_string()));
                }
                if member.len != 0 {
                    files.push(LogicalFile {
                        entry_index: entry.index, rel_path: &member.rel_path,
                        entry_offset: member.offset, size: member.len,
                        #[cfg(any(feature = "tls", test))]
                        sha256_hex: &member.sha256_hex,
                    });
                }
                if u64::try_from(files.len()).unwrap_or(u64::MAX) > QUIC_DELTA_MAX_MANIFEST_CHUNKS {
                    return Err(QuicTransportError::Source("too many logical files for tree delta".to_string()));
                }
            }
        }
        if u64::try_from(files.len()).unwrap_or(u64::MAX) > QUIC_DELTA_MAX_MANIFEST_CHUNKS {
            return Err(QuicTransportError::Source("too many logical files for tree delta".to_string()));
        }
    }
    if files.is_empty() {
        return Err(QuicTransportError::Source("tree delta has no nonempty logical files".to_string()));
    }
    Ok(files)
}

fn persistent(delta: &DeltaManifestWire) -> Result<PersistentChunkManifest, QuicTransportError> {
    let chunks = delta.chunks.iter().map(|chunk| {
        Ok(CasChunkRef {
            index: chunk.index, byte_offset: chunk.stream_offset, size_bytes: chunk.size_bytes,
            content_id: ContentId::new(quic_decode_delta_root(&chunk.content_id_hex, "tree file content id")?),
        })
    }).collect::<Result<Vec<_>, QuicTransportError>>()?;
    PersistentChunkManifest::new(delta.tree_id.clone(), chunks)
        .map_err(|error| QuicTransportError::Source(format!("invalid tree content manifest: {error}")))
}

/// Called only through the full manifest validator with explicit negotiation.
pub(super) fn validate_manifest(manifest: &TransferManifest) -> Result<(), QuicTransportError> {
    let delta = manifest.delta_manifest.as_ref().ok_or_else(|| {
        QuicTransportError::Source("tree delta manifest is absent".to_string())
    })?;
    if !is_tree(manifest)
        || delta.chunk_size != DATA_FRAGMENT_BYTES
        || delta.tree_id != manifest.merkle_root_hex
        || delta.total_size_bytes != manifest.total_bytes
        || u64::try_from(delta.chunks.len()).unwrap_or(u64::MAX) > QUIC_DELTA_MAX_MANIFEST_CHUNKS
    {
        return Err(QuicTransportError::Source("invalid bounded tree delta envelope".to_string()));
    }
    let files = logical_files(manifest)?;
    if files.len() != delta.chunks.len() {
        return Err(QuicTransportError::Source("tree delta does not cover every nonempty logical file".to_string()));
    }
    let mut offset = 0u64;
    for (position, (file, chunk)) in files.iter().zip(&delta.chunks).enumerate() {
        if usize::try_from(chunk.index).ok() != Some(position)
            || chunk.entry_index != file.entry_index || chunk.rel_path != file.rel_path
            || chunk.entry_offset != file.entry_offset || chunk.size_bytes != file.size
            || chunk.stream_offset != offset
        {
            return Err(QuicTransportError::Source("tree delta file index, path, offset or size mismatch".to_string()));
        }
        offset = offset.checked_add(file.size)
            .ok_or_else(|| QuicTransportError::Source("tree delta size overflow".to_string()))?;
    }
    let planner = persistent(delta)?;
    if offset != manifest.total_bytes || planner.total_size_bytes != offset
        || planner.merkle_root.to_hex() != delta.merkle_root_hex
    {
        return Err(QuicTransportError::Source("tree delta content root or coverage mismatch".to_string()));
    }
    Ok(())
}

#[cfg(any(feature = "tls", test))]
pub(super) fn may_offer(prepared: &QuicPreparedSource) -> bool {
    prepared.entries.len() == prepared.manifest.entries.len()
        && logical_files(&prepared.manifest).is_ok()
}

#[cfg(any(feature = "tls", test))]
pub(super) fn source_for_chunk<'a>(
    prepared: &'a QuicPreparedSource,
    chunk: &DeltaChunkWire,
) -> Result<(&'a Path, u64), QuicTransportError> {
    let source = usize::try_from(chunk.entry_index).ok()
        .and_then(|index| prepared.entries.get(index))
        .ok_or_else(|| QuicTransportError::Source("tree delta source entry is absent".to_string()))?;
    if source.index != chunk.entry_index
        || chunk.entry_offset.checked_add(chunk.size_bytes).is_none_or(|end| end > source.size)
    {
        return Err(QuicTransportError::Source("tree delta range exceeds its prepared source".to_string()));
    }
    Ok((source.abs_path.as_path(), chunk.entry_offset))
}

#[cfg(any(feature = "tls", test))]
fn io_error(cx: &Cx, error: std::io::Error) -> QuicTransportError {
    if cx.checkpoint().is_err() { QuicTransportError::Cancelled } else { error.into() }
}

#[cfg(any(feature = "tls", test))]
async fn read_range(
    cx: &Cx, path: &Path, offset: u64, size: u64, file_size: u64, buffer: &mut [u8],
) -> Result<(ContentId, [u8; 32]), QuicTransportError> {
    cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
    let metadata = crate::fs::symlink_metadata(path).await.map_err(|error| io_error(cx, error))?;
    if !metadata.is_file() || metadata.len() != file_size
        || offset.checked_add(size).is_none_or(|end| end > file_size) || buffer.is_empty()
    {
        return Err(QuicTransportError::Source("tree file changed size or kind during validation".to_string()));
    }
    let mut file = crate::fs::File::open(path).await.map_err(|error| io_error(cx, error))?;
    file.seek(std::io::SeekFrom::Start(offset)).await.map_err(|error| io_error(cx, error))?;
    let mut remaining = size;
    let mut cid = ContentId::streaming();
    let mut sha = Sha256::new();
    while remaining != 0 {
        cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
        let len = usize::try_from(remaining.min(buffer.len() as u64)).unwrap_or(buffer.len());
        file.read_exact(&mut buffer[..len]).await.map_err(|error| io_error(cx, error))?;
        cid.update(&buffer[..len]);
        sha.update(&buffer[..len]);
        remaining -= len as u64;
    }
    let metadata = crate::fs::symlink_metadata(path).await.map_err(|error| io_error(cx, error))?;
    if !metadata.is_file() || metadata.len() != file_size {
        return Err(QuicTransportError::Source("tree file changed size or kind after validation".to_string()));
    }
    Ok((cid.finalize(), sha.finalize().into()))
}

#[cfg(any(feature = "tls", test))]
async fn build_manifest(cx: &Cx, prepared: &QuicPreparedSource) -> Result<DeltaManifestWire, QuicTransportError> {
    let mut delta = DeltaManifestWire {
        schema: MANIFEST_SCHEMA.to_string(), tree_id: prepared.manifest.merkle_root_hex.clone(),
        chunk_size: DATA_FRAGMENT_BYTES, total_size_bytes: prepared.manifest.total_bytes,
        merkle_root_hex: String::new(), chunks: Vec::new(),
    };
    let mut buffer = vec![0; DATA_FRAGMENT_BYTES];
    let mut offset = 0u64;
    for file in logical_files(&prepared.manifest)? {
        let mut chunk = DeltaChunkWire {
            index: u32::try_from(delta.chunks.len()).map_err(|_| QuicTransportError::Source("tree index overflow".to_string()))?,
            entry_index: file.entry_index, rel_path: file.rel_path.to_string(),
            entry_offset: file.entry_offset, stream_offset: offset,
            size_bytes: file.size, content_id_hex: String::new(),
        };
        let (path, start) = source_for_chunk(prepared, &chunk)?;
        let source_size = prepared.entries[chunk.entry_index as usize].size;
        let (cid, sha) = read_range(cx, path, start, file.size, source_size, &mut buffer).await?;
        if super::hex_encode(&sha) != file.sha256_hex {
            return Err(QuicTransportError::Source("prepared tree file changed content".to_string()));
        }
        chunk.content_id_hex = cid.to_hex();
        offset = offset.checked_add(file.size)
            .ok_or_else(|| QuicTransportError::Source("tree file size overflow".to_string()))?;
        delta.chunks.push(chunk);
    }
    if offset != delta.total_size_bytes {
        return Err(QuicTransportError::Source("prepared tree files do not cover the transfer".to_string()));
    }
    delta.merkle_root_hex = persistent(&delta)?.merkle_root.to_hex();
    Ok(delta)
}

/// Build before connecting: a candidate that exceeds the envelope budget must
/// never make the receiver enter a session requiring the new tree schema.
#[cfg(any(feature = "tls", test))]
pub(super) async fn select_manifest(
    cx: &Cx, prepared: &mut QuicPreparedSource, config: &QuicConfig,
) -> Result<bool, QuicTransportError> {
    if !may_offer(prepared) { return Ok(false); }
    let mut candidate = prepared.manifest.clone();
    candidate.delta_manifest = Some(build_manifest(cx, prepared).await?);
    match super::json_frame(FrameType::ObjectManifest, &candidate) {
        Ok(frame) if frame.payload().len() <= usize::try_from(super::MAX_FRAME_SIZE)
            .unwrap_or(usize::MAX).saturating_sub(super::QUIC_DELTA_ENVELOPE_WIRE_BUDGET) => {}
        Ok(_) | Err(QuicTransportError::Frame(_)) => return Ok(false),
        Err(error) => return Err(error),
    }
    super::validate_quic_manifest_with_layouts(&candidate, config, false, true)?;
    prepared.manifest = candidate;
    Ok(true)
}

#[cfg(any(feature = "tls", test))]
async fn validate_source_metadata(
    cx: &Cx, prepared: &QuicPreparedSource, config: &QuicConfig,
) -> Result<(), QuicTransportError> {
    if prepared.entries.len() != prepared.manifest.entries.len() {
        return Err(QuicTransportError::Source("prepared tree entry count changed".to_string()));
    }
    for (entry, source) in prepared.manifest.entries.iter().zip(&prepared.entries) {
        cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
        if source.index != entry.index || source.size != entry.size {
            return Err(QuicTransportError::Source("prepared tree entry mapping changed".to_string()));
        }
        if entry.members.is_empty() {
            let expected = entry.metadata.clone().unwrap_or_default();
            if super::read_entry_metadata(&source.abs_path, &config.metadata_policy).await? != expected {
                return Err(QuicTransportError::Source("prepared tree entry metadata changed".to_string()));
            }
            if matches!(expected.file_kind, FileKind::Directory) { continue; }
        }
        let metadata = crate::fs::symlink_metadata(&source.abs_path).await?;
        if !metadata.is_file() || metadata.len() != entry.size {
            return Err(QuicTransportError::Source("prepared tree source changed size or kind".to_string()));
        }
    }
    Ok(())
}

#[cfg(any(feature = "tls", test))]
pub(super) async fn revalidate_source(
    cx: &Cx, prepared: &QuicPreparedSource, config: &QuicConfig,
) -> Result<(), QuicTransportError> {
    cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
    validate_source_metadata(cx, prepared, config).await?;
    let current = build_manifest(cx, prepared).await?;
    if prepared.manifest.delta_manifest.as_ref() != Some(&current) {
        return Err(QuicTransportError::Source("prepared tree delta content changed".to_string()));
    }
    validate_source_metadata(cx, prepared, config).await?;
    cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)
}

#[cfg(feature = "tls")]
pub(super) async fn plan(
    cx: &Cx, dest_dir: &Path, config: &QuicConfig, manifest: &TransferManifest,
) -> Result<Option<super::delta_chunks::ReceivePlan>, QuicTransportError> {
    use super::{BTreeMap, DeltaObjectRequest, DeltaWireMode, EntryDigest, flat_merkle_root_from_digests};
    use super::delta_chunks::{ReceivePlan, ReusableRange};

    validate_manifest(manifest)?;
    super::prepare_quic_destination_root(dest_dir).await?;
    let baseline = super::quic_safe_base_for_root_name(dest_dir, &manifest.root_name)?;
    super::reject_quic_destination_symlink_prefix(&baseline, &baseline).await?;
    let delta = manifest.delta_manifest.as_ref().expect("validated tree manifest");
    let mut buffer = vec![0; DATA_FRAGMENT_BYTES];
    let mut chunks = Vec::new();
    let mut digests = Vec::new();
    let mut reusable = BTreeMap::new();
    let mut offset = 0u64;
    for file in logical_files(manifest)? {
        cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
        let path = super::quic_join_relative(&baseline, file.rel_path)?;
        super::reject_quic_destination_symlink_prefix(&baseline, &path).await?;
        let metadata = match crate::fs::symlink_metadata(&path).await {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(io_error(cx, error)),
        };
        if !metadata.is_file() || metadata.len() != file.size || metadata.len() > config.max_transfer_bytes {
            continue;
        }
        let (cid, sha) = match read_range(cx, &path, 0, file.size, file.size, &mut buffer).await {
            Ok(digest) => digest,
            Err(QuicTransportError::Source(_)) => continue,
            Err(QuicTransportError::Io(error)) if matches!(error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::UnexpectedEof) => continue,
            Err(error) => return Err(error),
        };
        super::reject_quic_destination_symlink_prefix(&baseline, &path).await?;
        reusable.entry(cid.to_hex()).or_insert(ReusableRange {
            path, offset: 0, size: file.size,
        });
        digests.push(EntryDigest {
            rel_path: file.rel_path.to_string(), size: file.size,
            content_id: crate::atp::object::ObjectId::content(cid.clone()), content_sha256: sha,
        });
        chunks.push(CasChunkRef {
            index: u32::try_from(chunks.len()).map_err(|_| QuicTransportError::Control("tree baseline index overflow".to_string()))?,
            byte_offset: offset, size_bytes: file.size, content_id: cid,
        });
        offset = offset.checked_add(file.size)
            .ok_or_else(|| QuicTransportError::Control("tree baseline size overflow".to_string()))?;
    }
    let receiver = PersistentChunkManifest::new(flat_merkle_root_from_digests(&digests), chunks)
        .map_err(|error| QuicTransportError::Control(format!("tree receiver have-set: {error}")))?;
    let diff = persistent(delta)?.diff_against(&receiver);
    if diff.shared_chunks == 0 || diff.missing_bytes >= manifest.total_bytes { return Ok(None); }
    let request = DeltaObjectRequest {
        mode: DeltaWireMode::DeltaChunks, fallback_reason: Some(SELECTOR.to_string()),
        sender_merkle_root_hex: delta.merkle_root_hex.clone(),
        receiver_merkle_root_hex: Some(receiver.merkle_root.to_hex()),
        missing_bytes: diff.missing_bytes, shared_chunks: diff.shared_chunks,
        stale_chunks: u64::try_from(diff.stale_chunks.len()).unwrap_or(u64::MAX),
        missing_chunks: diff.missing_chunks.iter().map(|chunk| delta.chunks[chunk.index as usize].clone()).collect(),
    };
    super::delta_chunks::validate_request(manifest, &request)?;
    Ok(Some(ReceivePlan { request, baseline, reusable }))
}

#[cfg(any(feature = "tls", test))]
fn capability_symbol(
    hello: &QuicHello, nonce: TransferNonce, ack: Option<&QuicHelloAck>,
) -> Result<Symbol, QuicTransportError> {
    if hello.delta_transfer_nonce.is_some() || nonce.is_zero() {
        return Err(QuicTransportError::HandshakeRejected("tree capability requires its own nonzero nonce".to_string()));
    }
    let mut sha = Sha256::new();
    sha.update(b"ATP-QUIC-TREE-DELTA-CAPABILITY-V1\0");
    sha.update(nonce.as_bytes());
    super::quic_delta_hash_len_prefixed(&mut sha, &serde_json::to_vec(hello)
        .map_err(|error| QuicTransportError::Control(error.to_string()))?);
    match ack {
        Some(ack) => {
            if !ack.accepted || super::validate_quic_delta_ack(Some(nonce), ack)?.is_none() {
                return Err(QuicTransportError::HandshakeRejected("tree capability acknowledgement lacks a bound challenge".to_string()));
            }
            sha.update([1]);
            super::quic_delta_hash_len_prefixed(&mut sha, &serde_json::to_vec(ack)
                .map_err(|error| QuicTransportError::Control(error.to_string()))?);
        }
        None => sha.update([0]),
    }
    let digest: [u8; 32] = sha.finalize().into();
    Ok(Symbol::new(SymbolId::new(ObjectId::new(0x4154_502d_5155_4943, 0x2d54_5245_452d_5631), 0, 0),
        digest.to_vec(), SymbolKind::Source))
}

#[cfg(any(feature = "tls", test))]
fn sign(context: &SecurityContext, key: &[u8], symbol: &Symbol) -> Result<Vec<u8>, QuicTransportError> {
    if context.mode() != AuthMode::Strict {
        return Err(QuicTransportError::Config("tree delta requires strict authentication".to_string()));
    }
    Ok(context.derive_context(key).sign_symbol_tag(symbol).as_bytes().to_vec())
}

#[cfg(any(feature = "tls", test))]
fn verify(context: &SecurityContext, key: &[u8], symbol: Symbol, bytes: &[u8]) -> Result<(), QuicTransportError> {
    let tag = bytes.try_into().map_err(|_| QuicTransportError::HandshakeRejected("malformed tree capability tag".to_string()))?;
    let mut authenticated = AuthenticatedSymbol::from_parts(symbol, AuthenticationTag::from_bytes(tag));
    if context.mode() != AuthMode::Strict
        || context.derive_context(key).verify_authenticated_symbol(&mut authenticated).is_err()
        || !authenticated.is_verified()
    {
        return Err(QuicTransportError::HandshakeRejected("tree capability authentication failed".to_string()));
    }
    Ok(())
}

#[cfg(any(feature = "tls", test))]
pub(super) fn advertise(
    frame: &mut Frame, context: &SecurityContext, hello: &QuicHello, nonce: TransferNonce,
) -> Result<(), QuicTransportError> {
    let tag = sign(context, b"atp-quic-tree-delta-hello-v1", &capability_symbol(hello, nonce, None)?)?;
    let mut bytes = nonce.as_bytes().to_vec();
    bytes.extend_from_slice(&tag);
    frame.header.extensions.insert(HELLO_EXTENSION, bytes);
    Ok(())
}

#[cfg(any(feature = "tls", test))]
pub(super) fn offered(
    frame: &Frame, context: &SecurityContext, hello: &QuicHello,
) -> Result<Option<TransferNonce>, QuicTransportError> {
    let Some(bytes) = frame.header.extensions.get(&HELLO_EXTENSION) else { return Ok(None); };
    if bytes.len() != 64 {
        return Err(QuicTransportError::HandshakeRejected("malformed tree capability offer".to_string()));
    }
    let nonce = TransferNonce::new(bytes[..32].try_into().expect("checked nonce width"));
    verify(context, b"atp-quic-tree-delta-hello-v1", capability_symbol(hello, nonce, None)?, &bytes[32..])?;
    Ok(Some(nonce))
}

#[cfg(any(feature = "tls", test))]
pub(super) fn acknowledge(
    frame: &mut Frame, context: &SecurityContext, hello: &QuicHello, ack: &QuicHelloAck, nonce: TransferNonce,
) -> Result<(), QuicTransportError> {
    let tag = sign(context, b"atp-quic-tree-delta-ack-v1", &capability_symbol(hello, nonce, Some(ack))?)?;
    frame.header.extensions.insert(ACK_EXTENSION, tag);
    Ok(())
}

#[cfg(any(feature = "tls", test))]
pub(super) fn acknowledged(
    frame: &Frame, context: Option<&SecurityContext>, hello: &QuicHello,
    ack: &QuicHelloAck, offered_nonce: Option<TransferNonce>,
) -> Result<bool, QuicTransportError> {
    let Some(bytes) = frame.header.extensions.get(&ACK_EXTENSION) else { return Ok(false); };
    let nonce = offered_nonce.ok_or_else(|| QuicTransportError::HandshakeRejected("unsolicited tree capability acknowledgement".to_string()))?;
    let context = context.ok_or_else(|| QuicTransportError::HandshakeRejected("tree capability has no authentication context".to_string()))?;
    verify(context, b"atp-quic-tree-delta-ack-v1", capability_symbol(hello, nonce, Some(ack))?, bytes)?;
    Ok(true)
}

#[cfg(test)]
#[path = "tree_delta_tests.rs"]
mod tests;
