//! Negotiated, authenticated fixed-chunk reuse for one RQ object.
//!
//! Only missing chunks cross the reliable control stream. Reconstruction uses
//! bounded buffers and the ordinary RQ staging, verification and atomic commit
//! path. This does not change the fixed-size manifest or claim CDC/rateless delta.

use super::{
    AsyncReadExt, AsyncWriteExt, BTreeMap, BTreeSet, CasChunkRef, CompletionDigestIndex,
    ContentId, Cx, DeltaChunkWire, DeltaObjectRequest, DeltaWireMode,
    Digest, EntryDecoder, EntryDigest, Frame, FrameTransport, FrameType, Path, PathBuf,
    PersistentChunkManifest, ProtocolVersion, RQ_DELTA_MAX_MANIFEST_CHUNKS,
    ReceiveReceipt, ReceiveReport, RqConfig, RqDeltaSessionContext, RqError,
    RqReceiveOptions, RqSourceEntry, SecurityContext, SendReport, Sha256, SocketAddr,
    TransferManifest, UdpSendAccelerationReport, create_receive_staging_guard, entry_object_id,
    flat_merkle_root_from_digests, json_frame, parse_json,
    recv_delta_control_frame, reject_destination_symlink_prefix, reject_existing_symlink,
    rq_decode_delta_root, rq_delta_manifest_entry, rq_plan_delta_chunks, safe_base_for_root_name,
    send_delta_control_frame, sign_rq_delta_control, validate_rq_delta_source_unchanged,
    verify_and_commit_with_options, verify_rq_delta_control, write_entry_staging_range,
};
use serde::{Deserialize, Serialize};

/// Old frame codecs preserve/ignore unknown extensions; no Hello JSON or wire
/// version changes. The offer itself is authenticated, not merely a hint that
/// an active peer can add to an old sender's manifest.
pub(super) const OFFER_EXTENSION: u16 = 0x5252;
const SELECTOR: &str = "authenticated_fixed_delta_chunks_v1";
const OFFER_KEY: &[u8] = b"atp-rq-delta-chunks-offer-v1";
const OFFER_DOMAIN: &[u8] = b"ATP-RQ-DELTA-CHUNKS-OFFER-V1\0";
const DATA_HEADER_BYTES: usize = 12;
// Leave ample room for the canonical header and sequenced authentication tag;
// a manifest chunk can be almost MAX_FRAME_SIZE before either is added.
const DATA_FRAGMENT_BYTES: usize = 64 * 1024;

pub(super) fn advertise(
    frame: &mut Frame,
    context: &SecurityContext,
    session: RqDeltaSessionContext,
    manifest: &TransferManifest,
) -> Result<(), RqError> {
    let tag = sign_rq_delta_control(
        context,
        OFFER_KEY,
        OFFER_DOMAIN,
        session,
        &manifest.transfer_id,
        0,
        &SELECTOR,
    )?;
    frame.header.extensions.insert(OFFER_EXTENSION, tag.to_vec());
    Ok(())
}

pub(super) fn offered(
    frame: &Frame,
    context: &SecurityContext,
    session: RqDeltaSessionContext,
    manifest: &TransferManifest,
) -> Result<bool, RqError> {
    let Some(bytes) = frame.header.extensions.get(&OFFER_EXTENSION) else {
        return Ok(false);
    };
    let tag: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
        RqError::Authentication("malformed RQ changed-chunk capability proof".to_string())
    })?;
    // session_id already commits the exact manifest and both handshake nonces.
    verify_rq_delta_control(
        context,
        OFFER_KEY,
        OFFER_DOMAIN,
        session,
        &manifest.transfer_id,
        0,
        &SELECTOR,
        tag,
        "RQ changed-chunk capability proof",
    )?;
    Ok(true)
}

pub(super) fn validate_request(
    manifest: &TransferManifest,
    request: &DeltaObjectRequest,
    udp_port: u16,
    udp_ports: &[u16],
    control_source_stream: bool,
) -> Result<(), RqError> {
    let delta = manifest.delta_manifest.as_ref().ok_or_else(|| {
        RqError::Control("changed-chunk request has no sender manifest".to_string())
    })?;
    if rq_delta_manifest_entry(manifest).is_none()
        || request.mode != DeltaWireMode::DeltaChunks
        || request.fallback_reason.as_deref() != Some(SELECTOR)
        || request.sender_merkle_root_hex != delta.merkle_root_hex
        || request.receiver_merkle_root_hex.is_none()
        || udp_port != 0
        || !udp_ports.is_empty()
        || control_source_stream
        || request.shared_chunks == 0
        || request.missing_bytes >= delta.total_size_bytes
        || request.stale_chunks > RQ_DELTA_MAX_MANIFEST_CHUNKS
    {
        return Err(RqError::Control("malformed RQ changed-chunk request".to_string()));
    }
    rq_decode_delta_root(
        request.receiver_merkle_root_hex.as_deref().expect("checked receiver root"),
        "RQ delta receiver root",
    )?;
    let mut last_index = None;
    let mut missing_bytes = 0u64;
    for chunk in &request.missing_chunks {
        let index = usize::try_from(chunk.index)
            .map_err(|_| RqError::Control("delta chunk index overflow".to_string()))?;
        if delta.chunks.get(index) != Some(chunk)
            || last_index.is_some_and(|last| chunk.index <= last)
        {
            return Err(RqError::Control(
                "changed-chunk request is not an ordered subset of the sender manifest".to_string(),
            ));
        }
        last_index = Some(chunk.index);
        missing_bytes = missing_bytes.checked_add(chunk.size_bytes).ok_or_else(|| {
            RqError::Control("changed-chunk byte count overflow".to_string())
        })?;
    }
    let missing_count = u64::try_from(request.missing_chunks.len())
        .map_err(|_| RqError::Control("changed-chunk count overflow".to_string()))?;
    if missing_bytes != request.missing_bytes
        || missing_count.checked_add(request.shared_chunks)
            != u64::try_from(delta.chunks.len()).ok()
    {
        return Err(RqError::Control(
            "changed-chunk request accounting does not cover the manifest".to_string(),
        ));
    }
    Ok(())
}

pub(super) struct ReceivePlan {
    pub(super) request: DeltaObjectRequest,
    baseline: PathBuf,
    // One source location per content id; duplicates can reuse the same bytes.
    reusable: BTreeMap<String, (u64, u64)>,
}

pub(super) async fn plan(
    cx: &Cx,
    dest_dir: &Path,
    config: &RqConfig,
    manifest: &TransferManifest,
) -> Result<Option<ReceivePlan>, RqError> {
    let delta = manifest.delta_manifest.as_ref().ok_or_else(|| {
        RqError::Control("cannot plan changed chunks without a manifest".to_string())
    })?;
    let entry = rq_delta_manifest_entry(manifest).ok_or_else(|| {
        RqError::Control("changed chunks require one regular file".to_string())
    })?;
    let baseline = safe_base_for_root_name(dest_dir, &manifest.root_name)?;
    reject_existing_symlink(dest_dir).await?;
    reject_destination_symlink_prefix(&baseline, &baseline).await?;
    let metadata = match crate::fs::metadata(&baseline).await {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    // The receiver's old file may be larger than the sender's. Bound the old
    // manifest before reading or allocating even for an authenticated peer.
    let chunk_size = u64::try_from(delta.chunk_size)
        .map_err(|_| RqError::Control("delta chunk size overflow".to_string()))?;
    if chunk_size == 0
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > config.max_transfer_bytes
        || metadata.len().div_ceil(chunk_size) > RQ_DELTA_MAX_MANIFEST_CHUNKS
    {
        return Ok(None);
    }
    let mut file = crate::fs::File::open(&baseline).await?;
    let mut buffer = vec![0u8; delta.chunk_size];
    let mut receiver_chunks = Vec::new();
    let mut planner_chunks = Vec::new();
    let mut reusable = BTreeMap::new();
    let mut offset = 0u64;
    let mut sha256 = Sha256::new();
    let mut whole_content_id = ContentId::streaming();
    loop {
        cx.checkpoint().map_err(|_| RqError::Cancelled)?;
        let read = crate::net::atp::transport_common::delta::read_full_chunk(
            &mut file,
            &mut buffer,
        )
        .await?;
        if read == 0 {
            break;
        }
        let size_bytes = u64::try_from(read)
            .map_err(|_| RqError::Control("baseline chunk size overflow".to_string()))?;
        let end = offset.checked_add(size_bytes)
            .ok_or_else(|| RqError::Control("baseline size overflow".to_string()))?;
        if end > metadata.len()
            || u64::try_from(receiver_chunks.len()).unwrap_or(u64::MAX)
                >= RQ_DELTA_MAX_MANIFEST_CHUNKS
        {
            return Ok(None);
        }
        let bytes = &buffer[..read];
        sha256.update(bytes);
        whole_content_id.update(bytes);
        let content_id = ContentId::from_bytes(bytes);
        let content_id_hex = content_id.to_hex();
        let index = u32::try_from(receiver_chunks.len())
            .map_err(|_| RqError::Control("baseline chunk count overflow".to_string()))?;
        reusable.entry(content_id_hex.clone()).or_insert((offset, size_bytes));
        planner_chunks.push(CasChunkRef {
            index,
            byte_offset: offset,
            size_bytes,
            content_id,
        });
        receiver_chunks.push(DeltaChunkWire {
            index,
            entry_index: entry.index,
            rel_path: entry.rel_path.clone(),
            entry_offset: offset,
            stream_offset: offset,
            size_bytes,
            content_id_hex,
        });
        offset = end;
    }
    if offset != metadata.len() {
        return Ok(None);
    }
    let diff = rq_plan_delta_chunks(&delta.chunks, &receiver_chunks);
    if diff.shared_chunks == 0 || diff.missing_bytes >= delta.total_size_bytes {
        return Ok(None);
    }
    let receiver_tree = flat_merkle_root_from_digests(&[EntryDigest {
        rel_path: entry.rel_path.clone(),
        size: offset,
        content_id: crate::atp::object::ObjectId::content(whole_content_id.finalize()),
        content_sha256: sha256.finalize().into(),
    }]);
    let receiver_manifest = PersistentChunkManifest::new(receiver_tree, planner_chunks)
        .map_err(|error| RqError::Control(format!("build RQ baseline manifest: {error}")))?;
    let request = DeltaObjectRequest {
        mode: DeltaWireMode::DeltaChunks,
        fallback_reason: Some(SELECTOR.to_string()),
        sender_merkle_root_hex: delta.merkle_root_hex.clone(),
        receiver_merkle_root_hex: Some(receiver_manifest.merkle_root.to_hex()),
        missing_bytes: diff.missing_bytes,
        shared_chunks: diff.shared_chunks,
        stale_chunks: diff.stale_chunks,
        missing_chunks: diff.missing_chunks,
    };
    validate_request(manifest, &request, 0, &[], false)?;
    Ok(Some(ReceivePlan { request, baseline, reusable }))
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Complete {
    bytes_sent: u64,
    chunks_sent: u64,
}

fn data_frame(chunk: &DeltaChunkWire, relative_offset: u64, bytes: &[u8]) -> Result<Frame, RqError> {
    let mut payload = Vec::with_capacity(DATA_HEADER_BYTES + bytes.len());
    payload.extend_from_slice(&chunk.index.to_be_bytes());
    let offset = chunk.entry_offset.checked_add(relative_offset)
        .ok_or_else(|| RqError::Control("changed-chunk offset overflow".to_string()))?;
    payload.extend_from_slice(&offset.to_be_bytes());
    payload.extend_from_slice(bytes);
    Frame::new(ProtocolVersion::CURRENT, FrameType::ObjectData, payload)
        .map_err(|error| RqError::Frame(error.to_string()))
}

fn checked_data<'a>(
    frame: &'a Frame,
    chunk: &DeltaChunkWire,
    relative_offset: u64,
) -> Result<&'a [u8], RqError> {
    let payload = frame.payload();
    if frame.frame_type() != FrameType::ObjectData || payload.len() < DATA_HEADER_BYTES {
        return Err(RqError::Frame("expected one complete changed-chunk ObjectData frame".to_string()));
    }
    let index = u32::from_be_bytes(payload[..4].try_into().expect("chunk index width"));
    let offset = u64::from_be_bytes(payload[4..DATA_HEADER_BYTES].try_into().expect("chunk offset width"));
    let bytes = &payload[DATA_HEADER_BYTES..];
    let remaining = chunk.size_bytes.checked_sub(relative_offset).ok_or_else(|| {
        RqError::Frame("changed-chunk data exceeds the requested chunk".to_string())
    })?;
    let expected_len = remaining.min(DATA_FRAGMENT_BYTES as u64);
    if index != chunk.index
        || chunk.entry_offset.checked_add(relative_offset) != Some(offset)
        || expected_len == 0
        || u64::try_from(bytes.len()).ok() != Some(expected_len)
    {
        return Err(RqError::Integrity(
            "changed-chunk data differs from the next requested manifest chunk".to_string(),
        ));
    }
    Ok(bytes)
}

fn verify_chunk_bytes(chunk: &DeltaChunkWire, bytes: &[u8], label: &str) -> Result<(), RqError> {
    if u64::try_from(bytes.len()).ok() != Some(chunk.size_bytes)
        || ContentId::from_bytes(bytes).to_hex() != chunk.content_id_hex
    {
        return Err(RqError::Integrity(format!("{label} differs from its committed chunk")));
    }
    Ok(())
}

pub(super) async fn send<S>(
    cx: &Cx,
    control: &mut FrameTransport<S>,
    manifest: &TransferManifest,
    entries: &[RqSourceEntry],
    config: &RqConfig,
    request: &DeltaObjectRequest,
    peer: SocketAddr,
) -> Result<SendReport, RqError>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    // Parent enabled sequenced control only after authenticating this exact
    // request. Source bytes (including unrequested ones) must still match it.
    validate_rq_delta_source_unchanged(cx, manifest, entries, config).await?;
    let [source] = entries else {
        return Err(RqError::Control("changed chunks lost their single source".to_string()));
    };
    let mut file = crate::fs::File::open(&source.abs_path).await?;
    let delta = manifest.delta_manifest.as_ref().expect("validated delta manifest");
    let mut buffer = vec![0u8; delta.chunk_size];
    for chunk in &request.missing_chunks {
        cx.checkpoint().map_err(|_| RqError::Cancelled)?;
        let len = usize::try_from(chunk.size_bytes)
            .map_err(|_| RqError::Control("changed-chunk size overflow".to_string()))?;
        file.seek(std::io::SeekFrom::Start(chunk.entry_offset)).await?;
        let bytes = &mut buffer[..len];
        file.read_exact(bytes).await?;
        verify_chunk_bytes(chunk, bytes, "RQ source before sending")?;
        for (part, bytes) in bytes.chunks(DATA_FRAGMENT_BYTES).enumerate() {
            cx.checkpoint().map_err(|_| RqError::Cancelled)?;
            let relative_offset = u64::try_from(part * DATA_FRAGMENT_BYTES)
                .map_err(|_| RqError::Control("changed-chunk fragment offset overflow".to_string()))?;
            let frame = data_frame(chunk, relative_offset, bytes)?;
            send_delta_control_frame(
                cx, control, &frame, config.delta_control_timeout, "send authenticated changed chunk",
            ).await?;
        }
    }
    validate_rq_delta_source_unchanged(cx, manifest, entries, config).await?;
    let complete = Complete {
        bytes_sent: request.missing_bytes,
        chunks_sent: u64::try_from(request.missing_chunks.len()).unwrap_or(u64::MAX),
    };
    send_delta_control_frame(
        cx, control, &json_frame(FrameType::ObjectComplete, &complete)?,
        config.delta_control_timeout, "send changed-chunk completion",
    ).await?;
    let frame = recv_delta_control_frame(
        cx, control, config.delta_control_timeout, "receive changed-chunk proof",
    ).await?;
    if frame.frame_type() != FrameType::Proof {
        return Err(RqError::Unexpected { got: frame.frame_type(), expected: "authenticated Proof" });
    }
    let receipt: ReceiveReceipt = parse_json(&frame)?;
    if !receipt.committed
        || !receipt.sha_ok
        || !receipt.merkle_ok
        || receipt.bytes_received != request.missing_bytes
        || receipt.files != 1
        || receipt.symbols_accepted != 0
        || receipt.feedback_rounds != 0
        || receipt.reason.is_some()
        || !receipt.committed_paths.is_empty()
    {
        return Err(RqError::Integrity("receiver did not verify the changed-chunk transfer".to_string()));
    }
    send_delta_control_frame(
        cx, control,
        &Frame::empty(FrameType::Close).map_err(|error| RqError::Frame(error.to_string()))?,
        config.delta_control_timeout, "close changed-chunk transfer",
    ).await?;
    Ok(SendReport {
        transfer_id: manifest.transfer_id.clone(),
        bytes_sent: request.missing_bytes,
        files: 1,
        symbols_sent: 0,
        feedback_rounds: 0,
        merkle_root_hex: manifest.merkle_root_hex.clone(),
        receipt,
        udp_send_acceleration: UdpSendAccelerationReport::default(),
        peer,
    })
}

fn staging_decoder(manifest: &TransferManifest, staging_dir: &Path) -> Result<EntryDecoder, RqError> {
    let entry = rq_delta_manifest_entry(manifest).ok_or_else(|| {
        RqError::Control("changed chunks require one staging entry".to_string())
    })?;
    Ok(EntryDecoder {
        index: entry.index,
        object_id: entry_object_id(&manifest.transfer_id, entry.index),
        size: entry.size,
        pipeline: None,
        complete: false,
        staging_path: staging_dir.join("delta-object.part"),
        staging_write_offset: 0,
        staging_file_len: entry.size,
        staging_shared: false,
        staging_created: false,
        staging_file: None,
        staging_cursor: None,
        staging_unflushed_bytes: 0,
        cache_staging_file: true,
        bytes_written: 0,
        max_block_size: 0,
        source_streaming: false,
        source_blocks: Vec::new(),
        pending_decodes: Vec::new(),
        source_write_buffer: Vec::new(),
        source_write_buffer_offset: None,
        // Re-read the actual assembled file for the whole-object commit gate.
        inc: None,
        inc_digest: None,
    })
}

async fn copy_reused(
    cx: &Cx,
    manifest: &TransferManifest,
    plan: &ReceivePlan,
    decoder: &mut EntryDecoder,
) -> Result<(), RqError> {
    reject_destination_symlink_prefix(&plan.baseline, &plan.baseline).await?;
    let mut file = crate::fs::File::open(&plan.baseline).await?;
    let delta = manifest.delta_manifest.as_ref().expect("validated delta manifest");
    let missing: BTreeSet<u32> = plan.request.missing_chunks.iter().map(|chunk| chunk.index).collect();
    let mut buffer = vec![0u8; delta.chunk_size];
    for chunk in &delta.chunks {
        if missing.contains(&chunk.index) {
            continue;
        }
        cx.checkpoint().map_err(|_| RqError::Cancelled)?;
        let &(offset, size) = plan.reusable.get(&chunk.content_id_hex).ok_or_else(|| {
            RqError::Integrity("baseline no longer supplies a reused chunk".to_string())
        })?;
        let len = usize::try_from(chunk.size_bytes)
            .map_err(|_| RqError::Control("reused chunk size overflow".to_string()))?;
        if size != chunk.size_bytes {
            return Err(RqError::Integrity("reused chunk length mismatch".to_string()));
        }
        file.seek(std::io::SeekFrom::Start(offset)).await?;
        let bytes = &mut buffer[..len];
        file.read_exact(bytes).await?;
        verify_chunk_bytes(chunk, bytes, "RQ baseline after delta planning")?;
        write_entry_staging_range(decoder, chunk.entry_offset, bytes).await?;
        decoder.bytes_written = decoder.bytes_written.checked_add(chunk.size_bytes)
            .ok_or_else(|| RqError::Control("reconstructed byte count overflow".to_string()))?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn receive<S>(
    cx: &Cx,
    control: &mut FrameTransport<S>,
    manifest: &TransferManifest,
    config: &RqConfig,
    dest_dir: &Path,
    peer: SocketAddr,
    options: RqReceiveOptions,
    plan: ReceivePlan,
) -> Result<ReceiveReport, RqError>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let mut guard = create_receive_staging_guard(dest_dir, &manifest.transfer_id).await?;
    let staging_dir = guard.dir().to_path_buf();
    let mut decoder = staging_decoder(manifest, &staging_dir)?;
    let result = async {
        let delta = manifest.delta_manifest.as_ref().expect("validated delta manifest");
        let mut buffer = vec![0u8; delta.chunk_size];
        for chunk in &plan.request.missing_chunks {
            let len = usize::try_from(chunk.size_bytes)
                .map_err(|_| RqError::Control("changed-chunk size overflow".to_string()))?;
            let mut filled = 0usize;
            while filled < len {
                cx.checkpoint().map_err(|_| RqError::Cancelled)?;
                let frame = recv_delta_control_frame(
                    cx, control, config.delta_control_timeout, "receive authenticated changed chunk",
                ).await?;
                let bytes = checked_data(&frame, chunk, filled as u64)?;
                buffer[filled..filled + bytes.len()].copy_from_slice(bytes);
                filled += bytes.len();
            }
            let bytes = &buffer[..len];
            verify_chunk_bytes(chunk, bytes, "received RQ changed chunk")?;
            write_entry_staging_range(&mut decoder, chunk.entry_offset, bytes).await?;
            decoder.bytes_written = decoder.bytes_written.checked_add(chunk.size_bytes)
                .ok_or_else(|| RqError::Control("received changed-chunk byte count overflow".to_string()))?;
        }
        drop(buffer);
        let frame = recv_delta_control_frame(
            cx, control, config.delta_control_timeout, "receive changed-chunk completion",
        ).await?;
        if frame.frame_type() != FrameType::ObjectComplete {
            return Err(RqError::Unexpected {
                got: frame.frame_type(),
                expected: "authenticated ObjectComplete after the exact requested chunk set",
            });
        }
        let complete: Complete = parse_json(&frame)?;
        if complete.bytes_sent != plan.request.missing_bytes
            || complete.chunks_sent != u64::try_from(plan.request.missing_chunks.len()).unwrap_or(u64::MAX)
        {
            return Err(RqError::Integrity("changed-chunk completion count mismatch".to_string()));
        }
        // The baseline is re-read only after the remote subset is complete.
        // Every reused range is checked again, so a concurrent edit cannot
        // silently enter the staged reconstruction.
        copy_reused(cx, manifest, &plan, &mut decoder).await?;
        cx.checkpoint().map_err(|_| RqError::Cancelled)?;
        if decoder.bytes_written != decoder.size {
            return Err(RqError::Integrity("changed chunks did not reconstruct the whole object".to_string()));
        }
        decoder.complete = true;
        let mut receipt = verify_and_commit_with_options(
            manifest, std::slice::from_mut(&mut decoder), dest_dir, 0, 0,
            &BTreeMap::new(), &CompletionDigestIndex::default(), options,
        ).await?;
        if !receipt.committed || !receipt.sha_ok || !receipt.merkle_ok {
            return Err(RqError::Integrity(
                receipt.reason.unwrap_or_else(|| "changed-chunk reconstruction failed verification".to_string()),
            ));
        }
        let committed_paths = receipt.committed_paths.iter().map(PathBuf::from).collect();
        // Report actual transmitted object bytes, not bytes reused locally.
        // As on signed no-op, receiver-local paths stay out of plaintext proof.
        receipt.bytes_received = plan.request.missing_bytes;
        receipt.committed_paths.clear();
        send_delta_control_frame(
            cx, control, &json_frame(FrameType::Proof, &receipt)?,
            config.delta_control_timeout, "send verified changed-chunk proof",
        ).await?;
        super::drain_sender_close_after_proof(cx, control, "changed-chunks").await;
        Ok(ReceiveReport {
            transfer_id: manifest.transfer_id.clone(),
            bytes_received: receipt.bytes_received,
            files: receipt.files,
            committed: true,
            symbols_accepted: 0,
            feedback_rounds: 0,
            committed_paths,
            peer,
        })
    }.await;
    // Closing handles first preserves cleanup on Windows too. The armed guard
    // is the cancellation backstop until cooperative cleanup succeeds.
    drop(decoder);
    match crate::fs::remove_dir_all(&staging_dir).await {
        Ok(()) => guard.disarm(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => guard.disarm(),
        Err(error) if result.is_ok() => return Err(error.into()),
        Err(_) => {}
    }
    result
}

#[cfg(test)]
#[path = "delta_chunks_tests.rs"]
mod tests;
