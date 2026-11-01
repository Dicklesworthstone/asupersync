//! Native UDP session mechanics for negotiated chunk and whole-file reuse.

use super::{
    AsyncReadExt, BTreeSet, Cx, Duration, Frame, FrameType, Instant,
    NativeQuicFrameTransport, Ordering, Path, QUIC_STAGING_SEQ, QuicConfig, QuicLink,
    QuicPreparedSource, QuicReceiveOptions, QuicStagedEntryReceive, QuicStagingDirGuard,
    QuicTransportError, ReceiveReport, SendReport, TransferManifest,
    NEEDMORE_PTO, PROOF_WAIT_LIVENESS_MULTIPLIER, TERMINAL_PROOF_RETRANSMIT_ATTEMPTS,
    check_source_stream_control, commit_staged_entries, create_quic_staging_dir_guard,
    drive_native_source_stream_flush, erase_send, keep_peer_alive_while,
    needmore_pto_attempt_budget, queue_source_stream_frame, quic_staging_nonce_hex,
    refuse_transfer_in_band, wait_source_stream_send_admission,
};
use super::super::{
    ContentId, DeltaChunkWire, DeltaObjectRequest, QuicDeltaProof, QuicDeltaSessionContext,
    delta_chunks as delta, tree_delta,
    json_frame, make_quic_delta_proof, parse_json, send_native_close,
    validate_quic_prepared_delta_source_unchanged,
};

#[allow(clippy::too_many_arguments)]
pub(super) async fn send(
    cx: &Cx,
    link: &mut QuicLink,
    control: &mut NativeQuicFrameTransport,
    prepared: &QuicPreparedSource,
    config: &QuicConfig,
    session: QuicDeltaSessionContext,
    request: &DeltaObjectRequest,
) -> Result<SendReport, QuicTransportError> {
    cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
    let manifest = &prepared.manifest;
    delta::validate_request(manifest, request)?;
    let stream = control.stream;
    let limit = link.conn.stream_send_limit(stream).ok_or_else(|| {
        QuicTransportError::Control("changed-chunk control stream is missing".to_string())
    })?;
    let consumed = limit.checked_sub(link.conn.stream_send_credit_remaining(stream))
        .ok_or_else(|| QuicTransportError::Control("invalid control stream credit".to_string()))?;
    let bounded_limit = consumed.checked_add(delta::STREAM_WINDOW_BYTES)
        .ok_or_else(|| QuicTransportError::Control("changed-chunk window overflow".to_string()))?;
    // The v1 offer fixes the window. The receiver installs the same window at
    // this manifest boundary; subsequent reads advertise MAX_STREAM_DATA.
    link.conn.set_fresh_stream_send_limit(cx, stream, bounded_limit)
        .map_err(|error| {
            if cx.checkpoint().is_err() {
                QuicTransportError::Cancelled
            } else {
                error.into()
            }
        })?;
    let previous_stream = link.paced_source_stream.replace(stream);
    let previous_window = link.source_stream_send_window.replace(delta::STREAM_WINDOW_BYTES);
    let pacing = link.source_stream_pacing_decision(config);
    pacing.trace_epoch(cx, 0);
    link.data_plane_pacer.configure_source_stream(&pacing);
    link.begin_source_stream_rate_control(pacing.pacing_rate_bps);
    let result = erase_send(async {
        let mut early = None;
        let binding = Some((session, manifest));
        keep_peer_alive_while(cx, link, control,
            validate_quic_prepared_delta_source_unchanged(cx, prepared, config)).await?;
        check_source_stream_control(cx, link, control, &mut early, binding).await?;
        let mut queued = 0u64;
        if tree_delta::is_tree(manifest) {
            // One tree reference can name a multi-gigabyte logical file. Only
            // one wire fragment and one open source descriptor are retained.
            let mut buffer = vec![0u8; delta::DATA_FRAGMENT_BYTES];
            for chunk in &request.missing_chunks {
                cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
                let (path, source_offset) = tree_delta::source_for_chunk(prepared, chunk)?;
                let mut file = keep_peer_alive_while(cx, link, control, async {
                    let mut file = crate::fs::File::open(path)
                        .await.map_err(|error| delta::io_error(cx, error))?;
                    file.seek(std::io::SeekFrom::Start(source_offset))
                        .await.map_err(|error| delta::io_error(cx, error))?;
                    Ok(file)
                }).await?;
                let mut offset = 0u64;
                let mut content_id = ContentId::streaming();
                while offset < chunk.size_bytes {
                    cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
                    let len = usize::try_from(
                        (chunk.size_bytes - offset).min(delta::DATA_FRAGMENT_BYTES as u64),
                    ).expect("one data fragment fits usize");
                    keep_peer_alive_while(cx, link, control, async {
                        file.read_exact(&mut buffer[..len])
                            .await.map_err(|error| delta::io_error(cx, error))?;
                        Ok(())
                    }).await?;
                    content_id.update(&buffer[..len]);
                    let frame = delta::data_frame(chunk, offset, &buffer[..len])?;
                    queue_source_stream_frame(cx, link, control, &mut early, stream, config,
                        &frame, 16 * 1024, &mut queued, binding).await?;
                    check_source_stream_control(cx, link, control, &mut early, binding).await?;
                    offset += len as u64;
                }
                verify_streamed(chunk, offset, content_id.finalize(), "QUIC tree source")?;
            }
        } else {
            let [source] = prepared.entries.as_slice() else {
                return Err(QuicTransportError::Control("changed chunks lost their single source".to_string()));
            };
            let layout = manifest.delta_manifest.as_ref().expect("validated delta manifest");
            let mut file = crate::fs::File::open(&source.abs_path)
                .await.map_err(|error| delta::io_error(cx, error))?;
            let mut buffer = vec![0u8; layout.chunk_size];
            for chunk in &request.missing_chunks {
                cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
                let len = usize::try_from(chunk.size_bytes)
                    .map_err(|_| QuicTransportError::Control("changed-chunk size overflow".to_string()))?;
                keep_peer_alive_while(cx, link, control, async {
                    file.seek(std::io::SeekFrom::Start(chunk.entry_offset))
                        .await.map_err(|error| delta::io_error(cx, error))?;
                    file.read_exact(&mut buffer[..len]).await.map_err(|error| delta::io_error(cx, error))?;
                    delta::verify_bytes(chunk, &buffer[..len], "QUIC source before sending")
                }).await?;
                for (part, bytes) in buffer[..len].chunks(delta::DATA_FRAGMENT_BYTES).enumerate() {
                    cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
                    let frame = delta::data_frame(chunk, (part * delta::DATA_FRAGMENT_BYTES) as u64, bytes)?;
                    queue_source_stream_frame(cx, link, control, &mut early, stream, config,
                        &frame, 16 * 1024, &mut queued, binding).await?;
                    check_source_stream_control(cx, link, control, &mut early, binding).await?;
                }
            }
        }
        // Revalidate even locally reused source ranges before permitting the
        // receiver to commit. ObjectComplete is ordered after every fragment.
        keep_peer_alive_while(cx, link, control,
            validate_quic_prepared_delta_source_unchanged(cx, prepared, config)).await?;
        drive_native_source_stream_flush(cx, link, config.idle_timeout, true).await?;
        let _ = link.pump_inbound_for(cx, Duration::ZERO).await?;
        check_source_stream_control(cx, link, control, &mut early, binding).await?;
        let complete = json_frame(FrameType::ObjectComplete, &delta::Complete {
            bytes_sent: request.missing_bytes,
            chunks_sent: u64::try_from(request.missing_chunks.len()).unwrap_or(u64::MAX),
        })?;
        // This small frame is admitted before queueing, so success can only be
        // read after its complete wire image has been queued. A phase checker
        // inside a post-write flush could otherwise reject a valid fast proof.
        let close = Frame::empty(FrameType::Close)
            .map_err(|error| QuicTransportError::Frame(error.to_string()))?;
        // Reserve the terminal Close too: a lost final credit advertisement
        // must not turn an already committed proof into a local send failure.
        let terminal_bytes = (complete.encoded_len() + close.encoded_len()) as u64;
        wait_source_stream_send_admission(cx, link, control, &mut early, stream,
            terminal_bytes, config, binding).await?;
        control.send(cx, &mut link.conn, &complete)?;
        link.stream_source_exhausted = true;
        drive_native_source_stream_flush(cx, link, config.idle_timeout, true).await?;
        let proof_started = Instant::now();
        let proof_cap = config.idle_timeout.saturating_mul(PROOF_WAIT_LIVENESS_MULTIPLIER);
        let proof = loop {
            if proof_started.elapsed() >= proof_cap {
                return Err(QuicTransportError::Timeout {
                    operation: "receive committed QUIC changed-chunk proof", timeout: proof_cap,
                });
            }
            let frame = link.next_control_frame_with_source_stream_recovery(
                cx, control, "receive committed QUIC changed-chunk proof",
            ).await?;
            match frame.frame_type() {
                FrameType::Proof => break parse_json::<QuicDeltaProof>(&frame)?,
                FrameType::KeepAlive => {}
                got => return Err(QuicTransportError::Unexpected {
                    got, expected: "bound changed-chunk Proof | KeepAlive",
                }),
            }
        };
        if !proof.receipt.committed {
            let reason = super::super::validate_quic_delta_refusal(proof, session, manifest)?;
            // ObjectComplete finished the data frame sequence, so Close is
            // now safe and has reserved credit even if its update was lost.
            let _ = send_native_close(cx, &mut link.conn, control);
            let _ = link.flush(cx).await;
            return Err(QuicTransportError::Integrity(reason));
        }
        let receipt = delta::validate_proof(proof, session, manifest, request)?;
        send_native_close(cx, &mut link.conn, control)?;
        link.flush(cx).await?;
        Ok(SendReport {
            transfer_id: manifest.transfer_id.clone(), bytes_sent: request.missing_bytes,
            files: receipt.files, symbols_sent: 0, feedback_rounds: 0,
            merkle_root_hex: manifest.merkle_root_hex.clone(), receipt, peer: link.peer,
        })
    }).await;
    link.end_source_stream_rate_control();
    link.paced_source_stream = previous_stream;
    link.source_stream_send_window = previous_window;
    result.map_err(|error| {
        if cx.checkpoint().is_err() {
            QuicTransportError::Cancelled
        } else {
            error
        }
    })
}

async fn staging_guard(
    dest_dir: &Path,
    manifest: &TransferManifest,
) -> Result<QuicStagingDirGuard, QuicTransportError> {
    super::super::prepare_quic_destination_root(dest_dir).await?;
    for _ in 0..32 {
        let seq = QUIC_STAGING_SEQ.fetch_add(1, Ordering::Relaxed);
        let nonce = quic_staging_nonce_hex()?;
        let candidate = dest_dir.join(format!(
            ".atp-quic-staging-{}-{nonce}-{seq}", manifest.transfer_id,
        ));
        match create_quic_staging_dir_guard(candidate).await {
            Ok(guard) => {
                super::super::prepare_quic_destination_root(dest_dir).await?;
                super::super::reject_quic_existing_symlink(&guard.dir).await?;
                return Ok(guard);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
    }
    Err(QuicTransportError::Source("unable to create an owned QUIC delta staging directory".to_string()))
}

async fn next_data_frame(
    cx: &Cx,
    link: &mut QuicLink,
    control: &mut NativeQuicFrameTransport,
    manifest_frame: &Frame,
    request_frame: &Frame,
) -> Result<Frame, QuicTransportError> {
    let started = Instant::now();
    let cap = link.idle_timeout.saturating_mul(PROOF_WAIT_LIVENESS_MULTIPLIER);
    loop {
        if started.elapsed() >= cap {
            return Err(QuicTransportError::Timeout { operation: "receive QUIC changed-chunk progress", timeout: cap });
        }
        let frame = link.next_control_frame_with_source_stream_recovery(
            cx, control, "receive QUIC changed-chunk data or completion",
        ).await?;
        // Advertise consumed credit before disk work or the next read. The
        // sender must never wait for a full-chunk write to release this window.
        link.flush(cx).await?;
        match frame.frame_type() {
            FrameType::KeepAlive => {}
            FrameType::ObjectManifest if frame == *manifest_frame => {
                control.send(cx, &mut link.conn, request_frame)?;
                link.flush(cx).await?;
            }
            FrameType::ObjectManifest => return Err(QuicTransportError::Integrity(
                "sender changed the QUIC delta manifest after negotiation".to_string(),
            )),
            _ => return Ok(frame),
        }
    }
}

async fn copy_reused(
    cx: &Cx,
    manifest: &TransferManifest,
    plan: &delta::ReceivePlan,
    staged: &mut [QuicStagedEntryReceive],
) -> Result<u64, QuicTransportError> {
    let layout = manifest.delta_manifest.as_ref().expect("validated delta manifest");
    super::super::reject_quic_destination_symlink_prefix(&plan.baseline, &plan.baseline).await?;
    let mut open_baseline: Option<(std::path::PathBuf, crate::fs::File)> = None;
    let mut buffer = vec![0u8; delta::DATA_FRAGMENT_BYTES];
    let missing: BTreeSet<_> = plan.request.missing_chunks.iter().map(|chunk| chunk.index).collect();
    let mut copied = 0u64;
    for chunk in &layout.chunks {
        if missing.contains(&chunk.index) { continue; }
        cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
        let range = plan.reusable.get(&chunk.content_id_hex).ok_or_else(|| {
            QuicTransportError::Integrity("baseline no longer supplies a reused chunk".to_string())
        })?;
        if range.size != chunk.size_bytes {
            return Err(QuicTransportError::Integrity("reused chunk length mismatch".to_string()));
        }
        let index = usize::try_from(chunk.entry_index)
            .map_err(|_| QuicTransportError::Control("reused entry index overflow".to_string()))?;
        let entry = manifest.entries.get(index).ok_or_else(|| {
            QuicTransportError::Integrity("reused chunk references an absent entry".to_string())
        })?;
        let staged_entry = staged.get_mut(index).ok_or_else(|| {
            QuicTransportError::Integrity("reused chunk has no staged entry".to_string())
        })?;
        if open_baseline.as_ref().is_none_or(|(path, _)| path != &range.path) {
            super::super::reject_quic_destination_symlink_prefix(&plan.baseline, &range.path).await?;
            let file = crate::fs::File::open(&range.path)
                .await.map_err(|error| delta::io_error(cx, error))?;
            open_baseline = Some((range.path.clone(), file));
        }
        let (_, file) = open_baseline.as_mut().expect("opened verified baseline path");
        file.seek(std::io::SeekFrom::Start(range.offset))
            .await.map_err(|error| delta::io_error(cx, error))?;
        let mut offset = 0u64;
        let mut content_id = ContentId::streaming();
        while offset < range.size {
            cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
            let len = usize::try_from(
                (range.size - offset).min(delta::DATA_FRAGMENT_BYTES as u64),
            ).expect("one data fragment fits usize");
            file.read_exact(&mut buffer[..len]).await.map_err(|error| delta::io_error(cx, error))?;
            content_id.update(&buffer[..len]);
            let target = chunk.entry_offset.checked_add(offset).ok_or_else(|| {
                QuicTransportError::Integrity("reused target offset overflow".to_string())
            })?;
            staged_entry.write_range(entry, target, &buffer[..len]).await?;
            offset += len as u64;
        }
        verify_streamed(chunk, offset, content_id.finalize(), "QUIC baseline after planning")?;
        copied = copied.checked_add(range.size)
            .ok_or_else(|| QuicTransportError::Control("reused byte count overflow".to_string()))?;
    }
    Ok(copied)
}

fn verify_streamed(
    chunk: &DeltaChunkWire,
    size: u64,
    content_id: ContentId,
    label: &str,
) -> Result<(), QuicTransportError> {
    if size != chunk.size_bytes || content_id.to_hex() != chunk.content_id_hex {
        return Err(QuicTransportError::Integrity(format!(
            "{label} differs from its committed content",
        )));
    }
    Ok(())
}

/// Close loss is bounded by wall time even when the peer sends unrelated
/// traffic. Retransmits use the same stream offsets, never appended proofs.
async fn send_proof(
    cx: &Cx,
    link: &mut QuicLink,
    control: &mut NativeQuicFrameTransport,
    proof: &QuicDeltaProof,
    config: &QuicConfig,
) -> Result<(), QuicTransportError> {
    control.send(cx, &mut link.conn, &json_frame(FrameType::Proof, proof)?)?;
    link.flush(cx).await?;
    let frames = link.last_flushed_stream_frames();
    let attempts = TERMINAL_PROOF_RETRANSMIT_ATTEMPTS.min(needmore_pto_attempt_budget(config.idle_timeout));
    let deadline = cx.now() + NEEDMORE_PTO * attempts.saturating_add(1);
    let mut retransmit_at = cx.now() + NEEDMORE_PTO;
    loop {
        cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
        let now = cx.now();
        if now >= deadline { return Ok(()); }
        if now >= retransmit_at {
            link.retransmit_stream_frames(cx, &frames, "changed_chunk_proof_pto").await?;
            retransmit_at = now + NEEDMORE_PTO;
        }
        if let Some(frame) = control.try_recv(cx, &mut link.conn)? {
            match frame.frame_type() {
                FrameType::Close => { link.flush(cx).await?; return Ok(()); }
                FrameType::KeepAlive | FrameType::ObjectComplete => {}
                got => return Err(QuicTransportError::Unexpected { got, expected: "Close | KeepAlive | ObjectComplete" }),
            }
        }
        link.flush(cx).await?;
        let wait = Duration::from_nanos(retransmit_at.min(deadline).duration_since(cx.now()));
        let _ = link.pump_inbound_for(cx, wait).await?;
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn receive(
    cx: &Cx,
    link: &mut QuicLink,
    control: &mut NativeQuicFrameTransport,
    dest_dir: &Path,
    config: &QuicConfig,
    manifest: &TransferManifest,
    options: &QuicReceiveOptions,
    session: QuicDeltaSessionContext,
    plan: delta::ReceivePlan,
    manifest_frame: &Frame,
    request_frame: &Frame,
) -> Result<ReceiveReport, QuicTransportError> {
    cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
    delta::validate_request(manifest, &plan.request)?;
    let mut guard = match staging_guard(dest_dir, manifest).await {
        Ok(guard) => guard,
        Err(error) => {
            if cx.checkpoint().is_err() {
                return Err(QuicTransportError::Cancelled);
            }
            refuse_transfer_in_band(cx, link, control,
                "receiver could not stage the requested QUIC chunks".to_string(),
                Some((session, manifest))).await;
            return Err(error);
        }
    };
    let staging_dir = guard.dir.clone();
    let mut staged: Vec<_> = manifest.entries.iter().map(|entry| {
        QuicStagedEntryReceive::new_with_options(
            staging_dir.join(entry.index.to_string()), entry.size, manifest.entries.len(), options,
        )
    }).collect();
    let mut commit_started = false;
    let result = async {
        let mut received = 0u64;
        for chunk in &plan.request.missing_chunks {
            let index = usize::try_from(chunk.entry_index)
                .map_err(|_| QuicTransportError::Control("changed entry index overflow".to_string()))?;
            let entry = manifest.entries.get(index).ok_or_else(|| {
                QuicTransportError::Integrity("changed chunk references an absent entry".to_string())
            })?;
            let staged_entry = staged.get_mut(index).ok_or_else(|| {
                QuicTransportError::Integrity("changed chunk has no staged entry".to_string())
            })?;
            let mut filled = 0u64;
            let mut content_id = ContentId::streaming();
            while filled < chunk.size_bytes {
                cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
                let frame = next_data_frame(cx, link, control, manifest_frame, request_frame).await?;
                let bytes = delta::checked_data(&frame, chunk, filled)?;
                content_id.update(bytes);
                let target = chunk.entry_offset.checked_add(filled).ok_or_else(|| {
                    QuicTransportError::Integrity("changed target offset overflow".to_string())
                })?;
                keep_peer_alive_while(cx, link, control,
                    staged_entry.write_range(entry, target, bytes)).await?;
                filled += bytes.len() as u64;
            }
            verify_streamed(chunk, filled, content_id.finalize(), "received QUIC changed content")?;
            received = received.checked_add(chunk.size_bytes)
                .ok_or_else(|| QuicTransportError::Control("received chunk byte count overflow".to_string()))?;
        }
        let frame = next_data_frame(cx, link, control, manifest_frame, request_frame).await?;
        if frame.frame_type() != FrameType::ObjectComplete {
            return Err(QuicTransportError::Unexpected {
                got: frame.frame_type(), expected: "ObjectComplete after the exact requested chunk set",
            });
        }
        delta::validate_complete(&parse_json::<delta::Complete>(&frame)?, &plan.request)?;
        let reused = keep_peer_alive_while(cx, link, control, copy_reused(cx, manifest, &plan, &mut staged)).await?;
        cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
        if received != plan.request.missing_bytes || received.checked_add(reused) != Some(manifest.total_bytes) {
            return Err(QuicTransportError::Integrity("changed chunks did not reconstruct the whole object".to_string()));
        }
        // Once publication begins, an error may follow an atomic rename. Do
        // not claim a pre-commit refusal if durability/proof delivery then fails.
        commit_started = true;
        let (mut receipt, committed_paths) = commit_staged_entries(
            cx, link, control, dest_dir, manifest, &mut staged, config, options,
        ).await?;
        if !receipt.committed || !receipt.sha_ok || !receipt.merkle_ok {
            commit_started = false;
            return Err(QuicTransportError::Integrity(
                receipt.reason.unwrap_or_else(|| "QUIC delta reconstruction failed verification".to_string()),
            ));
        }
        receipt.bytes_received = received;
        let proof = make_quic_delta_proof(session, manifest, receipt.clone());
        send_proof(cx, link, control, &proof, config).await?;
        Ok(ReceiveReport {
            transfer_id: manifest.transfer_id.clone(), bytes_received: received, files: receipt.files,
            committed: true, symbols_accepted: 0, feedback_rounds: 0,
            decode_count: 0, decode_micros: 0, committed_paths, peer: link.peer,
        })
    }.await;
    if result.is_err() && !commit_started && cx.checkpoint().is_ok() {
        refuse_transfer_in_band(cx, link, control,
            "receiver could not reconstruct the requested QUIC chunks".to_string(),
            Some((session, manifest))).await;
    }
    // Drop file handles before cooperative cleanup; the still-armed guard is
    // the backstop if this future is cancelled or dropped during an await.
    drop(staged);
    match crate::fs::remove_dir_all(&staging_dir).await {
        Ok(()) => guard.disarm(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => guard.disarm(),
        Err(error) if result.is_ok() => return Err(delta::io_error(cx, error)),
        Err(_) => {}
    }
    result.map_err(|error| {
        if cx.checkpoint().is_err() {
            QuicTransportError::Cancelled
        } else {
            error
        }
    })
}
