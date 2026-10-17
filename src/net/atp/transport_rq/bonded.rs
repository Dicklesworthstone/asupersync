//! Bonded (N-donor) receive loop and donor control loop — z01bbr.6, Phase C
//! completion.
//!
//! One receiver accepts N donor control connections, hands each donor a
//! residue-disjoint slice of the same RaptorQ fountain (Phase A/C1 handshake),
//! ingests every donor's UDP symbols into ONE deduplicated symbol set feeding
//! the SAME per-entry decode pipeline as the single-source receiver (C2/C6),
//! and drives ONE aggregate feedback loop across all donors (C3): per-block
//! deficits become receiver-allocated disjoint repair windows, donor death
//! reallocates the dead donor's outstanding windows to survivors, and a
//! verified commit broadcasts Close so no donor keeps spraying into a
//! completed transfer. Staging → verify → commit is byte-for-byte the
//! single-source `verify_and_commit` path: a failed transfer writes nothing.
//!
//! The UDP symbol datagrams are exactly the wire format [`donate_path`]
//! emits; the control plane reuses the ATP frame codec with JSON payloads
//! (the single-source receiver's convention).

// This split implementation intentionally uses its parent module's private
// protocol machinery as one cohesive unit.
#[allow(clippy::wildcard_imports)]
use super::*;

use crate::channel::mpsc;
use crate::io::AsyncRead;
use crate::net::atp::bonding::{
    BondAuthKeyRef, BondEntryBlockGeometry, BondTransport, BondedDonorIngressStats,
    BondedDonorRepairWindow, BondedDonorSymbolKind, BondedDonorWindowWeight,
    BondedReceiverRetentionPolicy, BondedReceiverSymbolSet, BondedSymbolAuthVerdict,
    BondedSymbolDisposition, BondedSymbolKey, BondingHandshake, BondingReceiverControlPlane,
    EsiWindow, MAX_BONDING_DONORS, allocate_bonded_repair_windows,
    reallocate_failed_bonded_repair_windows, schedule_bonded_repair_continuation,
    verify_bonded_symbol_tag,
};
use crate::net::atp::sdk::{BondedTransferProgress, TransferPhase};

const BONDING_AUTH_REJECTION_TRACE_EVENT: &str = "atp.bonding.auth_rejection";

/// The most repair symbols a donor emits for one `BondedNeedMore`, whatever
/// windows it names (the QUIC sender's per-round bound). The receiver asks
/// again for any deficit left unserved.
const BONDED_MAX_REPAIR_SYMBOLS_PER_NEED_MORE: usize = 1 << 20;

/// The most repair symbols a donor emits for one block of `k` source symbols
/// in one `BondedNeedMore`: twice K plus 64, the per-block headroom a bonded
/// receiver keeps ([`bonded_retention_policy`]). A receiver-named window can
/// span 2^32 ESIs; this keeps it from sizing the donor's work.
fn bonded_need_more_block_repair_cap(k: u32) -> usize {
    usize::try_from(k)
        .unwrap_or(usize::MAX)
        .saturating_mul(2)
        .saturating_add(64)
}

/// Bonded control-plane protocol version carried in the donor hello.
///
/// Version 3 binds the protocol-v4 metadata commitment and RaptorQ geometry
/// during enrollment.
pub const ATP_RQ_BONDED_PROTOCOL: u32 = 3;

/// Donor → receiver bonded hello (`FrameType::Handshake` payload).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct BondedDonorHello {
    protocol: u32,
    transfer_id: String,
    merkle_root_hex: String,
    #[serde(default)]
    metadata_commitment_hex: String,
    #[serde(default)]
    symbol_size: u16,
    #[serde(default)]
    max_block_size: u64,
    symbol_auth: bool,
    offer: BondingHandshake,
}

/// Receiver → donor enrollment reply (`FrameType::HandshakeAck` payload).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct BondedDonorWelcome {
    accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    peer_id: String,
    donor_index: u32,
    donor_count: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    assignment: Option<DonorAssignment>,
    udp_ports: Vec<u16>,
}

/// Donor → receiver spray-round marker (`FrameType::ObjectComplete` payload).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct BondedRoundComplete {
    round: u32,
    donor_index: u32,
    symbols_sent: u64,
}

/// One block's receiver-allocated work for one donor (part of `BondedNeedMore`).
///
/// `source_esis` are missing systematic symbols this donor should retransmit
/// (B4 source-first). `repair_windows` are half-open receiver-allocated
/// repair ESI windows owned exclusively by this donor for this feedback round
/// ([`allocate_bonded_repair_windows`]), so two donors never duplicate a
/// repair ESI even after reallocation. One donor can hold several windows for
/// one block in the same round (e.g. a reallocated dead-donor window plus a
/// fresh deficit window).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct BondedBlockNeed {
    entry_index: u32,
    source_block_number: u8,
    #[serde(default)]
    source_esis: Vec<u32>,
    #[serde(default)]
    repair_windows: Vec<EsiWindow>,
}

/// Receiver → donor aggregated feedback (`FrameType::ObjectRequest` payload).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct BondedNeedMore {
    round: u32,
    blocks: Vec<BondedBlockNeed>,
}

/// Outcome of a committed [`receive_bonded`] call.
#[derive(Debug, Clone)]
pub struct BondedReceiveReport {
    /// Transfer identifier from the bonded descriptor.
    pub transfer_id: String,
    /// Total bytes committed.
    pub bytes_received: u64,
    /// Number of files committed.
    pub files: u32,
    /// Whether the transfer was atomically committed.
    pub committed: bool,
    /// Symbols accepted into the decode pipeline (post-dedup).
    pub symbols_accepted: u64,
    /// Aggregate fountain feedback rounds used.
    pub feedback_rounds: u32,
    /// Absolute committed paths.
    pub committed_paths: Vec<PathBuf>,
    /// Donor control connections enrolled for this transfer.
    pub enrolled_donors: u32,
    /// Repair symbols whose windows were reallocated from dead donors to
    /// survivors (`reallocate_failed_bonded_repair_windows`).
    pub reallocated_repair_windows: u64,
    /// Per-donor ingress counters (sorted by donor index; only donors that
    /// delivered at least one datagram appear).
    pub donor_ingress: Vec<(u32, BondedDonorIngressStats)>,
}

/// Outcome of a [`donate_bonded`] donor session.
#[derive(Debug, Clone)]
pub struct BondedDonateReport {
    /// Transfer identifier from the bonded descriptor.
    pub transfer_id: String,
    /// Receiver-assigned donor index.
    pub donor_index: u32,
    /// Total donors in the bonded transfer.
    pub donor_count: u32,
    /// Feedback rounds this donor served after the initial spray.
    pub feedback_rounds: u32,
    /// Total symbols sprayed across all rounds.
    pub symbols_sent: u64,
    /// Initial source-first spray report.
    pub spray: BondedDonorSendReport,
    /// Receiver's fail-closed commit receipt.
    pub receipt: ReceiveReceipt,
}

/// Rebuild the wire [`TransferManifest`] a bonded descriptor was derived from.
///
/// The descriptor is `TransferManifest` fields + agreed object params, so this
/// is the exact inverse of [`BondTransferDescriptor::from_manifest`]. Bonded
/// descriptors never carry packed members or large-object fragments. The
/// protocol-v4 metadata commitment is carried by the descriptor and passed
/// through unchanged so every donor and the receiver agree on both content and
/// regular-file metadata.
fn manifest_from_bonded_descriptor(descriptor: &BondTransferDescriptor) -> TransferManifest {
    TransferManifest {
        transfer_id: descriptor.transfer_id.clone(),
        root_name: descriptor.root_name.clone(),
        is_directory: descriptor.is_directory,
        total_bytes: descriptor.total_bytes,
        merkle_root_hex: descriptor.merkle_root_hex.clone(),
        metadata: descriptor.metadata.clone(),
        delta_manifest: None,
        entries: descriptor
            .entries
            .iter()
            .map(|entry| ManifestEntry {
                index: entry.index,
                rel_path: entry.rel_path.clone(),
                size: entry.size,
                sha256_hex: entry.sha256_hex.clone(),
                members: Vec::new(),
                fragment: None,
            })
            .collect(),
    }
}

/// One enrolled donor's control connection state on the receiver.
struct BondedDonorConn {
    donor_index: u32,
    control: FrameTransport<TcpStream>,
    peer: SocketAddr,
    alive: bool,
    round_done: bool,
}

/// Receiver-side per-block feedback state.
struct BondedBlockState {
    geometry: BondEntryBlockGeometry,
    decoder_pos: usize,
    /// Accepted-symbol target before the block stops asking for more. Starts
    /// at the block's `K` and is bumped when a coverage-complete block still
    /// fails to decode (RFC 6330 rank deficiency at K-exact solves).
    target_symbols: u32,
    /// Receiver-owned repair high-water mark: the first repair ESI not yet
    /// covered by the donors' round-0 budget or an allocated window.
    repair_cursor: u32,
    /// Repair windows allocated in the most recent feedback round. Windows
    /// held by donors that die are reallocated to survivors
    /// ([`reallocate_failed_bonded_repair_windows`]).
    outstanding: Vec<BondedDonorRepairWindow>,
}

fn bonded_block_states(
    descriptor: &BondTransferDescriptor,
    decoders: &[EntryDecoder],
    round0_repair_budget: u32,
) -> Result<BTreeMap<(u32, u8), BondedBlockState>, RqError> {
    let mut blocks = BTreeMap::new();
    for entry in &descriptor.entries {
        if entry.size == 0 {
            continue;
        }
        let Some(decoder_pos) = decoder_position_for_entry(decoders, entry.index) else {
            continue;
        };
        let Some(block_count) = descriptor.entry_source_block_count(entry.index) else {
            continue;
        };
        for source_block_number in 0..block_count {
            let sbn = u8::try_from(source_block_number).map_err(|_| {
                RqError::Coding(format!(
                    "bonded entry {} needs more than 256 source blocks",
                    entry.index
                ))
            })?;
            let Some(geometry) = descriptor.entry_block_geometry(entry.index, sbn) else {
                continue;
            };
            let k = u32::from(geometry.source_symbols);
            blocks.insert(
                (entry.index, sbn),
                BondedBlockState {
                    geometry,
                    decoder_pos,
                    target_symbols: k,
                    repair_cursor: k.saturating_add(round0_repair_budget),
                    outstanding: Vec::new(),
                },
            );
        }
    }
    Ok(blocks)
}

/// Bounded retention for the shared bonded symbol set (C4).
///
/// The per-block cap leaves generous repair headroom above `K` while keeping
/// a hostile or misbehaving donor from pinning unbounded receiver memory.
fn bonded_retention_policy(
    config: &RqConfig,
    tracked_blocks: usize,
) -> BondedReceiverRetentionPolicy {
    let max_k = fixed_block_k(config).max(1);
    let per_block = max_k.saturating_mul(2).saturating_add(64);
    let total = usize::try_from(per_block)
        .unwrap_or(usize::MAX)
        .saturating_mul(tracked_blocks.max(1));
    BondedReceiverRetentionPolicy::bounded(per_block, total)
}

/// Attribute one symbol to the donor that owns its ESI.
///
/// Receiver-allocated repair windows are authoritative (they survive donor
/// death reallocation); anything else falls back to the Phase-A static
/// residue map. Attribution is observability-only — it never partitions the
/// decoder state (C2).
fn bonded_attribute_donor(
    entry: u32,
    sbn: u8,
    esi: u32,
    donor_count: u32,
    blocks: &BTreeMap<(u32, u8), BondedBlockState>,
) -> u32 {
    if let Some(state) = blocks.get(&(entry, sbn)) {
        for window in &state.outstanding {
            if window.esi_window.contains(esi) {
                return window.donor_index;
            }
        }
    }
    if donor_count <= 1 {
        0
    } else {
        esi % donor_count
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct BondedIngest {
    observed: bool,
    accepted: bool,
}

#[allow(clippy::too_many_arguments)]
fn admit_bonded_datagram<'a, F>(
    buf: &'a [u8],
    n: usize,
    tag: u64,
    symbol_auth: Option<&SecurityContext>,
    donor_count: u32,
    blocks: &BTreeMap<(u32, u8), BondedBlockState>,
    symbol_set: &mut BondedReceiverSymbolSet,
    retention: BondedReceiverRetentionPolicy,
    symbol_size: u16,
    mut resolve_entry: F,
) -> (BondedIngest, Option<(usize, ParsedDatagram, &'a [u8])>)
where
    F: FnMut(u32) -> Option<(usize, ObjectId)>,
{
    let auth_required = symbol_auth.is_some();
    let Some((parsed, payload)) = parse_symbol_datagram_payload(buf, n, tag, auth_required) else {
        return (BondedIngest::default(), None);
    };
    let Some((decoder_pos, object_id)) = resolve_entry(parsed.entry) else {
        return (BondedIngest::default(), None);
    };
    if payload.len() != usize::from(symbol_size) {
        return (BondedIngest::default(), None);
    }
    let donor_index =
        bonded_attribute_donor(parsed.entry, parsed.sbn, parsed.esi, donor_count, blocks);
    // C2 auth gate: verify the bonded symbol tag BEFORE the key can enter the
    // shared set — a forged symbol must not consume dedup or retention state.
    if let Some(context) = symbol_auth {
        let symbol = Symbol::new(
            SymbolId::new(object_id, parsed.sbn, parsed.esi),
            payload.to_vec(),
            parsed.kind,
        );
        match verify_bonded_symbol_tag(context, &symbol, parsed.auth_tag) {
            BondedSymbolAuthVerdict::Accepted(_) => {}
            BondedSymbolAuthVerdict::Rejected(reason) => {
                let count = symbol_set.record_auth_rejection(donor_index);
                if count.is_power_of_two() {
                    bondtrace!(
                        "receiver: auth_reject donor_index={} attribution=esi_schedule reason={:?} count={}",
                        donor_index,
                        reason,
                        count
                    );
                }
                // An unauthenticated datagram is neither decoder input nor
                // liveness progress. Returning observed=false prevents a
                // wrong-key spray from extending stall or round-tail timers.
                return (BondedIngest::default(), None);
            }
        }
    }
    let observed = BondedIngest {
        observed: true,
        accepted: false,
    };
    let key = BondedSymbolKey::new(object_id, parsed.sbn, parsed.esi);
    match symbol_set.record_key_with_retention(donor_index, key, parsed.kind, retention) {
        BondedSymbolDisposition::Accepted(_) => (
            BondedIngest {
                observed: true,
                accepted: true,
            },
            Some((decoder_pos, parsed, payload)),
        ),
        BondedSymbolDisposition::Duplicate(_)
        | BondedSymbolDisposition::RejectedByRetention { .. } => (observed, None),
    }
}

fn trace_bonded_auth_rejections(
    cx: &Cx,
    symbol_set: &BondedReceiverSymbolSet,
    donor_count: u32,
    phase: &str,
) {
    for donor_index in 0..donor_count {
        let count = symbol_set.auth_rejected_symbols(donor_index);
        if count == 0 {
            continue;
        }
        let donor_index = donor_index.to_string();
        let count = count.to_string();
        cx.trace_with_fields(
            BONDING_AUTH_REJECTION_TRACE_EVENT,
            &[
                ("phase", phase),
                ("donor_index", donor_index.as_str()),
                ("attribution", "esi_schedule"),
                ("rejected_symbols", count.as_str()),
            ],
        );
        bondtrace!(
            "receiver: auth_reject_summary phase={} donor_index={} attribution=esi_schedule rejected_symbols={}",
            phase,
            donor_index,
            count
        );
    }
}

/// Feed one bonded donor datagram: parse, verify the per-symbol auth tag,
/// dedupe across donors, then feed the shared per-entry decode pipeline with
/// the same spawn/width gating as the single-source intake (C6).
#[allow(clippy::too_many_arguments)]
async fn feed_bonded_datagram_to_decoders(
    cx: &Cx,
    buf: &[u8],
    n: usize,
    tag: u64,
    symbol_auth: Option<&SecurityContext>,
    donor_count: u32,
    blocks: &BTreeMap<(u32, u8), BondedBlockState>,
    symbol_set: &mut BondedReceiverSymbolSet,
    retention: BondedReceiverRetentionPolicy,
    decoders: &mut [EntryDecoder],
    symbol_size: u16,
) -> Result<BondedIngest, RqError> {
    let (ingest, admitted) = admit_bonded_datagram(
        buf,
        n,
        tag,
        symbol_auth,
        donor_count,
        blocks,
        symbol_set,
        retention,
        symbol_size,
        |entry| {
            let pos = decoder_position_for_entry(decoders, entry)?;
            Some((pos, decoders[pos].object_id))
        },
    );
    let Some((pos, parsed, payload)) = admitted else {
        return Ok(ingest);
    };
    let source_streaming_source = decoders[pos].source_streaming && parsed.kind.is_source();
    let (allow_spawn_decode, decode_width_budget) = if source_streaming_source {
        (false, 0)
    } else {
        let decode_width_budget = rq_decode_width_budget_for_cx(cx, decoders, symbol_size);
        let mut pending_decode_jobs = rq_pending_decode_jobs(decoders);
        if pending_decode_jobs >= decode_width_budget {
            drain_ready_decodes(cx, decoders, false, decode_width_budget).await?;
            pending_decode_jobs = rq_pending_decode_jobs(decoders);
        }
        (
            pending_decode_jobs < decode_width_budget,
            decode_width_budget,
        )
    };
    let feed = feed_symbol_with_cx(
        cx,
        &mut decoders[pos],
        &parsed,
        payload,
        symbol_size,
        symbol_auth,
        allow_spawn_decode,
        decode_width_budget,
        false,
    )
    .await?;
    Ok(BondedIngest {
        observed: true,
        accepted: feed.accepted,
    })
}

fn bonded_donor_hello_refusal(
    hello: &BondedDonorHello,
    descriptor: &BondTransferDescriptor,
    symbol_auth_enabled: bool,
) -> Option<String> {
    if hello.protocol != ATP_RQ_BONDED_PROTOCOL {
        Some(format!(
            "unsupported bonded protocol {} (this peer speaks {ATP_RQ_BONDED_PROTOCOL})",
            hello.protocol
        ))
    } else if hello.transfer_id != descriptor.transfer_id {
        Some(format!(
            "bonded hello names transfer {} but this receiver serves {}",
            hello.transfer_id, descriptor.transfer_id
        ))
    } else if hello.merkle_root_hex != descriptor.merkle_root_hex {
        Some("bonded hello merkle root does not match the agreed descriptor".to_string())
    } else if descriptor
        .metadata
        .as_ref()
        .is_none_or(|metadata| metadata.commitment_hex != hello.metadata_commitment_hex)
    {
        Some("bonded hello metadata commitment does not match the agreed descriptor".to_string())
    } else if hello.symbol_size != descriptor.symbol_size {
        Some(format!(
            "bonded hello symbol size {} does not match the agreed descriptor's {}",
            hello.symbol_size, descriptor.symbol_size
        ))
    } else if hello.max_block_size != descriptor.max_block_size {
        Some(format!(
            "bonded hello max block size {} does not match the agreed descriptor's {}",
            hello.max_block_size, descriptor.max_block_size
        ))
    } else if hello.symbol_auth != symbol_auth_enabled {
        Some(format!(
            "symbol authentication mismatch: donor={}, receiver={symbol_auth_enabled}",
            hello.symbol_auth
        ))
    } else {
        None
    }
}

/// Accept and enroll donor control connections until every expected donor is
/// registered. Invalid hellos are rejected without consuming a donor slot.
#[allow(clippy::too_many_arguments)]
async fn accept_bonded_donors(
    cx: &Cx,
    control_listener: &TcpListener,
    control_plane: &mut BondingReceiverControlPlane,
    descriptor: &BondTransferDescriptor,
    symbol_auth_enabled: bool,
    udp_ports: &[u16],
    peer_id: &str,
    accept_timeout: Duration,
) -> Result<Vec<BondedDonorConn>, RqError> {
    let expected = control_plane.registry().expected_donor_count();
    let mut conns = Vec::with_capacity(usize::try_from(expected).unwrap_or(0));
    let mut attempts_left = expected.saturating_mul(8).saturating_add(8);
    while !control_plane.is_complete() {
        cx.checkpoint().map_err(|_| RqError::Cancelled)?;
        if attempts_left == 0 {
            return Err(RqError::HandshakeRejected(
                "bonded enrollment gave up: too many rejected donor hellos".to_string(),
            ));
        }
        attempts_left -= 1;
        let (stream, peer) = match crate::time::timeout(
            cx.now(),
            accept_timeout,
            control_listener.accept(),
        )
        .await
        {
            Ok(Ok(accepted)) => accepted,
            Ok(Err(err)) => return Err(RqError::Io(err)),
            Err(_elapsed) => {
                return Err(RqError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!(
                        "bonded enrollment timed out after {accept_timeout:?} with {} of {expected} donors",
                        control_plane.registry().enrolled_count()
                    ),
                )));
            }
        };
        let mut control = FrameTransport::new(stream);
        let hello_frame = match crate::time::timeout(cx.now(), accept_timeout, control.recv()).await
        {
            Ok(Ok(frame)) => frame,
            Ok(Err(_)) | Err(_) => continue,
        };
        let reject = |reason: String| BondedDonorWelcome {
            accepted: false,
            reason: Some(reason),
            peer_id: peer_id.to_string(),
            donor_index: 0,
            donor_count: expected,
            assignment: None,
            udp_ports: Vec::new(),
        };
        if hello_frame.frame_type() != FrameType::Handshake {
            let _ = control
                .send(&json_frame(
                    FrameType::HandshakeAck,
                    &reject("expected bonded Handshake frame".to_string()),
                )?)
                .await;
            continue;
        }
        let hello: BondedDonorHello = match parse_json(&hello_frame) {
            Ok(hello) => hello,
            Err(_) => {
                let _ = control
                    .send(&json_frame(
                        FrameType::HandshakeAck,
                        &reject("malformed bonded hello".to_string()),
                    )?)
                    .await;
                continue;
            }
        };
        let refusal = bonded_donor_hello_refusal(&hello, descriptor, symbol_auth_enabled);
        if let Some(reason) = refusal {
            let _ = control
                .send(&json_frame(FrameType::HandshakeAck, &reject(reason))?)
                .await;
            continue;
        }
        let enrollment = match control_plane.enroll_next_donor(&hello.offer) {
            Ok(enrollment) => enrollment,
            Err(err) => {
                let _ = control
                    .send(&json_frame(
                        FrameType::HandshakeAck,
                        &reject(err.to_string()),
                    )?)
                    .await;
                continue;
            }
        };
        bondtrace!(
            "receiver: donor_admitted {}",
            serde_json::to_string(&enrollment.admission_trace()).unwrap_or_default()
        );
        control
            .send(&json_frame(
                FrameType::HandshakeAck,
                &BondedDonorWelcome {
                    accepted: true,
                    reason: None,
                    peer_id: peer_id.to_string(),
                    donor_index: enrollment.donor_index,
                    donor_count: enrollment.assignment.donor_count,
                    assignment: Some(enrollment.assignment.clone()),
                    udp_ports: udp_ports.to_vec(),
                },
            )?)
            .await?;
        conns.push(BondedDonorConn {
            donor_index: enrollment.donor_index,
            control,
            peer,
            alive: true,
            round_done: false,
        });
    }
    Ok(conns)
}

/// Pump donor symbols and control frames until every live donor has marked the
/// current spray round complete (or every donor is dead).
#[allow(clippy::too_many_arguments)]
async fn pump_bonded_round(
    cx: &Cx,
    udp: &mut RqReceiverUdpFanout,
    conns: &mut [BondedDonorConn],
    round: u32,
    tag: u64,
    symbol_auth: Option<&SecurityContext>,
    donor_count: u32,
    blocks: &BTreeMap<(u32, u8), BondedBlockState>,
    symbol_set: &mut BondedReceiverSymbolSet,
    retention: BondedReceiverRetentionPolicy,
    decoders: &mut [EntryDecoder],
    symbol_size: u16,
    symbols_accepted: &mut u64,
    stall_window: Duration,
) -> Result<(), RqError> {
    use std::future::poll_fn;
    use std::pin::Pin;
    use std::task::Poll;

    enum BondedReady {
        Udp(crate::net::UdpRecvBatch),
        Control { conn_index: usize, len: usize },
        ControlClosed { conn_index: usize },
        Stalled,
    }

    let packet_size = usize::from(symbol_size) + AUTH_DGRAM_HEADER + 64;
    let mut cbuf = vec![0u8; 65536];
    let mut stall_sleep = crate::time::Sleep::after(cx.now_for_observability(), stall_window);

    loop {
        cx.checkpoint().map_err(|_| RqError::Cancelled)?;
        if conns.iter().all(|conn| !conn.alive || conn.round_done) {
            return Ok(());
        }
        let _ = drain_ready_decodes_if_pending(cx, decoders, symbol_size).await?;

        // Drain any control frame a prior read already buffered before parking.
        let mut buffered: Option<(usize, Frame)> = None;
        for (conn_index, conn) in conns.iter_mut().enumerate() {
            if !conn.alive {
                continue;
            }
            if let Some(frame) = conn
                .control
                .codec
                .decode(&mut conn.control.rbuf)
                .map_err(|e| RqError::Frame(e.to_string()))?
            {
                buffered = Some((conn_index, frame));
                break;
            }
        }
        if let Some((conn_index, frame)) = buffered {
            handle_bonded_donor_frame(conns, conn_index, round, frame).await?;
            stall_sleep.reset_after(cx.now_for_observability(), stall_window);
            continue;
        }

        let ready = poll_fn(|task_cx| {
            if Pin::new(&mut stall_sleep).poll(task_cx).is_ready() {
                return Poll::Ready(Ok::<BondedReady, std::io::Error>(BondedReady::Stalled));
            }
            match udp.poll_recv_batch_any(task_cx, RQ_INBOUND_PUMP_BATCH, packet_size) {
                Poll::Ready(Ok((_socket_index, batch))) => {
                    return Poll::Ready(Ok(BondedReady::Udp(batch)));
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {}
            }
            for (conn_index, conn) in conns.iter_mut().enumerate() {
                if !conn.alive {
                    continue;
                }
                let mut read_buf = ReadBuf::new(&mut cbuf);
                match Pin::new(&mut conn.control.stream).poll_read(task_cx, &mut read_buf) {
                    Poll::Ready(Ok(())) => {
                        let len = read_buf.filled().len();
                        return Poll::Ready(Ok(if len == 0 {
                            BondedReady::ControlClosed { conn_index }
                        } else {
                            BondedReady::Control { conn_index, len }
                        }));
                    }
                    Poll::Ready(Err(_)) => {
                        return Poll::Ready(Ok(BondedReady::ControlClosed { conn_index }));
                    }
                    Poll::Pending => {}
                }
            }
            Poll::Pending
        })
        .await?;

        match ready {
            BondedReady::Udp(mut batch) => {
                let mut progressed = false;
                for packet in &batch.packets {
                    let ingest = feed_bonded_datagram_to_decoders(
                        cx,
                        &packet.payload,
                        packet.payload.len(),
                        tag,
                        symbol_auth,
                        donor_count,
                        blocks,
                        symbol_set,
                        retention,
                        decoders,
                        symbol_size,
                    )
                    .await?;
                    progressed |= ingest.observed;
                    if ingest.accepted {
                        *symbols_accepted = (*symbols_accepted).saturating_add(1);
                    }
                }
                udp.recycle_recv_batch(&mut batch, RQ_INBOUND_PUMP_BATCH);
                if progressed {
                    stall_sleep.reset_after(cx.now_for_observability(), stall_window);
                }
            }
            BondedReady::Control { conn_index, len } => {
                conns[conn_index]
                    .control
                    .rbuf
                    .extend_from_slice(&cbuf[..len]);
                stall_sleep.reset_after(cx.now_for_observability(), stall_window);
            }
            BondedReady::ControlClosed { conn_index } => {
                bondtrace!(
                    "receiver: donor_dead donor_index={} peer={} round={}",
                    conns[conn_index].donor_index,
                    conns[conn_index].peer,
                    round
                );
                conns[conn_index].alive = false;
                stall_sleep.reset_after(cx.now_for_observability(), stall_window);
            }
            BondedReady::Stalled => {
                trace_bonded_auth_rejections(cx, symbol_set, donor_count, "stalled");
                return Err(RqError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!(
                        "bonded receive stalled in round {round}: no donor symbols or control frames for {stall_window:?}"
                    ),
                )));
            }
        }
    }
}

/// Apply one decoded donor control frame to the receiver round state.
async fn handle_bonded_donor_frame(
    conns: &mut [BondedDonorConn],
    conn_index: usize,
    round: u32,
    frame: Frame,
) -> Result<(), RqError> {
    match frame.frame_type() {
        FrameType::ObjectComplete => {
            let complete: BondedRoundComplete = parse_json(&frame)?;
            if complete.round > round {
                return Err(RqError::Frame(format!(
                    "bonded donor {} reported future round {} (receiver round {round})",
                    conns[conn_index].donor_index, complete.round
                )));
            }
            if complete.round == round {
                conns[conn_index].round_done = true;
            }
        }
        FrameType::KeepAlive => {
            let keep_alive =
                Frame::empty(FrameType::KeepAlive).map_err(|e| RqError::Frame(e.to_string()))?;
            if conns[conn_index].control.send(&keep_alive).await.is_err() {
                conns[conn_index].alive = false;
            }
        }
        FrameType::Close => {
            // Donor is leaving gracefully; survivors absorb its share.
            conns[conn_index].alive = false;
        }
        other => {
            bondtrace!(
                "receiver: donor {} sent unexpected {:?}; dropping that donor",
                conns[conn_index].donor_index,
                other
            );
            conns[conn_index].alive = false;
        }
    }
    Ok(())
}

/// Drain UDP symbols that raced behind the donors' round markers, mirroring
/// the single-source `drain_round_tail` quiet-window semantics through the
/// bonded dedup/auth intake.
#[allow(clippy::too_many_arguments)]
async fn drain_bonded_round_tail(
    cx: &Cx,
    udp: &mut RqReceiverUdpFanout,
    tag: u64,
    symbol_auth: Option<&SecurityContext>,
    donor_count: u32,
    blocks: &BTreeMap<(u32, u8), BondedBlockState>,
    symbol_set: &mut BondedReceiverSymbolSet,
    retention: BondedReceiverRetentionPolicy,
    decoders: &mut [EntryDecoder],
    symbol_size: u16,
    symbols_accepted: &mut u64,
    quiet_window: Duration,
) -> Result<u64, RqError> {
    if quiet_window.is_zero() {
        return Ok(0);
    }

    use std::future::poll_fn;
    use std::pin::Pin;
    use std::task::Poll;

    let mut rbuf = vec![0u8; usize::from(symbol_size) + AUTH_DGRAM_HEADER + 64];
    let mut quiet_sleep = crate::time::Sleep::after(cx.now_for_observability(), quiet_window);
    let hard_cap = quiet_window.saturating_mul(8).max(Duration::from_millis(1));
    let mut hard_sleep = crate::time::Sleep::after(cx.now_for_observability(), hard_cap);
    let mut drained = 0u64;

    loop {
        cx.checkpoint().map_err(|_| RqError::Cancelled)?;
        let ready = poll_fn(|task_cx| {
            if Pin::new(&mut hard_sleep).poll(task_cx).is_ready() {
                return Poll::Ready(Ok::<Option<usize>, std::io::Error>(None));
            }
            match udp.poll_recv_any(task_cx, &mut rbuf) {
                Poll::Ready(Ok((_socket_index, n))) => return Poll::Ready(Ok(Some(n))),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {}
            }
            if Pin::new(&mut quiet_sleep).poll(task_cx).is_ready() {
                return Poll::Ready(Ok(None));
            }
            Poll::Pending
        })
        .await?;

        let Some(n) = ready else {
            return Ok(drained);
        };
        let ingest = feed_bonded_datagram_to_decoders(
            cx,
            &rbuf,
            n,
            tag,
            symbol_auth,
            donor_count,
            blocks,
            symbol_set,
            retention,
            decoders,
            symbol_size,
        )
        .await?;
        if ingest.observed {
            drained += 1;
            if ingest.accepted {
                *symbols_accepted = (*symbols_accepted).saturating_add(1);
            }
            quiet_sleep.reset_after(cx.now_for_observability(), quiet_window);
        }
        let _ = drain_ready_decodes_if_pending(cx, decoders, symbol_size).await?;
    }
}

/// Emit one best-effort live [`BondedTransferProgress`] snapshot to an
/// optional SDK progress sink.
///
/// Everything a snapshot needs is derivable at the receiver's round boundary:
/// `blocks_remaining` is the count of tracked blocks whose owning entry has
/// not yet decoded, `blocks_total` is the number of tracked blocks, and the
/// per-donor ingress is exactly the tuple the terminal report carries. The
/// send uses `try_send` and ignores a full or closed channel so live progress
/// can never block or fail the transfer.
#[allow(clippy::too_many_arguments)]
fn emit_bonded_progress(
    progress: Option<&mpsc::Sender<BondedTransferProgress>>,
    manifest: &TransferManifest,
    blocks: &BTreeMap<(u32, u8), BondedBlockState>,
    decoders: &[EntryDecoder],
    symbol_set: &BondedReceiverSymbolSet,
    symbols_accepted: u64,
    feedback_rounds: u32,
    reallocated_repair_windows: u64,
    enrolled_donors: u32,
    phase: TransferPhase,
) {
    let Some(sink) = progress else {
        return;
    };
    let blocks_total = u32::try_from(blocks.len()).unwrap_or(u32::MAX);
    let blocks_remaining = u32::try_from(
        blocks
            .values()
            .filter(|state| !decoders[state.decoder_pos].complete)
            .count(),
    )
    .unwrap_or(u32::MAX);
    let donor_ingress: Vec<(u32, BondedDonorIngressStats)> = symbol_set
        .donor_targets()
        .into_iter()
        .filter_map(|donor| symbol_set.donor_stats(donor).map(|stats| (donor, stats)))
        .collect();
    let snapshot = BondedTransferProgress {
        transfer_id: manifest.transfer_id.clone(),
        symbols_accepted,
        bytes_total: manifest.total_bytes,
        blocks_total,
        blocks_remaining,
        feedback_rounds,
        reallocated_repair_windows,
        enrolled_donors,
        donor_ingress,
        phase,
    };
    let _ = sink.try_send(snapshot);
}

const MAX_BONDING_ADVERTISED_UDP_IPS: usize = 16;
const MAX_BONDING_RECEIVER_ENDPOINTS: usize = 1024;

fn validate_bonded_advertised_udp_ips(
    bind_ip: std::net::IpAddr,
    advertised: &[std::net::IpAddr],
) -> Result<Vec<std::net::IpAddr>, RqError> {
    if advertised.is_empty() {
        return Ok(vec![bind_ip]);
    }
    if advertised.len() > MAX_BONDING_ADVERTISED_UDP_IPS {
        return Err(RqError::Source(format!(
            "bonded receiver advertised {} UDP IPs, max {MAX_BONDING_ADVERTISED_UDP_IPS}",
            advertised.len()
        )));
    }

    let mut unique = BTreeSet::new();
    let mut validated = Vec::with_capacity(advertised.len());
    for &ip in advertised {
        if ip.is_unspecified() {
            return Err(RqError::Source(
                "bonded receiver UDP advertisement must not contain an unspecified IP".to_string(),
            ));
        }
        if ip.is_multicast() || matches!(ip, std::net::IpAddr::V4(ipv4) if ipv4.is_broadcast()) {
            return Err(RqError::Source(format!(
                "bonded receiver UDP advertisement must be unicast, got {ip}"
            )));
        }
        if ip.is_ipv4() != bind_ip.is_ipv4() {
            return Err(RqError::Source(format!(
                "bonded receiver UDP advertisement {ip} does not match bind address family {bind_ip}"
            )));
        }
        if unique.insert(ip) {
            validated.push(ip);
        }
    }
    Ok(validated)
}

fn validate_bonded_receiver_udp_endpoints(endpoints: &[SocketAddr]) -> Result<(), RqError> {
    if endpoints.is_empty() {
        return Err(RqError::HandshakeRejected(
            "bonded welcome advertised no receiver UDP endpoints".to_string(),
        ));
    }
    if endpoints.len() > MAX_BONDING_RECEIVER_ENDPOINTS {
        return Err(RqError::HandshakeRejected(format!(
            "bonded welcome advertised {} receiver UDP endpoints, max {MAX_BONDING_RECEIVER_ENDPOINTS}",
            endpoints.len()
        )));
    }

    let mut unique = BTreeSet::new();
    for &endpoint in endpoints {
        if endpoint.port() == 0 {
            return Err(RqError::HandshakeRejected(format!(
                "bonded welcome advertised receiver UDP port zero at {endpoint}"
            )));
        }
        if endpoint.ip().is_multicast()
            || matches!(endpoint.ip(), std::net::IpAddr::V4(ip) if ip.is_broadcast())
        {
            return Err(RqError::HandshakeRejected(format!(
                "bonded welcome advertised non-unicast receiver UDP endpoint {endpoint}"
            )));
        }
        if !unique.insert(endpoint) {
            return Err(RqError::HandshakeRejected(format!(
                "bonded welcome advertised duplicate receiver UDP endpoint {endpoint}"
            )));
        }
    }
    Ok(())
}

/// Receive one bonded transfer from up to `expected_donors` simultaneous
/// donors, verify it fail-closed, and commit it into `dest_dir`.
///
/// The receiver binds its UDP symbol plane first, then accepts one control
/// connection per donor on `control_listener` (the Phase C1 enrollment
/// handshake: the donor's [`BondingHandshake`] offer is negotiated by
/// [`BondingReceiverControlPlane`] and answered with the [`DonorAssignment`]
/// that [`donate_path`] executes). All donors spray into ONE deduplicated
/// symbol set feeding the same per-entry decode pipeline as the single-source
/// receiver; a one-donor bonded transfer is intentionally isomorphic to
/// [`receive_once`] (z01bbr.8.5). Aggregate per-block deficits drive ONE
/// feedback loop broadcast to all live donors (C3) as receiver-allocated
/// disjoint repair windows plus source-first retransmit lists; a donor that
/// dies mid-transfer has its outstanding windows reallocated to survivors
/// ([`reallocate_failed_bonded_repair_windows`]). Commit is the single-source
/// staging → SHA-256 → merkle `verify_and_commit`: a failed transfer writes
/// nothing to `dest_dir`.
#[allow(clippy::too_many_arguments)]
pub async fn receive_bonded(
    cx: &Cx,
    descriptor: &BondTransferDescriptor,
    dest_dir: &Path,
    control_listener: &TcpListener,
    udp_bind_ip: &str,
    expected_donors: u32,
    config: RqConfig,
    peer_id: &str,
    progress: Option<mpsc::Sender<BondedTransferProgress>>,
) -> Result<BondedReceiveReport, RqError> {
    receive_bonded_with_options(
        cx,
        descriptor,
        dest_dir,
        control_listener,
        udp_bind_ip,
        expected_donors,
        config,
        peer_id,
        progress,
        RqReceiveOptions::default(),
    )
    .await
}

/// [`receive_bonded`] with explicit receiver-only filesystem options.
///
/// Options are validated before the UDP symbol plane is bound or destination
/// staging is created. The validated bonded descriptor still determines
/// the committed topology; these options only authorize supported receiver
/// reconstruction policies such as FIFO materialization.
#[allow(clippy::too_many_arguments)]
pub async fn receive_bonded_with_options(
    cx: &Cx,
    descriptor: &BondTransferDescriptor,
    dest_dir: &Path,
    control_listener: &TcpListener,
    udp_bind_ip: &str,
    expected_donors: u32,
    config: RqConfig,
    peer_id: &str,
    progress: Option<mpsc::Sender<BondedTransferProgress>>,
    options: RqReceiveOptions,
) -> Result<BondedReceiveReport, RqError> {
    receive_bonded_with_options_and_advertised_ips(
        cx,
        descriptor,
        dest_dir,
        control_listener,
        udp_bind_ip,
        expected_donors,
        config,
        peer_id,
        progress,
        options,
        &[],
    )
    .await
}

/// [`receive_bonded_with_options`] with explicit receiver UDP IP
/// advertisement.
///
/// Each supplied IP is combined with every actually-bound UDP fanout port and
/// carried in the donor assignment. The list is operator authority: this
/// function does not guess which local interfaces are reachable from a donor.
/// An empty list preserves the compatibility behavior, advertising the bind IP
/// (including an unspecified bind address for protocol-v3 donors, which safely
/// replace it with the connected control IP plus the separately carried ports).
///
/// Explicit addresses must be unicast, non-unspecified, and in the same
/// address family as `udp_bind_ip`. They may differ from the bind IP when an
/// operator has configured routing or NAT that maps the advertised address to
/// the bound socket. Validation completes before any UDP socket is bound.
#[allow(clippy::too_many_arguments)]
pub async fn receive_bonded_with_options_and_advertised_ips(
    cx: &Cx,
    descriptor: &BondTransferDescriptor,
    dest_dir: &Path,
    control_listener: &TcpListener,
    udp_bind_ip: &str,
    expected_donors: u32,
    mut config: RqConfig,
    peer_id: &str,
    progress: Option<mpsc::Sender<BondedTransferProgress>>,
    options: RqReceiveOptions,
    advertised_udp_ips: &[std::net::IpAddr],
) -> Result<BondedReceiveReport, RqError> {
    options.validate()?;
    cx.checkpoint().map_err(|_| RqError::Cancelled)?;
    descriptor
        .validate()
        .map_err(|err| RqError::Source(format!("bonded descriptor invalid: {err}")))?;
    if expected_donors == 0 {
        return Err(RqError::Source(
            "bonded receive needs at least one expected donor".to_string(),
        ));
    }
    apply_bonded_descriptor_config(descriptor, &mut config)?;
    let symbol_auth = config.symbol_auth_context()?;
    let symbol_auth_enabled = symbol_auth.is_some();
    let manifest = manifest_from_bonded_descriptor(descriptor);
    validate_manifest(&manifest, &config)?;
    check_bonded_receive_symbol_budget(descriptor, &config)?;

    // UDP symbol plane first so every enrollment can advertise the ports.
    let bind_ip: std::net::IpAddr = udp_bind_ip
        .parse()
        .map_err(|e| RqError::Source(format!("invalid UDP bind ip '{udp_bind_ip}': {e}")))?;
    let advertised_udp_ips = validate_bonded_advertised_udp_ips(bind_ip, advertised_udp_ips)?;
    let endpoint_count = advertised_udp_ips
        .len()
        .checked_mul(config.udp_fanout.max(1))
        .ok_or_else(|| RqError::Source("bonded receiver endpoint count overflow".to_string()))?;
    if endpoint_count > MAX_BONDING_RECEIVER_ENDPOINTS {
        return Err(RqError::Source(format!(
            "bonded receiver would advertise {endpoint_count} UDP endpoints, max {MAX_BONDING_RECEIVER_ENDPOINTS}"
        )));
    }
    let recv_buf_bytes = if manifest.total_bytes == 0 {
        16 * 1024 * 1024
    } else {
        usize::try_from(manifest.total_bytes.saturating_add(32 * 1024 * 1024))
            .unwrap_or(usize::MAX)
            .clamp(16 * 1024 * 1024, 120 * 1024 * 1024)
    };
    let mut udp =
        RqReceiverUdpFanout::bind(bind_ip, config.udp_fanout.max(1), recv_buf_bytes).await?;
    let udp_ports = udp.local_ports()?;
    let receiver_udp_endpoints: Vec<SocketAddr> = advertised_udp_ips
        .iter()
        .flat_map(|&ip| udp_ports.iter().map(move |&port| SocketAddr::new(ip, port)))
        .collect();
    validate_bonded_receiver_udp_endpoints(&receiver_udp_endpoints)?;

    // C1 donor admission control plane.
    let auth_key_ref = symbol_auth_enabled.then(|| {
        BondAuthKeyRef::ControlPlane(
            descriptor
                .auth_key_id
                .clone()
                .unwrap_or_else(|| "rq-config-symbol-auth".to_string()),
        )
    });
    let receiver_offer = BondingHandshake::v1_static(
        [
            BondTransport::DirectIp,
            BondTransport::Ssh,
            BondTransport::Tailscale,
        ],
        expected_donors,
        symbol_auth_enabled,
    );
    let mut control_plane = BondingReceiverControlPlane::new(
        receiver_offer,
        expected_donors,
        receiver_udp_endpoints,
        auth_key_ref,
    )
    .map_err(|err| RqError::HandshakeRejected(err.to_string()))?;
    // Every deep subtree of the bonded receive is boxed behind
    // `dyn Future + Send` at its per-round await (one allocation per call), so
    // callers that spawn this future keep their `Send` proof within rustc's
    // default recursion depth (br-asupersync-lf8muy).
    let mut conns = erase_send(accept_bonded_donors(
        cx,
        control_listener,
        &mut control_plane,
        descriptor,
        symbol_auth_enabled,
        &udp_ports,
        peer_id,
        config.accept_timeout,
    ))
    .await?;
    let enrolled_donors = u32::try_from(conns.len()).unwrap_or(u32::MAX);
    let donor_count = expected_donors;

    // Same staging + per-entry decode pipeline as the single-source receiver.
    let staging_guard = create_receive_staging_guard(dest_dir, &manifest.transfer_id).await?;
    let staging_dir = staging_guard.dir().to_path_buf();
    let single_file_fragment_staging = single_file_fragment_staging_path(&manifest, &staging_dir);
    let source_streaming = config.repair_overhead <= 1.0 && config.source_retransmit_rounds > 0;
    let symbol_size = config.symbol_size;
    let receiver_max_block_size = config.max_block_size;
    let mut decoders: Vec<EntryDecoder> = manifest
        .entries
        .iter()
        .map(|e| {
            new_bonded_entry_decoder(
                e,
                &manifest,
                &staging_dir,
                single_file_fragment_staging.as_deref(),
                symbol_size,
                receiver_max_block_size,
                descriptor.max_block_size,
                &config,
                symbol_auth.as_ref(),
                source_streaming,
            )
        })
        .collect();

    let round0_repair_budget = bonded_initial_repair_symbols_per_block(&config)?;
    let mut blocks = bonded_block_states(descriptor, &decoders, round0_repair_budget)?;
    let retention = bonded_retention_policy(&config, blocks.len());
    let tag = transfer_tag(&manifest.transfer_id);
    let stall_window = config.accept_timeout.max(Duration::from_secs(1));
    let mut symbol_set = BondedReceiverSymbolSet::new();
    let mut symbols_accepted = 0u64;
    let mut feedback_rounds: u32 = 0;
    let mut round: u32 = 0;
    let mut reallocated_repair_windows = 0u64;
    bondtrace!(
        "receiver: bonded_start transfer_id={} donors={} entries={} blocks={} auth={} udp_ports={:?}",
        manifest.transfer_id,
        enrolled_donors,
        manifest.entries.len(),
        blocks.len(),
        symbol_auth_enabled,
        udp_ports
    );

    loop {
        cx.checkpoint().map_err(|_| RqError::Cancelled)?;
        erase_send(pump_bonded_round(
            cx,
            &mut udp,
            &mut conns,
            round,
            tag,
            symbol_auth.as_ref(),
            donor_count,
            &blocks,
            &mut symbol_set,
            retention,
            &mut decoders,
            symbol_size,
            &mut symbols_accepted,
            stall_window,
        ))
        .await?;
        erase_send(drain_bonded_round_tail(
            cx,
            &mut udp,
            tag,
            symbol_auth.as_ref(),
            donor_count,
            &blocks,
            &mut symbol_set,
            retention,
            &mut decoders,
            symbol_size,
            &mut symbols_accepted,
            config.round_tail_drain,
        ))
        .await?;
        let _ = erase_send(flush_and_seed_source_streaming_round_boundary(
            cx,
            &mut decoders,
            symbol_size,
            symbol_auth.as_ref(),
        ))
        .await?;
        let decode_width_budget = rq_decode_width_budget_for_cx(cx, &decoders, symbol_size);
        erase_send(join_all_pending_decodes(
            cx,
            &mut decoders,
            decode_width_budget,
        ))
        .await?;
        erase_send(flush_cached_entry_staging_files(&mut decoders)).await?;

        let pending: Vec<u32> = decoders
            .iter()
            .filter(|d| !d.complete)
            .map(|d| d.index)
            .collect();
        // Feedback targets cover only blocks of entries that still need
        // symbols; completed entries must never re-enter the request plan.
        let plan_blocks: Vec<(ObjectId, u8, u32)> = blocks
            .values()
            .filter(|state| !decoders[state.decoder_pos].complete)
            .map(|state| {
                (
                    state.geometry.object_id,
                    state.geometry.source_block_number,
                    state.target_symbols,
                )
            })
            .collect();
        let metrics =
            symbol_set.live_progress_metrics(plan_blocks.iter().copied(), pending.is_empty());
        let progress_phase = if pending.is_empty() {
            "complete"
        } else {
            "round_end"
        };
        metrics.trace_progress(cx, progress_phase);
        if !pending.is_empty() {
            trace_bonded_auth_rejections(cx, &symbol_set, donor_count, progress_phase);
        }

        // Live progress snapshot at the round boundary (best-effort; never
        // blocks or fails the transfer). `blocks_remaining` is the count of
        // blocks whose owning entry has not yet decoded, and the per-donor
        // ingress mirrors the terminal report's `donor_ingress`.
        emit_bonded_progress(
            progress.as_ref(),
            &manifest,
            &blocks,
            &decoders,
            &symbol_set,
            symbols_accepted,
            feedback_rounds,
            reallocated_repair_windows,
            enrolled_donors,
            TransferPhase::DataTransfer,
        );

        if pending.is_empty() {
            // Verify + commit exactly like the single-source path, then tell
            // every surviving donor to stop (Close wins over stale deficits).
            // Final cancel checkpoint before the irreversible commit: a Cx
            // aborted after the last decode round still unwinds here and
            // commits nothing (the module's cancel-correctness contract).
            cx.checkpoint().map_err(|_| RqError::Cancelled)?;
            let receipt = erase_send(verify_and_commit_with_options(
                &manifest,
                &mut decoders,
                dest_dir,
                symbols_accepted,
                feedback_rounds,
                &BTreeMap::new(),
                &CompletionDigestIndex::default(),
                options,
            ))
            .await?;
            let proof = json_frame(FrameType::Proof, &receipt)?;
            for conn in conns.iter_mut().filter(|conn| conn.alive) {
                if conn.control.send(&proof).await.is_err() {
                    conn.alive = false;
                    continue;
                }
                drain_sender_close_after_proof(cx, &mut conn.control, "bonded").await;
            }
            if !receipt.committed {
                trace_bonded_auth_rejections(cx, &symbol_set, donor_count, "failed");
                // Terminal failure snapshot: a progress consumer watching the
                // phase sees `Failed` for the decoded-but-unverified case
                // (other terminal errors/cancels are observed as the stream
                // closes plus the receiver's join outcome).
                emit_bonded_progress(
                    progress.as_ref(),
                    &manifest,
                    &blocks,
                    &decoders,
                    &symbol_set,
                    symbols_accepted,
                    feedback_rounds,
                    reallocated_repair_windows,
                    enrolled_donors,
                    TransferPhase::Failed,
                );
                return Err(RqError::Integrity(
                    receipt
                        .reason
                        .unwrap_or_else(|| "verification failed".to_string()),
                ));
            }
            let committed_paths: Vec<PathBuf> =
                receipt.committed_paths.iter().map(PathBuf::from).collect();
            // Final terminal snapshot: all blocks decoded and committed.
            emit_bonded_progress(
                progress.as_ref(),
                &manifest,
                &blocks,
                &decoders,
                &symbol_set,
                symbols_accepted,
                feedback_rounds,
                reallocated_repair_windows,
                enrolled_donors,
                TransferPhase::Completed,
            );
            trace_bonded_auth_rejections(cx, &symbol_set, donor_count, "completed");
            return Ok(BondedReceiveReport {
                transfer_id: manifest.transfer_id,
                bytes_received: receipt.bytes_received,
                files: receipt.files,
                committed: true,
                symbols_accepted,
                feedback_rounds,
                committed_paths,
                enrolled_donors,
                reallocated_repair_windows,
                donor_ingress: symbol_set
                    .donor_targets()
                    .into_iter()
                    .filter_map(|donor| symbol_set.donor_stats(donor).map(|stats| (donor, stats)))
                    .collect(),
            });
        }

        feedback_rounds += 1;
        if feedback_rounds > config.max_feedback_rounds {
            let receipt = ReceiveReceipt {
                committed: false,
                bytes_received: 0,
                files: u32::try_from(manifest.entries.len()).unwrap_or(u32::MAX),
                sha_ok: false,
                merkle_ok: false,
                symbols_accepted,
                feedback_rounds,
                reason: Some(format!(
                    "no convergence after {feedback_rounds} rounds, {} entries pending",
                    pending.len()
                )),
                committed_paths: Vec::new(),
            };
            if let Ok(proof) = json_frame(FrameType::Proof, &receipt) {
                for conn in conns.iter_mut().filter(|conn| conn.alive) {
                    let _ = conn.control.send(&proof).await;
                }
            }
            return Err(RqError::NoConvergence {
                rounds: feedback_rounds,
                pending: pending.len(),
            });
        }

        let live: Vec<u32> = conns
            .iter()
            .filter(|conn| conn.alive)
            .map(|conn| conn.donor_index)
            .collect();
        if live.is_empty() {
            return Err(RqError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!(
                    "all bonded donors disconnected with {} entries still pending",
                    pending.len()
                ),
            )));
        }
        let live_weights: Vec<BondedDonorWindowWeight> = live
            .iter()
            .map(|&donor_index| BondedDonorWindowWeight {
                donor_index,
                weight: symbol_set.donor_stats(donor_index).map_or(1, |stats| {
                    u32::try_from(stats.symbols_accepted)
                        .unwrap_or(u32::MAX)
                        .max(1)
                }),
            })
            .collect();

        // Rank-deficiency bump: a coverage-complete block inside an incomplete
        // entry failed a K-exact solve; raise its target so it asks for more.
        for state in blocks.values_mut() {
            if decoders[state.decoder_pos].complete {
                continue;
            }
            let coverage = symbol_set.block_coverage(
                state.geometry.object_id,
                state.geometry.source_block_number,
                state.target_symbols,
            );
            if coverage.deficit_symbols == 0 {
                let k = u32::from(state.geometry.source_symbols);
                state.target_symbols = coverage.accepted_symbols.saturating_add((k / 32).max(2));
            }
        }

        // C3 aggregate plan: source-first holes, then generic repair deficits.
        // Holes are computed against the block's true systematic count `K`
        // (never the rank-bumped coverage target — ESIs >= K are repair-only
        // and donors fail closed on a "source" request for them); deficits are
        // computed against the dynamic coverage target.
        let source_first_need_more = symbol_set.blocks_with_source_holes(
            blocks
                .values()
                .filter(|state| !decoders[state.decoder_pos].complete)
                .map(|state| {
                    (
                        state.geometry.object_id,
                        state.geometry.source_block_number,
                        u32::from(state.geometry.source_symbols),
                    )
                }),
        );
        let need_more = symbol_set.blocks_needing_more(
            blocks
                .values()
                .filter(|state| !decoders[state.decoder_pos].complete)
                .map(|state| {
                    (
                        state.geometry.object_id,
                        state.geometry.source_block_number,
                        state.target_symbols,
                    )
                }),
        );

        let mut needs: BTreeMap<u32, BTreeMap<(u32, u8), BondedBlockNeed>> = BTreeMap::new();

        // 1) Reallocate dead donors' outstanding windows to survivors before
        //    fresh allocation, so their repair budget is never dropped.
        let mut geometry_by_key: BTreeMap<(u32, u8), BondEntryBlockGeometry> = BTreeMap::new();
        for state in blocks.values_mut() {
            let failed: Vec<u32> = state
                .outstanding
                .iter()
                .map(|window| window.donor_index)
                .filter(|donor_index| !live.contains(donor_index))
                .collect();
            let mut next_outstanding = Vec::new();
            if !failed.is_empty() {
                let realloc = reallocate_failed_bonded_repair_windows(
                    state.geometry,
                    state.repair_cursor,
                    &state.outstanding,
                    &failed,
                    &live_weights,
                )
                .map_err(|err| {
                    RqError::Coding(format!("bonded repair reallocation failed: {err}"))
                })?;
                bondtrace!(
                    "receiver: reallocated dead-donor windows entry={} sbn={} failed={:?} symbols={} next_cursor={}",
                    state.geometry.entry_index,
                    state.geometry.source_block_number,
                    failed,
                    realloc.allocated_symbol_count(),
                    realloc.next_repair_esi
                );
                state.repair_cursor = realloc.next_repair_esi;
                reallocated_repair_windows = reallocated_repair_windows
                    .saturating_add(u64::from(realloc.allocated_symbol_count()));
                next_outstanding.extend(realloc.windows.iter().copied());
            }
            state.outstanding = next_outstanding;
            geometry_by_key.insert(
                (
                    state.geometry.entry_index,
                    state.geometry.source_block_number,
                ),
                state.geometry,
            );
        }

        // 2) Fresh disjoint windows for the aggregate coverage deficits.
        for coverage in &need_more {
            let Some((&key, _)) = geometry_by_key.iter().find(|(_, geometry)| {
                geometry.object_id == coverage.object_id
                    && geometry.source_block_number == coverage.sbn
            }) else {
                continue;
            };
            let Some(state) = blocks.get_mut(&key) else {
                continue;
            };
            if coverage.deficit_symbols == 0 {
                continue;
            }
            let alloc = allocate_bonded_repair_windows(
                state.geometry,
                state.repair_cursor,
                coverage.deficit_symbols,
                &live_weights,
            )
            .map_err(|err| RqError::Coding(format!("bonded repair allocation failed: {err}")))?;
            state.repair_cursor = alloc.next_repair_esi;
            state.outstanding.extend(alloc.windows.iter().copied());
        }

        // 3) Source-first retransmits, split receiver-side across live donors
        //    (never by static residue — a dead donor's residue class would
        //    otherwise be unreachable). Mirrors the single-source
        //    source-retransmit round budget.
        if feedback_rounds <= config.source_retransmit_rounds {
            for holes in &source_first_need_more {
                let Some(geometry) = geometry_by_key
                    .values()
                    .find(|geometry| {
                        geometry.object_id == holes.object_id
                            && geometry.source_block_number == holes.sbn
                    })
                    .copied()
                else {
                    continue;
                };
                for (position, &esi) in holes.missing_source_esis.iter().enumerate() {
                    let donor_index = live[position % live.len()];
                    bonded_need_entry(&mut needs, donor_index, geometry)
                        .source_esis
                        .push(esi);
                }
            }
        }
        for state in blocks.values() {
            for window in &state.outstanding {
                bonded_need_entry(&mut needs, window.donor_index, state.geometry)
                    .repair_windows
                    .push(window.esi_window);
            }
        }

        // 4) Broadcast: EVERY live donor gets a NeedMore (possibly empty) so
        //    the round marker protocol stays lockstep across the fleet.
        round += 1;
        for conn in conns.iter_mut().filter(|conn| conn.alive) {
            let donor_blocks: Vec<BondedBlockNeed> = needs
                .remove(&conn.donor_index)
                .map(|by_block| by_block.into_values().collect())
                .unwrap_or_default();
            let frame = json_frame(
                FrameType::ObjectRequest,
                &BondedNeedMore {
                    round,
                    blocks: donor_blocks,
                },
            )?;
            if conn.control.send(&frame).await.is_err() {
                bondtrace!(
                    "receiver: donor_dead_on_feedback donor_index={} round={}",
                    conn.donor_index,
                    round
                );
                conn.alive = false;
                continue;
            }
            conn.round_done = false;
        }
        bondtrace!(
            "receiver: need_more_broadcast round={} live_donors={} pending_entries={} deficit_blocks={} source_hole_blocks={}",
            round,
            conns.iter().filter(|conn| conn.alive).count(),
            pending.len(),
            need_more.len(),
            source_first_need_more.len()
        );
    }
}

/// Fetch (creating on first use) one donor's per-block need row.
fn bonded_need_entry(
    needs: &mut BTreeMap<u32, BTreeMap<(u32, u8), BondedBlockNeed>>,
    donor_index: u32,
    geometry: BondEntryBlockGeometry,
) -> &mut BondedBlockNeed {
    needs
        .entry(donor_index)
        .or_default()
        .entry((geometry.entry_index, geometry.source_block_number))
        .or_insert_with(|| BondedBlockNeed {
            entry_index: geometry.entry_index,
            source_block_number: geometry.source_block_number,
            source_esis: Vec::new(),
            repair_windows: Vec::new(),
        })
}

/// Build one bonded per-entry decoder, isomorphic to the single-source UDP
/// receive path's decoder construction (`receive_connection`).
#[allow(clippy::too_many_arguments)]
fn new_bonded_entry_decoder(
    e: &ManifestEntry,
    manifest: &TransferManifest,
    staging_dir: &Path,
    single_file_fragment_staging: Option<&Path>,
    symbol_size: u16,
    receiver_max_block_size: usize,
    wire_max_block_size: u64,
    config: &RqConfig,
    symbol_auth: Option<&SecurityContext>,
    source_streaming: bool,
) -> EntryDecoder {
    let object_id = entry_object_id(&manifest.transfer_id, e.index);
    let (staging_path, staging_write_offset, staging_file_len, staging_shared) =
        receive_staging_layout_for_entry(e, staging_dir, single_file_fragment_staging);
    let (pipeline, entry_source_streaming, source_blocks) = new_udp_entry_decode_state(
        e,
        object_id,
        symbol_size,
        receiver_max_block_size,
        wire_max_block_size,
        config,
        symbol_auth,
        source_streaming,
    );
    EntryDecoder {
        index: e.index,
        object_id,
        size: e.size,
        pipeline,
        complete: e.size == 0,
        staging_path,
        staging_write_offset,
        staging_file_len,
        staging_shared,
        staging_created: false,
        staging_file: None,
        staging_cursor: None,
        staging_unflushed_bytes: 0,
        cache_staging_file: should_cache_entry_staging_file(
            e.size,
            manifest.entries.len(),
            e.members.len(),
        ),
        bytes_written: 0,
        max_block_size: receiver_max_block_size,
        source_streaming: entry_source_streaming,
        source_blocks,
        pending_decodes: Vec::new(),
        inc: None,
        inc_digest: None,
        source_write_buffer: Vec::with_capacity(RQ_SOURCE_STAGE_BUFFER_BYTES),
        source_write_buffer_offset: None,
    }
}

fn select_bonded_receiver_udp_path(
    assignment: &DonorAssignment,
    legacy_udp_ports: &[u16],
    control_addr: SocketAddr,
) -> Result<Vec<SocketAddr>, RqError> {
    assignment
        .validate()
        .map_err(|error| RqError::HandshakeRejected(error.to_string()))?;
    validate_bonded_receiver_udp_endpoints(&assignment.receiver_udp_endpoints)?;

    let advertised = &assignment.receiver_udp_endpoints;
    let all_unspecified = advertised
        .iter()
        .all(|endpoint| endpoint.ip().is_unspecified());
    let any_unspecified = advertised
        .iter()
        .any(|endpoint| endpoint.ip().is_unspecified());
    let (selected, reason) = if all_unspecified {
        if legacy_udp_ports.is_empty() {
            return Err(RqError::HandshakeRejected(
                "legacy bonded welcome advertised no receiver UDP ports".to_string(),
            ));
        }
        if legacy_udp_ports.len() > MAX_BONDING_RECEIVER_ENDPOINTS {
            return Err(RqError::HandshakeRejected(format!(
                "legacy bonded welcome advertised {} UDP ports, max {MAX_BONDING_RECEIVER_ENDPOINTS}",
                legacy_udp_ports.len()
            )));
        }
        let mut selected = Vec::with_capacity(legacy_udp_ports.len());
        let mut unique_ports = BTreeSet::new();
        for &port in legacy_udp_ports {
            if port == 0 {
                return Err(RqError::HandshakeRejected(
                    "legacy bonded welcome advertised UDP port zero".to_string(),
                ));
            }
            if unique_ports.insert(port) {
                selected.push(SocketAddr::new(control_addr.ip(), port));
            }
        }
        (selected, "legacy-control-ip")
    } else {
        if any_unspecified {
            return Err(RqError::HandshakeRejected(
                "bonded welcome mixed unspecified and concrete receiver UDP endpoints".to_string(),
            ));
        }
        let selected: Vec<SocketAddr> = advertised
            .iter()
            .copied()
            .filter(|endpoint| endpoint.ip() == control_addr.ip())
            .collect();
        if selected.is_empty() {
            return Err(RqError::HandshakeRejected(format!(
                "bonded welcome advertised no receiver UDP path for connected control IP {}",
                control_addr.ip()
            )));
        }
        (selected, "control-path-affinity")
    };

    bondtrace!(
        "donor: endpoint_path_selected donor_index={} control_ip={} reason={} advertised={advertised:?} selected={selected:?}",
        assignment.donor_index,
        control_addr.ip(),
        reason,
    );
    Ok(selected)
}

/// Donate into a bonded transfer over the wire.
///
/// Enroll on the receiver's control plane, run the [`donate_path`]
/// source-first spray with the receiver-assigned [`DonorAssignment`], then
/// serve aggregated NeedMore/Close feedback (the B3 donor control loop) until
/// the receiver broadcasts its fail-closed commit receipt.
pub async fn donate_bonded(
    cx: &Cx,
    descriptor: &BondTransferDescriptor,
    control_addr: SocketAddr,
    source_root: &Path,
    config: RqConfig,
) -> Result<BondedDonateReport, RqError> {
    cx.checkpoint().map_err(|_| RqError::Cancelled)?;
    descriptor
        .validate()
        .map_err(|err| RqError::Source(format!("bonded descriptor invalid: {err}")))?;
    let manifest = manifest_from_bonded_descriptor(descriptor);
    validate_manifest(&manifest, &config)?;
    let metadata_commitment_hex = manifest
        .metadata
        .as_ref()
        .expect("validated protocol-v4 metadata")
        .commitment_hex
        .clone();
    let symbol_auth = config.symbol_auth_context()?;
    let symbol_auth_enabled = symbol_auth.is_some();

    let stream = match crate::time::timeout(
        cx.now(),
        config.accept_timeout,
        TcpStream::connect(control_addr),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(err)) => return Err(RqError::Io(err)),
        Err(_elapsed) => {
            return Err(RqError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("bonded donor connect to {control_addr} timed out"),
            )));
        }
    };
    let mut control = FrameTransport::new(stream);
    control
        .send(&json_frame(
            FrameType::Handshake,
            &BondedDonorHello {
                protocol: ATP_RQ_BONDED_PROTOCOL,
                transfer_id: descriptor.transfer_id.clone(),
                merkle_root_hex: descriptor.merkle_root_hex.clone(),
                metadata_commitment_hex,
                symbol_size: descriptor.symbol_size,
                max_block_size: descriptor.max_block_size,
                symbol_auth: symbol_auth_enabled,
                offer: BondingHandshake::v1_static(
                    [
                        BondTransport::DirectIp,
                        BondTransport::Ssh,
                        BondTransport::Tailscale,
                    ],
                    MAX_BONDING_DONORS,
                    symbol_auth_enabled,
                ),
            },
        )?)
        .await?;
    let ack = control.recv().await?;
    if ack.frame_type() != FrameType::HandshakeAck {
        return Err(RqError::Unexpected {
            got: ack.frame_type(),
            expected: "HandshakeAck",
        });
    }
    let welcome: BondedDonorWelcome = parse_json(&ack)?;
    if !welcome.accepted {
        return Err(RqError::HandshakeRejected(
            welcome
                .reason
                .unwrap_or_else(|| "bonded enrollment rejected".to_string()),
        ));
    }
    let mut assignment = welcome.assignment.ok_or_else(|| {
        RqError::Frame("bonded welcome accepted but carried no donor assignment".to_string())
    })?;
    // The unauthenticated v3 control welcome cannot redirect UDP spray to an
    // arbitrary third party. Select only the advertised IP that matches the
    // already-established control path, retaining all of that IP's fanout
    // ports. Legacy wildcard assignments remain compatible via the separately
    // carried port list plus the connected control IP.
    assignment.receiver_udp_endpoints =
        select_bonded_receiver_udp_path(&assignment, &welcome.udp_ports, control_addr)?;
    let primary = assignment
        .receiver_udp_endpoints
        .first()
        .copied()
        .ok_or_else(|| {
            RqError::Frame("bonded welcome advertised no receiver UDP endpoints".to_string())
        })?;

    let spray = donate_path(
        cx,
        descriptor,
        &assignment,
        primary,
        source_root,
        config.clone(),
    )
    .await?;
    let mut symbols_sent = spray.symbols_sent;
    control
        .send(&json_frame(
            FrameType::ObjectComplete,
            &BondedRoundComplete {
                round: 0,
                donor_index: assignment.donor_index,
                symbols_sent,
            },
        )?)
        .await?;

    let mut feedback_rounds = 0u32;
    loop {
        cx.checkpoint().map_err(|_| RqError::Cancelled)?;
        let frame = control.recv().await?;
        match frame.frame_type() {
            FrameType::ObjectRequest => {
                let need: BondedNeedMore = parse_json(&frame)?;
                feedback_rounds = feedback_rounds.max(need.round);
                let sent = bonded_donor_execute_need_more(
                    cx,
                    descriptor,
                    &assignment,
                    source_root,
                    &config,
                    symbol_auth.as_ref(),
                    &need,
                )
                .await?;
                symbols_sent = symbols_sent.saturating_add(sent);
                control
                    .send(&json_frame(
                        FrameType::ObjectComplete,
                        &BondedRoundComplete {
                            round: need.round,
                            donor_index: assignment.donor_index,
                            symbols_sent,
                        },
                    )?)
                    .await?;
            }
            FrameType::Proof => {
                let receipt: ReceiveReceipt = parse_json(&frame)?;
                if let Ok(close) = Frame::empty(FrameType::Close) {
                    let _ = control.send(&close).await;
                }
                return Ok(BondedDonateReport {
                    transfer_id: descriptor.transfer_id.clone(),
                    donor_index: assignment.donor_index,
                    donor_count: assignment.donor_count,
                    feedback_rounds,
                    symbols_sent,
                    spray,
                    receipt,
                });
            }
            FrameType::KeepAlive => {
                control
                    .send(
                        &Frame::empty(FrameType::KeepAlive)
                            .map_err(|e| RqError::Frame(e.to_string()))?,
                    )
                    .await?;
            }
            FrameType::Close => {
                return Err(RqError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "receiver closed bonded control before sending a proof",
                )));
            }
            other => {
                return Err(RqError::Unexpected {
                    got: other,
                    expected: "ObjectRequest | Proof | KeepAlive",
                });
            }
        }
    }
}

/// Serve one receiver `BondedNeedMore`: retransmit the requested source ESIs
/// and emit this donor's receiver-allocated repair window for each block,
/// through the same emission encoder and pacing as [`donate_path`].
async fn bonded_donor_execute_need_more(
    cx: &Cx,
    descriptor: &BondTransferDescriptor,
    assignment: &DonorAssignment,
    source_root: &Path,
    config: &RqConfig,
    symbol_auth: Option<&SecurityContext>,
    need: &BondedNeedMore,
) -> Result<u64, RqError> {
    if need.blocks.is_empty() {
        return Ok(0);
    }
    let receiver_endpoints = assignment.receiver_udp_endpoints.clone();
    let Some(first_endpoint) = receiver_endpoints.first().copied() else {
        return Err(RqError::Frame(
            "bonded donor assignment has no receiver UDP endpoints".to_string(),
        ));
    };
    let local_unspec = if first_endpoint.ip().is_ipv4() {
        std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
    } else {
        std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
    };
    let mut sockets = Vec::with_capacity(receiver_endpoints.len());
    for endpoint in &receiver_endpoints {
        let sock = UdpSocket::bind(SocketAddr::new(local_unspec, 0)).await?;
        sock.connect(*endpoint).await?;
        let _ = sock.tune_buffers(UdpBufferConfig {
            send_buffer_bytes: Some(16 * 1024 * 1024),
            recv_buffer_bytes: None,
        });
        sockets.push(sock);
    }

    let pacing_decision =
        bonded_donor_round0_pacing_decision(&descriptor.transfer_id, config, sockets.len());
    let mut pacer = RqSprayPacer::new_round0(pacing_decision.pacing, config, false);
    let mut send_batch = RqPendingSendBatch::new(sockets.len());
    let mut symbols_sent = 0u64;
    let mut rr = 0usize;
    let mut dropper = 0u32;
    let mut udp_send_acceleration = UdpSendAccelerationReport::default();
    let tag = transfer_tag(&descriptor.transfer_id);
    let mut repair_budget = BONDED_MAX_REPAIR_SYMBOLS_PER_NEED_MORE;

    for block in &need.blocks {
        cx.checkpoint().map_err(|_| RqError::Cancelled)?;
        let geometry = descriptor
            .entry_block_geometry(block.entry_index, block.source_block_number)
            .ok_or_else(|| {
                RqError::Frame(format!(
                    "bonded NeedMore names unknown block entry={} sbn={}",
                    block.entry_index, block.source_block_number
                ))
            })?;
        let entry = descriptor
            .entry_by_index(block.entry_index)
            .ok_or_else(|| {
                RqError::Frame(format!(
                    "bonded NeedMore names unknown entry {}",
                    block.entry_index
                ))
            })?;
        let entry_path = bonded_donor_entry_path(source_root, &entry.rel_path)?;
        let block_start = usize::try_from(geometry.block_start).map_err(|_| RqError::TooLarge {
            size: geometry.block_start,
            max: u64::try_from(usize::MAX).unwrap_or(u64::MAX),
        })?;
        let block_len = usize::try_from(geometry.block_bytes).map_err(|_| RqError::TooLarge {
            size: geometry.block_bytes,
            max: u64::try_from(usize::MAX).unwrap_or(u64::MAX),
        })?;
        let block_bytes = read_source_range(&entry_path, block_start, block_len).await?;
        let k = u32::from(geometry.source_symbols);

        let mut emissions: Vec<BondedDonorSymbolEmission> = Vec::new();
        for &esi in &block.source_esis {
            if esi >= k {
                return Err(RqError::Frame(format!(
                    "bonded NeedMore requested source esi {esi} >= K {k} for entry={} sbn={}",
                    block.entry_index, block.source_block_number
                )));
            }
            emissions.push(BondedDonorSymbolEmission {
                donor_index: assignment.donor_index,
                geometry,
                esi,
                kind: BondedDonorSymbolKind::Source,
                stagger_delay_slots: assignment.donor_index,
            });
        }
        let mut block_repair_budget = bonded_need_more_block_repair_cap(k).min(repair_budget);
        for window in &block.repair_windows {
            if window.end_exclusive <= window.start_inclusive {
                continue;
            }
            let span = usize::try_from(window.end_exclusive - window.start_inclusive)
                .unwrap_or(usize::MAX);
            let requested = span.min(block_repair_budget);
            if requested < span {
                bondtrace!(
                    "donor: need_more_window_capped donor_index={} entry={} sbn={} window={:?} served={requested}",
                    assignment.donor_index,
                    block.entry_index,
                    block.source_block_number,
                    window
                );
            }
            if requested == 0 {
                continue;
            }
            block_repair_budget -= requested;
            repair_budget -= requested;
            let mut windowed = assignment.clone();
            windowed.esi_windows = vec![*window];
            let schedule = schedule_bonded_repair_continuation(
                &windowed,
                geometry,
                window.start_inclusive,
                requested,
            )
            .map_err(|err| RqError::Coding(format!("bonded repair continuation failed: {err}")))?;
            for esi in schedule.repair_esis {
                emissions.push(BondedDonorSymbolEmission {
                    donor_index: assignment.donor_index,
                    geometry,
                    esi,
                    kind: BondedDonorSymbolKind::Repair,
                    stagger_delay_slots: schedule.stagger_delay_slots,
                });
            }
        }
        bondtrace!(
            "donor: need_more_block donor_index={} round={} entry={} sbn={} source_retransmits={} repair_windows={:?}",
            assignment.donor_index,
            need.round,
            block.entry_index,
            block.source_block_number,
            block.source_esis.len(),
            block.repair_windows
        );
        for emission in emissions {
            let symbol = encode_bonded_donor_emission(emission, &block_bytes, config)?;
            queue_bonded_donor_datagram(
                cx,
                &mut sockets,
                &mut rr,
                &mut symbols_sent,
                &mut dropper,
                tag,
                geometry.entry_index,
                &symbol,
                config,
                &mut pacer,
                symbol_auth,
                &mut send_batch,
                &mut udp_send_acceleration,
            )
            .await?;
        }
    }
    let report = send_batch.flush(&mut sockets, &mut symbols_sent).await?;
    udp_send_acceleration.observe_flush_report(report);
    Ok(symbols_sent)
}

#[cfg(test)]
#[path = "bonded_inline_tests.rs"]
mod tests;
