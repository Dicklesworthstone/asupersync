//! ATP-over-QUIC transport (Phase B scaffold).
//!
//! This module is the public-API skeleton for the *adaptive RaptorQ-over-QUIC*
//! data plane — the production ATP transport meant to beat rsync on lossy,
//! high-latency internet paths. It deliberately mirrors the public surface of
//! [`crate::net::atp::transport_tcp`] *exactly* so callers (the `atp` CLI, the
//! `atpd` daemon, fleet/loopback E2E harnesses) can target QUIC by swapping the
//! transport module and config type, with no other call-site changes.
//!
//! # Status: partially wired (`asupersync-arq-quic-epic-b0k8qo.2`)
//!
//! The endpoint-level send/receive coroutines still land in:
//!
//! - [`send_path`] → `asupersync-arq-quic-epic-b0k8qo.2.2` (B2: QUIC sender
//!   coroutine — connect, verify identity, manifest, encode + spray RaptorQ
//!   symbols across QUIC DATAGRAMs, fountain feedback).
//! - [`receive_once`] consumes one connection already routed into a
//!   [`ManagedQuicEndpoint`] and delegates to the wired accepted-connection
//!   receiver body. Live endpoint pumping and persistent serving remain B3
//!   follow-up work.
//! - [`serve`] drains connections already routed into a
//!   [`ManagedQuicEndpoint`] and delegates each one to the same accepted-
//!   connection receiver body. Live endpoint pumping and indefinite listener
//!   ownership remain native endpoint follow-up work.
//!
//! Until a given transfer entry point is wired, it **fails closed**: it
//! validates its configuration, emits a structured config summary, and returns
//! [`QuicTransportError::NotImplemented`]. There is no code path that reports a
//! fake success or moves zero bytes silently — the epic's non-negotiable
//! "every unwired op fails closed (typed error, never fake success)" rule.
//! [`receive_connection`] is the first wired B3 receiver surface: it consumes an
//! already-established native QUIC connection, verifies decoded entries, commits
//! them under the destination root, and returns a real report. [`receive_once`]
//! now removes a routed endpoint connection and drives that same body. [`serve`]
//! drains the currently routed queue with per-connection callbacks. Live
//! endpoint event-loop pumping and sender-side [`send_path`] native
//! connect/identity wiring remain fail-closed until their B2/B3 slices land.
//!
//! # Why a scaffold can land ahead of the Phase A data plane
//!
//! The tracker gates Phase B on Phase A (`...b0k8qo.1`, the QUIC application
//! data plane). That ordering is real for the *implementation* in B2/B3, which
//! consumes the Phase A DATAGRAM/STREAM/packet-protection surfaces. The
//! first scaffolds, however, only depended on already-landed pieces: the shared
//! bounded-memory helpers in [`crate::net::atp::transport_common`] (F0) and the
//! `transport_tcp` template it mirrors. The accepted-connection
//! [`receive_connection`] body now consumes the landed Phase A native STREAM and
//! DATAGRAM surfaces, while the still-unwired endpoint operations continue to
//! fail closed.
//!
//! # Reused wire / report types
//!
//! The manifest, receipt, and report types are intentionally **reused** from
//! [`crate::net::atp::transport_tcp`] (re-exported below) rather than
//! re-declared, so QUIC and TCP transfers commit to the byte-identical
//! manifest/merkle schema. A later refactor may hoist these into
//! `transport_common`; the re-export keeps the QUIC public surface stable
//! across that move.
//!
//! # Integrity & current memory boundary
//!
//! The accepted-connection receiver keeps `transport_tcp`'s fail-closed
//! integrity guarantee (per-entry SHA-256 + rebuilt flat-object-graph merkle
//! root vs. the manifest, atomic commit only on a full match). The native UDP
//! QUIC sender uses file-backed encoders that read one source block at a time,
//! and the receiver stages decoded blocks directly to disk before final
//! verification/commit. The in-memory encoder/decoder helpers remain for unit
//! tests and scaffold-only drivers; they are not the B5 bounded-memory proof
//! path.

#[cfg(feature = "tls")]
pub mod native_link;
pub mod symbol_datagram;
pub mod symbol_envelope;

use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::atp::delta::{CasChunkRef, PersistentChunkManifest};
use crate::atp::object::{ContentId, MetadataPolicy};
use crate::atp::safety::{
    portable_path_collision_key, validate_portable_path_component, validate_portable_path_set,
    validate_portable_relative_path,
};
use crate::bytes::{Bytes, BytesMut};
use crate::codec::Decoder;
use crate::config::EncodingConfig;
use crate::cx::Cx;
use crate::decoding::{
    BlockDecodeJob, BlockDecodeOutcome, BlockStateKind, DecodingConfig, DecodingPipeline,
    DeferredSymbolAcceptResult, MissingSourceSymbol, RejectReason, SymbolAcceptResult,
    run_block_decode_job,
};
use crate::encoding::EncodingPipeline;
use crate::io::AsyncReadExt;
use crate::net::atp::protocol::codec::AtpFrameCodec;
use crate::net::atp::protocol::frames::{Frame, FrameType, MAX_FRAME_SIZE, ProtocolVersion};
use crate::net::atp::protocol::session::TransferNonce;
#[cfg(any(feature = "tls", test))]
use crate::net::atp::protocol::session::{PeerId, SessionId};
use crate::net::atp::quic::AtpTransportMetrics;
use crate::net::atp::transport_common::delta::ATP_DELTA_CHUNK_MANIFEST_SCHEMA;
#[cfg(any(feature = "tls", test))]
use crate::net::atp::transport_common::metadata::read_entry_metadata;
use crate::net::atp::transport_common::metadata::{
    HardlinkIdentity, commit_hardlink_transactionally, commit_symlink_transactionally,
    path_is_link_or_reparse, validate_entry_metadata_for_receive,
    validate_symlink_metadata_for_receive,
};
#[cfg(test)]
use crate::net::atp::transport_common::metadata::{
    SymlinkTargetInfo, SymlinkTargetKind, SymlinkTargetSemantics,
};
use crate::net::atp::transport_common::streaming::collect_entries_with_policy;
use crate::net::atp::transport_common::{
    DeltaChunkWire, DeltaManifestWire, EntryDigest, EntryMetadata, FileKind, MetadataApplyReport,
    StreamingError, capture_directory_metadata_manifest, flat_merkle_root_from_digests,
    flat_merkle_root_from_slices, hash_file_streaming, hex_encode, metadata_commitment,
};
#[cfg(any(feature = "tls", test))]
use crate::net::atp::transport_common::{DeltaObjectRequest, DeltaWireMode};
#[cfg(test)]
use crate::net::atp::transport_common::{DirectoryMetadataEntry, DirectoryMetadataManifest};
use crate::net::quic_native::{
    ManagedEndpointError, ManagedQuicEndpoint, NativeQuicConnection, NativeQuicConnectionError,
    QuicConnection, QuicPathStats, QuicTransportMachine, StreamDirection, StreamId, StreamRole,
    StreamTableError,
};
use crate::security::{AuthMode, AuthenticatedSymbol, AuthenticationTag, SecurityContext};
use crate::transport::{
    AggregatorConfig, MultipathAggregator, PathId, ReordererConfig, TransportPath,
};
use crate::types::Time;
use crate::types::resource::{PoolConfig, SymbolPool};
use crate::types::symbol::{ObjectId, ObjectParams, Symbol, SymbolId, SymbolKind};

/// Opt-in stderr tracing for ATP/QUIC fountain-feedback diagnosis. This uses the
/// same environment switch as the RQ transport so a single MATRIX run can
/// capture both paths.
fn quic_rqtrace(args: std::fmt::Arguments<'_>) {
    if std::env::var_os("ATP_RQ_TRACE").is_some() {
        eprintln!("[ATP_RQ_TRACE] [atp-quic] {args}");
    }
}

#[allow(dead_code)]
pub(crate) fn quic_progress(args: std::fmt::Arguments<'_>) {
    eprintln!("[atp-quic] {args}");
}

// Reuse the manifest / receipt / report wire+value types so QUIC and TCP share
// one schema (see module docs). These are the "reuse manifest/report/receipt"
// half of the B1 acceptance.
pub use crate::net::atp::transport_tcp::{
    ManifestEntry, PackedMember, ReceiveReceipt, ReceiveReport, SendReport, TransferManifest,
};

/// Why the ATP-over-QUIC sender could not put more bytes on the wire at some
/// instant.
///
/// One variant per gate the sender waits behind. The
/// [`QuicSendLimiterReport`] accumulates how often and for how long each gate
/// held, so a slow transfer names its limiter instead of leaving it to be
/// inferred from throughput × RTT (br-asupersync-bi2462.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QuicSendStallReason {
    /// The byte pacer (source stream) or the token pacer (datagram spray)
    /// held the next send until its deadline.
    Pacing,
    /// QUIC recovery's congestion window: bytes in flight reached `cwnd`.
    Cwnd,
    /// Stream-level flow control: the receiver's `MAX_STREAM_DATA` credit for
    /// the paced source stream was below the admission minimum.
    StreamCredit,
    /// ATP's own in-flight admission cap on the source stream (bottleneck
    /// bandwidth × RTprop with a 16 MiB runaway ceiling): sent-but-unacked
    /// bytes exceeded it.
    UnackedGuard,
    /// The source-stream send queue exceeded its cap and had to be flushed
    /// before more data was admitted.
    ///
    /// The flush that drains it reports its own blocking gate (`Pacing`,
    /// `Cwnd`, `StreamCredit`) separately.
    SendQueue,
    /// Datagram-tier receiver window (`NeedMore` credit) blocked the spray.
    ReceiverWindow,
    /// A blocked flush with the congestion window and stream credit both
    /// available (anti-amplification or a generator refusal).
    Other,
}

impl QuicSendStallReason {
    /// Every reason, in report order.
    pub const ALL: [Self; 7] = [
        Self::Pacing,
        Self::Cwnd,
        Self::StreamCredit,
        Self::UnackedGuard,
        Self::SendQueue,
        Self::ReceiverWindow,
        Self::Other,
    ];

    /// Stable snake-case name used in the `atp send` JSON report.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Pacing => "pacing",
            Self::Cwnd => "cwnd",
            Self::StreamCredit => "stream_credit",
            Self::UnackedGuard => "unacked_guard",
            Self::SendQueue => "send_queue",
            Self::ReceiverWindow => "receiver_window",
            Self::Other => "other",
        }
    }
}

/// Count and total held time of one stall reason.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct QuicSendStall {
    /// How many times the sender waited behind this gate.
    pub count: u64,
    /// Total time the gate held the sender, in microseconds (saturating).
    pub micros: u64,
}

/// Sender-side limiter telemetry for one ATP-over-QUIC transfer.
///
/// Returned next to the [`SendReport`] by [`send_path_with_limiter_report`]
/// and printed by `atp send --transport quic` as the `limiter` block. Every
/// field is observational: the report changes nothing about how the sender
/// paces or recovers. Stall durations are attributed per wait-loop iteration
/// from the loop's own elapsed clock, so their sum never exceeds the wall
/// time of the loops that recorded them (a loop's final, un-attributed slice
/// is dropped, never guessed). Connection-level `MAX_DATA` credit is not
/// tracked by the native stack and has no entry here.
///
/// `#[non_exhaustive]`: fields are added in later `0.4.x` releases;
/// construct it with [`Default`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct QuicSendLimiterReport {
    /// Pacer-held sends: the source-stream byte pacer, the datagram token
    /// pacer, and the shared AIMD rate pacer's retry-after waits.
    pub pacing: QuicSendStall,
    /// Congestion-window-blocked waits.
    pub cwnd: QuicSendStall,
    /// `MAX_STREAM_DATA`-blocked waits on the paced source stream.
    pub stream_credit: QuicSendStall,
    /// Waits behind ATP's in-flight admission cap on the source stream.
    pub unacked_guard: QuicSendStall,
    /// Waits for the source-stream send queue to drain below its cap.
    pub send_queue: QuicSendStall,
    /// Datagram-tier receiver-window waits.
    pub receiver_window: QuicSendStall,
    /// Blocked flushes with no identifiable gate.
    pub other: QuicSendStall,
    /// Number of transport samples folded into the peak/min fields.
    pub transport_samples: u64,
    /// Highest QUIC bytes-in-flight observed at a sample point.
    pub peak_bytes_in_flight: u64,
    /// Highest congestion window observed at a sample point.
    pub peak_congestion_window_bytes: u64,
    /// Lowest congestion window observed at a sample point (`None` before
    /// the first sample).
    pub min_congestion_window_bytes: Option<u64>,
    /// Congestion window when the transfer finished.
    pub final_congestion_window_bytes: u64,
    /// Slow-start threshold when the transfer finished; `None` while QUIC
    /// recovery never left slow start (RFC 9002 keeps it at infinity).
    pub final_ssthresh_bytes: Option<u64>,
    /// Whether any sample saw recovery outside slow start.
    pub slow_start_exited: bool,
    /// Minimum RTT the QUIC transport's estimator measured, in its own units.
    ///
    /// The ATP data plane feeds QUIC recovery a synthetic event-count clock
    /// (one tick per packet sent or received plus pacer sleeps), so this and
    /// [`Self::smoothed_rtt_micros`] / [`Self::pto_count`] are event units,
    /// not wall time; the wall-clock path figures are
    /// [`Self::path_rtprop_micros`] and [`Self::path_bottleneck_bytes_per_s`].
    pub min_rtt_micros: Option<u64>,
    /// Smoothed RTT at the end of the transfer (same units as
    /// [`Self::min_rtt_micros`]).
    pub smoothed_rtt_micros: Option<u64>,
    /// Wall-clock path RTprop in microseconds: the minimum send→ACK flight
    /// time the source-stream delivery sampler saw, falling back to the
    /// handshake RTT sample before the first ACK (`None` on neither).
    pub path_rtprop_micros: Option<u64>,
    /// Highest wall-clock bottleneck-bandwidth estimate (bytes per second)
    /// the source-stream rate controller held while the admission gate ran;
    /// 0 until the first delivery sample.
    pub path_bottleneck_bytes_per_s: u64,
    /// Lowest in-flight admission cap the source-stream gate enforced
    /// (`None` if the gate never ran); [`Self::unacked_admission_cap_bytes`]
    /// is the cap at the end.
    pub min_unacked_admission_cap_bytes: Option<u64>,
    /// Highest source-stream sent-but-unacked byte count the gate saw (the
    /// bulk data is transport-untracked, so [`Self::peak_bytes_in_flight`]
    /// stays 0 on this path).
    pub peak_stream_unacked_bytes: u64,
    /// STREAM_DATA_BLOCKED frames the sender sent to ask the receiver for a
    /// larger source-stream window (only while credit-bound and loss-clean).
    pub stream_window_requests: u64,
    /// Largest source-stream send window the admission gate observed:
    /// remaining `MAX_STREAM_DATA` credit plus sent-but-unacked bytes, i.e.
    /// the peer's limit minus what it had acknowledged. Against the HelloAck
    /// window (2 MiB by default) this shows whether the receiver grew the
    /// window (`None` if the gate never ran).
    pub peak_stream_send_window_bytes: Option<u64>,
    /// Application-data loss timeouts that declared at least one packet lost.
    pub loss_timeouts: u64,
    /// Packets those timeouts declared lost.
    pub lost_packets: u64,
    /// Bytes those timeouts declared lost.
    pub lost_bytes: u64,
    /// Source-stream retransmit batches (ACK-gap and PTO driven).
    pub retransmit_batches: u64,
    /// Source-stream payload bytes queued for retransmission.
    pub retransmitted_stream_bytes: u64,
    /// QUIC recovery's PTO backoff count at the end of the transfer.
    pub pto_count: u32,
    /// The in-flight admission cap in force when the transfer finished.
    pub unacked_admission_cap_bytes: u64,
    /// Lowest `MAX_STREAM_DATA` credit seen at the source-stream admission
    /// gate (`None` if the gate never ran).
    pub min_stream_send_credit_bytes: Option<u64>,
    /// UDP send-batch failures counted by the endpoint (`ENOBUFS` and friends
    /// surface here on a real NIC behind a shallow qdisc).
    pub udp_send_errors: u64,
    /// Send buffer size asked of the socket.
    pub requested_send_buffer_bytes: Option<usize>,
    /// Send buffer size the platform reported after tuning (Linux doubles the
    /// request and clamps it to `net.core.wmem_max`).
    pub applied_send_buffer_bytes: Option<usize>,
    /// Receive buffer size asked of the socket.
    pub requested_recv_buffer_bytes: Option<usize>,
    /// Receive buffer size the platform reported after tuning.
    pub applied_recv_buffer_bytes: Option<usize>,
}

impl QuicSendLimiterReport {
    /// The stall record for `reason`.
    #[must_use]
    pub const fn stall(&self, reason: QuicSendStallReason) -> QuicSendStall {
        match reason {
            QuicSendStallReason::Pacing => self.pacing,
            QuicSendStallReason::Cwnd => self.cwnd,
            QuicSendStallReason::StreamCredit => self.stream_credit,
            QuicSendStallReason::UnackedGuard => self.unacked_guard,
            QuicSendStallReason::SendQueue => self.send_queue,
            QuicSendStallReason::ReceiverWindow => self.receiver_window,
            QuicSendStallReason::Other => self.other,
        }
    }

    // The recording side lives in `native_link` (feature `tls`); the pure
    // helpers stay available (and unit-tested) without it.
    #[cfg_attr(not(feature = "tls"), allow(dead_code))]
    fn stall_mut(&mut self, reason: QuicSendStallReason) -> &mut QuicSendStall {
        match reason {
            QuicSendStallReason::Pacing => &mut self.pacing,
            QuicSendStallReason::Cwnd => &mut self.cwnd,
            QuicSendStallReason::StreamCredit => &mut self.stream_credit,
            QuicSendStallReason::UnackedGuard => &mut self.unacked_guard,
            QuicSendStallReason::SendQueue => &mut self.send_queue,
            QuicSendStallReason::ReceiverWindow => &mut self.receiver_window,
            QuicSendStallReason::Other => &mut self.other,
        }
    }

    /// Every stall reason with its record, in [`QuicSendStallReason::ALL`]
    /// order.
    #[must_use]
    pub fn stalls(&self) -> [(QuicSendStallReason, QuicSendStall); 7] {
        QuicSendStallReason::ALL.map(|reason| (reason, self.stall(reason)))
    }

    /// Total held time across all reasons, in microseconds (saturating).
    #[must_use]
    pub fn total_stall_micros(&self) -> u64 {
        self.stalls()
            .iter()
            .fold(0u64, |total, (_, stall)| total.saturating_add(stall.micros))
    }

    /// The reason that held the sender longest, or `None` when nothing did.
    /// Ties resolve to the earlier entry of [`QuicSendStallReason::ALL`].
    #[must_use]
    pub fn dominant_stall(&self) -> Option<(QuicSendStallReason, QuicSendStall)> {
        let mut best: Option<(QuicSendStallReason, QuicSendStall)> = None;
        for (reason, stall) in self.stalls() {
            if stall.micros == 0 {
                continue;
            }
            match best {
                Some((_, current)) if current.micros >= stall.micros => {}
                _ => best = Some((reason, stall)),
            }
        }
        best
    }

    /// Record one wait of `held` behind `reason`.
    #[cfg_attr(not(feature = "tls"), allow(dead_code))]
    pub(crate) fn note_stall(&mut self, reason: QuicSendStallReason, held: Duration) {
        let stall = self.stall_mut(reason);
        stall.count = stall.count.saturating_add(1);
        stall.micros = stall
            .micros
            .saturating_add(duration_to_micros_saturating(held));
    }

    /// Fold one source-stream admission-gate sample into the min/peak
    /// fields: the cap in force, the sent-but-unacked bytes, the remaining
    /// stream credit, and the rate controller's bottleneck estimate.
    #[cfg_attr(not(feature = "tls"), allow(dead_code))]
    pub(crate) fn observe_source_stream(
        &mut self,
        admission_cap: u64,
        unacked_bytes: u64,
        credit_remaining: u64,
        bottleneck_bytes_per_s: u64,
    ) {
        self.min_unacked_admission_cap_bytes = Some(
            self.min_unacked_admission_cap_bytes
                .map_or(admission_cap, |min| min.min(admission_cap)),
        );
        self.peak_stream_unacked_bytes = self.peak_stream_unacked_bytes.max(unacked_bytes);
        let window = credit_remaining.saturating_add(unacked_bytes);
        self.peak_stream_send_window_bytes = Some(
            self.peak_stream_send_window_bytes
                .map_or(window, |peak| peak.max(window)),
        );
        self.path_bottleneck_bytes_per_s =
            self.path_bottleneck_bytes_per_s.max(bottleneck_bytes_per_s);
    }

    /// Fold one transport snapshot into the peak/min/slow-start fields.
    #[cfg_attr(not(feature = "tls"), allow(dead_code))]
    pub(crate) fn observe_transport(
        &mut self,
        bytes_in_flight: u64,
        congestion_window_bytes: u64,
        ssthresh_bytes: u64,
    ) {
        self.transport_samples = self.transport_samples.saturating_add(1);
        self.peak_bytes_in_flight = self.peak_bytes_in_flight.max(bytes_in_flight);
        self.peak_congestion_window_bytes = self
            .peak_congestion_window_bytes
            .max(congestion_window_bytes);
        self.min_congestion_window_bytes = Some(
            self.min_congestion_window_bytes
                .map_or(congestion_window_bytes, |min| {
                    min.min(congestion_window_bytes)
                }),
        );
        self.final_congestion_window_bytes = congestion_window_bytes;
        if ssthresh_bytes != u64::MAX {
            self.slow_start_exited = true;
            self.final_ssthresh_bytes = Some(ssthresh_bytes);
        }
    }
}

/// Microseconds of `duration`, saturating at `u64::MAX`.
#[cfg_attr(not(feature = "tls"), allow(dead_code))]
pub(crate) fn duration_to_micros_saturating(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

/// Splits a wait loop's monotonically growing elapsed time into
/// non-overlapping slices.
///
/// Per-iteration stall attribution can then never exceed the wall time of
/// the loop that recorded it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(not(feature = "tls"), allow(dead_code))]
pub(crate) struct QuicStallSliceAccounting {
    accounted: Duration,
}

impl QuicStallSliceAccounting {
    /// The time since the previous call, given the loop's total `elapsed`.
    /// A non-monotone `elapsed` yields an empty slice rather than a negative
    /// or double-counted one.
    #[cfg_attr(not(feature = "tls"), allow(dead_code))]
    pub(crate) fn take_slice(&mut self, elapsed: Duration) -> Duration {
        let slice = elapsed.saturating_sub(self.accounted);
        self.accounted = self.accounted.max(elapsed);
        slice
    }
}

/// Which gate holds the source-stream admission loop, given the three checks
/// it makes in order (queue cap, stream credit, in-flight admission cap).
#[cfg_attr(not(feature = "tls"), allow(dead_code))]
pub(crate) const fn classify_source_stream_admission(
    queue_over_cap: bool,
    credit_ok: bool,
    unacked_ok: bool,
) -> Option<QuicSendStallReason> {
    if queue_over_cap {
        Some(QuicSendStallReason::SendQueue)
    } else if !credit_ok {
        Some(QuicSendStallReason::StreamCredit)
    } else if !unacked_ok {
        Some(QuicSendStallReason::UnackedGuard)
    } else {
        None
    }
}

/// Which gate blocked a flush that sent nothing while stream frames were
/// pending.
///
/// The congestion window first, then exhausted stream credit on the paced
/// source stream, else an unidentified refusal.
#[cfg_attr(not(feature = "tls"), allow(dead_code))]
pub(crate) const fn classify_blocked_flush(
    can_send: bool,
    paced_stream_credit_remaining: Option<u64>,
) -> QuicSendStallReason {
    if !can_send {
        QuicSendStallReason::Cwnd
    } else if matches!(paced_stream_credit_remaining, Some(0)) {
        QuicSendStallReason::StreamCredit
    } else {
        QuicSendStallReason::Other
    }
}

/// Windows of credit a source stream must send without a single repair
/// episode before the sender asks the receiver to grow its window.
///
/// A path earns a larger window by proving it is loss-free, not by being
/// quiet for one window: at 2 MiB that is 16 MiB of clean delivery, ~3 % of
/// a 500 MB transfer on the WAN cell the growth exists for.
pub(crate) const SOURCE_STREAM_WINDOW_PROBE_WARMUP_WINDOWS: u64 = 8;

/// Sender-side state for [`source_stream_window_request_due`]: the send
/// limit when the admission gate first ran, and when it last asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SourceStreamWindowProbe {
    baseline_limit: u64,
    last_request_limit: u64,
}

/// Whether the source-stream admission gate should ask the receiver for a
/// larger window right now (a STREAM_DATA_BLOCKED frame), given the peer's
/// current `MAX_STREAM_DATA` limit, the window size, and the transfer's
/// running retransmit-batch count.
///
/// Asks only when the transfer has never retransmitted, the stream has sent
/// [`SOURCE_STREAM_WINDOW_PROBE_WARMUP_WINDOWS`] windows of credit since the
/// gate first ran, and at most once per window after that.
#[cfg_attr(not(feature = "tls"), allow(dead_code))]
pub(crate) fn source_stream_window_request_due(
    probe: &mut Option<SourceStreamWindowProbe>,
    send_limit: u64,
    window: u64,
    retransmit_batches: u64,
) -> bool {
    let probe = probe.get_or_insert(SourceStreamWindowProbe {
        baseline_limit: send_limit,
        last_request_limit: send_limit,
    });
    // Any repair episode at all disqualifies growth for the rest of the
    // transfer. Measured (2026-09-04, growth gated only on "no batch since
    // the last decision"): one quiet window on a lossy path was enough to
    // grow, and the grown window then cost `good` 42 s → 55 s with 149-240 MB
    // re-sent and killed `bad` outright on the receiver's reassembly guard.
    if retransmit_batches != 0 {
        return false;
    }
    let step = window.max(1);
    let warmup = step.saturating_mul(SOURCE_STREAM_WINDOW_PROBE_WARMUP_WINDOWS);
    if send_limit < probe.baseline_limit.saturating_add(warmup) {
        return false;
    }
    if send_limit < probe.last_request_limit.saturating_add(step) {
        return false;
    }
    probe.last_request_limit = send_limit;
    true
}

/// A finished ATP-over-QUIC send: the shared [`SendReport`] plus the sender's
/// limiter telemetry.
///
/// `#[non_exhaustive]` so later `0.4.x` releases can add fields without
/// breaking exhaustive destructuring.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct QuicSendOutcome {
    /// The transfer report shared with the TCP and RQ transports.
    pub report: SendReport,
    /// Why the sender waited, and what QUIC recovery looked like.
    pub limiter: QuicSendLimiterReport,
}

#[cfg(test)]
mod limiter_report_tests {
    use super::*;

    #[test]
    fn window_request_needs_a_clean_warmup_and_then_asks_once_per_window() {
        let window = 1_000;
        let warmup = window * SOURCE_STREAM_WINDOW_PROBE_WARMUP_WINDOWS;
        let mut probe = None;

        // Nothing is asked during the warmup, however clean the path is.
        assert!(!source_stream_window_request_due(
            &mut probe, 1_000, window, 0
        ));
        assert!(!source_stream_window_request_due(
            &mut probe,
            1_000 + warmup - 1,
            window,
            0
        ));
        // The warmup completes on a still-clean path: ask.
        assert!(source_stream_window_request_due(
            &mut probe,
            1_000 + warmup,
            window,
            0
        ));
        // Less than a window further on: no second ask.
        assert!(!source_stream_window_request_due(
            &mut probe,
            1_000 + warmup + window - 1,
            window,
            0
        ));
        // A full window further on: ask again.
        assert!(source_stream_window_request_due(
            &mut probe,
            1_000 + warmup + window,
            window,
            0
        ));
        // One repair episode disqualifies the transfer permanently, even
        // though windows keep going by cleanly afterwards.
        assert!(!source_stream_window_request_due(
            &mut probe,
            1_000 + warmup + 4 * window,
            window,
            1
        ));
        assert!(!source_stream_window_request_due(
            &mut probe,
            1_000 + warmup + 8 * window,
            window,
            1
        ));

        // A path that is already repairing when the gate first runs never
        // asks. The batch counter only ever grows, so no later call can
        // un-disqualify it however far the limit advances.
        let mut lossy = None;
        assert!(!source_stream_window_request_due(
            &mut lossy, 5_000, window, 3
        ));
        assert!(!source_stream_window_request_due(
            &mut lossy,
            5_000 + warmup,
            window,
            3
        ));
        assert!(!source_stream_window_request_due(
            &mut lossy,
            5_000 + warmup + 4 * window,
            window,
            9
        ));

        // A zero window degrades to one ask per byte of progress after the
        // warmup, and never panics.
        let mut zero = None;
        assert!(!source_stream_window_request_due(&mut zero, 5, 0, 0));
        assert!(source_stream_window_request_due(&mut zero, 13, 0, 0));
    }

    #[test]
    fn source_stream_samples_track_the_min_cap_and_peak_unacked() {
        let mut report = QuicSendLimiterReport::default();
        assert_eq!(report.min_unacked_admission_cap_bytes, None);
        assert_eq!(report.peak_stream_send_window_bytes, None);
        report.observe_source_stream(4_000, 10, 90, 500);
        report.observe_source_stream(2_000, 30, 20, 800);
        report.observe_source_stream(3_000, 20, 40, 0);
        assert_eq!(report.min_unacked_admission_cap_bytes, Some(2_000));
        assert_eq!(report.peak_stream_unacked_bytes, 30);
        assert_eq!(
            report.peak_stream_send_window_bytes,
            Some(100),
            "credit remaining plus unacked bytes, at its peak"
        );
        assert_eq!(report.path_bottleneck_bytes_per_s, 800);
    }

    #[test]
    fn stall_accounting_counts_every_reason_and_names_the_longest() {
        let mut report = QuicSendLimiterReport::default();
        assert_eq!(report.dominant_stall(), None);
        assert_eq!(report.total_stall_micros(), 0);

        let held = [
            (QuicSendStallReason::Pacing, 1_000),
            (QuicSendStallReason::Cwnd, 5_000),
            (QuicSendStallReason::StreamCredit, 300),
            (QuicSendStallReason::UnackedGuard, 7_000),
            (QuicSendStallReason::SendQueue, 20),
            (QuicSendStallReason::ReceiverWindow, 4),
            (QuicSendStallReason::Other, 1),
        ];
        for (reason, micros) in held {
            report.note_stall(reason, Duration::from_micros(micros));
            report.note_stall(reason, Duration::from_micros(micros));
        }

        for (reason, micros) in held {
            let stall = report.stall(reason);
            assert_eq!(stall.count, 2, "{}", reason.name());
            assert_eq!(stall.micros, micros * 2, "{}", reason.name());
        }
        let expected_total: u64 = held.iter().map(|(_, micros)| micros * 2).sum();
        assert_eq!(report.total_stall_micros(), expected_total);
        let (dominant, stall) = report.dominant_stall().expect("something stalled");
        assert_eq!(dominant, QuicSendStallReason::UnackedGuard);
        assert_eq!(stall.micros, 14_000);
        assert_eq!(dominant.name(), "unacked_guard");
        assert_eq!(
            report.stalls().map(|(reason, _)| reason),
            QuicSendStallReason::ALL
        );
    }

    #[test]
    fn dominant_stall_ties_resolve_to_report_order_and_ignore_counts() {
        let mut report = QuicSendLimiterReport::default();
        report.note_stall(QuicSendStallReason::Cwnd, Duration::from_micros(10));
        report.note_stall(QuicSendStallReason::Pacing, Duration::from_micros(10));
        // Many short pacing waits still lose to one long cwnd wait.
        for _ in 0..50 {
            report.note_stall(QuicSendStallReason::SendQueue, Duration::from_nanos(10));
        }
        let (dominant, _) = report.dominant_stall().expect("stalled");
        assert_eq!(dominant, QuicSendStallReason::Pacing);
        assert_eq!(report.send_queue.count, 50);
        assert_eq!(report.send_queue.micros, 0);
    }

    #[test]
    fn stall_micros_saturate_instead_of_wrapping() {
        let mut report = QuicSendLimiterReport::default();
        report.note_stall(QuicSendStallReason::Cwnd, Duration::MAX);
        report.note_stall(QuicSendStallReason::Cwnd, Duration::MAX);
        assert_eq!(report.cwnd.micros, u64::MAX);
        assert_eq!(report.total_stall_micros(), u64::MAX);
    }

    #[test]
    fn slice_accounting_never_exceeds_the_loop_wall_time() {
        let mut slices = QuicStallSliceAccounting::default();
        let mut attributed = Duration::ZERO;
        // Deterministic pseudo-random monotone clock with one backwards step.
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        let mut clock = Duration::ZERO;
        let mut previous_clock = Duration::ZERO;
        for step in 0..1_000u32 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let advance = Duration::from_micros(state % 5_000);
            clock += advance;
            let observed = if step == 500 {
                // A reading BELOW the last accounted point (a non-monotone
                // clock) must yield an empty slice, never a negative or a
                // double-counted one; the skipped advance is attributed by
                // the next monotone reading.
                previous_clock
                    .checked_sub(Duration::from_millis(3))
                    .unwrap_or(Duration::ZERO)
            } else {
                clock
            };
            let slice = slices.take_slice(observed);
            if step == 500 {
                assert_eq!(slice, Duration::ZERO, "a backwards clock yields no slice");
            }
            attributed += slice;
            assert!(
                attributed <= clock,
                "attributed {attributed:?} > wall {clock:?}"
            );
            previous_clock = clock;
        }
        assert_eq!(attributed, clock, "monotone slices sum to the wall time");
    }

    #[test]
    fn source_stream_admission_classifier_follows_gate_order() {
        assert_eq!(
            classify_source_stream_admission(true, false, false),
            Some(QuicSendStallReason::SendQueue)
        );
        assert_eq!(
            classify_source_stream_admission(false, false, false),
            Some(QuicSendStallReason::StreamCredit)
        );
        assert_eq!(
            classify_source_stream_admission(false, true, false),
            Some(QuicSendStallReason::UnackedGuard)
        );
        assert_eq!(classify_source_stream_admission(false, true, true), None);
    }

    #[test]
    fn blocked_flush_classifier_prefers_cwnd_then_stream_credit() {
        assert_eq!(
            classify_blocked_flush(false, Some(0)),
            QuicSendStallReason::Cwnd
        );
        assert_eq!(
            classify_blocked_flush(true, Some(0)),
            QuicSendStallReason::StreamCredit
        );
        assert_eq!(
            classify_blocked_flush(true, Some(1)),
            QuicSendStallReason::Other
        );
        assert_eq!(
            classify_blocked_flush(true, None),
            QuicSendStallReason::Other
        );
    }

    #[test]
    fn transport_samples_track_peaks_and_slow_start_exit() {
        let mut report = QuicSendLimiterReport::default();
        report.observe_transport(1_000, 12_000, u64::MAX);
        assert!(!report.slow_start_exited);
        assert_eq!(report.final_ssthresh_bytes, None);
        assert_eq!(report.min_congestion_window_bytes, Some(12_000));
        report.observe_transport(50_000, 64_000, u64::MAX);
        report.observe_transport(30_000, 32_000, 32_000);
        assert_eq!(report.transport_samples, 3);
        assert_eq!(report.peak_bytes_in_flight, 50_000);
        assert_eq!(report.peak_congestion_window_bytes, 64_000);
        assert_eq!(report.min_congestion_window_bytes, Some(12_000));
        assert_eq!(report.final_congestion_window_bytes, 32_000);
        assert_eq!(report.final_ssthresh_bytes, Some(32_000));
        assert!(report.slow_start_exited);
    }

    #[test]
    fn stall_reason_names_are_stable_and_distinct() {
        let names: std::collections::BTreeSet<&str> = QuicSendStallReason::ALL
            .iter()
            .map(|reason| reason.name())
            .collect();
        assert_eq!(names.len(), QuicSendStallReason::ALL.len());
        assert!(names.contains("cwnd"));
        assert!(names.contains("stream_credit"));
    }
}

// The RaptorQ symbol-envelope codec (the framing of a symbol inside a QUIC
// DATAGRAM) — the foundational piece B2/B3 build the sender/receiver on.
pub use symbol_envelope::{
    ATP_QUIC_SYMBOL_MAGIC, AUTH_ENVELOPE_HEADER_LEN, ENVELOPE_HEADER_LEN, QuicSymbolEnvelope,
    QuicSymbolEnvelopeError,
};

// The Symbol <-> QUIC-datagram bridge: maps types::symbol::Symbol to/from the
// envelope and moves it over the A6 QuicConnection datagram plane. The reusable
// data-path core for the B2 sender and B3 receiver coroutines.
pub use symbol_datagram::{
    SymbolDatagramError, envelope_to_symbol, recv_symbol_envelope, send_symbol, symbol_to_envelope,
};

pub use crate::net::atp::transport_rq::adaptive::{
    AdaptiveController as QuicAdaptiveController, AdaptivePolicy as QuicAdaptivePolicy,
    BlockPlan as QuicAdaptiveBlockPlan,
    DEFAULT_COLD_START_PACING_BYTES_PER_S as QUIC_DEFAULT_COLD_START_PACING_BYTES_PER_S,
    PathEstimate as QuicPathEstimate, PathSignalSample as QuicPathSignalSample,
    RateMatchedPacingPlan as QuicRateMatchedPacingPlan,
    rate_matched_pacing_plan as rq_rate_matched_pacing_plan,
};

/// Protocol identifier carried in the QUIC handshake; bump on wire-incompatible
/// changes. Distinct from `transport_tcp` (`1`) and `transport_rq` (`2`).
pub const ATP_QUIC_PROTOCOL: u32 = 3;

/// Default streaming hash/read buffer size. Bounds the sender's per-file
/// streaming pass; peak RSS is `O(chunk_size)`, independent of transfer size.
pub const DEFAULT_CHUNK_SIZE: usize = 256 * 1024;

/// Default RaptorQ symbol payload size, kept small enough that one symbol plus
/// its envelope fits a single QUIC DATAGRAM well under a 1500-byte path MTU.
pub const DEFAULT_SYMBOL_SIZE: u16 = 1024;

/// Default RaptorQ source-block size in bytes for QUIC DATAGRAM transfers.
///
/// With 1 KiB symbols this targets K ~= 512 source symbols per block. The sender
/// carries this value in the QUIC Hello and the receiver rejects mismatches, so
/// mixed-version peers fail closed instead of silently decoding with different
/// block geometry.
pub const DEFAULT_MAX_BLOCK_SIZE: usize = 512 * 1024;

/// Default ceiling on a single QUIC DATAGRAM's application payload.
///
/// Tracks the RFC 9221 `max_datagram_frame_size` budget; a RaptorQ symbol
/// envelope must fit within this, so it is validated against
/// [`QuicConfig::symbol_size`].
pub const DEFAULT_MAX_DATAGRAM_SIZE: usize = 1200;

/// Default round-0 repair multiplier (`>= 1.0`). The tiny default proactive
/// RaptorQ tail keeps the fast source-first shape while absorbing sparse loss.
pub const DEFAULT_REPAIR_OVERHEAD: f64 = 1.001;

/// Default ceiling on a single transfer's total bytes.
pub const DEFAULT_MAX_TRANSFER_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// Maximum payload routed over the QUIC reliable source stream.
///
/// The stream path is the default encrypted bulk path: QUIC STREAM reliability
/// supplies native ARQ/congestion control while TLS 1.3 supplies encryption, so
/// clean through ordinary lossy matrix cells skip the RaptorQ decode wall.
///
/// The historical 512 MiB bound existed because the receiver materialized each
/// entry in RAM; the receive path now streams chunks straight to staging (with
/// an incremental hash), flow credit is a numeric limit rather than a buffer,
/// and reassembly backlog is bounded per pump turn — so the bound only needs to
/// admit the largest single transfer the CLI/bench surface exercises (5 GiB)
/// with headroom. Transfers above it continue using the FEC DATAGRAM fountain.
pub(crate) const QUIC_RELIABLE_SOURCE_STREAM_MAX_BYTES: u64 = 8 * 1024 * 1024 * 1024;

/// Largest RaptorQ symbol payload that fits one default-size QUIC DATAGRAM
/// (`max_datagram_size` 1200) together with the worst-case authenticated
/// symbol envelope header.
///
/// CLI front ends use this as the QUIC symbol-size
/// default so users never size symbols by hand; explicitly configured larger
/// values still fail closed in [`QuicConfig::validate`].
pub const QUIC_DEFAULT_SYMBOL_SIZE: u16 = 1144;
const QUIC_SOURCE_STREAM_FRAME_MAX_BYTES: usize = MAX_FRAME_SIZE as usize;
const QUIC_SOURCE_STREAM_WIRE_HEADER_MAX_BYTES: usize = 1 + 2 + 4 + 1;
const QUIC_SOURCE_STREAM_DATA_HEADER_BYTES: usize = 4 + 8;
const QUIC_SOURCE_STREAM_CHUNK_BYTES: usize = QUIC_SOURCE_STREAM_FRAME_MAX_BYTES
    - QUIC_SOURCE_STREAM_WIRE_HEADER_MAX_BYTES
    - QUIC_SOURCE_STREAM_DATA_HEADER_BYTES;

/// Default maximum time to wait for a connected peer to make protocol progress.
///
/// Encrypted lossy transfers use this as the native NeedMore/repair convergence
/// budget after feedback starts. MATRIX-64 showed converging 50M/good reps
/// around 288s with one residual timeout, so keep the default above that slow
/// recovery envelope instead of killing a transfer mid-decode.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(360);

/// Default maximum time to wait for the QUIC handshake to complete.
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Default maximum time a one-shot receiver waits for the initial accept.
pub const DEFAULT_ACCEPT_TIMEOUT: Duration = Duration::from_secs(60);

/// Default number of accepted transfers a persistent server processes at once.
pub const DEFAULT_MAX_ACTIVE_CONNECTIONS: usize = 64;

/// Default bound on fountain feedback rounds before failing closed.
///
/// Lossy ATP/QUIC must let RaptorQ repair loop until block convergence or the
/// transfer deadline. A small round count can strand the final per-block
/// deficits even while the receiver is still making progress, so the default is
/// deliberately high; tests and callers can still set a lower explicit cap.
pub const DEFAULT_MAX_FEEDBACK_ROUNDS: u32 = 1024;

/// Maximum sparse source-symbol retransmit requests accepted in one feedback round.
const MAX_SOURCE_SYMBOL_REQUESTS_PER_FEEDBACK_ROUND: usize = 2048;

/// Maximum targeted repair block entries accepted in one feedback round.
const MAX_REPAIR_BLOCK_REQUESTS_PER_FEEDBACK_ROUND: usize = 16_384;

/// Maximum targeted fresh repair symbols accepted in one feedback round.
///
/// This is a protocol safety ceiling. Lossy native QUIC paths use a dynamic,
/// path-rate-matched lower cap before emitting `NeedMore`, so the repair round
/// fits the pipe instead of self-dropping in the kernel queue.
const MAX_REPAIR_SYMBOLS_PER_FEEDBACK_ROUND: usize = 1 << 20;
const QUIC_MAX_SOURCE_BLOCKS_PER_OBJECT: usize = 256;
/// Upper bound on a peer-advertised (Hello) `max_block_size` that the receiver will ADOPT.
/// The sender scales its block size UP for large entries (see
/// `effective_quic_max_block_size_for_largest_entry`) to keep the per-object source-block count
/// under `QUIC_MAX_SOURCE_BLOCKS_PER_OBJECT`; the receiver adopts that value so its decode geometry
/// matches, but caps it here so a hostile/oversized Hello cannot force unbounded per-block decode
/// buffers. 32 MiB admits the sender's `max_entry_len / QUIC_MAX_SOURCE_BLOCKS_PER_OBJECT` scaling
/// for entries up to ~8 GiB while keeping per-block decode memory bounded. (br-asupersync-j73ili)
const MAX_QUIC_ADOPTED_BLOCK_SIZE: usize = 32 * 1024 * 1024;
const QUIC_REPAIR_REQUEST_PACING_WINDOW_MILLIS: u64 = 2_000;
const QUIC_REPAIR_REQUEST_MIN_SYMBOLS_PER_ROUND: usize = 64;

/// Maximum native QUIC DATAGRAM symbols decoded before returning to the async
/// receiver loop.
///
/// Keep this aligned with the native receiver pump width: one UDP pump turn can
/// enqueue 512 symbols, so the decoder must be able to drain that full batch on
/// arrival before asking the sender for repair. Smaller slices let the no-evict
/// receive queue grow behind the decoder under lossy bursts and can manufacture
/// unnecessary NeedMore rounds.
const NATIVE_SYMBOL_DRAIN_BATCH: usize = 512;

/// Maximum native QUIC receiver decode jobs one entry may have in flight.
///
/// Mirrors the post-MATRIX-49/50 RQ receiver bound: enough fan-out to keep
/// independent bounded-K blocks off the hot receive pump, while avoiding
/// unbounded blocking-pool and decoded-block memory pressure under bursty loss.
const QUIC_MAX_PENDING_DECODE_JOBS_PER_ENTRY: usize = 64;
/// Maximum native QUIC receiver decode jobs one transfer may have in flight.
///
/// The per-entry bound alone is insufficient for tree transfers: thousands of
/// small files could otherwise multiply the blocking-pool queue and retained
/// decoded-block memory by entry count. Once this transfer-wide window is full,
/// decode falls back to the existing inline path until ready jobs drain.
const QUIC_MAX_PENDING_DECODE_JOBS_PER_TRANSFER: usize = 64;
/// Keep tiny encrypted tree entries on the inline decode path. A 50M encrypted
/// bulk object still has enough independent source blocks to amortize
/// blocking-pool dispatch; sub-8MiB entries usually do not.
const QUIC_PARALLEL_DECODE_MIN_ENTRY_BYTES: u64 = 8 * 1024 * 1024;
const QUIC_PARALLEL_DECODE_MIN_SOURCE_BLOCKS: usize = 8;

const QUIC_PRIMARY_RECEIVE_PATH_ID: PathId = PathId(1);

/// Default adaptive datagram fan-out hint.
///
/// Phase D wires true multi-connection fan-out. Until then this remains a
/// bounded, explicit controller output carried in the transfer config so C1 can
/// prove deterministic arm application without changing the single-connection
/// B2/B3 data path.
pub const DEFAULT_DATAGRAM_FANOUT: usize = 1;

/// Default upper bound for one paced QUIC DATAGRAM spray burst.
///
/// C3's token-bucket pacer, not the QUIC NewReno cwnd, owns data-plane burst
/// admission. This cap prevents a high adaptive/AIMD rate from turning one
/// scheduler slice into an unbounded outbound queue while still letting the
/// native encrypted link coalesce a near-full jumbo 1-RTT packet of symbol
/// DATAGRAM frames after MATRIX-39 removed the old one-symbol packet budget. The
/// native clean encrypted send path may expand this default cap into a bounded
/// multi-packet GSO window; an explicit non-default cap remains the operator's
/// pacing envelope.
pub const DEFAULT_MAX_SPRAY_SYMBOLS_PER_FLUSH: usize = 54;

const QUIC_SPRAY_BURST_RTT_FRACTION: f64 = 0.125;
const QUIC_SPRAY_MIN_PAUSE: Duration = Duration::from_millis(1);
const QUIC_SPRAY_MAX_PAUSE: Duration = Duration::from_secs(1);
const QUIC_SPRAY_MIN_BACKOFF: f64 = 0.10;
const QUIC_AIMD_LOSS_DECREASE_THRESHOLD: f64 = 0.03;
const QUIC_AIMD_CLEAN_INCREASE_THRESHOLD: f64 = 0.0015;
const QUIC_AIMD_MULTIPLICATIVE_DECREASE: f64 = 0.50;
const QUIC_AIMD_ADDITIVE_INCREASE_BYTES_PER_S: u64 = 1024 * 1024;
const QUIC_AIMD_MIN_RATE_BPS: u64 = 512 * 1024;
const QUIC_AIMD_MAX_RATE_BPS: u64 = 64 * 1024 * 1024;
const QUIC_ROUND0_CLEAN_RAMP_STEP_BYTES: u64 = 8 * 1024 * 1024;
const QUIC_ROUND0_CLEAN_RAMP_ADD_BYTES_PER_S: u64 = 8 * 1024 * 1024;
// Keep QUIC's first clean encrypted probe near the 200 Mbit "good" fixture
// until central A/B proves a higher encrypted sender rate is good-safe.
const QUIC_ROUND0_CLEAN_RAMP_MAX_PACING_BPS: u64 = 24 * 1024 * 1024;
/// Reliable source STREAM pacing ceiling for clean/GOOD authenticated paths.
///
/// This is intentionally separate from the DATAGRAM clean-ramp cap: stream
/// bytes are reliable and authenticated by QUIC/TLS, while lossy DATAGRAM
/// fountains keep the lower probe cap and AIMD feedback loop.
///
/// The `cfg_attr(not(feature = "tls"), allow(dead_code))` history: the only non-test
/// use site (`promote_source_stream_pacing`) is compiled out in builds omitting the
/// QUIC pacing path, so `deny(dead_code)` re-exposed it under `tls`. Allow unconditionally.
///
/// MATRIX-202 (cwnd-clock REFUTED): raising this cap to lift the ~36.5 MB/s clean-stream
/// throughput requires cwnd/ACK-clocking the source stream (otherwise a higher fixed rate
/// storms with no cwnd ceiling). But cwnd-clocking it — even though it lifted clean 500M
/// (14s→8.9s, ~56 MB/s) — CATASTROPHICALLY regressed mildly-lossy links (50M/good @0.1%
/// loss: 4s→~52s, ~12×) because NewReno collapses cwnd on every drop, whereas the fixed-rate
/// pacer + ack-gap retransmit shrugs off mild loss. And even cwnd-clocked, clean stayed below
/// rsync (56 vs ~100 MB/s: per-packet AEAD + no TSO/GSO — a structural QUIC-vs-TCP gap). So
/// the deliberate pacer-not-cwnd design (test `native_source_stream_bulk_admission_is_pacer_not_newreno_cwnd`)
/// stands; left at the AIMD cap. Beating rsync on clean-fast encrypted needs GSO+jumbo, not a
/// bigger rate — owned by br-asupersync-uw1cc2 / the GSO work (E-6.3).
#[allow(dead_code)]
pub(crate) const QUIC_RELIABLE_SOURCE_STREAM_MAX_PACING_BPS: u64 = QUIC_AIMD_MAX_RATE_BPS;
const QUIC_ROUND0_CLEAN_RAMP_MAX_REPAIR_OVERHEAD: f64 = DEFAULT_REPAIR_OVERHEAD;
// Same `tls`/`not(tls)` interaction as `QUIC_RELIABLE_SOURCE_STREAM_MAX_PACING_BPS`
// above: the only non-test use site (`quic_near_clean_source_stream_enabled` →
// `promote_source_stream_pacing`) is compiled out in builds that omit the QUIC
// pacing path (e.g. the franken_node dependency build, no `tls`), so `deny(dead_code)`
// re-exposes it. Allow unconditionally; harmless no-op when the use site is present.
#[allow(dead_code)]
const QUIC_NEAR_CLEAN_SOURCE_STREAM_MAX_LOSS_TARGET: f64 = 0.001;
/// Loss ceiling for the reliable-source-stream bulk path.
///
/// TCP/rsync wins the 10%/200ms broken encrypted cell because mature ARQ beats
/// ATP's round-trip-bounded fountain repair there. Keep STREAM bulk selected up
/// to this conservative extreme-loss threshold; above it, the existing
/// RaptorQ-over-DATAGRAM fountain remains available as the fallback.
const QUIC_RELIABLE_SOURCE_STREAM_MAX_LOSS_TARGET: f64 = 0.30;
/// Default native QUIC path-rate caps once loss is visible.
///
/// MATRIX-143 showed that RTT alone is not a congestion signal for the clean
/// encrypted tier: the transfer is mostly parked at cold-start speed. Keep the
/// cap for paths with observed loss, but let loss-free round 0 take the clean
/// ramp even when the handshake RTT is high.
///
/// Mirror the RQ lossy matrix split: bad/2% is shaped near 50 mbit, while the
/// broken/10% cell needs a 10 mbit-class first spray before sender-side AIMD has
/// a NeedMore round to measure delivery loss.
const QUIC_RATE_MATCHED_BAD_LINK_PACING_BPS: u64 = 6 * 1024 * 1024;
const QUIC_RATE_MATCHED_BROKEN_LINK_PACING_BPS: u64 = 1152 * 1024;
const QUIC_RATE_MATCHED_BAD_LINK_LOSS_MIN: f64 = 0.010;
const QUIC_RATE_MATCHED_BROKEN_LINK_LOSS_MIN: f64 = 0.030;
#[cfg_attr(not(feature = "tls"), allow(dead_code))]
const QUIC_AIMD_LOSS_TARGET_DECREASE_MARGIN: f64 = 0.030;
const QUIC_FEEDBACK_REPAIR_LOSS_ENABLE_MIN: f64 = 0.005;
const QUIC_FEEDBACK_REPAIR_LOSS_MARGIN_FRACTION: f64 = 0.25;
const QUIC_FEEDBACK_REPAIR_LOSS_MARGIN_MIN: f64 = 0.005;
const QUIC_FEEDBACK_REPAIR_MAX_OVERHEAD: f64 = 0.50;
const QUIC_ROUND0_TARGET_LOSS_ENABLE_MIN: f64 = QUIC_FEEDBACK_REPAIR_LOSS_ENABLE_MIN;
const QUIC_ROUND0_TARGET_LOSS_MARGIN_FRACTION: f64 = QUIC_FEEDBACK_REPAIR_LOSS_MARGIN_FRACTION;
const QUIC_ROUND0_TARGET_LOSS_MARGIN_MIN: f64 = QUIC_FEEDBACK_REPAIR_LOSS_MARGIN_MIN;
const QUIC_ROUND0_TARGET_REPAIR_ALPHA: f64 = 1e-6;
const QUIC_ROUND0_TARGET_REPAIR_MAX_OVERHEAD: f64 = QUIC_FEEDBACK_REPAIR_MAX_OVERHEAD;
const QUIC_FEEDBACK_REPAIR_ESCALATE_AFTER_ROUNDS: u32 = 2;
const QUIC_FEEDBACK_REPAIR_ESCALATE_MAX_EXTRA_PER_BLOCK: usize = 64;
// On encrypted-good, the first NeedMore often reflects a sparse K-gap after
// round-0 source spray. Send a small K-scaled cushion immediately instead of
// spending several RTTs discovering the same residual one symbol at a time.
const QUIC_FEEDBACK_FIRST_REPAIR_BURST_MIN_BLOCK_SYMBOLS: usize = 128;
const QUIC_FEEDBACK_FIRST_REPAIR_BURST_Z_ALPHA: f64 = 2.0;
const QUIC_FEEDBACK_FIRST_REPAIR_BURST_MARGIN_SYMBOLS: usize = 2;
const QUIC_FEEDBACK_FIRST_REPAIR_BURST_MAX_EXTRA_PER_BLOCK: usize = 32;
const QUIC_SOURCE_STREAM_READ_CHUNK: usize = 256 * 1024;
#[cfg(feature = "tls")]
const QUIC_NATIVE_STREAM_FLOW_HEADROOM_BYTES: u64 = 1024 * 1024;
#[cfg(feature = "tls")]
const QUIC_NATIVE_STREAM_FLOW_MIN_BYTES: u64 = 16 * 1024 * 1024;

/// Tuning knobs for the ATP-over-QUIC transport.
///
/// Mirrors the role of [`transport_tcp::TransferConfig`] while adding the
/// RaptorQ-over-QUIC knobs (symbol size, block size, repair overhead, datagram
/// budget, feedback rounds) that the B2/B3 coroutines will consume.
///
/// [`transport_tcp::TransferConfig`]: crate::net::atp::transport_tcp::TransferConfig
#[derive(Debug, Clone)]
pub struct QuicConfig {
    /// Streaming hash/read buffer size in bytes.
    pub chunk_size: usize,
    /// RaptorQ symbol payload size in bytes.
    pub symbol_size: u16,
    /// Maximum RaptorQ source-block size in bytes.
    pub max_block_size: usize,
    /// Maximum application payload carried in one QUIC DATAGRAM.
    pub max_datagram_size: usize,
    /// Extra repair fraction sprayed in round 0 (`>= 1.0`).
    pub repair_overhead: f64,
    /// Expected round-0 path loss fraction for benchmark/operator selection.
    ///
    /// A zero target means the link is being treated as clean, so native
    /// QUIC/TLS may choose the reliable stream source path. Non-zero loss keeps
    /// the transfer on the RaptorQ DATAGRAM fountain.
    pub round0_loss_target: f64,
    /// Maximum total bytes a single transfer may carry.
    pub max_transfer_bytes: u64,
    /// Enable receiver-driven delta negotiation on the authenticated control stream.
    ///
    /// The first rollout supports a live already-in-sync receipt for one
    /// unpacked regular file and requires a strict shared [`SecurityContext`]
    /// for receiver-challenged client proof. Server-authenticated TLS without
    /// that key stays on the full-object path and never probes delta state.
    /// This gate does not add client authorization to ordinary full uploads.
    pub enable_delta: bool,
    /// Shared strict authentication context for receiver-challenged delta control.
    ///
    /// This is deliberately separate from `Self::symbol_auth_context`. Native
    /// QUIC keeps source symbols on its reliable transport-authenticated stream,
    /// while this context proves possession of the shared key before receiver
    /// filesystem state is inspected or disclosed.
    pub delta_control_auth_context: Option<SecurityContext>,
    /// Maximum time to wait for the next protocol frame before failing closed.
    pub idle_timeout: Duration,
    /// Maximum time to wait for the QUIC handshake to complete.
    pub handshake_timeout: Duration,
    /// Maximum time a one-shot receive waits for `accept()`. In persistent
    /// `serve()` this doubles as the idle cancellation-checkpoint interval.
    pub accept_timeout: Duration,
    /// Maximum number of connections `serve()` may process concurrently.
    /// A value of zero is treated as one active connection.
    pub max_active_connections: usize,
    /// Maximum fountain feedback rounds before a transfer fails closed.
    pub max_feedback_rounds: u32,
    /// Adaptive controller's datagram fan-out hint.
    ///
    /// The current B2/B3 QUIC implementation uses one connection. This field
    /// intentionally records the selected C1 arm now; Phase D consumes it for
    /// multi-connection fan-out.
    pub datagram_fanout: usize,
    /// Optional sender bandwidth cap in bytes per second.
    ///
    /// This is the internal transport knob that future CLI `--bwlimit` plumbing
    /// will set. `None` lets QUIC path signals select the pacing rate.
    pub bwlimit_bps: Option<u64>,
    /// Maximum DATAGRAM symbols queued before a paced flush.
    ///
    /// The live decision is governed by the token-bucket pacer using the
    /// adaptive/AIMD rate, FEC-budgeted loss, responsiveness pressure, and this
    /// cap. QUIC recovery cwnd remains telemetry for path estimation; it is not
    /// the ATP RaptorQ data-plane admission gate.
    pub max_spray_symbols_per_flush: usize,
    /// Normalized host pressure used by the pacing policy.
    ///
    /// `0.0` means no local responsiveness pressure; `1.0` means saturated. The
    /// caller owns sampling CPU/loadavg/cgroup pressure and passes the snapshot
    /// here, keeping this library path deterministic and ambient-free.
    pub responsiveness_pressure: f64,
    /// Optional per-symbol authentication context for QUIC DATAGRAM symbols.
    ///
    /// When present, senders append an HMAC tag to every symbol envelope and
    /// receivers verify every symbol before decoding. Direct native QUIC/TLS
    /// transfers do not need this second authentication layer: the stream and
    /// DATAGRAM bytes are already covered by QUIC 1-RTT AEAD.
    pub symbol_auth_context: Option<SecurityContext>,
    /// Explicit opt-in for links whose transport already authenticates every
    /// byte (direct native QUIC/TLS) or trusted lab links that intentionally
    /// accept integrity-vs-manifest only.
    pub allow_unauthenticated_symbols: bool,
    /// Filesystem-metadata fidelity policy for manifest entries.
    pub metadata_policy: MetadataPolicy,
    /// Opt-in recreation of safe special files. Defaults to skip-and-trace.
    pub allow_special_files: bool,
    /// Opt-in hardlink preservation within a transfer.
    pub preserve_hardlinks: bool,
    /// Deterministic test/diagnostic symbol-loss injection. When nonzero, the
    /// sender skips every Nth symbol on the *initial* spray only (never on a
    /// repair round), so the fountain feedback loop must recover them. Zero
    /// disables injection. Mirrors `transport_rq`'s `debug_drop_one_in`.
    pub debug_drop_one_in: u32,
    /// Client-side TLS trust for [`send_path`]: the server name to verify and the
    /// root certificates that gate the handshake (no insecure skip-verify path).
    /// Required to open a real native QUIC connection; absent fails closed.
    #[cfg(feature = "tls")]
    pub client_tls: Option<native_link::QuicClientTls>,
    /// Server-side TLS material for the native receive path: the presented
    /// certificate chain and private key. Required to accept a real native QUIC
    /// connection; absent fails closed.
    #[cfg(feature = "tls")]
    pub server_tls: Option<native_link::QuicServerTls>,
}

/// Receiver-only filesystem reconstruction options for ATP-over-QUIC.
///
/// This type is separate from [`QuicConfig`] so adding receiver behaviors does
/// not break callers that construct the public transport config exhaustively.
/// All options default off, preserving the established dense-file behavior.
/// Sparse allocation is currently available only on Unix and remains subject
/// to the destination filesystem's hole-allocation support.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct QuicReceiveOptions {
    sparse_files: bool,
}

impl QuicReceiveOptions {
    /// Create receiver options with compatibility-preserving defaults.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            sparse_files: false,
        }
    }

    /// Reconstruct long zero runs as filesystem holes when enabled.
    ///
    /// This is a content-preserving allocation heuristic. It does not claim to
    /// reproduce the sender's exact filesystem extent map.
    #[must_use]
    pub const fn with_sparse_files(mut self, enabled: bool) -> Self {
        self.sparse_files = enabled;
        self
    }

    /// Whether the receiver reconstructs long zero runs as filesystem holes.
    #[must_use]
    pub const fn sparse_files(&self) -> bool {
        self.sparse_files
    }

    fn validate(&self) -> Result<(), QuicTransportError> {
        if self.sparse_files() && !cfg!(unix) {
            return Err(QuicTransportError::Config(
                "QUIC sparse-file reconstruction currently requires Unix; Windows needs an \
                 FSCTL_SET_SPARSE implementation before this option can be enabled"
                    .to_string(),
            ));
        }
        Ok(())
    }
}

/// Public per-symbol authentication posture for ATP-over-QUIC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicSymbolAuthMode {
    /// Symbols are signed and verified with a configured [`SecurityContext`].
    Authenticated,
    /// Symbols rely on the authenticated direct transport, e.g. QUIC 1-RTT AEAD.
    TransportAuthenticated,
    /// No auth context was configured and no explicit transport-auth opt-out was set.
    MissingAuthenticationContext,
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            chunk_size: DEFAULT_CHUNK_SIZE,
            symbol_size: DEFAULT_SYMBOL_SIZE,
            max_block_size: DEFAULT_MAX_BLOCK_SIZE,
            max_datagram_size: DEFAULT_MAX_DATAGRAM_SIZE,
            repair_overhead: DEFAULT_REPAIR_OVERHEAD,
            round0_loss_target: 0.0,
            max_transfer_bytes: DEFAULT_MAX_TRANSFER_BYTES,
            enable_delta: false,
            delta_control_auth_context: None,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            accept_timeout: DEFAULT_ACCEPT_TIMEOUT,
            max_active_connections: DEFAULT_MAX_ACTIVE_CONNECTIONS,
            max_feedback_rounds: DEFAULT_MAX_FEEDBACK_ROUNDS,
            datagram_fanout: DEFAULT_DATAGRAM_FANOUT,
            bwlimit_bps: None,
            max_spray_symbols_per_flush: DEFAULT_MAX_SPRAY_SYMBOLS_PER_FLUSH,
            responsiveness_pressure: 0.0,
            symbol_auth_context: None,
            allow_unauthenticated_symbols: false,
            metadata_policy: MetadataPolicy::default(),
            allow_special_files: false,
            preserve_hardlinks: false,
            debug_drop_one_in: 0,
            #[cfg(feature = "tls")]
            client_tls: None,
            #[cfg(feature = "tls")]
            server_tls: None,
        }
    }
}

impl QuicConfig {
    /// Require receiver-challenged delta control authentication with this context.
    #[must_use]
    pub fn with_delta_control_auth(mut self, context: SecurityContext) -> Self {
        self.delta_control_auth_context = Some(context);
        self
    }

    /// Require per-symbol authentication with this context.
    #[must_use]
    pub fn with_symbol_auth(mut self, context: SecurityContext) -> Self {
        self.symbol_auth_context = Some(context);
        self.allow_unauthenticated_symbols = false;
        self
    }

    /// Use the native QUIC/TLS transport AEAD as the symbol authentication
    /// boundary for direct, single-connection transfers.
    #[must_use]
    pub fn use_transport_authenticated_symbols(mut self) -> Self {
        self.symbol_auth_context = None;
        self.allow_unauthenticated_symbols = true;
        self
    }

    /// Explicitly allow symbols without per-symbol HMAC on links whose transport
    /// already authenticates every byte, or for trusted loopback/lab links.
    #[must_use]
    pub fn allow_unauthenticated_for_trusted_transport(self) -> Self {
        self.use_transport_authenticated_symbols()
    }

    /// Return the configured per-symbol authentication posture.
    #[must_use]
    pub fn symbol_auth_mode(&self) -> QuicSymbolAuthMode {
        if self.symbol_auth_context.is_some() {
            return QuicSymbolAuthMode::Authenticated;
        }
        if self.allow_unauthenticated_symbols {
            return QuicSymbolAuthMode::TransportAuthenticated;
        }
        QuicSymbolAuthMode::MissingAuthenticationContext
    }

    /// Validate that the symbol-auth posture is deliberate.
    pub fn validate_symbol_auth_mode(&self) -> Result<(), QuicTransportError> {
        self.symbol_auth_context().map(|_| ())
    }

    fn symbol_auth_context(&self) -> Result<Option<SecurityContext>, QuicTransportError> {
        if let Some(context) = &self.symbol_auth_context {
            return Ok(Some(context.clone()));
        }
        if self.allow_unauthenticated_symbols {
            return Ok(None);
        }
        Err(QuicTransportError::Config(
            "ATP-over-QUIC requires symbol_auth_context or a deliberate symbol authentication posture: call \
             with_symbol_auth(...) for relay/multipath/raw-UDP symbol auth or \
             use_transport_authenticated_symbols() for direct QUIC/TLS transport AEAD"
                .to_string(),
        ))
    }

    /// Validate the configuration, failing closed on any nonsensical knob before
    /// the transport opens a socket or allocates a buffer. Attacker-irrelevant
    /// (this is the *local* operator's config) but it turns silent misbehavior
    /// (zero timeouts that would hang, a symbol that cannot fit a datagram) into
    /// an explicit typed error.
    pub fn validate(&self) -> Result<(), QuicTransportError> {
        if self.chunk_size == 0 {
            return Err(QuicTransportError::Config(
                "chunk_size must be greater than 0".to_string(),
            ));
        }
        if self.symbol_size == 0 {
            return Err(QuicTransportError::Config(
                "symbol_size must be greater than 0".to_string(),
            ));
        }
        if self.max_block_size == 0 {
            return Err(QuicTransportError::Config(
                "max_block_size must be greater than 0".to_string(),
            ));
        }
        // A symbol payload (symbol_size) plus its worst-case (authenticated)
        // envelope header must fit one QUIC DATAGRAM. Use the authenticated
        // header so the bound holds regardless of the per-transfer auth posture.
        let min_datagram = usize::from(self.symbol_size) + AUTH_ENVELOPE_HEADER_LEN;
        if self.max_datagram_size < min_datagram {
            return Err(QuicTransportError::Config(format!(
                "max_datagram_size ({}) must be at least symbol_size ({}) + the \
                 {AUTH_ENVELOPE_HEADER_LEN}-byte authenticated envelope header = {min_datagram} \
                 so a symbol fits one DATAGRAM",
                self.max_datagram_size, self.symbol_size
            )));
        }
        if self.repair_overhead < 1.0 || self.repair_overhead.is_nan() {
            return Err(QuicTransportError::Config(format!(
                "repair_overhead ({}) must be >= 1.0",
                self.repair_overhead
            )));
        }
        if !self.round0_loss_target.is_finite() || !(0.0..1.0).contains(&self.round0_loss_target) {
            return Err(QuicTransportError::Config(format!(
                "round0_loss_target ({}) must be finite and in [0.0, 1.0)",
                self.round0_loss_target
            )));
        }
        if self.max_transfer_bytes == 0 {
            return Err(QuicTransportError::Config(
                "max_transfer_bytes must be greater than 0".to_string(),
            ));
        }
        if self.idle_timeout.is_zero() {
            return Err(QuicTransportError::Config(
                "idle_timeout must be greater than 0".to_string(),
            ));
        }
        if self.handshake_timeout.is_zero() {
            return Err(QuicTransportError::Config(
                "handshake_timeout must be greater than 0".to_string(),
            ));
        }
        if self.accept_timeout.is_zero() {
            return Err(QuicTransportError::Config(
                "accept_timeout must be greater than 0".to_string(),
            ));
        }
        if self.max_feedback_rounds == 0 {
            return Err(QuicTransportError::Config(
                "max_feedback_rounds must be greater than 0".to_string(),
            ));
        }
        if self.datagram_fanout == 0 {
            return Err(QuicTransportError::Config(
                "datagram_fanout must be greater than 0".to_string(),
            ));
        }
        if matches!(self.bwlimit_bps, Some(0)) {
            return Err(QuicTransportError::Config(
                "bwlimit_bps must be greater than 0 when set".to_string(),
            ));
        }
        if self.max_spray_symbols_per_flush == 0 {
            return Err(QuicTransportError::Config(
                "max_spray_symbols_per_flush must be greater than 0".to_string(),
            ));
        }
        if !self.responsiveness_pressure.is_finite()
            || !(0.0..=1.0).contains(&self.responsiveness_pressure)
        {
            return Err(QuicTransportError::Config(
                "responsiveness_pressure must be finite and in [0.0, 1.0]".to_string(),
            ));
        }
        self.validate_symbol_auth_mode()?;
        Ok(())
    }
}

/// QUIC-side adaptive arm selected by the deterministic C1 controller.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct QuicAdaptiveArm {
    /// Source symbols per RaptorQ block.
    pub k: u32,
    /// QUIC transfer repair multiplier (`1.0 + extra_repair_fraction`).
    pub repair_overhead: f64,
    /// Datagram fan-out hint for Phase D multi-connection spray.
    pub datagram_fanout: usize,
}

impl QuicAdaptiveArm {
    /// Convert the shared adaptive controller's block plan into QUIC config
    /// terms. The shared controller reports overhead as an extra fraction; the
    /// QUIC transfer config stores the multiplier used by the encoder.
    pub fn from_block_plan(plan: QuicAdaptiveBlockPlan) -> Result<Self, QuicTransportError> {
        if plan.k == 0 {
            return Err(QuicTransportError::Config(
                "adaptive arm k must be greater than 0".to_string(),
            ));
        }
        if !plan.overhead.is_finite() || plan.overhead < 0.0 {
            return Err(QuicTransportError::Config(format!(
                "adaptive arm overhead ({}) must be finite and >= 0.0",
                plan.overhead
            )));
        }
        if plan.fanout == 0 {
            return Err(QuicTransportError::Config(
                "adaptive arm fanout must be greater than 0".to_string(),
            ));
        }
        Ok(Self {
            k: plan.k,
            repair_overhead: 1.0 + plan.overhead,
            datagram_fanout: plan.fanout,
        })
    }

    /// Apply this arm to a transfer config. This is pure and side-effect-free;
    /// the caller can run it once per epoch and pass the returned config into
    /// the existing B2/B3 transfer helpers.
    pub fn apply_to_config(self, mut config: QuicConfig) -> Result<QuicConfig, QuicTransportError> {
        let k = usize::try_from(self.k).map_err(|_| {
            QuicTransportError::Config(format!("adaptive arm k ({}) does not fit usize", self.k))
        })?;
        config.max_block_size =
            usize::from(config.symbol_size)
                .checked_mul(k)
                .ok_or_else(|| {
                    QuicTransportError::Config(format!(
                        "adaptive arm k ({}) overflows max_block_size for symbol_size {}",
                        self.k, config.symbol_size
                    ))
                })?;
        config.repair_overhead = self.repair_overhead;
        config.datagram_fanout = self.datagram_fanout;
        config.validate()?;
        Ok(config)
    }
}

/// Apply a shared adaptive controller block plan to QUIC transfer configuration.
pub fn apply_quic_adaptive_block_plan(
    config: QuicConfig,
    plan: QuicAdaptiveBlockPlan,
) -> Result<QuicConfig, QuicTransportError> {
    QuicAdaptiveArm::from_block_plan(plan)?.apply_to_config(config)
}

/// Result of one QUIC adaptive pacing epoch.
#[derive(Debug, Clone)]
pub struct QuicAdaptivePacingDecision {
    /// Transfer config with the selected block/FEC/fan-out geometry and raw
    /// pacing cap applied.
    pub config: QuicConfig,
    /// Shared calibrated rate plan used to produce this decision.
    pub rate_plan: QuicRateMatchedPacingPlan,
    /// QUIC spray pacing decision derived from `config` and the current path
    /// signal.
    pub spray: QuicSprayPacingDecision,
}

/// Convert a shared adaptive path estimate into a QUIC transfer config and
/// spray pacing decision.
///
/// This is the Phase-C bridge from `PathEstimate` to QUIC's datagram pacing:
/// the shared model computes calibrated FEC overhead and a raw rate cap
/// `lambda`, where useful payload is bounded by `lambda / (1 + epsilon)`.
/// QUIC applies that raw cap through the existing deterministic spray pacer.
/// If evidence is too thin, the fixed transfer geometry is preserved and only a
/// conservative cold-start rate cap is applied.
pub fn quic_adaptive_rate_matched_pacing_decision(
    config: &QuicConfig,
    estimate: &QuicPathEstimate,
    path: QuicPathSignalSample,
    policy: &QuicAdaptivePolicy,
    cpu_parallelism: usize,
) -> Result<QuicAdaptivePacingDecision, QuicTransportError> {
    config.validate()?;

    let cold_start_bytes_per_s = config
        .bwlimit_bps
        .map_or(QUIC_DEFAULT_COLD_START_PACING_BYTES_PER_S, |cap| {
            cap.max(1) as f64
        });
    let max_burst_datagrams = u32::try_from(config.max_spray_symbols_per_flush)
        .unwrap_or(u32::MAX)
        .max(1);
    let rate_plan = rq_rate_matched_pacing_plan(
        estimate,
        policy,
        config.symbol_size,
        cold_start_bytes_per_s,
        max_burst_datagrams,
    );

    let mut adapted = if rate_plan.cold_start {
        config.clone()
    } else {
        apply_quic_adaptive_block_plan(config.clone(), rate_plan.block)?
    };
    adapted.bwlimit_bps = Some(adaptive_raw_pacing_bytes_per_s(config, rate_plan));
    adapted.max_spray_symbols_per_flush = adapted
        .max_spray_symbols_per_flush
        .min(usize::try_from(rate_plan.max_burst_datagrams).unwrap_or(usize::MAX))
        .max(1);
    adapted.validate()?;

    let spray =
        quic_spray_pacing_decision_from_config_with_cpu(&adapted, path.clamped(), cpu_parallelism);

    Ok(QuicAdaptivePacingDecision {
        config: adapted,
        rate_plan,
        spray,
    })
}

fn adaptive_raw_pacing_bytes_per_s(
    config: &QuicConfig,
    rate_plan: QuicRateMatchedPacingPlan,
) -> u64 {
    let raw_bytes = rate_plan
        .raw_pacing_bits_per_s
        .saturating_add(7)
        .checked_div(8)
        .unwrap_or(1)
        .max(1);
    config
        .bwlimit_bps
        .map_or(raw_bytes, |cap| cap.max(1).min(raw_bytes))
}

const MIN_QUIC_SPRAY_PACING_RTT_S: f64 = 0.001;
const MAX_QUIC_SPRAY_PACING_RTT_S: f64 = 60.0;
const MIN_QUIC_SPRAY_RATE_BPS: u64 = 1;

/// Deterministic machine-responsiveness pressure sampled by the caller.
///
/// The transport does not read load average or CPU state itself; that would be
/// ambient authority and would make lab replay depend on the host. Operators or
/// future CLI wiring can feed normalized values in `[0, 1]`.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct QuicMachinePressure {
    /// CPU saturation pressure, where `0.0` is idle and `1.0` is saturated.
    pub cpu_pressure: f64,
    /// Load/backlog pressure, where `0.0` is healthy and `1.0` is saturated.
    pub load_pressure: f64,
}

impl QuicMachinePressure {
    #[must_use]
    fn clamped(self) -> Self {
        Self {
            cpu_pressure: clamp_unit_pressure(self.cpu_pressure),
            load_pressure: clamp_unit_pressure(self.load_pressure),
        }
    }

    #[must_use]
    fn max_pressure(self) -> f64 {
        self.cpu_pressure.max(self.load_pressure)
    }
}

/// Inputs for one QUIC symbol-spray pacing epoch.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct QuicSprayPacingInput {
    /// Latest QUIC recovery/congestion-control signals.
    pub path: QuicPathSignalSample,
    /// RaptorQ symbol payload bytes.
    pub symbol_size: u16,
    /// Maximum application DATAGRAM payload bytes.
    pub max_datagram_size: usize,
    /// Future Phase-D fan-out hint. Until multi-connection fan-out lands, this
    /// divides the per-connection budget so an N-way sender cannot multiply the
    /// aggregate offered load by N.
    pub datagram_fanout: usize,
    /// Optional user/operator bandwidth cap in bytes per second. J6 wires this
    /// from `--bwlimit`; C3 keeps it as a pure input.
    pub bandwidth_limit_bps: Option<u64>,
    /// Optional transport-selected path-rate cap in bytes per second.
    ///
    /// Unlike `bandwidth_limit_bps`, this is not an operator directive. It is
    /// the native QUIC sender's default rate-match guard for loss-visible
    /// paths, so the encrypted data plane does not spend AES-GCM on symbols far
    /// beyond the shaped link rate once congestion is observable.
    pub path_rate_limit_bps: Option<u64>,
    /// Loss fraction expected to be absorbed by RaptorQ repair before treating
    /// path loss as congestion.
    pub fec_loss_budget: f64,
    /// Caller-sampled host responsiveness pressure.
    pub machine_pressure: QuicMachinePressure,
    /// Hard burst ceiling before a flush/yield, independent of path cwnd.
    pub burst_cap_symbols: usize,
}

/// The limiting factor chosen for a QUIC spray pacing epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicSprayPacingLimiter {
    /// The adaptive/AIMD token-bucket rate is the active limiter.
    PacingRate,
    /// The fixed burst ceiling capped a larger cwnd/rate budget.
    BurstCap,
    /// Recent loss reduced the pacing rate.
    LossBackoff,
    /// Machine responsiveness pressure reduced the pacing rate.
    ResponsivenessBackoff,
    /// The optional bandwidth cap reduced the pacing rate.
    BandwidthLimit,
    /// The transport-selected path-rate cap reduced the default spray rate.
    PathRateMatch,
}

impl QuicSprayPacingLimiter {
    #[must_use]
    fn as_str(self) -> &'static str {
        match self {
            Self::PacingRate => "pacing_rate",
            Self::BurstCap => "burst_cap",
            Self::LossBackoff => "loss",
            Self::ResponsivenessBackoff => "responsiveness",
            Self::BandwidthLimit => "bandwidth_limit",
            Self::PathRateMatch => "path_rate_match",
        }
    }
}

/// Deterministic QUIC symbol-spray pacing decision for one epoch.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct QuicSprayPacingDecision {
    /// Maximum symbols queued before flushing the native QUIC data plane.
    pub max_burst_symbols: usize,
    /// Pause after each burst so the receiver and kernel socket drain.
    pub pause_after_burst: Duration,
    /// Effective pacing rate in bytes per second after all caps/backoffs.
    pub pacing_rate_bps: u64,
    /// Raw cwnd converted to symbol slots.
    pub cwnd_symbols: usize,
    /// Per-fan-out share of the cwnd symbol budget.
    pub cwnd_share_symbols: usize,
    /// Per-fan-out share of the configured token-bucket burst ceiling.
    pub burst_cap_share_symbols: usize,
    /// Loss multiplier applied to the token-bucket rate.
    pub loss_backoff: f64,
    /// Machine responsiveness multiplier applied to the rate.
    pub responsiveness_backoff: f64,
    /// Clamped RTT used for the rate calculation.
    pub path_rtt_s: f64,
    /// Clamped path cwnd bytes used for the rate calculation.
    pub path_cwnd_bytes: u64,
    /// Clamped recent loss rate used for the rate calculation.
    pub path_loss_rate: f64,
    /// FEC repair budget discounted before loss is treated as congestion.
    pub fec_loss_budget: f64,
    /// Path loss beyond the FEC budget that reduced the token-bucket rate.
    pub congestion_loss_rate: f64,
    /// Active limiting factor.
    pub limiter: QuicSprayPacingLimiter,
}

impl QuicSprayPacingDecision {
    /// Emit this pacing epoch as structured trace fields. This is intended to
    /// run once per symbol round, never per symbol.
    pub fn trace_epoch(&self, cx: &Cx, epoch: u64) {
        let epoch = epoch.to_string();
        let max_burst_symbols = self.max_burst_symbols.to_string();
        let pause_after_burst_micros = self.pause_after_burst.as_micros().to_string();
        let pacing_rate_bps = self.pacing_rate_bps.to_string();
        let cwnd_symbols = self.cwnd_symbols.to_string();
        let loss_backoff = format!("{:.6}", self.loss_backoff);
        let responsiveness_backoff = format!("{:.6}", self.responsiveness_backoff);
        let path_rtt_s = format!("{:.6}", self.path_rtt_s);
        let path_cwnd_bytes = self.path_cwnd_bytes.to_string();
        let path_loss_rate = format!("{:.6}", self.path_loss_rate);
        let congestion_loss_rate = format!("{:.6}", self.congestion_loss_rate);

        // Correlation-safe field budget: <=12 explicit fields
        // (br-asupersync-an0t8o) so prioritized task/region/span ids never
        // evict the leading fields. Dropped: "transport" (in the message
        // name), the per-fanout shares (cwnd_share_symbols,
        // burst_cap_share_symbols — derivable from cwnd_symbols and the
        // config burst cap), and fec_loss_budget (config-derived; its effect
        // is already visible in congestion_loss_rate vs path_loss_rate).
        cx.trace_with_fields(
            "atp_quic.spray.pacing_epoch",
            &[
                ("epoch", &epoch),
                ("max_burst_symbols", &max_burst_symbols),
                ("pause_after_burst_micros", &pause_after_burst_micros),
                ("pacing_rate_bps", &pacing_rate_bps),
                ("cwnd_symbols", &cwnd_symbols),
                ("loss_backoff", &loss_backoff),
                ("responsiveness_backoff", &responsiveness_backoff),
                ("path_rtt_s", &path_rtt_s),
                ("path_cwnd_bytes", &path_cwnd_bytes),
                ("path_loss_rate", &path_loss_rate),
                ("congestion_loss_rate", &congestion_loss_rate),
                ("limiter", self.limiter.as_str()),
            ],
        );
    }
}

/// Convert QUIC path signals and caller-supplied caps into one bounded spray
/// pacing decision.
#[must_use]
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)]
pub fn quic_spray_pacing_decision(input: QuicSprayPacingInput) -> QuicSprayPacingDecision {
    let path = input.path.clamped();
    let machine_pressure = input.machine_pressure.clamped();
    let symbol_payload = usize::from(input.symbol_size.max(1))
        .saturating_add(AUTH_ENVELOPE_HEADER_LEN)
        .min(input.max_datagram_size.max(1));
    let fanout = input.datagram_fanout.max(1);
    let burst_cap = input.burst_cap_symbols.max(1);
    let rtt_s = path
        .smoothed_rtt_s
        .clamp(MIN_QUIC_SPRAY_PACING_RTT_S, MAX_QUIC_SPRAY_PACING_RTT_S);

    let cwnd_symbols_u64 = path
        .congestion_window_bytes
        .checked_div(u64::try_from(symbol_payload).unwrap_or(u64::MAX).max(1))
        .unwrap_or(0)
        .max(1);
    let cwnd_symbols = usize::try_from(cwnd_symbols_u64).unwrap_or(usize::MAX);
    let cwnd_share_symbols = (cwnd_symbols / fanout).max(1);
    let burst_cap_share_symbols = (burst_cap / fanout).max(1);

    let operator_cap = input
        .bandwidth_limit_bps
        .map(|cap| cap.max(MIN_QUIC_SPRAY_RATE_BPS));
    let path_rate_cap = input
        .path_rate_limit_bps
        .map(|cap| cap.max(MIN_QUIC_SPRAY_RATE_BPS));
    let rate_cap = match (operator_cap, path_rate_cap) {
        (Some(operator), Some(path)) => Some(operator.min(path)),
        (Some(operator), None) => Some(operator),
        (None, Some(path)) => Some(path),
        (None, None) => None,
    };
    let base_rate = rate_cap.unwrap_or(QUIC_DEFAULT_COLD_START_PACING_BYTES_PER_S as u64) as f64
        / fanout as f64;
    let fec_loss_budget = if input.fec_loss_budget.is_finite() {
        input.fec_loss_budget.clamp(0.0, 0.90)
    } else {
        0.0
    };
    let congestion_loss_rate = (path.loss_rate - fec_loss_budget).max(0.0).clamp(0.0, 0.90);
    let loss_backoff = (1.0 - (2.0 * congestion_loss_rate)).clamp(QUIC_SPRAY_MIN_BACKOFF, 1.0);
    let pressure = machine_pressure.max_pressure();
    let responsiveness_backoff = (1.0 - (0.75 * pressure)).clamp(QUIC_SPRAY_MIN_BACKOFF, 1.0);
    let rate = base_rate * loss_backoff * responsiveness_backoff;

    let rate = if rate.is_finite() && rate > 0.0 {
        rate
    } else {
        MIN_QUIC_SPRAY_RATE_BPS as f64
    };
    let pacing_rate_bps = rate.ceil().max(MIN_QUIC_SPRAY_RATE_BPS as f64) as u64;
    let burst_by_rate = ((rate * rtt_s * QUIC_SPRAY_BURST_RTT_FRACTION) / symbol_payload as f64)
        .ceil()
        .max(1.0) as usize;
    let max_burst_symbols = burst_by_rate.min(burst_cap_share_symbols).max(1);
    let burst_bytes = u64::try_from(max_burst_symbols)
        .unwrap_or(u64::MAX)
        .saturating_mul(u64::try_from(symbol_payload).unwrap_or(u64::MAX).max(1));
    let pause_after_burst = pacing_pause_for_bytes(burst_bytes, pacing_rate_bps);

    let operator_limited = operator_cap.is_some_and(|cap| rate_cap == Some(cap));
    let path_rate_limited = path_rate_cap.is_some_and(|cap| rate_cap == Some(cap));
    let limiter = if congestion_loss_rate > 0.0 {
        QuicSprayPacingLimiter::LossBackoff
    } else if pressure > 0.0 {
        QuicSprayPacingLimiter::ResponsivenessBackoff
    } else if operator_limited {
        QuicSprayPacingLimiter::BandwidthLimit
    } else if path_rate_limited {
        QuicSprayPacingLimiter::PathRateMatch
    } else if burst_cap_share_symbols < burst_by_rate {
        QuicSprayPacingLimiter::BurstCap
    } else {
        QuicSprayPacingLimiter::PacingRate
    };

    QuicSprayPacingDecision {
        max_burst_symbols,
        pause_after_burst,
        pacing_rate_bps,
        cwnd_symbols,
        cwnd_share_symbols,
        burst_cap_share_symbols,
        loss_backoff,
        responsiveness_backoff,
        path_rtt_s: rtt_s,
        path_cwnd_bytes: path.congestion_window_bytes,
        path_loss_rate: path.loss_rate,
        fec_loss_budget,
        congestion_loss_rate,
        limiter,
    }
}

/// Build a C3 pacing decision from a transfer config and C2 path signal.
#[must_use]
pub fn quic_spray_pacing_decision_from_config(
    config: &QuicConfig,
    path: QuicPathSignalSample,
) -> QuicSprayPacingDecision {
    quic_spray_pacing_decision_from_config_with_cpu(config, path, usize::MAX)
}

/// Build a C3/D1 pacing decision with an explicit CPU parallelism bound.
#[must_use]
pub fn quic_spray_pacing_decision_from_config_with_cpu(
    config: &QuicConfig,
    path: QuicPathSignalSample,
    cpu_parallelism: usize,
) -> QuicSprayPacingDecision {
    let path = quic_loss_seeded_path_signal(config, path);
    quic_spray_pacing_decision(QuicSprayPacingInput {
        path,
        symbol_size: config.symbol_size,
        max_datagram_size: config.max_datagram_size,
        datagram_fanout: quic_effective_datagram_fanout(config, cpu_parallelism),
        bandwidth_limit_bps: config.bwlimit_bps,
        path_rate_limit_bps: quic_default_path_rate_limit_bps(&path),
        fec_loss_budget: (quic_round0_loss_target_repair_overhead(config) - 1.0).max(0.0),
        machine_pressure: QuicMachinePressure {
            cpu_pressure: config.responsiveness_pressure,
            load_pressure: 0.0,
        },
        burst_cap_symbols: config.max_spray_symbols_per_flush,
    })
}

fn quic_loss_seeded_path_signal(
    config: &QuicConfig,
    path: QuicPathSignalSample,
) -> QuicPathSignalSample {
    let mut path = path.clamped();
    if config.round0_loss_target.is_finite() {
        path.loss_rate = path
            .loss_rate
            .max(config.round0_loss_target.clamp(0.0, 0.90));
    }
    path.clamped()
}

fn quic_loss_matched_pacing_cap_bps(loss_rate: f64) -> Option<u64> {
    if loss_rate > QUIC_RATE_MATCHED_BROKEN_LINK_LOSS_MIN {
        Some(QUIC_RATE_MATCHED_BROKEN_LINK_PACING_BPS)
    } else if loss_rate >= QUIC_RATE_MATCHED_BAD_LINK_LOSS_MIN {
        Some(QUIC_RATE_MATCHED_BAD_LINK_PACING_BPS)
    } else {
        None
    }
}

fn quic_default_path_rate_limit_bps(path: &QuicPathSignalSample) -> Option<u64> {
    quic_loss_matched_pacing_cap_bps(path.loss_rate)
}

#[cfg_attr(not(feature = "tls"), allow(dead_code))]
pub(crate) fn quic_loss_target_pacing_cap_bps(config: &QuicConfig) -> Option<u64> {
    let loss = config.round0_loss_target;
    if !loss.is_finite() {
        return None;
    }
    quic_loss_matched_pacing_cap_bps(loss)
}

#[cfg_attr(not(feature = "tls"), allow(dead_code))]
pub(crate) fn quic_aimd_loss_decrease_threshold(config: &QuicConfig) -> f64 {
    let expected_loss = if quic_loss_target_pacing_cap_bps(config).is_some() {
        config.round0_loss_target
    } else {
        0.0
    };
    (expected_loss + QUIC_AIMD_LOSS_TARGET_DECREASE_MARGIN)
        .max(QUIC_AIMD_LOSS_DECREASE_THRESHOLD)
        .clamp(0.0, 0.90)
}

fn quic_fixed_block_k(config: &QuicConfig) -> u32 {
    let symbol_size = usize::from(config.symbol_size.max(1));
    let k = config.max_block_size.div_ceil(symbol_size).max(1);
    u32::try_from(k).unwrap_or(u32::MAX)
}

fn quic_repair_pacing_cap_bps(
    config: &QuicConfig,
    round_loss_fraction: Option<f64>,
) -> Option<u64> {
    [
        config.bwlimit_bps,
        quic_loss_target_pacing_cap_bps(config),
        round_loss_fraction
            .filter(|loss| loss.is_finite())
            .and_then(quic_loss_matched_pacing_cap_bps),
    ]
    .into_iter()
    .flatten()
    .min()
}

fn quic_repair_symbol_round_cap(config: &QuicConfig, round_loss_fraction: Option<f64>) -> usize {
    let Some(rate_bps) = quic_repair_pacing_cap_bps(config, round_loss_fraction) else {
        return MAX_REPAIR_SYMBOLS_PER_FEEDBACK_ROUND;
    };
    let symbol_size = u64::from(config.symbol_size.max(1));
    let window_bytes = rate_bps.saturating_mul(QUIC_REPAIR_REQUEST_PACING_WINDOW_MILLIS) / 1_000;
    let window_symbols = usize::try_from(window_bytes / symbol_size).unwrap_or(usize::MAX);
    window_symbols
        .max(QUIC_REPAIR_REQUEST_MIN_SYMBOLS_PER_ROUND)
        .min(MAX_REPAIR_SYMBOLS_PER_FEEDBACK_ROUND)
}

fn quic_round0_loss_target_repair_enabled(config: &QuicConfig) -> bool {
    let loss = config.round0_loss_target;
    loss.is_finite() && loss >= QUIC_ROUND0_TARGET_LOSS_ENABLE_MIN
}

fn quic_round0_loss_target_loss_bar(config: &QuicConfig) -> f64 {
    (config.round0_loss_target * (1.0 + QUIC_ROUND0_TARGET_LOSS_MARGIN_FRACTION)
        + QUIC_ROUND0_TARGET_LOSS_MARGIN_MIN)
        .clamp(0.0, QUIC_ROUND0_TARGET_REPAIR_MAX_OVERHEAD)
}

fn quic_round0_loss_target_repair_overhead(config: &QuicConfig) -> f64 {
    if !quic_round0_loss_target_repair_enabled(config) {
        return config.repair_overhead.max(1.0);
    }
    let loss_bar = quic_round0_loss_target_loss_bar(config);
    let overhead = crate::net::atp::transport_rq::adaptive::decode_repair_overhead_for_target(
        quic_fixed_block_k(config),
        loss_bar,
        QUIC_ROUND0_TARGET_REPAIR_ALPHA,
        QUIC_ROUND0_TARGET_REPAIR_MAX_OVERHEAD,
    )
    .min(QUIC_ROUND0_TARGET_REPAIR_MAX_OVERHEAD);
    config.repair_overhead.max(1.0 + overhead)
}

/// Bound the configured QUIC DATAGRAM fan-out by connection and CPU capacity.
///
/// `QuicConfig::validate` rejects zero fan-out, but this helper is deliberately
/// total so callers that have not validated yet still get one usable lane
/// instead of a divide-by-zero hazard.
#[must_use]
pub fn quic_effective_datagram_fanout(config: &QuicConfig, cpu_parallelism: usize) -> usize {
    config
        .datagram_fanout
        .max(1)
        .min(config.max_active_connections.max(1))
        .min(cpu_parallelism.max(1))
}

/// One RaptorQ source block that is ready for QUIC fan-out scheduling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuicFanoutBlock {
    /// Manifest entry index.
    pub entry: u32,
    /// RaptorQ source block number within the entry.
    pub sbn: u8,
    /// Number of source or repair symbols to spray for this block.
    pub symbols: usize,
}

/// One scheduled symbol slot on a bounded QUIC fan-out lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuicFanoutSymbolSlot {
    /// Zero-based fan-out lane / connection index.
    pub connection: usize,
    /// Manifest entry index.
    pub entry: u32,
    /// RaptorQ source block number within the entry.
    pub sbn: u8,
    /// Zero-based symbol ordinal within this block's scheduled run.
    pub symbol_index_in_block: usize,
}

/// Deterministic D1 fan-out plan for one symbol-spray epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicFanoutSprayPlan {
    /// Bounded connection count used for this plan.
    pub connection_count: usize,
    /// Ordered symbol slots to spray.
    pub slots: Vec<QuicFanoutSymbolSlot>,
    /// Per-connection symbol counts for tracing and assertions.
    pub per_connection_symbols: Vec<u64>,
    /// Total symbols covered by the plan.
    pub total_symbols: u64,
}

impl QuicFanoutSprayPlan {
    /// Whether this epoch has no positive-symbol work.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }
}

/// Binding from a logical fan-out lane to a physical QUIC connection.
///
/// A migrated path changes the physical connection/generation, not the logical
/// symbol lane. Symbols keep their original object/block/ESI identity, so a
/// migration cannot make the receiver treat retransmitted symbols as new data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuicFanoutLaneBinding {
    /// Logical lane index emitted by [`QuicBlockInterleavingScheduler`].
    pub logical_connection: usize,
    /// Physical connection index currently serving this lane.
    pub physical_connection: usize,
    /// Monotonic migration generation for this lane.
    pub migration_generation: u64,
}

impl QuicFanoutLaneBinding {
    /// Identity binding for a non-migrated lane.
    #[must_use]
    pub const fn identity(connection: usize) -> Self {
        Self {
            logical_connection: connection,
            physical_connection: connection,
            migration_generation: 0,
        }
    }
}

/// Symbol work assigned to one logical fan-out lane / physical connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicFanoutConnectionBatch {
    /// Logical lane index.
    pub logical_connection: usize,
    /// Physical QUIC connection currently carrying this lane.
    pub physical_connection: usize,
    /// Migration generation for replay/trace assertions.
    pub migration_generation: u64,
    /// Ordered symbol slots for this connection.
    pub slots: Vec<QuicFanoutSymbolSlot>,
}

impl QuicFanoutConnectionBatch {
    /// Number of symbols assigned to this connection in the epoch.
    #[must_use]
    pub fn symbol_count(&self) -> usize {
        self.slots.len()
    }
}

/// Per-connection dispatch view of a fan-out spray epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicFanoutDispatchPlan {
    /// Bounded logical connection count used for this plan.
    pub connection_count: usize,
    /// One deterministic batch per logical connection.
    pub batches: Vec<QuicFanoutConnectionBatch>,
    /// Total symbols covered by the plan.
    pub total_symbols: u64,
}

impl QuicFanoutDispatchPlan {
    /// Whether this epoch has no positive-symbol work.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.total_symbols == 0
    }
}

/// Deterministic block-interleaving scheduler for D1 QUIC fan-out.
///
/// The scheduler streams one symbol slot at a time. It round-robins across
/// blocks first, then across connection lanes, so a large block cannot starve
/// other pending blocks and each configured lane receives work when enough
/// symbols exist.
#[derive(Debug, Clone)]
pub struct QuicBlockInterleavingScheduler {
    blocks: Vec<QuicFanoutBlock>,
    remaining: Vec<usize>,
    emitted: Vec<usize>,
    next_block: usize,
    next_connection: usize,
    connection_count: usize,
}

impl QuicBlockInterleavingScheduler {
    /// Build a scheduler over the non-empty block work items.
    #[must_use]
    pub fn new(blocks: &[QuicFanoutBlock], connection_count: usize) -> Self {
        let blocks = blocks
            .iter()
            .copied()
            .filter(|block| block.symbols > 0)
            .collect::<Vec<_>>();
        let remaining = blocks.iter().map(|block| block.symbols).collect::<Vec<_>>();
        let emitted = vec![0; blocks.len()];
        Self {
            blocks,
            remaining,
            emitted,
            next_block: 0,
            next_connection: 0,
            connection_count: connection_count.max(1),
        }
    }

    /// Number of fan-out lanes this scheduler can feed.
    #[must_use]
    pub fn connection_count(&self) -> usize {
        self.connection_count
    }

    /// Whether no positive-symbol block work was supplied.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }
}

impl Iterator for QuicBlockInterleavingScheduler {
    type Item = QuicFanoutSymbolSlot;

    fn next(&mut self) -> Option<Self::Item> {
        if self.blocks.is_empty() {
            return None;
        }

        for _ in 0..self.blocks.len() {
            let block_index = self.next_block;
            self.next_block = (self.next_block + 1) % self.blocks.len();
            if self.remaining[block_index] == 0 {
                continue;
            }

            let block = self.blocks[block_index];
            let symbol_index_in_block = self.emitted[block_index];
            self.remaining[block_index] -= 1;
            self.emitted[block_index] += 1;

            let connection = self.next_connection;
            self.next_connection = (self.next_connection + 1) % self.connection_count;

            return Some(QuicFanoutSymbolSlot {
                connection,
                entry: block.entry,
                sbn: block.sbn,
                symbol_index_in_block,
            });
        }

        None
    }
}

/// Plan one bounded QUIC fan-out spray epoch from pending block work.
#[must_use]
pub fn quic_plan_fanout_spray(
    config: &QuicConfig,
    cpu_parallelism: usize,
    blocks: &[QuicFanoutBlock],
) -> QuicFanoutSprayPlan {
    let connection_count = quic_effective_datagram_fanout(config, cpu_parallelism);
    let mut per_connection_symbols = vec![0u64; connection_count];
    let mut slots = Vec::new();

    for slot in QuicBlockInterleavingScheduler::new(blocks, connection_count) {
        if let Some(symbols) = per_connection_symbols.get_mut(slot.connection) {
            *symbols = symbols.saturating_add(1);
        }
        slots.push(slot);
    }

    let total_symbols = slots.len().try_into().unwrap_or(u64::MAX);
    QuicFanoutSprayPlan {
        connection_count,
        slots,
        per_connection_symbols,
        total_symbols,
    }
}

/// Plan a D1/D2 per-connection dispatch epoch with optional migrated lane
/// bindings.
///
/// `lane_bindings` may remap a logical fan-out lane to a new physical QUIC
/// connection after migration. Out-of-range bindings are ignored, so stale
/// migration receipts cannot create extra lanes or bypass the configured fan-out
/// bound.
#[must_use]
pub fn quic_plan_fanout_dispatch(
    config: &QuicConfig,
    cpu_parallelism: usize,
    blocks: &[QuicFanoutBlock],
    lane_bindings: &[QuicFanoutLaneBinding],
) -> QuicFanoutDispatchPlan {
    let spray = quic_plan_fanout_spray(config, cpu_parallelism, blocks);
    let mut bindings = (0..spray.connection_count)
        .map(QuicFanoutLaneBinding::identity)
        .collect::<Vec<_>>();
    for binding in lane_bindings {
        if let Some(slot) = bindings.get_mut(binding.logical_connection) {
            *slot = *binding;
        }
    }

    let mut batches = bindings
        .iter()
        .map(|binding| QuicFanoutConnectionBatch {
            logical_connection: binding.logical_connection,
            physical_connection: binding.physical_connection,
            migration_generation: binding.migration_generation,
            slots: Vec::new(),
        })
        .collect::<Vec<_>>();
    for slot in spray.slots {
        if let Some(batch) = batches.get_mut(slot.connection) {
            batch.slots.push(slot);
        }
    }

    QuicFanoutDispatchPlan {
        connection_count: spray.connection_count,
        batches,
        total_symbols: spray.total_symbols,
    }
}

/// Derive the initial source+proactive-repair symbol work from a transfer
/// manifest.
///
/// This is the Phase-D bridge between the source preflight and the fan-out
/// scheduler: it turns the effective per-entry block geometry into the exact
/// number of symbol slots the round-0 spray will offer, without reading source
/// bytes or changing the wire format.
pub fn quic_initial_fanout_blocks_for_manifest(
    manifest: &TransferManifest,
    config: &QuicConfig,
) -> Result<Vec<QuicFanoutBlock>, QuicTransportError> {
    config.validate()?;
    let symbol_size = usize::from(config.symbol_size.max(1));
    let max_block = config.max_block_size.max(1);
    let mut blocks = Vec::new();
    for entry in &manifest.entries {
        let block_count = block_count_for_len(entry.size, config)?;
        for block_index in 0..block_count {
            let block_start = u64::try_from(block_index)
                .unwrap_or(u64::MAX)
                .saturating_mul(u64::try_from(max_block).unwrap_or(u64::MAX));
            let block_len = usize::try_from((entry.size - block_start).min(max_block as u64))
                .unwrap_or(usize::MAX);
            let source_symbols = block_len.div_ceil(symbol_size).max(1);
            let repair_symbols = initial_repair_per_block(block_len, config);
            blocks.push(QuicFanoutBlock {
                entry: entry.index,
                sbn: u8::try_from(block_index).map_err(|_| QuicTransportError::TooLarge {
                    size: entry.size,
                    max: u64::try_from(max_block)
                        .unwrap_or(u64::MAX)
                        .saturating_mul(u64::from(u8::MAX) + 1),
                })?,
                symbols: source_symbols.saturating_add(repair_symbols),
            });
        }
    }
    Ok(blocks)
}

/// Plan the round-0 QUIC fan-out dispatch from a manifest and effective config.
pub fn quic_plan_initial_fanout_dispatch(
    config: &QuicConfig,
    cpu_parallelism: usize,
    manifest: &TransferManifest,
    lane_bindings: &[QuicFanoutLaneBinding],
) -> Result<QuicFanoutDispatchPlan, QuicTransportError> {
    let blocks = quic_initial_fanout_blocks_for_manifest(manifest, config)?;
    Ok(quic_plan_fanout_dispatch(
        config,
        cpu_parallelism,
        &blocks,
        lane_bindings,
    ))
}

/// Emit stable per-connection spray counts for D1 fan-out diagnostics.
pub fn trace_quic_fanout_spray_counts(cx: &Cx, round: u64, counts: &[u64]) {
    let round = round.to_string();
    let connections = counts.len().to_string();
    for (connection, symbols) in counts.iter().enumerate() {
        let connection = connection.to_string();
        let symbols = symbols.to_string();
        cx.trace_with_fields(
            "atp_quic.spray.fanout_connection",
            &[
                ("transport", "quic"),
                ("round", &round),
                ("connection", &connection),
                ("connections", &connections),
                ("symbols", &symbols),
            ],
        );
    }
}

/// Emit stable per-lane dispatch fields for a planned fan-out spray epoch.
pub fn trace_quic_fanout_dispatch_plan(cx: &Cx, round: u64, plan: &QuicFanoutDispatchPlan) {
    let round = round.to_string();
    let connections = plan.connection_count.to_string();
    let total_symbols = plan.total_symbols.to_string();
    for batch in &plan.batches {
        let logical_connection = batch.logical_connection.to_string();
        let physical_connection = batch.physical_connection.to_string();
        let migration_generation = batch.migration_generation.to_string();
        let symbols = batch.symbol_count().to_string();
        cx.trace_with_fields(
            "atp_quic.spray.fanout_dispatch",
            &[
                ("transport", "quic"),
                ("round", &round),
                ("logical_connection", &logical_connection),
                ("physical_connection", &physical_connection),
                ("migration_generation", &migration_generation),
                ("connections", &connections),
                ("symbols", &symbols),
                ("total_symbols", &total_symbols),
            ],
        );
    }
}

fn clamp_unit_pressure(value: f64) -> f64 {
    if value.is_nan() {
        0.0
    } else {
        value.clamp(0.0, 1.0)
    }
}

fn pacing_pause_for_bytes(bytes: u64, rate_bps: u64) -> Duration {
    duration_from_secs_clamped(bytes.max(1) as f64 / rate_bps.max(1) as f64)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct QuicRound0CleanPacingRamp {
    sent_datagrams: u64,
    next_step_bytes: u64,
    burst_cap_symbols: usize,
    max_rate_bps: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct QuicRound0CleanPacingRampReport {
    pub(crate) sent_datagrams: u64,
    pub(crate) sent_bytes: u64,
    pub(crate) old_rate_bps: u64,
    pub(crate) new_rate_bps: u64,
    pub(crate) next_step_bytes: u64,
    pub(crate) max_rate_bps: u64,
}

#[cfg_attr(not(feature = "tls"), allow(dead_code))]
impl QuicRound0CleanPacingRamp {
    #[cfg(test)]
    pub(crate) fn new(max_rate_bps: u64) -> Self {
        Self::new_with_burst_cap(max_rate_bps, usize::MAX)
    }

    pub(crate) fn new_with_burst_cap(max_rate_bps: u64, burst_cap_symbols: usize) -> Self {
        Self {
            sent_datagrams: 0,
            next_step_bytes: QUIC_ROUND0_CLEAN_RAMP_STEP_BYTES,
            burst_cap_symbols: burst_cap_symbols.max(1),
            max_rate_bps: max_rate_bps.clamp(
                QUIC_AIMD_MIN_RATE_BPS,
                QUIC_ROUND0_CLEAN_RAMP_MAX_PACING_BPS,
            ),
        }
    }

    pub(crate) fn observe_datagram(
        &mut self,
        pacing: &mut QuicSprayPacingDecision,
        datagram_frame_bytes: usize,
    ) -> Option<QuicRound0CleanPacingRampReport> {
        self.sent_datagrams = self.sent_datagrams.saturating_add(1);
        let frame_bytes = u64::try_from(datagram_frame_bytes.max(1)).unwrap_or(u64::MAX);
        let sent_bytes = self.sent_datagrams.saturating_mul(frame_bytes);
        let old_rate = pacing.pacing_rate_bps;
        let mut changed = false;
        while sent_bytes >= self.next_step_bytes && pacing.pacing_rate_bps < self.max_rate_bps {
            let current = pacing.pacing_rate_bps;
            let next = current
                .saturating_add(QUIC_ROUND0_CLEAN_RAMP_ADD_BYTES_PER_S)
                .clamp(QUIC_AIMD_MIN_RATE_BPS, self.max_rate_bps);
            if next == current {
                break;
            }
            pacing.pacing_rate_bps = next;
            update_quic_pacing_pause(pacing, datagram_frame_bytes, self.burst_cap_symbols);
            self.next_step_bytes = self
                .next_step_bytes
                .saturating_add(QUIC_ROUND0_CLEAN_RAMP_STEP_BYTES);
            changed = true;
        }
        changed.then_some(QuicRound0CleanPacingRampReport {
            sent_datagrams: self.sent_datagrams,
            sent_bytes,
            old_rate_bps: old_rate,
            new_rate_bps: pacing.pacing_rate_bps,
            next_step_bytes: self.next_step_bytes,
            max_rate_bps: self.max_rate_bps,
        })
    }
}

pub(crate) fn quic_round0_clean_ramp_max_pacing_bps(pacing: &QuicSprayPacingDecision) -> u64 {
    match pacing.limiter {
        QuicSprayPacingLimiter::BandwidthLimit => pacing.pacing_rate_bps,
        _ => QUIC_ROUND0_CLEAN_RAMP_MAX_PACING_BPS,
    }
}

pub(crate) fn quic_round0_clean_ramp_enabled(
    config: &QuicConfig,
    pacing: &QuicSprayPacingDecision,
    with_source: bool,
) -> bool {
    let max_pacing_bps = quic_round0_clean_ramp_max_pacing_bps(pacing);
    with_source
        && quic_round0_datagram_ramp_enabled(config, pacing)
        && pacing.pacing_rate_bps < max_pacing_bps
}

fn quic_clean_source_base_enabled(config: &QuicConfig) -> bool {
    quic_source_stream_base_enabled(config)
        && config.repair_overhead.is_finite()
        && config.repair_overhead <= QUIC_ROUND0_CLEAN_RAMP_MAX_REPAIR_OVERHEAD
}

fn quic_source_stream_base_enabled(config: &QuicConfig) -> bool {
    config.debug_drop_one_in == 0
        && config.bwlimit_bps.is_none()
        && quic_effective_datagram_fanout(config, usize::MAX) == 1
}

fn quic_round0_datagram_ramp_enabled(
    config: &QuicConfig,
    pacing: &QuicSprayPacingDecision,
) -> bool {
    quic_clean_source_base_enabled(config)
        && (0.0..=f64::EPSILON).contains(&config.round0_loss_target)
        && pacing.path_loss_rate <= f64::EPSILON
}

// Only non-test caller (`promote_source_stream_pacing` in `native_link`) is
// compiled out in builds that omit the QUIC pacing path, so `deny(dead_code)`
// re-exposes this gate the same way it did the loss-target const above.
#[allow(dead_code)]
pub(crate) fn quic_near_clean_source_stream_enabled(
    config: &QuicConfig,
    pacing: &QuicSprayPacingDecision,
) -> bool {
    quic_source_stream_base_enabled(config)
        && (0.0..=QUIC_NEAR_CLEAN_SOURCE_STREAM_MAX_LOSS_TARGET + f64::EPSILON)
            .contains(&config.round0_loss_target)
        && (0.0..=QUIC_NEAR_CLEAN_SOURCE_STREAM_MAX_LOSS_TARGET + f64::EPSILON)
            .contains(&pacing.path_loss_rate)
}

pub(crate) fn quic_reliable_source_stream_loss_enabled(
    config: &QuicConfig,
    pacing: &QuicSprayPacingDecision,
) -> bool {
    quic_source_stream_base_enabled(config)
        && (0.0..=QUIC_RELIABLE_SOURCE_STREAM_MAX_LOSS_TARGET + f64::EPSILON)
            .contains(&config.round0_loss_target)
        && (0.0..=QUIC_RELIABLE_SOURCE_STREAM_MAX_LOSS_TARGET + f64::EPSILON)
            .contains(&pacing.path_loss_rate)
}

#[cfg(feature = "tls")]
pub(crate) fn quic_native_stream_flow_limit(config: &QuicConfig) -> u64 {
    config
        .max_transfer_bytes
        .min(QUIC_RELIABLE_SOURCE_STREAM_MAX_BYTES)
        .saturating_add(QUIC_NATIVE_STREAM_FLOW_HEADROOM_BYTES)
        .max(QUIC_NATIVE_STREAM_FLOW_MIN_BYTES)
}

pub(crate) fn quic_reliable_source_stream_eligible(
    total_bytes: u64,
    config: &QuicConfig,
    pacing: &QuicSprayPacingDecision,
) -> bool {
    total_bytes > 0
        && total_bytes <= config.max_transfer_bytes
        && total_bytes <= QUIC_RELIABLE_SOURCE_STREAM_MAX_BYTES
        && matches!(
            config.symbol_auth_mode(),
            QuicSymbolAuthMode::TransportAuthenticated
        )
        && quic_reliable_source_stream_loss_enabled(config, pacing)
}

fn quic_source_stream_enabled(
    total_bytes: u64,
    config: &QuicConfig,
    conn: &QuicConnection,
) -> bool {
    let pacing =
        quic_spray_pacing_decision_from_config(config, quic_path_signal_from_connection(conn));
    quic_reliable_source_stream_eligible(total_bytes, config, &pacing)
}

fn update_quic_pacing_pause(
    pacing: &mut QuicSprayPacingDecision,
    datagram_frame_bytes: usize,
    burst_cap_symbols: usize,
) {
    let frame_bytes = u64::try_from(datagram_frame_bytes.max(1)).unwrap_or(u64::MAX);
    let burst_by_rate =
        ((pacing.pacing_rate_bps.max(1) as f64 * pacing.path_rtt_s * QUIC_SPRAY_BURST_RTT_FRACTION)
            / frame_bytes.max(1) as f64)
            .ceil()
            .max(1.0) as usize;
    pacing.max_burst_symbols = burst_by_rate
        .min(pacing.burst_cap_share_symbols)
        .min(burst_cap_symbols.max(1))
        .max(1);
    let burst_bytes = u64::try_from(pacing.max_burst_symbols.max(1))
        .unwrap_or(u64::MAX)
        .saturating_mul(frame_bytes);
    pacing.pause_after_burst = pacing_pause_for_bytes(burst_bytes, pacing.pacing_rate_bps);
}

struct QuicSymbolPacer {
    decision: QuicSprayPacingDecision,
    round0_ramp: Option<QuicRound0CleanPacingRamp>,
    datagram_frame_bytes: usize,
    sent_since_pause: usize,
    epoch: u64,
}

impl QuicSymbolPacer {
    fn from_connection(config: &QuicConfig, connection: &QuicConnection) -> Self {
        Self::from_connection_for_round(config, connection, false)
    }

    fn from_connection_for_round(
        config: &QuicConfig,
        connection: &QuicConnection,
        with_source: bool,
    ) -> Self {
        Self::new(
            config,
            quic_spray_pacing_decision_from_config(
                config,
                quic_path_signal_from_connection(connection),
            ),
            with_source,
        )
    }

    fn from_native_connection(config: &QuicConfig, connection: &NativeQuicConnection) -> Self {
        Self::from_native_connection_for_round(config, connection, false)
    }

    fn from_native_connection_for_round(
        config: &QuicConfig,
        connection: &NativeQuicConnection,
        with_source: bool,
    ) -> Self {
        Self::new(
            config,
            quic_spray_pacing_decision_from_config(
                config,
                quic_path_signal_from_native_connection(connection),
            ),
            with_source,
        )
    }

    fn new(config: &QuicConfig, decision: QuicSprayPacingDecision, with_source: bool) -> Self {
        let datagram_frame_bytes =
            usize::from(config.symbol_size.max(1)).saturating_add(AUTH_ENVELOPE_HEADER_LEN);
        let round0_ramp =
            quic_round0_clean_ramp_enabled(config, &decision, with_source).then(|| {
                QuicRound0CleanPacingRamp::new_with_burst_cap(
                    QUIC_ROUND0_CLEAN_RAMP_MAX_PACING_BPS,
                    config.max_spray_symbols_per_flush,
                )
            });
        if round0_ramp.is_some() {
            quic_rqtrace(format_args!(
                "sender-native: round0_clean_pacing_ramp enabled start_rate_Bps={} step_bytes={} max_rate_Bps={} datagram_bytes={} burst_symbols={}",
                decision.pacing_rate_bps,
                QUIC_ROUND0_CLEAN_RAMP_STEP_BYTES,
                QUIC_ROUND0_CLEAN_RAMP_MAX_PACING_BPS,
                datagram_frame_bytes,
                decision.max_burst_symbols,
            ));
        }
        Self {
            decision,
            round0_ramp,
            datagram_frame_bytes,
            sent_since_pause: 0,
            epoch: 0,
        }
    }

    async fn after_symbol_sent(&mut self, cx: &Cx) -> Result<(), QuicTransportError> {
        self.sent_since_pause = self.sent_since_pause.saturating_add(1);
        if let Some(ramp) = &mut self.round0_ramp {
            if let Some(report) =
                ramp.observe_datagram(&mut self.decision, self.datagram_frame_bytes)
            {
                quic_rqtrace(format_args!(
                    "sender-native: round0_clean_rate_ramp sent_datagrams={} sent_bytes={} old_rate_Bps={} new_rate_Bps={} next_step_bytes={} max_rate_Bps={}",
                    report.sent_datagrams,
                    report.sent_bytes,
                    report.old_rate_bps,
                    report.new_rate_bps,
                    report.next_step_bytes,
                    report.max_rate_bps,
                ));
            }
        }
        if self.sent_since_pause < self.decision.max_burst_symbols {
            return Ok(());
        }
        self.decision.trace_epoch(cx, self.epoch);
        self.epoch = self.epoch.saturating_add(1);
        self.sent_since_pause = 0;
        crate::time::sleep(cx.now(), self.decision.pause_after_burst).await;
        cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)
    }
}

/// Convert A6 connection path stats into the shared adaptive reward signal.
///
/// RTT is reported in seconds for the adaptive controller, with smoothed RTT
/// preferred and the latest RTT sample used while smoothing has not initialized.
#[must_use]
pub fn quic_path_signal_from_stats(stats: QuicPathStats) -> QuicPathSignalSample {
    QuicPathSignalSample {
        smoothed_rtt_s: rtt_micros_to_seconds(
            stats.smoothed_rtt_micros.or(stats.latest_rtt_micros),
        ),
        congestion_window_bytes: stats.congestion_window_bytes,
        loss_rate: stats.loss_rate,
    }
    .clamped()
}

/// Snapshot the high-level A6 connection API as an adaptive path signal.
#[must_use]
pub fn quic_path_signal_from_connection(connection: &QuicConnection) -> QuicPathSignalSample {
    quic_path_signal_from_stats(connection.path_stats())
}

/// Snapshot a native QUIC connection as an adaptive path signal.
#[must_use]
pub fn quic_path_signal_from_native_connection(
    connection: &NativeQuicConnection,
) -> QuicPathSignalSample {
    quic_path_signal_from_transport(connection.transport())
}

/// Snapshot the native transport recovery/CC state as an adaptive path signal.
#[must_use]
pub fn quic_path_signal_from_transport(transport: &QuicTransportMachine) -> QuicPathSignalSample {
    let rtt = transport.rtt();
    QuicPathSignalSample {
        smoothed_rtt_s: rtt_micros_to_seconds(
            rtt.smoothed_rtt_micros().or(rtt.latest_rtt_micros()),
        ),
        congestion_window_bytes: transport.congestion_window_bytes(),
        loss_rate: transport.packet_loss_rate(),
    }
    .clamped()
}

/// Convert ATP QUIC metrics snapshots into the shared adaptive reward signal.
#[must_use]
pub fn quic_path_signal_from_metrics(metrics: &AtpTransportMetrics) -> QuicPathSignalSample {
    QuicPathSignalSample {
        smoothed_rtt_s: rtt_micros_to_seconds(
            metrics.smoothed_rtt_micros.or(metrics.latest_rtt_micros),
        ),
        congestion_window_bytes: metrics.congestion_window_bytes,
        loss_rate: metrics.loss_rate,
    }
    .clamped()
}

/// Feed a measured QUIC block outcome plus A6 path stats into the adaptive
/// reward update.
pub fn observe_quic_adaptive_path_stats(
    controller: &mut QuicAdaptiveController,
    sent: u64,
    received: u64,
    wall_s: f64,
    useful_bytes: u64,
    symbol_size: u16,
    stats: QuicPathStats,
) {
    controller.observe_path_signals(
        sent,
        received,
        wall_s,
        useful_bytes,
        symbol_size,
        quic_path_signal_from_stats(stats),
    );
}

fn finite_positive_or(value: f64, fallback: f64) -> f64 {
    if value.is_finite() && value > 0.0 {
        value
    } else {
        fallback.max(1.0)
    }
}

fn duration_from_secs_clamped(seconds: f64) -> Duration {
    Duration::from_secs_f64(
        finite_positive_or(seconds, QUIC_SPRAY_MIN_PAUSE.as_secs_f64()).clamp(
            QUIC_SPRAY_MIN_PAUSE.as_secs_f64(),
            QUIC_SPRAY_MAX_PAUSE.as_secs_f64(),
        ),
    )
}

fn rtt_micros_to_seconds(rtt_micros: Option<u64>) -> f64 {
    rtt_micros.map_or(0.0, |rtt| rtt as f64 / 1_000_000.0)
}

/// Errors from the ATP-over-QUIC transport.
///
/// Mirrors [`transport_tcp::TransportError`] (so error handling is uniform
/// across transports) and adds [`QuicTransportError::Config`] for invalid
/// configuration, [`QuicTransportError::Quic`] for native QUIC failures, and
/// [`QuicTransportError::NotImplemented`] for the still-unwired scaffold ops.
///
/// [`transport_tcp::TransportError`]: crate::net::atp::transport_tcp::TransportError
#[derive(Debug, thiserror::Error)]
pub enum QuicTransportError {
    /// Network or local I/O failure.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// Frame codec error.
    #[error("frame error: {0}")]
    Frame(String),
    /// JSON (de)serialization error for a control frame.
    #[error("control frame decode error: {0}")]
    Control(String),
    /// The peer rejected the handshake.
    #[error("[ASUP-E802] handshake rejected by peer: {0}")]
    HandshakeRejected(String),
    /// An unexpected frame type arrived for the current protocol state.
    #[error("unexpected frame: got {got:?}, expected {expected}")]
    Unexpected {
        /// The frame type actually received.
        got: FrameType,
        /// A description of what was expected.
        expected: &'static str,
    },
    /// The transfer exceeded the configured size ceiling.
    #[error("transfer exceeds maximum size ({size} > {max} bytes)")]
    TooLarge {
        /// Declared or observed size.
        size: u64,
        /// Configured maximum.
        max: u64,
    },
    /// Integrity verification failed (SHA-256 or merkle-root mismatch).
    #[error("integrity verification failed: {0}")]
    Integrity(String),
    /// The fountain feedback loop exhausted its configured round budget.
    #[error(
        "[ASUP-E801] transfer did not converge after {rounds} feedback rounds ({pending} entries still incomplete); if accepted symbols do not advance decode rank, see [ASUP-E805]"
    )]
    NoConvergence {
        /// Feedback rounds attempted.
        rounds: u32,
        /// Entries still undecoded.
        pending: usize,
    },
    /// The source path was invalid (missing, unsupported type).
    #[error("invalid source path: {0}")]
    Source(String),
    /// The transport configuration was invalid.
    #[error("invalid transport configuration: {0}")]
    Config(String),
    /// A native QUIC endpoint/connection error.
    #[error("native QUIC error: {0}")]
    Quic(String),
    /// The transfer was cancelled via the capability context.
    #[error("transfer cancelled")]
    Cancelled,
    /// A transport operation exceeded its configured timeout.
    #[error("[ASUP-E804] transport timeout during {operation} after {timeout:?}")]
    Timeout {
        /// Operation that timed out.
        operation: &'static str,
        /// Configured timeout duration.
        timeout: Duration,
    },
    /// A transfer entry point that is not yet wired (B2/B3). Failing closed with
    /// this typed error is the scaffold's contract: never report fake success.
    #[error(
        "transport_quic operation '{operation}' is not yet wired (lands in {wired_by}); \
         failing closed instead of reporting fake success"
    )]
    NotImplemented {
        /// The unwired entry point.
        operation: &'static str,
        /// The bead that wires it.
        wired_by: &'static str,
    },
}

impl From<StreamingError> for QuicTransportError {
    fn from(err: StreamingError) -> Self {
        Self::Source(err.into_message())
    }
}

impl From<crate::net::quic_native::NativeQuicConnectionError> for QuicTransportError {
    fn from(err: crate::net::quic_native::NativeQuicConnectionError) -> Self {
        Self::Quic(err.to_string())
    }
}

impl From<ManagedEndpointError> for QuicTransportError {
    fn from(err: ManagedEndpointError) -> Self {
        match err {
            ManagedEndpointError::Cancelled => Self::Cancelled,
            other => Self::Quic(other.to_string()),
        }
    }
}

impl From<SymbolDatagramError> for QuicTransportError {
    fn from(err: SymbolDatagramError) -> Self {
        Self::Quic(err.to_string())
    }
}

// ─── Control-plane payloads (JSON over one QUIC stream) ─────────────────────

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct QuicHello {
    protocol: u32,
    role: String,
    peer_id: String,
    symbol_size: u16,
    max_block_size: u64,
    #[serde(default)]
    symbol_auth: bool,
    #[serde(default)]
    source_stream: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source_stream_id: Option<u64>,
    #[serde(default)]
    total_bytes: u64,
    /// Fresh sender challenge offered only for authenticated delta control.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    delta_transfer_nonce: Option<TransferNonce>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct QuicHelloAck {
    accepted: bool,
    peer_id: String,
    #[serde(default)]
    source_stream: bool,
    /// Bounded receive window (bytes) the receiver advertises for the paced
    /// source stream. A compliant sender installs this as its initial
    /// send-credit limit for that stream and then follows the receiver's
    /// MAX_STREAM_DATA advertisements, bounding un-read bytes in the
    /// receiver's reassembly buffer to roughly one window. `None` (older
    /// receivers) keeps the historic unbounded-credit behavior.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source_stream_recv_window: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    /// Echo of the sender's delta challenge when the receiver accepts delta.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    delta_transfer_nonce: Option<TransferNonce>,
    /// Fresh receiver challenge for cross-session replay rejection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    delta_receiver_nonce: Option<TransferNonce>,
    /// Opaque commitment to the receiver's configured destination root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    delta_destination_root: Option<[u8; 32]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(any(feature = "tls", test))]
struct QuicDeltaHandshakeContext {
    sender_nonce: TransferNonce,
    receiver_nonce: TransferNonce,
    destination_root: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(any(feature = "tls", test))]
struct QuicDeltaSessionContext {
    session_id: SessionId,
    destination_root: [u8; 32],
}

/// Sender proof of live PSK possession over the receiver-challenged delta session.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[cfg(any(feature = "tls", test))]
struct QuicDeltaManifestEnvelope {
    session_id: SessionId,
    destination_root: [u8; 32],
    control_seq: u64,
    manifest: TransferManifest,
    client_auth_tag: [u8; 32],
}

/// QUIC-only binding around the TCP-compatible inner delta request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[cfg(any(feature = "tls", test))]
struct QuicDeltaObjectRequest {
    session_id: SessionId,
    transfer_id: String,
    destination_root: [u8; 32],
    control_seq: u64,
    request: DeltaObjectRequest,
}

/// Terminal proof for an authenticated QUIC delta no-op.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[cfg(any(feature = "tls", test))]
struct QuicDeltaProof {
    session_id: SessionId,
    transfer_id: String,
    destination_root: [u8; 32],
    control_seq: u64,
    receipt: ReceiveReceipt,
}

/// Sender → receiver marker for one completed QUIC symbol spray round.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
struct QuicRoundComplete {
    /// Feedback/spray round this marker closes. The initial source spray is
    /// round 0; each NeedMore repair round uses that NeedMore's feedback round.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    round: u32,
    /// Number of QUIC DATAGRAM symbols the sender emitted in the completed
    /// spray round. Empty legacy ObjectComplete frames parse as unknown.
    #[serde(default)]
    round_symbols_sent: u64,
}

/// Receiver → sender fountain feedback: entries still needing more symbols.
#[allow(dead_code)]
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
struct QuicNeedMore {
    /// Monotonic feedback round assigned by the receiver. This distinguishes
    /// same-shape sparse-loss repair requests from duplicate PTO resends.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    feedback_round: u32,
    /// Entry indices that have not yet decoded.
    pending: Vec<u32>,
    /// Fresh repair deficits for specific incomplete blocks.
    #[serde(default)]
    repair_blocks: Vec<QuicBlockRepairRequest>,
    /// Sparse systematic source symbols missing from incomplete blocks.
    #[serde(default)]
    source_symbols: Vec<QuicSourceSymbolRequest>,
    /// Matching QUIC DATAGRAM symbols observed by the receiver in the completed
    /// spray round. This is the pacing/loss signal; symbols that do not advance
    /// decode rank still prove that the datagram arrived on the wire.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    round_symbols_observed: Option<u64>,
    /// Receiver-computed symbol loss fraction for the completed spray round.
    ///
    /// AIMD uses this explicit wire-loss signal; pending decode pressure remains
    /// separate and only feeds repair/FEC sizing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    round_loss_fraction: Option<f64>,
    /// Matching QUIC DATAGRAM symbols accepted into a decoder in the completed
    /// spray round. Diagnostic only; duplicates or dependent repair rows can
    /// arrive without improving decode rank.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    round_symbols_accepted: Option<u64>,
    /// Raw incomplete-block deficit before QUIC repair over-provisioning.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    repair_base_deficit_symbols: Option<u64>,
    /// Loss-compensated target derived from the raw deficit and measured loss.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    repair_loss_compensated_target_symbols: Option<u64>,
    /// Gap between the requested repair symbols and the loss-compensated target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    repair_request_gap_to_target_symbols: Option<u64>,
    /// Dynamic per-round repair request cap used to build this feedback frame.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    repair_symbol_round_cap: Option<u64>,
    /// Aggregate decoder rank across pending entries after this round.
    ///
    /// Unlike `round_symbols_observed`, this is confirmed useful progress. The
    /// native sender uses rank deltas as the lossy datagram congestion signal
    /// when receiver arrival loss is blind to queue overflow.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending_rank: Option<u64>,
    /// Aggregate rank columns (`rank + rank_deficit`) across pending blocks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending_rank_columns: Option<u64>,
    /// Aggregate rank deficit across pending blocks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending_rank_deficit: Option<u64>,
    /// Decode jobs still in flight when the feedback was generated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending_decode_jobs: Option<u64>,
}

fn is_zero_u32(value: &u32) -> bool {
    *value == 0
}

/// Request for fresh repair symbols for one incomplete source block.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
struct QuicBlockRepairRequest {
    entry: u32,
    sbn: u8,
    symbols: u32,
}

/// Request for retransmission of one systematic source symbol.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
struct QuicSourceSymbolRequest {
    entry: u32,
    sbn: u8,
    esi: u32,
}

#[allow(dead_code)]
fn validate_need_more_feedback(
    manifest: &TransferManifest,
    config: &QuicConfig,
    need: &QuicNeedMore,
) -> Result<std::collections::BTreeSet<u32>, QuicTransportError> {
    if !need.repair_blocks.is_empty() && !need.source_symbols.is_empty() {
        return Err(QuicTransportError::Integrity(
            "receiver requested both fresh repair blocks and source-symbol retransmits".to_string(),
        ));
    }
    if need.repair_blocks.len() > MAX_REPAIR_BLOCK_REQUESTS_PER_FEEDBACK_ROUND {
        return Err(QuicTransportError::Integrity(format!(
            "receiver requested {} repair blocks in one feedback round (max {})",
            need.repair_blocks.len(),
            MAX_REPAIR_BLOCK_REQUESTS_PER_FEEDBACK_ROUND
        )));
    }
    if need.source_symbols.len() > MAX_SOURCE_SYMBOL_REQUESTS_PER_FEEDBACK_ROUND {
        return Err(QuicTransportError::Integrity(format!(
            "receiver requested {} source symbols in one feedback round (max {})",
            need.source_symbols.len(),
            MAX_SOURCE_SYMBOL_REQUESTS_PER_FEEDBACK_ROUND
        )));
    }

    let manifest_entries = manifest
        .entries
        .iter()
        .map(|entry| (entry.index, entry))
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut pending = std::collections::BTreeSet::new();
    for entry in &need.pending {
        if !manifest_entries.contains_key(entry) {
            return Err(QuicTransportError::Integrity(format!(
                "receiver requested repair for unknown entry {entry}"
            )));
        }
        if !pending.insert(*entry) {
            return Err(QuicTransportError::Integrity(format!(
                "receiver requested duplicate repair entry {entry}"
            )));
        }
    }
    if !pending.is_empty() && need.repair_blocks.is_empty() && need.source_symbols.is_empty() {
        return Err(QuicTransportError::Integrity(
            "receiver NeedMore listed pending entries without targeted repair/source deficits"
                .to_string(),
        ));
    }

    let mut block_requests = std::collections::BTreeSet::new();
    let mut repair_symbols = 0usize;
    for request in &need.repair_blocks {
        if !pending.contains(&request.entry) {
            return Err(QuicTransportError::Integrity(format!(
                "receiver requested repair block for non-pending entry {}",
                request.entry
            )));
        }
        if request.symbols == 0 {
            return Err(QuicTransportError::Integrity(format!(
                "receiver requested zero repair symbols for entry={} sbn={}",
                request.entry, request.sbn
            )));
        }
        let Some(entry) = manifest_entries.get(&request.entry).copied() else {
            return Err(QuicTransportError::Integrity(format!(
                "receiver requested repair block for unknown entry {}",
                request.entry
            )));
        };
        validate_feedback_block(entry, request.sbn, config, "repair")?;
        if !block_requests.insert((request.entry, request.sbn)) {
            return Err(QuicTransportError::Integrity(format!(
                "receiver requested duplicate repair block entry={} sbn={}",
                request.entry, request.sbn
            )));
        }
        repair_symbols =
            repair_symbols.saturating_add(usize::try_from(request.symbols).unwrap_or(usize::MAX));
        if repair_symbols > MAX_REPAIR_SYMBOLS_PER_FEEDBACK_ROUND {
            return Err(QuicTransportError::Integrity(format!(
                "receiver requested {repair_symbols} repair symbols in one feedback round (max {})",
                MAX_REPAIR_SYMBOLS_PER_FEEDBACK_ROUND
            )));
        }
    }
    if let Some(cap) = need.repair_symbol_round_cap {
        let cap = usize::try_from(cap).unwrap_or(usize::MAX);
        if cap == 0 || cap > MAX_REPAIR_SYMBOLS_PER_FEEDBACK_ROUND {
            return Err(QuicTransportError::Integrity(format!(
                "receiver reported invalid repair symbol round cap {cap} (max {})",
                MAX_REPAIR_SYMBOLS_PER_FEEDBACK_ROUND
            )));
        }
        if repair_symbols > cap {
            return Err(QuicTransportError::Integrity(format!(
                "receiver requested {repair_symbols} repair symbols above its reported round cap {cap}"
            )));
        }
    }

    let mut source_requests = std::collections::BTreeSet::new();
    for request in &need.source_symbols {
        if !pending.contains(&request.entry) {
            return Err(QuicTransportError::Integrity(format!(
                "receiver requested source symbol for non-pending entry {}",
                request.entry
            )));
        }
        let Some(entry) = manifest_entries.get(&request.entry).copied() else {
            return Err(QuicTransportError::Integrity(format!(
                "receiver requested source symbol for unknown entry {}",
                request.entry
            )));
        };
        let block_k = validate_feedback_block(entry, request.sbn, config, "source symbol")?;
        let esi = usize::try_from(request.esi).map_err(|_| {
            QuicTransportError::Integrity(format!(
                "source request esi {} outside entry {} block {} K={block_k}",
                request.esi, request.entry, request.sbn
            ))
        })?;
        if esi >= block_k {
            return Err(QuicTransportError::Integrity(format!(
                "source request esi {} outside entry {} block {} K={block_k}",
                request.esi, request.entry, request.sbn
            )));
        }
        if !source_requests.insert((request.entry, request.sbn, request.esi)) {
            return Err(QuicTransportError::Integrity(format!(
                "receiver requested duplicate source symbol entry={} sbn={} esi={}",
                request.entry, request.sbn, request.esi
            )));
        }
    }

    Ok(pending)
}

fn validate_feedback_block(
    entry: &ManifestEntry,
    sbn: u8,
    config: &QuicConfig,
    request_kind: &str,
) -> Result<usize, QuicTransportError> {
    let block_count = block_count_for_len(entry.size, config)?;
    let block_index = usize::from(sbn);
    if block_index >= block_count {
        return Err(QuicTransportError::Integrity(format!(
            "receiver requested {request_kind} block {sbn} outside entry {} ({block_count} blocks)",
            entry.index
        )));
    }
    let block_start = u64::from(sbn)
        .checked_mul(config.max_block_size as u64)
        .ok_or_else(|| {
            QuicTransportError::Integrity(format!(
                "receiver requested {request_kind} block offset overflow for entry {}",
                entry.index
            ))
        })?;
    let block_len = usize::try_from((entry.size - block_start).min(config.max_block_size as u64))
        .unwrap_or(usize::MAX);
    Ok(block_len
        .div_ceil(usize::from(config.symbol_size.max(1)))
        .max(1))
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
enum QuicControlReply {
    Proof(ReceiveReceipt),
    NeedMore(QuicNeedMore),
}

#[allow(dead_code)]
fn json_frame<T: Serialize>(ty: FrameType, value: &T) -> Result<Frame, QuicTransportError> {
    let payload =
        serde_json::to_vec(value).map_err(|err| QuicTransportError::Control(err.to_string()))?;
    let frame = Frame::new(ProtocolVersion::CURRENT, ty, payload)
        .map_err(|err| QuicTransportError::Frame(err.to_string()))?;
    let encoded_len = u64::try_from(frame.encoded_len()).unwrap_or(u64::MAX);
    if encoded_len > MAX_FRAME_SIZE {
        return Err(QuicTransportError::Frame(format!(
            "{ty:?} JSON frame encodes to {encoded_len} bytes (max {MAX_FRAME_SIZE}); \
             split or chunk the manifest/control payload"
        )));
    }
    Ok(frame)
}

#[allow(dead_code)]
fn parse_json<T: for<'de> Deserialize<'de>>(frame: &Frame) -> Result<T, QuicTransportError> {
    serde_json::from_slice(frame.payload())
        .map_err(|err| QuicTransportError::Control(err.to_string()))
}

#[allow(dead_code)]
fn parse_quic_round_complete(frame: &Frame) -> Result<QuicRoundComplete, QuicTransportError> {
    if frame.payload().is_empty() {
        Ok(QuicRoundComplete::default())
    } else {
        parse_json(frame)
    }
}

fn receiver_round_loss_fraction(observed: u64, sent: u64) -> Option<f64> {
    if sent == 0 {
        return None;
    }
    let observed = observed.min(sent);
    Some((1.0 - observed as f64 / sent as f64).clamp(0.0, 0.90))
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)]
fn quic_loss_compensated_repair_target_symbols(
    base_deficit: usize,
    round_loss_fraction: Option<f64>,
) -> usize {
    if base_deficit == 0 {
        return 0;
    }
    let Some(loss) = round_loss_fraction.filter(|loss| loss.is_finite()) else {
        return base_deficit;
    };
    if loss <= 0.0 {
        return base_deficit;
    }
    let effective_loss = loss
        .max(QUIC_FEEDBACK_REPAIR_LOSS_ENABLE_MIN)
        .min(QUIC_FEEDBACK_REPAIR_MAX_OVERHEAD);
    let compensated_loss = (effective_loss * (1.0 + QUIC_FEEDBACK_REPAIR_LOSS_MARGIN_FRACTION)
        + QUIC_FEEDBACK_REPAIR_LOSS_MARGIN_MIN)
        .clamp(0.0, 0.90);
    let delivery_fraction = (1.0 - compensated_loss).max(0.10);
    ((base_deficit as f64) / delivery_fraction).ceil() as usize
}

#[allow(dead_code)]
fn parse_json_frame<T: for<'de> Deserialize<'de>>(
    frame: &Frame,
    expected: FrameType,
    expected_name: &'static str,
) -> Result<T, QuicTransportError> {
    if frame.frame_type() != expected {
        return Err(QuicTransportError::Unexpected {
            got: frame.frame_type(),
            expected: expected_name,
        });
    }
    parse_json(frame)
}

/// Derive the per-entry RaptorQ [`ObjectId`] deterministically from the
/// transfer id and entry index, matching `transport_rq` so the symbol bridge can
/// resolve envelope routing without carrying object ids on the wire.
#[allow(dead_code)]
fn entry_object_id(transfer_id: &str, index: u32) -> ObjectId {
    let mut hasher = Sha256::new();
    hasher.update(b"asupersync.atp.rq.entry-object-id.v1\0");
    hasher.update(transfer_id.as_bytes());
    hasher.update(index.to_be_bytes());
    let digest = hasher.finalize();
    let high = u64::from_be_bytes([
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7],
    ]);
    let low = u64::from_be_bytes([
        digest[8], digest[9], digest[10], digest[11], digest[12], digest[13], digest[14],
        digest[15],
    ]);
    ObjectId::new(high, low)
}

/// First 8 bytes of a transfer-id digest as the QUIC DATAGRAM routing tag.
///
/// This is a cheap stray-packet filter and routing key, not a security
/// boundary; per-symbol auth lives in the symbol envelope/auth context.
#[allow(dead_code)]
fn transfer_tag(transfer_id: &str) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(b"asupersync.atp.rq.tag.v1\0");
    hasher.update(transfer_id.as_bytes());
    let digest = hasher.finalize();
    u64::from_be_bytes([
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7],
    ])
}

#[allow(dead_code)]
fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_encode(&hasher.finalize())
}

#[allow(dead_code)]
fn transfer_id_hex(merkle_root_hex: &str, total_bytes: u64, file_count: usize) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"asupersync.atp.quic.transfer-id.v1\0");
    hasher.update(merkle_root_hex.as_bytes());
    hasher.update(total_bytes.to_be_bytes());
    hasher.update(u64::try_from(file_count).unwrap_or(u64::MAX).to_be_bytes());
    let digest = hasher.finalize();
    hex_encode(&digest[..16])
}

#[allow(dead_code)]
fn manifest_from_entries(
    root_name: &str,
    is_directory: bool,
    entries: &[(String, Vec<u8>)],
) -> TransferManifest {
    let total_bytes = entries.iter().fold(0u64, |acc, (_, bytes)| {
        acc.saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX))
    });
    let merkle_root_hex = flat_merkle_root_from_slices(
        entries
            .iter()
            .map(|(rel_path, bytes)| (rel_path.as_str(), bytes.as_slice())),
    );
    let manifest_entries = entries
        .iter()
        .enumerate()
        .map(|(i, (rel_path, bytes))| ManifestEntry {
            index: u32::try_from(i).unwrap_or(u32::MAX),
            rel_path: rel_path.clone(),
            size: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            sha256_hex: sha256_hex(bytes),
            metadata: None,
            members: Vec::new(),
        })
        .collect::<Vec<_>>();
    let transfer_id = transfer_id_hex(&merkle_root_hex, total_bytes, manifest_entries.len());
    TransferManifest {
        transfer_id,
        root_name: root_name.to_string(),
        is_directory,
        total_bytes,
        merkle_root_hex,
        metadata_root_hex: None,
        directory_metadata: None,
        entries: manifest_entries,
        delta_manifest: None,
    }
}

#[allow(dead_code)]
struct QuicEntryEncoder {
    index: u32,
    object_id: ObjectId,
    source: QuicEntryEncoderSource,
    repair_cursors: Vec<usize>,
}

#[allow(dead_code)]
enum QuicEntryEncoderSource {
    Memory(Vec<u8>),
    File {
        abs_path: PathBuf,
        size: u64,
        sha256_hex: String,
    },
}

#[allow(dead_code)]
impl QuicEntryEncoder {
    fn memory(index: u32, object_id: ObjectId, bytes: Vec<u8>, config: &QuicConfig) -> Self {
        let block_count = block_count_for_len(bytes.len() as u64, config).unwrap_or(1);
        Self {
            index,
            object_id,
            source: QuicEntryEncoderSource::Memory(bytes),
            repair_cursors: vec![0; block_count],
        }
    }

    fn file(entry: &QuicSourceEntry, config: &QuicConfig) -> Result<Self, QuicTransportError> {
        Ok(Self {
            index: entry.index,
            object_id: entry.object_id,
            source: QuicEntryEncoderSource::File {
                abs_path: entry.abs_path.clone(),
                size: entry.size,
                sha256_hex: entry.sha256_hex.clone(),
            },
            repair_cursors: vec![0; block_count_for_len(entry.size, config)?],
        })
    }

    fn size(&self) -> u64 {
        match &self.source {
            QuicEntryEncoderSource::Memory(bytes) => bytes.len() as u64,
            QuicEntryEncoderSource::File { size, .. } => *size,
        }
    }

    fn memory_bytes(&self) -> Result<&[u8], QuicTransportError> {
        match &self.source {
            QuicEntryEncoderSource::Memory(bytes) => Ok(bytes),
            QuicEntryEncoderSource::File { abs_path, .. } => {
                Err(QuicTransportError::Source(format!(
                    "file-backed QUIC encoder for {} must be streamed block-by-block",
                    abs_path.display()
                )))
            }
        }
    }

    fn in_memory_block(&self, sbn: u8, config: &QuicConfig) -> Result<&[u8], QuicTransportError> {
        let bytes = self.memory_bytes()?;
        let block_start = usize::from(sbn)
            .checked_mul(config.max_block_size)
            .ok_or_else(|| {
                QuicTransportError::Integrity("source request block offset overflow".to_string())
            })?;
        if block_start >= bytes.len() {
            return Err(QuicTransportError::Integrity(format!(
                "source request block {sbn} outside entry {} ({} bytes)",
                self.index,
                bytes.len()
            )));
        }
        let block_len = config.max_block_size.min(bytes.len() - block_start);
        Ok(&bytes[block_start..block_start + block_len])
    }

    fn block_count(&self, config: &QuicConfig) -> Result<usize, QuicTransportError> {
        block_count_for_len(self.size(), config)
    }

    fn block_len(&self, sbn: u8, config: &QuicConfig) -> Result<usize, QuicTransportError> {
        let block_start = u64::from(sbn)
            .checked_mul(config.max_block_size as u64)
            .ok_or_else(|| {
                QuicTransportError::Integrity("source request block offset overflow".to_string())
            })?;
        let size = self.size();
        if block_start >= size {
            return Err(QuicTransportError::Integrity(format!(
                "source request block {sbn} outside entry {} ({size} bytes)",
                self.index
            )));
        }
        Ok(
            usize::try_from((size - block_start).min(config.max_block_size as u64))
                .unwrap_or(usize::MAX),
        )
    }

    async fn read_block(
        &self,
        cx: &Cx,
        sbn: u8,
        config: &QuicConfig,
    ) -> Result<Vec<u8>, QuicTransportError> {
        let offset = u64::from(sbn)
            .checked_mul(config.max_block_size as u64)
            .ok_or_else(|| {
                QuicTransportError::Integrity("source request block offset overflow".to_string())
            })?;
        let block_len = self.block_len(sbn, config)?;
        match &self.source {
            QuicEntryEncoderSource::Memory(bytes) => {
                let start = usize::try_from(offset).map_err(|_| {
                    QuicTransportError::Integrity(
                        "source request block offset overflow".to_string(),
                    )
                })?;
                let end = start.saturating_add(block_len);
                Ok(bytes[start..end].to_vec())
            }
            QuicEntryEncoderSource::File {
                abs_path,
                size,
                sha256_hex: _,
            } => {
                cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
                let mut file = crate::fs::File::open(abs_path).await.map_err(|err| {
                    QuicTransportError::Source(format!("{}: {err}", abs_path.display()))
                })?;
                file.seek(std::io::SeekFrom::Start(offset))
                    .await
                    .map_err(|err| {
                        QuicTransportError::Source(format!("{}: {err}", abs_path.display()))
                    })?;
                let mut block = vec![0_u8; block_len];
                let mut read = 0usize;
                while read < block_len {
                    cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
                    let n = file.read(&mut block[read..]).await.map_err(|err| {
                        QuicTransportError::Source(format!("{}: {err}", abs_path.display()))
                    })?;
                    if n == 0 {
                        return Err(QuicTransportError::Source(format!(
                            "{} changed while preparing QUIC symbols (short read at block {sbn}, \
                             read {read} of {block_len} bytes, manifest size {size})",
                            abs_path.display()
                        )));
                    }
                    read += n;
                }
                Ok(block)
            }
        }
    }

    fn repair_cursor(&self, sbn: u8) -> usize {
        self.repair_cursors
            .get(usize::from(sbn))
            .copied()
            .unwrap_or(0)
    }

    fn set_repair_cursor(&mut self, sbn: u8, cursor: usize) {
        let idx = usize::from(sbn);
        if idx >= self.repair_cursors.len() {
            self.repair_cursors.resize(idx + 1, 0);
        }
        self.repair_cursors[idx] = cursor;
    }
}

fn block_count_for_len(size: u64, config: &QuicConfig) -> Result<usize, QuicTransportError> {
    if size == 0 {
        return Ok(0);
    }
    let max_block = u64::try_from(config.max_block_size.max(1)).unwrap_or(u64::MAX);
    let blocks = size.div_ceil(max_block);
    if blocks > u64::try_from(QUIC_MAX_SOURCE_BLOCKS_PER_OBJECT).unwrap_or(u64::MAX) {
        return Err(QuicTransportError::TooLarge {
            size,
            max: max_block.saturating_mul(
                u64::try_from(QUIC_MAX_SOURCE_BLOCKS_PER_OBJECT).unwrap_or(u64::MAX),
            ),
        });
    }
    usize::try_from(blocks).map_err(|_| QuicTransportError::TooLarge {
        size,
        max: max_block
            .saturating_mul(u64::try_from(QUIC_MAX_SOURCE_BLOCKS_PER_OBJECT).unwrap_or(u64::MAX)),
    })
}

fn quic_symbol_aligned_block_size(
    config: &QuicConfig,
    bytes: usize,
) -> Result<usize, QuicTransportError> {
    let symbol_size = usize::from(config.symbol_size.max(1));
    let units = bytes.max(symbol_size).div_ceil(symbol_size);
    units
        .checked_mul(symbol_size)
        .ok_or_else(|| QuicTransportError::TooLarge {
            size: u64::try_from(bytes).unwrap_or(u64::MAX),
            max: u64::MAX,
        })
}

fn effective_quic_max_block_size_for_largest_entry(
    config: &QuicConfig,
    max_entry_len: usize,
) -> Result<usize, QuicTransportError> {
    let configured = quic_symbol_aligned_block_size(config, config.max_block_size)?;
    if max_entry_len == 0 {
        return Ok(configured);
    }
    let min_for_source_block_count = max_entry_len.div_ceil(QUIC_MAX_SOURCE_BLOCKS_PER_OBJECT);
    let min_for_source_block_count =
        quic_symbol_aligned_block_size(config, min_for_source_block_count)?;
    Ok(configured.max(min_for_source_block_count))
}

fn effective_quic_config_for_largest_entry(
    config: &QuicConfig,
    max_entry_len: usize,
) -> Result<QuicConfig, QuicTransportError> {
    let mut config = config.clone();
    config.max_block_size =
        effective_quic_max_block_size_for_largest_entry(&config, max_entry_len)?;
    config.validate()?;
    Ok(config)
}

fn effective_quic_receiver_config(config: &QuicConfig) -> Result<QuicConfig, QuicTransportError> {
    let mut config = config.clone();
    config.max_block_size = quic_symbol_aligned_block_size(&config, config.max_block_size)?;
    config.validate()?;
    Ok(config)
}

#[cfg(test)]
fn effective_quic_config_for_entries(
    config: &QuicConfig,
    entries: &[(String, Vec<u8>)],
) -> Result<QuicConfig, QuicTransportError> {
    let max_entry_len = entries
        .iter()
        .map(|(_, bytes)| bytes.len())
        .max()
        .unwrap_or(0);
    effective_quic_config_for_largest_entry(config, max_entry_len)
}

fn empty_quic_entry_digest(rel_path: String) -> EntryDigest {
    let empty_sha: [u8; 32] = Sha256::digest(b"").into();
    EntryDigest {
        rel_path,
        size: 0,
        content_id: crate::atp::object::ObjectId::content(ContentId::from_bytes(b"")),
        content_sha256: empty_sha,
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
struct QuicSourceEntry {
    index: u32,
    rel_path: String,
    abs_path: PathBuf,
    size: u64,
    object_id: ObjectId,
    sha256_hex: String,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) struct QuicPreparedSource {
    manifest: TransferManifest,
    entries: Vec<QuicSourceEntry>,
    max_block_size: usize,
    /// Keeps materialized pack temp files alive for the duration of the send
    /// (pack entries' `abs_path` points into this directory).
    pack_tempdir: Option<std::sync::Arc<tempfile::TempDir>>,
}

impl QuicPreparedSource {
    pub(crate) fn effective_config(&self, config: &QuicConfig) -> QuicConfig {
        let mut config = config.clone();
        config.max_block_size = self.max_block_size;
        config
    }
}

#[allow(dead_code)]
struct QuicEntryDecoder {
    index: u32,
    object_id: ObjectId,
    size: u64,
    pipeline: Option<DecodingPipeline>,
    complete: bool,
    data: Vec<u8>,
    pending_decodes: Vec<QuicPendingDecode>,
}

struct QuicPendingDecode {
    block_sbn: u8,
    started_at: Instant,
    handle: crate::runtime::TaskHandle<BlockDecodeOutcome>,
}

fn quic_pending_decode_jobs(decoders: &[QuicEntryDecoder]) -> usize {
    decoders
        .iter()
        .map(|decoder| decoder.pending_decodes.len())
        .sum()
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct QuicPendingDecodeProgress {
    pending_decode_jobs: u64,
    rank: u64,
    rank_columns: u64,
    rank_deficit: u64,
}

fn usize_to_u64_saturating(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn quic_pending_decode_progress(
    decoders: &[QuicEntryDecoder],
    pending: &[u32],
    config: &QuicConfig,
) -> QuicPendingDecodeProgress {
    let mut progress = QuicPendingDecodeProgress::default();
    for decoder in decoders
        .iter()
        .filter(|decoder| pending.contains(&decoder.index))
    {
        progress.pending_decode_jobs = progress
            .pending_decode_jobs
            .saturating_add(usize_to_u64_saturating(decoder.pending_decodes.len()));
        let Some(pipeline) = decoder.pipeline.as_ref() else {
            continue;
        };
        for block_index in 0..quic_decoder_block_count(decoder, config) {
            let Some(sbn) = u8::try_from(block_index).ok() else {
                continue;
            };
            let Some(status) = pipeline.block_status(sbn) else {
                continue;
            };
            let Some(rank) = status.rank else {
                continue;
            };
            let deficit = status.rank_deficit.unwrap_or(0);
            progress.rank = progress.rank.saturating_add(usize_to_u64_saturating(rank));
            progress.rank_columns = progress.rank_columns.saturating_add(
                usize_to_u64_saturating(rank).saturating_add(usize_to_u64_saturating(deficit)),
            );
            progress.rank_deficit = progress
                .rank_deficit
                .saturating_add(usize_to_u64_saturating(deficit));
        }
    }
    progress
}

fn quic_block_decode_pending(decoder: &QuicEntryDecoder, block_sbn: u8) -> bool {
    decoder
        .pending_decodes
        .iter()
        .any(|pending| pending.block_sbn == block_sbn)
}

fn quic_entry_source_block_count_for_geometry(entry_size: u64, max_block_size: usize) -> usize {
    if entry_size == 0 {
        return 0;
    }
    let max_block_size = u64::try_from(max_block_size.max(1)).unwrap_or(u64::MAX);
    entry_size
        .div_ceil(max_block_size)
        .min(u64::from(u8::MAX) + 1)
        .try_into()
        .unwrap_or(usize::from(u8::MAX) + 1)
}

#[cfg(test)]
fn quic_should_parallel_decode_entry_geometry(entry_size: u64, max_block_size: usize) -> bool {
    entry_size >= QUIC_PARALLEL_DECODE_MIN_ENTRY_BYTES
        && quic_entry_source_block_count_for_geometry(entry_size, max_block_size)
            >= QUIC_PARALLEL_DECODE_MIN_SOURCE_BLOCKS
}

fn quic_entry_source_block_count(decoder: &QuicEntryDecoder, config: &QuicConfig) -> usize {
    quic_entry_source_block_count_for_geometry(decoder.size, config.max_block_size)
}

fn quic_should_parallel_decode_entry(decoder: &QuicEntryDecoder, config: &QuicConfig) -> bool {
    decoder.size >= QUIC_PARALLEL_DECODE_MIN_ENTRY_BYTES
        && quic_entry_source_block_count(decoder, config) >= QUIC_PARALLEL_DECODE_MIN_SOURCE_BLOCKS
}

fn quic_transfer_decode_width(decoders: &[QuicEntryDecoder], config: &QuicConfig) -> usize {
    if decoders
        .iter()
        .any(|decoder| quic_should_parallel_decode_entry(decoder, config))
    {
        QUIC_MAX_PENDING_DECODE_JOBS_PER_TRANSFER
    } else {
        0
    }
}

fn quic_entry_decode_width_budget(
    decoder: &QuicEntryDecoder,
    config: &QuicConfig,
    transfer_decode_width: usize,
) -> usize {
    if !quic_should_parallel_decode_entry(decoder, config) {
        return 0;
    }
    quic_entry_source_block_count(decoder, config)
        .min(QUIC_MAX_PENDING_DECODE_JOBS_PER_ENTRY)
        .min(transfer_decode_width.max(1))
        .max(1)
}

#[cfg(test)]
fn quic_entry_decode_width_budget_for_geometry(
    entry_size: u64,
    max_block_size: usize,
    transfer_decode_width: usize,
) -> usize {
    if !quic_should_parallel_decode_entry_geometry(entry_size, max_block_size) {
        return 0;
    }
    quic_entry_source_block_count_for_geometry(entry_size, max_block_size)
        .min(QUIC_MAX_PENDING_DECODE_JOBS_PER_ENTRY)
        .min(transfer_decode_width.max(1))
        .max(1)
}

#[cfg_attr(not(feature = "tls"), allow(dead_code))]
pub(crate) struct QuicDecodedBlock {
    pub(crate) entry: u32,
    pub(crate) sbn: u8,
    pub(crate) data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct QuicDecodeStats {
    pub(crate) decode_count: u64,
    pub(crate) decode_micros: u64,
}

impl QuicDecodeStats {
    fn record_completed_block(&mut self, elapsed: Duration) {
        self.decode_count = self.decode_count.saturating_add(1);
        let micros = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
        self.decode_micros = self.decode_micros.saturating_add(micros);
    }

    fn add(&mut self, other: Self) {
        self.decode_count = self.decode_count.saturating_add(other.decode_count);
        self.decode_micros = self.decode_micros.saturating_add(other.decode_micros);
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct QuicRoundSymbolStats {
    observed: u64,
    accepted: u64,
}

#[allow(dead_code)]
struct QuicConnectionTransferOutcome {
    manifest: TransferManifest,
    send_report: SendReport,
    receipt: ReceiveReceipt,
    symbols_sent: u64,
    symbols_accepted: u64,
}

#[allow(dead_code)]
struct QuicSenderFeedbackState<'a> {
    manifest: &'a TransferManifest,
    encoders: &'a mut [QuicEntryEncoder],
    config: &'a QuicConfig,
    peer: SocketAddr,
    feedback_rounds: u32,
    symbols_sent: u64,
    round_symbols_start: u64,
    aimd_rate_bps: u64,
    aimd_feedback_seen: bool,
    last_round_loss_fraction: f64,
}

#[allow(dead_code)]
impl<'a> QuicSenderFeedbackState<'a> {
    fn new(
        manifest: &'a TransferManifest,
        encoders: &'a mut [QuicEntryEncoder],
        config: &'a QuicConfig,
        peer: SocketAddr,
        symbols_sent: u64,
    ) -> Self {
        Self {
            manifest,
            encoders,
            config,
            peer,
            feedback_rounds: 0,
            symbols_sent,
            round_symbols_start: 0,
            aimd_rate_bps: config
                .bwlimit_bps
                .unwrap_or(QUIC_DEFAULT_COLD_START_PACING_BYTES_PER_S as u64)
                .clamp(QUIC_AIMD_MIN_RATE_BPS, QUIC_AIMD_MAX_RATE_BPS),
            aimd_feedback_seen: false,
            last_round_loss_fraction: 0.0,
        }
    }

    fn sent_this_round(&self) -> u64 {
        self.symbols_sent.saturating_sub(self.round_symbols_start)
    }

    fn observe_need_more(&mut self, need: &QuicNeedMore) {
        let sent_this_round = self.sent_this_round();
        if sent_this_round == 0 {
            return;
        }
        let loss = need
            .round_loss_fraction
            .filter(|loss| loss.is_finite())
            .or_else(|| {
                need.round_symbols_observed
                    .and_then(|observed| receiver_round_loss_fraction(observed, sent_this_round))
            })
            .unwrap_or(0.0)
            .clamp(0.0, 0.90);
        self.aimd_feedback_seen = true;
        self.last_round_loss_fraction = loss;
        if loss > QUIC_AIMD_LOSS_DECREASE_THRESHOLD {
            let reduced =
                (self.aimd_rate_bps as f64 * QUIC_AIMD_MULTIPLICATIVE_DECREASE).ceil() as u64;
            self.aimd_rate_bps = reduced.clamp(QUIC_AIMD_MIN_RATE_BPS, QUIC_AIMD_MAX_RATE_BPS);
        } else if loss <= QUIC_AIMD_CLEAN_INCREASE_THRESHOLD {
            self.aimd_rate_bps = self
                .aimd_rate_bps
                .saturating_add(QUIC_AIMD_ADDITIVE_INCREASE_BYTES_PER_S)
                .clamp(QUIC_AIMD_MIN_RATE_BPS, QUIC_AIMD_MAX_RATE_BPS);
        }
    }

    fn next_round_config(&self) -> QuicConfig {
        if !self.aimd_feedback_seen {
            return self.config.clone();
        }
        let mut config = self.config.clone();
        config.bwlimit_bps = Some(
            config
                .bwlimit_bps
                .map_or(self.aimd_rate_bps, |cap| cap.min(self.aimd_rate_bps))
                .clamp(QUIC_AIMD_MIN_RATE_BPS, QUIC_AIMD_MAX_RATE_BPS),
        );
        config
    }

    fn mark_next_round_started(&mut self, previous_symbols_sent: u64, sent: u64) {
        self.round_symbols_start = previous_symbols_sent;
        self.symbols_sent = self.symbols_sent.saturating_add(sent);
    }
}

fn trace_quic_aimd_feedback(cx: &Cx, state: &QuicSenderFeedbackState<'_>) {
    if cx.trace_buffer().is_none() {
        return;
    }
    let round = state.feedback_rounds.to_string();
    let sent_this_round = state.sent_this_round().to_string();
    let loss = format!("{:.6}", state.last_round_loss_fraction);
    let aimd_rate_bps = state.aimd_rate_bps.to_string();
    cx.trace_with_fields(
        "atp_quic.sender.aimd_feedback",
        &[
            ("transport", "quic"),
            ("round", round.as_str()),
            ("sent_this_round", sent_this_round.as_str()),
            ("round_loss_fraction", loss.as_str()),
            ("aimd_rate_bps", aimd_rate_bps.as_str()),
        ],
    );
}

fn quic_repair_symbol_total(requests: &[QuicBlockRepairRequest]) -> u64 {
    requests.iter().fold(0u64, |acc, request| {
        acc.saturating_add(u64::from(request.symbols))
    })
}

fn quic_repair_block_request_summary(requests: &[QuicBlockRepairRequest]) -> String {
    use std::fmt::Write as _;

    const MAX_TRACE_BLOCKS: usize = 128;

    let mut summary = String::new();
    for (idx, request) in requests.iter().take(MAX_TRACE_BLOCKS).enumerate() {
        if idx != 0 {
            summary.push(';');
        }
        let _ = write!(
            &mut summary,
            "{}:{}:{}",
            request.entry, request.sbn, request.symbols
        );
    }
    if requests.len() > MAX_TRACE_BLOCKS {
        if !summary.is_empty() {
            summary.push(';');
        }
        let _ = write!(
            &mut summary,
            "+{}more",
            requests.len().saturating_sub(MAX_TRACE_BLOCKS)
        );
    }
    summary
}

fn quic_need_more_response_mode(need: &QuicNeedMore) -> &'static str {
    if !need.repair_blocks.is_empty() {
        "block_repair"
    } else if need.pending.is_empty() && need.source_symbols.is_empty() {
        "empty"
    } else if need.source_symbols.is_empty() {
        "missing_deficit"
    } else {
        "source_retransmit"
    }
}

#[allow(clippy::too_many_arguments)]
fn trace_quic_sender_need_more(
    cx: &Cx,
    round: u32,
    symbols_sent_total: u64,
    sent_this_round: u64,
    need: &QuicNeedMore,
    config: &QuicConfig,
    aimd_rate_bps: Option<u64>,
    native_aimd_cap_bps: Option<u64>,
) {
    if std::env::var_os("ATP_RQ_TRACE").is_some() {
        quic_rqtrace(format_args!(
            "sender: NeedMore round={} pending={} repair_blocks={} repair_symbols_requested={} source_requests={} sent_total={} sent_this_round={} observed={} accepted={} loss={:.6} repair_base_deficit={} repair_loss_compensated_target={} repair_request_gap_to_target={} max_feedback_rounds={} repair_symbol_round_cap={} repair_block_request_cap={} repair_block_requests={} aimd_rate_bps={} native_aimd_cap_bps={}",
            round,
            need.pending.len(),
            need.repair_blocks.len(),
            quic_repair_symbol_total(&need.repair_blocks),
            need.source_symbols.len(),
            symbols_sent_total,
            sent_this_round,
            need.round_symbols_observed.unwrap_or(0),
            need.round_symbols_accepted.unwrap_or(0),
            need.round_loss_fraction.unwrap_or(0.0),
            need.repair_base_deficit_symbols.unwrap_or(0),
            need.repair_loss_compensated_target_symbols.unwrap_or(0),
            need.repair_request_gap_to_target_symbols.unwrap_or(0),
            config.max_feedback_rounds,
            need.repair_symbol_round_cap
                .unwrap_or(MAX_REPAIR_SYMBOLS_PER_FEEDBACK_ROUND as u64),
            MAX_REPAIR_BLOCK_REQUESTS_PER_FEEDBACK_ROUND,
            quic_repair_block_request_summary(&need.repair_blocks),
            aimd_rate_bps
                .map(|rate| rate.to_string())
                .unwrap_or_else(|| "none".to_string()),
            native_aimd_cap_bps
                .map(|rate| rate.to_string())
                .unwrap_or_else(|| "none".to_string())
        ));
    }
    if cx.trace_buffer().is_none() {
        return;
    }

    let round = round.to_string();
    let symbols_sent_total = symbols_sent_total.to_string();
    let sent_this_round = sent_this_round.to_string();
    let pending = need.pending.len().to_string();
    let repair_blocks = need.repair_blocks.len().to_string();
    let repair_symbols_requested = quic_repair_symbol_total(&need.repair_blocks).to_string();
    let source_symbols = need.source_symbols.len().to_string();
    let repair_base_deficit = need.repair_base_deficit_symbols.unwrap_or(0).to_string();
    let repair_loss_compensated_target = need
        .repair_loss_compensated_target_symbols
        .unwrap_or(0)
        .to_string();
    let repair_request_gap_to_target = need
        .repair_request_gap_to_target_symbols
        .unwrap_or(0)
        .to_string();
    let aimd_rate_bps = aimd_rate_bps.map_or_else(|| "none".to_string(), |rate| rate.to_string());
    let native_aimd_cap_bps =
        native_aimd_cap_bps.map_or_else(|| "none".to_string(), |rate| rate.to_string());

    // Correlation-safe field budget: <=12 explicit fields (br-asupersync-an0t8o).
    // LogEntry caps at MAX_FIELDS=16 and prioritized task/region/span ids evict
    // the OLDEST fields of a full entry; fields past 16 are never recorded.
    // Dropped here: "transport" (the message name carries it), config statics
    // (max_feedback_rounds, the two repair caps), the receiver-reported round
    // trio (round_symbols_observed/accepted, round_loss_fraction — already on
    // atp_quic.receive.need_more), and the per-block summary string.
    cx.trace_with_fields(
        "atp_quic.sender.need_more",
        &[
            ("round", round.as_str()),
            ("symbols_sent_total", symbols_sent_total.as_str()),
            ("sent_this_round", sent_this_round.as_str()),
            ("pending", pending.as_str()),
            ("repair_blocks", repair_blocks.as_str()),
            (
                "repair_symbols_requested",
                repair_symbols_requested.as_str(),
            ),
            ("source_symbols", source_symbols.as_str()),
            ("repair_base_deficit", repair_base_deficit.as_str()),
            (
                "repair_loss_compensated_target",
                repair_loss_compensated_target.as_str(),
            ),
            (
                "repair_request_gap_to_target",
                repair_request_gap_to_target.as_str(),
            ),
            ("aimd_rate_bps", aimd_rate_bps.as_str()),
            ("native_aimd_cap_bps", native_aimd_cap_bps.as_str()),
        ],
    );
}

fn trace_quic_sender_repair_round(
    cx: &Cx,
    round: u32,
    mode: &str,
    symbols_before: u64,
    emitted_symbols: u64,
    need: &QuicNeedMore,
) {
    if std::env::var_os("ATP_RQ_TRACE").is_some() {
        quic_rqtrace(format_args!(
            "sender: repair_round round={} mode={} symbols_before={} emitted_symbols={} symbols_after={} pending={} repair_blocks={} repair_symbols_requested={} source_requests={} repair_base_deficit={} repair_loss_compensated_target={} repair_request_gap_to_target={} repair_block_requests={}",
            round,
            mode,
            symbols_before,
            emitted_symbols,
            symbols_before.saturating_add(emitted_symbols),
            need.pending.len(),
            need.repair_blocks.len(),
            quic_repair_symbol_total(&need.repair_blocks),
            need.source_symbols.len(),
            need.repair_base_deficit_symbols.unwrap_or(0),
            need.repair_loss_compensated_target_symbols.unwrap_or(0),
            need.repair_request_gap_to_target_symbols.unwrap_or(0),
            quic_repair_block_request_summary(&need.repair_blocks)
        ));
    }
    if cx.trace_buffer().is_none() {
        return;
    }

    let symbols_after_value = symbols_before.saturating_add(emitted_symbols);
    let round = round.to_string();
    let symbols_before = symbols_before.to_string();
    let emitted_symbols = emitted_symbols.to_string();
    let symbols_after = symbols_after_value.to_string();
    let pending = need.pending.len().to_string();
    let repair_blocks = need.repair_blocks.len().to_string();
    let repair_symbols_requested = quic_repair_symbol_total(&need.repair_blocks).to_string();
    let source_symbols = need.source_symbols.len().to_string();
    let repair_base_deficit = need.repair_base_deficit_symbols.unwrap_or(0).to_string();
    let repair_loss_compensated_target = need
        .repair_loss_compensated_target_symbols
        .unwrap_or(0)
        .to_string();
    let repair_request_gap_to_target = need
        .repair_request_gap_to_target_symbols
        .unwrap_or(0)
        .to_string();

    // Correlation-safe field budget: <=12 explicit fields
    // (br-asupersync-an0t8o). Dropped: "transport" (in the message name) and
    // the per-block summary string (on the ATP_RQ_TRACE line).
    cx.trace_with_fields(
        "atp_quic.sender.repair_round",
        &[
            ("round", round.as_str()),
            ("mode", mode),
            ("symbols_before", symbols_before.as_str()),
            ("emitted_symbols", emitted_symbols.as_str()),
            ("symbols_after", symbols_after.as_str()),
            ("pending", pending.as_str()),
            ("repair_blocks", repair_blocks.as_str()),
            (
                "repair_symbols_requested",
                repair_symbols_requested.as_str(),
            ),
            ("source_symbols", source_symbols.as_str()),
            ("repair_base_deficit", repair_base_deficit.as_str()),
            (
                "repair_loss_compensated_target",
                repair_loss_compensated_target.as_str(),
            ),
            (
                "repair_request_gap_to_target",
                repair_request_gap_to_target.as_str(),
            ),
        ],
    );
}

#[cfg(test)]
fn encoders_from_entries(
    manifest: &TransferManifest,
    entries: &[(String, Vec<u8>)],
    config: &QuicConfig,
) -> Result<Vec<QuicEntryEncoder>, QuicTransportError> {
    let config = effective_quic_config_for_entries(config, entries)?;
    Ok(manifest
        .entries
        .iter()
        .zip(entries)
        .map(|(entry, (_, bytes))| {
            QuicEntryEncoder::memory(
                entry.index,
                entry_object_id(&manifest.transfer_id, entry.index),
                bytes.clone(),
                &config,
            )
        })
        .collect())
}

#[allow(dead_code)]
/// Largest file that may be packed into a combined entry (inclusive).
///
/// Mirrors the RaptorQ tier's E-15 coalescing: many-small-file trees pay the
/// QUIC tier's per-entry stream/staging/commit overhead once per pack instead
/// of once per file (the tier measured 3.8× slower than the RQ tier on
/// tree_small from exactly this per-entry tax, MATRIX-212).
const QUIC_PACK_MEMBER_MAX_BYTES: u64 = 1024 * 1024;
/// Target combined size for one pack entry.
const QUIC_PACK_TARGET_BYTES: u64 = 8 * 1024 * 1024;

#[cfg(feature = "tls")]
fn metadata_makes_windows_staging_readonly(metadata: &EntryMetadata) -> bool {
    const WINDOWS_FILE_ATTRIBUTE_READONLY: u32 = 0x0000_0001;
    cfg!(windows)
        && metadata
            .windows_attributes
            .is_some_and(|attributes| attributes & WINDOWS_FILE_ATTRIBUTE_READONLY != 0)
}

/// One planned source entry: metadata resolved, packing eligibility decided,
/// content hashing deferred so pack members are read exactly once.
struct QuicPlannedSource {
    rel_path: String,
    abs_path: PathBuf,
    metadata: EntryMetadata,
    size: u64,
    zero_content: bool,
    pack_eligible: bool,
}

enum QuicBuildItem {
    Plain(usize),
    Pack(Vec<usize>),
}

const QUIC_DELTA_MAX_MANIFEST_CHUNKS: u64 = 4_096;
const QUIC_DELTA_ENVELOPE_WIRE_BUDGET: usize = 2 * 1024;

fn quic_delta_control_auth_context(config: &QuicConfig) -> Option<&SecurityContext> {
    config
        .delta_control_auth_context
        .as_ref()
        .filter(|context| context.mode() == AuthMode::Strict)
}

fn quic_delta_manifest_entry(manifest: &TransferManifest) -> Option<&ManifestEntry> {
    let [entry] = manifest.entries.as_slice() else {
        return None;
    };
    let metadata = entry.metadata.clone().unwrap_or_default();
    (!manifest.is_directory
        && entry.members.is_empty()
        && matches!(metadata.file_kind, FileKind::Regular)
        && metadata.hardlink_target.is_none()
        && metadata.symlink_target.is_none()
        && metadata.symlink_target_info.is_none())
    .then_some(entry)
}

async fn build_quic_delta_manifest_for_file(
    cx: &Cx,
    tree_id: &str,
    path: &Path,
    entry_index: u32,
    rel_path: &str,
    expected_size: u64,
    expected_sha256_hex: &str,
    chunk_size: usize,
) -> Result<DeltaManifestWire, QuicTransportError> {
    const OBJECT_DATA_HEADER_BYTES: usize = 12;
    let max_chunk_size = usize::try_from(MAX_FRAME_SIZE)
        .unwrap_or(usize::MAX)
        .saturating_sub(OBJECT_DATA_HEADER_BYTES);
    let chunk_size = chunk_size.max(1).min(max_chunk_size);
    let mut file = crate::fs::File::open(path)
        .await
        .map_err(|error| QuicTransportError::Source(format!("{}: {error}", path.display())))?;
    let mut buf = vec![0u8; chunk_size];
    let mut chunks = Vec::new();
    let mut planner_chunks = Vec::new();
    let mut offset = 0u64;
    let mut index = 0u32;
    let mut sha256 = Sha256::new();
    let mut content_id = ContentId::streaming();
    loop {
        cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
        // A whole `chunk_size` chunk per iteration (asupersync-u4j7sr): one
        // read of `crate::fs::File` returns at most 128 KiB.
        let read = crate::net::atp::transport_common::delta::read_full_chunk(&mut file, &mut buf)
            .await
            .map_err(|error| QuicTransportError::Source(format!("{}: {error}", path.display())))?;
        if read == 0 {
            break;
        }
        let bytes = &buf[..read];
        sha256.update(bytes);
        content_id.update(bytes);
        let size_bytes = u64::try_from(read)
            .map_err(|_| QuicTransportError::Control("delta chunk size overflow".to_string()))?;
        let content_id = ContentId::from_bytes(bytes);
        planner_chunks.push(CasChunkRef {
            index,
            byte_offset: offset,
            size_bytes,
            content_id: content_id.clone(),
        });
        chunks.push(DeltaChunkWire {
            index,
            entry_index,
            rel_path: rel_path.to_string(),
            entry_offset: offset,
            stream_offset: offset,
            size_bytes,
            content_id_hex: content_id.to_hex(),
        });
        index = index
            .checked_add(1)
            .ok_or_else(|| QuicTransportError::Control("delta chunk index overflow".to_string()))?;
        offset = offset.checked_add(size_bytes).ok_or_else(|| {
            QuicTransportError::Control("delta chunk offset overflow".to_string())
        })?;
    }
    if offset != expected_size {
        return Err(QuicTransportError::Source(format!(
            "{} changed while building QUIC delta manifest (read {offset} bytes, expected {})",
            path.display(),
            expected_size
        )));
    }
    let content_sha256: [u8; 32] = sha256.finalize().into();
    if hex_encode(&content_sha256) != expected_sha256_hex
        || flat_merkle_root_from_digests(&[EntryDigest {
            rel_path: rel_path.to_string(),
            size: offset,
            content_id: crate::atp::object::ObjectId::content(content_id.finalize()),
            content_sha256,
        }]) != tree_id
    {
        return Err(QuicTransportError::Source(format!(
            "{} changed while building its QUIC delta manifest",
            path.display()
        )));
    }
    let planner =
        PersistentChunkManifest::new(tree_id.to_string(), planner_chunks).map_err(|error| {
            QuicTransportError::Control(format!("build QUIC delta manifest: {error}"))
        })?;
    Ok(DeltaManifestWire {
        schema: ATP_DELTA_CHUNK_MANIFEST_SCHEMA.to_string(),
        tree_id: tree_id.to_string(),
        chunk_size,
        total_size_bytes: planner.total_size_bytes,
        merkle_root_hex: planner.merkle_root.to_hex(),
        chunks,
    })
}

async fn maybe_attach_quic_delta_manifest(
    cx: &Cx,
    manifest: &mut TransferManifest,
    entries: &[QuicSourceEntry],
    config: &QuicConfig,
) -> Result<(), QuicTransportError> {
    let Some(manifest_entry) = quic_delta_manifest_entry(manifest) else {
        return Ok(());
    };
    let [source_entry] = entries else {
        return Ok(());
    };
    if !config.enable_delta
        || quic_delta_control_auth_context(config).is_none()
        || source_entry.index != manifest_entry.index
        || source_entry.rel_path != manifest_entry.rel_path
        || source_entry.size != manifest_entry.size
        || source_entry.sha256_hex != manifest_entry.sha256_hex
    {
        return Ok(());
    }
    let chunk_size = config.chunk_size.max(1).min(
        usize::try_from(MAX_FRAME_SIZE)
            .unwrap_or(usize::MAX)
            .saturating_sub(12),
    );
    let chunk_size_u64 = u64::try_from(chunk_size).unwrap_or(u64::MAX);
    if manifest_entry.size.div_ceil(chunk_size_u64) > QUIC_DELTA_MAX_MANIFEST_CHUNKS {
        return Ok(());
    }
    let delta = build_quic_delta_manifest_for_file(
        cx,
        &manifest.merkle_root_hex,
        &source_entry.abs_path,
        source_entry.index,
        &source_entry.rel_path,
        source_entry.size,
        &source_entry.sha256_hex,
        chunk_size,
    )
    .await?;
    manifest.delta_manifest = Some(delta);
    match json_frame(FrameType::ObjectManifest, manifest) {
        Ok(frame)
            if frame.payload().len()
                <= usize::try_from(MAX_FRAME_SIZE)
                    .unwrap_or(usize::MAX)
                    .saturating_sub(QUIC_DELTA_ENVELOPE_WIRE_BUDGET) => {}
        Ok(_) => {
            manifest.delta_manifest = None;
            cx.trace_with_fields(
                "atp_quic.delta_manifest_fallback",
                &[
                    ("reason", "authenticated_envelope_budget"),
                    ("mode", "full_object"),
                ],
            );
        }
        Err(QuicTransportError::Frame(reason)) => {
            manifest.delta_manifest = None;
            cx.trace_with_fields(
                "atp_quic.delta_manifest_fallback",
                &[("reason", reason.as_str()), ("mode", "full_object")],
            );
        }
        Err(error) => return Err(error),
    }
    Ok(())
}

#[cfg(any(feature = "tls", test))]
async fn validate_quic_prepared_delta_source_unchanged(
    cx: &Cx,
    prepared: &QuicPreparedSource,
    config: &QuicConfig,
) -> Result<(), QuicTransportError> {
    let manifest = &prepared.manifest;
    let delta = manifest.delta_manifest.as_ref().ok_or_else(|| {
        QuicTransportError::Control(
            "cannot revalidate a prepared QUIC source without a delta manifest".to_string(),
        )
    })?;
    let entry = quic_delta_manifest_entry(manifest).ok_or_else(|| {
        QuicTransportError::Control(
            "prepared QUIC delta source no longer has a supported transfer shape".to_string(),
        )
    })?;
    let [source] = prepared.entries.as_slice() else {
        return Err(QuicTransportError::Control(
            "prepared QUIC delta source must contain exactly one entry".to_string(),
        ));
    };
    let expected_metadata = entry.metadata.clone().unwrap_or_default();
    if read_entry_metadata(&source.abs_path, &config.metadata_policy).await? != expected_metadata {
        return Err(QuicTransportError::Source(
            "prepared QUIC source metadata changed before delta no-op completion".to_string(),
        ));
    }
    let current = build_quic_delta_manifest_for_file(
        cx,
        &manifest.merkle_root_hex,
        &source.abs_path,
        entry.index,
        &entry.rel_path,
        entry.size,
        &entry.sha256_hex,
        delta.chunk_size,
    )
    .await?;
    if current != *delta
        || read_entry_metadata(&source.abs_path, &config.metadata_policy).await?
            != expected_metadata
    {
        return Err(QuicTransportError::Integrity(
            "prepared QUIC source changed before delta no-op completion".to_string(),
        ));
    }
    Ok(())
}

fn quic_flush_pack_group(
    items: &mut Vec<QuicBuildItem>,
    group: &mut Vec<usize>,
    group_bytes: &mut u64,
) {
    if group.len() >= 2 {
        items.push(QuicBuildItem::Pack(std::mem::take(group)));
    } else if let Some(idx) = group.pop() {
        items.push(QuicBuildItem::Plain(idx));
    }
    *group_bytes = 0;
}

/// Materialize one pack file in a single blocking-pool task: stream every
/// member through the pack writer with raw `std::fs`, computing per-member
/// SHA-256 + content id and the pack-level SHA-256 in the same read. The
/// async per-member loop paid a pool round-trip per open/read — the
/// sender-side twin of the MATRIX-211 commit dispatch tail.
///
/// Returns `(per-member (len, sha256, content_id), pack_sha256)`.
#[allow(clippy::type_complexity)]
fn build_quic_pack_oneshot(
    pack_path: &Path,
    inputs: &[(PathBuf, u64)],
) -> std::io::Result<(Vec<(u64, [u8; 32], crate::atp::object::ObjectId)>, [u8; 32])> {
    use std::io::{Read, Write};

    let mut pack = std::io::BufWriter::new(std::fs::File::create(pack_path)?);
    let mut pack_sha = Sha256::new();
    let mut out = Vec::with_capacity(inputs.len());
    let mut buf = vec![0u8; 256 * 1024];
    for (path, expected) in inputs {
        let mut src = std::fs::File::open(path)?;
        let mut sha = Sha256::new();
        let mut cid = ContentId::streaming();
        let mut len = 0u64;
        loop {
            let n = src.read(&mut buf)?;
            if n == 0 {
                break;
            }
            sha.update(&buf[..n]);
            cid.update(&buf[..n]);
            pack_sha.update(&buf[..n]);
            pack.write_all(&buf[..n])?;
            len = len.saturating_add(n as u64);
        }
        if len != *expected {
            return Err(std::io::Error::other(format!(
                "{} changed while packing (read {len} bytes, planned {expected})",
                path.display()
            )));
        }
        out.push((
            len,
            sha.finalize().into(),
            crate::atp::object::ObjectId::content(cid.finalize()),
        ));
    }
    pack.flush()?;
    Ok((out, pack_sha.finalize().into()))
}

async fn prepare_source_manifest(
    cx: &Cx,
    source: &Path,
    config: &QuicConfig,
) -> Result<QuicPreparedSource, QuicTransportError> {
    config.validate()?;
    let (root_name, is_directory, source_entries) =
        collect_entries_with_policy(source, &config.metadata_policy).await?;
    let directory_metadata = if is_directory {
        let captured = capture_directory_metadata_manifest(source, &config.metadata_policy).await?;
        (!captured.is_empty()).then_some(captured)
    } else {
        None
    };
    let _ = quic_safe_base_for_root_name(Path::new("base"), &root_name)?;
    let mut read_buf = vec![0_u8; config.chunk_size];

    // Pass 1: metadata + hardlink resolution + packing eligibility. Content
    // hashing is deferred to the build pass so pack members are read once.
    // Path safety stays on the async side (cheap, pure, cancellable); the
    // stat/xattr storm runs as ONE blocking task via the sync metadata cores
    // instead of 2-3 pool round-trips per member — ~4000 dispatches on a
    // 2000-file tree, the pass-1 tail MATRIX-215 left behind
    // (br-asupersync-i7pdxb).
    for source_entry in &source_entries {
        cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
        quic_join_relative(Path::new("base"), &source_entry.rel_path)?;
    }
    let planned = {
        let policy = config.metadata_policy.clone();
        let preserve_hardlinks = config.preserve_hardlinks;
        let max_transfer_bytes = config.max_transfer_bytes;
        let batch_entries: Vec<(String, PathBuf)> = source_entries
            .iter()
            .map(|entry| (entry.rel_path.clone(), entry.abs_path.clone()))
            .collect();
        crate::runtime::spawn_blocking(move || {
            use crate::net::atp::transport_common::metadata::{
                inode_key_if_regular_sync, read_entry_metadata_sync,
            };
            let mut hardlink_primary: std::collections::HashMap<HardlinkIdentity, (String, usize)> =
                std::collections::HashMap::new();
            let mut batch_total = 0u64;
            let mut planned: Vec<QuicPlannedSource> = Vec::with_capacity(batch_entries.len());
            for (rel_path, abs_path) in batch_entries {
                let mut metadata = read_entry_metadata_sync(&abs_path, &policy)?;
                if preserve_hardlinks && matches!(metadata.file_kind, FileKind::Regular) {
                    if let Some(key) = inode_key_if_regular_sync(&abs_path)? {
                        if let Some((primary, primary_index)) = hardlink_primary.get(&key) {
                            metadata.hardlink_target = Some(primary.clone());
                            // The receiver validates hardlink targets against
                            // prior plain entries. Once a duplicate proves this
                            // inode is a hardlink group, keep its primary out of
                            // a small-file pack as well as the zero-content
                            // secondary.
                            planned[*primary_index].pack_eligible = false;
                        } else {
                            hardlink_primary.insert(key, (rel_path.clone(), planned.len()));
                        }
                    }
                }
                validate_symlink_metadata_for_receive(&rel_path, &metadata).map_err(|error| {
                    QuicTransportError::Source(format!(
                        "{}: invalid symlink metadata: {error}",
                        abs_path.display()
                    ))
                })?;
                let zero_content = !matches!(metadata.file_kind, FileKind::Regular)
                    || metadata.hardlink_target.is_some();
                let size = if zero_content {
                    0
                } else {
                    std::fs::metadata(&abs_path)
                        .map_err(|err| {
                            QuicTransportError::Source(format!("{}: {err}", abs_path.display()))
                        })?
                        .len()
                };
                batch_total =
                    batch_total
                        .checked_add(size)
                        .ok_or(QuicTransportError::TooLarge {
                            size: u64::MAX,
                            max: max_transfer_bytes,
                        })?;
                if batch_total > max_transfer_bytes {
                    return Err(QuicTransportError::TooLarge {
                        size: batch_total,
                        max: max_transfer_bytes,
                    });
                }
                let pack_eligible =
                    is_directory && !zero_content && size <= QUIC_PACK_MEMBER_MAX_BYTES;
                planned.push(QuicPlannedSource {
                    rel_path,
                    abs_path,
                    metadata,
                    size,
                    zero_content,
                    pack_eligible,
                });
            }
            Ok::<(Vec<QuicPlannedSource>, u64), QuicTransportError>((planned, batch_total))
        })
        .await
    };
    let (planned, total_bytes) = planned?;

    // Pass 2: group consecutive small regular files into packs. Zero-content
    // entries without a hardlink target (directories, symlinks) carry no
    // stream bytes, so they stay in place without fragmenting a pack run.
    // Hardlink entries flush the run so a packed primary always commits
    // before the link that references it; large files flush it like the RQ
    // tier does.
    let mut items: Vec<QuicBuildItem> = Vec::with_capacity(planned.len());
    let mut group: Vec<usize> = Vec::new();
    let mut group_bytes = 0u64;
    for (idx, plan) in planned.iter().enumerate() {
        if plan.pack_eligible {
            if !group.is_empty() && group_bytes.saturating_add(plan.size) > QUIC_PACK_TARGET_BYTES {
                quic_flush_pack_group(&mut items, &mut group, &mut group_bytes);
            }
            group.push(idx);
            group_bytes = group_bytes.saturating_add(plan.size);
        } else if plan.zero_content && plan.metadata.hardlink_target.is_none() {
            items.push(QuicBuildItem::Plain(idx));
        } else {
            quic_flush_pack_group(&mut items, &mut group, &mut group_bytes);
            items.push(QuicBuildItem::Plain(idx));
        }
    }
    quic_flush_pack_group(&mut items, &mut group, &mut group_bytes);

    // Pass 3: hash + materialize in manifest order. `digests` is the LOGICAL
    // (member-flattened) digest list — the merkle root and metadata
    // commitment are computed over logical files, so they are invariant to
    // how files were packed and the receiver recomputes them from members.
    let mut digests: Vec<EntryDigest> = Vec::with_capacity(planned.len());
    let mut manifest_entries: Vec<ManifestEntry> = Vec::with_capacity(items.len());
    let mut entry_sources: Vec<PathBuf> = Vec::with_capacity(items.len());
    let mut pack_tempdir: Option<tempfile::TempDir> = None;
    let mut pack_count = 0usize;
    for item in &items {
        cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
        let index = u32::try_from(manifest_entries.len()).unwrap_or(u32::MAX);
        match item {
            QuicBuildItem::Plain(idx) => {
                let plan = &planned[*idx];
                let digest = if plan.zero_content {
                    empty_quic_entry_digest(plan.rel_path.clone())
                } else {
                    let (size, content_id, content_sha256) =
                        hash_file_streaming(&plan.abs_path, &mut read_buf).await?;
                    EntryDigest {
                        rel_path: plan.rel_path.clone(),
                        size,
                        content_id,
                        content_sha256,
                    }
                };
                manifest_entries.push(ManifestEntry {
                    index,
                    rel_path: plan.rel_path.clone(),
                    size: digest.size,
                    sha256_hex: hex_encode(&digest.content_sha256),
                    metadata: if plan.metadata.is_bare() {
                        None
                    } else {
                        Some(plan.metadata.clone())
                    },
                    members: Vec::new(),
                });
                entry_sources.push(plan.abs_path.clone());
                digests.push(digest);
            }
            QuicBuildItem::Pack(indices) => {
                let tempdir = match pack_tempdir.as_ref() {
                    Some(dir) => dir,
                    None => {
                        let mut tempdir_builder = tempfile::Builder::new();
                        tempdir_builder.prefix(".atp-quic-pack-");
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt as _;

                            tempdir_builder.permissions(std::fs::Permissions::from_mode(0o700));
                        }
                        let dir = tempdir_builder.tempdir().map_err(|err| {
                            QuicTransportError::Source(format!("create pack tempdir: {err}"))
                        })?;
                        pack_tempdir = Some(dir);
                        pack_tempdir.as_ref().expect("pack tempdir just installed")
                    }
                };
                let pack_path = tempdir.path().join(format!("pack-{pack_count}"));
                // Materialize the whole pack in ONE blocking-pool task; the
                // async per-member loop paid a pool round-trip per open/read
                // (2000 files ≈ the sender-side MATRIX-211 dispatch tail).
                let inputs: Vec<(PathBuf, u64)> = indices
                    .iter()
                    .map(|member_idx| {
                        let plan = &planned[*member_idx];
                        (plan.abs_path.clone(), plan.size)
                    })
                    .collect();
                let oneshot_pack_path = pack_path.clone();
                let (member_digests, pack_sha256) = crate::runtime::spawn_blocking_io(move || {
                    build_quic_pack_oneshot(&oneshot_pack_path, &inputs)
                })
                .await
                .map_err(|err| {
                    QuicTransportError::Source(format!("{}: {err}", pack_path.display()))
                })?;
                cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
                let mut members: Vec<PackedMember> = Vec::with_capacity(indices.len());
                let mut offset = 0u64;
                for (member_idx, (len, content_sha256, content_id)) in
                    indices.iter().zip(member_digests)
                {
                    let plan = &planned[*member_idx];
                    members.push(PackedMember {
                        rel_path: plan.rel_path.clone(),
                        offset,
                        len,
                        sha256_hex: hex_encode(&content_sha256),
                        metadata: if plan.metadata.is_bare() {
                            None
                        } else {
                            Some(plan.metadata.clone())
                        },
                    });
                    digests.push(EntryDigest {
                        rel_path: plan.rel_path.clone(),
                        size: len,
                        content_id,
                        content_sha256,
                    });
                    offset = offset.saturating_add(len);
                }
                manifest_entries.push(ManifestEntry {
                    index,
                    rel_path: format!(".atp-pack-{pack_count}"),
                    size: offset,
                    sha256_hex: hex_encode(&pack_sha256),
                    metadata: None,
                    members,
                });
                entry_sources.push(pack_path);
                pack_count += 1;
            }
        }
    }

    let max_entry_len = manifest_entries.iter().try_fold(0usize, |max, entry| {
        usize::try_from(entry.size)
            .map(|size| max.max(size))
            .map_err(|_| QuicTransportError::TooLarge {
                size: entry.size,
                max: usize::MAX as u64,
            })
    })?;
    let effective_config = effective_quic_config_for_largest_entry(config, max_entry_len)?;
    let merkle_root_hex = flat_merkle_root_from_digests(&digests);
    let transfer_id = transfer_id_hex(&merkle_root_hex, total_bytes, digests.len());
    let mut manifest = TransferManifest {
        transfer_id,
        root_name,
        is_directory,
        total_bytes,
        merkle_root_hex,
        metadata_root_hex: None,
        directory_metadata,
        entries: manifest_entries,
        delta_manifest: None,
    };
    // Computed from the built entries (members flattened) so the sender and
    // receiver commitments are symmetric by construction.
    manifest.metadata_root_hex = manifest_metadata_commitment(&manifest);

    let entries = manifest
        .entries
        .iter()
        .zip(entry_sources)
        .map(|(entry, abs_path)| QuicSourceEntry {
            index: entry.index,
            rel_path: entry.rel_path.clone(),
            abs_path,
            size: entry.size,
            object_id: entry_object_id(&manifest.transfer_id, entry.index),
            sha256_hex: entry.sha256_hex.clone(),
        })
        .collect::<Vec<_>>();

    maybe_attach_quic_delta_manifest(cx, &mut manifest, &entries, &effective_config).await?;
    validate_quic_manifest(&manifest, &effective_config)?;

    Ok(QuicPreparedSource {
        manifest,
        entries,
        max_block_size: effective_config.max_block_size,
        pack_tempdir: pack_tempdir.map(std::sync::Arc::new),
    })
}

#[allow(dead_code)]
fn object_params_for(
    object_id: ObjectId,
    size: u64,
    symbol_size: u16,
    max_block_size: usize,
) -> ObjectParams {
    let symbol_size_usize = usize::from(symbol_size.max(1));
    let total = usize::try_from(size).unwrap_or(usize::MAX);
    let mut blocks = 0u16;
    let mut max_k = 0usize;
    if total > 0 {
        let mut offset = 0usize;
        let block_limit = max_block_size.max(1);
        while offset < total {
            let len = (total - offset).min(block_limit);
            let k = len.div_ceil(symbol_size_usize);
            max_k = max_k.max(k);
            blocks = blocks.saturating_add(1);
            offset += len;
        }
    }
    ObjectParams::new(
        object_id,
        size,
        symbol_size,
        blocks,
        u16::try_from(max_k).unwrap_or(u16::MAX),
    )
}

#[allow(dead_code)]
fn decoders_from_manifest(
    manifest: &TransferManifest,
    config: &QuicConfig,
) -> Result<Vec<QuicEntryDecoder>, QuicTransportError> {
    let symbol_auth = config.symbol_auth_context()?;
    let symbol_auth_enabled = symbol_auth.is_some();
    manifest
        .entries
        .iter()
        .map(|entry| {
            let object_id = entry_object_id(&manifest.transfer_id, entry.index);
            let dconfig = DecodingConfig {
                symbol_size: config.symbol_size,
                max_block_size: config.max_block_size,
                repair_overhead: config.repair_overhead,
                min_overhead: 0,
                max_buffered_symbols: 0,
                block_timeout: Duration::from_secs(0),
                verify_auth: symbol_auth_enabled,
            };
            let mut pipeline = if let Some(context) = &symbol_auth {
                DecodingPipeline::with_auth(dconfig, context.clone())
            } else {
                DecodingPipeline::new(dconfig)
            };
            let params = object_params_for(
                object_id,
                entry.size,
                config.symbol_size,
                config.max_block_size,
            );
            pipeline.set_object_params(params).map_err(|err| {
                QuicTransportError::Control(format!(
                    "entry {} RaptorQ object metadata rejected: {err}",
                    entry.index
                ))
            })?;
            Ok(QuicEntryDecoder {
                index: entry.index,
                object_id,
                size: entry.size,
                pipeline: Some(pipeline),
                complete: entry.size == 0,
                data: Vec::new(),
                pending_decodes: Vec::new(),
            })
        })
        .collect()
}

/// Build bare entry decoders for the reliable source-stream path.
///
/// The reliable QUIC source stream delivers whole objects as ordered bytes and
/// never RaptorQ-decodes — `mark_quic_decoder_complete_from_stream` drops the
/// pipeline (`pipeline = None`) and fills `data` directly. Constructing the
/// RaptorQ pipeline here would run `set_object_params`, whose block-partition
/// check caps an object at `max_block_size * 256` (SBN u8) and fail-closed
/// rejects any source-stream object > ~128 MiB even though it is never decoded
/// (ASUP-E802 / br-asupersync-j73ili, MATRIX-201: 500M `object size ... exceeds
/// limit ...`). Skip the pipeline entirely on this path; the sha256 + Merkle
/// verification in `verify_and_commit` still fail-closes on any corruption.
fn source_stream_decoders_from_manifest(manifest: &TransferManifest) -> Vec<QuicEntryDecoder> {
    manifest
        .entries
        .iter()
        .map(|entry| QuicEntryDecoder {
            index: entry.index,
            object_id: entry_object_id(&manifest.transfer_id, entry.index),
            size: entry.size,
            pipeline: None,
            complete: entry.size == 0,
            data: Vec::new(),
            pending_decodes: Vec::new(),
        })
        .collect()
}

#[allow(dead_code)]
fn encoding_pipeline(config: &QuicConfig) -> EncodingPipeline {
    EncodingPipeline::new(
        EncodingConfig {
            repair_overhead: config.repair_overhead,
            max_block_size: config.max_block_size,
            symbol_size: config.symbol_size,
            encoding_parallelism: 1,
            decoding_parallelism: 1,
        },
        SymbolPool::new(PoolConfig::default()),
    )
}

#[allow(
    dead_code,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)]
fn initial_repair_per_block(data_len: usize, config: &QuicConfig) -> usize {
    let repair_overhead = quic_round0_loss_target_repair_overhead(config);
    if repair_overhead <= 1.0 {
        0
    } else {
        let block_source_symbols = data_len
            .min(config.max_block_size.max(1))
            .div_ceil(usize::from(config.symbol_size.max(1)))
            .max(1);
        ((block_source_symbols as f64) * (repair_overhead - 1.0)).ceil() as usize
    }
}

fn repair_batch_per_block(config: &QuicConfig) -> usize {
    let block_k = config
        .max_block_size
        .div_ceil(usize::from(config.symbol_size.max(1)))
        .max(1);
    (block_k / 4).max(16)
}

#[allow(dead_code)]
fn spray_symbol_round(
    cx: &Cx,
    conn: &mut QuicConnection,
    manifest: &TransferManifest,
    encoders: &mut [QuicEntryEncoder],
    pending: &std::collections::BTreeSet<u32>,
    config: &QuicConfig,
    symbol_auth: Option<&SecurityContext>,
    with_source: bool,
) -> Result<u64, QuicTransportError> {
    let tag = transfer_tag(&manifest.transfer_id);
    let mut sent = 0u64;
    let repair_batch = repair_batch_per_block(config);
    for entry in encoders
        .iter_mut()
        .filter(|entry| pending.contains(&entry.index))
    {
        cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
        let bytes = entry.memory_bytes()?;
        let already = entry.repair_cursor(0);
        let target_repair = if with_source {
            initial_repair_per_block(bytes.len(), config)
        } else {
            already.saturating_add(repair_batch)
        };
        let repair_count = target_repair.saturating_sub(already);
        if !with_source && repair_count == 0 {
            entry.set_repair_cursor(0, target_repair);
            continue;
        }

        let mut pipeline = encoding_pipeline(config);
        if with_source {
            for encoded in pipeline.encode_with_repair(entry.object_id, bytes, target_repair) {
                let symbol = encoded
                    .map_err(|err| QuicTransportError::Control(err.to_string()))?
                    .into_symbol();
                let auth_tag = symbol_auth.map(|ctx| *ctx.sign_symbol_tag(&symbol).as_bytes());
                send_symbol(cx, conn, &symbol, tag, entry.index, auth_tag)?;
                sent = sent.saturating_add(1);
            }
        } else {
            for encoded in
                pipeline.encode_repair_range(entry.object_id, bytes, already, repair_count)
            {
                let symbol = encoded
                    .map_err(|err| QuicTransportError::Control(err.to_string()))?
                    .into_symbol();
                let auth_tag = symbol_auth.map(|ctx| *ctx.sign_symbol_tag(&symbol).as_bytes());
                send_symbol(cx, conn, &symbol, tag, entry.index, auth_tag)?;
                sent = sent.saturating_add(1);
            }
        }
        entry.set_repair_cursor(0, target_repair);
    }
    Ok(sent)
}

#[allow(dead_code)]
async fn spray_streaming_symbol_round(
    cx: &Cx,
    conn: &mut QuicConnection,
    manifest: &TransferManifest,
    encoders: &mut [QuicEntryEncoder],
    pending: &std::collections::BTreeSet<u32>,
    config: &QuicConfig,
    symbol_auth: Option<&SecurityContext>,
    with_source: bool,
) -> Result<u64, QuicTransportError> {
    let tag = transfer_tag(&manifest.transfer_id);
    let mut sent = 0u64;
    let mut pacer = QuicSymbolPacer::from_connection_for_round(config, conn, with_source);
    let repair_batch = repair_batch_per_block(config);
    for entry in encoders
        .iter_mut()
        .filter(|entry| pending.contains(&entry.index))
    {
        cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
        for block_index in 0..entry.block_count(config)? {
            let sbn = u8::try_from(block_index).map_err(|_| QuicTransportError::TooLarge {
                size: entry.size(),
                max: u64::try_from(config.max_block_size.max(1))
                    .unwrap_or(u64::MAX)
                    .saturating_mul(u64::from(u8::MAX) + 1),
            })?;
            let block = entry.read_block(cx, sbn, config).await?;
            let already = entry.repair_cursor(sbn);
            let target_repair = if with_source {
                initial_repair_per_block(block.len(), config)
            } else {
                already.saturating_add(repair_batch)
            };
            let repair_count = target_repair.saturating_sub(already);
            if !with_source && repair_count == 0 {
                entry.set_repair_cursor(sbn, target_repair);
                continue;
            }

            let mut pipeline = encoding_pipeline(config);
            let encoded = if with_source {
                EitherNativeEncoding::Source(pipeline.encode_single_block_with_repair(
                    entry.object_id,
                    sbn,
                    &block,
                    target_repair,
                ))
            } else {
                EitherNativeEncoding::Repair(pipeline.encode_single_block_repair_range(
                    entry.object_id,
                    sbn,
                    &block,
                    already,
                    repair_count,
                ))
            };
            for symbol in encoded {
                let symbol = symbol
                    .map_err(|err| QuicTransportError::Control(err.to_string()))?
                    .into_symbol();
                let auth_tag = symbol_auth.map(|ctx| *ctx.sign_symbol_tag(&symbol).as_bytes());
                send_symbol(cx, conn, &symbol, tag, entry.index, auth_tag)?;
                sent = sent.saturating_add(1);
                pacer.after_symbol_sent(cx).await?;
            }
            entry.set_repair_cursor(sbn, target_repair);
        }
    }
    Ok(sent)
}

#[allow(dead_code)]
fn source_symbol_for_request(
    enc: &QuicEntryEncoder,
    request: QuicSourceSymbolRequest,
    config: &QuicConfig,
) -> Result<Symbol, QuicTransportError> {
    if request.entry != enc.index {
        return Err(QuicTransportError::Integrity(format!(
            "source request entry mismatch: request={}, encoder={}",
            request.entry, enc.index
        )));
    }
    let symbol_size = usize::from(config.symbol_size.max(1));
    let block = enc.in_memory_block(request.sbn, config)?;
    let block_len = block.len();
    let block_k = block_len.div_ceil(symbol_size).max(1);
    let esi = usize::try_from(request.esi).map_err(|_| {
        QuicTransportError::Integrity("source request ESI does not fit usize".to_string())
    })?;
    if esi >= block_k {
        return Err(QuicTransportError::Integrity(format!(
            "source request esi {} outside entry {} block {} K={}",
            request.esi, enc.index, request.sbn, block_k
        )));
    }

    let start = esi * symbol_size;
    let end = (start + symbol_size).min(block_len);
    let mut buffer = vec![0u8; symbol_size];
    if start < end {
        buffer[..end - start].copy_from_slice(&block[start..end]);
    }
    Ok(Symbol::new(
        SymbolId::new(enc.object_id, request.sbn, request.esi),
        buffer,
        SymbolKind::Source,
    ))
}

#[allow(dead_code)]
async fn streaming_source_symbol_for_request(
    cx: &Cx,
    enc: &QuicEntryEncoder,
    request: QuicSourceSymbolRequest,
    config: &QuicConfig,
) -> Result<Symbol, QuicTransportError> {
    if request.entry != enc.index {
        return Err(QuicTransportError::Integrity(format!(
            "source request entry mismatch: request={}, encoder={}",
            request.entry, enc.index
        )));
    }
    let block = enc.read_block(cx, request.sbn, config).await?;
    let symbol_size = usize::from(config.symbol_size.max(1));
    let block_len = block.len();
    let block_k = block_len.div_ceil(symbol_size).max(1);
    let esi = usize::try_from(request.esi).map_err(|_| {
        QuicTransportError::Integrity("source request ESI does not fit usize".to_string())
    })?;
    if esi >= block_k {
        return Err(QuicTransportError::Integrity(format!(
            "source request esi {} outside entry {} block {} K={}",
            request.esi, enc.index, request.sbn, block_k
        )));
    }

    let start = esi * symbol_size;
    let end = (start + symbol_size).min(block_len);
    let mut buffer = vec![0u8; symbol_size];
    if start < end {
        buffer[..end - start].copy_from_slice(&block[start..end]);
    }
    Ok(Symbol::new(
        SymbolId::new(enc.object_id, request.sbn, request.esi),
        buffer,
        SymbolKind::Source,
    ))
}

#[allow(dead_code)]
async fn send_source_symbol_requests(
    cx: &Cx,
    conn: &mut QuicConnection,
    manifest: &TransferManifest,
    encoders: &[QuicEntryEncoder],
    requests: &[QuicSourceSymbolRequest],
    config: &QuicConfig,
    symbol_auth: Option<&SecurityContext>,
) -> Result<u64, QuicTransportError> {
    let tag = transfer_tag(&manifest.transfer_id);
    let mut sent = 0u64;
    let mut pacer = QuicSymbolPacer::from_connection(config, conn);
    for request in requests {
        cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
        let enc = encoders
            .iter()
            .find(|entry| entry.index == request.entry)
            .ok_or_else(|| {
                QuicTransportError::Integrity(format!(
                    "receiver requested source symbol for unknown entry {}",
                    request.entry
                ))
            })?;
        let symbol = streaming_source_symbol_for_request(cx, enc, *request, config).await?;
        let auth_tag = symbol_auth.map(|ctx| *ctx.sign_symbol_tag(&symbol).as_bytes());
        send_symbol(cx, conn, &symbol, tag, request.entry, auth_tag)?;
        sent = sent.saturating_add(1);
        pacer.after_symbol_sent(cx).await?;
    }
    Ok(sent)
}

#[allow(dead_code)]
async fn send_block_repair_requests(
    cx: &Cx,
    conn: &mut QuicConnection,
    manifest: &TransferManifest,
    encoders: &mut [QuicEntryEncoder],
    requests: &[QuicBlockRepairRequest],
    config: &QuicConfig,
    symbol_auth: Option<&SecurityContext>,
) -> Result<u64, QuicTransportError> {
    let tag = transfer_tag(&manifest.transfer_id);
    let mut sent = 0u64;
    let mut pacer = QuicSymbolPacer::from_connection(config, conn);
    for request in requests {
        cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
        let enc = encoders
            .iter_mut()
            .find(|entry| entry.index == request.entry)
            .ok_or_else(|| {
                QuicTransportError::Integrity(format!(
                    "receiver requested repair block for unknown entry {}",
                    request.entry
                ))
            })?;
        let repair_count = usize::try_from(request.symbols).map_err(|_| {
            QuicTransportError::Integrity("repair symbol count does not fit usize".to_string())
        })?;
        let block = enc.read_block(cx, request.sbn, config).await?;
        let already = enc.repair_cursor(request.sbn);
        let target_repair = already.saturating_add(repair_count);
        quic_rqtrace(format_args!(
            "sender: repair_block entry={} sbn={} requested_symbols={} repair_cursor_start={} repair_cursor_target={}",
            request.entry, request.sbn, repair_count, already, target_repair
        ));
        let mut pipeline = encoding_pipeline(config);
        let sent_before_request = sent;
        for encoded in pipeline.encode_single_block_repair_range(
            enc.object_id,
            request.sbn,
            &block,
            already,
            repair_count,
        ) {
            let symbol = encoded
                .map_err(|err| QuicTransportError::Control(err.to_string()))?
                .into_symbol();
            let auth_tag = symbol_auth.map(|ctx| *ctx.sign_symbol_tag(&symbol).as_bytes());
            send_symbol(cx, conn, &symbol, tag, request.entry, auth_tag)?;
            sent = sent.saturating_add(1);
            pacer.after_symbol_sent(cx).await?;
        }
        let emitted_for_request = sent.saturating_sub(sent_before_request);
        if emitted_for_request != u64::from(request.symbols) {
            return Err(QuicTransportError::Integrity(format!(
                "sender emitted {emitted_for_request} repair symbols for receiver-requested deficit {} on entry {} block {}",
                request.symbols, request.entry, request.sbn
            )));
        }
        enc.set_repair_cursor(request.sbn, target_repair);
    }
    Ok(sent)
}

#[allow(dead_code)]
fn spray_initial_symbols(
    cx: &Cx,
    conn: &mut QuicConnection,
    manifest: &TransferManifest,
    encoders: &mut [QuicEntryEncoder],
    config: &QuicConfig,
    symbol_auth: Option<&SecurityContext>,
) -> Result<u64, QuicTransportError> {
    let pending = encoders
        .iter()
        .map(|entry| entry.index)
        .collect::<std::collections::BTreeSet<_>>();
    spray_symbol_round(
        cx,
        conn,
        manifest,
        encoders,
        &pending,
        config,
        symbol_auth,
        true,
    )
}

#[allow(dead_code)]
async fn send_repair_round_and_object_complete(
    cx: &Cx,
    conn: &mut QuicConnection,
    control: &mut QuicFrameTransport,
    manifest: &TransferManifest,
    encoders: &mut [QuicEntryEncoder],
    need: &QuicNeedMore,
    feedback_round: u32,
    config: &QuicConfig,
    symbol_auth: Option<&SecurityContext>,
) -> Result<u64, QuicTransportError> {
    validate_quic_manifest(manifest, config)?;
    if need.pending.is_empty() && need.repair_blocks.is_empty() && need.source_symbols.is_empty() {
        send_object_complete_for_round(cx, conn, control, feedback_round, 0)?;
        return Ok(0);
    }
    validate_need_more_feedback(manifest, config, need)?;
    let requested_repair_symbols = quic_repair_symbol_total(&need.repair_blocks);
    let sent = if !need.repair_blocks.is_empty() {
        send_block_repair_requests(
            cx,
            conn,
            manifest,
            encoders,
            &need.repair_blocks,
            config,
            symbol_auth,
        )
        .await?
    } else if need.source_symbols.is_empty() {
        return Err(QuicTransportError::Integrity(
            "receiver NeedMore listed pending entries without targeted repair/source deficits"
                .to_string(),
        ));
    } else {
        send_source_symbol_requests(
            cx,
            conn,
            manifest,
            encoders,
            &need.source_symbols,
            config,
            symbol_auth,
        )
        .await?
    };
    if !need.repair_blocks.is_empty() && sent != requested_repair_symbols {
        return Err(QuicTransportError::Integrity(format!(
            "sender emitted {sent} repair symbols for receiver-requested deficit {requested_repair_symbols}"
        )));
    }
    send_object_complete_for_round(cx, conn, control, feedback_round, sent)?;
    Ok(sent)
}

#[allow(dead_code)]
async fn read_source_entry_bytes(
    cx: &Cx,
    entry: &QuicSourceEntry,
    config: &QuicConfig,
) -> Result<Vec<u8>, QuicTransportError> {
    // Transitional bridge: the manifest hash pass is streaming, but the
    // current EncodingPipeline API still accepts an in-memory object payload.
    // Do not use this helper as bounded-memory evidence for B5.
    let capacity = usize::try_from(entry.size).map_err(|_| QuicTransportError::TooLarge {
        size: entry.size,
        max: config.max_transfer_bytes,
    })?;
    let mut file = crate::fs::File::open(&entry.abs_path)
        .await
        .map_err(|err| {
            QuicTransportError::Source(format!("{}: {err}", entry.abs_path.display()))
        })?;
    let mut bytes = Vec::with_capacity(capacity);
    let mut buf = vec![0_u8; config.chunk_size.max(1)];
    let mut read = 0u64;
    loop {
        cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
        let n = file.read(&mut buf).await.map_err(|err| {
            QuicTransportError::Source(format!("{}: {err}", entry.abs_path.display()))
        })?;
        if n == 0 {
            break;
        }
        read = read.saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
        if read > entry.size {
            return Err(QuicTransportError::Source(format!(
                "{} grew while preparing QUIC symbols (read {read} bytes, manifest size {})",
                entry.abs_path.display(),
                entry.size
            )));
        }
        bytes.extend_from_slice(&buf[..n]);
    }

    if read != entry.size {
        return Err(QuicTransportError::Source(format!(
            "{} changed while preparing QUIC symbols (read {read} bytes, manifest size {})",
            entry.abs_path.display(),
            entry.size
        )));
    }
    let got_sha = sha256_hex(&bytes);
    if got_sha != entry.sha256_hex {
        return Err(QuicTransportError::Integrity(format!(
            "{} changed while preparing QUIC symbols (sha256 {got_sha}, manifest {})",
            entry.abs_path.display(),
            entry.sha256_hex
        )));
    }
    Ok(bytes)
}

#[allow(dead_code)]
async fn encoders_from_prepared_source(
    cx: &Cx,
    prepared: &QuicPreparedSource,
    config: &QuicConfig,
) -> Result<Vec<QuicEntryEncoder>, QuicTransportError> {
    let config = prepared.effective_config(config);
    config.validate()?;
    let mut encoders = Vec::with_capacity(prepared.entries.len());
    for entry in &prepared.entries {
        cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
        encoders.push(QuicEntryEncoder::file(entry, &config)?);
    }
    Ok(encoders)
}

#[allow(dead_code)]
fn send_manifest_symbols_complete(
    cx: &Cx,
    conn: &mut QuicConnection,
    control: &mut QuicFrameTransport,
    manifest: &TransferManifest,
    encoders: &mut [QuicEntryEncoder],
    config: &QuicConfig,
) -> Result<u64, QuicTransportError> {
    validate_quic_manifest(manifest, config)?;
    let symbol_auth = config.symbol_auth_context()?;
    send_manifest(cx, conn, control, manifest)?;
    let symbols_sent =
        spray_initial_symbols(cx, conn, manifest, encoders, config, symbol_auth.as_ref())?;
    send_object_complete(cx, conn, control, symbols_sent)?;
    Ok(symbols_sent)
}

#[allow(dead_code)]
async fn send_prepared_source_manifest_symbols_complete(
    cx: &Cx,
    conn: &mut QuicConnection,
    control: &mut QuicFrameTransport,
    prepared: &QuicPreparedSource,
    config: &QuicConfig,
) -> Result<u64, QuicTransportError> {
    let config = prepared.effective_config(config);
    config.validate()?;
    validate_quic_manifest(&prepared.manifest, &config)?;
    let mut encoders = encoders_from_prepared_source(cx, prepared, &config).await?;
    let symbol_auth = config.symbol_auth_context()?;
    send_manifest(cx, conn, control, &prepared.manifest)?;
    let pending = encoders
        .iter()
        .map(|entry| entry.index)
        .collect::<std::collections::BTreeSet<_>>();
    let symbols_sent = spray_streaming_symbol_round(
        cx,
        conn,
        &prepared.manifest,
        &mut encoders,
        &pending,
        &config,
        symbol_auth.as_ref(),
        true,
    )
    .await?;
    send_object_complete(cx, conn, control, symbols_sent)?;
    Ok(symbols_sent)
}

#[allow(dead_code)]
fn finish_sender_transfer(
    cx: &Cx,
    conn: &mut QuicConnection,
    control: &mut QuicFrameTransport,
    manifest: &TransferManifest,
    peer: SocketAddr,
    receipt: ReceiveReceipt,
    symbols_sent: u64,
    feedback_rounds: u32,
) -> Result<SendReport, QuicTransportError> {
    send_close(cx, conn, control)?;
    if !receipt.committed {
        return Err(QuicTransportError::Integrity(
            receipt
                .reason
                .clone()
                .unwrap_or_else(|| "receiver did not commit".to_string()),
        ));
    }

    Ok(SendReport {
        transfer_id: manifest.transfer_id.clone(),
        bytes_sent: manifest.total_bytes,
        files: manifest_logical_files(manifest),
        symbols_sent,
        feedback_rounds,
        merkle_root_hex: manifest.merkle_root_hex.clone(),
        receipt,
        peer,
    })
}

#[allow(dead_code)]
async fn handle_sender_feedback_or_proof(
    cx: &Cx,
    conn: &mut QuicConnection,
    control: &mut QuicFrameTransport,
    state: &mut QuicSenderFeedbackState<'_>,
) -> Result<Option<SendReport>, QuicTransportError> {
    match receive_proof_or_need_more(cx, conn, control)? {
        QuicControlReply::Proof(receipt) => finish_sender_transfer(
            cx,
            conn,
            control,
            state.manifest,
            state.peer,
            receipt,
            state.symbols_sent,
            state.feedback_rounds,
        )
        .map(Some),
        QuicControlReply::NeedMore(need) => {
            state.feedback_rounds = state.feedback_rounds.saturating_add(1);
            state.observe_need_more(&need);
            trace_quic_aimd_feedback(cx, state);
            trace_quic_sender_need_more(
                cx,
                state.feedback_rounds,
                state.symbols_sent,
                state.sent_this_round(),
                &need,
                state.config,
                Some(state.aimd_rate_bps),
                None,
            );
            if need.pending.is_empty()
                && need.repair_blocks.is_empty()
                && need.source_symbols.is_empty()
            {
                trace_quic_sender_repair_round(
                    cx,
                    state.feedback_rounds,
                    quic_need_more_response_mode(&need),
                    state.symbols_sent,
                    0,
                    &need,
                );
                return Ok(None);
            }
            let round_config = state.next_round_config();
            let symbol_auth = round_config.symbol_auth_context()?;
            let previous_symbols_sent = state.symbols_sent;
            let response_mode = quic_need_more_response_mode(&need);
            let sent = send_repair_round_and_object_complete(
                cx,
                conn,
                control,
                state.manifest,
                state.encoders,
                &need,
                state.feedback_rounds,
                &round_config,
                symbol_auth.as_ref(),
            )
            .await?;
            state.mark_next_round_started(previous_symbols_sent, sent);
            trace_quic_sender_repair_round(
                cx,
                state.feedback_rounds,
                response_mode,
                previous_symbols_sent,
                sent,
                &need,
            );
            Ok(None)
        }
    }
}

#[allow(dead_code)]
fn receive_proof_close_and_report(
    cx: &Cx,
    conn: &mut QuicConnection,
    control: &mut QuicFrameTransport,
    manifest: &TransferManifest,
    peer: SocketAddr,
) -> Result<SendReport, QuicTransportError> {
    let receipt = match receive_proof_or_need_more(cx, conn, control)? {
        QuicControlReply::Proof(receipt) => receipt,
        QuicControlReply::NeedMore(need) => {
            return Err(QuicTransportError::Integrity(format!(
                "sender received NeedMore instead of proof for entries {:?}",
                need.pending
            )));
        }
    };
    finish_sender_transfer(cx, conn, control, manifest, peer, receipt, 0, 0)
}

#[allow(dead_code)]
fn feed_authenticated_symbol(
    decoder: &mut QuicEntryDecoder,
    auth_symbol: AuthenticatedSymbol,
) -> Result<bool, QuicTransportError> {
    if decoder.complete {
        return Ok(false);
    }
    let Some(pipeline) = decoder.pipeline.as_mut() else {
        return Ok(false);
    };
    match pipeline.feed(auth_symbol) {
        Ok(
            SymbolAcceptResult::Accepted { .. }
            | SymbolAcceptResult::DecodingStarted { .. }
            | SymbolAcceptResult::BlockComplete { .. },
        ) => Ok(true),
        Ok(SymbolAcceptResult::Rejected(RejectReason::AuthenticationFailed)) => Err(
            QuicTransportError::Integrity("symbol authentication failed".to_string()),
        ),
        Ok(SymbolAcceptResult::Duplicate | SymbolAcceptResult::Rejected(_)) => Ok(false),
        Err(err) => Err(QuicTransportError::Control(format!(
            "RaptorQ decoder rejected symbol: {err}"
        ))),
    }
}

fn materialize_decoder_data_if_complete(
    decoder: &mut QuicEntryDecoder,
) -> Result<(), QuicTransportError> {
    if !decoder
        .pipeline
        .as_ref()
        .is_some_and(DecodingPipeline::is_complete)
    {
        return Ok(());
    }
    let Some(pipeline) = decoder.pipeline.take() else {
        return Ok(());
    };
    let mut bytes = pipeline.into_data().map_err(|err| {
        QuicTransportError::Control(format!(
            "RaptorQ decoder completed but data assembly failed: {err}"
        ))
    })?;
    bytes.truncate(usize::try_from(decoder.size).unwrap_or(usize::MAX));
    decoder.data = bytes;
    decoder.complete = true;
    Ok(())
}

fn finish_quic_decode_outcome(
    decoder: &mut QuicEntryDecoder,
    outcome: BlockDecodeOutcome,
    decode_stats: &mut QuicDecodeStats,
    started_at: Instant,
) -> Result<bool, QuicTransportError> {
    let result = {
        let Some(pipeline) = decoder.pipeline.as_mut() else {
            return Ok(false);
        };
        pipeline.finish_decode_job(outcome)
    };
    match result {
        SymbolAcceptResult::BlockComplete { .. } => {
            decode_stats.record_completed_block(started_at.elapsed());
            materialize_decoder_data_if_complete(decoder)?;
            Ok(true)
        }
        SymbolAcceptResult::Rejected(RejectReason::AuthenticationFailed) => Err(
            QuicTransportError::Integrity("symbol authentication failed".to_string()),
        ),
        SymbolAcceptResult::Rejected(reason) => Err(QuicTransportError::Control(format!(
            "RaptorQ decoder rejected deferred block: {reason:?}"
        ))),
        SymbolAcceptResult::Accepted { .. }
        | SymbolAcceptResult::DecodingStarted { .. }
        | SymbolAcceptResult::Duplicate => Ok(false),
    }
}

fn feed_authenticated_symbol_deferred(
    cx: &Cx,
    decoder: &mut QuicEntryDecoder,
    auth_symbol: AuthenticatedSymbol,
    config: &QuicConfig,
    decode_stats: &mut QuicDecodeStats,
    allow_spawn_decode: bool,
    transfer_decode_width: usize,
) -> Result<bool, QuicTransportError> {
    if decoder.complete {
        return Ok(false);
    }
    let result = {
        let Some(pipeline) = decoder.pipeline.as_mut() else {
            return Ok(false);
        };
        pipeline.feed_deferred(auth_symbol)
    };
    let started_at = Instant::now();
    match result {
        Ok(DeferredSymbolAcceptResult::Immediate(SymbolAcceptResult::BlockComplete { .. })) => {
            decode_stats.record_completed_block(started_at.elapsed());
            materialize_decoder_data_if_complete(decoder)?;
            Ok(true)
        }
        Ok(DeferredSymbolAcceptResult::Immediate(
            SymbolAcceptResult::Accepted { .. } | SymbolAcceptResult::DecodingStarted { .. },
        )) => Ok(true),
        Ok(DeferredSymbolAcceptResult::Immediate(SymbolAcceptResult::Rejected(
            RejectReason::AuthenticationFailed,
        ))) => Err(QuicTransportError::Integrity(
            "symbol authentication failed".to_string(),
        )),
        Ok(DeferredSymbolAcceptResult::Immediate(
            SymbolAcceptResult::Duplicate | SymbolAcceptResult::Rejected(_),
        )) => Ok(false),
        Ok(DeferredSymbolAcceptResult::Decode(job)) => {
            let block_sbn = job.sbn();
            let entry_decode_width =
                quic_entry_decode_width_budget(decoder, config, transfer_decode_width);
            if !allow_spawn_decode
                || entry_decode_width <= 1
                || decoder.pending_decodes.len() >= entry_decode_width
            {
                let outcome = run_block_decode_job(job);
                return finish_quic_decode_outcome(decoder, outcome, decode_stats, started_at);
            }
            let fallback_job = job.clone();
            match cx.spawn_blocking(move |_child| run_block_decode_job(job)) {
                Ok(handle) => {
                    decoder.pending_decodes.push(QuicPendingDecode {
                        block_sbn,
                        started_at,
                        handle,
                    });
                    Ok(true)
                }
                Err(_) => {
                    let outcome = run_block_decode_job(fallback_job);
                    finish_quic_decode_outcome(decoder, outcome, decode_stats, started_at)
                }
            }
        }
        Err(err) => Err(QuicTransportError::Control(format!(
            "RaptorQ decoder rejected symbol: {err}"
        ))),
    }
}

async fn drain_ready_quic_decodes(
    cx: &Cx,
    decoders: &mut [QuicEntryDecoder],
    decode_stats: &mut QuicDecodeStats,
) -> Result<u64, QuicTransportError> {
    let mut completed = 0u64;
    for decoder in decoders {
        let mut i = 0usize;
        while i < decoder.pending_decodes.len() {
            if !decoder.pending_decodes[i].handle.is_finished() {
                i += 1;
                continue;
            }
            let mut pending = decoder.pending_decodes.swap_remove(i);
            let block_sbn = pending.block_sbn;
            let outcome = pending.handle.join(cx).await.map_err(|join_err| {
                QuicTransportError::Control(format!(
                    "decode task failed for entry {} block {}: {join_err:?}",
                    decoder.index, block_sbn
                ))
            })?;
            if finish_quic_decode_outcome(decoder, outcome, decode_stats, pending.started_at)? {
                completed = completed.saturating_add(1);
            }
        }
    }
    Ok(completed)
}

async fn join_all_quic_decodes(
    cx: &Cx,
    decoders: &mut [QuicEntryDecoder],
    decode_stats: &mut QuicDecodeStats,
) -> Result<u64, QuicTransportError> {
    let mut completed = 0u64;
    for decoder in decoders {
        while let Some(mut pending) = decoder.pending_decodes.pop() {
            let block_sbn = pending.block_sbn;
            let outcome = pending.handle.join(cx).await.map_err(|join_err| {
                QuicTransportError::Control(format!(
                    "decode task failed for entry {} block {}: {join_err:?}",
                    decoder.index, block_sbn
                ))
            })?;
            if finish_quic_decode_outcome(decoder, outcome, decode_stats, pending.started_at)? {
                completed = completed.saturating_add(1);
            }
        }
    }
    Ok(completed)
}

#[cfg_attr(not(feature = "tls"), allow(dead_code))]
fn finish_quic_streaming_decode_result(
    decoder: &mut QuicEntryDecoder,
    result: SymbolAcceptResult,
    elapsed: Duration,
    decode_stats: &mut QuicDecodeStats,
) -> Result<Option<QuicDecodedBlock>, QuicTransportError> {
    match result {
        SymbolAcceptResult::BlockComplete { block_sbn, data } => {
            decode_stats.record_completed_block(elapsed);
            decoder.complete = decoder
                .pipeline
                .as_ref()
                .is_some_and(DecodingPipeline::is_complete);
            Ok(Some(QuicDecodedBlock {
                entry: decoder.index,
                sbn: block_sbn,
                data,
            }))
        }
        SymbolAcceptResult::Accepted { .. } | SymbolAcceptResult::DecodingStarted { .. } => {
            Ok(None)
        }
        SymbolAcceptResult::Rejected(RejectReason::AuthenticationFailed) => Err(
            QuicTransportError::Integrity("symbol authentication failed".to_string()),
        ),
        SymbolAcceptResult::Duplicate | SymbolAcceptResult::Rejected(_) => Ok(None),
    }
}

#[cfg_attr(not(feature = "tls"), allow(dead_code))]
fn finish_quic_streaming_decode_outcome(
    cx: &Cx,
    decoder: &mut QuicEntryDecoder,
    outcome: BlockDecodeOutcome,
    config: &QuicConfig,
    decode_stats: &mut QuicDecodeStats,
    allow_spawn_decode: bool,
    transfer_decode_width: usize,
) -> Result<Option<QuicDecodedBlock>, QuicTransportError> {
    let elapsed = outcome.elapsed();
    let result = {
        let Some(pipeline) = decoder.pipeline.as_mut() else {
            return Ok(None);
        };
        pipeline.finish_decode_job_deferred(outcome)
    };
    match result {
        DeferredSymbolAcceptResult::Immediate(result) => {
            finish_quic_streaming_decode_result(decoder, result, elapsed, decode_stats)
        }
        DeferredSymbolAcceptResult::Decode(job) => dispatch_quic_streaming_decode_job(
            cx,
            decoder,
            job,
            config,
            decode_stats,
            allow_spawn_decode,
            transfer_decode_width,
        ),
    }
}

#[cfg_attr(not(feature = "tls"), allow(dead_code))]
fn dispatch_quic_streaming_decode_job(
    cx: &Cx,
    decoder: &mut QuicEntryDecoder,
    job: BlockDecodeJob,
    config: &QuicConfig,
    decode_stats: &mut QuicDecodeStats,
    allow_spawn_decode: bool,
    transfer_decode_width: usize,
) -> Result<Option<QuicDecodedBlock>, QuicTransportError> {
    let block_sbn = job.sbn();
    if decoder.complete
        || decoder.pipeline.is_none()
        || quic_block_decode_pending(decoder, block_sbn)
    {
        return Ok(None);
    }

    let entry_decode_width = quic_entry_decode_width_budget(decoder, config, transfer_decode_width);
    if !allow_spawn_decode
        || entry_decode_width <= 1
        || decoder.pending_decodes.len() >= entry_decode_width
    {
        return finish_quic_streaming_decode_outcome(
            cx,
            decoder,
            run_block_decode_job(job),
            config,
            decode_stats,
            allow_spawn_decode,
            transfer_decode_width,
        );
    }

    let fallback_job = job.clone();
    match cx.spawn_blocking(move |_child| run_block_decode_job(job)) {
        Ok(handle) => {
            decoder.pending_decodes.push(QuicPendingDecode {
                block_sbn,
                started_at: Instant::now(),
                handle,
            });
            Ok(None)
        }
        Err(_) => finish_quic_streaming_decode_outcome(
            cx,
            decoder,
            run_block_decode_job(fallback_job),
            config,
            decode_stats,
            allow_spawn_decode,
            transfer_decode_width,
        ),
    }
}

#[cfg_attr(not(feature = "tls"), allow(dead_code))]
fn feed_authenticated_symbol_take_block_deferred(
    cx: &Cx,
    decoder: &mut QuicEntryDecoder,
    auth_symbol: AuthenticatedSymbol,
    config: &QuicConfig,
    decode_stats: &mut QuicDecodeStats,
    allow_spawn_decode: bool,
    transfer_decode_width: usize,
) -> Result<(bool, Option<QuicDecodedBlock>), QuicTransportError> {
    if decoder.complete {
        return Ok((false, None));
    }
    let result = {
        let Some(pipeline) = decoder.pipeline.as_mut() else {
            return Ok((false, None));
        };
        pipeline.feed_streaming_block_deferred(auth_symbol)
    };
    let started_at = Instant::now();
    match result {
        Ok(DeferredSymbolAcceptResult::Immediate(SymbolAcceptResult::BlockComplete {
            block_sbn,
            data,
        })) => {
            decode_stats.record_completed_block(started_at.elapsed());
            decoder.complete = decoder
                .pipeline
                .as_ref()
                .is_some_and(DecodingPipeline::is_complete);
            Ok((
                true,
                Some(QuicDecodedBlock {
                    entry: decoder.index,
                    sbn: block_sbn,
                    data,
                }),
            ))
        }
        Ok(DeferredSymbolAcceptResult::Immediate(
            SymbolAcceptResult::Accepted { .. } | SymbolAcceptResult::DecodingStarted { .. },
        )) => Ok((true, None)),
        Ok(DeferredSymbolAcceptResult::Immediate(SymbolAcceptResult::Rejected(
            RejectReason::AuthenticationFailed,
        ))) => Err(QuicTransportError::Integrity(
            "symbol authentication failed".to_string(),
        )),
        Ok(DeferredSymbolAcceptResult::Immediate(
            SymbolAcceptResult::Duplicate | SymbolAcceptResult::Rejected(_),
        )) => Ok((false, None)),
        Ok(DeferredSymbolAcceptResult::Decode(job)) => Ok((
            true,
            dispatch_quic_streaming_decode_job(
                cx,
                decoder,
                job,
                config,
                decode_stats,
                allow_spawn_decode,
                transfer_decode_width,
            )?,
        )),
        Err(err) => Err(QuicTransportError::Control(format!(
            "RaptorQ decoder rejected symbol: {err}"
        ))),
    }
}

#[cfg_attr(not(feature = "tls"), allow(dead_code))]
async fn drain_ready_quic_decodes_with_blocks(
    cx: &Cx,
    decoders: &mut [QuicEntryDecoder],
    config: &QuicConfig,
    decode_stats: &mut QuicDecodeStats,
    allow_spawn_decode: bool,
    transfer_decode_width: usize,
) -> Result<Vec<QuicDecodedBlock>, QuicTransportError> {
    let mut completed = Vec::new();
    for decoder in decoders {
        let mut i = 0usize;
        while i < decoder.pending_decodes.len() {
            if !decoder.pending_decodes[i].handle.is_finished() {
                i += 1;
                continue;
            }
            let mut pending = decoder.pending_decodes.swap_remove(i);
            let block_sbn = pending.block_sbn;
            let outcome = pending.handle.join(cx).await.map_err(|join_err| {
                QuicTransportError::Control(format!(
                    "decode task failed for entry {} block {}: {join_err:?}",
                    decoder.index, block_sbn
                ))
            })?;
            if let Some(block) = finish_quic_streaming_decode_outcome(
                cx,
                decoder,
                outcome,
                config,
                decode_stats,
                allow_spawn_decode,
                transfer_decode_width,
            )? {
                completed.push(block);
            }
        }
    }
    Ok(completed)
}

#[cfg_attr(not(feature = "tls"), allow(dead_code))]
async fn join_all_quic_decodes_with_blocks(
    cx: &Cx,
    decoders: &mut [QuicEntryDecoder],
    config: &QuicConfig,
    decode_stats: &mut QuicDecodeStats,
    transfer_decode_width: usize,
) -> Result<Vec<QuicDecodedBlock>, QuicTransportError> {
    let mut completed = Vec::new();
    for decoder in decoders {
        while let Some(mut pending) = decoder.pending_decodes.pop() {
            let block_sbn = pending.block_sbn;
            let outcome = pending.handle.join(cx).await.map_err(|join_err| {
                QuicTransportError::Control(format!(
                    "decode task failed for entry {} block {}: {join_err:?}",
                    decoder.index, block_sbn
                ))
            })?;
            if let Some(block) = finish_quic_streaming_decode_outcome(
                cx,
                decoder,
                outcome,
                config,
                decode_stats,
                true,
                transfer_decode_width,
            )? {
                completed.push(block);
            }
        }
    }
    Ok(completed)
}

fn authenticated_symbol_from_envelope(
    envelope: &QuicSymbolEnvelope,
    object_id: ObjectId,
    auth_required: bool,
) -> Result<AuthenticatedSymbol, QuicTransportError> {
    let symbol = envelope_to_symbol(envelope, object_id);
    if auth_required {
        let tag = envelope.auth_tag.ok_or_else(|| {
            QuicTransportError::Integrity("authenticated symbol envelope missing tag".to_string())
        })?;
        return Ok(AuthenticatedSymbol::from_parts(
            symbol,
            AuthenticationTag::from_bytes(tag),
        ));
    }
    Ok(AuthenticatedSymbol::new_unauthenticated(symbol))
}

fn verified_authenticated_symbol_from_envelope(
    envelope: &QuicSymbolEnvelope,
    object_id: ObjectId,
    symbol_auth: Option<&SecurityContext>,
) -> Result<AuthenticatedSymbol, QuicTransportError> {
    let mut authenticated =
        authenticated_symbol_from_envelope(envelope, object_id, symbol_auth.is_some())?;
    if let Some(context) = symbol_auth {
        context
            .verify_authenticated_symbol(&mut authenticated)
            .map_err(|_| {
                QuicTransportError::Integrity("symbol authentication failed".to_string())
            })?;
    }
    Ok(authenticated)
}

fn primary_quic_receive_aggregator(remote: impl Into<String>) -> MultipathAggregator {
    let aggregator = MultipathAggregator::new(AggregatorConfig {
        reorder: ReordererConfig {
            immediate_delivery: true,
            ..ReordererConfig::default()
        },
        ..AggregatorConfig::default()
    });
    aggregator.paths().register(TransportPath::new(
        QUIC_PRIMARY_RECEIVE_PATH_ID,
        "quic-primary",
        remote,
    ));
    aggregator
}

fn authenticated_symbol_with_existing_tag(
    symbol: Symbol,
    source: &AuthenticatedSymbol,
) -> AuthenticatedSymbol {
    let tag = *source.tag();
    if tag.is_zero() {
        AuthenticatedSymbol::new_unauthenticated(symbol)
    } else {
        AuthenticatedSymbol::from_parts(symbol, tag)
    }
}

fn trace_aggregated_symbol_result(
    cx: Option<&Cx>,
    entry: u32,
    path: PathId,
    symbol: SymbolId,
    ready: usize,
    accepted: u64,
    duplicate: bool,
) {
    let Some(cx) = cx else {
        return;
    };
    let entry = entry.to_string();
    let path = path.to_string();
    let symbol = symbol.to_string();
    let ready = ready.to_string();
    let accepted = accepted.to_string();
    let duplicate = duplicate.to_string();
    cx.trace_with_fields(
        "atp_quic.receive.aggregate_symbol",
        &[
            ("entry", entry.as_str()),
            ("path", path.as_str()),
            ("symbol", symbol.as_str()),
            ("ready", ready.as_str()),
            ("accepted", accepted.as_str()),
            ("duplicate", duplicate.as_str()),
        ],
    );
}

#[derive(Clone, Copy)]
struct QuicReceiveAggregation<'a> {
    aggregator: &'a MultipathAggregator,
    path: PathId,
    now: Time,
    trace_cx: Option<&'a Cx>,
}

impl<'a> QuicReceiveAggregation<'a> {
    fn new(aggregator: &'a MultipathAggregator, path: PathId, now: Time) -> Self {
        Self {
            aggregator,
            path,
            now,
            trace_cx: None,
        }
    }

    fn with_trace(mut self, cx: &'a Cx) -> Self {
        self.trace_cx = Some(cx);
        self
    }
}

fn feed_aggregated_symbol_for_entry(
    decoders: &mut [QuicEntryDecoder],
    entry: u32,
    auth_symbol: AuthenticatedSymbol,
    receive: QuicReceiveAggregation<'_>,
) -> Result<u64, QuicTransportError> {
    let decoder = decoders
        .iter_mut()
        .find(|decoder| decoder.index == entry)
        .ok_or_else(|| {
            QuicTransportError::Integrity(format!("symbol for unknown manifest entry {entry}"))
        })?;

    let source_symbol_id = auth_symbol.symbol().id();
    let source_tag = *auth_symbol.tag();
    let aggregated =
        receive
            .aggregator
            .process(auth_symbol.symbol().clone(), receive.path, receive.now);
    let duplicate = aggregated.was_duplicate;
    let ready = aggregated.ready.len();
    let mut accepted = 0u64;
    for symbol in aggregated.ready {
        if !source_tag.is_zero() && symbol.id() != source_symbol_id {
            return Err(QuicTransportError::Integrity(
                "authenticated QUIC receive aggregation emitted a buffered symbol without its original tag"
                    .to_string(),
            ));
        }
        let ready = authenticated_symbol_with_existing_tag(symbol, &auth_symbol);
        if feed_authenticated_symbol(decoder, ready)? {
            accepted = accepted.saturating_add(1);
        }
    }
    trace_aggregated_symbol_result(
        receive.trace_cx,
        entry,
        receive.path,
        source_symbol_id,
        ready,
        accepted,
        duplicate,
    );
    Ok(accepted)
}

fn feed_aggregated_symbol_for_entry_deferred(
    cx: &Cx,
    decoders: &mut [QuicEntryDecoder],
    entry: u32,
    auth_symbol: AuthenticatedSymbol,
    receive: QuicReceiveAggregation<'_>,
    config: &QuicConfig,
    decode_stats: &mut QuicDecodeStats,
) -> Result<u64, QuicTransportError> {
    let decoder_index = decoders
        .iter()
        .position(|decoder| decoder.index == entry)
        .ok_or_else(|| {
            QuicTransportError::Integrity(format!("symbol for unknown manifest entry {entry}"))
        })?;

    let source_symbol_id = auth_symbol.symbol().id();
    let source_tag = *auth_symbol.tag();
    let aggregated =
        receive
            .aggregator
            .process(auth_symbol.symbol().clone(), receive.path, receive.now);
    let duplicate = aggregated.was_duplicate;
    let ready = aggregated.ready.len();
    let mut accepted = 0u64;
    for symbol in aggregated.ready {
        if !source_tag.is_zero() && symbol.id() != source_symbol_id {
            return Err(QuicTransportError::Integrity(
                "authenticated QUIC receive aggregation emitted a buffered symbol without its original tag"
                    .to_string(),
            ));
        }
        let ready = authenticated_symbol_with_existing_tag(symbol, &auth_symbol);
        let transfer_decode_width = quic_transfer_decode_width(decoders, config);
        let allow_spawn_decode = quic_pending_decode_jobs(decoders) < transfer_decode_width;
        if feed_authenticated_symbol_deferred(
            cx,
            &mut decoders[decoder_index],
            ready,
            config,
            decode_stats,
            allow_spawn_decode,
            transfer_decode_width,
        )? {
            accepted = accepted.saturating_add(1);
        }
    }
    trace_aggregated_symbol_result(
        receive.trace_cx,
        entry,
        receive.path,
        source_symbol_id,
        ready,
        accepted,
        duplicate,
    );
    Ok(accepted)
}

#[allow(dead_code)]
fn drain_symbol_datagrams(
    conn: &mut QuicConnection,
    manifest: &TransferManifest,
    decoders: &mut [QuicEntryDecoder],
    config: &QuicConfig,
) -> Result<u64, QuicTransportError> {
    let aggregator = primary_quic_receive_aggregator("quic-scaffold-peer");
    let receive =
        QuicReceiveAggregation::new(&aggregator, QUIC_PRIMARY_RECEIVE_PATH_ID, Time::ZERO);
    drain_symbol_datagrams_with_aggregator(conn, manifest, decoders, config, receive)
}

#[allow(dead_code)]
fn drain_symbol_datagrams_with_aggregator(
    conn: &mut QuicConnection,
    manifest: &TransferManifest,
    decoders: &mut [QuicEntryDecoder],
    config: &QuicConfig,
    receive: QuicReceiveAggregation<'_>,
) -> Result<u64, QuicTransportError> {
    let symbol_auth = config.symbol_auth_context()?;
    let auth_required = symbol_auth.is_some();
    let tag = transfer_tag(&manifest.transfer_id);
    let mut accepted = 0u64;
    while let Some(envelope) = recv_symbol_envelope(conn, auth_required)? {
        if envelope.transfer_tag != tag {
            return Err(QuicTransportError::Integrity(format!(
                "symbol transfer tag mismatch: got {}, expected {tag}",
                envelope.transfer_tag
            )));
        }
        if envelope.payload.len() != usize::from(config.symbol_size) {
            return Err(QuicTransportError::Integrity(format!(
                "symbol payload has {} bytes, expected {}",
                envelope.payload.len(),
                config.symbol_size
            )));
        }
        let decoder = decoders
            .iter()
            .find(|decoder| decoder.index == envelope.entry)
            .ok_or_else(|| {
                QuicTransportError::Integrity(format!(
                    "symbol for unknown manifest entry {}",
                    envelope.entry
                ))
            })?;
        let auth_symbol = verified_authenticated_symbol_from_envelope(
            &envelope,
            decoder.object_id,
            symbol_auth.as_ref(),
        )?;
        accepted = accepted.saturating_add(feed_aggregated_symbol_for_entry(
            decoders,
            envelope.entry,
            auth_symbol,
            receive,
        )?);
    }
    Ok(accepted)
}

#[allow(dead_code)]
fn assemble_completed_entries(decoders: &mut [QuicEntryDecoder]) -> QuicDecodeStats {
    let mut stats = QuicDecodeStats::default();
    for decoder in decoders {
        if decoder.complete
            || !decoder
                .pipeline
                .as_ref()
                .is_some_and(DecodingPipeline::is_complete)
        {
            continue;
        }
        let Some(pipeline) = decoder.pipeline.take() else {
            continue;
        };
        let started_at = Instant::now();
        if let Ok(mut bytes) = pipeline.into_data() {
            stats.record_completed_block(started_at.elapsed());
            bytes.truncate(usize::try_from(decoder.size).unwrap_or(usize::MAX));
            decoder.data = bytes;
            decoder.complete = true;
        }
    }
    stats
}

#[allow(dead_code)]
fn pending_entries(decoders: &[QuicEntryDecoder]) -> Vec<u32> {
    decoders
        .iter()
        .filter(|decoder| !decoder.complete)
        .map(|decoder| decoder.index)
        .collect()
}

fn quic_decoder_block_count(decoder: &QuicEntryDecoder, config: &QuicConfig) -> usize {
    if decoder.size == 0 {
        return 0;
    }
    let max_block_size = u64::try_from(config.max_block_size.max(1)).unwrap_or(u64::MAX);
    decoder
        .size
        .div_ceil(max_block_size)
        .min(u64::from(u8::MAX) + 1)
        .try_into()
        .unwrap_or(usize::from(u8::MAX) + 1)
}

#[allow(dead_code)]
fn quic_decoder_block_source_symbols(
    decoder: &QuicEntryDecoder,
    sbn: u8,
    config: &QuicConfig,
) -> usize {
    let max_block_size = u64::try_from(config.max_block_size.max(1)).unwrap_or(u64::MAX);
    let start = u64::from(sbn).saturating_mul(max_block_size);
    if start >= decoder.size {
        return 0;
    }
    let len = decoder.size.saturating_sub(start).min(max_block_size);
    let symbol_size = u64::from(config.symbol_size.max(1));
    usize::try_from(len.div_ceil(symbol_size).max(1)).unwrap_or(usize::MAX)
}

#[allow(dead_code)]
fn quic_targeted_repair_symbols(
    base_deficit: usize,
    round_loss_fraction: Option<f64>,
    remaining_round_budget: usize,
) -> usize {
    quic_targeted_repair_symbols_for_round(
        base_deficit,
        round_loss_fraction,
        remaining_round_budget,
        0,
        base_deficit,
    )
}

fn quic_feedback_round_extra_repair_symbols(block_source_n: usize, feedback_round: u32) -> usize {
    if feedback_round <= QUIC_FEEDBACK_REPAIR_ESCALATE_AFTER_ROUNDS || block_source_n == 0 {
        return 0;
    }
    let shift = feedback_round
        .saturating_sub(QUIC_FEEDBACK_REPAIR_ESCALATE_AFTER_ROUNDS + 1)
        .min(6);
    let extra = 1usize << shift;
    extra.min(
        block_source_n
            .max(1)
            .min(QUIC_FEEDBACK_REPAIR_ESCALATE_MAX_EXTRA_PER_BLOCK),
    )
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)]
fn quic_first_repair_burst_target_symbols(
    base_deficit: usize,
    block_source_n: usize,
    round_loss_fraction: Option<f64>,
    feedback_round: u32,
) -> usize {
    if base_deficit == 0 {
        return 0;
    }
    if feedback_round != 1 || block_source_n < QUIC_FEEDBACK_FIRST_REPAIR_BURST_MIN_BLOCK_SYMBOLS {
        return base_deficit;
    }
    let Some(loss) = round_loss_fraction.filter(|loss| loss.is_finite()) else {
        return base_deficit;
    };
    if loss <= 0.0 {
        return base_deficit;
    }
    let effective_loss = loss
        .max(QUIC_FEEDBACK_REPAIR_LOSS_ENABLE_MIN)
        .min(QUIC_FEEDBACK_REPAIR_MAX_OVERHEAD);
    let delivery_fraction = (1.0 - effective_loss).max(0.10);
    let expected_lost_symbols = (block_source_n as f64) * effective_loss / delivery_fraction;
    let capacity_extra = (expected_lost_symbols
        + QUIC_FEEDBACK_FIRST_REPAIR_BURST_Z_ALPHA * expected_lost_symbols.sqrt()
        + QUIC_FEEDBACK_FIRST_REPAIR_BURST_MARGIN_SYMBOLS as f64)
        .ceil() as usize;
    let extra = capacity_extra
        .min(QUIC_FEEDBACK_FIRST_REPAIR_BURST_MAX_EXTRA_PER_BLOCK)
        .min(block_source_n);
    base_deficit.saturating_add(extra)
}

fn quic_targeted_repair_symbols_for_round(
    base_deficit: usize,
    round_loss_fraction: Option<f64>,
    remaining_round_budget: usize,
    feedback_round: u32,
    block_source_n: usize,
) -> usize {
    if base_deficit == 0 {
        return 0;
    }
    let loss_compensated_target =
        quic_loss_compensated_repair_target_symbols(base_deficit, round_loss_fraction);
    let escalated_target = base_deficit.saturating_add(quic_feedback_round_extra_repair_symbols(
        block_source_n,
        feedback_round,
    ));
    let first_repair_burst_target = quic_first_repair_burst_target_symbols(
        base_deficit,
        block_source_n,
        round_loss_fraction,
        feedback_round,
    );
    let target = base_deficit
        .max(loss_compensated_target)
        .max(escalated_target)
        .max(first_repair_burst_target)
        .min(MAX_REPAIR_SYMBOLS_PER_FEEDBACK_ROUND);
    if remaining_round_budget == 0 {
        target
    } else {
        target.min(remaining_round_budget)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct QuicRepairRequestAccounting {
    base_deficit_symbols: u64,
    loss_compensated_target_symbols: u64,
    requested_repair_symbols: u64,
    request_gap_to_target_symbols: u64,
}

#[allow(dead_code)]
fn block_repair_requests(
    decoders: &[QuicEntryDecoder],
    config: &QuicConfig,
    limit: usize,
    round_loss_fraction: Option<f64>,
) -> Vec<QuicBlockRepairRequest> {
    block_repair_requests_with_accounting(decoders, config, limit, round_loss_fraction, 0).0
}

fn block_repair_requests_with_accounting(
    decoders: &[QuicEntryDecoder],
    config: &QuicConfig,
    limit: usize,
    round_loss_fraction: Option<f64>,
    feedback_round: u32,
) -> (Vec<QuicBlockRepairRequest>, QuicRepairRequestAccounting) {
    let mut requests = Vec::new();
    let mut accounting = QuicRepairRequestAccounting::default();
    let mut requested_symbols = 0usize;
    'decoders: for decoder in decoders {
        if decoder.complete {
            continue;
        }
        let Some(pipeline) = decoder.pipeline.as_ref() else {
            continue;
        };
        let remaining = if limit == 0 {
            0
        } else {
            limit.saturating_sub(requested_symbols)
        };
        if limit != 0 && remaining == 0 {
            break;
        }

        let mut missing_by_block = std::collections::BTreeMap::<u8, usize>::new();
        for MissingSourceSymbol { sbn, .. } in pipeline.missing_source_symbols(0) {
            *missing_by_block.entry(sbn).or_default() += 1;
        }

        for block_index in 0..quic_decoder_block_count(decoder, config) {
            if limit != 0 && requested_symbols >= limit {
                break 'decoders;
            }
            if requests.len() >= MAX_REPAIR_BLOCK_REQUESTS_PER_FEEDBACK_ROUND {
                break 'decoders;
            }
            let sbn = u8::try_from(block_index).unwrap_or(u8::MAX);
            let status_deficit = pipeline.block_status(sbn).and_then(|status| {
                if matches!(
                    status.state,
                    BlockStateKind::Decoded | BlockStateKind::Decoding
                ) || status.symbols_needed == 0
                {
                    None
                } else {
                    status
                        .rank_deficit
                        .filter(|deficit| *deficit > 0)
                        .or_else(|| {
                            Some(
                                status
                                    .symbols_needed
                                    .saturating_sub(status.symbols_received)
                                    .max(1),
                            )
                        })
                }
            });
            let missing_source_symbols = missing_by_block.get(&sbn).copied().unwrap_or(0);
            let raw_base_deficit = status_deficit.unwrap_or(missing_source_symbols);
            if raw_base_deficit == 0 {
                continue;
            }
            let block_source_n = quic_decoder_block_source_symbols(decoder, sbn, config);
            let loss_compensated_target = quic_targeted_repair_symbols_for_round(
                raw_base_deficit.min(MAX_REPAIR_SYMBOLS_PER_FEEDBACK_ROUND),
                round_loss_fraction,
                0,
                feedback_round,
                block_source_n,
            );
            let base_deficit = raw_base_deficit.min(MAX_REPAIR_SYMBOLS_PER_FEEDBACK_ROUND);
            let remaining = if limit == 0 {
                0
            } else {
                limit.saturating_sub(requested_symbols)
            };
            let mut deficit = quic_targeted_repair_symbols_for_round(
                base_deficit,
                round_loss_fraction,
                remaining,
                feedback_round,
                block_source_n,
            )
            .min(MAX_REPAIR_SYMBOLS_PER_FEEDBACK_ROUND);
            if deficit == 0 {
                continue;
            }
            if limit != 0 {
                deficit = deficit.min(limit.saturating_sub(requested_symbols));
            }
            if deficit == 0 {
                break 'decoders;
            }
            requested_symbols = requested_symbols.saturating_add(deficit);
            accounting.base_deficit_symbols = accounting
                .base_deficit_symbols
                .saturating_add(u64::try_from(raw_base_deficit).unwrap_or(u64::MAX));
            accounting.loss_compensated_target_symbols = accounting
                .loss_compensated_target_symbols
                .saturating_add(u64::try_from(loss_compensated_target).unwrap_or(u64::MAX));
            accounting.requested_repair_symbols = accounting
                .requested_repair_symbols
                .saturating_add(u64::try_from(deficit).unwrap_or(u64::MAX));
            requests.push(QuicBlockRepairRequest {
                entry: decoder.index,
                sbn,
                symbols: u32::try_from(deficit).unwrap_or(u32::MAX),
            });
        }
    }
    accounting.request_gap_to_target_symbols = accounting
        .loss_compensated_target_symbols
        .saturating_sub(accounting.requested_repair_symbols);
    (requests, accounting)
}

#[allow(dead_code)]
fn source_symbol_requests(
    decoders: &[QuicEntryDecoder],
    limit: usize,
) -> Vec<QuicSourceSymbolRequest> {
    let mut requests = Vec::new();
    for decoder in decoders {
        if decoder.complete {
            continue;
        }
        let Some(pipeline) = decoder.pipeline.as_ref() else {
            continue;
        };
        let remaining = if limit == 0 {
            0
        } else {
            limit.saturating_sub(requests.len())
        };
        if limit != 0 && remaining == 0 {
            break;
        }
        requests.extend(pipeline.missing_source_symbols(remaining).into_iter().map(
            |MissingSourceSymbol { sbn, esi }| QuicSourceSymbolRequest {
                entry: decoder.index,
                sbn,
                esi,
            },
        ));
        if limit != 0 && requests.len() >= limit {
            break;
        }
    }
    requests
}

#[allow(dead_code)]
fn verify_in_memory_receipt(
    manifest: &TransferManifest,
    decoders: &[QuicEntryDecoder],
) -> ReceiveReceipt {
    let mut decoded = std::collections::HashMap::new();
    for decoder in decoders {
        decoded.insert(decoder.index, decoder.data.clone());
    }

    let mut sha_ok = true;
    let mut received = 0u64;
    for entry in &manifest.entries {
        let Some(bytes) = decoded.get(&entry.index) else {
            sha_ok = false;
            continue;
        };
        received = received.saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) != entry.size
            || sha256_hex(bytes) != entry.sha256_hex
        {
            sha_ok = false;
        }
        for member in &entry.members {
            match packed_member_slice(bytes, member) {
                Some(slice) if sha256_hex(slice) == member.sha256_hex => {}
                _ => sha_ok = false,
            }
        }
    }

    // Logical (member-flattened) reconstruction: the merkle root is computed
    // over logical files on both sides, invariant to packing.
    let mut rebuilt: Vec<(String, Vec<u8>)> = Vec::with_capacity(manifest.entries.len());
    for entry in &manifest.entries {
        let bytes = decoded.get(&entry.index).cloned().unwrap_or_default();
        if entry.members.is_empty() {
            rebuilt.push((entry.rel_path.clone(), bytes));
        } else {
            for member in &entry.members {
                let slice = packed_member_slice(&bytes, member)
                    .map(<[u8]>::to_vec)
                    .unwrap_or_default();
                rebuilt.push((member.rel_path.clone(), slice));
            }
        }
    }
    let merkle_ok = flat_merkle_root_from_slices(
        rebuilt
            .iter()
            .map(|(rel_path, bytes)| (rel_path.as_str(), bytes.as_slice())),
    ) == manifest.merkle_root_hex;
    let metadata_ok = manifest_metadata_commitment(manifest) == manifest.metadata_root_hex;
    let committed = sha_ok && merkle_ok && metadata_ok && pending_entries(decoders).is_empty();
    let committed_paths = if committed {
        manifest
            .entries
            .iter()
            .map(|entry| format!("/quic-memory/{}/{}", manifest.root_name, entry.rel_path))
            .collect()
    } else {
        Vec::new()
    };
    ReceiveReceipt {
        committed,
        bytes_received: received,
        files: manifest_logical_files(manifest),
        sha_ok,
        merkle_ok,
        symbols_accepted: 0,
        feedback_rounds: 0,
        decode_count: 0,
        decode_micros: 0,
        reason: if committed {
            None
        } else if !sha_ok {
            Some("per-entry SHA-256 mismatch".to_string())
        } else if !merkle_ok {
            Some("merkle-root mismatch".to_string())
        } else if !metadata_ok {
            Some("metadata commitment mismatch".to_string())
        } else {
            Some("entries still pending".to_string())
        },
        committed_paths,
    }
}

/// Slice one packed member's byte range out of a decoded pack entry.
fn packed_member_slice<'a>(bytes: &'a [u8], member: &PackedMember) -> Option<&'a [u8]> {
    let start = usize::try_from(member.offset).ok()?;
    let len = usize::try_from(member.len).ok()?;
    let end = start.checked_add(len)?;
    bytes.get(start..end)
}

/// Logical file count: packed entries contribute one per member.
fn manifest_logical_files(manifest: &TransferManifest) -> u32 {
    let count = manifest.entries.iter().fold(0usize, |acc, entry| {
        acc.saturating_add(entry.members.len().max(1))
    });
    u32::try_from(count).unwrap_or(u32::MAX)
}

/// Maximum control-stream chunk read per decode attempt.
#[allow(dead_code)]
const CONTROL_READ_CHUNK: usize = 64 * 1024;

/// ATP frame transport over one QUIC bidirectional control stream.
///
/// This is the reliable control-plane half B2/B3 need: canonical ATP
/// [`Frame`] wire bytes are queued
/// through the A6 control-stream API, and inbound bytes are incrementally
/// decoded with the same [`AtpFrameCodec`] TCP uses. It is deliberately
/// non-blocking: `try_recv` returns `Ok(None)` when the stream has only a
/// partial frame or no bytes yet; the caller decides how to pump/wait.
///
/// The B2/B3 adapter is covered by inline tests here before the higher-level
/// send/receive coroutines call it; keep the dead-code allowance pinned to this
/// interim helper until those call sites land.
#[allow(dead_code)]
pub struct QuicFrameTransport {
    stream: StreamId,
    codec: AtpFrameCodec,
    rbuf: BytesMut,
}

#[allow(dead_code)]
impl QuicFrameTransport {
    /// Open a local bidirectional control stream.
    pub fn open(cx: &Cx, conn: &mut QuicConnection) -> Result<Self, QuicTransportError> {
        let stream = conn.open_control_stream(cx)?;
        Ok(Self::for_stream(stream))
    }

    /// Bind to an already-known control stream id.
    ///
    /// B3 uses this for the first client-initiated stream until the high-level
    /// QUIC API exposes an accept-next-remote-control-stream helper.
    pub fn for_stream(stream: StreamId) -> Self {
        Self {
            stream,
            codec: AtpFrameCodec::new(),
            rbuf: BytesMut::new(),
        }
    }

    /// Underlying QUIC stream id.
    #[must_use]
    pub fn stream(&self) -> StreamId {
        self.stream
    }

    /// Encode and queue a canonical ATP frame on the control stream.
    pub fn send(
        &mut self,
        cx: &Cx,
        conn: &mut QuicConnection,
        frame: &crate::net::atp::protocol::frames::Frame,
    ) -> Result<(), QuicTransportError> {
        let wire = frame
            .to_wire_bytes()
            .map_err(|err| QuicTransportError::Frame(err.to_string()))?;
        conn.write_control(cx, self.stream, Bytes::from(wire), false)?;
        Ok(())
    }

    /// Serialize a typed JSON control payload, wrap it in the requested ATP frame
    /// type, and queue it on the control stream.
    pub fn send_json<T: Serialize>(
        &mut self,
        cx: &Cx,
        conn: &mut QuicConnection,
        ty: FrameType,
        value: &T,
    ) -> Result<(), QuicTransportError> {
        let frame = json_frame(ty, value)?;
        self.send(cx, conn, &frame)
    }

    /// Try to decode the next complete ATP frame from the control stream.
    ///
    /// Pending reads preserve partial frames; FIN refuses a truncated frame.
    pub fn try_recv(
        &mut self,
        cx: &Cx,
        conn: &mut QuicConnection,
    ) -> Result<Option<crate::net::atp::protocol::frames::Frame>, QuicTransportError> {
        loop {
            if let Some(frame) = self
                .codec
                .decode(&mut self.rbuf)
                .map_err(|err| QuicTransportError::Frame(err.to_string()))?
            {
                return Ok(Some(frame));
            }

            let chunk = conn.read_control(cx, self.stream, CONTROL_READ_CHUNK)?;
            if chunk.is_empty() {
                if conn.is_control_eof(self.stream)? {
                    return self
                        .codec
                        .decode_eof(&mut self.rbuf)
                        .map_err(|err| QuicTransportError::Frame(err.to_string()));
                }
                return Ok(None);
            }
            self.rbuf.extend_from_slice(&chunk);
        }
    }

    /// Try to receive a typed JSON control payload, rejecting unexpected frame
    /// types before deserializing attacker-controlled JSON bytes.
    pub fn try_recv_json<T: for<'de> Deserialize<'de>>(
        &mut self,
        cx: &Cx,
        conn: &mut QuicConnection,
        expected: FrameType,
        expected_name: &'static str,
    ) -> Result<Option<T>, QuicTransportError> {
        let Some(frame) = self.try_recv(cx, conn)? else {
            return Ok(None);
        };
        parse_json_frame(&frame, expected, expected_name).map(Some)
    }
}

/// ATP frame transport over an accepted native QUIC control stream.
///
/// This mirrors [`QuicFrameTransport`] for the B3 public receive path, whose
/// API accepts a [`NativeQuicConnection`] by value. The lower native connection
/// already owns reassembled stream bytes and buffered DATAGRAM payloads for an
/// accepted peer, but it is not wrapped in the high-level [`QuicConnection`]
/// handle. Keep this adapter small and receiver-scoped until the managed
/// endpoint exposes a first-class accepted-connection handle.
#[allow(dead_code)]
struct NativeQuicFrameTransport {
    stream: StreamId,
    codec: AtpFrameCodec,
    rbuf: BytesMut,
}

#[allow(dead_code)]
impl NativeQuicFrameTransport {
    fn open(cx: &Cx, conn: &mut NativeQuicConnection) -> Result<Self, QuicTransportError> {
        let stream = conn.open_local_bidi(cx)?;
        Ok(Self::for_stream(stream))
    }

    fn for_stream(stream: StreamId) -> Self {
        Self {
            stream,
            codec: AtpFrameCodec::new(),
            rbuf: BytesMut::new(),
        }
    }

    fn send(
        &mut self,
        cx: &Cx,
        conn: &mut NativeQuicConnection,
        frame: &Frame,
    ) -> Result<(), QuicTransportError> {
        let wire = frame
            .to_wire_bytes()
            .map_err(|err| QuicTransportError::Frame(err.to_string()))?;
        conn.write_stream_bytes(cx, self.stream, Bytes::from(wire), false)?;
        Ok(())
    }

    fn send_json<T: Serialize>(
        &mut self,
        cx: &Cx,
        conn: &mut NativeQuicConnection,
        ty: FrameType,
        value: &T,
    ) -> Result<(), QuicTransportError> {
        let frame = json_frame(ty, value)?;
        self.send(cx, conn, &frame)
    }

    fn try_recv(
        &mut self,
        cx: &Cx,
        conn: &mut NativeQuicConnection,
    ) -> Result<Option<Frame>, QuicTransportError> {
        loop {
            if let Some(frame) = self
                .codec
                .decode(&mut self.rbuf)
                .map_err(|err| QuicTransportError::Frame(err.to_string()))?
            {
                return Ok(Some(frame));
            }

            let chunk = match conn.read_stream_bytes(cx, self.stream, CONTROL_READ_CHUNK) {
                Ok(chunk) => chunk,
                Err(NativeQuicConnectionError::StreamTable(StreamTableError::UnknownStream(
                    stream,
                ))) if stream == self.stream => {
                    return Ok(None);
                }
                Err(err) => return Err(err.into()),
            };
            if chunk.is_empty() {
                if conn.is_stream_read_eof(self.stream)? {
                    return self
                        .codec
                        .decode_eof(&mut self.rbuf)
                        .map_err(|err| QuicTransportError::Frame(err.to_string()));
                }
                return Ok(None);
            }
            self.rbuf.extend_from_slice(&chunk);
        }
    }
}

#[allow(dead_code)]
fn next_control_frame(
    cx: &Cx,
    conn: &mut QuicConnection,
    control: &mut QuicFrameTransport,
    operation: &'static str,
) -> Result<Frame, QuicTransportError> {
    control
        .try_recv(cx, conn)?
        .ok_or_else(|| QuicTransportError::Frame(format!("{operation}: no complete frame ready")))
}

#[allow(dead_code)]
fn next_native_control_frame(
    cx: &Cx,
    conn: &mut NativeQuicConnection,
    control: &mut NativeQuicFrameTransport,
    operation: &'static str,
) -> Result<Frame, QuicTransportError> {
    control
        .try_recv(cx, conn)?
        .ok_or_else(|| QuicTransportError::Frame(format!("{operation}: no complete frame ready")))
}

#[allow(dead_code)]
fn sender_hello(peer_id: &str, config: &QuicConfig, symbol_auth: bool) -> QuicHello {
    sender_hello_with_source_stream(peer_id, config, symbol_auth, None, 0, None)
}

#[allow(dead_code)]
fn sender_hello_with_source_stream(
    peer_id: &str,
    config: &QuicConfig,
    symbol_auth: bool,
    source_stream: Option<StreamId>,
    total_bytes: u64,
    delta_transfer_nonce: Option<TransferNonce>,
) -> QuicHello {
    QuicHello {
        protocol: ATP_QUIC_PROTOCOL,
        role: "sender".to_string(),
        peer_id: peer_id.to_string(),
        symbol_size: config.symbol_size,
        max_block_size: u64::try_from(config.max_block_size).unwrap_or(u64::MAX),
        symbol_auth,
        source_stream: source_stream.is_some(),
        source_stream_id: source_stream.map(|stream| stream.0),
        total_bytes,
        delta_transfer_nonce,
    }
}

#[cfg(feature = "tls")]
fn fresh_quic_delta_nonce(
    cx: &Cx,
    role: &'static [u8],
    avoid: Option<TransferNonce>,
) -> Result<TransferNonce, QuicTransportError> {
    for attempt in 0u32..4 {
        let mut entropy = [0u8; 32];
        cx.random_bytes(&mut entropy);
        let mut hasher = Sha256::new();
        hasher.update(b"ATP-QUIC-DELTA-NONCE-V1\0");
        hasher.update(u64::try_from(role.len()).unwrap_or(u64::MAX).to_be_bytes());
        hasher.update(role);
        hasher.update(attempt.to_be_bytes());
        hasher.update(entropy);
        let nonce = TransferNonce::new(hasher.finalize().into());
        if !nonce.is_zero() && Some(nonce) != avoid {
            return Ok(nonce);
        }
    }
    Err(QuicTransportError::Control(
        "unable to derive a distinct non-zero QUIC delta nonce".to_string(),
    ))
}

#[cfg(any(feature = "tls", test))]
fn quic_delta_destination_root_commitment(
    context: &SecurityContext,
    receiver_nonce: TransferNonce,
    dest_dir: &Path,
) -> Result<[u8; 32], QuicTransportError> {
    if context.mode() != AuthMode::Strict {
        return Err(QuicTransportError::Config(
            "QUIC delta destination binding requires a strict authentication context".to_string(),
        ));
    }
    let encoded_path = dest_dir.as_os_str().as_encoded_bytes();
    let mut hasher = Sha256::new();
    hasher.update(b"ATP-QUIC-DELTA-DESTINATION-ROOT-V1\0");
    hasher.update(receiver_nonce.as_bytes());
    hasher.update(
        u64::try_from(encoded_path.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    hasher.update(encoded_path);
    let transcript_digest: [u8; 32] = hasher.finalize().into();
    let symbol = Symbol::new(
        SymbolId::new(
            ObjectId::new(0x4154_502d_5155_4943, 0x2d44_454c_5441_2d44),
            0,
            0,
        ),
        transcript_digest.to_vec(),
        SymbolKind::Source,
    );
    let control = context.derive_context(b"atp-quic-delta-destination-root-v1");
    Ok(*control.sign_symbol_tag(&symbol).as_bytes())
}

fn quic_decode_delta_root(value: &str, label: &str) -> Result<[u8; 32], QuicTransportError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(QuicTransportError::Control(format!(
            "{label} must be a canonical 64-character lowercase hex digest"
        )));
    }
    let mut decoded = [0u8; 32];
    hex::decode_to_slice(value, &mut decoded)
        .map_err(|error| QuicTransportError::Control(format!("decode {label}: {error}")))?;
    Ok(decoded)
}

#[cfg(any(feature = "tls", test))]
fn quic_delta_hash_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(bytes);
}

#[cfg(any(feature = "tls", test))]
fn derive_quic_delta_session(
    handshake: QuicDeltaHandshakeContext,
    sender_peer_id: &str,
    receiver_peer_id: &str,
    manifest: &TransferManifest,
) -> Result<QuicDeltaSessionContext, QuicTransportError> {
    let delta_manifest = manifest.delta_manifest.as_ref().ok_or_else(|| {
        QuicTransportError::Control(
            "delta-bound QUIC session requires a delta manifest".to_string(),
        )
    })?;
    let outer_root = quic_decode_delta_root(&manifest.merkle_root_hex, "manifest Merkle root")?;
    let delta_root = quic_decode_delta_root(
        &delta_manifest.merkle_root_hex,
        "delta manifest Merkle root",
    )?;
    let sender = PeerId::from_label(sender_peer_id);
    let receiver = PeerId::from_label(receiver_peer_id);

    // These application labels provide transcript domain separation only;
    // they are not asserted to be TLS certificate identities.
    let mut hasher = Sha256::new();
    hasher.update(b"ATP-QUIC-DELTA-SESSION-V1\0");
    hasher.update(ATP_QUIC_PROTOCOL.to_be_bytes());
    hasher.update(handshake.sender_nonce.as_bytes());
    hasher.update(handshake.receiver_nonce.as_bytes());
    hasher.update(handshake.destination_root);
    quic_delta_hash_len_prefixed(&mut hasher, sender.as_bytes());
    quic_delta_hash_len_prefixed(&mut hasher, receiver.as_bytes());
    quic_delta_hash_len_prefixed(&mut hasher, manifest.transfer_id.as_bytes());
    quic_delta_hash_len_prefixed(&mut hasher, manifest.root_name.as_bytes());
    hasher.update([u8::from(manifest.is_directory)]);
    hasher.update(manifest.total_bytes.to_be_bytes());
    hasher.update(outer_root);
    hasher.update(delta_root);
    match manifest.metadata_root_hex.as_deref() {
        Some(root) => {
            hasher.update([1]);
            hasher.update(quic_decode_delta_root(root, "manifest metadata root")?);
        }
        None => hasher.update([0]),
    }

    Ok(QuicDeltaSessionContext {
        session_id: SessionId::from_digest(hasher.finalize().into()),
        destination_root: handshake.destination_root,
    })
}

#[cfg(any(feature = "tls", test))]
fn quic_delta_manifest_auth_symbol(
    session: QuicDeltaSessionContext,
    manifest: &TransferManifest,
) -> Result<Symbol, QuicTransportError> {
    let manifest_bytes = serde_json::to_vec(manifest).map_err(|error| {
        QuicTransportError::Control(format!(
            "serialize canonical QUIC delta manifest client proof: {error}"
        ))
    })?;
    let mut hasher = Sha256::new();
    hasher.update(b"ATP-QUIC-DELTA-MANIFEST-CLIENT-PROOF-V1\0");
    hasher.update(session.session_id.as_bytes());
    hasher.update(session.destination_root);
    hasher.update(0u64.to_be_bytes());
    quic_delta_hash_len_prefixed(&mut hasher, manifest.transfer_id.as_bytes());
    quic_delta_hash_len_prefixed(&mut hasher, &manifest_bytes);
    let transcript_digest: [u8; 32] = hasher.finalize().into();
    Ok(Symbol::new(
        SymbolId::new(
            ObjectId::new(0x4154_502d_5155_4943, 0x2d44_454c_5441_2d4d),
            0,
            0,
        ),
        transcript_digest.to_vec(),
        SymbolKind::Source,
    ))
}

#[cfg(any(feature = "tls", test))]
fn make_quic_delta_manifest_envelope(
    context: &SecurityContext,
    session: QuicDeltaSessionContext,
    manifest: &TransferManifest,
) -> Result<QuicDeltaManifestEnvelope, QuicTransportError> {
    if context.mode() != AuthMode::Strict {
        return Err(QuicTransportError::Config(
            "QUIC delta control requires a strict authentication context".to_string(),
        ));
    }
    let control = context.derive_context(b"atp-quic-delta-manifest-client-proof-v1");
    let symbol = quic_delta_manifest_auth_symbol(session, manifest)?;
    Ok(QuicDeltaManifestEnvelope {
        session_id: session.session_id,
        destination_root: session.destination_root,
        control_seq: 0,
        manifest: manifest.clone(),
        client_auth_tag: *control.sign_symbol_tag(&symbol).as_bytes(),
    })
}

#[cfg(any(feature = "tls", test))]
fn validate_quic_delta_manifest_envelope(
    context: &SecurityContext,
    session: QuicDeltaSessionContext,
    envelope: &QuicDeltaManifestEnvelope,
) -> Result<(), QuicTransportError> {
    if context.mode() != AuthMode::Strict
        || envelope.control_seq != 0
        || envelope.session_id != session.session_id
        || envelope.destination_root != session.destination_root
    {
        return Err(QuicTransportError::HandshakeRejected(
            "QUIC delta client proof binding mismatch".to_string(),
        ));
    }
    let symbol = quic_delta_manifest_auth_symbol(session, &envelope.manifest)?;
    let mut authenticated = AuthenticatedSymbol::from_parts(
        symbol,
        AuthenticationTag::from_bytes(envelope.client_auth_tag),
    );
    let control = context.derive_context(b"atp-quic-delta-manifest-client-proof-v1");
    if control
        .verify_authenticated_symbol(&mut authenticated)
        .is_err()
        || !authenticated.is_verified()
    {
        return Err(QuicTransportError::HandshakeRejected(
            "QUIC delta client proof authentication failed".to_string(),
        ));
    }
    Ok(())
}

#[cfg(any(feature = "tls", test))]
fn validate_quic_delta_ack(
    offered: Option<TransferNonce>,
    ack: &QuicHelloAck,
) -> Result<Option<QuicDeltaHandshakeContext>, QuicTransportError> {
    let response = (
        ack.delta_transfer_nonce,
        ack.delta_receiver_nonce,
        ack.delta_destination_root,
    );
    match (offered, response) {
        (None | Some(_), (None, None, None)) => Ok(None),
        (None, _) => Err(QuicTransportError::HandshakeRejected(
            "receiver returned unsolicited QUIC delta binding fields".to_string(),
        )),
        (Some(expected), (Some(echoed), Some(receiver), Some(destination_root))) => {
            if echoed != expected {
                return Err(QuicTransportError::HandshakeRejected(
                    "receiver echoed the wrong QUIC delta transfer nonce".to_string(),
                ));
            }
            if receiver.is_zero() || receiver == expected {
                return Err(QuicTransportError::HandshakeRejected(
                    "receiver QUIC delta nonce must be distinct and non-zero".to_string(),
                ));
            }
            if destination_root.iter().all(|byte| *byte == 0) {
                return Err(QuicTransportError::HandshakeRejected(
                    "receiver QUIC delta destination commitment is all zero".to_string(),
                ));
            }
            Ok(Some(QuicDeltaHandshakeContext {
                sender_nonce: expected,
                receiver_nonce: receiver,
                destination_root,
            }))
        }
        (Some(_), _) => Err(QuicTransportError::HandshakeRejected(
            "receiver returned a partial QUIC delta binding tuple".to_string(),
        )),
    }
}

#[cfg(any(feature = "tls", test))]
fn make_quic_delta_request(
    session: QuicDeltaSessionContext,
    manifest: &TransferManifest,
    request: DeltaObjectRequest,
) -> QuicDeltaObjectRequest {
    QuicDeltaObjectRequest {
        session_id: session.session_id,
        transfer_id: manifest.transfer_id.clone(),
        destination_root: session.destination_root,
        control_seq: 0,
        request,
    }
}

#[cfg(any(feature = "tls", test))]
async fn build_quic_receiver_delta_request(
    cx: &Cx,
    dest_dir: &Path,
    config: &QuicConfig,
    session: QuicDeltaSessionContext,
    manifest: &TransferManifest,
) -> Result<QuicDeltaObjectRequest, QuicTransportError> {
    cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
    let delta = manifest.delta_manifest.as_ref().ok_or_else(|| {
        QuicTransportError::Control(
            "cannot build a bound QUIC delta request without a delta manifest".to_string(),
        )
    })?;
    let entry = quic_delta_manifest_entry(manifest).ok_or_else(|| {
        QuicTransportError::Control(
            "cannot build a bound QUIC delta request for this transfer shape".to_string(),
        )
    })?;
    let full = |receiver_root: Option<String>, reason: &'static str| {
        make_quic_delta_request(
            session,
            manifest,
            DeltaObjectRequest::full(delta.merkle_root_hex.clone(), receiver_root, reason),
        )
    };

    prepare_quic_destination_root(dest_dir).await?;
    let path = quic_safe_base_for_root_name(dest_dir, &manifest.root_name)?;
    reject_quic_destination_symlink_prefix(&path, &path).await?;
    let existing = match crate::fs::symlink_metadata(&path).await {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(full(None, "destination_missing"));
        }
        Err(error) => return Err(error.into()),
    };
    if !existing.is_file() || existing.len() != entry.size {
        return Ok(full(None, "destination_shape_or_size_mismatch"));
    }
    let expected_metadata = entry.metadata.clone().unwrap_or_default();
    let receiver_metadata = read_entry_metadata(&path, &config.metadata_policy).await?;
    if receiver_metadata != expected_metadata {
        return Ok(full(None, "destination_metadata_mismatch"));
    }

    let receiver_delta = match build_quic_delta_manifest_for_file(
        cx,
        &manifest.merkle_root_hex,
        &path,
        entry.index,
        &entry.rel_path,
        entry.size,
        &entry.sha256_hex,
        delta.chunk_size,
    )
    .await
    {
        Ok(delta) => delta,
        Err(QuicTransportError::Source(_)) => {
            return Ok(full(None, "destination_changed_during_delta_validation"));
        }
        Err(error) => return Err(error),
    };
    reject_quic_destination_symlink_prefix(&path, &path).await?;
    if read_entry_metadata(&path, &config.metadata_policy).await? != expected_metadata {
        return Ok(full(None, "destination_metadata_changed_during_validation"));
    }
    if receiver_delta != *delta {
        return Ok(full(
            Some(receiver_delta.merkle_root_hex),
            "destination_delta_root_mismatch",
        ));
    }

    Ok(make_quic_delta_request(
        session,
        manifest,
        DeltaObjectRequest {
            mode: DeltaWireMode::AlreadyInSync,
            fallback_reason: None,
            sender_merkle_root_hex: delta.merkle_root_hex.clone(),
            receiver_merkle_root_hex: Some(delta.merkle_root_hex.clone()),
            missing_bytes: 0,
            shared_chunks: u64::try_from(delta.chunks.len()).unwrap_or(u64::MAX),
            stale_chunks: 0,
            missing_chunks: Vec::new(),
        },
    ))
}

#[cfg(any(feature = "tls", test))]
fn validate_quic_delta_request(
    envelope: &QuicDeltaObjectRequest,
    session: QuicDeltaSessionContext,
    manifest: &TransferManifest,
) -> Result<DeltaWireMode, QuicTransportError> {
    if envelope.control_seq != 0
        || envelope.session_id != session.session_id
        || envelope.transfer_id != manifest.transfer_id
        || envelope.destination_root != session.destination_root
    {
        return Err(QuicTransportError::Control(
            "QUIC delta ObjectRequest binding mismatch".to_string(),
        ));
    }
    let delta_manifest = manifest.delta_manifest.as_ref().ok_or_else(|| {
        QuicTransportError::Control("bound delta request without a delta manifest".to_string())
    })?;
    let request = &envelope.request;
    if request.sender_merkle_root_hex != delta_manifest.merkle_root_hex {
        return Err(QuicTransportError::Control(
            "QUIC delta ObjectRequest sender root mismatch".to_string(),
        ));
    }
    match request.mode {
        DeltaWireMode::FullObject => {
            let fallback_reason_valid = request.fallback_reason.as_deref().is_some_and(|reason| {
                !reason.trim().is_empty() && reason.len() <= 256 && reason.is_ascii()
            });
            let receiver_root_valid =
                request
                    .receiver_merkle_root_hex
                    .as_deref()
                    .is_none_or(|root| {
                        quic_decode_delta_root(root, "receiver delta manifest Merkle root").is_ok()
                    });
            if !fallback_reason_valid
                || !receiver_root_valid
                || request.missing_bytes != 0
                || request.shared_chunks != 0
                || request.stale_chunks != 0
                || !request.missing_chunks.is_empty()
            {
                return Err(QuicTransportError::Control(
                    "malformed QUIC full-object delta request".to_string(),
                ));
            }
        }
        DeltaWireMode::AlreadyInSync => {
            let expected_shared = u64::try_from(delta_manifest.chunks.len()).unwrap_or(u64::MAX);
            if request.fallback_reason.is_some()
                || request.receiver_merkle_root_hex.as_deref()
                    != Some(delta_manifest.merkle_root_hex.as_str())
                || request.missing_bytes != 0
                || !request.missing_chunks.is_empty()
                || request.stale_chunks != 0
                || request.shared_chunks != expected_shared
            {
                return Err(QuicTransportError::Control(
                    "malformed QUIC AlreadyInSync delta request".to_string(),
                ));
            }
        }
        DeltaWireMode::DeltaChunks => {
            return Err(QuicTransportError::Control(
                "QUIC missing-chunk delta requests are not enabled in this rollout".to_string(),
            ));
        }
    }
    Ok(request.mode)
}

#[cfg(any(feature = "tls", test))]
fn make_quic_delta_proof(
    session: QuicDeltaSessionContext,
    manifest: &TransferManifest,
    receipt: ReceiveReceipt,
) -> QuicDeltaProof {
    QuicDeltaProof {
        session_id: session.session_id,
        transfer_id: manifest.transfer_id.clone(),
        destination_root: session.destination_root,
        control_seq: 1,
        receipt,
    }
}

#[cfg(any(feature = "tls", test))]
fn validate_quic_delta_proof(
    proof: QuicDeltaProof,
    session: QuicDeltaSessionContext,
    manifest: &TransferManifest,
) -> Result<ReceiveReceipt, QuicTransportError> {
    if proof.control_seq != 1
        || proof.session_id != session.session_id
        || proof.transfer_id != manifest.transfer_id
        || proof.destination_root != session.destination_root
    {
        return Err(QuicTransportError::Control(
            "QUIC delta Proof binding mismatch".to_string(),
        ));
    }
    if !proof.receipt.committed
        || !proof.receipt.sha_ok
        || !proof.receipt.merkle_ok
        || proof.receipt.bytes_received != 0
        || proof.receipt.files != manifest_logical_files(manifest)
        || proof.receipt.symbols_accepted != 0
        || proof.receipt.feedback_rounds != 0
        || proof.receipt.decode_count != 0
        || proof.receipt.decode_micros != 0
        || proof.receipt.reason.is_some()
        || proof.receipt.committed_paths.len() != 1
        || proof.receipt.committed_paths[0].is_empty()
    {
        return Err(QuicTransportError::Integrity(
            proof
                .receipt
                .reason
                .clone()
                .unwrap_or_else(|| "receiver did not commit the QUIC delta no-op".to_string()),
        ));
    }
    Ok(proof.receipt)
}

#[allow(dead_code)]
fn reject_hello_reason(
    hello: &QuicHello,
    config: &QuicConfig,
    expected_symbol_auth: bool,
) -> Option<String> {
    if hello.protocol != ATP_QUIC_PROTOCOL {
        return Some(format!(
            "unsupported protocol {} (this peer speaks {ATP_QUIC_PROTOCOL})",
            hello.protocol
        ));
    }
    if hello.symbol_size == 0 {
        return Some("symbol_size must be greater than 0".to_string());
    }
    if hello.max_block_size == 0 {
        return Some("max_block_size must be greater than 0".to_string());
    }
    if hello.symbol_size != config.symbol_size {
        return Some(format!(
            "sender symbol_size ({}) must match receiver symbol_size ({})",
            hello.symbol_size, config.symbol_size
        ));
    }
    // The sender is authoritative on block geometry: it scales `max_block_size` UP for large
    // entries (see `effective_quic_max_block_size_for_largest_entry`) to keep the per-object source
    // block count bounded. The receiver ADOPTS the sender's value (in
    // `receive_established_native_connection`) provided it is symbol-aligned, at least the
    // receiver's own aligned floor, and within `MAX_QUIC_ADOPTED_BLOCK_SIZE` (which bounds per-block
    // decode memory). A strict equality here rejected every large transfer whose sender scaled the
    // block size — the ASUP-E802 handshake failure. (br-asupersync-j73ili)
    let receiver_floor = match quic_symbol_aligned_block_size(config, config.max_block_size) {
        Ok(v) => u64::try_from(v).unwrap_or(u64::MAX),
        Err(_) => {
            return Some(
                "receiver max_block_size cannot be aligned to symbol_size without overflow"
                    .to_string(),
            );
        }
    };
    let hello_block = usize::try_from(hello.max_block_size).unwrap_or(usize::MAX);
    let hello_aligned = match quic_symbol_aligned_block_size(config, hello_block) {
        Ok(v) => u64::try_from(v).unwrap_or(u64::MAX),
        Err(_) => {
            return Some(format!(
                "sender max_block_size ({}) cannot be aligned to symbol_size without overflow",
                hello.max_block_size
            ));
        }
    };
    if hello_aligned != hello.max_block_size {
        return Some(format!(
            "sender max_block_size ({}) is not a multiple of symbol_size ({})",
            hello.max_block_size, config.symbol_size
        ));
    }
    if hello.max_block_size < receiver_floor {
        return Some(format!(
            "sender max_block_size ({}) is below the receiver floor ({receiver_floor})",
            hello.max_block_size
        ));
    }
    if hello.max_block_size > MAX_QUIC_ADOPTED_BLOCK_SIZE as u64 {
        return Some(format!(
            "sender max_block_size ({}) exceeds the maximum adopted block size ({MAX_QUIC_ADOPTED_BLOCK_SIZE})",
            hello.max_block_size
        ));
    }
    let min_datagram = usize::from(hello.symbol_size) + AUTH_ENVELOPE_HEADER_LEN;
    if min_datagram > config.max_datagram_size {
        return Some(format!(
            "sender symbol_size ({}) plus {AUTH_ENVELOPE_HEADER_LEN}-byte authenticated envelope \
             header exceeds receiver max_datagram_size ({})",
            hello.symbol_size, config.max_datagram_size
        ));
    }
    if hello.symbol_auth != expected_symbol_auth {
        return Some(format!(
            "symbol authentication mismatch: sender={}, receiver={expected_symbol_auth}",
            hello.symbol_auth
        ));
    }
    if hello
        .delta_transfer_nonce
        .is_some_and(TransferNonce::is_zero)
    {
        return Some("delta_transfer_nonce must not be all zero".to_string());
    }
    if let Some(reason) = reject_source_stream_hello_reason(hello) {
        return Some(reason);
    }
    None
}

fn reject_source_stream_hello_reason(hello: &QuicHello) -> Option<String> {
    match (hello.source_stream, hello.source_stream_id) {
        (false, None) => None,
        (false, Some(id)) => Some(format!(
            "source_stream_id {id} advertised while source_stream=false"
        )),
        (true, None) => Some("source_stream=true requires source_stream_id".to_string()),
        (true, Some(id)) => {
            if hello.total_bytes == 0 {
                return Some("source_stream=true requires non-zero total_bytes".to_string());
            }
            if hello.total_bytes > QUIC_RELIABLE_SOURCE_STREAM_MAX_BYTES {
                return Some(format!(
                    "source stream transfer size {} exceeds stream cap {}",
                    hello.total_bytes, QUIC_RELIABLE_SOURCE_STREAM_MAX_BYTES
                ));
            }
            let stream = StreamId(id);
            if stream == first_client_bidi_stream() {
                return Some("source stream must not reuse the control stream".to_string());
            }
            if stream.direction() != StreamDirection::Bidirectional
                || stream.is_local_for(StreamRole::Server)
            {
                return Some(format!(
                    "source stream id {id} must be a client-initiated bidirectional stream"
                ));
            }
            None
        }
    }
}

fn source_stream_from_hello(hello: &QuicHello) -> Result<Option<StreamId>, QuicTransportError> {
    if let Some(reason) = reject_source_stream_hello_reason(hello) {
        return Err(QuicTransportError::HandshakeRejected(reason));
    }
    Ok(hello.source_stream_id.map(StreamId))
}

// B2/B3 coroutine helpers are exercised by deterministic loopback tests before
// the public transfer entry points call them.
#[allow(dead_code)]
fn send_sender_hello(
    cx: &Cx,
    conn: &mut QuicConnection,
    control: &mut QuicFrameTransport,
    config: &QuicConfig,
    peer_id: &str,
    symbol_auth: bool,
) -> Result<(), QuicTransportError> {
    let frame = json_frame(
        FrameType::Handshake,
        &sender_hello(peer_id, config, symbol_auth),
    )?;
    control.send(cx, conn, &frame)
}

#[allow(dead_code)]
fn receive_sender_hello_and_ack(
    cx: &Cx,
    conn: &mut QuicConnection,
    control: &mut QuicFrameTransport,
    config: &QuicConfig,
    peer_id: &str,
    expected_symbol_auth: bool,
) -> Result<QuicHello, QuicTransportError> {
    let receiver_config = effective_quic_receiver_config(config)?;
    let frame = next_control_frame(cx, conn, control, "receive sender handshake")?;
    if frame.frame_type() != FrameType::Handshake {
        return Err(QuicTransportError::Unexpected {
            got: frame.frame_type(),
            expected: "Handshake",
        });
    }
    let hello: QuicHello = parse_json(&frame)?;
    let reason = reject_hello_reason(&hello, &receiver_config, expected_symbol_auth);
    let accepted = reason.is_none();
    let accepted_source_stream = accepted
        && hello.source_stream
        && quic_source_stream_enabled(hello.total_bytes, &receiver_config, conn);
    let ack = QuicHelloAck {
        accepted,
        peer_id: peer_id.to_string(),
        source_stream: accepted_source_stream,
        source_stream_recv_window: None,
        reason: reason.clone(),
        delta_transfer_nonce: None,
        delta_receiver_nonce: None,
        delta_destination_root: None,
    };
    let ack_frame = json_frame(FrameType::HandshakeAck, &ack)?;
    control.send(cx, conn, &ack_frame)?;
    if let Some(reason) = reason {
        return Err(QuicTransportError::HandshakeRejected(reason));
    }
    Ok(hello)
}

#[allow(dead_code)]
fn receive_native_sender_hello_and_ack(
    cx: &Cx,
    conn: &mut NativeQuicConnection,
    control: &mut NativeQuicFrameTransport,
    config: &QuicConfig,
    peer_id: &str,
    expected_symbol_auth: bool,
) -> Result<QuicHello, QuicTransportError> {
    let receiver_config = effective_quic_receiver_config(config)?;
    let frame = next_native_control_frame(cx, conn, control, "receive sender handshake")?;
    if frame.frame_type() != FrameType::Handshake {
        return Err(QuicTransportError::Unexpected {
            got: frame.frame_type(),
            expected: "Handshake",
        });
    }
    let hello: QuicHello = parse_json(&frame)?;
    let reason = reject_hello_reason(&hello, &receiver_config, expected_symbol_auth);
    let accepted = reason.is_none();
    let accepted_source_stream = accepted
        && hello.source_stream
        && quic_native_source_stream_enabled(hello.total_bytes, &receiver_config, conn);
    let ack = QuicHelloAck {
        accepted,
        peer_id: peer_id.to_string(),
        source_stream: accepted_source_stream,
        source_stream_recv_window: None,
        reason: reason.clone(),
        delta_transfer_nonce: None,
        delta_receiver_nonce: None,
        delta_destination_root: None,
    };
    let ack_frame = json_frame(FrameType::HandshakeAck, &ack)?;
    control.send(cx, conn, &ack_frame)?;
    if let Some(reason) = reason {
        return Err(QuicTransportError::HandshakeRejected(reason));
    }
    Ok(hello)
}

#[allow(dead_code)]
fn send_native_sender_hello(
    cx: &Cx,
    conn: &mut NativeQuicConnection,
    control: &mut NativeQuicFrameTransport,
    config: &QuicConfig,
    peer_id: &str,
    symbol_auth: bool,
    source_stream: Option<StreamId>,
    total_bytes: u64,
    delta_transfer_nonce: Option<TransferNonce>,
) -> Result<(), QuicTransportError> {
    let frame = json_frame(
        FrameType::Handshake,
        &sender_hello_with_source_stream(
            peer_id,
            config,
            symbol_auth,
            source_stream,
            total_bytes,
            delta_transfer_nonce,
        ),
    )?;
    control.send(cx, conn, &frame)
}

#[allow(dead_code)]
fn receive_sender_hello_ack(
    cx: &Cx,
    conn: &mut QuicConnection,
    control: &mut QuicFrameTransport,
) -> Result<QuicHelloAck, QuicTransportError> {
    let frame = next_control_frame(cx, conn, control, "receive sender handshake ack")?;
    if frame.frame_type() != FrameType::HandshakeAck {
        return Err(QuicTransportError::Unexpected {
            got: frame.frame_type(),
            expected: "HandshakeAck",
        });
    }
    let ack: QuicHelloAck = parse_json(&frame)?;
    if !ack.accepted {
        return Err(QuicTransportError::HandshakeRejected(
            ack.reason
                .clone()
                .unwrap_or_else(|| "no reason given".to_string()),
        ));
    }
    Ok(ack)
}

#[allow(dead_code)]
fn receive_native_sender_hello_ack(
    cx: &Cx,
    conn: &mut NativeQuicConnection,
    control: &mut NativeQuicFrameTransport,
) -> Result<QuicHelloAck, QuicTransportError> {
    let frame = next_native_control_frame(cx, conn, control, "receive sender handshake ack")?;
    if frame.frame_type() != FrameType::HandshakeAck {
        return Err(QuicTransportError::Unexpected {
            got: frame.frame_type(),
            expected: "HandshakeAck",
        });
    }
    let ack: QuicHelloAck = parse_json(&frame)?;
    if !ack.accepted {
        return Err(QuicTransportError::HandshakeRejected(
            ack.reason
                .clone()
                .unwrap_or_else(|| "no reason given".to_string()),
        ));
    }
    Ok(ack)
}

#[allow(dead_code)]
fn send_manifest(
    cx: &Cx,
    conn: &mut QuicConnection,
    control: &mut QuicFrameTransport,
    manifest: &TransferManifest,
) -> Result<(), QuicTransportError> {
    control.send_json(cx, conn, FrameType::ObjectManifest, manifest)
}

#[allow(dead_code)]
fn send_native_manifest(
    cx: &Cx,
    conn: &mut NativeQuicConnection,
    control: &mut NativeQuicFrameTransport,
    manifest: &TransferManifest,
) -> Result<(), QuicTransportError> {
    control.send_json(cx, conn, FrameType::ObjectManifest, manifest)
}

#[allow(dead_code)]
fn receive_manifest(
    cx: &Cx,
    conn: &mut QuicConnection,
    control: &mut QuicFrameTransport,
) -> Result<TransferManifest, QuicTransportError> {
    let frame = next_control_frame(cx, conn, control, "receive transfer manifest")?;
    parse_json_frame(&frame, FrameType::ObjectManifest, "ObjectManifest")
}

#[allow(dead_code)]
fn receive_native_manifest(
    cx: &Cx,
    conn: &mut NativeQuicConnection,
    control: &mut NativeQuicFrameTransport,
) -> Result<TransferManifest, QuicTransportError> {
    let frame = next_native_control_frame(cx, conn, control, "receive transfer manifest")?;
    parse_json_frame(&frame, FrameType::ObjectManifest, "ObjectManifest")
}

#[allow(dead_code)]
fn send_empty_control_frame(
    cx: &Cx,
    conn: &mut QuicConnection,
    control: &mut QuicFrameTransport,
    frame_type: FrameType,
) -> Result<(), QuicTransportError> {
    let frame =
        Frame::empty(frame_type).map_err(|err| QuicTransportError::Frame(err.to_string()))?;
    control.send(cx, conn, &frame)
}

#[allow(dead_code)]
fn send_object_complete(
    cx: &Cx,
    conn: &mut QuicConnection,
    control: &mut QuicFrameTransport,
    round_symbols_sent: u64,
) -> Result<(), QuicTransportError> {
    send_object_complete_for_round(cx, conn, control, 0, round_symbols_sent)
}

#[allow(dead_code)]
fn send_object_complete_for_round(
    cx: &Cx,
    conn: &mut QuicConnection,
    control: &mut QuicFrameTransport,
    round: u32,
    round_symbols_sent: u64,
) -> Result<(), QuicTransportError> {
    control.send_json(
        cx,
        conn,
        FrameType::ObjectComplete,
        &QuicRoundComplete {
            round,
            round_symbols_sent,
        },
    )
}

#[allow(dead_code)]
fn receive_object_complete(
    cx: &Cx,
    conn: &mut QuicConnection,
    control: &mut QuicFrameTransport,
) -> Result<QuicRoundComplete, QuicTransportError> {
    let frame = next_control_frame(cx, conn, control, "receive object-complete marker")?;
    if frame.frame_type() != FrameType::ObjectComplete {
        return Err(QuicTransportError::Unexpected {
            got: frame.frame_type(),
            expected: "ObjectComplete",
        });
    }
    parse_quic_round_complete(&frame)
}

#[allow(dead_code)]
fn receive_native_object_complete(
    cx: &Cx,
    conn: &mut NativeQuicConnection,
    control: &mut NativeQuicFrameTransport,
) -> Result<QuicRoundComplete, QuicTransportError> {
    let frame = next_native_control_frame(cx, conn, control, "receive object-complete marker")?;
    if frame.frame_type() != FrameType::ObjectComplete {
        return Err(QuicTransportError::Unexpected {
            got: frame.frame_type(),
            expected: "ObjectComplete",
        });
    }
    parse_quic_round_complete(&frame)
}

#[allow(dead_code)]
fn send_native_object_complete(
    cx: &Cx,
    conn: &mut NativeQuicConnection,
    control: &mut NativeQuicFrameTransport,
    round_symbols_sent: u64,
) -> Result<(), QuicTransportError> {
    control.send_json(
        cx,
        conn,
        FrameType::ObjectComplete,
        &QuicRoundComplete {
            round_symbols_sent,
            ..QuicRoundComplete::default()
        },
    )
}

#[allow(dead_code)]
fn send_need_more(
    cx: &Cx,
    conn: &mut QuicConnection,
    control: &mut QuicFrameTransport,
    need: &QuicNeedMore,
) -> Result<(), QuicTransportError> {
    control.send_json(cx, conn, FrameType::ObjectRequest, need)
}

#[allow(dead_code)]
fn send_proof(
    cx: &Cx,
    conn: &mut QuicConnection,
    control: &mut QuicFrameTransport,
    receipt: &ReceiveReceipt,
) -> Result<(), QuicTransportError> {
    control.send_json(cx, conn, FrameType::Proof, receipt)
}

#[allow(dead_code)]
fn send_native_need_more(
    cx: &Cx,
    conn: &mut NativeQuicConnection,
    control: &mut NativeQuicFrameTransport,
    need: &QuicNeedMore,
) -> Result<(), QuicTransportError> {
    control.send_json(cx, conn, FrameType::ObjectRequest, need)
}

#[allow(dead_code)]
fn send_native_proof(
    cx: &Cx,
    conn: &mut NativeQuicConnection,
    control: &mut NativeQuicFrameTransport,
    receipt: &ReceiveReceipt,
) -> Result<(), QuicTransportError> {
    control.send_json(cx, conn, FrameType::Proof, receipt)
}

#[allow(dead_code)]
fn receive_proof_or_need_more(
    cx: &Cx,
    conn: &mut QuicConnection,
    control: &mut QuicFrameTransport,
) -> Result<QuicControlReply, QuicTransportError> {
    let frame = next_control_frame(cx, conn, control, "receive proof or fountain feedback")?;
    match frame.frame_type() {
        FrameType::Proof => parse_json::<ReceiveReceipt>(&frame).map(QuicControlReply::Proof),
        FrameType::ObjectRequest => {
            parse_json::<QuicNeedMore>(&frame).map(QuicControlReply::NeedMore)
        }
        got => Err(QuicTransportError::Unexpected {
            got,
            expected: "Proof | ObjectRequest",
        }),
    }
}

#[allow(dead_code)]
fn send_close(
    cx: &Cx,
    conn: &mut QuicConnection,
    control: &mut QuicFrameTransport,
) -> Result<(), QuicTransportError> {
    send_empty_control_frame(cx, conn, control, FrameType::Close)
}

#[allow(dead_code)]
fn send_native_close(
    cx: &Cx,
    conn: &mut NativeQuicConnection,
    control: &mut NativeQuicFrameTransport,
) -> Result<(), QuicTransportError> {
    let frame =
        Frame::empty(FrameType::Close).map_err(|err| QuicTransportError::Frame(err.to_string()))?;
    control.send(cx, conn, &frame)
}

#[allow(dead_code)]
fn receive_native_proof_or_need_more(
    cx: &Cx,
    conn: &mut NativeQuicConnection,
    control: &mut NativeQuicFrameTransport,
) -> Result<QuicControlReply, QuicTransportError> {
    let frame = next_native_control_frame(cx, conn, control, "receive proof or fountain feedback")?;
    match frame.frame_type() {
        FrameType::Proof => parse_json::<ReceiveReceipt>(&frame).map(QuicControlReply::Proof),
        FrameType::ObjectRequest => {
            parse_json::<QuicNeedMore>(&frame).map(QuicControlReply::NeedMore)
        }
        got => Err(QuicTransportError::Unexpected {
            got,
            expected: "Proof | ObjectRequest",
        }),
    }
}

fn first_client_bidi_stream() -> StreamId {
    StreamId::local(StreamRole::Client, StreamDirection::Bidirectional, 0)
}

#[allow(dead_code)]
fn native_symbol_datagram(
    symbol: &Symbol,
    transfer_tag: u64,
    entry: u32,
    auth_tag: Option<[u8; crate::security::tag::TAG_SIZE]>,
) -> Result<Bytes, QuicTransportError> {
    let envelope = symbol_to_envelope(symbol, transfer_tag, entry, auth_tag);
    envelope
        .encode()
        .map_err(SymbolDatagramError::from)
        .map_err(QuicTransportError::from)
}

fn quic_native_source_stream_enabled(
    total_bytes: u64,
    config: &QuicConfig,
    conn: &NativeQuicConnection,
) -> bool {
    let pacing = quic_spray_pacing_decision_from_config(
        config,
        quic_path_signal_from_native_connection(conn),
    );
    quic_reliable_source_stream_eligible(total_bytes, config, &pacing)
}

async fn send_native_source_stream_entries(
    cx: &Cx,
    conn: &mut NativeQuicConnection,
    stream: StreamId,
    prepared: &QuicPreparedSource,
    config: &QuicConfig,
) -> Result<u64, QuicTransportError> {
    let mut streamed = 0u64;
    let mut buf = vec![0_u8; config.chunk_size.max(1).min(QUIC_SOURCE_STREAM_CHUNK_BYTES)];
    for entry in &prepared.entries {
        cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
        if entry.size == 0 {
            continue;
        }
        let mut file = crate::fs::File::open(&entry.abs_path)
            .await
            .map_err(|err| {
                QuicTransportError::Source(format!("{}: {err}", entry.abs_path.display()))
            })?;
        let mut hasher = Sha256::new();
        let mut read = 0u64;
        loop {
            cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
            let n = file.read(&mut buf).await.map_err(|err| {
                QuicTransportError::Source(format!("{}: {err}", entry.abs_path.display()))
            })?;
            if n == 0 {
                break;
            }
            read = read.saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
            if read > entry.size {
                return Err(QuicTransportError::Source(format!(
                    "{} grew while streaming QUIC source bytes (read {read} bytes, manifest size {})",
                    entry.abs_path.display(),
                    entry.size
                )));
            }
            hasher.update(&buf[..n]);
            conn.write_stream_bytes(cx, stream, Bytes::copy_from_slice(&buf[..n]), false)?;
            streamed = streamed.saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
        }
        if read != entry.size {
            return Err(QuicTransportError::Source(format!(
                "{} changed while streaming QUIC source bytes (read {read} bytes, manifest size {})",
                entry.abs_path.display(),
                entry.size
            )));
        }
        let got_sha = hex_encode(&hasher.finalize());
        if got_sha != entry.sha256_hex {
            return Err(QuicTransportError::Integrity(format!(
                "{} changed while streaming QUIC source bytes (sha256 {got_sha}, manifest {})",
                entry.abs_path.display(),
                entry.sha256_hex
            )));
        }
    }
    conn.write_stream_bytes(cx, stream, Bytes::new(), true)?;
    Ok(streamed)
}

fn mark_quic_decoder_complete_from_stream(
    decoder: &mut QuicEntryDecoder,
    entry: &ManifestEntry,
    bytes: Vec<u8>,
) -> Result<(), QuicTransportError> {
    let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if len != entry.size {
        return Err(QuicTransportError::Integrity(format!(
            "source stream entry {} has {} bytes, expected {}",
            entry.index, len, entry.size
        )));
    }
    let got_sha = sha256_hex(&bytes);
    if got_sha != entry.sha256_hex {
        return Err(QuicTransportError::Integrity(format!(
            "source stream entry {} sha256 {got_sha}, expected {}",
            entry.index, entry.sha256_hex
        )));
    }
    decoder.pending_decodes.clear();
    decoder.pipeline = None;
    decoder.data = bytes;
    decoder.complete = true;
    Ok(())
}

async fn receive_native_source_stream_entries(
    cx: &Cx,
    conn: &mut NativeQuicConnection,
    stream: StreamId,
    manifest: &TransferManifest,
    decoders: &mut [QuicEntryDecoder],
    config: &QuicConfig,
) -> Result<u64, QuicTransportError> {
    let mut received = 0u64;
    for entry in &manifest.entries {
        cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
        let expected_len =
            usize::try_from(entry.size).map_err(|_| QuicTransportError::TooLarge {
                size: entry.size,
                max: usize::MAX as u64,
            })?;
        let decoder = decoders
            .iter_mut()
            .find(|decoder| decoder.index == entry.index)
            .ok_or_else(|| {
                QuicTransportError::Integrity(format!(
                    "source stream for unknown manifest entry {}",
                    entry.index
                ))
            })?;
        if expected_len == 0 {
            mark_quic_decoder_complete_from_stream(decoder, entry, Vec::new())?;
            continue;
        }
        let mut bytes = Vec::with_capacity(expected_len);
        while bytes.len() < expected_len {
            cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
            let remaining = expected_len - bytes.len();
            let chunk_len = remaining
                .min(config.chunk_size.max(1))
                .min(QUIC_SOURCE_STREAM_READ_CHUNK);
            let chunk = conn.read_stream_bytes(cx, stream, chunk_len)?;
            if chunk.is_empty() {
                return Err(QuicTransportError::Integrity(format!(
                    "source stream ended before entry {} completed ({} of {} bytes)",
                    entry.index,
                    bytes.len(),
                    expected_len
                )));
            }
            received = received.saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
            bytes.extend_from_slice(&chunk);
        }
        mark_quic_decoder_complete_from_stream(decoder, entry, bytes)?;
    }
    let extra = conn.read_stream_bytes(cx, stream, 1)?;
    if !extra.is_empty() {
        return Err(QuicTransportError::Integrity(
            "source stream carried bytes beyond the manifest total".to_string(),
        ));
    }
    if !conn.is_stream_read_eof(stream)? {
        return Err(QuicTransportError::Integrity(
            "source stream did not finish after manifest bytes".to_string(),
        ));
    }
    if received != manifest.total_bytes {
        return Err(QuicTransportError::Integrity(format!(
            "source stream delivered {received} bytes, expected {}",
            manifest.total_bytes
        )));
    }
    Ok(received)
}

#[allow(dead_code)]
fn send_native_symbol(
    cx: &Cx,
    conn: &mut NativeQuicConnection,
    symbol: &Symbol,
    transfer_tag: u64,
    entry: u32,
    auth_tag: Option<[u8; crate::security::tag::TAG_SIZE]>,
) -> Result<(), QuicTransportError> {
    if !conn.can_send_1rtt() {
        return Err(QuicTransportError::Quic(
            "send_native_symbol requires an established 1-RTT connection".to_string(),
        ));
    }
    let bytes = native_symbol_datagram(symbol, transfer_tag, entry, auth_tag)?;
    conn.send_datagram(cx, bytes)?;
    Ok(())
}

#[allow(dead_code)]
fn send_native_symbol_batch<I>(
    cx: &Cx,
    conn: &mut NativeQuicConnection,
    payloads: I,
) -> Result<usize, QuicTransportError>
where
    I: IntoIterator<Item = Bytes>,
{
    if !conn.can_send_1rtt() {
        return Err(QuicTransportError::Quic(
            "send_native_symbol_batch requires an established 1-RTT connection".to_string(),
        ));
    }
    conn.send_datagram_batch(cx, payloads)
        .map_err(QuicTransportError::from)
}

#[allow(dead_code)]
async fn spray_native_symbol_round(
    cx: &Cx,
    conn: &mut NativeQuicConnection,
    manifest: &TransferManifest,
    encoders: &mut [QuicEntryEncoder],
    pending: &std::collections::BTreeSet<u32>,
    config: &QuicConfig,
    symbol_auth: Option<&SecurityContext>,
    with_source: bool,
) -> Result<u64, QuicTransportError> {
    let tag = transfer_tag(&manifest.transfer_id);
    let mut sent = 0u64;
    let mut pacer = QuicSymbolPacer::from_native_connection_for_round(config, conn, with_source);
    let repair_batch = repair_batch_per_block(config);
    for entry in encoders
        .iter_mut()
        .filter(|entry| pending.contains(&entry.index))
    {
        cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
        for block_index in 0..entry.block_count(config)? {
            let sbn = u8::try_from(block_index).map_err(|_| QuicTransportError::TooLarge {
                size: entry.size(),
                max: u64::try_from(config.max_block_size.max(1))
                    .unwrap_or(u64::MAX)
                    .saturating_mul(u64::from(u8::MAX) + 1),
            })?;
            let block = entry.read_block(cx, sbn, config).await?;
            let already = entry.repair_cursor(sbn);
            let target_repair = if with_source {
                initial_repair_per_block(block.len(), config)
            } else {
                already.saturating_add(repair_batch)
            };
            let repair_count = target_repair.saturating_sub(already);
            if !with_source && repair_count == 0 {
                entry.set_repair_cursor(sbn, target_repair);
                continue;
            }

            let mut pipeline = encoding_pipeline(config);
            let encoded = if with_source {
                EitherNativeEncoding::Source(pipeline.encode_single_block_with_repair(
                    entry.object_id,
                    sbn,
                    &block,
                    target_repair,
                ))
            } else {
                EitherNativeEncoding::Repair(pipeline.encode_single_block_repair_range(
                    entry.object_id,
                    sbn,
                    &block,
                    already,
                    repair_count,
                ))
            };
            for symbol in encoded {
                let symbol = symbol
                    .map_err(|err| QuicTransportError::Control(err.to_string()))?
                    .into_symbol();
                let auth_tag = symbol_auth.map(|ctx| *ctx.sign_symbol_tag(&symbol).as_bytes());
                send_native_symbol(cx, conn, &symbol, tag, entry.index, auth_tag)?;
                sent = sent.saturating_add(1);
                pacer.after_symbol_sent(cx).await?;
            }
            entry.set_repair_cursor(sbn, target_repair);
        }
    }
    Ok(sent)
}

enum EitherNativeEncoding<'a> {
    Source(crate::encoding::EncodingIterator<'a>),
    Repair(crate::encoding::RepairEncodingIterator<'a>),
}

impl Iterator for EitherNativeEncoding<'_> {
    type Item = Result<crate::encoding::EncodedSymbol, crate::encoding::EncodingError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Source(iter) => iter.next(),
            Self::Repair(iter) => iter.next(),
        }
    }
}

#[allow(dead_code)]
async fn spray_native_initial_symbols(
    cx: &Cx,
    conn: &mut NativeQuicConnection,
    manifest: &TransferManifest,
    encoders: &mut [QuicEntryEncoder],
    config: &QuicConfig,
    symbol_auth: Option<&SecurityContext>,
) -> Result<u64, QuicTransportError> {
    let pending = encoders
        .iter()
        .map(|entry| entry.index)
        .collect::<std::collections::BTreeSet<_>>();
    spray_native_symbol_round(
        cx,
        conn,
        manifest,
        encoders,
        &pending,
        config,
        symbol_auth,
        true,
    )
    .await
}

#[allow(dead_code)]
async fn native_source_symbol_for_request(
    cx: &Cx,
    enc: &QuicEntryEncoder,
    request: QuicSourceSymbolRequest,
    config: &QuicConfig,
) -> Result<Symbol, QuicTransportError> {
    if request.entry != enc.index {
        return Err(QuicTransportError::Integrity(format!(
            "source request entry mismatch: request={}, encoder={}",
            request.entry, enc.index
        )));
    }
    let block = enc.read_block(cx, request.sbn, config).await?;
    let symbol_size = usize::from(config.symbol_size.max(1));
    let block_k = block.len().div_ceil(symbol_size).max(1);
    let esi = usize::try_from(request.esi).map_err(|_| {
        QuicTransportError::Integrity("source request ESI does not fit usize".to_string())
    })?;
    if esi >= block_k {
        return Err(QuicTransportError::Integrity(format!(
            "source request esi {} outside entry {} block {} K={}",
            request.esi, enc.index, request.sbn, block_k
        )));
    }

    let start = esi * symbol_size;
    let end = (start + symbol_size).min(block.len());
    let mut buffer = vec![0u8; symbol_size];
    if start < end {
        buffer[..end - start].copy_from_slice(&block[start..end]);
    }
    Ok(Symbol::new(
        SymbolId::new(enc.object_id, request.sbn, request.esi),
        buffer,
        SymbolKind::Source,
    ))
}

#[allow(dead_code)]
async fn send_native_source_symbol_requests(
    cx: &Cx,
    conn: &mut NativeQuicConnection,
    manifest: &TransferManifest,
    encoders: &[QuicEntryEncoder],
    requests: &[QuicSourceSymbolRequest],
    config: &QuicConfig,
    symbol_auth: Option<&SecurityContext>,
) -> Result<u64, QuicTransportError> {
    let tag = transfer_tag(&manifest.transfer_id);
    let mut sent = 0u64;
    let mut pacer = QuicSymbolPacer::from_native_connection(config, conn);
    for request in requests {
        cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
        let enc = encoders
            .iter()
            .find(|entry| entry.index == request.entry)
            .ok_or_else(|| {
                QuicTransportError::Integrity(format!(
                    "receiver requested source symbol for unknown entry {}",
                    request.entry
                ))
            })?;
        let symbol = native_source_symbol_for_request(cx, enc, *request, config).await?;
        let auth_tag = symbol_auth.map(|ctx| *ctx.sign_symbol_tag(&symbol).as_bytes());
        send_native_symbol(cx, conn, &symbol, tag, request.entry, auth_tag)?;
        sent = sent.saturating_add(1);
        pacer.after_symbol_sent(cx).await?;
    }
    Ok(sent)
}

#[allow(dead_code)]
async fn send_native_block_repair_requests(
    cx: &Cx,
    conn: &mut NativeQuicConnection,
    manifest: &TransferManifest,
    encoders: &mut [QuicEntryEncoder],
    requests: &[QuicBlockRepairRequest],
    config: &QuicConfig,
    symbol_auth: Option<&SecurityContext>,
) -> Result<u64, QuicTransportError> {
    let tag = transfer_tag(&manifest.transfer_id);
    let mut sent = 0u64;
    let mut pacer = QuicSymbolPacer::from_native_connection(config, conn);
    for request in requests {
        cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
        let enc = encoders
            .iter_mut()
            .find(|entry| entry.index == request.entry)
            .ok_or_else(|| {
                QuicTransportError::Integrity(format!(
                    "receiver requested repair block for unknown entry {}",
                    request.entry
                ))
            })?;
        let repair_count = usize::try_from(request.symbols).map_err(|_| {
            QuicTransportError::Integrity("repair symbol count does not fit usize".to_string())
        })?;
        let block = enc.read_block(cx, request.sbn, config).await?;
        let already = enc.repair_cursor(request.sbn);
        let target_repair = already.saturating_add(repair_count);
        quic_rqtrace(format_args!(
            "sender-native: repair_block entry={} sbn={} requested_symbols={} repair_cursor_start={} repair_cursor_target={}",
            request.entry, request.sbn, repair_count, already, target_repair
        ));
        let mut pipeline = encoding_pipeline(config);
        let sent_before_request = sent;
        for encoded in pipeline.encode_single_block_repair_range(
            enc.object_id,
            request.sbn,
            &block,
            already,
            repair_count,
        ) {
            let symbol = encoded
                .map_err(|err| QuicTransportError::Control(err.to_string()))?
                .into_symbol();
            let auth_tag = symbol_auth.map(|ctx| *ctx.sign_symbol_tag(&symbol).as_bytes());
            send_native_symbol(cx, conn, &symbol, tag, request.entry, auth_tag)?;
            sent = sent.saturating_add(1);
            pacer.after_symbol_sent(cx).await?;
        }
        let emitted_for_request = sent.saturating_sub(sent_before_request);
        if emitted_for_request != u64::from(request.symbols) {
            return Err(QuicTransportError::Integrity(format!(
                "sender emitted {emitted_for_request} repair symbols for receiver-requested deficit {} on entry {} block {}",
                request.symbols, request.entry, request.sbn
            )));
        }
        enc.set_repair_cursor(request.sbn, target_repair);
    }
    Ok(sent)
}

#[allow(dead_code)]
async fn send_native_repair_round_and_object_complete(
    cx: &Cx,
    conn: &mut NativeQuicConnection,
    control: &mut NativeQuicFrameTransport,
    manifest: &TransferManifest,
    encoders: &mut [QuicEntryEncoder],
    need: &QuicNeedMore,
    config: &QuicConfig,
    symbol_auth: Option<&SecurityContext>,
) -> Result<u64, QuicTransportError> {
    validate_quic_manifest(manifest, config)?;
    if need.pending.is_empty() && need.repair_blocks.is_empty() && need.source_symbols.is_empty() {
        send_native_object_complete(cx, conn, control, 0)?;
        return Ok(0);
    }
    validate_need_more_feedback(manifest, config, need)?;
    let requested_repair_symbols = quic_repair_symbol_total(&need.repair_blocks);
    let sent = if !need.repair_blocks.is_empty() {
        send_native_block_repair_requests(
            cx,
            conn,
            manifest,
            encoders,
            &need.repair_blocks,
            config,
            symbol_auth,
        )
        .await?
    } else if need.source_symbols.is_empty() {
        return Err(QuicTransportError::Integrity(
            "receiver NeedMore listed pending entries without targeted repair/source deficits"
                .to_string(),
        ));
    } else {
        send_native_source_symbol_requests(
            cx,
            conn,
            manifest,
            encoders,
            &need.source_symbols,
            config,
            symbol_auth,
        )
        .await?
    };
    if !need.repair_blocks.is_empty() && sent != requested_repair_symbols {
        return Err(QuicTransportError::Integrity(format!(
            "sender emitted {sent} repair symbols for receiver-requested deficit {requested_repair_symbols}"
        )));
    }
    send_native_object_complete(cx, conn, control, sent)?;
    Ok(sent)
}

#[allow(dead_code)]
async fn send_native_manifest_symbols_complete(
    cx: &Cx,
    conn: &mut NativeQuicConnection,
    control: &mut NativeQuicFrameTransport,
    manifest: &TransferManifest,
    encoders: &mut [QuicEntryEncoder],
    config: &QuicConfig,
) -> Result<u64, QuicTransportError> {
    validate_quic_manifest(manifest, config)?;
    let symbol_auth = config.symbol_auth_context()?;
    send_native_manifest(cx, conn, control, manifest)?;
    let symbols_sent =
        spray_native_initial_symbols(cx, conn, manifest, encoders, config, symbol_auth.as_ref())
            .await?;
    send_native_object_complete(cx, conn, control, symbols_sent)?;
    Ok(symbols_sent)
}

#[allow(dead_code)]
async fn send_native_prepared_source_manifest_symbols_complete(
    cx: &Cx,
    conn: &mut NativeQuicConnection,
    control: &mut NativeQuicFrameTransport,
    prepared: &QuicPreparedSource,
    config: &QuicConfig,
    source_stream: Option<StreamId>,
) -> Result<(Vec<QuicEntryEncoder>, u64), QuicTransportError> {
    let config = prepared.effective_config(config);
    config.validate()?;
    validate_quic_manifest(&prepared.manifest, &config)?;
    let mut encoders = encoders_from_prepared_source(cx, prepared, &config).await?;
    let symbols_sent = if let Some(stream) = source_stream {
        send_native_manifest(cx, conn, control, &prepared.manifest)?;
        let streamed =
            send_native_source_stream_entries(cx, conn, stream, prepared, &config).await?;
        if streamed != prepared.manifest.total_bytes {
            return Err(QuicTransportError::Integrity(format!(
                "source stream sent {streamed} bytes, expected {}",
                prepared.manifest.total_bytes
            )));
        }
        send_native_object_complete(cx, conn, control, 0)?;
        0
    } else {
        send_native_manifest_symbols_complete(
            cx,
            conn,
            control,
            &prepared.manifest,
            &mut encoders,
            &config,
        )
        .await?
    };
    Ok((encoders, symbols_sent))
}

#[allow(dead_code)]
fn finish_native_sender_transfer(
    cx: &Cx,
    conn: &mut NativeQuicConnection,
    control: &mut NativeQuicFrameTransport,
    manifest: &TransferManifest,
    peer: SocketAddr,
    receipt: ReceiveReceipt,
    symbols_sent: u64,
    feedback_rounds: u32,
) -> Result<SendReport, QuicTransportError> {
    send_native_close(cx, conn, control)?;
    if !receipt.committed {
        return Err(QuicTransportError::Integrity(
            receipt
                .reason
                .clone()
                .unwrap_or_else(|| "receiver did not commit".to_string()),
        ));
    }

    Ok(SendReport {
        transfer_id: manifest.transfer_id.clone(),
        bytes_sent: manifest.total_bytes,
        files: manifest_logical_files(manifest),
        symbols_sent,
        feedback_rounds,
        merkle_root_hex: manifest.merkle_root_hex.clone(),
        receipt,
        peer,
    })
}

#[allow(dead_code)]
async fn handle_native_sender_feedback_or_proof(
    cx: &Cx,
    conn: &mut NativeQuicConnection,
    control: &mut NativeQuicFrameTransport,
    state: &mut QuicSenderFeedbackState<'_>,
) -> Result<Option<SendReport>, QuicTransportError> {
    match receive_native_proof_or_need_more(cx, conn, control)? {
        QuicControlReply::Proof(receipt) => finish_native_sender_transfer(
            cx,
            conn,
            control,
            state.manifest,
            state.peer,
            receipt,
            state.symbols_sent,
            state.feedback_rounds,
        )
        .map(Some),
        QuicControlReply::NeedMore(need) => {
            state.feedback_rounds = state.feedback_rounds.saturating_add(1);
            state.observe_need_more(&need);
            trace_quic_aimd_feedback(cx, state);
            trace_quic_sender_need_more(
                cx,
                state.feedback_rounds,
                state.symbols_sent,
                state.sent_this_round(),
                &need,
                state.config,
                Some(state.aimd_rate_bps),
                None,
            );
            if need.pending.is_empty()
                && need.repair_blocks.is_empty()
                && need.source_symbols.is_empty()
            {
                trace_quic_sender_repair_round(
                    cx,
                    state.feedback_rounds,
                    quic_need_more_response_mode(&need),
                    state.symbols_sent,
                    0,
                    &need,
                );
                return Ok(None);
            }
            let round_config = state.next_round_config();
            let symbol_auth = round_config.symbol_auth_context()?;
            let previous_symbols_sent = state.symbols_sent;
            let response_mode = quic_need_more_response_mode(&need);
            let sent = send_native_repair_round_and_object_complete(
                cx,
                conn,
                control,
                state.manifest,
                state.encoders,
                &need,
                &round_config,
                symbol_auth.as_ref(),
            )
            .await?;
            state.mark_next_round_started(previous_symbols_sent, sent);
            trace_quic_sender_repair_round(
                cx,
                state.feedback_rounds,
                response_mode,
                previous_symbols_sent,
                sent,
                &need,
            );
            Ok(None)
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NativeSenderDrivePoint {
    HelloSent,
    ObjectCompleteSent,
}

#[allow(dead_code)]
async fn send_prepared_source_over_established_native_connection<F>(
    cx: &Cx,
    conn: &mut NativeQuicConnection,
    peer: SocketAddr,
    prepared: &QuicPreparedSource,
    config: &QuicConfig,
    peer_id: &str,
    mut drive_peer: F,
) -> Result<SendReport, QuicTransportError>
where
    F: FnMut(NativeSenderDrivePoint, &mut NativeQuicConnection) -> Result<(), QuicTransportError>,
{
    let config = prepared.effective_config(config);
    cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
    config.validate()?;
    validate_quic_manifest(&prepared.manifest, &config)?;
    let fanout_plan =
        quic_plan_initial_fanout_dispatch(&config, usize::MAX, &prepared.manifest, &[])?;
    trace_quic_fanout_dispatch_plan(cx, 0, &fanout_plan);
    let symbol_auth = config.symbol_auth_context()?;
    let symbol_auth_enabled = symbol_auth.is_some();
    let mut control = NativeQuicFrameTransport::open(cx, conn)?;
    let offered_source_stream =
        if quic_native_source_stream_enabled(prepared.manifest.total_bytes, &config, conn) {
            Some(conn.open_local_bidi(cx)?)
        } else {
            None
        };

    send_native_sender_hello(
        cx,
        conn,
        &mut control,
        &config,
        peer_id,
        symbol_auth_enabled,
        offered_source_stream,
        prepared.manifest.total_bytes,
        None,
    )?;
    drive_peer(NativeSenderDrivePoint::HelloSent, conn)?;
    let ack = receive_native_sender_hello_ack(cx, conn, &mut control)?;
    let source_stream = match (offered_source_stream, ack.source_stream) {
        (Some(stream), true) => Some(stream),
        (None, true) => {
            return Err(QuicTransportError::HandshakeRejected(
                "receiver accepted an unoffered QUIC source stream".to_string(),
            ));
        }
        _ => None,
    };

    let (mut encoders, symbols_sent) = send_native_prepared_source_manifest_symbols_complete(
        cx,
        conn,
        &mut control,
        prepared,
        &config,
        source_stream,
    )
    .await?;
    drive_peer(NativeSenderDrivePoint::ObjectCompleteSent, conn)?;

    let mut state = QuicSenderFeedbackState::new(
        &prepared.manifest,
        &mut encoders,
        &config,
        peer,
        symbols_sent,
    );
    loop {
        cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
        if let Some(report) =
            handle_native_sender_feedback_or_proof(cx, conn, &mut control, &mut state).await?
        {
            return Ok(report);
        }
        drive_peer(NativeSenderDrivePoint::ObjectCompleteSent, conn)?;
    }
}

fn decode_native_symbol_envelope(
    bytes: Bytes,
    auth_required: bool,
) -> Result<QuicSymbolEnvelope, QuicTransportError> {
    QuicSymbolEnvelope::decode_bytes(bytes, auth_required)
        .map_err(SymbolDatagramError::from)
        .map_err(QuicTransportError::from)
}

#[allow(dead_code)]
fn recv_native_symbol_envelope(
    conn: &mut NativeQuicConnection,
    auth_required: bool,
) -> Result<Option<QuicSymbolEnvelope>, QuicTransportError> {
    match conn.recv_datagram() {
        Some(bytes) => decode_native_symbol_envelope(bytes, auth_required).map(Some),
        None => Ok(None),
    }
}

#[allow(dead_code)]
fn drain_native_symbol_datagrams(
    conn: &mut NativeQuicConnection,
    manifest: &TransferManifest,
    decoders: &mut [QuicEntryDecoder],
    config: &QuicConfig,
) -> Result<u64, QuicTransportError> {
    let aggregator = primary_quic_receive_aggregator("quic-native-peer");
    let receive =
        QuicReceiveAggregation::new(&aggregator, QUIC_PRIMARY_RECEIVE_PATH_ID, Time::ZERO);
    drain_native_symbol_datagrams_with_aggregator(conn, manifest, decoders, config, receive)
}

fn drain_native_symbol_datagrams_with_aggregator(
    conn: &mut NativeQuicConnection,
    manifest: &TransferManifest,
    decoders: &mut [QuicEntryDecoder],
    config: &QuicConfig,
    receive: QuicReceiveAggregation<'_>,
) -> Result<u64, QuicTransportError> {
    let symbol_auth = config.symbol_auth_context()?;
    let auth_required = symbol_auth.is_some();
    let tag = transfer_tag(&manifest.transfer_id);
    let mut accepted = 0u64;
    let mut datagrams = VecDeque::with_capacity(NATIVE_SYMBOL_DRAIN_BATCH);
    loop {
        if conn.recv_datagram_batch(NATIVE_SYMBOL_DRAIN_BATCH, &mut datagrams) == 0 {
            break;
        }
        while let Some(bytes) = datagrams.pop_front() {
            let envelope = decode_native_symbol_envelope(bytes, auth_required)?;
            if envelope.transfer_tag != tag {
                return Err(QuicTransportError::Integrity(format!(
                    "symbol transfer tag mismatch: got {}, expected {tag}",
                    envelope.transfer_tag
                )));
            }
            if envelope.payload.len() != usize::from(config.symbol_size) {
                return Err(QuicTransportError::Integrity(format!(
                    "symbol payload has {} bytes, expected {}",
                    envelope.payload.len(),
                    config.symbol_size
                )));
            }
            let decoder = decoders
                .iter()
                .find(|decoder| decoder.index == envelope.entry)
                .ok_or_else(|| {
                    QuicTransportError::Integrity(format!(
                        "symbol for unknown manifest entry {}",
                        envelope.entry
                    ))
                })?;
            let auth_symbol = verified_authenticated_symbol_from_envelope(
                &envelope,
                decoder.object_id,
                symbol_auth.as_ref(),
            )?;
            accepted = accepted.saturating_add(feed_aggregated_symbol_for_entry(
                decoders,
                envelope.entry,
                auth_symbol,
                receive,
            )?);
        }
    }
    Ok(accepted)
}

async fn drain_native_symbol_datagrams_with_aggregator_deferred(
    cx: &Cx,
    conn: &mut NativeQuicConnection,
    manifest: &TransferManifest,
    decoders: &mut [QuicEntryDecoder],
    config: &QuicConfig,
    receive: QuicReceiveAggregation<'_>,
    decode_stats: &mut QuicDecodeStats,
) -> Result<QuicRoundSymbolStats, QuicTransportError> {
    let symbol_auth = config.symbol_auth_context()?;
    let auth_required = symbol_auth.is_some();
    let tag = transfer_tag(&manifest.transfer_id);
    let mut stats = QuicRoundSymbolStats::default();
    let mut datagrams = VecDeque::with_capacity(NATIVE_SYMBOL_DRAIN_BATCH);
    loop {
        if conn.recv_datagram_batch(NATIVE_SYMBOL_DRAIN_BATCH, &mut datagrams) == 0 {
            break;
        }
        while let Some(bytes) = datagrams.pop_front() {
            let envelope = decode_native_symbol_envelope(bytes, auth_required)?;
            if envelope.transfer_tag != tag {
                return Err(QuicTransportError::Integrity(format!(
                    "symbol transfer tag mismatch: got {}, expected {tag}",
                    envelope.transfer_tag
                )));
            }
            if envelope.payload.len() != usize::from(config.symbol_size) {
                return Err(QuicTransportError::Integrity(format!(
                    "symbol payload has {} bytes, expected {}",
                    envelope.payload.len(),
                    config.symbol_size
                )));
            }
            let decoder = decoders
                .iter()
                .find(|decoder| decoder.index == envelope.entry)
                .ok_or_else(|| {
                    QuicTransportError::Integrity(format!(
                        "symbol for unknown manifest entry {}",
                        envelope.entry
                    ))
                })?;
            stats.observed = stats.observed.saturating_add(1);
            let auth_symbol = verified_authenticated_symbol_from_envelope(
                &envelope,
                decoder.object_id,
                symbol_auth.as_ref(),
            )?;
            stats.accepted =
                stats
                    .accepted
                    .saturating_add(feed_aggregated_symbol_for_entry_deferred(
                        cx,
                        decoders,
                        envelope.entry,
                        auth_symbol,
                        receive,
                        config,
                        decode_stats,
                    )?);
            let _ = drain_ready_quic_decodes(cx, decoders, decode_stats).await?;
        }
    }
    let _ = drain_ready_quic_decodes(cx, decoders, decode_stats).await?;
    Ok(stats)
}

#[cfg_attr(not(feature = "tls"), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NativeSymbolDrainMode {
    ReadyOnly,
    #[allow(dead_code)]
    JoinPendingDecodes,
}

#[cfg_attr(not(feature = "tls"), allow(dead_code))]
async fn drain_native_symbol_datagrams_with_blocks(
    cx: &Cx,
    conn: &mut NativeQuicConnection,
    manifest: &TransferManifest,
    decoders: &mut [QuicEntryDecoder],
    config: &QuicConfig,
    decode_stats: &mut QuicDecodeStats,
    round: u32,
    mut block_counts: Option<&mut std::collections::BTreeMap<(u32, u8), (u64, u64)>>,
    drain_mode: NativeSymbolDrainMode,
    max_batches: usize,
) -> Result<(u64, u64, Vec<QuicDecodedBlock>), QuicTransportError> {
    let symbol_auth = config.symbol_auth_context()?;
    let auth_required = symbol_auth.is_some();
    let tag = transfer_tag(&manifest.transfer_id);
    let mut accepted = 0u64;
    let mut completed = Vec::new();
    let mut drained = 0usize;
    let mut drain_batches = 0usize;
    let mut datagrams = VecDeque::with_capacity(NATIVE_SYMBOL_DRAIN_BATCH);
    let mut drain_batch = VecDeque::with_capacity(NATIVE_SYMBOL_DRAIN_BATCH);
    for _ in 0..max_batches.max(1) {
        if conn.recv_datagram_batch(NATIVE_SYMBOL_DRAIN_BATCH, &mut drain_batch) == 0 {
            break;
        }
        drain_batches = drain_batches.saturating_add(1);
        datagrams.extend(drain_batch.drain(..));
    }
    while let Some(bytes) = datagrams.pop_front() {
        let envelope = decode_native_symbol_envelope(bytes, auth_required)?;
        if envelope.transfer_tag != tag {
            return Err(QuicTransportError::Integrity(format!(
                "symbol transfer tag mismatch: got {}, expected {tag}",
                envelope.transfer_tag
            )));
        }
        if envelope.payload.len() != usize::from(config.symbol_size) {
            return Err(QuicTransportError::Integrity(format!(
                "symbol payload has {} bytes, expected {}",
                envelope.payload.len(),
                config.symbol_size
            )));
        }
        let decoder_index = decoders
            .iter_mut()
            .position(|decoder| decoder.index == envelope.entry)
            .ok_or_else(|| {
                QuicTransportError::Integrity(format!(
                    "symbol for unknown manifest entry {}",
                    envelope.entry
                ))
            })?;
        let auth_symbol = verified_authenticated_symbol_from_envelope(
            &envelope,
            decoders[decoder_index].object_id,
            symbol_auth.as_ref(),
        )?;
        let block_sbn = auth_symbol.symbol().sbn();
        let transfer_decode_width = quic_transfer_decode_width(decoders, config);
        let allow_spawn_decode = quic_pending_decode_jobs(decoders) < transfer_decode_width;
        let (was_accepted, block) = feed_authenticated_symbol_take_block_deferred(
            cx,
            &mut decoders[decoder_index],
            auth_symbol,
            config,
            decode_stats,
            allow_spawn_decode,
            transfer_decode_width,
        )?;
        if let Some(block_counts) = block_counts.as_deref_mut() {
            let block_counts = block_counts.entry((envelope.entry, block_sbn)).or_default();
            block_counts.0 = block_counts.0.saturating_add(1);
            if was_accepted {
                block_counts.1 = block_counts.1.saturating_add(1);
            }
        }
        if was_accepted {
            accepted = accepted.saturating_add(1);
        }
        if let Some(block) = block {
            completed.push(block);
        }
        completed.extend(
            drain_ready_quic_decodes_with_blocks(
                cx,
                decoders,
                config,
                decode_stats,
                allow_spawn_decode,
                transfer_decode_width,
            )
            .await?,
        );
        drained = drained.saturating_add(1);
    }
    if drain_batches > 1 {
        let batches = drain_batches.to_string();
        let datagrams_drained = drained.to_string();
        let symbols_accepted = accepted.to_string();
        let completed_blocks = completed.len().to_string();
        let pending_datagrams_after = conn.pending_datagram_count().to_string();
        cx.trace_with_fields(
            "atp_quic.receive.symbol_drain_backlog",
            &[
                ("batches", batches.as_str()),
                ("datagrams_drained", datagrams_drained.as_str()),
                ("symbols_accepted", symbols_accepted.as_str()),
                ("completed_blocks", completed_blocks.as_str()),
                ("pending_datagrams_after", pending_datagrams_after.as_str()),
            ],
        );
    }
    let transfer_decode_width = quic_transfer_decode_width(decoders, config);
    match drain_mode {
        NativeSymbolDrainMode::ReadyOnly => {
            let allow_spawn_decode = quic_pending_decode_jobs(decoders) < transfer_decode_width;
            completed.extend(
                drain_ready_quic_decodes_with_blocks(
                    cx,
                    decoders,
                    config,
                    decode_stats,
                    allow_spawn_decode,
                    transfer_decode_width,
                )
                .await?,
            );
        }
        NativeSymbolDrainMode::JoinPendingDecodes => {
            completed.extend(
                join_all_quic_decodes_with_blocks(
                    cx,
                    decoders,
                    config,
                    decode_stats,
                    transfer_decode_width,
                )
                .await?,
            );
        }
    }
    for block in &completed {
        quic_progress(format_args!(
            "receiver: decode_complete round={round} transfer={} entry={} sbn={} bytes={}",
            manifest.transfer_id,
            block.entry,
            block.sbn,
            block.data.len()
        ));
    }
    Ok((
        u64::try_from(drained).unwrap_or(u64::MAX),
        accepted,
        completed,
    ))
}

#[cfg_attr(not(feature = "tls"), allow(dead_code))]
async fn join_native_symbol_decode_jobs_with_blocks(
    cx: &Cx,
    decoders: &mut [QuicEntryDecoder],
    config: &QuicConfig,
    decode_stats: &mut QuicDecodeStats,
) -> Result<Vec<QuicDecodedBlock>, QuicTransportError> {
    let transfer_decode_width = quic_transfer_decode_width(decoders, config);
    join_all_quic_decodes_with_blocks(cx, decoders, config, decode_stats, transfer_decode_width)
        .await
}

fn validate_quic_manifest(
    manifest: &TransferManifest,
    config: &QuicConfig,
) -> Result<(), QuicTransportError> {
    const MAX_QUIC_LOGICAL_MANIFEST_ENTRIES: usize = 4 * 1024 * 1024;
    // The off-wire `transfer_id` is interpolated directly into the receiver's
    // on-disk staging-directory path (native_link.rs:
    // `.atp-quic-staging-{transfer_id}-...`), which is created and then
    // `remove_dir_all`'d during a receive. A legitimate sender always emits a
    // bounded lowercase-hex token, so constrain it to a bounded alphanumeric
    // token here. Without this a hostile peer could set `transfer_id` to e.g.
    // `x/../../../../tmp/pwn` and steer the receiver's staging writes and
    // `remove_dir_all` outside the destination directory (directory traversal /
    // arbitrary delete). Mirrors the transport_tcp `validate_manifest` guard
    // (asupersync-my6ocy).
    if manifest.transfer_id.is_empty()
        || manifest.transfer_id.len() > 64
        || !manifest
            .transfer_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric())
    {
        return Err(QuicTransportError::Source(format!(
            "unsafe manifest transfer_id: {}",
            manifest.transfer_id
        )));
    }
    validate_portable_path_component(&manifest.root_name).map_err(|_| {
        QuicTransportError::Source(format!("unsafe manifest root_name: {}", manifest.root_name))
    })?;
    if manifest.total_bytes > config.max_transfer_bytes {
        return Err(QuicTransportError::TooLarge {
            size: manifest.total_bytes,
            max: config.max_transfer_bytes,
        });
    }
    let logical_entries = manifest.entries.iter().try_fold(0usize, |total, entry| {
        total.checked_add(entry.members.len().max(1))
    });
    let logical_entries = logical_entries
        .and_then(|total| {
            total.checked_add(
                manifest
                    .directory_metadata
                    .as_ref()
                    .map_or(0, |directories| directories.entries.len()),
            )
        })
        .ok_or_else(|| {
            QuicTransportError::Source("manifest logical entry count overflow".to_string())
        })?;
    if logical_entries > MAX_QUIC_LOGICAL_MANIFEST_ENTRIES {
        return Err(QuicTransportError::Source(format!(
            "manifest declares {logical_entries} logical files/directories (max {MAX_QUIC_LOGICAL_MANIFEST_ENTRIES})"
        )));
    }
    if !manifest.is_directory && manifest.entries.len() != 1 {
        return Err(QuicTransportError::Source(
            "single-file transfer manifest must contain exactly one entry".to_string(),
        ));
    }
    if manifest
        .metadata_root_hex
        .as_ref()
        .is_some_and(|root| root.len() != 64 || !root.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        return Err(QuicTransportError::Source(
            "manifest metadata_root_hex is not a 64-byte hex digest".to_string(),
        ));
    }

    let mut seen_paths = std::collections::BTreeMap::<String, String>::new();
    let mut hardlink_primaries = BTreeMap::<String, EntryMetadata>::new();
    let mut total = 0u64;
    let empty_sha_hex = hex_encode(&Sha256::digest(b""));
    for (expected, entry) in manifest.entries.iter().enumerate() {
        let expected = u32::try_from(expected).unwrap_or(u32::MAX);
        if entry.index != expected {
            return Err(QuicTransportError::Source(format!(
                "manifest entry index {} is not sequential (expected {expected})",
                entry.index
            )));
        }
        if entry.rel_path.is_empty() {
            return Err(QuicTransportError::Source(
                "manifest entry rel_path is empty".to_string(),
            ));
        }
        quic_join_relative(Path::new("base"), &entry.rel_path)?;
        if entry.metadata.as_ref().is_some_and(EntryMetadata::is_bare) {
            return Err(QuicTransportError::Source(format!(
                "manifest entry {} carries non-canonical bare metadata",
                entry.rel_path
            )));
        }
        let metadata = entry.metadata.clone().unwrap_or_default();
        if metadata.hardlink_target.is_some() && !matches!(metadata.file_kind, FileKind::Regular) {
            return Err(QuicTransportError::Source(format!(
                "manifest entry {} declares hardlink metadata on non-regular kind {:?}",
                entry.rel_path, metadata.file_kind
            )));
        }
        validate_entry_metadata_for_receive(&entry.rel_path, &metadata, &config.metadata_policy)
            .map_err(|error| {
                QuicTransportError::Source(format!(
                    "manifest entry {} has invalid metadata: {error}",
                    entry.rel_path
                ))
            })?;
        if metadata.hardlink_target.is_some() && !config.preserve_hardlinks {
            return Err(QuicTransportError::Source(format!(
                "manifest hardlink entry {} is denied by receiver policy",
                entry.rel_path
            )));
        }
        if let Some(primary_rel) = &metadata.hardlink_target {
            quic_join_relative(Path::new("base"), primary_rel)?;
            let primary_key = portable_path_collision_key(primary_rel);
            let primary_metadata = hardlink_primaries.get(&primary_key);
            if primary_rel == &entry.rel_path
                || primary_metadata.is_none()
                || seen_paths
                    .get(&primary_key)
                    .is_none_or(|seen| seen != primary_rel)
            {
                return Err(QuicTransportError::Source(format!(
                    "manifest hardlink entry {} targets missing or later primary {}",
                    entry.rel_path, primary_rel
                )));
            }
            let mut alias_metadata = metadata.clone();
            alias_metadata.hardlink_target = None;
            if primary_metadata != Some(&alias_metadata) {
                return Err(QuicTransportError::Source(format!(
                    "manifest hardlink entry {} declares metadata different from primary {}",
                    entry.rel_path, primary_rel
                )));
            }
        }
        if (!matches!(metadata.file_kind, FileKind::Regular) || metadata.hardlink_target.is_some())
            && (entry.size != 0 || entry.sha256_hex.as_str() != empty_sha_hex.as_str())
        {
            return Err(QuicTransportError::Source(format!(
                "manifest metadata-only entry {} must carry zero content",
                entry.rel_path
            )));
        }
        // Packed entry names are internal object identifiers and are never
        // committed as destination paths. Keep them out of the logical-path
        // namespace so a legitimate member named `.atp-pack-N` cannot collide
        // with its synthetic container.
        if entry.members.is_empty()
            && seen_paths
                .insert(
                    portable_path_collision_key(&entry.rel_path),
                    entry.rel_path.clone(),
                )
                .is_some()
        {
            return Err(QuicTransportError::Source(format!(
                "duplicate manifest entry path (including case collision) {}",
                entry.rel_path
            )));
        }
        if matches!(metadata.file_kind, FileKind::Regular)
            && metadata.hardlink_target.is_none()
            && entry.members.is_empty()
        {
            hardlink_primaries.insert(
                portable_path_collision_key(&entry.rel_path),
                metadata.clone(),
            );
        }
        if entry.sha256_hex.len() != 64 || !entry.sha256_hex.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(QuicTransportError::Source(format!(
                "manifest entry {} has invalid sha256_hex",
                entry.index
            )));
        }
        if !entry.members.is_empty() {
            if !manifest.is_directory {
                return Err(QuicTransportError::Source(format!(
                    "packed entry {} in a single-file transfer",
                    entry.rel_path
                )));
            }
            if entry.metadata.is_some() {
                return Err(QuicTransportError::Source(format!(
                    "packed entry {} must not carry entry-level metadata",
                    entry.rel_path
                )));
            }
            let mut expected_offset = 0u64;
            for member in &entry.members {
                if member.rel_path.is_empty() {
                    return Err(QuicTransportError::Source(
                        "packed member rel_path is empty".to_string(),
                    ));
                }
                quic_join_relative(Path::new("base"), &member.rel_path)?;
                if seen_paths
                    .insert(
                        portable_path_collision_key(&member.rel_path),
                        member.rel_path.clone(),
                    )
                    .is_some()
                {
                    return Err(QuicTransportError::Source(format!(
                        "duplicate manifest entry path (including case collision) {}",
                        member.rel_path
                    )));
                }
                if member.offset != expected_offset {
                    return Err(QuicTransportError::Source(format!(
                        "packed member {} offset {} is not contiguous (expected {expected_offset})",
                        member.rel_path, member.offset
                    )));
                }
                expected_offset = expected_offset.checked_add(member.len).ok_or_else(|| {
                    QuicTransportError::Source(format!(
                        "packed member {} byte range overflows",
                        member.rel_path
                    ))
                })?;
                if member.sha256_hex.len() != 64
                    || !member.sha256_hex.bytes().all(|b| b.is_ascii_hexdigit())
                {
                    return Err(QuicTransportError::Source(format!(
                        "packed member {} has invalid sha256_hex",
                        member.rel_path
                    )));
                }
                let member_metadata = member.metadata.clone().unwrap_or_default();
                if member.metadata.as_ref().is_some_and(EntryMetadata::is_bare) {
                    return Err(QuicTransportError::Source(format!(
                        "packed member {} carries non-canonical bare metadata",
                        member.rel_path
                    )));
                }
                validate_entry_metadata_for_receive(
                    &member.rel_path,
                    &member_metadata,
                    &config.metadata_policy,
                )
                .map_err(|error| {
                    QuicTransportError::Source(format!(
                        "packed member {} has invalid metadata: {error}",
                        member.rel_path
                    ))
                })?;
                if !matches!(member_metadata.file_kind, FileKind::Regular)
                    || member_metadata.hardlink_target.is_some()
                    || member_metadata.symlink_target.is_some()
                {
                    return Err(QuicTransportError::Source(format!(
                        "packed member {} must be a plain regular file",
                        member.rel_path
                    )));
                }
            }
            if expected_offset != entry.size {
                return Err(QuicTransportError::Source(format!(
                    "packed entry {} member spans ({expected_offset}) do not cover its size ({})",
                    entry.rel_path, entry.size
                )));
            }
        }
        total = total.checked_add(entry.size).ok_or_else(|| {
            QuicTransportError::Source("manifest entry sizes overflow u64".to_string())
        })?;
        if total > config.max_transfer_bytes {
            return Err(QuicTransportError::TooLarge {
                size: total,
                max: config.max_transfer_bytes,
            });
        }
    }
    if total != manifest.total_bytes {
        return Err(QuicTransportError::Source(format!(
            "manifest total_bytes {} does not match entry sum {total}",
            manifest.total_bytes
        )));
    }
    let mut committed_paths = Vec::new();
    for entry in &manifest.entries {
        if entry.members.is_empty() {
            committed_paths.push(entry.rel_path.as_str());
        } else {
            committed_paths.extend(entry.members.iter().map(|member| member.rel_path.as_str()));
        }
    }
    reject_quic_symlink_traversal(manifest)?;
    validate_portable_path_set(committed_paths).map_err(|error| {
        QuicTransportError::Source(format!("unsafe manifest path tree: {error}"))
    })?;
    validate_quic_directory_metadata(manifest, config)?;
    if manifest_metadata_commitment(manifest) != manifest.metadata_root_hex {
        return Err(QuicTransportError::Source(
            "manifest metadata commitment mismatch".to_string(),
        ));
    }
    validate_quic_delta_manifest(manifest)?;
    Ok(())
}

fn validate_quic_delta_manifest(manifest: &TransferManifest) -> Result<(), QuicTransportError> {
    let Some(delta) = manifest.delta_manifest.as_ref() else {
        return Ok(());
    };
    let Some(entry) = quic_delta_manifest_entry(manifest) else {
        return Err(QuicTransportError::Source(
            "QUIC delta manifest is supported only for one unpacked regular file".to_string(),
        ));
    };
    if u64::try_from(delta.chunks.len()).unwrap_or(u64::MAX) > QUIC_DELTA_MAX_MANIFEST_CHUNKS {
        return Err(QuicTransportError::Source(
            "QUIC delta manifest declares too many chunks".to_string(),
        ));
    }
    if delta.schema != ATP_DELTA_CHUNK_MANIFEST_SCHEMA {
        return Err(QuicTransportError::Source(format!(
            "unsupported QUIC delta manifest schema: {}",
            delta.schema
        )));
    }
    if delta.tree_id != manifest.merkle_root_hex {
        return Err(QuicTransportError::Source(
            "QUIC delta manifest tree id does not match the transfer Merkle root".to_string(),
        ));
    }
    let max_chunk_size = usize::try_from(MAX_FRAME_SIZE)
        .unwrap_or(usize::MAX)
        .saturating_sub(12);
    if delta.chunk_size == 0 || delta.chunk_size > max_chunk_size {
        return Err(QuicTransportError::Source(format!(
            "QUIC delta manifest chunk size {} is outside 1..={max_chunk_size}",
            delta.chunk_size
        )));
    }
    if delta.total_size_bytes != manifest.total_bytes || delta.total_size_bytes != entry.size {
        return Err(QuicTransportError::Source(format!(
            "QUIC delta manifest size {} does not match transfer size {}",
            delta.total_size_bytes, manifest.total_bytes
        )));
    }
    let max_chunk_size = u64::try_from(delta.chunk_size).unwrap_or(u64::MAX);
    let mut planner_chunks = Vec::with_capacity(delta.chunks.len());
    let mut expected_offset = 0u64;
    for (position, chunk) in delta.chunks.iter().enumerate() {
        let expected_index = u32::try_from(position).map_err(|_| {
            QuicTransportError::Source("too many QUIC delta manifest chunks".to_string())
        })?;
        let is_final = position.saturating_add(1) == delta.chunks.len();
        if chunk.index != expected_index
            || chunk.entry_index != entry.index
            || chunk.rel_path != entry.rel_path
            || chunk.entry_offset != expected_offset
            || chunk.stream_offset != expected_offset
            || chunk.size_bytes == 0
            || chunk.size_bytes > max_chunk_size
            || (!is_final && chunk.size_bytes != max_chunk_size)
        {
            return Err(QuicTransportError::Source(format!(
                "QUIC delta chunk {} has invalid index, path, offset, or size",
                chunk.index
            )));
        }
        let content_id = ContentId::new(quic_decode_delta_root(
            &chunk.content_id_hex,
            "QUIC delta content id",
        )?);
        planner_chunks.push(CasChunkRef {
            index: chunk.index,
            byte_offset: chunk.stream_offset,
            size_bytes: chunk.size_bytes,
            content_id,
        });
        expected_offset = expected_offset
            .checked_add(chunk.size_bytes)
            .ok_or_else(|| {
                QuicTransportError::Source(
                    "QUIC delta manifest chunk offsets overflow u64".to_string(),
                )
            })?;
    }
    if expected_offset != entry.size {
        return Err(QuicTransportError::Source(format!(
            "QUIC delta chunks cover {expected_offset} bytes, expected {}",
            entry.size
        )));
    }
    let planner =
        PersistentChunkManifest::new(delta.tree_id.clone(), planner_chunks).map_err(|error| {
            QuicTransportError::Source(format!("invalid QUIC delta manifest: {error}"))
        })?;
    let _ = quic_decode_delta_root(&delta.merkle_root_hex, "QUIC delta manifest Merkle root")?;
    if planner.total_size_bytes != delta.total_size_bytes
        || planner.merkle_root.to_hex() != delta.merkle_root_hex
    {
        return Err(QuicTransportError::Source(
            "QUIC delta manifest Merkle root or total size mismatch".to_string(),
        ));
    }
    json_frame(FrameType::ObjectManifest, manifest)?;
    Ok(())
}

fn validate_quic_directory_metadata_value(
    rel_path: &str,
    metadata: &EntryMetadata,
    config: &QuicConfig,
) -> Result<(), QuicTransportError> {
    if !matches!(metadata.file_kind, FileKind::Directory) {
        return Err(QuicTransportError::Source(format!(
            "directory metadata entry {rel_path} declares non-directory kind {:?}",
            metadata.file_kind
        )));
    }
    if metadata.hardlink_target.is_some()
        || metadata.symlink_target.is_some()
        || metadata.symlink_target_info.is_some()
    {
        return Err(QuicTransportError::Source(format!(
            "directory metadata entry {rel_path} declares link metadata"
        )));
    }
    if metadata.unix_mode.is_none()
        && metadata.mtime_unix_secs.is_none()
        && metadata.mtime_nanos.is_none()
        && metadata.uid.is_none()
        && metadata.gid.is_none()
        && metadata.windows_attributes.is_none()
        && metadata.xattrs.is_empty()
    {
        return Err(QuicTransportError::Source(format!(
            "directory metadata entry {rel_path} carries no fidelity fields"
        )));
    }
    validate_entry_metadata_for_receive(rel_path, metadata, &config.metadata_policy).map_err(
        |error| {
            QuicTransportError::Source(format!(
                "directory metadata entry {rel_path} has invalid metadata: {error}"
            ))
        },
    )
}

fn validate_quic_directory_metadata(
    manifest: &TransferManifest,
    config: &QuicConfig,
) -> Result<(), QuicTransportError> {
    let Some(directories) = &manifest.directory_metadata else {
        return Ok(());
    };
    if directories.is_empty() {
        return Err(QuicTransportError::Source(
            "directory metadata must be omitted when empty".to_string(),
        ));
    }
    if !manifest.is_directory {
        return Err(QuicTransportError::Source(
            "single-file transfer declares directory metadata".to_string(),
        ));
    }
    if let Some(root) = &directories.root {
        validate_quic_directory_metadata_value(".", root, config)?;
    }
    if !directories
        .entries
        .windows(2)
        .all(|pair| pair[0].rel_path < pair[1].rel_path)
    {
        return Err(QuicTransportError::Source(
            "directory metadata entries are not in strict lexicographic order".to_string(),
        ));
    }

    let mut expected = BTreeMap::<String, String>::new();
    for entry in &manifest.entries {
        let logical = if entry.members.is_empty() {
            vec![entry.rel_path.as_str()]
        } else {
            entry
                .members
                .iter()
                .map(|member| member.rel_path.as_str())
                .collect::<Vec<_>>()
        };
        for path in logical {
            let components = path.split('/').collect::<Vec<_>>();
            // Directory metadata represents only otherwise-implicit ancestors.
            // An explicit empty-directory content entry owns its own leaf metadata
            // and must never have a second commitment value for the same path.
            let directory_count = components.len().saturating_sub(1);
            let mut rendered = String::new();
            for component in components.into_iter().take(directory_count) {
                if !rendered.is_empty() {
                    rendered.push('/');
                }
                rendered.push_str(component);
                expected.insert(portable_path_collision_key(&rendered), rendered.clone());
            }
        }
    }

    let mut seen = BTreeMap::<String, String>::new();
    for directory in &directories.entries {
        quic_join_relative(Path::new("base"), &directory.rel_path)?;
        validate_quic_directory_metadata_value(&directory.rel_path, &directory.metadata, config)?;
        let key = portable_path_collision_key(&directory.rel_path);
        if let Some(previous) = seen.insert(key.clone(), directory.rel_path.clone()) {
            return Err(QuicTransportError::Source(format!(
                "duplicate or case-colliding directory metadata paths: {previous} and {}",
                directory.rel_path
            )));
        }
        let Some(expected_path) = expected.get(&key) else {
            return Err(QuicTransportError::Source(format!(
                "directory metadata path {} is not represented by the transfer tree",
                directory.rel_path
            )));
        };
        if expected_path != &directory.rel_path {
            return Err(QuicTransportError::Source(format!(
                "directory metadata path {} aliases transfer directory {expected_path}",
                directory.rel_path
            )));
        }
    }
    Ok(())
}

fn quic_safe_base_for_root_name(
    dest_dir: &Path,
    root_name: &str,
) -> Result<PathBuf, QuicTransportError> {
    validate_portable_path_component(root_name).map_err(|_| {
        QuicTransportError::Source(format!("unsafe manifest root_name: {root_name}"))
    })?;
    Ok(dest_dir.join(root_name))
}

fn quic_join_relative(base: &Path, rel: &str) -> Result<PathBuf, QuicTransportError> {
    validate_portable_relative_path(rel).map_err(|_| {
        QuicTransportError::Source(format!("unsafe path component in entry: {rel}"))
    })?;
    let mut out = base.to_path_buf();
    for component in rel.split('/') {
        out.push(component);
    }
    Ok(out)
}

async fn reject_quic_destination_symlink_prefix(
    base: &Path,
    out_path: &Path,
) -> Result<(), QuicTransportError> {
    reject_quic_destination_symlink_path(base, out_path, true).await
}

/// Whether `path` is one of the operating system's own symlinked mount
/// points (macOS: `/tmp`, `/var`, `/etc` -> `/private/...`).
///
/// The destination-ancestor symlink rule tolerates these: it exists to
/// catch a destination directory swapped for a link that escapes the root,
/// and the OS layout above every temp directory is not that
/// (br-asupersync-bi2462.21.3).
fn is_os_symlinked_mount_point(path: &Path) -> bool {
    cfg!(target_os = "macos") && matches!(path.to_str(), Some("/tmp" | "/var" | "/etc"))
}

async fn reject_quic_destination_symlink_ancestors(
    base: &Path,
    out_path: &Path,
) -> Result<(), QuicTransportError> {
    reject_quic_destination_symlink_path(base, out_path, false).await
}

async fn reject_quic_destination_symlink_path(
    base: &Path,
    out_path: &Path,
    include_leaf: bool,
) -> Result<(), QuicTransportError> {
    let rel = out_path.strip_prefix(base).map_err(|_| {
        QuicTransportError::Source(format!(
            "destination path {} is outside safe base {}",
            out_path.display(),
            base.display()
        ))
    })?;

    // `base` is below the caller-selected destination directory. Revalidate
    // every outer ancestor on each mutation too: otherwise replacing dest_dir
    // with a junction after the one-time prepare pass makes `base` appear to be
    // a normal directory reached through an escaped namespace.
    for ancestor in base
        .ancestors()
        .skip(1)
        .filter(|path| !path.as_os_str().is_empty())
    {
        if is_os_symlinked_mount_point(ancestor) {
            // macOS lays out /tmp, /var and /etc as symlinks into /private;
            // they are the operating system's own namespace, not an escape
            // route a peer could plant (br-asupersync-bi2462.21.3).
            continue;
        }
        reject_quic_existing_symlink(ancestor).await?;
    }

    let components = rel.components().collect::<Vec<_>>();
    let mut current = base.to_path_buf();
    if include_leaf || !components.is_empty() {
        reject_quic_existing_symlink(&current).await?;
    }
    let component_count = components.len();
    for (index, component) in components.into_iter().enumerate() {
        let Component::Normal(component) = component else {
            return Err(QuicTransportError::Source(format!(
                "unsafe destination component in {}",
                out_path.display()
            )));
        };
        current.push(component);
        if include_leaf || index + 1 < component_count {
            reject_quic_existing_symlink(&current).await?;
        }
    }
    Ok(())
}

async fn reject_quic_existing_symlink(path: &Path) -> Result<(), QuicTransportError> {
    match path_is_link_or_reparse(path).await {
        Ok(true) => Err(QuicTransportError::Source(format!(
            "destination path crosses existing symlink or reparse point: {}",
            path.display()
        ))),
        Ok(false) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

/// Creates the receiver's destination root and rejects any symlink or reparse
/// point on its ancestor chain, before and after the create.
///
/// A relative destination (`atp recv out/dir`, the bench harness's cell paths)
/// ends its `ancestors()` walk at the empty path, which names no file: the
/// post-create pass below must skip it, exactly as the per-entry ancestor
/// walks already do, or every relative destination fails with a spurious
/// "No such file or directory" after the manifest (asupersync-wlbrlr).
async fn prepare_quic_destination_root(dest_dir: &Path) -> Result<(), QuicTransportError> {
    for candidate in dest_dir
        .ancestors()
        .filter(|path| !path.as_os_str().is_empty())
    {
        match path_is_link_or_reparse(candidate).await {
            Ok(true) => {
                return Err(QuicTransportError::Source(format!(
                    "destination path crosses existing symlink or reparse point: {}",
                    candidate.display()
                )));
            }
            Ok(false) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    crate::fs::create_dir_all(dest_dir).await?;
    for candidate in dest_dir
        .ancestors()
        .filter(|path| !path.as_os_str().is_empty())
    {
        match path_is_link_or_reparse(candidate).await {
            Ok(true) => {
                return Err(QuicTransportError::Source(format!(
                    "destination path became a symlink or reparse point: {}",
                    candidate.display()
                )));
            }
            Ok(false) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn manifest_metadata_commitment(manifest: &TransferManifest) -> Option<String> {
    // The commitment covers LOGICAL files: a packed entry contributes one
    // pair per member (the pack entry itself is an internal container and
    // carries no metadata), so it is invariant to how files were packed.
    let metadata_pairs: Vec<(String, EntryMetadata)> = manifest
        .entries
        .iter()
        .flat_map(|entry| {
            if entry.members.is_empty() {
                vec![(
                    entry.rel_path.clone(),
                    entry.metadata.clone().unwrap_or_default(),
                )]
            } else {
                entry
                    .members
                    .iter()
                    .map(|member| {
                        (
                            member.rel_path.clone(),
                            member.metadata.clone().unwrap_or_default(),
                        )
                    })
                    .collect()
            }
        })
        .collect();
    let mut metadata_refs: Vec<(&str, &EntryMetadata)> = metadata_pairs
        .iter()
        .map(|(path, metadata)| (path.as_str(), metadata))
        .collect();
    if let Some(directory_metadata) = &manifest.directory_metadata {
        metadata_refs.extend(directory_metadata.commitment_pairs());
    }
    metadata_commitment(&metadata_refs)
}

/// Reject a manifest where a later entry is nested under an earlier symlink
/// entry. Lexical path sanitization blocks `..`, but without this check the
/// receiver could create `link -> /tmp/outside` and then write `link/file`.
fn reject_quic_symlink_traversal(manifest: &TransferManifest) -> Result<(), QuicTransportError> {
    let symlink_paths: Vec<&str> = manifest
        .entries
        .iter()
        .filter(|entry| {
            entry
                .metadata
                .as_ref()
                .is_some_and(|metadata| matches!(metadata.file_kind, FileKind::Symlink))
        })
        .map(|entry| entry.rel_path.as_str())
        .collect();
    if symlink_paths.is_empty() {
        return Ok(());
    }
    let entry_and_member_paths = manifest.entries.iter().flat_map(|entry| {
        std::iter::once(entry.rel_path.as_str())
            .chain(entry.members.iter().map(|member| member.rel_path.as_str()))
    });
    for path in entry_and_member_paths {
        let path_key = portable_path_collision_key(path);
        for symlink in &symlink_paths {
            let symlink_key = portable_path_collision_key(symlink);
            if path_key.len() > symlink_key.len()
                && path_key.as_bytes()[symlink_key.len()] == b'/'
                && path_key.starts_with(&symlink_key)
            {
                return Err(QuicTransportError::Source(format!(
                    "manifest entry {path} is nested under symlink entry {symlink}; refusing to \
                     write through a link"
                )));
            }
        }
    }
    Ok(())
}

fn trace_quic_metadata_skips(cx: &Cx, out_path: &Path, report: &MetadataApplyReport) {
    if cx.trace_buffer().is_none() {
        return;
    }
    let path = out_path.display().to_string();
    for (field, reason) in &report.skipped {
        cx.trace_with_fields(
            "atp_quic_metadata_skipped",
            &[
                ("path", path.as_str()),
                ("field", *field),
                ("reason", reason.as_str()),
            ],
        );
    }
}

#[cfg(unix)]
fn verify_quic_required_unix_regular_metadata(
    out_path: &Path,
    expected: &EntryMetadata,
    observed: &EntryMetadata,
) -> Result<(), String> {
    if !matches!(expected.file_kind, FileKind::Regular) {
        return Ok(());
    }
    if let Some(expected_mode) = expected.unix_mode
        && observed.unix_mode != Some(expected_mode)
    {
        let observed_mode = observed
            .unix_mode
            .map_or_else(|| "missing".to_string(), |mode| format!("{mode:#06o}"));
        return Err(format!(
            "{}: required QUIC metadata field mode did not materialize exactly: expected {expected_mode:#06o}, observed {observed_mode}",
            out_path.display()
        ));
    }
    if let Some(expected_seconds) = expected.mtime_unix_secs {
        let expected_nanos = expected.mtime_nanos.unwrap_or(0);
        if observed.mtime_unix_secs != Some(expected_seconds)
            || observed.mtime_nanos.unwrap_or(0) != expected_nanos
        {
            return Err(format!(
                "{}: required QUIC metadata field mtime did not materialize exactly: expected ({expected_seconds}, {expected_nanos}), observed ({:?}, {:?})",
                out_path.display(),
                observed.mtime_unix_secs,
                observed.mtime_nanos
            ));
        }
    }
    Ok(())
}

fn verify_quic_required_unix_regular_metadata_sync(
    out_path: &Path,
    metadata: &EntryMetadata,
) -> Result<(), StreamingError> {
    #[cfg(unix)]
    if matches!(metadata.file_kind, FileKind::Regular)
        && (metadata.unix_mode.is_some() || metadata.mtime_unix_secs.is_some())
    {
        let policy = MetadataPolicy {
            preserve_unix_permissions: metadata.unix_mode.is_some(),
            preserve_timestamps: metadata.mtime_unix_secs.is_some(),
            ..MetadataPolicy::portable()
        };
        let observed = crate::net::atp::transport_common::metadata::read_entry_metadata_sync(
            out_path, &policy,
        )?;
        verify_quic_required_unix_regular_metadata(out_path, metadata, &observed)
            .map_err(StreamingError::new)?;
    }
    #[cfg(not(unix))]
    let _ = (out_path, metadata);
    Ok(())
}

fn apply_quic_entry_metadata_sync_verified(
    out_path: &Path,
    metadata: &EntryMetadata,
) -> Result<MetadataApplyReport, StreamingError> {
    let report =
        crate::net::atp::transport_common::metadata::apply_entry_metadata_sync(out_path, metadata)?;
    verify_quic_required_unix_regular_metadata_sync(out_path, metadata)?;
    Ok(report)
}

async fn apply_quic_metadata_verified(
    out_path: &Path,
    metadata: &EntryMetadata,
) -> Result<MetadataApplyReport, QuicTransportError> {
    let out_path = out_path.to_path_buf();
    let metadata = metadata.clone();
    crate::runtime::spawn_blocking(move || {
        apply_quic_entry_metadata_sync_verified(&out_path, &metadata)
    })
    .await
    .map_err(QuicTransportError::from)
}

#[cfg(feature = "tls")]
async fn apply_quic_entry_metadata(
    cx: &Cx,
    out_path: &Path,
    entry: &ManifestEntry,
) -> Result<(), QuicTransportError> {
    if let Some(metadata) = &entry.metadata {
        let report = apply_quic_metadata_verified(out_path, metadata).await?;
        trace_quic_metadata_skips(cx, out_path, &report);
    }
    Ok(())
}

async fn apply_quic_directory_metadata(
    cx: &Cx,
    base: &Path,
    manifest: &TransferManifest,
) -> Result<(), QuicTransportError> {
    let mut directory_values = BTreeMap::<&str, &EntryMetadata>::new();
    if let Some(directories) = &manifest.directory_metadata {
        for directory in &directories.entries {
            directory_values.insert(directory.rel_path.as_str(), &directory.metadata);
        }
    }
    for entry in &manifest.entries {
        if entry.members.is_empty() {
            if let Some(metadata) = entry
                .metadata
                .as_ref()
                .filter(|metadata| matches!(metadata.file_kind, FileKind::Directory))
            {
                directory_values.insert(entry.rel_path.as_str(), metadata);
            }
        }
    }

    let mut entries = directory_values.into_iter().collect::<Vec<_>>();
    entries.sort_by(|left, right| {
        right
            .0
            .split('/')
            .count()
            .cmp(&left.0.split('/').count())
            .then_with(|| right.0.cmp(left.0))
    });
    for (rel_path, metadata) in entries {
        let path = quic_join_relative(base, rel_path)?;
        reject_quic_destination_symlink_prefix(base, &path).await?;
        crate::fs::create_dir_all(&path).await?;
        reject_quic_destination_symlink_prefix(base, &path).await?;
        let report = apply_quic_metadata_verified(&path, metadata).await?;
        trace_quic_metadata_skips(cx, &path, &report);
    }
    if let Some(root) = manifest
        .directory_metadata
        .as_ref()
        .and_then(|directories| directories.root.as_ref())
    {
        reject_quic_destination_symlink_prefix(base, base).await?;
        crate::fs::create_dir_all(base).await?;
        reject_quic_destination_symlink_prefix(base, base).await?;
        let report = apply_quic_metadata_verified(base, root).await?;
        trace_quic_metadata_skips(cx, base, &report);
    }
    Ok(())
}

#[cfg(feature = "tls")]
async fn apply_quic_member_metadata(
    cx: &Cx,
    out_path: &Path,
    member: &PackedMember,
) -> Result<(), QuicTransportError> {
    if let Some(metadata) = &member.metadata {
        let report = apply_quic_metadata_verified(out_path, metadata).await?;
        trace_quic_metadata_skips(cx, out_path, &report);
    }
    Ok(())
}

fn trace_quic_special_file_skipped(cx: &Cx, out_path: &Path, kind: FileKind) {
    if cx.trace_buffer().is_none() {
        return;
    }
    let path = out_path.display().to_string();
    let kind = format!("{kind:?}");
    cx.trace_with_fields(
        "atp_quic_special_file_skipped",
        &[("path", path.as_str()), ("kind", kind.as_str())],
    );
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QuicMetadataCommit {
    Regular,
    Committed,
    Skipped,
}

async fn commit_quic_metadata_entry(
    cx: &Cx,
    base: &Path,
    out_path: &Path,
    entry: &ManifestEntry,
    config: &QuicConfig,
) -> Result<QuicMetadataCommit, QuicTransportError> {
    let Some(metadata) = &entry.metadata else {
        return Ok(QuicMetadataCommit::Regular);
    };
    if matches!(metadata.file_kind, FileKind::Symlink) {
        reject_quic_destination_symlink_ancestors(base, out_path).await?;
    } else {
        reject_quic_destination_symlink_prefix(base, out_path).await?;
    }

    if metadata.file_kind.is_special() {
        if matches!(metadata.file_kind, FileKind::Fifo) && config.allow_special_files {
            #[cfg(unix)]
            {
                if let Some(parent) = out_path.parent() {
                    crate::fs::create_dir_all(parent).await?;
                }
                reject_quic_destination_symlink_prefix(base, out_path).await?;
                let mode = metadata.unix_mode.unwrap_or(0o644);
                let _ = crate::fs::remove_file(out_path).await;
                crate::net::atp::transport_common::metadata::recreate_fifo(out_path, mode).await?;
                let report = apply_quic_metadata_verified(out_path, metadata).await?;
                trace_quic_metadata_skips(cx, out_path, &report);
                return Ok(QuicMetadataCommit::Committed);
            }
        }
        trace_quic_special_file_skipped(cx, out_path, metadata.file_kind);
        return Ok(QuicMetadataCommit::Skipped);
    }

    if let Some(parent) = out_path.parent() {
        crate::fs::create_dir_all(parent).await?;
    }

    // Parent creation may have materialized prefixes that were absent during
    // the first check. Revalidate immediately before the filesystem mutation
    // so an external junction/reparse swap cannot rely on that stale result.
    if matches!(metadata.file_kind, FileKind::Symlink) {
        reject_quic_destination_symlink_ancestors(base, out_path).await?;
    } else {
        reject_quic_destination_symlink_prefix(base, out_path).await?;
    }

    if matches!(metadata.file_kind, FileKind::Directory) {
        crate::fs::create_dir_all(out_path).await?;
        reject_quic_destination_symlink_prefix(base, out_path).await?;
        return Ok(QuicMetadataCommit::Committed);
    }

    if matches!(metadata.file_kind, FileKind::Symlink) {
        commit_symlink_transactionally(&entry.rel_path, out_path, metadata).await?;
        return Ok(QuicMetadataCommit::Committed);
    }

    if let Some(primary_rel) = &metadata.hardlink_target {
        let primary_path = quic_join_relative(base, primary_rel)?;
        reject_quic_destination_symlink_prefix(base, &primary_path).await?;
        commit_hardlink_transactionally(&primary_path, out_path).await?;
        return Ok(QuicMetadataCommit::Committed);
    }

    Ok(QuicMetadataCommit::Regular)
}

#[cfg(test)]
async fn commit_decoded_entries(
    cx: &Cx,
    dest_dir: &Path,
    manifest: &TransferManifest,
    decoders: &[QuicEntryDecoder],
    symbols_accepted: u64,
    feedback_rounds: u32,
    decode_stats: QuicDecodeStats,
    config: &QuicConfig,
) -> Result<(ReceiveReceipt, Vec<PathBuf>), QuicTransportError> {
    commit_decoded_entries_with_options(
        cx,
        dest_dir,
        manifest,
        decoders,
        symbols_accepted,
        feedback_rounds,
        decode_stats,
        config,
        &QuicReceiveOptions::default(),
    )
    .await
}

async fn commit_decoded_entries_with_options(
    cx: &Cx,
    dest_dir: &Path,
    manifest: &TransferManifest,
    decoders: &[QuicEntryDecoder],
    symbols_accepted: u64,
    feedback_rounds: u32,
    decode_stats: QuicDecodeStats,
    config: &QuicConfig,
    options: &QuicReceiveOptions,
) -> Result<(ReceiveReceipt, Vec<PathBuf>), QuicTransportError> {
    let mut receipt = verify_in_memory_receipt(manifest, decoders);
    receipt.symbols_accepted = symbols_accepted;
    receipt.feedback_rounds = feedback_rounds;
    receipt.decode_count = decode_stats.decode_count;
    receipt.decode_micros = decode_stats.decode_micros;
    if !receipt.committed {
        return Ok((receipt, Vec::new()));
    }

    prepare_quic_destination_root(dest_dir).await?;
    let base = quic_safe_base_for_root_name(dest_dir, &manifest.root_name)?;
    reject_quic_existing_symlink(dest_dir).await?;
    let mut committed_paths = Vec::with_capacity(manifest.entries.len().saturating_add(1));
    if manifest.is_directory && manifest.entries.is_empty() {
        reject_quic_destination_symlink_prefix(&base, &base).await?;
        crate::fs::create_dir_all(&base).await?;
        reject_quic_destination_symlink_prefix(&base, &base).await?;
        committed_paths.push(base.clone());
    }
    for entry in &manifest.entries {
        cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
        let decoder = decoders
            .iter()
            .find(|decoder| decoder.index == entry.index)
            .ok_or_else(|| {
                QuicTransportError::Integrity(format!(
                    "decoded entry {} missing during commit",
                    entry.index
                ))
            })?;
        if !entry.members.is_empty() {
            // Packed entry: split the verified pack into its member files.
            for member in &entry.members {
                let member_path = quic_join_relative(&base, &member.rel_path)?;
                reject_quic_destination_symlink_prefix(&base, &member_path).await?;
                if let Some(parent) = member_path.parent() {
                    crate::fs::create_dir_all(parent).await?;
                }
                reject_quic_destination_symlink_prefix(&base, &member_path).await?;
                let slice = packed_member_slice(&decoder.data, member).ok_or_else(|| {
                    QuicTransportError::Integrity(format!(
                        "packed member {} range escapes its verified entry",
                        member.rel_path
                    ))
                })?;
                let report = crate::net::atp::transport_common::metadata::commit_regular_bytes_with_metadata_verified_transactionally(
                    &member_path,
                    slice,
                    member.metadata.as_ref(),
                    options.sparse_files(),
                    verify_quic_required_unix_regular_metadata_sync,
                )
                .await?;
                trace_quic_metadata_skips(cx, &member_path, &report);
                committed_paths.push(member_path);
            }
            continue;
        }
        let out_path = if manifest.is_directory {
            quic_join_relative(&base, &entry.rel_path)?
        } else {
            base.clone()
        };
        match commit_quic_metadata_entry(cx, &base, &out_path, entry, config).await? {
            QuicMetadataCommit::Committed => {
                committed_paths.push(out_path);
                continue;
            }
            QuicMetadataCommit::Skipped => continue,
            QuicMetadataCommit::Regular => {}
        }
        reject_quic_destination_symlink_prefix(&base, &out_path).await?;
        if let Some(parent) = out_path.parent() {
            crate::fs::create_dir_all(parent).await?;
        }
        reject_quic_destination_symlink_prefix(&base, &out_path).await?;
        let report = crate::net::atp::transport_common::metadata::commit_regular_bytes_with_metadata_verified_transactionally(
            &out_path,
            &decoder.data,
            entry.metadata.as_ref(),
            options.sparse_files(),
            verify_quic_required_unix_regular_metadata_sync,
        )
        .await?;
        trace_quic_metadata_skips(cx, &out_path, &report);
        committed_paths.push(out_path);
    }

    apply_quic_directory_metadata(cx, &base, manifest).await?;

    receipt.committed_paths = committed_paths
        .iter()
        .map(|path| path.display().to_string())
        .collect();
    Ok((receipt, committed_paths))
}

async fn receive_native_symbol_round(
    cx: &Cx,
    connection: &mut NativeQuicConnection,
    control: &mut NativeQuicFrameTransport,
    manifest: &TransferManifest,
    decoders: &mut [QuicEntryDecoder],
    config: &QuicConfig,
    aggregator: &MultipathAggregator,
    symbols_accepted: &mut u64,
    feedback_rounds: &mut u32,
    decode_stats: &mut QuicDecodeStats,
) -> Result<Option<QuicNeedMore>, QuicTransportError> {
    cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
    let round_stats = drain_native_symbol_datagrams_with_aggregator_deferred(
        cx,
        connection,
        manifest,
        decoders,
        config,
        QuicReceiveAggregation::new(aggregator, QUIC_PRIMARY_RECEIVE_PATH_ID, cx.now())
            .with_trace(cx),
        decode_stats,
    )
    .await?;
    *symbols_accepted = (*symbols_accepted).saturating_add(round_stats.accepted);
    let round_complete = receive_native_object_complete(cx, connection, control)?;
    let _ = join_all_quic_decodes(cx, decoders, decode_stats).await?;
    decode_stats.add(assemble_completed_entries(decoders));

    let pending = pending_entries(decoders);
    if pending.is_empty() {
        return Ok(None);
    }
    if *feedback_rounds >= config.max_feedback_rounds {
        return Err(QuicTransportError::NoConvergence {
            rounds: *feedback_rounds,
            pending: pending.len(),
        });
    }
    let round_loss_fraction =
        receiver_round_loss_fraction(round_stats.observed, round_complete.round_symbols_sent);
    let round = (*feedback_rounds).saturating_add(1);
    let repair_symbol_round_cap = quic_repair_symbol_round_cap(config, round_loss_fraction);
    let (repair_blocks, repair_accounting) = block_repair_requests_with_accounting(
        decoders,
        config,
        repair_symbol_round_cap,
        round_loss_fraction,
        round,
    );
    let source_symbols = if repair_blocks.is_empty() {
        source_symbol_requests(decoders, MAX_SOURCE_SYMBOL_REQUESTS_PER_FEEDBACK_ROUND)
    } else {
        Vec::new()
    };
    let progress = quic_pending_decode_progress(decoders, &pending, config);
    let need = QuicNeedMore {
        feedback_round: round,
        pending,
        repair_blocks,
        source_symbols,
        round_symbols_observed: Some(round_stats.observed),
        round_loss_fraction,
        round_symbols_accepted: Some(round_stats.accepted),
        repair_base_deficit_symbols: Some(repair_accounting.base_deficit_symbols),
        repair_loss_compensated_target_symbols: Some(
            repair_accounting.loss_compensated_target_symbols,
        ),
        repair_request_gap_to_target_symbols: Some(repair_accounting.request_gap_to_target_symbols),
        repair_symbol_round_cap: Some(u64::try_from(repair_symbol_round_cap).unwrap_or(u64::MAX)),
        pending_rank: Some(progress.rank),
        pending_rank_columns: Some(progress.rank_columns),
        pending_rank_deficit: Some(progress.rank_deficit),
        pending_decode_jobs: Some(progress.pending_decode_jobs),
    };
    let pending_count = need.pending.len().to_string();
    let block_request_count = need.repair_blocks.len().to_string();
    let repair_symbol_count = need
        .repair_blocks
        .iter()
        .fold(0u64, |acc, request| {
            acc.saturating_add(u64::from(request.symbols))
        })
        .to_string();
    let source_request_count = need.source_symbols.len().to_string();
    let accepted_count = symbols_accepted.to_string();
    let round_symbols_sent = round_complete.round_symbols_sent.to_string();
    let round_symbols_observed = round_stats.observed.to_string();
    let round_symbols_accepted = round_stats.accepted.to_string();
    let round_loss_fraction = format!("{:.6}", need.round_loss_fraction.unwrap_or(0.0));
    let repair_block_requests = quic_repair_block_request_summary(&need.repair_blocks);
    let repair_symbol_round_cap = repair_symbol_round_cap.to_string();
    let repair_block_request_cap = MAX_REPAIR_BLOCK_REQUESTS_PER_FEEDBACK_ROUND.to_string();
    let repair_base_deficit = repair_accounting.base_deficit_symbols.to_string();
    let repair_loss_compensated_target = repair_accounting
        .loss_compensated_target_symbols
        .to_string();
    let repair_request_gap_to_target = repair_accounting.request_gap_to_target_symbols.to_string();
    let round_text = round.to_string();
    // LogEntry caps fields at MAX_FIELDS (16) and task/region/span correlation
    // ids are inserted with priority at collect time, evicting the OLDEST
    // fields when full. Keep this emission at <=12 explicit fields so all four
    // correlation ids fit without evicting `round`/`pending`. The dropped
    // per-round detail (round_symbols_sent, repair_block_requests, the two
    // caps) still prints on the env-gated ATP_RQ_TRACE line below.
    cx.trace_with_fields(
        "atp_quic.receive.need_more",
        &[
            ("round", round_text.as_str()),
            ("pending", pending_count.as_str()),
            ("block_requests", block_request_count.as_str()),
            ("repair_symbols", repair_symbol_count.as_str()),
            ("source_requests", source_request_count.as_str()),
            ("round_symbols_observed", round_symbols_observed.as_str()),
            ("round_symbols_accepted", round_symbols_accepted.as_str()),
            ("round_loss_fraction", round_loss_fraction.as_str()),
            ("symbols_accepted", accepted_count.as_str()),
            ("repair_base_deficit", repair_base_deficit.as_str()),
            (
                "repair_loss_compensated_target",
                repair_loss_compensated_target.as_str(),
            ),
            (
                "repair_request_gap_to_target",
                repair_request_gap_to_target.as_str(),
            ),
        ],
    );
    quic_rqtrace(format_args!(
        "receiver: NeedMore round={} pending={} repair_blocks={} requested_repair_symbols={} source_requests={} round_symbols_sent={} round_symbols_observed={} round_symbols_accepted={} round_loss_fraction={} symbols_accepted={} repair_base_deficit={} repair_loss_compensated_target={} repair_request_gap_to_target={} max_feedback_rounds={} repair_symbol_round_cap={} repair_block_request_cap={} repair_block_requests={}",
        round,
        pending_count,
        block_request_count,
        repair_symbol_count,
        source_request_count,
        round_symbols_sent,
        round_symbols_observed,
        round_symbols_accepted,
        round_loss_fraction,
        accepted_count,
        repair_base_deficit,
        repair_loss_compensated_target,
        repair_request_gap_to_target,
        config.max_feedback_rounds,
        repair_symbol_round_cap,
        repair_block_request_cap,
        repair_block_requests,
    ));
    send_native_need_more(cx, connection, control, &need)?;
    *feedback_rounds = round;
    Ok(Some(need))
}

async fn receive_established_native_connection(
    cx: &Cx,
    mut connection: NativeQuicConnection,
    peer: SocketAddr,
    dest_dir: &Path,
    config: QuicConfig,
    peer_id: &str,
    options: QuicReceiveOptions,
) -> Result<ReceiveReport, QuicTransportError> {
    let mut config = effective_quic_receiver_config(&config)?;
    let mut control = NativeQuicFrameTransport::for_stream(first_client_bidi_stream());
    let symbol_auth = config.symbol_auth_context()?;
    let symbol_auth_enabled = symbol_auth.is_some();

    let hello = receive_native_sender_hello_and_ack(
        cx,
        &mut connection,
        &mut control,
        &config,
        peer_id,
        symbol_auth_enabled,
    )?;
    // Adopt the sender's (bounded-accepted in `reject_hello_reason`) block geometry so the
    // receiver's decoders + block-count math match the sender's encode geometry for large entries.
    // Without this the handshake would accept a scaled block size but decode with the receiver's
    // default, corrupting reassembly (ASUP-E802 / br-asupersync-j73ili).
    if let Ok(hello_block) = usize::try_from(hello.max_block_size) {
        config.max_block_size = hello_block;
    }
    let source_stream = if hello.source_stream
        && quic_native_source_stream_enabled(hello.total_bytes, &config, &connection)
    {
        source_stream_from_hello(&hello)?
    } else {
        None
    };
    let manifest = receive_native_manifest(cx, &mut connection, &mut control)?;
    validate_quic_manifest(&manifest, &config)?;
    // The reliable source stream never RaptorQ-decodes, so build bare decoders that
    // skip the RaptorQ object-metadata block-partition validation (which caps objects
    // at max_block_size*256 and would fail-closed reject any source-stream object
    // >~128 MiB). The datagram/fountain path still gets full decoders. (j73ili)
    let mut decoders = if source_stream.is_some() {
        source_stream_decoders_from_manifest(&manifest)
    } else {
        decoders_from_manifest(&manifest, &config)?
    };
    let aggregator = primary_quic_receive_aggregator(peer.to_string());
    let mut symbols_accepted = 0u64;
    let mut feedback_rounds = 0u32;
    let mut decode_stats = QuicDecodeStats::default();

    if let Some(stream) = source_stream {
        if hello.total_bytes != manifest.total_bytes {
            return Err(QuicTransportError::Integrity(format!(
                "source stream hello total_bytes {} did not match manifest total_bytes {}",
                hello.total_bytes, manifest.total_bytes
            )));
        }
        let streamed = receive_native_source_stream_entries(
            cx,
            &mut connection,
            stream,
            &manifest,
            &mut decoders,
            &config,
        )
        .await?;
        if streamed != manifest.total_bytes {
            return Err(QuicTransportError::Integrity(format!(
                "source stream delivered {streamed} bytes, expected {}",
                manifest.total_bytes
            )));
        }
        let complete = receive_native_object_complete(cx, &mut connection, &mut control)?;
        if complete.round_symbols_sent != 0 {
            return Err(QuicTransportError::Integrity(format!(
                "source stream round reported {} datagram symbols",
                complete.round_symbols_sent
            )));
        }
    } else {
        loop {
            if receive_native_symbol_round(
                cx,
                &mut connection,
                &mut control,
                &manifest,
                &mut decoders,
                &config,
                &aggregator,
                &mut symbols_accepted,
                &mut feedback_rounds,
                &mut decode_stats,
            )
            .await?
            .is_none()
            {
                break;
            }
        }
    }

    let (receipt, committed_paths) = commit_decoded_entries_with_options(
        cx,
        dest_dir,
        &manifest,
        &decoders,
        symbols_accepted,
        feedback_rounds,
        decode_stats,
        &config,
        &options,
    )
    .await?;
    send_native_proof(cx, &mut connection, &mut control, &receipt)?;
    let _ = send_native_close(cx, &mut connection, &mut control);

    if !receipt.committed {
        return Err(QuicTransportError::Integrity(
            receipt
                .reason
                .clone()
                .unwrap_or_else(|| "receiver did not commit".to_string()),
        ));
    }

    Ok(ReceiveReport {
        transfer_id: manifest.transfer_id,
        bytes_received: receipt.bytes_received,
        files: receipt.files,
        committed: true,
        symbols_accepted: receipt.symbols_accepted,
        feedback_rounds: receipt.feedback_rounds,
        decode_count: receipt.decode_count,
        decode_micros: receipt.decode_micros,
        committed_paths,
        peer,
    })
}

/// Emit a deterministic, structured config summary at the start of a transport
/// operation (the "config summary on start" logging requirement). Routes
/// through [`Cx::trace_with_fields`] so production stays silent unless a trace
/// sink is attached — no stdout/stderr from the runtime. The env-gated
/// `ATP_QUIC_TRACE` hook (see `quic_native`) remains the per-frame diagnostic
/// channel for the B2/B3 wire paths.
fn trace_config_summary(
    cx: &Cx,
    operation: &str,
    config: &QuicConfig,
    peer_id: &str,
    receive_options: Option<&QuicReceiveOptions>,
) {
    let protocol = ATP_QUIC_PROTOCOL.to_string();
    let symbol_size = config.symbol_size.to_string();
    let max_block_size = config.max_block_size.to_string();
    let max_datagram_size = config.max_datagram_size.to_string();
    let repair_overhead = format!("{:.4}", config.repair_overhead);
    let max_transfer_bytes = config.max_transfer_bytes.to_string();
    let chunk_size = config.chunk_size.to_string();
    let idle_timeout = format!("{:?}", config.idle_timeout);
    let handshake_timeout = format!("{:?}", config.handshake_timeout);
    let accept_timeout = format!("{:?}", config.accept_timeout);
    let max_active_connections = config.max_active_connections.to_string();
    let max_feedback_rounds = config.max_feedback_rounds.to_string();
    let datagram_fanout = config.datagram_fanout.to_string();
    let bwlimit_bps = config
        .bwlimit_bps
        .map_or_else(|| "none".to_string(), |limit| limit.to_string());
    let max_spray_symbols_per_flush = config.max_spray_symbols_per_flush.to_string();
    let responsiveness_pressure = format!("{:.6}", config.responsiveness_pressure);
    let metadata_policy = format!("{:?}", config.metadata_policy);
    let allow_special_files = config.allow_special_files.to_string();
    let preserve_hardlinks = config.preserve_hardlinks.to_string();
    let sparse_files = receive_options.map_or_else(
        || "not-applicable".to_string(),
        |options| options.sparse_files().to_string(),
    );
    cx.trace_with_fields(
        "atp_quic.transport.start",
        &[
            ("operation", operation),
            ("protocol", &protocol),
            ("peer_id", peer_id),
            ("chunk_size", &chunk_size),
            ("symbol_size", &symbol_size),
            ("max_block_size", &max_block_size),
            ("max_datagram_size", &max_datagram_size),
            ("repair_overhead", &repair_overhead),
            ("max_transfer_bytes", &max_transfer_bytes),
            ("max_active_connections", &max_active_connections),
            ("max_feedback_rounds", &max_feedback_rounds),
            ("datagram_fanout", &datagram_fanout),
        ],
    );
    // The three timeouts live on the companion `.config` entry: both entries
    // must stay at <=12 explicit fields so prioritized task/region/span
    // correlation ids never evict the leading fields (br-asupersync-an0t8o).
    cx.trace_with_fields(
        "atp_quic.transport.config",
        &[
            ("operation", operation),
            ("peer_id", peer_id),
            ("idle_timeout", &idle_timeout),
            ("handshake_timeout", &handshake_timeout),
            ("accept_timeout", &accept_timeout),
            ("bwlimit_bps", &bwlimit_bps),
            ("max_spray_symbols_per_flush", &max_spray_symbols_per_flush),
            ("responsiveness_pressure", &responsiveness_pressure),
            ("metadata_policy", &metadata_policy),
            ("allow_special_files", &allow_special_files),
            ("preserve_hardlinks", &preserve_hardlinks),
            ("sparse_files", &sparse_files),
        ],
    );
}

// ─── Public API: send ────────────────────────────────────────────────────────

/// Compute the exact content and metadata roots a QUIC send prepares for
/// `source` under `config`, without opening a network connection.
///
/// This executes the same source walk, hardlink resolution, packing, hashing,
/// directory capture, and manifest validation as [`send_path`]. It is intended
/// for retained preflight/postflight evidence; comparing roots captured before
/// a live send with roots captured from the source and committed destination
/// afterwards supports a bounded point-in-time comparison. It is not an atomic
/// filesystem snapshot and does not exclude transient intervening mutations.
pub async fn source_integrity_roots(
    cx: &Cx,
    source: &Path,
    config: &QuicConfig,
) -> Result<(String, Option<String>), QuicTransportError> {
    cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
    let prepared = prepare_source_manifest(cx, source, config).await?;
    Ok((
        prepared.manifest.merkle_root_hex.clone(),
        prepared.manifest.metadata_root_hex.clone(),
    ))
}

/// Transfer the file or directory at `source` to `addr` over a real QUIC
/// connection.
///
/// Mirrors [`transport_tcp::send_path`]. The B2 sender performs the streaming
/// source walk/hash/manifest preflight, then (with the `tls` feature) opens a
/// real native QUIC connection to `addr`: it runs the genuine `rustls::quic`
/// TLS-1.3 handshake over a UDP socket — verifying the server identity against
/// the configured roots (no insecure skip-verify) — and drives the full sender
/// coroutine (Hello, manifest, RaptorQ symbol spray over QUIC DATAGRAMs, and the
/// fountain feedback loop) until the receiver returns a committed Proof.
///
/// Requires `QuicConfig::client_tls` to be set; without it (or without the
/// `tls` feature) it fails closed — there is no insecure transport path.
///
/// [`transport_tcp::send_path`]: crate::net::atp::transport_tcp::send_path
pub async fn send_path(
    cx: &Cx,
    addr: SocketAddr,
    source: &Path,
    config: QuicConfig,
    peer_id: &str,
) -> Result<SendReport, QuicTransportError> {
    send_path_with_limiter_report(cx, addr, source, config, peer_id)
        .await
        .map(|outcome| outcome.report)
}

/// [`send_path`] that also returns the sender's limiter telemetry.
///
/// Same transfer, same [`SendReport`]; the extra [`QuicSendLimiterReport`]
/// says why the sender waited (pacing, cwnd, stream credit, ATP's in-flight
/// admission cap, queue drains, receiver window), what QUIC recovery looked
/// like (peak/final cwnd, ssthresh, RTTs, loss timeouts, retransmitted bytes,
/// PTO count) and what the UDP socket was given (applied buffer sizes,
/// send-batch errors). `atp send --transport quic` prints it as the `limiter`
/// JSON block. Observational only: it does not change throughput
/// (br-asupersync-bi2462.2).
pub async fn send_path_with_limiter_report(
    cx: &Cx,
    addr: SocketAddr,
    source: &Path,
    config: QuicConfig,
    peer_id: &str,
) -> Result<QuicSendOutcome, QuicTransportError> {
    cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
    config.validate()?;
    trace_config_summary(cx, "send_path", &config, peer_id, None);
    let prepared = prepare_source_manifest(cx, source, &config).await?;
    let config = prepared.effective_config(&config);
    config.validate()?;
    let fanout_plan =
        quic_plan_initial_fanout_dispatch(&config, usize::MAX, &prepared.manifest, &[])?;
    trace_quic_fanout_dispatch_plan(cx, 0, &fanout_plan);
    #[cfg(feature = "tls")]
    {
        let (report, limiter) =
            native_link::send_prepared_over_udp(cx, addr, &prepared, &config, peer_id).await?;
        Ok(QuicSendOutcome { report, limiter })
    }
    #[cfg(not(feature = "tls"))]
    {
        let _ = (addr, prepared);
        Err(QuicTransportError::Config(
            "ATP-over-QUIC send requires the `tls` feature for the native QUIC/TLS-1.3 \
             handshake; there is no insecure transport path"
                .to_string(),
        ))
    }
}

/// Bind a server UDP socket on `listen`, accept exactly one transfer over a real
/// QUIC connection, write it under `dest_dir`, verify it, and return a report.
///
/// The native-UDP server counterpart to [`send_path`] (parallel to
/// [`transport_tcp::receive_once`], but it owns the UDP endpoint and runs the
/// real `rustls::quic` accept-side handshake presenting the configured server
/// certificate). Requires [`QuicConfig::server_tls`]; only available with the
/// `tls` feature.
///
/// [`transport_tcp::receive_once`]: crate::net::atp::transport_tcp::receive_once
#[cfg(feature = "tls")]
pub async fn receive_path(
    cx: &Cx,
    listen: SocketAddr,
    dest_dir: &Path,
    config: QuicConfig,
    peer_id: &str,
) -> Result<ReceiveReport, QuicTransportError> {
    receive_path_with_options(
        cx,
        listen,
        dest_dir,
        config,
        peer_id,
        QuicReceiveOptions::default(),
    )
    .await
}

/// [`receive_path`] with explicit receiver-only filesystem options.
#[cfg(feature = "tls")]
pub async fn receive_path_with_options(
    cx: &Cx,
    listen: SocketAddr,
    dest_dir: &Path,
    config: QuicConfig,
    peer_id: &str,
    options: QuicReceiveOptions,
) -> Result<ReceiveReport, QuicTransportError> {
    cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
    options.validate()?;
    config.validate()?;
    trace_config_summary(cx, "receive_path", &config, peer_id, Some(&options));
    let endpoint = native_link::bind_server_endpoint(cx, listen).await?;
    native_link::receive_on_endpoint_with_options(cx, endpoint, dest_dir, &config, peer_id, options)
        .await
}

// ─── Public API: receive ─────────────────────────────────────────────────────

/// Accept exactly one transfer on `endpoint`, write it to `dest_dir`, verify it,
/// and return a report.
///
/// Mirrors [`transport_tcp::receive_once`] (with a [`ManagedQuicEndpoint`] in
/// place of a `TcpListener`). This entry point consumes the next connection
/// already routed into the managed endpoint and delegates to
/// [`receive_connection`]. Endpoint packet pumping is still owned by the native
/// endpoint layer; when no routed connection is available, this function fails
/// closed with a typed accept timeout rather than reporting fake success.
///
/// [`transport_tcp::receive_once`]: crate::net::atp::transport_tcp::receive_once
pub async fn receive_once(
    cx: &Cx,
    endpoint: &mut ManagedQuicEndpoint,
    dest_dir: &Path,
    config: QuicConfig,
    peer_id: &str,
) -> Result<ReceiveReport, QuicTransportError> {
    receive_once_with_options(
        cx,
        endpoint,
        dest_dir,
        config,
        peer_id,
        QuicReceiveOptions::default(),
    )
    .await
}

/// [`receive_once`] with explicit receiver-only filesystem options.
pub async fn receive_once_with_options(
    cx: &Cx,
    endpoint: &mut ManagedQuicEndpoint,
    dest_dir: &Path,
    config: QuicConfig,
    peer_id: &str,
    options: QuicReceiveOptions,
) -> Result<ReceiveReport, QuicTransportError> {
    cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
    options.validate()?;
    config.validate()?;
    trace_config_summary(cx, "receive_once", &config, peer_id, Some(&options));

    let Some(accepted) = endpoint.take_next_connection(cx)? else {
        return Err(QuicTransportError::Timeout {
            operation: "receive_once accept",
            timeout: config.accept_timeout,
        });
    };

    let connection_id = format!("{:?}", accepted.connection_id);
    let peer = accepted.peer_addr.to_string();
    cx.trace_with_fields(
        "atp_quic.receive_once.accepted",
        &[
            ("connection_id", connection_id.as_str()),
            ("peer", peer.as_str()),
            ("peer_id", peer_id),
        ],
    );

    receive_established_native_connection(
        cx,
        accepted.connection,
        accepted.peer_addr,
        dest_dir,
        config,
        peer_id,
        options,
    )
    .await
}

/// Drive a single accepted QUIC connection through the receive protocol.
///
/// Mirrors [`transport_tcp::receive_connection`] (with a
/// [`NativeQuicConnection`] in place of a `TcpStream`). The caller supplies an
/// already-established native QUIC connection whose first client-initiated
/// bidirectional stream carries ATP control frames and whose DATAGRAM queue
/// carries RaptorQ symbols. Endpoint accept/connect and continuous event-loop
/// pumping remain separate B2/B3 work; this function is the accepted-connection
/// receiver body.
///
/// [`transport_tcp::receive_connection`]: crate::net::atp::transport_tcp::receive_connection
// `connection` is owned by value to mirror `transport_tcp::receive_connection`'s
// `stream: TcpStream` exactly; B3 consumes it to drive the receive protocol.
pub async fn receive_connection(
    cx: &Cx,
    connection: NativeQuicConnection,
    peer: SocketAddr,
    dest_dir: &Path,
    config: QuicConfig,
    peer_id: &str,
) -> Result<ReceiveReport, QuicTransportError> {
    receive_connection_with_options(
        cx,
        connection,
        peer,
        dest_dir,
        config,
        peer_id,
        QuicReceiveOptions::default(),
    )
    .await
}

/// [`receive_connection`] with explicit receiver-only filesystem options.
pub async fn receive_connection_with_options(
    cx: &Cx,
    connection: NativeQuicConnection,
    peer: SocketAddr,
    dest_dir: &Path,
    config: QuicConfig,
    peer_id: &str,
    options: QuicReceiveOptions,
) -> Result<ReceiveReport, QuicTransportError> {
    cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
    options.validate()?;
    config.validate()?;
    trace_config_summary(cx, "receive_connection", &config, peer_id, Some(&options));
    receive_established_native_connection(cx, connection, peer, dest_dir, config, peer_id, options)
        .await
}

/// Drain routed endpoint connections, handling each accepted connection as a
/// receive.
///
/// Mirrors [`transport_tcp::serve`] (with a [`ManagedQuicEndpoint`] in place of
/// a `TcpListener`). This B3 slice handles connections already routed into the
/// managed endpoint. Live endpoint packet pumping and indefinite listener
/// ownership remain lower-level native endpoint work.
///
/// [`transport_tcp::serve`]: crate::net::atp::transport_tcp::serve
// Owned `endpoint` / `dest_dir` / `peer_id` / `on_result` mirror
// `transport_tcp::serve`'s by-value signature exactly; this queued-connection
// B3 slice consumes them while draining already-routed connections.
#[allow(clippy::needless_pass_by_value)]
pub async fn serve<F>(
    cx: &Cx,
    endpoint: ManagedQuicEndpoint,
    dest_dir: PathBuf,
    config: QuicConfig,
    peer_id: String,
    on_result: F,
) -> Result<(), QuicTransportError>
where
    F: FnMut(Result<ReceiveReport, QuicTransportError>),
{
    serve_with_options(
        cx,
        endpoint,
        dest_dir,
        config,
        peer_id,
        QuicReceiveOptions::default(),
        on_result,
    )
    .await
}

/// [`serve`] with explicit receiver-only filesystem options.
#[allow(clippy::needless_pass_by_value)]
pub async fn serve_with_options<F>(
    cx: &Cx,
    mut endpoint: ManagedQuicEndpoint,
    dest_dir: PathBuf,
    config: QuicConfig,
    peer_id: String,
    options: QuicReceiveOptions,
    mut on_result: F,
) -> Result<(), QuicTransportError>
where
    F: FnMut(Result<ReceiveReport, QuicTransportError>),
{
    cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
    options.validate()?;
    config.validate()?;
    trace_config_summary(cx, "serve", &config, &peer_id, Some(&options));

    loop {
        cx.checkpoint().map_err(|_| QuicTransportError::Cancelled)?;
        let Some(accepted) = endpoint.take_next_connection(cx)? else {
            return Ok(());
        };
        let connection_id = format!("{:?}", accepted.connection_id);
        let peer = accepted.peer_addr.to_string();
        cx.trace_with_fields(
            "atp_quic.serve.accepted",
            &[
                ("connection_id", connection_id.as_str()),
                ("peer", peer.as_str()),
                ("peer_id", peer_id.as_str()),
            ],
        );
        let result = receive_established_native_connection(
            cx,
            accepted.connection,
            accepted.peer_addr,
            &dest_dir,
            config.clone(),
            &peer_id,
            options,
        )
        .await;
        on_result(result);
    }
}

#[cfg(test)]
include!("transport_quic_tests.rs");
