//! ATP-over-RaptorQ transport (v1): the *fast, robust* ATP data plane.
//!
//! Where [`crate::net::atp::transport_tcp`] moves bytes over a single reliable
//! TCP stream, this transport is built for saturating the pipe on a lossy,
//! high-latency internet path:
//!
//! - **Data plane = RaptorQ fountain symbols over UDP.** Each file entry is
//!   erasure-coded ([`crate::raptorq`], RFC 6330 systematic RaptorQ) into source
//!   plus repair symbols. Symbols are *fungible*: any `K (+ε)` of them recover
//!   the entry, from any socket, in any order. Loss is absorbed by repair
//!   symbols instead of head-of-line-blocking retransmits.
//! - **Multi-socket fan-out.** Symbols are sprayed round-robin across `N` UDP
//!   sockets so a single flow's congestion control / per-socket buffer does not
//!   cap throughput.
//! - **Reliable control plane = one TCP connection** reusing the canonical
//!   `AtpFrameCodec`: handshake (transfer id + receiver UDP port + coding
//!   params), the transfer manifest, fountain *NeedMore* feedback, and the final
//!   verified receipt.
//!
//! # Integrity (fail-closed, identical guarantee to `transport_tcp`)
//!
//! After decode, the receiver (1) checks every entry's SHA-256 against the
//! manifest, (2) verifies the versioned logical-file and directory metadata
//! commitment, and
//! (3) rebuilds the deterministic flat
//! [`crate::atp::object::ObjectGraph`] and compares the flat Merkle root to the
//! manifest root. Only if both hold does it atomically write the destination and
//! report `committed = true`. Any mismatch, oversize entry, unreachable peer, or
//! undecodable transfer is a hard error.
//!
//! # Fountain feedback loop
//!
//! v1 uses a bounded request/response loop rather than a continuous concurrent
//! ARQ, which keeps it correct on the current runtime:
//!
//! 1. Sender sprays every entry's source symbols across the UDP sockets, plus
//!    optional initial repair symbols when `repair_overhead > 1.0`, then sends
//!    `ObjectComplete` on TCP.
//! 2. Receiver feeds arriving symbols into a per-entry [`DecodingPipeline`].
//!    On `ObjectComplete` it replies with either a `Proof` receipt (all entries
//!    decoded → verified + committed) or a `NeedMore` list of still-incomplete
//!    entry indices.
//! 3. For each `NeedMore` round the sender generates a *fresh* batch of repair
//!    symbols (higher ESI range — RaptorQ is rateless) for the listed entries
//!    and resprays. Bounded by `max_feedback_rounds`; exhausting them is a hard
//!    error, never a silent partial success.
//!
//! On a low-loss path the initial over-provision means round 0 succeeds; the
//! loop only engages under real loss, which the loopback loss-injection test
//! exercises deterministically.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Adaptive block-size / overhead / fan-out optimizer; see
/// `docs/atp_rq_adaptive_design.md`.
pub mod adaptive;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use smallvec::SmallVec;

use crate::atp::delta::{CasChunkRef, PersistentChunkManifest};
use crate::atp::object::ContentId;
use crate::atp::object::MetadataPolicy;
use crate::atp::safety::{
    portable_path_collision_key, validate_portable_path_component, validate_portable_path_set,
    validate_portable_relative_path,
};
use crate::bytes::BytesMut;
use crate::codec::Decoder;
use crate::cx::Cx;
use crate::decoding::{
    BlockDecodeJob, BlockDecodeKind, BlockDecodeOutcome, DecodingConfig, DecodingPipeline,
    DeferredSymbolAcceptResult, MissingSourceSymbol, RejectReason, SymbolAcceptResult,
    run_block_decode_job,
};
use crate::encoding::{EncodedSymbol, EncodingPipeline, MAX_SOURCE_BLOCKS, max_object_size};
use crate::io::{AsyncReadExt, AsyncWriteExt, ReadBuf};
use crate::net::atp::bonding::{
    BondTransferDescriptor, BondedDonorSymbolEmission, DonorAssignment, schedule_bonded_donor_spray,
};
use crate::net::atp::datagram::beacons::{BeaconMeasurement, BeaconScheduler};
use crate::net::atp::datagram::congestion::{
    CongestionConfig, CongestionController, DatagramRateConfig, DatagramRateController,
    DatagramRateDecision, DatagramRateSample,
};
use crate::net::atp::loss::detector::{AtpLossDetector, LossRecommendation};
use crate::net::atp::protocol::codec::AtpFrameCodec;
use crate::net::atp::protocol::frames::{Frame, FrameType, MAX_FRAME_SIZE, ProtocolVersion};
use crate::net::atp::protocol::session::TransferNonce;
use crate::net::atp::protocol::varint::VarInt;
use crate::net::atp::transport_common::delta::ATP_DELTA_CHUNK_MANIFEST_SCHEMA;
use crate::net::atp::transport_common::metadata::{
    DirectoryMetadataEntry, DirectoryMetadataManifest, EntryMetadata, HardlinkIdentity,
    MetadataApplyReport, PathLinkKind, apply_entry_metadata, capture_directory_metadata_manifest,
    classify_path_link_sync, commit_staged_regular_file_transactionally, inode_key_if_regular_sync,
    metadata_commitment, path_is_link_or_reparse, read_entry_metadata_sync,
    validate_entry_metadata_for_receive,
};
use crate::net::atp::transport_common::{
    DeltaChunkWire, DeltaManifestWire, DeltaObjectRequest, DeltaWireMode, EntryDigest,
    MultiObjectSplitConfig, StreamingError, flat_merkle_root_from_digests, hash_file_streaming,
    hex_encode, plan_multi_object_split,
};
use crate::net::{TcpListener, TcpStream, UDP_MAX_GSO_SEGMENTS, UdpBufferConfig, UdpSocket};
use crate::security::authenticated::AuthenticatedSymbol;
use crate::security::tag::TAG_SIZE;
use crate::security::{AuthMode, AuthenticationTag, SecurityContext};
use crate::types::resource::{PoolConfig, SymbolPool};
use crate::types::symbol::{ObjectId, ObjectParams, Symbol, SymbolId, SymbolKind};
use crate::util::entropy::{EntropySource, OsEntropy};
use adaptive::{AdaptiveController, AdaptivePolicy, BlockPlan, PathEstimate, PathSignalSample};

/// Protocol identifier carried in the handshake; bump on wire-incompatible
/// changes.
pub const ATP_RQ_PROTOCOL: u32 = 4;

/// Schema carried inside [`RqMetadataManifest`].
const RQ_METADATA_MANIFEST_VERSION: u8 = 1;

/// Magic prefix on every UDP symbol datagram (`"ATRQ"`).
const SYMBOL_MAGIC: u32 = 0x4154_5251;

/// Default RaptorQ symbol payload size.
///
/// Kept small enough that one symbol plus the authenticated datagram header and
/// IPv4/UDP framing stays under a 1500-byte Ethernet MTU, while avoiding the
/// packet-rate tax of 1 KiB symbols on 100 Mbit links.
pub const DEFAULT_SYMBOL_SIZE: u16 = 1400;

/// Default source-block ceiling.
///
/// With 1400-byte symbols this bounds a block at ~5992 source symbols (well
/// under the RFC 6330 K=56403 cap) and lets a single entry span up to 256
/// blocks (SBN is a `u8`), i.e. up to ~2 GiB per encoded object at this default
/// block size. Larger logical files are split into ordered RaptorQ objects by
/// [`split_large_entries`] so each object's K stays bounded (E-12).
pub const DEFAULT_MAX_BLOCK_SIZE: usize = 8 * 1024 * 1024;

/// Target source-symbol count for the effective transfer block size.
///
/// RaptorQ's matrix work grows sharply with K. A K~512 block is small enough to
/// keep decode/repair work bounded on commodity fleet hosts while still sending
/// large enough UDP bursts to amortize control feedback.
const TARGET_SOURCE_SYMBOLS_PER_BLOCK: usize = 512;
/// Byte ceiling for the normal streaming block-size target.
const TARGET_STREAMING_BLOCK_BYTES: usize = 4 * 1024 * 1024;
/// Maximum encoded ATP-RQ symbols sent in one connected UDP batch.
///
/// Match the UDP GSO segment budget so fixed-size RQ symbols fill one
/// super-packet before the sender flushes. Fanout must not multiply this
/// aggregate burst, or a clean round-0 ramp can overrun the receiver despite
/// aggregate pacing.
const RQ_SEND_BATCH_PER_SOCKET: usize = UDP_MAX_GSO_SEGMENTS;

/// Default round-0 repair multiplier.
///
/// The default keeps the fast source-first shape so trusted/lab RQ receivers can
/// repair sparse source-symbol holes directly before falling back to fountain
/// repair. Adaptive per-round FEC can still raise the sprayed repair overhead
/// without changing this receiver-side source-streaming gate.
pub const DEFAULT_REPAIR_OVERHEAD: f64 = 1.0;

/// Default number of UDP sockets the sender sprays across.
///
/// A single stream is the stable default for the clean round-0 pacing ramp.
/// Multi-stream fanout remains opt-in for targeted experiments.
pub const DEFAULT_UDP_FANOUT: usize = 1;

/// Default ceiling on a single transfer's total bytes (receiver buffers + decode
/// matrices live in memory in v1).
pub const DEFAULT_MAX_TRANSFER_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// Default maximum time a one-shot RQ receiver waits for the control connection.
///
/// This matches the TCP transport's fail-closed accept bound so scripted
/// `atp recv --once` users cannot hang forever when the sender never connects.
pub const DEFAULT_ACCEPT_TIMEOUT: Duration = Duration::from_secs(60);

/// Default maximum time an RQ sender waits to open the TCP control connection.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(60);

/// Fixed chunk size for the first authenticated RQ delta-control rollout. The
/// first rollout selects only full-object vs no-op, so near-frame-sized chunks
/// keep the signed manifest bounded while covering the 500 MiB resync cell.
const RQ_DELTA_CHUNK_SIZE: usize = 1024 * 1024 - 12;
/// Bound the signed manifest independently of the transport-wide frame limit.
const RQ_DELTA_MAX_MANIFEST_CHUNKS: u64 = 4_096;
/// Reserve space for session bindings and the authentication tag around a
/// delta-capable `ObjectManifest`.
const RQ_DELTA_ENVELOPE_WIRE_BUDGET: usize = 2 * 1024;
/// Protocol-wide bound for authenticated receiver UDP endpoint advertisements.
const RQ_DELTA_MAX_ADVERTISED_UDP_PORTS: usize = 256;

/// Maximum number of files a single transfer manifest may declare. This bounds
/// receiver bookkeeping derived from attacker-controlled control-plane JSON.
const MAX_MANIFEST_ENTRIES: usize = 4 * 1024 * 1024;

/// E-15 tree coalescing: files strictly smaller than this become candidates for
/// packing into a combined RaptorQ object. The threshold intentionally includes
/// the benchmark `tree_small` generator's 1 MiB max-size bucket so those entries
/// share the packed-object receiver staging path instead of becoming thousands
/// of cache-skipping single-file RQ objects.
const PACK_THRESHOLD: u64 = 1024 * 1024 + 1;

/// E-15 tree coalescing: target size for a combined RaptorQ object. The packer
/// greedily fills a pack with small files until adding the next would exceed this
/// (a pack always holds at least one file, so a lone file larger than the target
/// but smaller than [`PACK_THRESHOLD`] still forms its own pack). Roughly one
/// RaptorQ object's worth of bytes — large enough to collapse the per-object
/// runtime overhead, small enough that a lost symbol does not span the whole tree.
const PACK_TARGET: u64 = 8 * 1024 * 1024;

/// Keep a staging descriptor hot for large entries only when the manifest is
/// small enough that the receiver cannot retain too many open files.
const ENTRY_STAGING_FILE_CACHE_MIN_BYTES: u64 = 1024 * 1024;
const ENTRY_STAGING_FILE_CACHE_MAX_ENTRIES: usize = 128;
const RQ_SINGLE_FILE_FRAGMENT_STAGING_DIR: &str = ".atp-rq-fragment-staging";

/// Default bound on fountain feedback rounds before failing closed.
pub const DEFAULT_MAX_FEEDBACK_ROUNDS: u32 = 16;

/// Default receiver-side quiet drain after each round-complete marker.
pub const DEFAULT_ROUND_TAIL_DRAIN_MS: u64 = 2;

/// Default source-retransmit feedback rounds.
///
/// Bounded sparse retransmit is default-on for the source-first path because
/// entry-level repair feedback otherwise re-sprays every block of a large file
/// when only a few systematic symbols are missing. After these early rounds the
/// transport falls back to fountain repair for bursty or non-sparse loss.
pub const DEFAULT_SOURCE_RETRANSMIT_ROUNDS: u32 = 2;

/// Hard cap on source-symbol retransmit requests in one feedback frame. Larger
/// loss bursts fall back to fountain repair rather than creating huge JSON
/// control messages.
pub const DEFAULT_MAX_SOURCE_RETRANSMIT_REQUESTS: usize = 8192;

/// Default receiver-side quiet drain after each round-complete marker.
pub const DEFAULT_ROUND_TAIL_DRAIN: Duration = Duration::from_millis(DEFAULT_ROUND_TAIL_DRAIN_MS);

/// Cold-start aggregate sender pace before feedback evidence exists.
///
/// This is deliberately below a typical LAN burst and above the 100 Mbps rsync
/// baseline target. The pacer uses short symbol bursts with sleeps, so the
/// receiver can drain UDP continuously instead of absorbing a full parallel
/// encode burst in the kernel receive buffer.
const RQ_COLD_START_PACING_BPS: u64 = 16 * 1024 * 1024;
const RQ_MIN_PACING_BPS: u64 = 512 * 1024;
const RQ_MAX_PACING_BPS: u64 = 64 * 1024 * 1024;
/// Explicitly loss-free round-0 sprays can probe above cold-start after each
/// cold-start-sized byte step of emitted datagrams. Loss-configured rounds keep
/// the older AIMD floor/cap path; UDP fanout shares one aggregate pacer and one
/// aggregate send batch limit so additional sockets cannot multiply the
/// clean-ramp burst.
const RQ_ROUND0_CLEAN_RAMP_STEP_BYTES: u64 = RQ_COLD_START_PACING_BPS;
const RQ_ROUND0_CLEAN_RAMP_ADD_BYTES_PER_S: u64 = 8 * 1024 * 1024;
const RQ_ROUND0_CLEAN_RAMP_MAX_PACING_BPS: u64 = 128 * 1024 * 1024;
const RQ_ROUND0_CLEAN_RAMP_FANOUT_MAX_PACING_BPS: u64 = 32 * 1024 * 1024;
/// Small, explicitly clean transfers should not pay proactive RaptorQ repair
/// setup in round 0 when the peer does not take the control-source fast lane.
/// Keep this UDP/RQ fallback gate below large-object lanes; large clean should
/// use the disk-backed control-source stream instead.
const RQ_SMALL_CLEAN_SOURCE_ONLY_MAX_BYTES: u64 = 64 * 1024 * 1024;
const RQ_SMALL_CLEAN_SOURCE_ONLY_MAX_REPAIR_OVERHEAD: f64 = 1.001;
/// Maximum ATP wire frame size expressed as a `usize` for control-source sizing.
const RQ_CONTROL_SOURCE_FRAME_MAX_BYTES: usize = MAX_FRAME_SIZE as usize;
/// Maximum no-extension ATP frame header for source `ObjectData` frames:
/// version(1) + ObjectData type(2) + large payload length(4) + extension count(1).
const RQ_CONTROL_SOURCE_WIRE_HEADER_MAX_BYTES: usize = 1 + 2 + 4 + 1;
const RQ_CONTROL_SOURCE_DATA_HEADER: usize = 4 + 8;
const RQ_CONTROL_SOURCE_AUTH_DATA_HEADER: usize = RQ_CONTROL_SOURCE_DATA_HEADER + TAG_SIZE;
const RQ_CONTROL_SOURCE_AUTH_SYMBOL_DOMAIN: &[u8] =
    b"asupersync.atp.rq.control-source-data-auth.v1\0";
/// Control-stream payload chunk for the clean/near-clean source-stream lane.
///
/// Fill each ATP frame to the largest safe no-extension `ObjectData` frame.
/// A 500 MiB clean transfer becomes about 500 bounded control frames instead
/// of ~1000 half-full frames or hundreds of thousands of RQ source datagrams.
const RQ_CONTROL_SOURCE_CHUNK_BYTES: usize = RQ_CONTROL_SOURCE_FRAME_MAX_BYTES
    - RQ_CONTROL_SOURCE_WIRE_HEADER_MAX_BYTES
    - RQ_CONTROL_SOURCE_DATA_HEADER;
const RQ_CONTROL_SOURCE_AUTH_CHUNK_BYTES: usize = RQ_CONTROL_SOURCE_FRAME_MAX_BYTES
    - RQ_CONTROL_SOURCE_WIRE_HEADER_MAX_BYTES
    - RQ_CONTROL_SOURCE_AUTH_DATA_HEADER;
/// Flush cadence for bulk `ObjectData` frames on the reliable control stream.
///
/// Handshake, feedback, proof, and close frames still flush immediately through
/// `FrameTransport::send`; only the clean source-stream bulk loop batches these
/// writes. The threshold is deliberately above a 100 Mbit / 25 ms BDP while
/// remaining tiny relative to the 100 MB RSS gate because bytes are handed to
/// the OS stream, not buffered in user space.
const RQ_CONTROL_SOURCE_FLUSH_BYTES: usize = 8 * 1024 * 1024;
/// Best-effort socket buffer request for the clean source-stream control path.
const RQ_CONTROL_STREAM_SOCKET_BUFFER_BYTES: usize = 16 * 1024 * 1024;
/// The 2% "bad" matrix path is rate-shaped to 50 mbit. Cold-starting it at
/// 16 MiB/s overshoots the pipe before feedback can correct the spray, causing
/// repair rounds to chase self-inflicted drops. Keep this deliberately narrow:
/// clean/high-BDP uses the clean ramp, good/0.1% stays source-first, and
/// broken/10% gets its own narrower 10 mbit-class cap.
const RQ_BAD_LINK_ROUND0_LOSS_MIN: f64 = 0.015;
const RQ_BAD_LINK_ROUND0_LOSS_MAX: f64 = RQ_MILD_LOSS_PACING_MAX_LOSS;
const RQ_BAD_LINK_ROUND0_PACING_BPS: u64 = 6 * 1024 * 1024;
const RQ_BROKEN_LINK_ROUND0_LOSS_MIN: f64 = RQ_BAD_LINK_ROUND0_LOSS_MAX;
const RQ_BROKEN_LINK_ROUND0_LOSS_MAX: f64 = RQ_SOURCE_FEC_FALLBACK_MAX_OVERHEAD;
const RQ_BROKEN_LINK_ROUND0_PACING_BPS: u64 = 1152 * 1024;
const RQ_COLD_START_BURST_SYMBOLS: usize = 16;
const RQ_ADAPTIVE_BURST_SYMBOLS: usize = 32;
const RQ_RECEIVER_FLOW_CONTROL_WINDOW_MAX_BYTES: u64 = 16 * 1024 * 1024;
const RQ_PACING_MIN_PAUSE: Duration = Duration::from_micros(50);
const RQ_PACING_MAX_PAUSE: Duration = Duration::from_millis(250);
const RQ_ADAPTIVE_MIN_SAMPLES: u32 = 1;
const RQ_ASSUMED_DECODE_SYMBOLS_PER_S: f64 = 250_000.0;
const RQ_CODING_GAMMA: f64 = 1.5;
const RQ_LOSS_EMA_ALPHA: f64 = 0.35;
const RQ_BW_EMA_ALPHA: f64 = 0.35;
const RQ_BW_TROUGH_RECOVERY_ALPHA: f64 = 0.10;
const RQ_LOSS_BAR_MULTIPLIER: f64 = 1.75;
const RQ_PENDING_PRESSURE_LOSS_FLOOR: f64 = 0.05;
const RQ_REGIME_SHIFT_LOSS_DELTA: f64 = 0.20;
/// Keep mild-loss repair rounds from turning sparse feedback into a self-reinforcing crawl.
const RQ_MILD_LOSS_PACING_FLOOR_FRACTION: f64 = 0.50;
const RQ_SOURCE_FIRST_MILD_LOSS_PACING_FLOOR_FRACTION: f64 = 1.0;
const RQ_MILD_LOSS_PACING_MAX_LOSS: f64 = 0.03;
const RQ_STALLED_REPAIR_PRESSURE_MIN: f64 = 0.50;
const RQ_STALLED_REPAIR_PAYLOAD_FRACTION_MAX: f64 = 0.50;
const RQ_SOURCE_FEC_FALLBACK_ALPHA: f64 = 1e-6;
const RQ_SOURCE_FEC_FALLBACK_MAX_OVERHEAD: f64 = 0.50;
const RQ_SOURCE_FEC_FALLBACK_MIN_LOSS_BAR: f64 = 0.01;
const RQ_SOURCE_FEC_FALLBACK_MIN_OVERHEAD: f64 = 0.03;
/// Receiver-observed loss must directly size feedback repair rounds. The adaptive
/// model's smoothed loss bar can be too small after sparse source retransmit
/// rounds; this floor turns a broken-link sample (p≈0.10) into ≈13% fresh repair
/// per block while staying zero for clean/good paths.
const RQ_FEEDBACK_REPAIR_LOSS_ENABLE_MIN: f64 = RQ_ROUND0_TARGET_LOSS_ENABLE_MIN;
const RQ_FEEDBACK_REPAIR_LOSS_MARGIN_FRACTION: f64 = 0.25;
const RQ_FEEDBACK_REPAIR_LOSS_MARGIN_MIN: f64 = 0.005;
const RQ_AIMD_LOSS_DECREASE_THRESHOLD_MIN: f64 = RQ_MILD_LOSS_PACING_MAX_LOSS;
const RQ_AIMD_LOSS_DECREASE_THRESHOLD_MARGIN: f64 = 0.03;
const RQ_AIMD_CLEAN_INCREASE_THRESHOLD: f64 = 0.0015;
const RQ_AIMD_MULTIPLICATIVE_DECREASE: f64 = 0.50;
const RQ_AIMD_ADDITIVE_INCREASE_BYTES_PER_S: u64 = 1024 * 1024;
/// Loss-targeted cells may overrun a slower path during round 0 before any
/// feedback exists. Once the receiver reports real wire loss, use its observed
/// delivery rate as the backoff anchor instead of repeatedly halving below the
/// pipe.
const RQ_LOSS_TARGET_DELIVERY_BACKOFF_HEADROOM: f64 = 1.10;
/// Loss-targeted cells must also react when receiver arrival loss is
/// underreported but confirmed decode/rank progress is far below the offered
/// send rate. Ratios below this are treated as congestion for AIMD/LossDetector.
const RQ_LOSS_TARGET_PROGRESS_STALL_RATIO: f64 = 0.50;
const RQ_LOSS_TARGET_PROGRESS_LOSS_MARGIN: f64 = 0.01;
/// Do not spend proactive round-0 repair on clean and near-clean links. The
/// MATRIX "good" cell is 0.1% loss and must stay on the source-first path.
const RQ_ROUND0_TARGET_LOSS_ENABLE_MIN: f64 = 0.005;
/// Near-clean loss ceiling allowed onto the reliable control-source stream.
///
/// This matches the MATRIX "good" 0.1% loss fixture while keeping bad/lossy
/// regimes on the FEC datagram fountain.
const RQ_CONTROL_SOURCE_STREAM_MAX_LOSS_TARGET: f64 = RQ_ROUND0_TARGET_LOSS_ENABLE_MIN / 5.0;
/// Minimum object size (bytes) for the large-transfer moderate-loss reliable-stream fallback.
/// Below this the FEC datagram spray converges fine on lossy links (e.g. 50M/broken WINS via
/// forward-repair); at/above it the spray rate-collapses on lossy objects, so the reliable
/// control-source stream (TCP retransmit) is used instead. (MATRIX-199 / br-...317hxr.2.5)
const RQ_LARGE_LOSSY_SOURCE_STREAM_MIN_BYTES: u64 = 256 * 1024 * 1024;
/// Moderate loss ceiling for the large-transfer reliable-stream fallback. Covers the MATRIX "bad"
/// 2% fixture but excludes "broken" (10%), where even reliable TCP degrades and the FEC spray is
/// the right tool. Proven: 500M/bad@2% reliable-stream 95.3s beats rsync 97.9s; the FEC spray
/// times out (pacing collapse, 317hxr.2.5). This bound can shrink once the spray collapse is fixed.
const RQ_LARGE_LOSSY_SOURCE_STREAM_MAX_LOSS_TARGET: f64 = 0.03;
/// Convert an explicit path-loss target into a conservative upper bound before
/// feeding the RaptorQ overhead solver. At 2% loss this produces a ~3% sizing
/// input, enough margin for one-round convergence without turning clean links
/// into fixed-overhead transfers.
const RQ_ROUND0_TARGET_LOSS_MARGIN_FRACTION: f64 = 0.25;
const RQ_ROUND0_TARGET_LOSS_MARGIN_MIN: f64 = 0.005;
/// Hard cap on the per-round fractional repair overhead taken from the controller's
/// wire-loss-driven `plan.overhead` (round_tuning). Without this, a round-0 spray that
/// over-paces a slow link self-inflicts high real loss, the wire-loss estimate clamps near
/// 0.9, and plan.overhead explodes (~9.4 ⇒ ~10.7× total), which both crushes the pacing rate
/// (base/(1+overhead)) and sprays ~10× the data. Bounding the fractional overhead at 1.0
/// (≤2× total) covers any realistic wire loss (≤~50%) in one repair round while preventing
/// the pathological blow-up. (MATRIX-12; bead atp-dataplane-redesign-317hxr.2.5.)
const RQ_MAX_ROUND_REPAIR_OVERHEAD: f64 = 1.0;

/// Packets pulled from the UDP socket per receive-pump turn.
///
/// Mirrors the native QUIC inbound pump batch width so RQ drains bursty symbol
/// sprays after one readiness wait instead of waking once per datagram.
const RQ_INBOUND_PUMP_BATCH: usize = 512;
/// Maximum full batches drained after the first ready batch in one pump turn.
const RQ_INBOUND_PUMP_MAX_DRAIN_BATCHES: usize = 64;
/// Minimum authenticated UDP batch worth sending through the blocking pool.
const RQ_AUTH_VERIFY_PARALLEL_MIN_SYMBOLS: usize = 32;
/// Aim for this many HMAC verifications per blocking-pool task.
const RQ_AUTH_VERIFY_TARGET_CHUNK_SYMBOLS: usize = 32;
/// Hard ceiling on one entry's queued RQ repair-decode jobs.
///
/// A single large file is split into many independent bounded-K source blocks.
/// Let that one entry fan those block decoders across 64-core matrix workers;
/// the receiver pump remains async and the transfer-wide budget below reserves
/// CPU/memory.
const RQ_MAX_PENDING_DECODE_JOBS_PER_ENTRY: usize = 64;
/// Hard ceiling on one transfer's queued RQ repair-decode jobs.
const RQ_MAX_PENDING_DECODE_JOBS_PER_TRANSFER_HARD: usize = 64;
/// Minimum CPU cores left for the UDP/control receive pump and filesystem work.
const RQ_DECODE_MIN_CORES_RESERVED_FOR_IO: usize = 1;
/// Upper bound on CPU cores held back from RQ decode on large machines.
const RQ_DECODE_MAX_CORES_RESERVED_FOR_IO: usize = 4;
/// Soft memory envelope for queued RQ repair-decode jobs.
///
/// `BlockDecodeJob` owns a cloned symbol set plus matrix-solve workspace. The
/// width gate estimates that footprint from current block geometry and lowers
/// the effective transfer width before queued decoders can blow past the
/// MATRIX-5 receiver RSS target. Keep this bounded, but high enough that the
/// 500M matrix cell can use most of a 64-core receiver after the large-entry
/// SBN block-size planner lowers K.
const RQ_DECODE_JOB_MEMORY_BUDGET_BYTES: usize = 256 * 1024 * 1024;
const RQ_DECODE_JOB_MEMORY_FLOOR_BYTES: usize = 1024 * 1024;
const RQ_DECODE_JOB_SYMBOL_MEMORY_MULTIPLIER: usize = 1;
/// Small transfers decode cheaper than they schedule onto the blocking pool.
///
/// MATRIX-49: 500M/bad needs parallel block decode, but 50M/bad regressed when
/// a handful of cheap block solves were over-dispatched. Keep those small
/// entries sequential while preserving wide fanout for 500M-class geometry.
/// MATRIX-50 tightened the gate to require both a large entry and many blocks:
/// block count alone can reopen fanout for 50M-class shapes.
const RQ_PARALLEL_DECODE_MIN_ENTRY_BYTES: u64 = 128 * 1024 * 1024;
const RQ_PARALLEL_DECODE_MIN_SOURCE_BLOCKS: usize = 128;
/// RQ repair feedback is round/RTT-bound: do not reject symbols for an
/// undecoded block. Decoded blocks are cleared immediately after commit.
const RQ_REPAIR_RECEIVE_SYMBOL_CAP_PER_BLOCK: usize = usize::MAX;
/// Estimate at least this much extra repair headroom beyond K for one RQ receive block.
///
/// This is now a decode-job memory estimate only. The RQ receiver must not
/// reject repair symbols for an undecoded block, because MATRIX-5 showed that
/// retention bounding adds repair rounds and dominates wall time.
const RQ_REPAIR_SYMBOL_RETENTION_MIN_EXTRA: usize = 256;
/// Tiny quiet window used only after a full batch, matching the native QUIC pump.
const RQ_INBOUND_PUMP_DRAIN_GRACE: Duration = Duration::from_millis(1);
/// Coalesce clean/source-streamed staging writes so the receiver does not issue
/// one async file write per UDP symbol on large clean transfers.
const RQ_SOURCE_STAGE_BUFFER_BYTES: usize = 256 * 1024;

/// Process-unique suffix for RQ receive staging directories.
static RQ_STAGING_SEQ: AtomicU64 = AtomicU64::new(1);
/// Process-unique nonce folded into source-stream transfer ids that are no
/// longer content-merkle-derived.
static RQ_TRANSFER_SEQ: AtomicU64 = AtomicU64::new(1);
const RQ_STAGING_CREATE_ATTEMPTS: u64 = 1024;

/// UDP datagram header size (magic + transfer tag + entry + sbn + esi + kind +
/// len), big-endian.
const DGRAM_HEADER: usize = 4 + 8 + 4 + 1 + 4 + 1 + 2;

/// UDP datagram header plus the authenticated-symbol tag.
const AUTH_DGRAM_HEADER: usize = DGRAM_HEADER + TAG_SIZE;

/// Opt-in receiver staging-write cursor audit (c54to7 diagnosis). When
/// `ATP_RQ_STAGING_CURSOR_AUDIT` is set, the cached-staging-handle write path
/// verifies the skip-seek invariant with a `stream_position` call before every
/// skip-eligible write, logs any desync, and self-heals by re-seeking. Off by
/// default: it costs one extra lseek per skip-eligible write.
fn staging_cursor_audit_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("ATP_RQ_STAGING_CURSOR_AUDIT").is_some())
}

/// Opt-in stderr tracing for transport bring-up/diagnosis. Off unless the
/// `ATP_RQ_TRACE` env var is set, so the production path stays silent.
macro_rules! rqtrace {
    ($($arg:tt)*) => {
        if std::env::var_os("ATP_RQ_TRACE").is_some() {
            eprintln!("[atp-rq] {}", format!($($arg)*));
        }
    };
}

/// Opt-in stderr tracing for channel-bonded donor spray bring-up.
/// Off unless `ATP_BOND_TRACE` is set.
macro_rules! bondtrace {
    ($($arg:tt)*) => {
        if std::env::var_os("ATP_BOND_TRACE").is_some() {
            eprintln!("[ATP_BOND_TRACE] [atp-rq] {}", format!($($arg)*));
        }
    };
}

// Bonded (N-donor) receive loop and donor control loop (z01bbr.6). Declared
// after the trace macros so the child module can use them.
mod bonded;
pub use bonded::{
    ATP_RQ_BONDED_PROTOCOL, BondedDonateReport, BondedReceiveReport, donate_bonded, receive_bonded,
};

/// Transport tuning knobs.
#[derive(Debug, Clone)]
pub struct RqConfig {
    /// RaptorQ symbol payload size in bytes.
    pub symbol_size: u16,
    /// Maximum source-block size in bytes.
    pub max_block_size: usize,
    /// Extra repair fraction sprayed in round 0 (>= 1.0).
    pub repair_overhead: f64,
    /// Explicit expected round-0 wire loss as a fraction in `[0, 1)`.
    ///
    /// This is optional and defaults to `0.0`. Matrix benchmark callers can set it
    /// from the known netem loss for lossy cells so the first spray includes a
    /// calibrated fountain repair budget. Clean and near-clean values stay below
    /// `RQ_ROUND0_TARGET_LOSS_ENABLE_MIN` and therefore preserve the source-first
    /// path.
    pub round0_loss_target: f64,
    /// Number of UDP sockets the sender sprays across.
    pub udp_fanout: usize,
    /// Maximum total bytes a single transfer may carry.
    pub max_transfer_bytes: u64,
    /// Filesystem metadata captured by the sender and accepted by the receiver.
    ///
    /// RQ preserves regular-file metadata and the complete directory topology,
    /// including nested empty directories. Symlinks/reparse points remain
    /// fail-closed at source preflight.
    pub metadata_policy: MetadataPolicy,
    /// Detect source hardlinks and fail before transfer rather than silently
    /// flattening inode identity. RQ does not yet encode hardlink topology; use
    /// TCP or QUIC when this requested fidelity is present.
    pub preserve_hardlinks: bool,
    /// Maximum time a one-shot receiver waits for the TCP control accept.
    pub accept_timeout: Duration,
    /// Maximum fountain feedback rounds before failing closed.
    pub max_feedback_rounds: u32,
    /// Receiver-side quiet window after each `ObjectComplete` frame.
    ///
    /// TCP can deliver the control-plane round marker before the receiver has
    /// drained all UDP symbols already queued in the kernel. This window lets
    /// the receiver consume that tail before it asks for repair symbols.
    pub round_tail_drain: Duration,
    /// Number of early feedback rounds that may request missing systematic
    /// source symbols instead of repair symbols when `repair_overhead <= 1.0`.
    ///
    /// Defaults to zero for WAN throughput. Positive values are intended for
    /// controlled lab or very low-loss links where sparse source retransmit is
    /// known to converge faster than constructing repair symbols.
    pub source_retransmit_rounds: u32,
    /// Maximum source-symbol retransmit requests in one feedback frame.
    ///
    /// `0` means unbounded, but only after `source_retransmit_rounds` explicitly
    /// opts the transport into source retransmit feedback.
    pub max_source_retransmit_requests: usize,
    /// Test-only: deterministically drop 1-in-N sprayed source symbols on the
    /// sender to exercise the repair/feedback path. 0 disables.
    pub debug_drop_one_in: u32,
    /// Optional per-symbol authentication context for UDP RaptorQ datagrams and
    /// clean-link control-source `ObjectData` frames.
    ///
    /// When present, senders append a tag for each symbol and receivers verify
    /// every symbol before decoding. Control-source data frames are also tagged
    /// and fail closed before staging writes. The TCP handshake, manifest, and
    /// feedback frames still need their own authenticated transport to claim full
    /// anti-forgery for the whole control plane.
    pub symbol_auth_context: Option<SecurityContext>,
    /// Explicit escape hatch for loopback/lab callers that run over a trusted
    /// transport and accept integrity-vs-manifest only.
    pub allow_unauthenticated_symbols: bool,
    /// Offer receiver-driven delta negotiation on the existing framed control
    /// stream when a strict symbol-authentication key is configured.
    ///
    /// Delta is deliberately unavailable in the trusted unauthenticated lab
    /// posture: destination state is never consulted for an unauthenticated
    /// challenge or manifest. A strict symmetric symbol key is the sole
    /// authorization for this equality query; `peer_id` is self-asserted, so
    /// deployments that treat destination-state probing as sensitive should
    /// use a narrowly scoped per-peer or per-transfer key. This opt-in does not
    /// disable legacy unauthenticated clients or provide an admission replay
    /// cache, so deployment-level connection limits remain necessary.
    pub enable_delta: bool,
    /// Absolute per-frame deadline for the authenticated delta-control exchange.
    pub delta_control_timeout: Duration,
}

/// Public per-symbol authentication posture for ATP-over-RaptorQ.
///
/// This reports whether the UDP symbol plane is configured to verify tags. It
/// does not claim full Byzantine symbol-injection protection by itself because
/// the TCP control channel and manifest still need authenticated transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RqSymbolAuthMode {
    /// Symbols are signed and verified with a configured [`SecurityContext`].
    Authenticated,
    /// Symbols are deliberately unauthenticated on a trusted loopback/lab link.
    TrustedUnauthenticated,
    /// No auth context was configured and no explicit trusted opt-out was set.
    MissingAuthenticationContext,
}

impl Default for RqConfig {
    fn default() -> Self {
        Self {
            symbol_size: DEFAULT_SYMBOL_SIZE,
            max_block_size: DEFAULT_MAX_BLOCK_SIZE,
            repair_overhead: DEFAULT_REPAIR_OVERHEAD,
            round0_loss_target: 0.0,
            udp_fanout: DEFAULT_UDP_FANOUT,
            max_transfer_bytes: DEFAULT_MAX_TRANSFER_BYTES,
            metadata_policy: MetadataPolicy::default(),
            preserve_hardlinks: false,
            accept_timeout: DEFAULT_ACCEPT_TIMEOUT,
            max_feedback_rounds: DEFAULT_MAX_FEEDBACK_ROUNDS,
            round_tail_drain: DEFAULT_ROUND_TAIL_DRAIN,
            source_retransmit_rounds: DEFAULT_SOURCE_RETRANSMIT_ROUNDS,
            max_source_retransmit_requests: DEFAULT_MAX_SOURCE_RETRANSMIT_REQUESTS,
            debug_drop_one_in: 0,
            symbol_auth_context: None,
            allow_unauthenticated_symbols: false,
            enable_delta: false,
            delta_control_timeout: DEFAULT_CONNECT_TIMEOUT,
        }
    }
}

impl RqConfig {
    /// Require per-symbol authentication with this context.
    #[must_use]
    pub fn with_symbol_auth(mut self, context: SecurityContext) -> Self {
        self.symbol_auth_context = Some(context);
        self.allow_unauthenticated_symbols = false;
        self
    }

    /// Explicitly allow unauthenticated symbols for trusted loopback/lab links.
    #[must_use]
    pub fn allow_unauthenticated_for_trusted_transport(mut self) -> Self {
        self.symbol_auth_context = None;
        self.allow_unauthenticated_symbols = true;
        self
    }

    /// Return the configured per-symbol authentication posture.
    #[must_use]
    pub fn symbol_auth_mode(&self) -> RqSymbolAuthMode {
        if self.symbol_auth_context.is_some() {
            return RqSymbolAuthMode::Authenticated;
        }
        if self.allow_unauthenticated_symbols {
            return RqSymbolAuthMode::TrustedUnauthenticated;
        }
        RqSymbolAuthMode::MissingAuthenticationContext
    }

    /// Validate that the symbol-auth posture is deliberate.
    pub fn validate_symbol_auth_mode(&self) -> Result<(), RqError> {
        self.symbol_auth_context().map(|_| ())
    }

    fn symbol_auth_context(&self) -> Result<Option<SecurityContext>, RqError> {
        if let Some(context) = &self.symbol_auth_context {
            return Ok(Some(context.clone()));
        }
        if self.allow_unauthenticated_symbols {
            return Ok(None);
        }
        Err(RqError::Authentication(
            "ATP RaptorQ transport requires symbol_auth_context; call \
             with_symbol_auth(...) or explicitly opt into \
             allow_unauthenticated_for_trusted_transport() for loopback/lab use"
                .to_string(),
        ))
    }
}

#[derive(Debug, Clone, Copy)]
struct RqRoundTuning {
    repair_overhead: f64,
    pacing: RqSprayPacing,
}

#[derive(Debug, Clone, Copy)]
struct RqSprayPacing {
    path_rate_bps: u64,
    datagram_bytes: u32,
    max_burst_size: u32,
    rtt: Option<Duration>,
    loss_detected: bool,
}

impl RqSprayPacing {
    fn cold_start(symbol_size: u16) -> Self {
        Self::from_rate(
            RQ_COLD_START_PACING_BPS,
            symbol_size,
            RQ_COLD_START_BURST_SYMBOLS,
            None,
            false,
        )
    }

    #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
    fn from_rate(
        rate_bytes_per_sec: u64,
        symbol_size: u16,
        burst_symbols: usize,
        rtt: Option<Duration>,
        loss_detected: bool,
    ) -> Self {
        let pacing_rate_bytes_per_sec =
            rate_bytes_per_sec.clamp(RQ_MIN_PACING_BPS, RQ_MAX_PACING_BPS);
        let symbol_bytes = u64::from(symbol_size.max(1))
            .saturating_add(u64::try_from(AUTH_DGRAM_HEADER).unwrap_or(u64::MAX));
        let datagram_bytes = u32::try_from(symbol_bytes).unwrap_or(u32::MAX).max(1);
        let path_rate_bps = pacing_rate_bytes_per_sec.saturating_mul(8);
        let max_burst_size = u32::try_from(burst_symbols.max(1))
            .unwrap_or(u32::MAX)
            .max(1);
        Self {
            path_rate_bps,
            datagram_bytes,
            max_burst_size,
            rtt,
            loss_detected,
        }
    }

    fn rate_bytes_per_sec(self) -> u64 {
        self.path_rate_bps / 8
    }

    fn set_rate_bytes_per_sec(&mut self, rate_bytes_per_sec: u64, max_rate_bytes_per_sec: u64) {
        let rate = rate_bytes_per_sec.clamp(
            RQ_MIN_PACING_BPS,
            max_rate_bytes_per_sec.max(RQ_MIN_PACING_BPS),
        );
        self.path_rate_bps = rate.saturating_mul(8);
    }

    fn burst_bytes(self) -> u64 {
        u64::from(self.datagram_bytes).saturating_mul(u64::from(self.max_burst_size))
    }

    fn configured_bdp_bytes(self) -> Option<u64> {
        self.rtt
            .map(|rtt| rate_window_bytes(self.rate_bytes_per_sec(), rtt))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RqSenderWindowProbe {
    sent_symbols: u64,
    payload_bytes: u64,
    wire_bytes: u64,
    send_wall_ms: u64,
    control_wait_ms: u64,
    configured_rate_bytes_per_sec: u64,
    observed_payload_bytes_per_sec: u64,
    observed_wire_bytes_per_sec: u64,
    configured_bdp_bytes: u64,
    configured_control_window_bytes: u64,
    observed_payload_window_bytes: u64,
    observed_wire_window_bytes: u64,
    burst_bytes: u64,
    burst_symbols: u32,
    datagram_bytes: u32,
}

impl RqSenderWindowProbe {
    fn new(
        pacing: RqSprayPacing,
        sent_symbols: u64,
        symbol_size: u16,
        send_wall: Duration,
        control_wait: Duration,
    ) -> Self {
        let payload_bytes = sent_symbols.saturating_mul(u64::from(symbol_size.max(1)));
        let wire_bytes = sent_symbols.saturating_mul(u64::from(pacing.datagram_bytes));
        let observed_payload_bytes_per_sec = bytes_per_second_ceil(payload_bytes, send_wall);
        let observed_wire_bytes_per_sec = bytes_per_second_ceil(wire_bytes, send_wall);
        Self {
            sent_symbols,
            payload_bytes,
            wire_bytes,
            send_wall_ms: duration_millis_u64(send_wall),
            control_wait_ms: duration_millis_u64(control_wait),
            configured_rate_bytes_per_sec: pacing.rate_bytes_per_sec(),
            observed_payload_bytes_per_sec,
            observed_wire_bytes_per_sec,
            configured_bdp_bytes: pacing.configured_bdp_bytes().unwrap_or(0),
            configured_control_window_bytes: rate_window_bytes(
                pacing.rate_bytes_per_sec(),
                control_wait,
            ),
            observed_payload_window_bytes: rate_window_bytes(
                observed_payload_bytes_per_sec,
                control_wait,
            ),
            observed_wire_window_bytes: rate_window_bytes(
                observed_wire_bytes_per_sec,
                control_wait,
            ),
            burst_bytes: pacing.burst_bytes(),
            burst_symbols: pacing.max_burst_size,
            datagram_bytes: pacing.datagram_bytes,
        }
    }

    fn peak_window_bytes(self) -> u64 {
        self.configured_bdp_bytes
            .max(self.configured_control_window_bytes)
            .max(self.observed_payload_window_bytes)
            .max(self.observed_wire_window_bytes)
    }
}

fn trace_sender_window_probe(
    phase: &str,
    feedback_round: u32,
    probe: RqSenderWindowProbe,
    peak_window_bytes: u64,
    udp_send_acceleration: UdpSendAccelerationReport,
) {
    rqtrace!(
        "sender: window_probe phase={} feedback_round={} sent_symbols={} payload_bytes={} wire_bytes={} send_wall_ms={} control_wait_ms={} configured_rate_Bps={} observed_payload_Bps={} observed_wire_Bps={} configured_bdp_bytes={} configured_control_window_bytes={} observed_payload_window_bytes={} observed_wire_window_bytes={} peak_window_bytes={} burst_bytes={} burst_symbols={} datagram_bytes={} udp_flushes={} udp_datagrams={} udp_payload_bytes={}",
        phase,
        feedback_round,
        probe.sent_symbols,
        probe.payload_bytes,
        probe.wire_bytes,
        probe.send_wall_ms,
        probe.control_wait_ms,
        probe.configured_rate_bytes_per_sec,
        probe.observed_payload_bytes_per_sec,
        probe.observed_wire_bytes_per_sec,
        probe.configured_bdp_bytes,
        probe.configured_control_window_bytes,
        probe.observed_payload_window_bytes,
        probe.observed_wire_window_bytes,
        peak_window_bytes,
        probe.burst_bytes,
        probe.burst_symbols,
        probe.datagram_bytes,
        udp_send_acceleration.flushes,
        udp_send_acceleration.datagrams,
        udp_send_acceleration.payload_bytes,
    );
}

fn bytes_per_second_ceil(bytes: u64, elapsed: Duration) -> u64 {
    let nanos = elapsed.as_nanos().max(1);
    let rate = u128::from(bytes)
        .saturating_mul(1_000_000_000)
        .div_ceil(nanos);
    u64::try_from(rate).unwrap_or(u64::MAX)
}

fn rate_window_bytes(bytes_per_sec: u64, rtt: Duration) -> u64 {
    let nanos = rtt.as_nanos();
    if nanos == 0 || bytes_per_sec == 0 {
        return 0;
    }
    let bytes = u128::from(bytes_per_sec)
        .saturating_mul(nanos)
        .div_ceil(1_000_000_000);
    u64::try_from(bytes).unwrap_or(u64::MAX)
}

fn rq_receiver_flow_credit_bytes(config: &RqConfig, pending_bytes: u64) -> u64 {
    let symbol_bytes = u64::from(config.symbol_size.max(1));
    let datagram_bytes = symbol_bytes
        .saturating_add(u64::try_from(AUTH_DGRAM_HEADER).unwrap_or(u64::MAX))
        .max(1);
    let min_window = datagram_bytes
        .saturating_mul(u64::try_from(RQ_ADAPTIVE_BURST_SYMBOLS).unwrap_or(u64::MAX))
        .max(symbol_bytes);
    if pending_bytes == 0 {
        return RQ_RECEIVER_FLOW_CONTROL_WINDOW_MAX_BYTES.max(min_window);
    }
    pending_bytes.clamp(min_window, RQ_RECEIVER_FLOW_CONTROL_WINDOW_MAX_BYTES)
}

fn duration_for_rate_window(bytes: u64, bytes_per_sec: u64) -> Duration {
    if bytes == 0 || bytes_per_sec == 0 {
        return Duration::ZERO;
    }
    let nanos = u128::from(bytes)
        .saturating_mul(1_000_000_000)
        .div_ceil(u128::from(bytes_per_sec));
    Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX))
}

fn duration_millis_u64(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

struct RqSprayPacer {
    controller: CongestionController,
    pacing: RqSprayPacing,
    shared_decision: Option<DatagramRateDecision>,
    round0_ramp: Option<RqRound0CleanPacingRamp>,
    small_clean_burst: Option<RqSmallCleanBurstPacer>,
}

#[derive(Debug, Clone, Copy)]
struct RqRound0CleanPacingRamp {
    sent_datagrams: u64,
    next_step_bytes: u64,
    max_rate_bytes_per_sec: u64,
}

#[derive(Debug, Clone, Copy)]
struct RqSmallCleanBurstPacer {
    remaining_in_burst: u32,
    next_burst_at: Option<Instant>,
}

impl RqSmallCleanBurstPacer {
    fn new() -> Self {
        Self {
            remaining_in_burst: 0,
            next_burst_at: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RqRound0CleanPacingRampReport {
    sent_datagrams: u64,
    sent_bytes: u64,
    old_rate_bytes_per_sec: u64,
    new_rate_bytes_per_sec: u64,
    next_step_bytes: u64,
    max_rate_bytes_per_sec: u64,
}

impl RqRound0CleanPacingRamp {
    fn new(max_rate_bytes_per_sec: u64) -> Self {
        Self {
            sent_datagrams: 0,
            next_step_bytes: RQ_ROUND0_CLEAN_RAMP_STEP_BYTES,
            max_rate_bytes_per_sec: max_rate_bytes_per_sec.clamp(
                RQ_COLD_START_PACING_BPS.max(RQ_MIN_PACING_BPS),
                RQ_ROUND0_CLEAN_RAMP_MAX_PACING_BPS,
            ),
        }
    }

    fn observe_datagram(
        &mut self,
        pacing: &mut RqSprayPacing,
    ) -> Option<RqRound0CleanPacingRampReport> {
        self.sent_datagrams = self.sent_datagrams.saturating_add(1);
        let sent_bytes = self
            .sent_datagrams
            .saturating_mul(u64::from(pacing.datagram_bytes.max(1)));
        let old_rate = pacing.rate_bytes_per_sec();
        let mut changed = false;
        while sent_bytes >= self.next_step_bytes
            && pacing.rate_bytes_per_sec() < self.max_rate_bytes_per_sec
        {
            let current = pacing.rate_bytes_per_sec();
            let next = current
                .saturating_add(RQ_ROUND0_CLEAN_RAMP_ADD_BYTES_PER_S)
                .clamp(RQ_MIN_PACING_BPS, self.max_rate_bytes_per_sec);
            if next == current {
                break;
            }
            pacing.set_rate_bytes_per_sec(next, self.max_rate_bytes_per_sec);
            self.next_step_bytes = self
                .next_step_bytes
                .saturating_add(RQ_ROUND0_CLEAN_RAMP_STEP_BYTES);
            changed = true;
        }
        changed.then_some(RqRound0CleanPacingRampReport {
            sent_datagrams: self.sent_datagrams,
            sent_bytes,
            old_rate_bytes_per_sec: old_rate,
            new_rate_bytes_per_sec: pacing.rate_bytes_per_sec(),
            next_step_bytes: self.next_step_bytes,
            max_rate_bytes_per_sec: self.max_rate_bytes_per_sec,
        })
    }
}

fn round0_clean_ramp_max_rate(config: &RqConfig) -> u64 {
    if config.udp_fanout.max(1) == 1 {
        RQ_ROUND0_CLEAN_RAMP_MAX_PACING_BPS
    } else {
        RQ_ROUND0_CLEAN_RAMP_FANOUT_MAX_PACING_BPS
    }
}

fn round0_clean_ramp_enabled(config: &RqConfig, pacing: RqSprayPacing) -> bool {
    // MATRIX-76: near-clean "good" links remain source-first, but must not take
    // the no-feedback high-BDP ramp. A fixed 128 MiB/s probe overruns 200 Mbit
    // paths before the first feedback frame can produce a delivery-rate cap.
    let loss_free_target = round0_source_first_loss_target(config)
        && (0.0..=f64::EPSILON).contains(&config.round0_loss_target);
    // Clean UDP fallback still ramps when the control-source stream is not
    // selected, for example debug-drop or non-clean transfer regimes.
    config.debug_drop_one_in == 0
        && config.repair_overhead <= RQ_SMALL_CLEAN_SOURCE_ONLY_MAX_REPAIR_OVERHEAD
        && loss_free_target
        && !pacing.loss_detected
        && pacing.rate_bytes_per_sec() <= RQ_COLD_START_PACING_BPS
}

impl RqSprayPacer {
    fn new_round0(pacing: RqSprayPacing, config: &RqConfig, force_clean_ramp: bool) -> Self {
        let clean_ramp_enabled = round0_clean_ramp_enabled(config, pacing);
        let round0_ramp = clean_ramp_enabled
            .then(|| RqRound0CleanPacingRamp::new(round0_clean_ramp_max_rate(config)));
        if round0_ramp.is_some() {
            rqtrace!(
                "sender: round0_clean_pacing_ramp enabled start_rate_Bps={} step_bytes={} max_rate_Bps={} udp_fanout={} datagram_bytes={} burst_symbols={} forced={}",
                pacing.rate_bytes_per_sec(),
                RQ_ROUND0_CLEAN_RAMP_STEP_BYTES,
                round0_clean_ramp_max_rate(config),
                config.udp_fanout.max(1),
                pacing.datagram_bytes,
                pacing.max_burst_size,
                force_clean_ramp,
            );
        }
        Self::new_with_round0_ramp(pacing, round0_ramp, force_clean_ramp && clean_ramp_enabled)
    }

    fn new_with_round0_ramp(
        pacing: RqSprayPacing,
        round0_ramp: Option<RqRound0CleanPacingRamp>,
        small_clean_burst: bool,
    ) -> Self {
        let mut controller = CongestionController::new(CongestionConfig::default());
        Self::configure_controller(&mut controller, pacing, None);
        Self {
            controller,
            pacing,
            shared_decision: None,
            round0_ramp,
            small_clean_burst: small_clean_burst.then(RqSmallCleanBurstPacer::new),
        }
    }

    fn configure_controller(
        controller: &mut CongestionController,
        pacing: RqSprayPacing,
        shared_decision: Option<DatagramRateDecision>,
    ) {
        if let Some(decision) = shared_decision {
            controller.configure_from_rate_decision(
                decision,
                pacing.datagram_bytes,
                pacing.max_burst_size,
            );
        } else {
            controller.configure_for_path_rate(
                pacing.path_rate_bps,
                pacing.datagram_bytes,
                pacing.max_burst_size,
            );
        }
        controller.update_congestion_feedback(pacing.rtt, pacing.loss_detected);
    }

    fn configure_with_shared_decision(
        &mut self,
        pacing: RqSprayPacing,
        shared_decision: Option<DatagramRateDecision>,
    ) {
        self.pacing = pacing;
        self.shared_decision = shared_decision;
        self.round0_ramp = None;
        self.small_clean_burst = None;
        Self::configure_controller(&mut self.controller, pacing, shared_decision);
    }

    fn pacing(&self) -> RqSprayPacing {
        self.pacing
    }

    fn observe_datagram_sent(&mut self) {
        let Some(ramp) = &mut self.round0_ramp else {
            return;
        };
        if let Some(report) = ramp.observe_datagram(&mut self.pacing) {
            Self::configure_controller(&mut self.controller, self.pacing, self.shared_decision);
            rqtrace!(
                "sender: round0_clean_rate_ramp sent_datagrams={} sent_bytes={} old_rate_Bps={} new_rate_Bps={} path_rate_bps={} next_step_bytes={} max_rate_Bps={}",
                report.sent_datagrams,
                report.sent_bytes,
                report.old_rate_bytes_per_sec,
                report.new_rate_bytes_per_sec,
                self.pacing.path_rate_bps,
                report.next_step_bytes,
                report.max_rate_bytes_per_sec,
            );
        }
    }

    async fn before_send(&mut self, cx: &Cx) -> Result<(), RqError> {
        if self.small_clean_burst.is_some() {
            return self.before_small_clean_burst_send(cx).await;
        }

        loop {
            let now = Instant::now();
            if self.controller.try_consume_send_budget(now) {
                return Ok(());
            }
            let wait = self
                .controller
                .time_until_send_budget(now)
                .clamp(RQ_PACING_MIN_PAUSE, RQ_PACING_MAX_PAUSE);
            crate::time::sleep(cx.now(), wait).await;
            cx.checkpoint().map_err(|_| RqError::Cancelled)?;
        }
    }

    async fn before_small_clean_burst_send(&mut self, cx: &Cx) -> Result<(), RqError> {
        let pacing = self.pacing;
        let burst_symbols = pacing
            .max_burst_size
            .max(u32::try_from(RQ_SEND_BATCH_PER_SOCKET).unwrap_or(u32::MAX));
        let Some(burst) = self.small_clean_burst.as_mut() else {
            return Ok(());
        };

        if burst.remaining_in_burst > 0 {
            burst.remaining_in_burst = burst.remaining_in_burst.saturating_sub(1);
            return Ok(());
        }

        while let Some(next_burst_at) = burst.next_burst_at {
            let now = Instant::now();
            let Some(wait) = next_burst_at.checked_duration_since(now) else {
                break;
            };
            let wait = wait.clamp(RQ_PACING_MIN_PAUSE, RQ_PACING_MAX_PAUSE);
            crate::time::sleep(cx.now(), wait).await;
            cx.checkpoint().map_err(|_| RqError::Cancelled)?;
        }

        let burst_bytes =
            u64::from(pacing.datagram_bytes.max(1)).saturating_mul(u64::from(burst_symbols.max(1)));
        let burst_interval = duration_for_rate_window(burst_bytes, pacing.rate_bytes_per_sec());
        burst.next_burst_at = Instant::now().checked_add(burst_interval);
        burst.remaining_in_burst = burst_symbols.saturating_sub(1);
        Ok(())
    }
}

struct RqPendingSendBatch {
    by_socket: Vec<Vec<Vec<u8>>>,
    queued: usize,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct RqSendBatchFlushReport {
    socket_flushes: usize,
    native_flushes: usize,
    native_packets: usize,
    gso_flushes: usize,
    gso_packets: usize,
    fallback_flushes: usize,
    fallback_packets: usize,
    partial_flushes: usize,
    error_flushes: usize,
    packets_processed: usize,
    bytes_processed: usize,
}

impl RqPendingSendBatch {
    fn new(fanout: usize) -> Self {
        let fanout = fanout.max(1);
        Self {
            by_socket: (0..fanout).map(|_| Vec::new()).collect(),
            queued: 0,
        }
    }

    fn fanout(&self) -> usize {
        self.by_socket.len()
    }

    fn global_flush_symbols(&self) -> usize {
        RQ_SEND_BATCH_PER_SOCKET
    }

    fn push(&mut self, socket_index: usize, payload: Vec<u8>) {
        let index = socket_index % self.fanout();
        self.by_socket[index].push(payload);
        self.queued += 1;
    }

    fn should_flush(&self) -> bool {
        self.queued >= self.global_flush_symbols()
            || self
                .by_socket
                .iter()
                .any(|payloads| payloads.len() >= RQ_SEND_BATCH_PER_SOCKET)
    }

    async fn flush(
        &mut self,
        sockets: &mut [UdpSocket],
        symbols_sent: &mut u64,
    ) -> Result<RqSendBatchFlushReport, RqError> {
        debug_assert_eq!(self.by_socket.len(), sockets.len().max(1));
        if self.queued == 0 {
            return Ok(RqSendBatchFlushReport::default());
        }

        let symbols_before_flush = *symbols_sent;
        let mut flush_report = RqSendBatchFlushReport::default();
        for (socket_index, payloads) in self.by_socket.iter_mut().enumerate() {
            if payloads.is_empty() {
                continue;
            }

            let socket = sockets.get_mut(socket_index).ok_or_else(|| {
                RqError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "RQ send batch socket index out of range",
                ))
            })?;
            let expected = payloads.len();
            let report = {
                let payload_refs = payloads
                    .iter()
                    .map(Vec::as_slice)
                    .collect::<SmallVec<[_; RQ_SEND_BATCH_PER_SOCKET]>>();
                socket.send_connected_batch(&payload_refs).await?
            };

            *symbols_sent = symbols_sent
                .saturating_add(u64::try_from(report.packets_processed).unwrap_or(u64::MAX));
            flush_report.socket_flushes += 1;
            flush_report.packets_processed += report.packets_processed;
            flush_report.bytes_processed += report.bytes_processed;
            flush_report.native_flushes += usize::from(report.native_send_batch_used);
            if report.native_send_batch_used {
                flush_report.native_packets += report.packets_processed;
            }
            flush_report.gso_flushes += usize::from(report.gso_send_used);
            if report.gso_send_used {
                flush_report.gso_packets += report.packets_processed;
            }
            flush_report.fallback_flushes += usize::from(report.fallback_used);
            if report.fallback_used {
                flush_report.fallback_packets += report.packets_processed;
            }
            flush_report.error_flushes += usize::from(report.error.is_some());
            if report.packets_processed != expected {
                let reason = report.error.unwrap_or_else(|| {
                    format!(
                        "partial RQ UDP send batch: sent {} of {expected}",
                        report.packets_processed
                    )
                });
                let partial_flushes = flush_report.partial_flushes.saturating_add(1);
                rqtrace!(
                    "sender: udp_batch partial flushes={} native_flushes={} gso_flushes={} fallback_flushes={} partial_flushes={} packets={} bytes={} symbols_before={} symbols_after={} error={}",
                    flush_report.socket_flushes,
                    flush_report.native_flushes,
                    flush_report.gso_flushes,
                    flush_report.fallback_flushes,
                    partial_flushes,
                    flush_report.packets_processed,
                    flush_report.bytes_processed,
                    symbols_before_flush,
                    *symbols_sent,
                    reason,
                );
                return Err(RqError::Io(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    reason,
                )));
            }

            payloads.clear();
        }

        self.queued = 0;
        rqtrace!(
            "sender: udp_batch flushes={} native_flushes={} gso_flushes={} fallback_flushes={} partial_flushes={} packets={} bytes={} symbols_before={} symbols_after={}",
            flush_report.socket_flushes,
            flush_report.native_flushes,
            flush_report.gso_flushes,
            flush_report.fallback_flushes,
            flush_report.partial_flushes,
            flush_report.packets_processed,
            flush_report.bytes_processed,
            symbols_before_flush,
            *symbols_sent,
        );
        if send_progress_crossed_yield_boundary(symbols_before_flush, *symbols_sent) {
            crate::runtime::yield_now().await;
        }
        Ok(flush_report)
    }

    #[cfg(test)]
    fn queued_count(&self) -> usize {
        self.queued
    }

    #[cfg(test)]
    fn socket_batch_len(&self, socket_index: usize) -> usize {
        self.by_socket[socket_index].len()
    }
}

fn send_progress_crossed_yield_boundary(before: u64, after: u64) -> bool {
    after > before && before / 64 != after / 64
}

struct RqReceiverUdpFanout {
    sockets: Vec<UdpSocket>,
    next_poll: usize,
    recv_payload_pool: Vec<Vec<u8>>,
}

impl RqReceiverUdpFanout {
    async fn bind(
        bind_ip: std::net::IpAddr,
        fanout: usize,
        recv_buffer_bytes: usize,
    ) -> std::io::Result<Self> {
        let fanout = fanout.max(1);
        let mut sockets = Vec::with_capacity(fanout);
        for _ in 0..fanout {
            let socket = UdpSocket::bind(SocketAddr::new(bind_ip, 0)).await?;
            let _ = socket.tune_buffers(UdpBufferConfig {
                recv_buffer_bytes: Some(recv_buffer_bytes),
                send_buffer_bytes: None,
            });
            sockets.push(socket);
        }

        Ok(Self {
            sockets,
            next_poll: 0,
            recv_payload_pool: Vec::with_capacity(RQ_INBOUND_PUMP_BATCH),
        })
    }

    fn len(&self) -> usize {
        self.sockets.len()
    }

    fn local_ports(&self) -> std::io::Result<Vec<u16>> {
        self.sockets
            .iter()
            .map(|socket| socket.local_addr().map(|addr| addr.port()))
            .collect()
    }

    fn poll_recv_any(
        &mut self,
        task_cx: &std::task::Context<'_>,
        rbuf: &mut [u8],
    ) -> std::task::Poll<std::io::Result<(usize, usize)>> {
        use std::task::Poll;

        if self.sockets.is_empty() {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "RQ receiver UDP fanout has no sockets",
            )));
        }

        let socket_count = self.sockets.len();
        for offset in 0..socket_count {
            let socket_index = (self.next_poll + offset) % socket_count;
            match self.sockets[socket_index].poll_recv(task_cx, rbuf) {
                Poll::Ready(Ok(n)) => {
                    self.next_poll = (socket_index + 1) % socket_count;
                    return Poll::Ready(Ok((socket_index, n)));
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {}
            }
        }

        Poll::Pending
    }

    fn poll_recv_batch_any(
        &mut self,
        task_cx: &mut std::task::Context<'_>,
        max_packets: usize,
        packet_size: usize,
    ) -> std::task::Poll<std::io::Result<(usize, crate::net::UdpRecvBatch)>> {
        use std::future::Future;
        use std::task::Poll;

        if self.sockets.is_empty() {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "RQ receiver UDP fanout has no sockets",
            )));
        }

        let socket_count = self.sockets.len();
        for offset in 0..socket_count {
            let socket_index = (self.next_poll + offset) % socket_count;
            let poll_result = {
                let socket = &mut self.sockets[socket_index];
                let recv_payload_pool = &mut self.recv_payload_pool;
                let mut recv = std::pin::pin!(socket.recv_batch_from_reusing(
                    max_packets,
                    packet_size,
                    recv_payload_pool
                ));
                Future::poll(recv.as_mut(), task_cx)
            };
            match poll_result {
                Poll::Ready(Ok(batch)) => {
                    self.next_poll = (socket_index + 1) % socket_count;
                    return Poll::Ready(Ok((socket_index, batch)));
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {}
            }
        }

        Poll::Pending
    }

    async fn recv_batch_from_socket(
        &mut self,
        socket_index: usize,
        max_packets: usize,
        packet_size: usize,
    ) -> std::io::Result<crate::net::UdpRecvBatch> {
        let socket = self.sockets.get_mut(socket_index).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "RQ receiver UDP fanout socket index out of range",
            )
        })?;
        socket
            .recv_batch_from_reusing(max_packets, packet_size, &mut self.recv_payload_pool)
            .await
    }

    fn recycle_recv_batch(&mut self, batch: &mut crate::net::UdpRecvBatch, max_spare: usize) {
        batch.recycle_payloads_into(&mut self.recv_payload_pool, max_spare);
    }
}

struct RqAdaptiveSendState {
    controller: AdaptiveController,
    shared_rate: DatagramRateController,
    shared_rate_decision: Option<DatagramRateDecision>,
    shared_rate_clock_micros: u64,
    loss_detector: AtpLossDetector,
    beacons: BeaconScheduler,
    est: PathEstimate,
    symbol_size: u16,
    aimd_rate_bps: u64,
    aimd_feedback_seen: bool,
    last_round_loss_fraction: f64,
    loss_ema: f64,
    pacing_loss_ema: f64,
    pacing_loss_bar: f64,
    loss_bar: f64,
    bw_ema_bps: f64,
    bw_trough_bps: f64,
    loss_pacing_cap_bps: Option<u64>,
    loss_fec_floor: f64,
    regime_shift: bool,
    last_pending_rank: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RqDeliverySampleKind {
    InitialOrRepair,
    SourceRetransmit,
}

#[derive(Debug, Clone, Copy, Default)]
struct RqNeedMoreProgress {
    pending_rank: Option<u64>,
    pending_rank_columns: Option<u64>,
    pending_rank_deficit: Option<u64>,
    pending_decode_jobs: Option<u64>,
}

fn rq_shared_rate_config(config: &RqConfig) -> DatagramRateConfig {
    let initial = round0_bad_link_pacing_bps(config).unwrap_or(RQ_COLD_START_PACING_BPS);
    let symbol_bytes = u64::from(config.symbol_size.max(1));
    DatagramRateConfig {
        initial_pacing_bytes_per_s: initial,
        min_pacing_bytes_per_s: RQ_MIN_PACING_BPS,
        max_pacing_bytes_per_s: RQ_MAX_PACING_BPS,
        initial_cwnd_bytes: symbol_bytes
            .saturating_mul(u64::try_from(RQ_ADAPTIVE_BURST_SYMBOLS).unwrap_or(u64::MAX)),
        min_cwnd_bytes: symbol_bytes.max(1),
        max_cwnd_bytes: RQ_RECEIVER_FLOW_CONTROL_WINDOW_MAX_BYTES,
        pacing_gain: 1.0,
        cwnd_gain: 2.0,
        loss_backoff_threshold: aimd_loss_decrease_threshold(config),
        loss_backoff_factor: RQ_AIMD_MULTIPLICATIVE_DECREASE,
        loss_delivery_headroom: RQ_LOSS_TARGET_DELIVERY_BACKOFF_HEADROOM,
        receiver_window_gain: 1.0,
        min_receiver_window_bytes: symbol_bytes.max(1),
        max_receiver_window_bytes: RQ_RECEIVER_FLOW_CONTROL_WINDOW_MAX_BYTES,
        min_rtt_window_micros: 10_000_000,
    }
}

impl RqDeliverySampleKind {
    fn feeds_pacing_estimator(self) -> bool {
        matches!(self, Self::InitialOrRepair)
    }
}

fn delivery_sample_kind_for_need_more_response(
    requested_sources: usize,
    fec_fallback_active: bool,
) -> RqDeliverySampleKind {
    if requested_sources == 0 || fec_fallback_active {
        RqDeliverySampleKind::InitialOrRepair
    } else {
        RqDeliverySampleKind::SourceRetransmit
    }
}

#[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
impl RqAdaptiveSendState {
    fn new(seed: u64, config: &RqConfig, fanout: usize) -> Self {
        let fixed_k = fixed_block_k(config);
        let cores = std::thread::available_parallelism().map_or(4.0, |n| {
            f64::from(u32::try_from(n.get()).unwrap_or(u32::MAX))
        });
        let policy = AdaptivePolicy {
            cores,
            min_samples_to_activate: RQ_ADAPTIVE_MIN_SAMPLES,
            arm_grid_k: vec![fixed_k],
            arm_grid_fanout: vec![fanout.max(1)],
            ..AdaptivePolicy::default()
        };
        let est = PathEstimate {
            coding_ref_k: fixed_k,
            dec_symbols_per_s: RQ_ASSUMED_DECODE_SYMBOLS_PER_S,
            enc_symbols_per_s: RQ_ASSUMED_DECODE_SYMBOLS_PER_S,
            coding_gamma: RQ_CODING_GAMMA,
            ..PathEstimate::unknown()
        };
        let mut controller = AdaptiveController::new(policy, seed);
        controller.update_estimate(est);
        Self {
            controller,
            shared_rate: DatagramRateController::new(rq_shared_rate_config(config)),
            shared_rate_decision: None,
            shared_rate_clock_micros: 0,
            loss_detector: AtpLossDetector::new(),
            beacons: BeaconScheduler::new(seed, Instant::now()),
            est,
            symbol_size: config.symbol_size,
            aimd_rate_bps: round0_bad_link_pacing_bps(config).unwrap_or(RQ_COLD_START_PACING_BPS),
            aimd_feedback_seen: false,
            last_round_loss_fraction: 0.0,
            loss_ema: 0.0,
            pacing_loss_ema: 0.0,
            pacing_loss_bar: 0.0,
            loss_bar: 0.0,
            bw_ema_bps: 0.0,
            bw_trough_bps: 0.0,
            loss_pacing_cap_bps: None,
            loss_fec_floor: 0.0,
            regime_shift: false,
            last_pending_rank: None,
        }
    }

    fn record_beacon_exchange(&mut self, control_wait: Duration) {
        let now = Instant::now();
        let measurement = BeaconMeasurement::with_rtt(duration_micros_u32(control_wait), 0);
        let _action = self.beacons.next_action(now, measurement);
        self.beacons.observe_probe_result(now, control_wait);
    }

    fn mark_control_peer_activity(&mut self) {
        self.beacons.mark_peer_activity(Instant::now());
    }

    fn next_control_keepalive_due(&mut self) -> bool {
        let measurement = self
            .beacons
            .latest_rtt()
            .map_or_else(BeaconMeasurement::empty, |rtt| {
                BeaconMeasurement::with_rtt(duration_micros_u32(rtt), 0)
            });
        self.beacons
            .next_action(Instant::now(), measurement)
            .is_some()
    }

    fn control_liveness_expired(&self) -> bool {
        self.beacons.peer_liveness_expired()
    }

    fn missed_control_probes(&self) -> u8 {
        self.beacons.missed_probes()
    }

    fn round_tuning(&mut self, config: &RqConfig) -> RqRoundTuning {
        let fixed = RqRoundTuning {
            repair_overhead: config.repair_overhead.max(1.0),
            pacing: RqSprayPacing::cold_start(config.symbol_size),
        };
        let Some(mut plan) = self.controller.next_block_plan(self.symbol_size) else {
            return fixed;
        };
        // Bound the wire-loss-driven overhead before it feeds either the repair budget or the
        // pacing rate, so a round-0 over-pace artifact can't blow it up to ~10× (MATRIX-12).
        plan.overhead = plan.overhead.min(RQ_MAX_ROUND_REPAIR_OVERHEAD);

        let mut repair_overhead = config
            .repair_overhead
            .max(1.0 + plan.overhead)
            .max(1.0 + self.loss_fec_floor);
        let model_rate = self.pacing_rate_for(plan, config);
        let mut rate = if self.aimd_feedback_seen {
            self.aimd_rate_bps
        } else {
            model_rate.min(self.aimd_rate_bps)
        };
        if let Some(cap) = self.loss_pacing_cap_bps {
            rate = rate.min(self.loss_pacing_cap_for_current_regime(cap, config));
        }
        if let Some(decision) = self.shared_rate_decision {
            rate = rate.min(
                decision
                    .pacing_bytes_per_s
                    .max(aimd_decrease_floor_bps(config)),
            );
        }
        if self.regime_shift || self.pacing_loss_bar >= RQ_REGIME_SHIFT_LOSS_DELTA {
            repair_overhead = repair_overhead.max(1.03);
            if !self.aimd_feedback_seen {
                rate = rate.min(RQ_COLD_START_PACING_BPS / 2);
            }
        }

        RqRoundTuning {
            repair_overhead,
            pacing: RqSprayPacing::from_rate(
                rate,
                config.symbol_size,
                RQ_ADAPTIVE_BURST_SYMBOLS,
                Some(duration_from_secs(self.est.rtt_s)),
                self.pacing_loss_ema > 0.0,
            ),
        }
    }

    fn shared_rate_decision(&self) -> Option<DatagramRateDecision> {
        self.shared_rate_decision
    }

    fn round0_tuning(&mut self, config: &RqConfig) -> RqRoundTuning {
        let mut tuning = self.round_tuning(config);
        let round0_repair_overhead = round0_loss_target_repair_overhead(config);
        if let Some(rate) = round0_bad_link_pacing_bps(config) {
            tuning
                .pacing
                .set_rate_bytes_per_sec(rate, RQ_MAX_PACING_BPS);
        }
        if round0_loss_target_repair_enabled(config) {
            rqtrace!(
                "sender: round0_loss_target_tuning loss_target={:.4} loss_bar={:.4} source_k={} repair_overhead={:.4} extra_fraction={:.4} pacing_rate_Bps={} path_rate_bps={} max_block_size={} symbol_size={}",
                config.round0_loss_target,
                round0_loss_target_loss_bar(config),
                fixed_block_k(config),
                round0_repair_overhead,
                (round0_repair_overhead - 1.0).max(0.0),
                tuning.pacing.rate_bytes_per_sec(),
                tuning.pacing.path_rate_bps,
                config.max_block_size,
                config.symbol_size,
            );
        }
        tuning.repair_overhead = tuning.repair_overhead.max(round0_repair_overhead);
        tuning
    }

    fn source_fec_fallback_tuning(&mut self, config: &RqConfig) -> RqRoundTuning {
        let mut tuning = self.round_tuning(config);
        let k = fixed_block_k(config);
        let loss_bar = self.source_fec_fallback_loss_bar(config);
        let overhead = adaptive::overhead_for_target(
            k,
            loss_bar,
            RQ_SOURCE_FEC_FALLBACK_ALPHA,
            RQ_SOURCE_FEC_FALLBACK_MAX_OVERHEAD,
        );
        let measured_loss_overhead =
            measured_feedback_repair_overhead(self.last_round_loss_fraction);
        tuning.repair_overhead = tuning
            .repair_overhead
            .max(1.0 + overhead)
            .max(1.0 + measured_loss_overhead)
            .max(1.0 + RQ_SOURCE_FEC_FALLBACK_MIN_OVERHEAD)
            // Bound the FEC-fallback budget the same as round_tuning: when the wire-loss
            // estimate is inflated by a round-0 over-pace artifact (loss_bar≈0.9),
            // overhead_for_target returns ~9.7 ⇒ ~10.7× and a single round sprays ~10× the
            // object (~518MB for 50M → 1.7GB recv RSS). Cap at ≤2× total so repair stays
            // bounded; convergence still completes in ~2 rounds for realistic loss (MATRIX-13).
            .min(1.0 + RQ_MAX_ROUND_REPAIR_OVERHEAD);
        tuning
    }

    fn source_fec_fallback_loss_bar(&self, config: &RqConfig) -> f64 {
        let configured_loss_bar = if round0_loss_target_repair_enabled(config) {
            round0_loss_target_loss_bar(config)
        } else {
            0.0
        };
        let measured_loss = self.pacing_loss_ema.max(self.est.loss_p_hat);
        self.loss_bar
            .max(self.loss_ema)
            .max(measured_loss)
            .max(configured_loss_bar)
            .max(RQ_SOURCE_FEC_FALLBACK_MIN_LOSS_BAR)
    }

    #[cfg(test)]
    fn observe_need_more(
        &mut self,
        config: &RqConfig,
        digests: &[EntryDigest],
        pending: &BTreeSet<u32>,
        sent_this_round: u64,
        received_this_round: u64,
        round_loss_fraction: Option<f64>,
        delivery_sample_kind: RqDeliverySampleKind,
        send_wall: Duration,
        control_wait: Duration,
        total_bytes: u64,
    ) {
        let pending_bytes = pending_bytes(digests, pending);
        self.observe_need_more_with_progress(
            config,
            digests,
            pending,
            pending_bytes,
            RqNeedMoreProgress::default(),
            sent_this_round,
            received_this_round,
            round_loss_fraction,
            delivery_sample_kind,
            send_wall,
            control_wait,
            total_bytes,
        );
    }

    fn observe_need_more_with_progress(
        &mut self,
        config: &RqConfig,
        digests: &[EntryDigest],
        pending: &BTreeSet<u32>,
        prior_pending_bytes: u64,
        progress: RqNeedMoreProgress,
        sent_this_round: u64,
        received_this_round: u64,
        round_loss_fraction: Option<f64>,
        delivery_sample_kind: RqDeliverySampleKind,
        send_wall: Duration,
        control_wait: Duration,
        total_bytes: u64,
    ) {
        self.record_beacon_exchange(control_wait);

        let send_wall_s = finite_duration_s(send_wall);
        let rtt_s = finite_duration_s(control_wait);
        let pending_bytes = pending_bytes(digests, pending);
        let sent_symbols = sent_this_round.max(1);
        let pending_units = u64::try_from(pending.len()).unwrap_or(u64::MAX).max(1);
        let received_symbols = received_this_round.min(sent_symbols);
        let decode_pending_loss = (pending_units as f64 / sent_symbols as f64).clamp(0.0, 0.90);
        let derived_wire_loss = if sent_this_round == 0 {
            0.0
        } else {
            (1.0 - received_symbols as f64 / sent_symbols as f64).clamp(0.0, 0.90)
        };
        let wire_loss_hat = round_loss_fraction
            .filter(|loss| loss.is_finite())
            .map_or(derived_wire_loss, |loss| loss.clamp(0.0, 0.90));
        let feeds_pacing_estimator = delivery_sample_kind.feeds_pacing_estimator();
        let estimator_wire_loss = if feeds_pacing_estimator {
            wire_loss_hat
        } else {
            0.0
        };
        let symbol_payload_bytes = u64::from(config.symbol_size.max(1));
        let sent_payload_bytes = sent_symbols.saturating_mul(symbol_payload_bytes);
        let useful_bytes = received_symbols.saturating_mul(symbol_payload_bytes);
        let receiver_delivery_bps = (useful_bytes as f64 / send_wall_s).max(1.0);
        let offered_bps = (sent_payload_bytes as f64 / send_wall_s).max(1.0);
        let progress_delivery_bps = self.progress_delivery_bps(
            config,
            prior_pending_bytes,
            pending_bytes,
            progress,
            symbol_payload_bytes,
            send_wall_s,
        );
        let progress_delivery_bytes = progress_delivery_bps.map(|delivery_bps| {
            (delivery_bps * send_wall_s)
                .ceil()
                .clamp(0.0, sent_payload_bytes as f64) as u64
        });
        // Rank-stall reads as congestion ONLY when arrivals corroborate it.
        // The stall-ratio congestion proxy exists for kernel-overflow drops,
        // but overflow also depresses the ARRIVAL count — whereas a
        // decode-side stall (e.g. one rank-deficient block) leaves arrivals
        // healthy. Without this gate a single stalled block inflated the
        // pacing loss to 0.90 and halved the path rate every round while
        // 90%+ of symbols were arriving (MATRIX-8 re-entry via the
        // progress-stall term; MATRIX-207). Decode pressure still feeds
        // repair/FEC sizing below, never the pacer.
        let arrival_ratio = received_symbols as f64 / sent_symbols.max(1) as f64;
        let arrivals_corroborate_congestion =
            arrival_ratio < 1.0 - aimd_loss_decrease_threshold(config);
        let progress_congestion_loss = if arrivals_corroborate_congestion {
            progress_delivery_bps
                .and_then(|delivery_bps| {
                    loss_target_progress_congestion_loss(config, delivery_bps, offered_bps)
                })
                .unwrap_or(0.0)
        } else {
            0.0
        };
        let pacing_loss_sample = estimator_wire_loss.max(progress_congestion_loss);
        // Same evidence rule for the delivery estimate the AIMD backs off
        // toward: with healthy arrivals, the arrival-clocked receiver rate is
        // the path's true delivery; the rank-progress rate only substitutes
        // when arrivals themselves say the wire is failing.
        let observed_delivery_bps = if arrivals_corroborate_congestion {
            progress_delivery_bps.unwrap_or(receiver_delivery_bps)
        } else {
            receiver_delivery_bps
        }
        .max(1.0);
        let delivered_payload_bytes = progress_delivery_bytes
            .unwrap_or(useful_bytes)
            .min(sent_payload_bytes);
        self.observe_shared_rate(
            config,
            sent_payload_bytes,
            delivered_payload_bytes,
            pending_bytes,
            send_wall,
            control_wait,
        );
        if sent_this_round != 0 && feeds_pacing_estimator {
            self.apply_aimd_feedback(config, pacing_loss_sample, Some(observed_delivery_bps));
        }
        let byte_pressure = if total_bytes == 0 {
            0.0
        } else {
            (pending_bytes as f64 / total_bytes as f64).clamp(0.0, 1.0)
        };
        let pressure_loss = byte_pressure * RQ_PENDING_PRESSURE_LOSS_FLOOR;
        let repair_loss_hat = pacing_loss_sample
            .max(decode_pending_loss)
            .max(pressure_loss)
            .clamp(0.0, 0.90);

        if feeds_pacing_estimator {
            self.regime_shift = self.pacing_loss_ema > 0.0
                && pacing_loss_sample > (self.pacing_loss_ema * 3.0 + RQ_REGIME_SHIFT_LOSS_DELTA);
        }
        self.loss_ema = ema(self.loss_ema, repair_loss_hat, RQ_LOSS_EMA_ALPHA);
        if feeds_pacing_estimator {
            self.pacing_loss_ema = ema(self.pacing_loss_ema, pacing_loss_sample, RQ_LOSS_EMA_ALPHA);
        }
        let raw_loss_bar = repair_loss_hat.max(self.loss_ema) * RQ_LOSS_BAR_MULTIPLIER;
        self.loss_bar = if self.loss_bar <= 0.0 {
            raw_loss_bar
        } else {
            ema(self.loss_bar, raw_loss_bar, RQ_LOSS_EMA_ALPHA).max(repair_loss_hat)
        }
        .clamp(0.0, 0.90);
        if feeds_pacing_estimator {
            let raw_pacing_loss_bar =
                pacing_loss_sample.max(self.pacing_loss_ema) * RQ_LOSS_BAR_MULTIPLIER;
            self.pacing_loss_bar = if self.pacing_loss_bar <= 0.0 {
                raw_pacing_loss_bar
            } else {
                ema(self.pacing_loss_bar, raw_pacing_loss_bar, RQ_LOSS_EMA_ALPHA)
                    .max(pacing_loss_sample)
            }
            .clamp(0.0, 0.90);
        }

        let useful_factor = (1.0 - pacing_loss_sample * 0.5).clamp(0.25, 1.0);
        let bw_sample = offered_bps * useful_factor;
        let sent_payload_fraction = if pending_bytes == 0 {
            1.0
        } else {
            (sent_payload_bytes as f64 / pending_bytes as f64).clamp(0.0, 1.0)
        };
        let stalled_repair_sample = byte_pressure >= RQ_STALLED_REPAIR_PRESSURE_MIN
            && sent_payload_fraction < RQ_STALLED_REPAIR_PAYLOAD_FRACTION_MAX
            && pacing_loss_sample <= RQ_MILD_LOSS_PACING_MAX_LOSS;
        if feeds_pacing_estimator && (self.bw_ema_bps <= 0.0 || !stalled_repair_sample) {
            self.bw_ema_bps = if self.bw_ema_bps <= 0.0 {
                bw_sample
            } else {
                ema(self.bw_ema_bps, bw_sample, RQ_BW_EMA_ALPHA)
            };
            self.update_bw_trough(bw_sample);
        }

        self.est = PathEstimate {
            rtt_s,
            loss_p_hat: self.pacing_loss_ema,
            loss_p_bar: self.loss_bar,
            bw_median_bps: self.bw_ema_bps,
            bw_trough_bps: self.bw_trough_bps.max(self.bw_ema_bps * 0.5),
            enc_symbols_per_s: RQ_ASSUMED_DECODE_SYMBOLS_PER_S,
            dec_symbols_per_s: RQ_ASSUMED_DECODE_SYMBOLS_PER_S,
            coding_ref_k: fixed_block_k(config),
            coding_gamma: RQ_CODING_GAMMA,
            samples: self.est.samples.saturating_add(1),
        };
        self.controller.update_estimate(self.est);

        let cwnd_bytes = (self.bw_ema_bps * rtt_s)
            .max(f64::from(config.symbol_size.max(1)))
            .ceil() as u64;
        self.loss_pacing_cap_bps = None;
        self.loss_fec_floor = 0.0;
        let lost_symbols = ((sent_symbols as f64) * pacing_loss_sample)
            .ceil()
            .clamp(0.0, sent_symbols as f64) as u64;
        if feeds_pacing_estimator {
            let loss_result = self.loss_detector.observe_datagram_loss_sample(
                sent_symbols,
                lost_symbols,
                Some(control_wait),
                sent_payload_bytes,
                cwnd_bytes,
            );
            // "Mild" is relative to the configured regime: on a loss-target
            // link the expected erasure rate (plus the AIMD margin) is the
            // ambient condition, not congestion (MATRIX-207).
            let mild_loss_ceiling =
                aimd_loss_decrease_threshold(config).max(RQ_MILD_LOSS_PACING_MAX_LOSS);
            let mild_wire_loss = pacing_loss_sample <= mild_loss_ceiling
                && self.pacing_loss_ema <= mild_loss_ceiling;
            self.apply_loss_recommendations(&loss_result.recommendations, mild_wire_loss);
            self.controller.observe_path_signals(
                sent_symbols,
                received_symbols,
                send_wall_s,
                useful_bytes,
                config.symbol_size,
                PathSignalSample {
                    smoothed_rtt_s: rtt_s,
                    congestion_window_bytes: cwnd_bytes.max(u64::from(config.symbol_size.max(1))),
                    loss_rate: pacing_loss_sample,
                },
            );
        }
    }

    fn observe_shared_rate(
        &mut self,
        config: &RqConfig,
        sent_payload_bytes: u64,
        delivered_payload_bytes: u64,
        pending_bytes: u64,
        send_wall: Duration,
        control_wait: Duration,
    ) {
        if sent_payload_bytes == 0 {
            return;
        }
        let rtt_micros = u64::try_from(control_wait.as_micros())
            .unwrap_or(u64::MAX)
            .max(1);
        if self.shared_rate_clock_micros == 0 {
            self.shared_rate_clock_micros = 1;
            let _ = self.shared_rate.observe(DatagramRateSample {
                now_micros: self.shared_rate_clock_micros,
                sent_bytes: 1,
                acked_bytes: 1,
                lost_bytes: 0,
                bytes_in_flight: 0,
                rtt_micros: Some(rtt_micros),
                receiver_credit_bytes: None,
                receiver_window_bytes: None,
            });
        }
        let elapsed_micros = u64::try_from(send_wall.as_micros())
            .unwrap_or(u64::MAX)
            .max(1);
        self.shared_rate_clock_micros =
            self.shared_rate_clock_micros.saturating_add(elapsed_micros);
        let receiver_credit = rq_receiver_flow_credit_bytes(config, pending_bytes);
        let sample_sent_bytes = sent_payload_bytes.max(1);
        let sample_delivered_bytes = delivered_payload_bytes.min(sample_sent_bytes);
        let bytes_in_flight = sample_sent_bytes.saturating_sub(sample_delivered_bytes);
        self.shared_rate_decision = Some(self.shared_rate.observe(DatagramRateSample {
            now_micros: self.shared_rate_clock_micros,
            sent_bytes: sample_sent_bytes,
            acked_bytes: sample_delivered_bytes,
            lost_bytes: bytes_in_flight,
            bytes_in_flight,
            rtt_micros: Some(rtt_micros),
            receiver_credit_bytes: Some(receiver_credit),
            receiver_window_bytes: Some(receiver_credit.saturating_add(bytes_in_flight)),
        }));
    }

    fn progress_delivery_bps(
        &mut self,
        config: &RqConfig,
        prior_pending_bytes: u64,
        pending_bytes: u64,
        progress: RqNeedMoreProgress,
        symbol_payload_bytes: u64,
        send_wall_s: f64,
    ) -> Option<f64> {
        if !round0_loss_target_repair_enabled(config) {
            self.last_pending_rank = progress.pending_rank;
            return None;
        }

        let completed_entry_bytes = prior_pending_bytes.saturating_sub(pending_bytes);
        let progress_accounted = progress.pending_rank.is_some()
            || progress.pending_rank_columns.is_some()
            || progress.pending_rank_deficit.is_some()
            || progress.pending_decode_jobs.is_some();
        let rank_delta_bytes = progress.pending_rank.map(|rank| {
            let delta = self
                .last_pending_rank
                .map_or(rank, |previous| rank.saturating_sub(previous));
            self.last_pending_rank = Some(rank);
            delta.saturating_mul(symbol_payload_bytes)
        });
        let progress_bytes = completed_entry_bytes.max(rank_delta_bytes.unwrap_or(0));
        if progress_bytes == 0 {
            progress_accounted.then_some(0.0)
        } else {
            Some(progress_bytes as f64 / send_wall_s)
        }
    }

    fn apply_aimd_feedback(
        &mut self,
        config: &RqConfig,
        loss_fraction: f64,
        observed_delivery_bps: Option<f64>,
    ) {
        let loss = loss_fraction.clamp(0.0, 0.90);
        let decrease_threshold = aimd_loss_decrease_threshold(config);
        self.aimd_feedback_seen = true;
        self.last_round_loss_fraction = loss;
        if loss > decrease_threshold {
            let multiplicative =
                (self.aimd_rate_bps as f64 * RQ_AIMD_MULTIPLICATIVE_DECREASE).ceil() as u64;
            let reduced = loss_target_delivery_backoff_bps(config, observed_delivery_bps)
                .map_or(multiplicative, |delivery_backoff| {
                    delivery_backoff.min(multiplicative)
                });
            self.aimd_rate_bps = reduced.clamp(aimd_decrease_floor_bps(config), RQ_MAX_PACING_BPS);
        } else if loss <= RQ_AIMD_CLEAN_INCREASE_THRESHOLD
            && let Some(ceiling) = aimd_clean_increase_ceiling_bps(config)
            && self.aimd_rate_bps < ceiling
        {
            self.aimd_rate_bps = self
                .aimd_rate_bps
                .saturating_add(RQ_AIMD_ADDITIVE_INCREASE_BYTES_PER_S)
                .clamp(RQ_MIN_PACING_BPS, ceiling);
        }
    }

    fn apply_loss_recommendations(
        &mut self,
        recommendations: &[LossRecommendation],
        mild_wire_loss: bool,
    ) {
        for recommendation in recommendations {
            match recommendation {
                // Wire-slowing recommendations only apply when loss EXCEEDS the
                // regime's expectation (`mild_wire_loss` is threshold-aware):
                // on a configured-lossy link the erasure loss is the ambient
                // condition FEC already pays for, not congestion evidence.
                // Un-gated, sustained 9% link loss halved the pacing cap to
                // the floor every round and turned a 66s repair round into
                // 209s (500M/broken, MATRIX-207).
                LossRecommendation::ReduceCongestionWindow { factor } if !mild_wire_loss => {
                    let cap = (self.bw_ema_bps * (*factor).clamp(0.1, 1.0)).ceil() as u64;
                    self.lower_pacing_cap(cap);
                }
                LossRecommendation::EnablePacing { rate } if !mild_wire_loss => {
                    let ema_cap = if self.bw_ema_bps > 0.0 {
                        (self.bw_ema_bps * 0.75).ceil() as u64
                    } else {
                        RQ_COLD_START_PACING_BPS / 2
                    };
                    self.lower_pacing_cap((*rate).max(ema_cap));
                }
                LossRecommendation::ReduceCongestionWindow { .. }
                | LossRecommendation::EnablePacing { .. } => {}
                LossRecommendation::EnableFec { rate } => {
                    self.loss_fec_floor = self.loss_fec_floor.max((*rate).clamp(0.0, 0.50));
                }
                LossRecommendation::SwitchCongestionControl { .. } if !mild_wire_loss => {
                    self.regime_shift = true;
                    let cap = if self.bw_ema_bps > 0.0 {
                        (self.bw_ema_bps * 0.5).ceil() as u64
                    } else {
                        RQ_COLD_START_PACING_BPS / 2
                    };
                    self.lower_pacing_cap(cap);
                    self.loss_fec_floor = self.loss_fec_floor.max(0.03);
                }
                LossRecommendation::SwitchCongestionControl { .. } => {}
                LossRecommendation::IncreaseReorderingThreshold { .. } => {}
            }
        }
    }

    fn lower_pacing_cap(&mut self, cap_bps: u64) {
        let cap = cap_bps.clamp(RQ_MIN_PACING_BPS, RQ_MAX_PACING_BPS);
        self.loss_pacing_cap_bps = Some(
            self.loss_pacing_cap_bps
                .map_or(cap, |previous| previous.min(cap)),
        );
    }

    fn observe_probe_success(
        &mut self,
        config: &RqConfig,
        sent_this_round: u64,
        send_wall: Duration,
        control_wait: Duration,
    ) {
        self.record_beacon_exchange(control_wait);

        if sent_this_round == 0 {
            self.est = PathEstimate {
                rtt_s: finite_duration_s(control_wait),
                samples: self.est.samples.saturating_add(1),
                ..self.est
            };
            self.controller.update_estimate(self.est);
            return;
        }

        let send_wall_s = finite_duration_s(send_wall);
        let rtt_s = finite_duration_s(control_wait);
        let sent_payload_bytes =
            sent_this_round.saturating_mul(u64::from(config.symbol_size.max(1)));
        let bw_sample = (sent_payload_bytes as f64 / send_wall_s).max(1.0);
        self.observe_shared_rate(
            config,
            sent_payload_bytes,
            sent_payload_bytes,
            sent_payload_bytes,
            send_wall,
            control_wait,
        );
        self.apply_aimd_feedback(config, 0.0, Some(bw_sample));
        self.bw_ema_bps = if self.bw_ema_bps <= 0.0 {
            bw_sample
        } else {
            ema(self.bw_ema_bps, bw_sample, RQ_BW_EMA_ALPHA)
        };
        self.update_bw_trough(bw_sample);
        self.loss_ema = ema(self.loss_ema, 0.0, RQ_LOSS_EMA_ALPHA);
        self.pacing_loss_ema = ema(self.pacing_loss_ema, 0.0, RQ_LOSS_EMA_ALPHA);
        self.loss_bar = ema(self.loss_bar, 0.0, RQ_LOSS_EMA_ALPHA);
        self.pacing_loss_bar = ema(self.pacing_loss_bar, 0.0, RQ_LOSS_EMA_ALPHA);
        self.loss_pacing_cap_bps = None;
        self.loss_fec_floor = 0.0;

        self.est = PathEstimate {
            rtt_s,
            loss_p_hat: self.pacing_loss_ema,
            loss_p_bar: self.loss_bar,
            bw_median_bps: self.bw_ema_bps,
            bw_trough_bps: self.bw_trough_bps.max(self.bw_ema_bps * 0.5),
            enc_symbols_per_s: RQ_ASSUMED_DECODE_SYMBOLS_PER_S,
            dec_symbols_per_s: RQ_ASSUMED_DECODE_SYMBOLS_PER_S,
            coding_ref_k: fixed_block_k(config),
            coding_gamma: RQ_CODING_GAMMA,
            samples: self.est.samples.saturating_add(1),
        };
        self.controller.update_estimate(self.est);

        let cwnd_bytes = (self.bw_ema_bps * rtt_s)
            .max(f64::from(config.symbol_size.max(1)))
            .ceil() as u64;
        self.controller.observe_path_signals(
            sent_this_round,
            sent_this_round,
            send_wall_s,
            sent_payload_bytes,
            config.symbol_size,
            PathSignalSample {
                smoothed_rtt_s: rtt_s,
                congestion_window_bytes: cwnd_bytes.max(u64::from(config.symbol_size.max(1))),
                loss_rate: 0.0,
            },
        );
    }

    fn pacing_rate_for(&self, plan: BlockPlan, config: &RqConfig) -> u64 {
        let mut network_bps = if self.est.bw_median_bps > 0.0 {
            self.est.bw_median_bps.min(self.est.bw_trough_bps.max(1.0))
        } else {
            RQ_COLD_START_PACING_BPS as f64
        };
        if self.mild_loss_pacing_floor_applies() {
            network_bps = network_bps.max(self.mild_loss_pacing_floor_bps(config) as f64);
        }
        let decode_bps =
            self.est.decode_symbols_per_s_at(plan.k) * f64::from(self.symbol_size.max(1));
        let base = network_bps.min(decode_bps.max(1.0));
        let rate = base / (1.0 + plan.overhead.max(0.0));
        rqtrace!(
            "pacing_rate_for: network_bps={:.0} decode_bps={:.0} base={:.0} overhead={:.4} rate={:.0} bw_median={:.0} bw_trough={:.0} mild_floor={}",
            network_bps,
            decode_bps,
            base,
            plan.overhead.max(0.0),
            rate,
            self.est.bw_median_bps,
            self.est.bw_trough_bps,
            self.mild_loss_pacing_floor_applies()
        );
        rate.ceil()
            .clamp(RQ_MIN_PACING_BPS as f64, RQ_MAX_PACING_BPS as f64) as u64
    }

    fn update_bw_trough(&mut self, bw_sample: f64) {
        if self.bw_trough_bps <= 0.0 || bw_sample < self.bw_trough_bps {
            self.bw_trough_bps = bw_sample;
        } else {
            self.bw_trough_bps = ema(self.bw_trough_bps, bw_sample, RQ_BW_TROUGH_RECOVERY_ALPHA)
                .min(self.bw_ema_bps.max(bw_sample));
        }
    }

    fn mild_loss_pacing_floor_applies(&self) -> bool {
        let pacing_loss = self.pacing_loss_ema;
        let has_repair_pressure = self.loss_bar > 0.0 || self.pacing_loss_bar > 0.0;
        !self.regime_shift
            && has_repair_pressure
            && pacing_loss <= RQ_MILD_LOSS_PACING_MAX_LOSS
            && self.est.bw_median_bps > 0.0
    }

    fn mild_loss_pacing_floor_bps(&self, config: &RqConfig) -> u64 {
        if let Some(rate) = round0_bad_link_pacing_bps(config) {
            return rate;
        }
        let floor_fraction = if round0_source_first_loss_target(config)
            && config.round0_loss_target > f64::EPSILON
        {
            RQ_SOURCE_FIRST_MILD_LOSS_PACING_FLOOR_FRACTION
        } else {
            RQ_MILD_LOSS_PACING_FLOOR_FRACTION
        };
        (RQ_COLD_START_PACING_BPS as f64 * floor_fraction).ceil() as u64
    }

    fn loss_pacing_cap_for_current_regime(&self, cap: u64, config: &RqConfig) -> u64 {
        if self.mild_loss_pacing_floor_applies() {
            cap.max(self.mild_loss_pacing_floor_bps(config))
        } else {
            cap
        }
    }
}

fn fixed_block_k(config: &RqConfig) -> u32 {
    let symbol_size = usize::from(config.symbol_size.max(1));
    let k = config.max_block_size.div_ceil(symbol_size).max(1);
    u32::try_from(k).unwrap_or(u32::MAX)
}

/// Per-block decode-failure target for the round-0 first flight.
///
/// Deliberately far looser than `RQ_SOURCE_FEC_FALLBACK_ALPHA` (1e-6): a
/// round-0 block that misses decode is simply repaired by the feedback round
/// at the (now sustained) path rate, so paying a ~4.75σ concentration margin
/// up front is a pure byte tax. On the 500M/broken cell the 1e-6 target
/// inflated round-0 to +25.3% repair overhead — 657 MB on a 10 mbit link is
/// ≥526 s of wire time before any repair, which alone loses to rsync. At
/// α=0.02, K=437 the margin drops to ~+16-18% and the expected ~2% of blocks
/// that miss cost one cheap repair round (MATRIX-207).
const RQ_ROUND0_TARGET_ALPHA: f64 = 0.02;

fn round0_loss_target_repair_overhead(config: &RqConfig) -> f64 {
    if !round0_loss_target_repair_enabled(config) {
        return config.repair_overhead.max(1.0);
    }
    let loss_bar = round0_loss_target_loss_bar(config);
    let overhead = adaptive::decode_repair_overhead_for_target(
        fixed_block_k(config),
        loss_bar,
        RQ_ROUND0_TARGET_ALPHA,
        RQ_SOURCE_FEC_FALLBACK_MAX_OVERHEAD,
    )
    .min(RQ_MAX_ROUND_REPAIR_OVERHEAD);
    config.repair_overhead.max(1.0 + overhead)
}

fn round0_loss_target_loss_bar(config: &RqConfig) -> f64 {
    (config.round0_loss_target * (1.0 + RQ_ROUND0_TARGET_LOSS_MARGIN_FRACTION)
        + RQ_ROUND0_TARGET_LOSS_MARGIN_MIN)
        .clamp(0.0, RQ_SOURCE_FEC_FALLBACK_MAX_OVERHEAD)
}

fn round0_loss_target_repair_enabled(config: &RqConfig) -> bool {
    let loss = config.round0_loss_target;
    loss.is_finite() && loss >= RQ_ROUND0_TARGET_LOSS_ENABLE_MIN
}

fn round0_bad_link_pacing_bps(config: &RqConfig) -> Option<u64> {
    let loss = config.round0_loss_target;
    if loss.is_finite()
        && (RQ_BAD_LINK_ROUND0_LOSS_MIN..=RQ_BAD_LINK_ROUND0_LOSS_MAX).contains(&loss)
    {
        Some(RQ_BAD_LINK_ROUND0_PACING_BPS)
    } else if loss.is_finite()
        && loss > RQ_BROKEN_LINK_ROUND0_LOSS_MIN
        && loss <= RQ_BROKEN_LINK_ROUND0_LOSS_MAX
    {
        Some(RQ_BROKEN_LINK_ROUND0_PACING_BPS)
    } else {
        None
    }
}

fn round0_source_first_loss_target(config: &RqConfig) -> bool {
    let loss = config.round0_loss_target;
    loss.is_finite() && loss >= 0.0 && !round0_loss_target_repair_enabled(config)
}

fn small_clean_source_only_round0(total_bytes: u64, config: &RqConfig) -> bool {
    clean_control_source_stream_round0(config)
        && total_bytes <= RQ_SMALL_CLEAN_SOURCE_ONLY_MAX_BYTES
}

fn clean_control_source_stream_round0(config: &RqConfig) -> bool {
    let loss_free_target = round0_source_first_loss_target(config)
        && (0.0..=f64::EPSILON).contains(&config.round0_loss_target);
    control_source_stream_base_round0(config) && loss_free_target
}

fn near_clean_control_source_stream_round0(config: &RqConfig) -> bool {
    let source_first_target = round0_source_first_loss_target(config)
        && config.round0_loss_target <= RQ_CONTROL_SOURCE_STREAM_MAX_LOSS_TARGET + f64::EPSILON;
    control_source_stream_base_round0(config) && source_first_target
}

fn control_source_stream_base_round0(config: &RqConfig) -> bool {
    config.debug_drop_one_in == 0
        && config.repair_overhead.is_finite()
        && config.repair_overhead <= RQ_SMALL_CLEAN_SOURCE_ONLY_MAX_REPAIR_OVERHEAD
}

fn control_source_stream_eligible(total_bytes: u64, config: &RqConfig) -> bool {
    if total_bytes == 0 || total_bytes > config.max_transfer_bytes {
        return false;
    }
    if near_clean_control_source_stream_round0(config) {
        return true;
    }
    // ADDITIVE composing path selection (MATRIX-199 / 317hxr.2.5): a LARGE object over a
    // MODERATELY-lossy link takes the reliable control-source stream instead of the FEC datagram
    // spray, because the spray rate-collapses on large lossy objects (a non-converging block
    // inflates the loss estimate → the pacing rate halves each round → timeout) while reliable TCP
    // retransmit completes and beats rsync (500M/bad@2%: reliable-stream 95.3s vs rsync 97.9s;
    // spray times out). Small objects and high-loss links still take the spray, where forward-repair
    // wins (e.g. 50M/broken). This does NOT touch the FEC pacing path; once the spray collapse is
    // fixed (317hxr.2.5) this fallback can be narrowed.
    total_bytes >= RQ_LARGE_LOSSY_SOURCE_STREAM_MIN_BYTES
        && control_source_stream_base_round0(config)
        && config.round0_loss_target.is_finite()
        && config.round0_loss_target >= 0.0
        && config.round0_loss_target <= RQ_LARGE_LOSSY_SOURCE_STREAM_MAX_LOSS_TARGET
}

fn apply_small_clean_round0_source_only(
    total_bytes: u64,
    config: &RqConfig,
    mut tuning: RqRoundTuning,
) -> RqRoundTuning {
    if small_clean_source_only_round0(total_bytes, config) {
        tuning.repair_overhead = 1.0;
        tuning.pacing = RqSprayPacing::cold_start(config.symbol_size);
    }
    tuning
}

fn measured_feedback_repair_overhead(loss_fraction: f64) -> f64 {
    if !loss_fraction.is_finite() {
        return 0.0;
    }
    let loss = loss_fraction.clamp(0.0, RQ_SOURCE_FEC_FALLBACK_MAX_OVERHEAD);
    if loss < RQ_FEEDBACK_REPAIR_LOSS_ENABLE_MIN {
        return 0.0;
    }
    (loss * (1.0 + RQ_FEEDBACK_REPAIR_LOSS_MARGIN_FRACTION) + RQ_FEEDBACK_REPAIR_LOSS_MARGIN_MIN)
        .clamp(0.0, RQ_SOURCE_FEC_FALLBACK_MAX_OVERHEAD)
}

fn aimd_loss_decrease_threshold(config: &RqConfig) -> f64 {
    let expected_loss = if round0_loss_target_repair_enabled(config) {
        config.round0_loss_target
    } else {
        0.0
    };
    (expected_loss + RQ_AIMD_LOSS_DECREASE_THRESHOLD_MARGIN)
        .max(RQ_AIMD_LOSS_DECREASE_THRESHOLD_MIN)
        .clamp(0.0, 0.90)
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn loss_target_delivery_backoff_bps(
    config: &RqConfig,
    observed_delivery_bps: Option<f64>,
) -> Option<u64> {
    if !round0_loss_target_repair_enabled(config) {
        return None;
    }
    let delivery_bps = observed_delivery_bps?.clamp(1.0, RQ_MAX_PACING_BPS as f64);
    if !delivery_bps.is_finite() {
        return None;
    }
    Some(
        (delivery_bps * RQ_LOSS_TARGET_DELIVERY_BACKOFF_HEADROOM)
            .ceil()
            .clamp(RQ_MIN_PACING_BPS as f64, RQ_MAX_PACING_BPS as f64) as u64,
    )
}

fn aimd_decrease_floor_bps(config: &RqConfig) -> u64 {
    if round0_source_first_loss_target(config) && config.round0_loss_target > f64::EPSILON {
        // MATRIX-77: the good cell's sparse residual feedback should size
        // repair without dragging the next spray below cold-start. Bad/broken
        // cells use round-0 repair targets and keep the older AIMD decrease.
        RQ_COLD_START_PACING_BPS
    } else {
        RQ_MIN_PACING_BPS
    }
}

fn aimd_clean_increase_ceiling_bps(config: &RqConfig) -> Option<u64> {
    if round0_loss_target_repair_enabled(config) {
        round0_bad_link_pacing_bps(config)
    } else {
        Some(RQ_MAX_PACING_BPS)
    }
}

fn loss_target_progress_congestion_loss(
    config: &RqConfig,
    progress_delivery_bps: f64,
    offered_bps: f64,
) -> Option<f64> {
    if !round0_loss_target_repair_enabled(config) || !offered_bps.is_finite() || offered_bps <= 0.0
    {
        return None;
    }
    let delivery_ratio = (progress_delivery_bps / offered_bps).clamp(0.0, 1.0);
    if delivery_ratio >= RQ_LOSS_TARGET_PROGRESS_STALL_RATIO {
        return None;
    }
    let decrease_threshold = aimd_loss_decrease_threshold(config);
    Some(
        (1.0 - delivery_ratio)
            .max(decrease_threshold + RQ_LOSS_TARGET_PROGRESS_LOSS_MARGIN)
            .clamp(0.0, 0.90),
    )
}

fn pending_bytes(digests: &[EntryDigest], pending: &BTreeSet<u32>) -> u64 {
    pending.iter().fold(0u64, |acc, index| {
        let Some(entry) = usize::try_from(*index)
            .ok()
            .and_then(|idx| digests.get(idx))
        else {
            return acc;
        };
        acc.saturating_add(entry.size)
    })
}

fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn finite_duration_s(duration: Duration) -> f64 {
    duration.as_secs_f64().max(0.000_001)
}

fn duration_from_secs(seconds: f64) -> Duration {
    if seconds.is_finite() {
        Duration::from_secs_f64(seconds.clamp(0.000_001, 60.0))
    } else {
        Duration::from_micros(1)
    }
}

fn duration_micros_u32(duration: Duration) -> u32 {
    u32::try_from(duration.as_micros()).unwrap_or(u32::MAX)
}

fn ema(prev: f64, sample: f64, alpha: f64) -> f64 {
    prev.mul_add(1.0 - alpha, sample * alpha)
}

/// Errors from the ATP-over-RaptorQ transport.
#[derive(Debug, thiserror::Error)]
pub enum RqError {
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
    /// RaptorQ encode/decode error.
    #[error("coding error: {0}")]
    Coding(String),
    /// The fountain feedback loop ran out of rounds with entries still
    /// undecoded.
    #[error(
        "[ASUP-E801] transfer did not converge after {rounds} feedback rounds ({pending} entries still incomplete); if accepted symbols do not advance decode rank, see [ASUP-E805]"
    )]
    NoConvergence {
        /// Feedback rounds attempted.
        rounds: u32,
        /// Entries still undecoded.
        pending: usize,
    },
    /// Integrity verification failed (SHA-256 or merkle-root mismatch).
    #[error("integrity verification failed: {0}")]
    Integrity(String),
    /// Symbol authentication is missing, mismatched, or invalid.
    #[error("symbol authentication failed: {0}")]
    Authentication(String),
    /// The source path was invalid (missing, unsupported type).
    #[error("invalid source path: {0}")]
    Source(String),
    /// The transfer was cancelled via the capability context.
    #[error("transfer cancelled")]
    Cancelled,
}

// ─── Wire control payloads (JSON over TCP) ───────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Hello {
    protocol: u32,
    role: String,
    peer_id: String,
    symbol_size: u16,
    max_block_size: u64,
    #[serde(default)]
    symbol_auth: bool,
    /// Total payload bytes of the transfer. The receiver sizes its UDP recv buffer to absorb the
    /// sender's (now parallel-encoded) symbol burst so the CPU-bound decode can drain it without
    /// kernel drops. `serde(default)` keeps it tolerant of peers that do not send it.
    #[serde(default)]
    total_bytes: u64,
    /// Sender preference for the clean source-only control-stream lane.
    ///
    /// Older receivers ignore this field and omit the matching ack bit, causing
    /// the sender to fall back to the UDP/RaptorQ symbol path.
    #[serde(default)]
    prefer_control_source_stream: bool,
    /// Fresh sender challenge. Present only when an exact authenticated delta
    /// manifest will follow a successfully authenticated acknowledgement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    delta_transfer_nonce: Option<TransferNonce>,
    /// Sender-role shared-key possession proof over the exact initial offer.
    /// It must accompany `delta_transfer_nonce` and is verified before the
    /// receiver allocates delta state or UDP sockets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    delta_client_auth_tag: Option<[u8; 32]>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HelloAck {
    accepted: bool,
    peer_id: String,
    /// First UDP port the receiver is listening on for symbol datagrams.
    udp_port: u16,
    /// Full receiver-side UDP fanout. Empty means legacy single-port `udp_port`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    udp_ports: Vec<u16>,
    /// Receiver accepted the clean source-only control-stream lane.
    #[serde(default)]
    control_source_stream: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    /// Echo of the sender's delta challenge.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    delta_transfer_nonce: Option<TransferNonce>,
    /// Fresh receiver challenge for cross-session replay rejection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    delta_receiver_nonce: Option<TransferNonce>,
    /// Keyed commitment to the configured destination root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    delta_destination_root: Option<[u8; 32]>,
    /// Receiver-role shared-key possession proof over the complete
    /// acknowledgement and both peer labels. This does not establish a unique
    /// peer identity because every holder of the symmetric key can produce it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    delta_server_auth_tag: Option<[u8; 32]>,
}

fn hello_ack_udp_ports(ack: &HelloAck) -> SmallVec<[u16; DEFAULT_UDP_FANOUT]> {
    advertised_udp_ports(ack.udp_port, &ack.udp_ports)
}

fn advertised_udp_ports(primary: u16, advertised: &[u16]) -> SmallVec<[u16; DEFAULT_UDP_FANOUT]> {
    let mut ports = SmallVec::<[u16; DEFAULT_UDP_FANOUT]>::new();
    if advertised.is_empty() {
        if primary != 0 {
            ports.push(primary);
        }
        return ports;
    }

    if primary != 0 {
        ports.push(primary);
    }
    for &port in advertised {
        if port != 0 && !ports.contains(&port) {
            ports.push(port);
        }
    }
    ports
}

fn receiver_udp_addr_for_socket(
    peer: SocketAddr,
    udp_ports: &[u16],
    socket_index: usize,
) -> Result<SocketAddr, RqError> {
    if udp_ports.is_empty() {
        return Err(RqError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "RQ receiver did not advertise any UDP data ports",
        )));
    }
    Ok(SocketAddr::new(
        peer.ip(),
        udp_ports[socket_index % udp_ports.len()],
    ))
}

/// One logical file packed into a combined RaptorQ object (E-15 coalescing).
///
/// When [`ManifestEntry::members`] is non-empty the entry's content is the byte
/// concatenation of its members in `offset` order; the receiver splits the decoded
/// object back into the member files on commit. This amortizes the per-object
/// runtime overhead (decode pipeline / tasks / commit) that makes many-small-file
/// trees slow (profiled: ~81% runtime sync, 5.8× a same-byte single file).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PackedMember {
    /// Path of this file relative to the transfer root.
    pub rel_path: String,
    /// Byte offset of this file within the combined object content.
    pub offset: u64,
    /// Byte length of this file.
    pub len: u64,
    /// Lowercase hex SHA-256 of this file's content (per-member integrity check).
    pub sha256_hex: String,
}

/// One ordered RaptorQ object shard of a larger logical file.
///
/// A fragmented entry's manifest `rel_path` names the encoded object, while
/// this metadata names the logical file that will be reassembled and committed
/// after all shards verify. `sha256_hex` is the whole logical file SHA-256, not
/// the per-shard object hash (that remains [`ManifestEntry::sha256_hex`]).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LargeObjectFragment {
    /// Logical file path relative to the transfer root.
    pub rel_path: String,
    /// Zero-based shard ordinal within the logical file.
    pub shard_index: u32,
    /// Total shard count for this logical file.
    pub shard_count: u32,
    /// Byte offset of this shard in the logical file.
    pub logical_offset: u64,
    /// Byte length carried by this shard.
    pub len: u64,
    /// Whole logical file size.
    pub logical_size: u64,
    /// Lowercase hex SHA-256 of the whole logical file.
    pub sha256_hex: String,
}

/// One file within a transfer manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManifestEntry {
    /// Stable index within the transfer (manifest order).
    pub index: u32,
    /// Path relative to the transfer root.
    pub rel_path: String,
    /// Entry size in bytes.
    pub size: u64,
    /// Lowercase hex SHA-256 of the entry content.
    pub sha256_hex: String,
    /// Files packed into this entry (E-15 coalescing). Empty = a normal single-file
    /// entry whose content IS the file (prior wire format, byte-identical). Non-empty
    /// = this entry is a combined object and these members are extracted by offset on
    /// receive. `skip_serializing_if` keeps the no-packing wire byte-identical.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<PackedMember>,
    /// Large-file multi-object metadata. Present when this manifest entry is one
    /// ordered shard of a single logical file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fragment: Option<LargeObjectFragment>,
}

/// One logical file's non-bare metadata in an RQ transfer.
///
/// Metadata is keyed by the final logical path rather than encoded-object path,
/// so packing and large-file fragmentation cannot change its meaning.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RqMetadataEntry {
    /// Path relative to the transfer root.
    pub rel_path: String,
    /// Metadata captured under the sender's [`MetadataPolicy`].
    pub metadata: EntryMetadata,
}

/// Versioned metadata block committed independently from content integrity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RqMetadataManifest {
    /// RQ metadata schema version.
    pub version: u8,
    /// Canonical commitment over every logical file plus explicit directory
    /// metadata record.
    pub commitment_hex: String,
    /// Non-bare per-file metadata. Missing logical paths reconstruct as bare
    /// regular files before commitment verification.
    pub entries: Vec<RqMetadataEntry>,
    /// Transfer-root and implicit non-empty-directory metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directories: Option<DirectoryMetadataManifest>,
}

/// Transfer manifest carried in the `ObjectManifest` frame.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TransferManifest {
    /// Stable transfer identifier (hex).
    pub transfer_id: String,
    /// Name of the transfer root (file name or directory name).
    pub root_name: String,
    /// Whether the root is a directory (vs a single file).
    pub is_directory: bool,
    /// Total bytes across all entries.
    pub total_bytes: u64,
    /// Lowercase hex of `MerkleRoot::from_graph` over the flat object graph.
    pub merkle_root_hex: String,
    /// Versioned filesystem metadata commitment. The optional wire shape keeps
    /// deserialization diagnostic-friendly for older manifests, but protocol v4
    /// validation rejects `None` so the whole block cannot be stripped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<RqMetadataManifest>,
    /// Bounded receiver-driven delta manifest. It is authoritative only inside
    /// an authenticated `RqDeltaManifestEnvelope`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delta_manifest: Option<DeltaManifestWire>,
    /// File entries in manifest order.
    pub entries: Vec<ManifestEntry>,
}

/// Object-level digest carried in the source-stream `ObjectComplete` trailer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ObjectCompleteEntryDigest {
    /// Manifest entry index.
    index: u32,
    /// Entry byte length observed by the sender while streaming.
    size: u64,
    /// Lowercase hex SHA-256 of this encoded object.
    sha256_hex: String,
}

/// Logical-file digest carried in the source-stream `ObjectComplete` trailer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ObjectCompleteLogicalDigest {
    /// Logical path relative to the transfer root.
    rel_path: String,
    /// Logical file byte length observed by the sender while streaming.
    size: u64,
    /// Lowercase hex SHA-256 of the logical file.
    sha256_hex: String,
}

/// Sender -> receiver marker for one finished spray/source-stream round.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct RqRoundComplete {
    /// Number of datagrams the sender emitted in the completed spray round.
    ///
    /// The receiver uses this with its observed datagram count to report an
    /// explicit loss fraction in `NeedMore`. Empty legacy `ObjectComplete`
    /// frames are treated as unknown and fall back to sender-side inference.
    #[serde(default)]
    round_symbols_sent: u64,
    /// Source-stream trailer digests for each encoded object. Empty on the UDP
    /// RaptorQ datagram path, where manifest hashes remain authoritative.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    entry_digests: Vec<ObjectCompleteEntryDigest>,
    /// Source-stream trailer digests for logical files whose digest is not
    /// authoritatively carried by the manifest.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    logical_digests: Vec<ObjectCompleteLogicalDigest>,
    /// Source-stream logical merkle root. Empty on the UDP datagram path, where
    /// the manifest merkle root remains authoritative.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    merkle_root_hex: Option<String>,
}

/// Sender-side UDP batch acceleration counters for the ATP-RQ symbol plane.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct UdpSendAccelerationReport {
    /// Logical per-socket batch flushes issued by the RQ sender.
    pub flushes: u64,
    /// Symbol datagrams reported as processed by the UDP layer.
    pub datagrams: u64,
    /// Payload bytes reported as processed by the UDP layer.
    pub payload_bytes: u64,
    /// Flushes that used an OS-native send batching syscall.
    pub native_batch_flushes: u64,
    /// Datagrams processed by flushes that used an OS-native send batching syscall.
    pub native_batch_datagrams: u64,
    /// Flushes that used UDP Generic Segmentation Offload.
    pub gso_flushes: u64,
    /// Datagrams processed by flushes that used UDP Generic Segmentation Offload.
    pub gso_datagrams: u64,
    /// Flushes that used the portable fallback loop for at least part of the batch.
    pub fallback_flushes: u64,
    /// Datagrams processed by flushes that used the portable fallback loop.
    pub fallback_datagrams: u64,
    /// Flushes that returned fewer datagrams than the sender queued.
    pub partial_flushes: u64,
    /// Flushes that surfaced a UDP-layer error string.
    pub error_flushes: u64,
}

impl UdpSendAccelerationReport {
    fn observe_flush_report(&mut self, report: RqSendBatchFlushReport) {
        self.flushes = self
            .flushes
            .saturating_add(u64::try_from(report.socket_flushes).unwrap_or(u64::MAX));
        self.datagrams = self
            .datagrams
            .saturating_add(u64::try_from(report.packets_processed).unwrap_or(u64::MAX));
        self.payload_bytes = self
            .payload_bytes
            .saturating_add(u64::try_from(report.bytes_processed).unwrap_or(u64::MAX));
        self.native_batch_flushes = self
            .native_batch_flushes
            .saturating_add(u64::try_from(report.native_flushes).unwrap_or(u64::MAX));
        self.native_batch_datagrams = self
            .native_batch_datagrams
            .saturating_add(u64::try_from(report.native_packets).unwrap_or(u64::MAX));
        self.gso_flushes = self
            .gso_flushes
            .saturating_add(u64::try_from(report.gso_flushes).unwrap_or(u64::MAX));
        self.gso_datagrams = self
            .gso_datagrams
            .saturating_add(u64::try_from(report.gso_packets).unwrap_or(u64::MAX));
        self.fallback_flushes = self
            .fallback_flushes
            .saturating_add(u64::try_from(report.fallback_flushes).unwrap_or(u64::MAX));
        self.fallback_datagrams = self
            .fallback_datagrams
            .saturating_add(u64::try_from(report.fallback_packets).unwrap_or(u64::MAX));
        self.partial_flushes = self
            .partial_flushes
            .saturating_add(u64::try_from(report.partial_flushes).unwrap_or(u64::MAX));
        self.error_flushes = self
            .error_flushes
            .saturating_add(u64::try_from(report.error_flushes).unwrap_or(u64::MAX));
    }
}

/// Receiver → sender fountain feedback: entries still needing more symbols.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct NeedMore {
    /// Entry indices that have not yet decoded.
    pending: Vec<u32>,
    /// Sparse systematic source symbols missing from incomplete blocks.
    #[serde(default)]
    source_symbols: Vec<SourceSymbolRequest>,
    /// Matching RQ symbols observed by the receiver in the completed spray round.
    ///
    /// This is the pacing/loss signal: duplicates and symbols that fail to
    /// advance decode rank still prove the datagram arrived on the wire.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    round_symbols_observed: Option<u64>,
    /// Receiver-computed symbol loss fraction for the completed spray round.
    ///
    /// AIMD uses this explicit wire-loss signal; pending decode pressure remains
    /// separate and only feeds repair/FEC sizing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    round_loss_fraction: Option<f64>,
    /// Matching RQ symbols accepted into a decoder in the completed spray round.
    ///
    /// This remains diagnostic only; accepted symbols can stall on duplicate or
    /// dependent repair rows and must not be treated as packet loss.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    round_symbols_accepted: Option<u64>,
    /// Aggregate decoder rank across the still-pending entries after this round.
    ///
    /// Unlike `round_symbols_observed`, this is confirmed useful progress. The
    /// sender uses rank deltas as a delivery-clocked congestion signal for lossy
    /// cells where kernel overflow can make arrival loss appear artificially low.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending_rank: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending_rank_columns: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending_rank_deficit: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending_decode_jobs: Option<u64>,
}

/// Request for retransmission of one systematic source symbol.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
struct SourceSymbolRequest {
    entry: u32,
    sbn: u8,
    esi: u32,
}

/// Receipt returned by the receiver in the `Proof` frame.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReceiveReceipt {
    /// Whether the receiver atomically committed the transfer to its destination.
    pub committed: bool,
    /// Total bytes received.
    pub bytes_received: u64,
    /// Number of files received.
    pub files: u32,
    /// Whether every entry's SHA-256 matched the manifest.
    pub sha_ok: bool,
    /// Whether the rebuilt merkle root matched the manifest.
    pub merkle_ok: bool,
    /// Total symbol datagrams the receiver accepted.
    pub symbols_accepted: u64,
    /// Fountain feedback rounds used.
    pub feedback_rounds: u32,
    /// Failure reason when `committed` is false.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Absolute destination paths that were committed. Privacy-preserving
    /// authenticated no-op proofs leave this empty; the receiver keeps its
    /// local paths in [`ReceiveReport::committed_paths`].
    pub committed_paths: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RqDeltaHandshakeContext {
    sender_nonce: TransferNonce,
    receiver_nonce: TransferNonce,
    destination_root: [u8; 32],
    handshake_hash: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RqDeltaSessionContext {
    session_id: [u8; 32],
    destination_root: [u8; 32],
}

#[derive(zeroize::ZeroizeOnDrop)]
struct RqDeltaDestinationBinding {
    receiver_secret_salt: [u8; 32],
    commitment: [u8; 32],
}

// Security boundary: these envelopes authenticate the delta negotiation and
// its zero-byte completion with a symmetric key. They do not encrypt the raw
// TCP stream, authorize a self-asserted `peer_id`, or authenticate the legacy
// NeedMore/Proof exchange after a signed FullObject request. In that fallback
// branch the existing wire receipt can still expose committed receiver paths.

/// Sender-role shared-key possession proof over the exact typed manifest.
/// It authenticates the protocol role, not a unique peer identity or signer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RqDeltaManifestEnvelope {
    session_id: [u8; 32],
    destination_root: [u8; 32],
    control_seq: u64,
    manifest: TransferManifest,
    client_auth_tag: [u8; 32],
}

/// Receiver-selected delta mode, authenticated by shared-key role possession
/// on the raw TCP control stream. The stream provides no confidentiality.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RqDeltaObjectRequestEnvelope {
    session_id: [u8; 32],
    transfer_id: String,
    destination_root: [u8; 32],
    control_seq: u64,
    request: DeltaObjectRequest,
    /// UDP ports are deferred until after the sender's manifest proof verifies.
    /// They are empty for an already-in-sync no-op.
    #[serde(default)]
    udp_port: u16,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    udp_ports: Vec<u16>,
    server_auth_tag: [u8; 32],
}

/// Sender-role authenticated zero-object completion for the no-op branch.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RqDeltaCompleteEnvelope {
    session_id: [u8; 32],
    transfer_id: String,
    destination_root: [u8; 32],
    control_seq: u64,
    bytes_sent: u64,
    client_auth_tag: [u8; 32],
}

/// Receiver-role authenticated proof after live destination revalidation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RqDeltaProofEnvelope {
    session_id: [u8; 32],
    transfer_id: String,
    destination_root: [u8; 32],
    control_seq: u64,
    receipt: ReceiveReceipt,
    server_auth_tag: [u8; 32],
}

/// Outcome of a successful [`send_path`] call.
#[derive(Debug, Clone)]
pub struct SendReport {
    /// Transfer identifier.
    pub transfer_id: String,
    /// Total bytes sent.
    pub bytes_sent: u64,
    /// Number of files sent.
    pub files: u32,
    /// Total symbol datagrams emitted (across all feedback rounds).
    pub symbols_sent: u64,
    /// Fountain feedback rounds used.
    pub feedback_rounds: u32,
    /// Merkle root (hex) of the transfer.
    pub merkle_root_hex: String,
    /// The receiver's receipt.
    pub receipt: ReceiveReceipt,
    /// UDP send acceleration counters observed on the RQ symbol plane.
    pub udp_send_acceleration: UdpSendAccelerationReport,
    /// Peer control-plane address.
    pub peer: SocketAddr,
}

/// Outcome of a successful received transfer.
#[derive(Debug, Clone)]
pub struct ReceiveReport {
    /// Transfer identifier.
    pub transfer_id: String,
    /// Total bytes received.
    pub bytes_received: u64,
    /// Number of files committed.
    pub files: u32,
    /// Whether the transfer was committed to the destination.
    pub committed: bool,
    /// Total symbol datagrams accepted.
    pub symbols_accepted: u64,
    /// Fountain feedback rounds used.
    pub feedback_rounds: u32,
    /// Absolute committed paths.
    pub committed_paths: Vec<PathBuf>,
    /// Peer control-plane address.
    pub peer: SocketAddr,
}

/// Outcome of a bonded donor's one-way symbol spray.
///
/// This is the B1 donor-side data-path report: the donor has proven its local
/// bytes match the agreed descriptor, materialized only its assigned ESIs, and
/// sent those symbols to the receiver endpoint(s). Receiver feedback and
/// `NeedMore`/`Close` handling are intentionally left to the B3 control loop.
#[derive(Debug, Clone)]
pub struct BondedDonorSendReport {
    /// Stable transfer identifier from the bonded descriptor.
    pub transfer_id: String,
    /// Donor index used by the active assignment.
    pub donor_index: u32,
    /// Total donor count in the active assignment.
    pub donor_count: u32,
    /// Receiver UDP endpoints this donor connected to.
    pub receiver_endpoints: Vec<SocketAddr>,
    /// Descriptor entries considered for spray.
    pub entries: usize,
    /// Source blocks considered for spray.
    pub blocks: usize,
    /// Systematic/source symbols emitted.
    pub source_symbols_sent: u64,
    /// Repair/FEC symbols emitted.
    pub repair_symbols_sent: u64,
    /// Total UDP datagrams emitted by the donor.
    pub symbols_sent: u64,
    /// Pacing decision used for the donor's initial source-first spray.
    pub pacing: BondedDonorPacingReport,
    /// UDP send acceleration counters observed while spraying.
    pub udp_send_acceleration: UdpSendAccelerationReport,
}

/// Pacing evidence for a bonded donor's source-first spray.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BondedDonorPacingReport {
    /// Initial token-bucket rate before any clean-link round-0 ramp.
    pub initial_rate_bytes_per_sec: u64,
    /// Final token-bucket rate after the donor spray completed.
    pub final_rate_bytes_per_sec: u64,
    /// Maximum symbols allowed in one pacer burst.
    pub burst_symbols: u32,
    /// Maximum bytes allowed in one pacer burst.
    pub burst_bytes: u64,
    /// Estimated authenticated symbol datagram size.
    pub datagram_bytes: u32,
    /// Whether the clean-link additive round-0 ramp is enabled.
    pub clean_round0_ramp_enabled: bool,
}

#[derive(Debug, Clone, Copy)]
struct BondedDonorPacingDecision {
    pacing: RqSprayPacing,
    report: BondedDonorPacingReport,
}

fn bonded_donor_round0_pacing_decision(
    transfer_id: &str,
    config: &RqConfig,
    fanout: usize,
) -> BondedDonorPacingDecision {
    let mut state = RqAdaptiveSendState::new(transfer_tag(transfer_id), config, fanout);
    let pacing = state.round0_tuning(config).pacing;
    BondedDonorPacingDecision {
        pacing,
        report: BondedDonorPacingReport {
            initial_rate_bytes_per_sec: pacing.rate_bytes_per_sec(),
            final_rate_bytes_per_sec: pacing.rate_bytes_per_sec(),
            burst_symbols: pacing.max_burst_size,
            burst_bytes: pacing.burst_bytes(),
            datagram_bytes: pacing.datagram_bytes,
            clean_round0_ramp_enabled: round0_clean_ramp_enabled(config, pacing),
        },
    }
}

/// Donate this host's assigned slice of an agreed bonded RaptorQ fountain.
///
/// The descriptor is the receiver/donor agreement from Phase A. `source_root`
/// is this donor's local directory containing the descriptor's relative entry
/// paths; the descriptor proof rejects mismatched or escaping paths before any
/// symbol is sent. `receiver_endpoint` is the primary UDP endpoint selected by
/// the control plane, and any additional endpoints in `assignment` are used for
/// send fanout.
///
/// This B1 entrypoint performs the initial source-first spray only. It does not
/// read receiver feedback, honor `NeedMore`, or close the bonded control plane;
/// those belong to the B3 donor-control loop.
pub async fn donate_path(
    cx: &Cx,
    descriptor: &BondTransferDescriptor,
    assignment: &DonorAssignment,
    receiver_endpoint: SocketAddr,
    source_root: &Path,
    mut config: RqConfig,
) -> Result<BondedDonorSendReport, RqError> {
    cx.checkpoint().map_err(|_| RqError::Cancelled)?;
    assignment
        .validate()
        .map_err(|err| RqError::Coding(format!("invalid bonded donor assignment: {err}")))?;
    descriptor
        .prove_local_holding(source_root)
        .await
        .map_err(|err| RqError::Source(format!("bonded donor byte proof failed: {err}")))?;
    apply_bonded_descriptor_config(descriptor, &mut config)?;

    let symbol_auth = config.symbol_auth_context()?;
    if assignment.requires_symbol_auth() && symbol_auth.is_none() {
        return Err(RqError::Authentication(
            "bonded donor assignment requires symbol auth but RqConfig allowed unauthenticated symbols"
                .to_string(),
        ));
    }

    let repair_symbols_per_block = bonded_initial_repair_symbols_per_block(&config)?;
    let schedule = schedule_bonded_donor_spray(descriptor, assignment, repair_symbols_per_block)
        .map_err(|err| RqError::Coding(format!("bonded donor spray schedule failed: {err}")))?;
    let receiver_endpoints = bonded_receiver_endpoints(assignment, receiver_endpoint);
    let local_unspec = if receiver_endpoint.ip().is_ipv4() {
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
        bonded_donor_round0_pacing_decision(&descriptor.transfer_id, &config, sockets.len());
    let mut pacing_report = pacing_decision.report;
    let mut pacer = RqSprayPacer::new_round0(pacing_decision.pacing, &config, false);
    let mut send_batch = RqPendingSendBatch::new(sockets.len());
    let mut symbols_sent = 0u64;
    let mut source_symbols_sent = 0u64;
    let mut repair_symbols_sent = 0u64;
    let mut rr = 0usize;
    let mut dropper = 0u32;
    let mut udp_send_acceleration = UdpSendAccelerationReport::default();
    let tag = transfer_tag(&descriptor.transfer_id);
    let assignment_mode = if assignment.esi_windows.is_empty() {
        "static-residue"
    } else {
        "windowed"
    };
    bondtrace!(
        "donor: spray_start transfer_id={} donor_index={} donor_count={} assignment_mode={} esi_windows={:?} receiver_endpoints={} blocks={} repair_symbols_per_block={} pacing_rate_Bps={} burst_symbols={} burst_bytes={} clean_round0_ramp={}",
        descriptor.transfer_id,
        assignment.donor_index,
        assignment.donor_count,
        assignment_mode,
        assignment.esi_windows,
        receiver_endpoints.len(),
        schedule.blocks.len(),
        repair_symbols_per_block,
        pacing_report.initial_rate_bytes_per_sec,
        pacing_report.burst_symbols,
        pacing_report.burst_bytes,
        pacing_report.clean_round0_ramp_enabled,
    );

    for block in &schedule.blocks {
        cx.checkpoint().map_err(|_| RqError::Cancelled)?;
        let entry = descriptor
            .entry_by_index(block.geometry.entry_index)
            .ok_or_else(|| {
                RqError::Coding(format!(
                    "bonded donor schedule references unknown entry {}",
                    block.geometry.entry_index
                ))
            })?;
        let entry_path = bonded_donor_entry_path(source_root, &entry.rel_path)?;
        let block_start =
            usize::try_from(block.geometry.block_start).map_err(|_| RqError::TooLarge {
                size: block.geometry.block_start,
                max: u64::try_from(usize::MAX).unwrap_or(u64::MAX),
            })?;
        let block_len =
            usize::try_from(block.geometry.block_bytes).map_err(|_| RqError::TooLarge {
                size: block.geometry.block_bytes,
                max: u64::try_from(usize::MAX).unwrap_or(u64::MAX),
            })?;
        bondtrace!(
            "donor: block_start transfer_id={} donor_index={} entry={} sbn={} block_start={} block_bytes={} source_esis={} repair_esis={} stagger_delay_slots={} symbols_sent_so_far={} pacing_rate_Bps={}",
            descriptor.transfer_id,
            assignment.donor_index,
            block.geometry.entry_index,
            block.geometry.source_block_number,
            block.geometry.block_start,
            block.geometry.block_bytes,
            block.source_esis.len(),
            block.repair_esis.len(),
            block.stagger_delay_slots,
            symbols_sent,
            pacer.pacing().rate_bytes_per_sec(),
        );
        let block_bytes = read_source_range(&entry_path, block_start, block_len).await?;

        for emission in block.iter_symbol_emissions(schedule.donor_index) {
            let symbol = encode_bonded_donor_emission(emission, &block_bytes, &config)?;
            match emission.symbol_kind() {
                SymbolKind::Source => source_symbols_sent = source_symbols_sent.saturating_add(1),
                SymbolKind::Repair => repair_symbols_sent = repair_symbols_sent.saturating_add(1),
            }
            queue_bonded_donor_datagram(
                cx,
                &mut sockets,
                &mut rr,
                &mut symbols_sent,
                &mut dropper,
                tag,
                block.geometry.entry_index,
                &symbol,
                &config,
                &mut pacer,
                symbol_auth.as_ref(),
                &mut send_batch,
                &mut udp_send_acceleration,
            )
            .await?;
        }
        bondtrace!(
            "donor: block_done transfer_id={} donor_index={} entry={} sbn={} symbols_sent={} source_symbols_sent={} repair_symbols_sent={} pacing_rate_Bps={}",
            descriptor.transfer_id,
            assignment.donor_index,
            block.geometry.entry_index,
            block.geometry.source_block_number,
            symbols_sent,
            source_symbols_sent,
            repair_symbols_sent,
            pacer.pacing().rate_bytes_per_sec(),
        );
    }

    let report = send_batch.flush(&mut sockets, &mut symbols_sent).await?;
    udp_send_acceleration.observe_flush_report(report);
    pacing_report.final_rate_bytes_per_sec = pacer.pacing().rate_bytes_per_sec();
    bondtrace!(
        "donor: spray_done transfer_id={} donor_index={} donor_count={} symbols_sent={} source_symbols_sent={} repair_symbols_sent={} initial_pacing_rate_Bps={} final_pacing_rate_Bps={} udp_flushes={} native_batch_datagrams={} gso_datagrams={} fallback_datagrams={}",
        descriptor.transfer_id,
        assignment.donor_index,
        assignment.donor_count,
        symbols_sent,
        source_symbols_sent,
        repair_symbols_sent,
        pacing_report.initial_rate_bytes_per_sec,
        pacing_report.final_rate_bytes_per_sec,
        udp_send_acceleration.flushes,
        udp_send_acceleration.native_batch_datagrams,
        udp_send_acceleration.gso_datagrams,
        udp_send_acceleration.fallback_datagrams,
    );

    Ok(BondedDonorSendReport {
        transfer_id: descriptor.transfer_id.clone(),
        donor_index: assignment.donor_index,
        donor_count: assignment.donor_count,
        receiver_endpoints,
        entries: descriptor.entries.len(),
        blocks: schedule.blocks.len(),
        source_symbols_sent,
        repair_symbols_sent,
        symbols_sent,
        pacing: pacing_report,
        udp_send_acceleration,
    })
}

// ─── Frame transport over the TCP control stream ─────────────────────────────

struct FrameTransport<S> {
    stream: S,
    codec: AtpFrameCodec,
    rbuf: BytesMut,
    // A control frame that the spray-time drain (`service_rq_spray_control`) pulled but that is
    // NOT a KeepAlive — i.e. the receiver raced ahead and sent a terminal/feedback frame (Proof /
    // ObjectRequest) while the sender was still spraying. We stash it here instead of erroring so
    // the post-spray feedback loop's `recv()` returns it normally (fixes zz35zq: the fast-transfer
    // "unexpected frame: got Proof, expected KeepAlive while spraying" abort).
    stashed: Option<Frame>,
}

impl<S> FrameTransport<S>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    fn new(stream: S) -> Self {
        Self {
            stream,
            codec: AtpFrameCodec::new(),
            rbuf: BytesMut::new(),
            stashed: None,
        }
    }

    async fn send(&mut self, frame: &Frame) -> Result<(), RqError> {
        self.send_unflushed(frame).await?;
        self.flush().await
    }

    async fn send_unflushed(&mut self, frame: &Frame) -> Result<usize, RqError> {
        let bytes = frame
            .to_wire_bytes()
            .map_err(|e| RqError::Frame(e.to_string()))?;
        let len = bytes.len();
        self.stream.write_all(&bytes).await?;
        Ok(len)
    }

    async fn send_control_source_data_unflushed(
        &mut self,
        transfer_id: &str,
        entry: u32,
        offset: u64,
        data: &[u8],
        symbol_auth: Option<&SecurityContext>,
    ) -> Result<usize, RqError> {
        let bytes = control_source_data_wire_frame(transfer_id, entry, offset, data, symbol_auth)?;
        let len = bytes.len();
        self.stream.write_all(&bytes).await?;
        Ok(len)
    }

    async fn flush(&mut self) -> Result<(), RqError> {
        self.stream.flush().await?;
        Ok(())
    }

    async fn recv(&mut self) -> Result<Frame, RqError> {
        // A frame deferred by the spray-time drain takes precedence (see `stashed`).
        if let Some(frame) = self.stashed.take() {
            return Ok(frame);
        }
        loop {
            if let Some(frame) = self
                .codec
                .decode(&mut self.rbuf)
                .map_err(|e| RqError::Frame(e.to_string()))?
            {
                return Ok(frame);
            }
            let mut tmp = vec![0u8; 65536];
            let n = self.stream.read(&mut tmp).await?;
            if n == 0 {
                return Err(RqError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "peer closed control connection mid-transfer",
                )));
            }
            self.rbuf.extend_from_slice(&tmp[..n]);
        }
    }

    async fn try_recv_ready(&mut self) -> Result<Option<Frame>, RqError> {
        use std::future::poll_fn;
        use std::pin::Pin;
        use std::task::Poll;

        if self.stashed.is_some() {
            return Ok(None);
        }

        if let Some(frame) = self
            .codec
            .decode(&mut self.rbuf)
            .map_err(|e| RqError::Frame(e.to_string()))?
        {
            return Ok(Some(frame));
        }

        let mut tmp = [0u8; 4096];
        let ready = poll_fn(|task_cx| {
            let mut read_buf = ReadBuf::new(&mut tmp);
            match Pin::new(&mut self.stream).poll_read(task_cx, &mut read_buf) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(Some(read_buf.filled().len()))),
                Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
                Poll::Pending => Poll::Ready(Ok(None)),
            }
        })
        .await?;

        let Some(n) = ready else {
            return Ok(None);
        };
        if n == 0 {
            return Err(RqError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "peer closed control connection mid-transfer",
            )));
        }
        self.rbuf.extend_from_slice(&tmp[..n]);
        self.codec
            .decode(&mut self.rbuf)
            .map_err(|e| RqError::Frame(e.to_string()))
    }
}

async fn drain_sender_close_after_proof<S>(cx: &Cx, control: &mut FrameTransport<S>, phase: &str)
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    if cx.is_cancel_requested() {
        return;
    }

    for _ in 0..4 {
        let frame = match control.try_recv_ready().await {
            Ok(Some(frame)) => frame,
            Ok(None) => break,
            Err(err) => {
                rqtrace!("receiver: sender Close after Proof unavailable phase={phase}: {err}");
                return;
            }
        };
        match frame.frame_type() {
            FrameType::Close => {
                rqtrace!("receiver: drained sender Close after Proof phase={phase}");
                return;
            }
            FrameType::ObjectComplete | FrameType::KeepAlive => {
                rqtrace!(
                    "receiver: draining late {:?} after Proof phase={phase}",
                    frame.frame_type()
                );
            }
            other => {
                rqtrace!("receiver: ignoring post-Proof frame {other:?} phase={phase}");
                return;
            }
        }
    }

    rqtrace!("receiver: no ready sender Close after Proof phase={phase}");
}

fn tune_control_stream_for_bulk_source(stream: &TcpStream) {
    let _ = stream.set_nodelay(true);

    #[cfg(not(target_arch = "wasm32"))]
    if let Some(std_stream) = stream.try_as_std() {
        let sock = socket2::SockRef::from(std_stream);
        let _ = sock.set_send_buffer_size(RQ_CONTROL_STREAM_SOCKET_BUFFER_BYTES);
        let _ = sock.set_recv_buffer_size(RQ_CONTROL_STREAM_SOCKET_BUFFER_BYTES);
    }
}

// ─── Helpers (entry walk + merkle, shared definition with transport_tcp) ─────

fn json_frame<T: Serialize>(ty: FrameType, value: &T) -> Result<Frame, RqError> {
    let payload = serde_json::to_vec(value).map_err(|e| RqError::Control(e.to_string()))?;
    Frame::new(ProtocolVersion::CURRENT, ty, payload).map_err(|e| RqError::Frame(e.to_string()))
}

fn parse_json<T: for<'de> Deserialize<'de>>(frame: &Frame) -> Result<T, RqError> {
    serde_json::from_slice(frame.payload()).map_err(|e| RqError::Control(e.to_string()))
}

fn rq_delta_control_auth_context(config: &RqConfig) -> Option<&SecurityContext> {
    config
        .symbol_auth_context
        .as_ref()
        .filter(|context| context.mode() == AuthMode::Strict)
}

fn fresh_rq_delta_nonce(
    cx: &Cx,
    role: &'static [u8],
    avoid: Option<TransferNonce>,
) -> Result<TransferNonce, RqError> {
    for attempt in 0u32..4 {
        let mut entropy = [0u8; 32];
        cx.random_bytes(&mut entropy);
        let mut hasher = Sha256::new();
        hasher.update(b"ATP-RQ-DELTA-NONCE-V1\0");
        hasher.update(u64::try_from(role.len()).unwrap_or(u64::MAX).to_be_bytes());
        hasher.update(role);
        hasher.update(attempt.to_be_bytes());
        hasher.update(entropy);
        let nonce = TransferNonce::new(hasher.finalize().into());
        if !nonce.is_zero() && Some(nonce) != avoid {
            return Ok(nonce);
        }
    }
    Err(RqError::Control(
        "unable to derive a distinct non-zero RQ delta nonce".to_string(),
    ))
}

fn rq_delta_hash_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(bytes);
}

fn rq_delta_hello_auth_symbol(hello: &Hello) -> Result<Symbol, RqError> {
    let mut unsigned_hello = hello.clone();
    unsigned_hello.delta_client_auth_tag = None;
    let transcript = serde_json::to_vec(&unsigned_hello)
        .map_err(|error| RqError::Control(format!("serialize RQ delta initial offer: {error}")))?;
    let mut hasher = Sha256::new();
    hasher.update(b"ATP-RQ-DELTA-CLIENT-HELLO-V1\0");
    rq_delta_hash_len_prefixed(&mut hasher, &transcript);
    Ok(Symbol::new(
        SymbolId::new(
            ObjectId::new(0x4154_502d_5251_2d44, 0x454c_5441_2d48_454c),
            0,
            0,
        ),
        hasher.finalize().to_vec(),
        SymbolKind::Source,
    ))
}

fn sign_rq_delta_hello(context: &SecurityContext, hello: &Hello) -> Result<[u8; 32], RqError> {
    if context.mode() != AuthMode::Strict {
        return Err(RqError::Authentication(
            "RQ delta initial offer requires strict authentication".to_string(),
        ));
    }
    let control = context.derive_context(b"atp-rq-delta-client-hello-v1");
    Ok(*control
        .sign_symbol_tag(&rq_delta_hello_auth_symbol(hello)?)
        .as_bytes())
}

fn rq_delta_destination_root_commitment(
    context: &SecurityContext,
    receiver_nonce: TransferNonce,
    dest_dir: &Path,
    receiver_secret_salt: &[u8; 32],
) -> Result<[u8; 32], RqError> {
    if context.mode() != AuthMode::Strict {
        return Err(RqError::Authentication(
            "RQ delta destination binding requires strict authentication".to_string(),
        ));
    }
    let encoded_path = dest_dir.as_os_str().as_encoded_bytes();
    let mut hasher = Sha256::new();
    hasher.update(b"ATP-RQ-DELTA-DESTINATION-ROOT-V1\0");
    hasher.update(receiver_nonce.as_bytes());
    hasher.update(receiver_secret_salt);
    rq_delta_hash_len_prefixed(&mut hasher, encoded_path);
    let symbol = Symbol::new(
        SymbolId::new(
            ObjectId::new(0x4154_502d_5251_2d44, 0x454c_5441_2d44_5354),
            0,
            0,
        ),
        hasher.finalize().to_vec(),
        SymbolKind::Source,
    );
    let control = context.derive_context(b"atp-rq-delta-destination-root-v1");
    Ok(*control.sign_symbol_tag(&symbol).as_bytes())
}

fn new_rq_delta_destination_binding(
    cx: &Cx,
    context: &SecurityContext,
    receiver_nonce: TransferNonce,
    dest_dir: &Path,
) -> Result<RqDeltaDestinationBinding, RqError> {
    let mut receiver_secret_salt = [0u8; 32];
    cx.random_bytes(&mut receiver_secret_salt);
    let commitment = rq_delta_destination_root_commitment(
        context,
        receiver_nonce,
        dest_dir,
        &receiver_secret_salt,
    )?;
    Ok(RqDeltaDestinationBinding {
        receiver_secret_salt,
        commitment,
    })
}

fn validate_rq_delta_destination_binding(
    binding: &RqDeltaDestinationBinding,
    context: &SecurityContext,
    receiver_nonce: TransferNonce,
    dest_dir: &Path,
) -> Result<(), RqError> {
    let current = rq_delta_destination_root_commitment(
        context,
        receiver_nonce,
        dest_dir,
        &binding.receiver_secret_salt,
    )?;
    if current != binding.commitment {
        return Err(RqError::Authentication(
            "RQ delta destination binding changed during the session".to_string(),
        ));
    }
    Ok(())
}

fn rq_delta_ack_transcript_digest(hello: &Hello, ack: &HelloAck) -> Result<[u8; 32], RqError> {
    let mut unsigned_ack = ack.clone();
    unsigned_ack.delta_server_auth_tag = None;
    let transcript = serde_json::to_vec(&(hello, unsigned_ack)).map_err(|error| {
        RqError::Control(format!(
            "serialize RQ delta acknowledgement transcript: {error}"
        ))
    })?;
    let mut hasher = Sha256::new();
    hasher.update(b"ATP-RQ-DELTA-SERVER-ACK-V1\0");
    rq_delta_hash_len_prefixed(&mut hasher, &transcript);
    Ok(hasher.finalize().into())
}

fn rq_delta_ack_auth_symbol(hello: &Hello, ack: &HelloAck) -> Result<Symbol, RqError> {
    Ok(Symbol::new(
        SymbolId::new(
            ObjectId::new(0x4154_502d_5251_2d44, 0x454c_5441_2d41_434b),
            0,
            0,
        ),
        rq_delta_ack_transcript_digest(hello, ack)?.to_vec(),
        SymbolKind::Source,
    ))
}

fn sign_rq_delta_ack(
    context: &SecurityContext,
    hello: &Hello,
    ack: &HelloAck,
) -> Result<[u8; 32], RqError> {
    if context.mode() != AuthMode::Strict {
        return Err(RqError::Authentication(
            "RQ delta acknowledgement requires strict authentication".to_string(),
        ));
    }
    let control = context.derive_context(b"atp-rq-delta-server-ack-v1");
    Ok(*control
        .sign_symbol_tag(&rq_delta_ack_auth_symbol(hello, ack)?)
        .as_bytes())
}

fn verify_rq_delta_auth_tag(
    context: &SecurityContext,
    derivation: &'static [u8],
    symbol: Symbol,
    tag: [u8; 32],
    label: &'static str,
) -> Result<(), RqError> {
    if context.mode() != AuthMode::Strict {
        return Err(RqError::Authentication(format!(
            "{label} requires strict authentication"
        )));
    }
    let mut authenticated =
        AuthenticatedSymbol::from_parts(symbol, AuthenticationTag::from_bytes(tag));
    let control = context.derive_context(derivation);
    if control
        .verify_authenticated_symbol(&mut authenticated)
        .is_err()
        || !authenticated.is_verified()
    {
        return Err(RqError::Authentication(format!(
            "{label} authentication failed"
        )));
    }
    Ok(())
}

fn validate_rq_delta_hello(
    context: Option<&SecurityContext>,
    hello: &Hello,
) -> Result<Option<TransferNonce>, RqError> {
    match (hello.delta_transfer_nonce, hello.delta_client_auth_tag) {
        (None, None) => Ok(None),
        (Some(sender_nonce), Some(tag)) => {
            let context = context.ok_or_else(|| {
                RqError::Authentication(
                    "RQ delta offer requires a strict receiver authentication context".to_string(),
                )
            })?;
            if sender_nonce.is_zero() {
                return Err(RqError::Authentication(
                    "RQ delta offer used an all-zero sender nonce".to_string(),
                ));
            }
            verify_rq_delta_auth_tag(
                context,
                b"atp-rq-delta-client-hello-v1",
                rq_delta_hello_auth_symbol(hello)?,
                tag,
                "RQ delta initial offer",
            )?;
            Ok(Some(sender_nonce))
        }
        _ => Err(RqError::Authentication(
            "RQ delta initial offer has a partial authentication tuple".to_string(),
        )),
    }
}

fn validate_rq_delta_ack(
    context: &SecurityContext,
    hello: &Hello,
    ack: &HelloAck,
) -> Result<Option<RqDeltaHandshakeContext>, RqError> {
    let offered = hello.delta_transfer_nonce;
    let response = (
        ack.delta_transfer_nonce,
        ack.delta_receiver_nonce,
        ack.delta_destination_root,
        ack.delta_server_auth_tag,
    );
    let Some(expected) = offered else {
        return if response == (None, None, None, None) {
            Ok(None)
        } else {
            Err(RqError::HandshakeRejected(
                "receiver returned unsolicited RQ delta binding fields".to_string(),
            ))
        };
    };
    let (Some(echoed), receiver, destination_root, Some(tag)) = response else {
        return Err(RqError::Authentication(
            "receiver omitted its authenticated RQ delta response".to_string(),
        ));
    };
    verify_rq_delta_auth_tag(
        context,
        b"atp-rq-delta-server-ack-v1",
        rq_delta_ack_auth_symbol(hello, ack)?,
        tag,
        "RQ delta acknowledgement",
    )?;
    if echoed != expected {
        return Err(RqError::Authentication(
            "receiver echoed the wrong RQ delta transfer nonce".to_string(),
        ));
    }
    match (receiver, destination_root) {
        (None, None) => Ok(None),
        (Some(receiver_nonce), Some(destination_root)) => {
            if receiver_nonce.is_zero() || receiver_nonce == expected {
                return Err(RqError::Authentication(
                    "receiver RQ delta nonce must be distinct and non-zero".to_string(),
                ));
            }
            if destination_root.iter().all(|byte| *byte == 0) {
                return Err(RqError::Authentication(
                    "receiver RQ delta destination commitment is all zero".to_string(),
                ));
            }
            Ok(Some(RqDeltaHandshakeContext {
                sender_nonce: expected,
                receiver_nonce,
                destination_root,
                handshake_hash: rq_delta_ack_transcript_digest(hello, ack)?,
            }))
        }
        _ => Err(RqError::Authentication(
            "receiver returned a partial RQ delta binding tuple".to_string(),
        )),
    }
}

fn rq_decode_delta_root(value: &str, label: &str) -> Result<[u8; 32], RqError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(RqError::Control(format!(
            "{label} must be a canonical 64-character lowercase hex digest"
        )));
    }
    let mut decoded = [0u8; 32];
    hex::decode_to_slice(value, &mut decoded)
        .map_err(|error| RqError::Control(format!("decode {label}: {error}")))?;
    Ok(decoded)
}

fn derive_rq_delta_session(
    handshake: RqDeltaHandshakeContext,
    sender_peer_id: &str,
    receiver_peer_id: &str,
    manifest: &TransferManifest,
) -> Result<RqDeltaSessionContext, RqError> {
    let delta = manifest.delta_manifest.as_ref().ok_or_else(|| {
        RqError::Control("delta-bound RQ session requires a delta manifest".to_string())
    })?;
    let outer_root = rq_decode_delta_root(&manifest.merkle_root_hex, "manifest Merkle root")?;
    let delta_root = rq_decode_delta_root(&delta.merkle_root_hex, "delta manifest Merkle root")?;
    let metadata_root = manifest
        .metadata
        .as_ref()
        .ok_or_else(|| RqError::Control("RQ delta manifest requires metadata".to_string()))?
        .commitment_hex
        .as_str();

    let mut hasher = Sha256::new();
    hasher.update(b"ATP-RQ-DELTA-SESSION-V1\0");
    hasher.update(ATP_RQ_PROTOCOL.to_be_bytes());
    hasher.update(handshake.sender_nonce.as_bytes());
    hasher.update(handshake.receiver_nonce.as_bytes());
    hasher.update(handshake.destination_root);
    hasher.update(handshake.handshake_hash);
    rq_delta_hash_len_prefixed(&mut hasher, sender_peer_id.as_bytes());
    rq_delta_hash_len_prefixed(&mut hasher, receiver_peer_id.as_bytes());
    rq_delta_hash_len_prefixed(&mut hasher, manifest.transfer_id.as_bytes());
    rq_delta_hash_len_prefixed(&mut hasher, manifest.root_name.as_bytes());
    hasher.update([u8::from(manifest.is_directory)]);
    hasher.update(manifest.total_bytes.to_be_bytes());
    hasher.update(outer_root);
    hasher.update(delta_root);
    hasher.update(rq_decode_delta_root(
        metadata_root,
        "manifest metadata commitment",
    )?);
    let exact_manifest = serde_json::to_vec(manifest)
        .map_err(|error| RqError::Control(format!("serialize exact RQ delta manifest: {error}")))?;
    let mut manifest_hasher = Sha256::new();
    manifest_hasher.update(b"ATP-RQ-DELTA-EXACT-MANIFEST-V1\0");
    rq_delta_hash_len_prefixed(&mut manifest_hasher, &exact_manifest);
    hasher.update(manifest_hasher.finalize());
    Ok(RqDeltaSessionContext {
        session_id: hasher.finalize().into(),
        destination_root: handshake.destination_root,
    })
}

fn rq_delta_control_auth_symbol<T: Serialize>(
    domain: &'static [u8],
    session: RqDeltaSessionContext,
    transfer_id: &str,
    control_seq: u64,
    payload: &T,
) -> Result<Symbol, RqError> {
    let payload = serde_json::to_vec(payload)
        .map_err(|error| RqError::Control(format!("serialize RQ delta proof: {error}")))?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(session.session_id);
    hasher.update(session.destination_root);
    hasher.update(control_seq.to_be_bytes());
    rq_delta_hash_len_prefixed(&mut hasher, transfer_id.as_bytes());
    rq_delta_hash_len_prefixed(&mut hasher, &payload);
    Ok(Symbol::new(
        SymbolId::new(
            ObjectId::new(0x4154_502d_5251_2d44, 0x454c_5441_2d43_5452),
            0,
            u32::try_from(control_seq).unwrap_or(u32::MAX),
        ),
        hasher.finalize().to_vec(),
        SymbolKind::Source,
    ))
}

fn sign_rq_delta_control<T: Serialize>(
    context: &SecurityContext,
    derivation: &'static [u8],
    domain: &'static [u8],
    session: RqDeltaSessionContext,
    transfer_id: &str,
    control_seq: u64,
    payload: &T,
) -> Result<[u8; 32], RqError> {
    if context.mode() != AuthMode::Strict {
        return Err(RqError::Authentication(
            "RQ delta control requires strict authentication".to_string(),
        ));
    }
    let control = context.derive_context(derivation);
    Ok(*control
        .sign_symbol_tag(&rq_delta_control_auth_symbol(
            domain,
            session,
            transfer_id,
            control_seq,
            payload,
        )?)
        .as_bytes())
}

fn verify_rq_delta_control<T: Serialize>(
    context: &SecurityContext,
    derivation: &'static [u8],
    domain: &'static [u8],
    session: RqDeltaSessionContext,
    transfer_id: &str,
    control_seq: u64,
    payload: &T,
    tag: [u8; 32],
    label: &'static str,
) -> Result<(), RqError> {
    verify_rq_delta_auth_tag(
        context,
        derivation,
        rq_delta_control_auth_symbol(domain, session, transfer_id, control_seq, payload)?,
        tag,
        label,
    )
}

fn make_rq_delta_manifest_envelope(
    context: &SecurityContext,
    session: RqDeltaSessionContext,
    manifest: &TransferManifest,
) -> Result<RqDeltaManifestEnvelope, RqError> {
    let client_auth_tag = sign_rq_delta_control(
        context,
        b"atp-rq-delta-manifest-client-proof-v1",
        b"ATP-RQ-DELTA-MANIFEST-CLIENT-PROOF-V1\0",
        session,
        &manifest.transfer_id,
        0,
        manifest,
    )?;
    Ok(RqDeltaManifestEnvelope {
        session_id: session.session_id,
        destination_root: session.destination_root,
        control_seq: 0,
        manifest: manifest.clone(),
        client_auth_tag,
    })
}

fn validate_rq_delta_manifest_envelope(
    context: &SecurityContext,
    session: RqDeltaSessionContext,
    envelope: &RqDeltaManifestEnvelope,
) -> Result<(), RqError> {
    if envelope.control_seq != 0
        || envelope.session_id != session.session_id
        || envelope.destination_root != session.destination_root
    {
        return Err(RqError::HandshakeRejected(
            "RQ delta manifest client-proof binding mismatch".to_string(),
        ));
    }
    verify_rq_delta_control(
        context,
        b"atp-rq-delta-manifest-client-proof-v1",
        b"ATP-RQ-DELTA-MANIFEST-CLIENT-PROOF-V1\0",
        session,
        &envelope.manifest.transfer_id,
        envelope.control_seq,
        &envelope.manifest,
        envelope.client_auth_tag,
        "RQ delta manifest client proof",
    )
}

fn make_rq_delta_request_envelope(
    context: &SecurityContext,
    session: RqDeltaSessionContext,
    manifest: &TransferManifest,
    request: DeltaObjectRequest,
    udp_port: u16,
    udp_ports: Vec<u16>,
) -> Result<RqDeltaObjectRequestEnvelope, RqError> {
    let control_seq = 1;
    let server_auth_tag = sign_rq_delta_control(
        context,
        b"atp-rq-delta-object-request-server-proof-v1",
        b"ATP-RQ-DELTA-OBJECT-REQUEST-SERVER-PROOF-V1\0",
        session,
        &manifest.transfer_id,
        control_seq,
        &(&request, udp_port, &udp_ports),
    )?;
    Ok(RqDeltaObjectRequestEnvelope {
        session_id: session.session_id,
        transfer_id: manifest.transfer_id.clone(),
        destination_root: session.destination_root,
        control_seq,
        request,
        udp_port,
        udp_ports,
        server_auth_tag,
    })
}

fn validate_rq_delta_request_envelope(
    context: &SecurityContext,
    session: RqDeltaSessionContext,
    manifest: &TransferManifest,
    envelope: &RqDeltaObjectRequestEnvelope,
    control_source_stream: bool,
) -> Result<DeltaWireMode, RqError> {
    if envelope.control_seq != 1
        || envelope.session_id != session.session_id
        || envelope.transfer_id != manifest.transfer_id
        || envelope.destination_root != session.destination_root
    {
        return Err(RqError::Control(
            "RQ delta ObjectRequest binding mismatch".to_string(),
        ));
    }
    verify_rq_delta_control(
        context,
        b"atp-rq-delta-object-request-server-proof-v1",
        b"ATP-RQ-DELTA-OBJECT-REQUEST-SERVER-PROOF-V1\0",
        session,
        &manifest.transfer_id,
        envelope.control_seq,
        &(&envelope.request, envelope.udp_port, &envelope.udp_ports),
        envelope.server_auth_tag,
        "RQ delta ObjectRequest",
    )?;
    let delta = manifest.delta_manifest.as_ref().ok_or_else(|| {
        RqError::Control("bound RQ delta request without a delta manifest".to_string())
    })?;
    let request = &envelope.request;
    if request.sender_merkle_root_hex != delta.merkle_root_hex {
        return Err(RqError::Control(
            "RQ delta ObjectRequest sender root mismatch".to_string(),
        ));
    }
    match request.mode {
        DeltaWireMode::FullObject => {
            let canonical_udp_ports = envelope.udp_port != 0
                && !envelope.udp_ports.is_empty()
                && envelope.udp_ports.first() == Some(&envelope.udp_port)
                && envelope.udp_ports.len() <= RQ_DELTA_MAX_ADVERTISED_UDP_PORTS
                && envelope.udp_ports.iter().all(|port| *port != 0)
                && envelope
                    .udp_ports
                    .iter()
                    .copied()
                    .collect::<BTreeSet<_>>()
                    .len()
                    == envelope.udp_ports.len();
            if request.fallback_reason.as_deref() != Some("full_object_required")
                || request.receiver_merkle_root_hex.is_some()
                || request.missing_bytes != 0
                || request.shared_chunks != 0
                || request.stale_chunks != 0
                || !request.missing_chunks.is_empty()
                || (control_source_stream
                    && (envelope.udp_port != 0 || !envelope.udp_ports.is_empty()))
                || (!control_source_stream && !canonical_udp_ports)
            {
                return Err(RqError::Control(
                    "malformed RQ full-object delta request".to_string(),
                ));
            }
        }
        DeltaWireMode::AlreadyInSync => {
            let expected_shared = u64::try_from(delta.chunks.len()).unwrap_or(u64::MAX);
            if request.fallback_reason.is_some()
                || request.receiver_merkle_root_hex.as_deref()
                    != Some(delta.merkle_root_hex.as_str())
                || request.missing_bytes != 0
                || !request.missing_chunks.is_empty()
                || request.stale_chunks != 0
                || request.shared_chunks != expected_shared
                || envelope.udp_port != 0
                || !envelope.udp_ports.is_empty()
            {
                return Err(RqError::Control(
                    "malformed RQ AlreadyInSync delta request".to_string(),
                ));
            }
        }
        DeltaWireMode::DeltaChunks => {
            return Err(RqError::Control(
                "RQ missing-chunk delta requests are not enabled in this rollout".to_string(),
            ));
        }
    }
    Ok(request.mode)
}

fn make_rq_delta_complete(
    context: &SecurityContext,
    session: RqDeltaSessionContext,
    manifest: &TransferManifest,
) -> Result<RqDeltaCompleteEnvelope, RqError> {
    let control_seq = 2;
    let bytes_sent = 0u64;
    let client_auth_tag = sign_rq_delta_control(
        context,
        b"atp-rq-delta-complete-client-proof-v1",
        b"ATP-RQ-DELTA-COMPLETE-CLIENT-PROOF-V1\0",
        session,
        &manifest.transfer_id,
        control_seq,
        &bytes_sent,
    )?;
    Ok(RqDeltaCompleteEnvelope {
        session_id: session.session_id,
        transfer_id: manifest.transfer_id.clone(),
        destination_root: session.destination_root,
        control_seq,
        bytes_sent,
        client_auth_tag,
    })
}

fn validate_rq_delta_complete(
    context: &SecurityContext,
    session: RqDeltaSessionContext,
    manifest: &TransferManifest,
    complete: &RqDeltaCompleteEnvelope,
) -> Result<(), RqError> {
    if complete.control_seq != 2
        || complete.session_id != session.session_id
        || complete.transfer_id != manifest.transfer_id
        || complete.destination_root != session.destination_root
        || complete.bytes_sent != 0
    {
        return Err(RqError::Control(
            "RQ delta ObjectComplete binding mismatch".to_string(),
        ));
    }
    verify_rq_delta_control(
        context,
        b"atp-rq-delta-complete-client-proof-v1",
        b"ATP-RQ-DELTA-COMPLETE-CLIENT-PROOF-V1\0",
        session,
        &manifest.transfer_id,
        complete.control_seq,
        &complete.bytes_sent,
        complete.client_auth_tag,
        "RQ delta ObjectComplete",
    )
}

fn make_rq_delta_proof(
    context: &SecurityContext,
    session: RqDeltaSessionContext,
    manifest: &TransferManifest,
    receipt: ReceiveReceipt,
) -> Result<RqDeltaProofEnvelope, RqError> {
    let control_seq = 3;
    let server_auth_tag = sign_rq_delta_control(
        context,
        b"atp-rq-delta-proof-server-proof-v1",
        b"ATP-RQ-DELTA-PROOF-SERVER-PROOF-V1\0",
        session,
        &manifest.transfer_id,
        control_seq,
        &receipt,
    )?;
    Ok(RqDeltaProofEnvelope {
        session_id: session.session_id,
        transfer_id: manifest.transfer_id.clone(),
        destination_root: session.destination_root,
        control_seq,
        receipt,
        server_auth_tag,
    })
}

fn validate_rq_delta_proof(
    context: &SecurityContext,
    session: RqDeltaSessionContext,
    manifest: &TransferManifest,
    proof: RqDeltaProofEnvelope,
) -> Result<ReceiveReceipt, RqError> {
    if proof.control_seq != 3
        || proof.session_id != session.session_id
        || proof.transfer_id != manifest.transfer_id
        || proof.destination_root != session.destination_root
    {
        return Err(RqError::Control(
            "RQ delta Proof binding mismatch".to_string(),
        ));
    }
    verify_rq_delta_control(
        context,
        b"atp-rq-delta-proof-server-proof-v1",
        b"ATP-RQ-DELTA-PROOF-SERVER-PROOF-V1\0",
        session,
        &manifest.transfer_id,
        proof.control_seq,
        &proof.receipt,
        proof.server_auth_tag,
        "RQ delta Proof",
    )?;
    if !proof.receipt.committed
        || !proof.receipt.sha_ok
        || !proof.receipt.merkle_ok
        || proof.receipt.bytes_received != 0
        || proof.receipt.files != 1
        || proof.receipt.symbols_accepted != 0
        || proof.receipt.feedback_rounds != 0
        || proof.receipt.reason.is_some()
        || !proof.receipt.committed_paths.is_empty()
    {
        return Err(RqError::Integrity(
            proof
                .receipt
                .reason
                .clone()
                .unwrap_or_else(|| "receiver did not commit the RQ delta no-op".to_string()),
        ));
    }
    Ok(proof.receipt)
}

async fn send_delta_control_frame<S>(
    cx: &Cx,
    control: &mut FrameTransport<S>,
    frame: &Frame,
    timeout: Duration,
    phase: &'static str,
) -> Result<(), RqError>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    match crate::time::timeout(cx.now(), timeout, control.send(frame)).await {
        Ok(result) => result,
        Err(_) => Err(RqError::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!("delta control timed out during {phase} after {timeout:?}"),
        ))),
    }
}

async fn recv_delta_control_frame<S>(
    cx: &Cx,
    control: &mut FrameTransport<S>,
    timeout: Duration,
    phase: &'static str,
) -> Result<Frame, RqError>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    match crate::time::timeout(cx.now(), timeout, control.recv()).await {
        Ok(result) => result,
        Err(_) => Err(RqError::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!("delta control timed out during {phase} after {timeout:?}"),
        ))),
    }
}

/// Receive the sender-side handshake acknowledgement and preserve its protocol
/// stage in the error type. Auto selection may fall back after this function,
/// but never after the manifest or payload phase begins.
async fn receive_sender_handshake_ack<S>(
    cx: &Cx,
    control: &mut FrameTransport<S>,
    timeout: Duration,
) -> Result<HelloAck, RqError>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let frame = match crate::time::timeout(cx.now(), timeout, control.recv()).await {
        Ok(result) => result.map_err(|err| {
            RqError::HandshakeRejected(format!("invalid handshake response: {err}"))
        })?,
        Err(_elapsed) => {
            return Err(RqError::HandshakeRejected(format!(
                "handshake unavailable: receive sender acknowledgement timed out after {timeout:?}"
            )));
        }
    };
    if frame.frame_type() != FrameType::HandshakeAck {
        return Err(RqError::HandshakeRejected(format!(
            "unexpected {:?} frame while awaiting HandshakeAck",
            frame.frame_type()
        )));
    }
    let ack: HelloAck = parse_json(&frame).map_err(|err| {
        RqError::HandshakeRejected(format!("invalid handshake acknowledgement: {err}"))
    })?;
    if !ack.accepted {
        return Err(RqError::HandshakeRejected(
            ack.reason.unwrap_or_else(|| "no reason given".to_string()),
        ));
    }
    Ok(ack)
}

fn sender_handshake_transport_error(stage: &str, error: RqError) -> RqError {
    match error {
        error @ RqError::Io(_) => {
            RqError::HandshakeRejected(format!("handshake unavailable during {stage}: {error}"))
        }
        error => error,
    }
}

fn control_source_data_chunk_bytes(auth_enabled: bool) -> usize {
    if auth_enabled {
        RQ_CONTROL_SOURCE_AUTH_CHUNK_BYTES
    } else {
        RQ_CONTROL_SOURCE_CHUNK_BYTES
    }
}

fn control_source_data_auth_tag_bytes(auth_enabled: bool) -> usize {
    if auth_enabled { TAG_SIZE } else { 0 }
}

fn control_source_data_auth_symbol(
    transfer_id: &str,
    entry: u32,
    offset: u64,
    data: &[u8],
) -> Symbol {
    let entry_id = entry_object_id(transfer_id, entry);
    let object_id = ObjectId::new(
        entry_id.high() ^ 0xC057_DA7A_AA71_0001,
        entry_id.low() ^ 0xA771_C057_5EED_0001,
    );
    let mut payload =
        Vec::with_capacity(RQ_CONTROL_SOURCE_AUTH_SYMBOL_DOMAIN.len() + 8 + data.len());
    payload.extend_from_slice(RQ_CONTROL_SOURCE_AUTH_SYMBOL_DOMAIN);
    payload.extend_from_slice(&offset.to_be_bytes());
    payload.extend_from_slice(data);
    Symbol::new(SymbolId::new(object_id, 0, 0), payload, SymbolKind::Source)
}

fn sign_control_source_data_tag(
    context: &SecurityContext,
    transfer_id: &str,
    entry: u32,
    offset: u64,
    data: &[u8],
) -> AuthenticationTag {
    let symbol = control_source_data_auth_symbol(transfer_id, entry, offset, data);
    context.sign_symbol_tag(&symbol)
}

fn verify_control_source_data_tag(
    context: &SecurityContext,
    transfer_id: &str,
    entry: u32,
    offset: u64,
    data: &[u8],
    tag: AuthenticationTag,
) -> Result<(), RqError> {
    let symbol = control_source_data_auth_symbol(transfer_id, entry, offset, data);
    let mut auth = AuthenticatedSymbol::from_parts(symbol, tag);
    if context.verify_authenticated_symbol(&mut auth).is_ok() && auth.is_verified() {
        Ok(())
    } else {
        Err(RqError::Authentication(format!(
            "control source ObjectData authentication failed for entry {entry} offset {offset}"
        )))
    }
}

fn control_source_data_payload(
    transfer_id: &str,
    entry: u32,
    offset: u64,
    data: &[u8],
    symbol_auth: Option<&SecurityContext>,
) -> Vec<u8> {
    let auth_len = control_source_data_auth_tag_bytes(symbol_auth.is_some());
    let mut payload = Vec::with_capacity(RQ_CONTROL_SOURCE_DATA_HEADER + auth_len + data.len());
    payload.extend_from_slice(&entry.to_be_bytes());
    payload.extend_from_slice(&offset.to_be_bytes());
    if let Some(context) = symbol_auth {
        let tag = sign_control_source_data_tag(context, transfer_id, entry, offset, data);
        payload.extend_from_slice(tag.as_bytes());
    }
    payload.extend_from_slice(data);
    payload
}

#[cfg(test)]
fn control_source_data_frame(entry: u32, offset: u64, data: &[u8]) -> Result<Frame, RqError> {
    control_source_data_frame_with_auth("control-source-test", entry, offset, data, None)
}

#[cfg(test)]
fn control_source_data_frame_with_auth(
    transfer_id: &str,
    entry: u32,
    offset: u64,
    data: &[u8],
    symbol_auth: Option<&SecurityContext>,
) -> Result<Frame, RqError> {
    let payload = control_source_data_payload(transfer_id, entry, offset, data, symbol_auth);
    Frame::new(ProtocolVersion::CURRENT, FrameType::ObjectData, payload)
        .map_err(|e| RqError::Frame(e.to_string()))
}

fn control_source_data_wire_frame(
    transfer_id: &str,
    entry: u32,
    offset: u64,
    data: &[u8],
    symbol_auth: Option<&SecurityContext>,
) -> Result<BytesMut, RqError> {
    let auth_len = control_source_data_auth_tag_bytes(symbol_auth.is_some());
    let payload_len = RQ_CONTROL_SOURCE_DATA_HEADER
        .checked_add(auth_len)
        .and_then(|len| len.checked_add(data.len()))
        .ok_or_else(|| {
            RqError::Frame("control source ObjectData payload length overflow".into())
        })?;
    let max_payload_len = RQ_CONTROL_SOURCE_DATA_HEADER
        .checked_add(auth_len)
        .and_then(|len| len.checked_add(control_source_data_chunk_bytes(symbol_auth.is_some())))
        .ok_or_else(|| {
            RqError::Frame("control source ObjectData payload length overflow".into())
        })?;
    if payload_len > max_payload_len {
        return Err(RqError::Frame(format!(
            "control source ObjectData payload too large: {payload_len} bytes (max {max_payload_len})"
        )));
    }
    let payload_len_u64 = u64::try_from(payload_len)
        .map_err(|_| RqError::Frame("control source ObjectData payload too large".into()))?;
    let header_len = control_frame_header_len(
        ProtocolVersion::CURRENT,
        FrameType::ObjectData,
        payload_len_u64,
    )?;
    let total_len = header_len
        .checked_add(payload_len)
        .ok_or_else(|| RqError::Frame("control source ObjectData frame length overflow".into()))?;
    let max_frame_size = usize::try_from(MAX_FRAME_SIZE).unwrap_or(usize::MAX);
    if total_len > max_frame_size {
        return Err(RqError::Frame(format!(
            "control source ObjectData frame too large: {total_len} bytes (max {max_frame_size})"
        )));
    }

    let mut wire = BytesMut::with_capacity(total_len);
    encode_control_frame_varint(&mut wire, u64::from(ProtocolVersion::CURRENT.0))?;
    encode_control_frame_varint(&mut wire, FrameType::ObjectData as u64)?;
    encode_control_frame_varint(&mut wire, payload_len_u64)?;
    encode_control_frame_varint(&mut wire, 0)?;
    wire.extend_from_slice(&control_source_data_payload(
        transfer_id,
        entry,
        offset,
        data,
        symbol_auth,
    ));
    debug_assert_eq!(wire.len(), total_len);
    Ok(wire)
}

fn control_frame_header_len(
    version: ProtocolVersion,
    frame_type: FrameType,
    payload_len: u64,
) -> Result<usize, RqError> {
    let version_len = control_frame_varint(u64::from(version.0))?.encoded_len();
    let type_len = frame_type.to_varint().encoded_len();
    let payload_len_len = control_frame_varint(payload_len)?.encoded_len();

    version_len
        .checked_add(type_len)
        .and_then(|len| len.checked_add(payload_len_len))
        .and_then(|len| len.checked_add(1))
        .ok_or_else(|| RqError::Frame("control frame header length overflow".into()))
}

fn control_frame_varint(value: u64) -> Result<VarInt, RqError> {
    VarInt::try_from(value).map_err(|err| RqError::Frame(err.to_string()))
}

fn encode_control_frame_varint(dst: &mut BytesMut, value: u64) -> Result<(), RqError> {
    control_frame_varint(value)?
        .encode(dst)
        .into_result()
        .map_err(|err| RqError::Frame(err.to_string()))
}

struct ControlSourceData<'a> {
    entry: u32,
    offset: u64,
    data: &'a [u8],
}

fn parse_control_source_data_frame<'a>(
    frame: &'a Frame,
    transfer_id: &str,
    symbol_auth: Option<&SecurityContext>,
) -> Result<ControlSourceData<'a>, RqError> {
    let payload = frame.payload();
    if payload.len() < RQ_CONTROL_SOURCE_DATA_HEADER {
        return Err(RqError::Frame(format!(
            "ObjectData frame shorter than {RQ_CONTROL_SOURCE_DATA_HEADER}-byte source header"
        )));
    }
    let entry = u32::from_be_bytes(payload[0..4].try_into().expect("entry header width"));
    let offset = u64::from_be_bytes(payload[4..12].try_into().expect("offset header width"));
    let data = if let Some(context) = symbol_auth {
        if payload.len() < RQ_CONTROL_SOURCE_AUTH_DATA_HEADER {
            return Err(RqError::Authentication(format!(
                "authenticated ObjectData frame shorter than {RQ_CONTROL_SOURCE_AUTH_DATA_HEADER}-byte source auth header"
            )));
        }
        let mut tag_bytes = [0u8; TAG_SIZE];
        tag_bytes.copy_from_slice(
            &payload[RQ_CONTROL_SOURCE_DATA_HEADER..RQ_CONTROL_SOURCE_AUTH_DATA_HEADER],
        );
        let data = &payload[RQ_CONTROL_SOURCE_AUTH_DATA_HEADER..];
        verify_control_source_data_tag(
            context,
            transfer_id,
            entry,
            offset,
            data,
            AuthenticationTag::from_bytes(tag_bytes),
        )?;
        data
    } else {
        &payload[RQ_CONTROL_SOURCE_DATA_HEADER..]
    };
    Ok(ControlSourceData {
        entry,
        offset,
        data,
    })
}

fn parse_round_complete(frame: &Frame) -> Result<RqRoundComplete, RqError> {
    if frame.payload().is_empty() {
        Ok(RqRoundComplete::default())
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

fn parse_and_validate_manifest_frame(
    frame: &Frame,
    config: &RqConfig,
) -> Result<TransferManifest, RqError> {
    let manifest: TransferManifest = parse_json(frame)?;
    validate_manifest(&manifest, config)?;
    Ok(manifest)
}

/// Derive the per-entry RaptorQ [`ObjectId`] deterministically from the transfer
/// id and entry index, so sender and receiver agree without extra signaling.
fn entry_object_id(transfer_id: &str, index: u32) -> ObjectId {
    let mut hasher = Sha256::new();
    hasher.update(b"asupersync.atp.rq.entry-object-id.v1\0");
    hasher.update(transfer_id.as_bytes());
    hasher.update(index.to_be_bytes());
    let d = hasher.finalize();
    let high = u64::from_be_bytes([d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]]);
    let low = u64::from_be_bytes([d[8], d[9], d[10], d[11], d[12], d[13], d[14], d[15]]);
    ObjectId::new(high, low)
}

/// First 8 bytes of the transfer id hex, as a datagram-tag `u64` (cheap stray
/// packet filter — not a security boundary).
fn transfer_tag(transfer_id: &str) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(b"asupersync.atp.rq.tag.v1\0");
    hasher.update(transfer_id.as_bytes());
    let d = hasher.finalize();
    u64::from_be_bytes([d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]])
}

/// Hash-pass buffer size for sender manifest construction. This bounds the
/// manifest pass independently of transfer size.
const RQ_STREAM_HASH_BUFFER_SIZE: usize = 1024 * 1024;

#[derive(Debug, Clone)]
struct RqSourceEntry {
    rel_path: String,
    abs_path: PathBuf,
    /// Metadata for the final logical file. Packed synthetic objects carry bare
    /// metadata because their members remain the committed logical files.
    metadata: EntryMetadata,
    /// Byte offset in `abs_path` where this encoded object starts.
    source_offset: u64,
    /// Byte length of this encoded object. `None` means the whole file at
    /// `abs_path`, preserving the historical no-split path.
    source_len: Option<u64>,
    /// Logical files packed into this combined RaptorQ object (E-15 coalescing).
    /// Empty = a normal single-file entry whose content IS the file at `abs_path`
    /// (prior behavior, byte-identical wire). Non-empty = `abs_path` points at a
    /// temp file holding the concatenation of these members in `offset` order, and
    /// the receiver splits it back into the member files on commit.
    members: Vec<PackedMember>,
    /// Large-file multi-object metadata for this encoded object.
    fragment: Option<LargeObjectFragment>,
}

fn rq_delta_manifest_entry(manifest: &TransferManifest) -> Option<&ManifestEntry> {
    let [entry] = manifest.entries.as_slice() else {
        return None;
    };
    (!manifest.is_directory && entry.members.is_empty() && entry.fragment.is_none())
        .then_some(entry)
}

fn rq_manifest_entry_metadata(manifest: &TransferManifest, rel_path: &str) -> EntryMetadata {
    manifest
        .metadata
        .as_ref()
        .and_then(|metadata| {
            metadata
                .entries
                .iter()
                .find(|entry| entry.rel_path == rel_path)
        })
        .map_or_else(EntryMetadata::default, |entry| entry.metadata.clone())
}

async fn read_rq_entry_metadata(
    path: &Path,
    policy: &MetadataPolicy,
) -> Result<EntryMetadata, RqError> {
    let path = path.to_path_buf();
    let policy = policy.clone();
    crate::runtime::spawn_blocking(move || read_entry_metadata_sync(&path, &policy))
        .await
        .map_err(|error| RqError::Source(error.into_message()))
}

async fn build_rq_delta_manifest_for_file(
    cx: &Cx,
    tree_id: &str,
    path: &Path,
    entry_index: u32,
    rel_path: &str,
    expected_size: u64,
    expected_sha256_hex: &str,
    chunk_size: usize,
) -> Result<DeltaManifestWire, RqError> {
    const OBJECT_DATA_HEADER_BYTES: usize = 12;
    let max_chunk_size = usize::try_from(MAX_FRAME_SIZE)
        .unwrap_or(usize::MAX)
        .saturating_sub(OBJECT_DATA_HEADER_BYTES);
    let chunk_size = chunk_size.max(1).min(max_chunk_size);
    let mut file = crate::fs::File::open(path)
        .await
        .map_err(|error| RqError::Source(format!("{}: {error}", path.display())))?;
    let mut buf = vec![0u8; chunk_size];
    let mut chunks = Vec::new();
    let mut planner_chunks = Vec::new();
    let mut offset = 0u64;
    let mut index = 0u32;
    let mut sha256 = Sha256::new();
    let mut whole_content_id = ContentId::streaming();
    loop {
        cx.checkpoint().map_err(|_| RqError::Cancelled)?;
        let read = file
            .read(&mut buf)
            .await
            .map_err(|error| RqError::Source(format!("{}: {error}", path.display())))?;
        if read == 0 {
            break;
        }
        let bytes = &buf[..read];
        sha256.update(bytes);
        whole_content_id.update(bytes);
        let size_bytes = u64::try_from(read)
            .map_err(|_| RqError::Control("RQ delta chunk size overflow".to_string()))?;
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
            .ok_or_else(|| RqError::Control("RQ delta chunk index overflow".to_string()))?;
        offset = offset
            .checked_add(size_bytes)
            .ok_or_else(|| RqError::Control("RQ delta chunk offset overflow".to_string()))?;
    }
    if offset != expected_size {
        return Err(RqError::Source(format!(
            "{} changed while building RQ delta manifest (read {offset} bytes, expected {expected_size})",
            path.display()
        )));
    }
    let content_sha256: [u8; 32] = sha256.finalize().into();
    if hex_encode(&content_sha256) != expected_sha256_hex
        || flat_merkle_root_from_digests(&[EntryDigest {
            rel_path: rel_path.to_string(),
            size: offset,
            content_id: crate::atp::object::ObjectId::content(whole_content_id.finalize()),
            content_sha256,
        }]) != tree_id
    {
        return Err(RqError::Source(format!(
            "{} changed while building its RQ delta manifest",
            path.display()
        )));
    }
    let planner = PersistentChunkManifest::new(tree_id.to_string(), planner_chunks)
        .map_err(|error| RqError::Control(format!("build RQ delta manifest: {error}")))?;
    Ok(DeltaManifestWire {
        schema: ATP_DELTA_CHUNK_MANIFEST_SCHEMA.to_string(),
        tree_id: tree_id.to_string(),
        chunk_size,
        total_size_bytes: planner.total_size_bytes,
        merkle_root_hex: planner.merkle_root.to_hex(),
        chunks,
    })
}

async fn maybe_attach_rq_delta_manifest(
    cx: &Cx,
    manifest: &mut TransferManifest,
    entries: &[RqSourceEntry],
    config: &RqConfig,
) -> Result<(), RqError> {
    let Some(manifest_entry) = rq_delta_manifest_entry(manifest) else {
        return Ok(());
    };
    let [source_entry] = entries else {
        return Ok(());
    };
    let metadata = rq_manifest_entry_metadata(manifest, &manifest_entry.rel_path);
    if !config.enable_delta
        || rq_delta_control_auth_context(config).is_none()
        || source_entry.source_offset != 0
        || source_entry.source_len.is_some()
        || source_entry.rel_path != manifest_entry.rel_path
        || !matches!(
            metadata.file_kind,
            crate::net::atp::transport_common::FileKind::Regular
        )
        || metadata.hardlink_target.is_some()
        || metadata.symlink_target.is_some()
        || metadata.symlink_target_info.is_some()
    {
        return Ok(());
    }
    let chunk_size_u64 = u64::try_from(RQ_DELTA_CHUNK_SIZE).unwrap_or(u64::MAX);
    if manifest_entry.size.div_ceil(chunk_size_u64) > RQ_DELTA_MAX_MANIFEST_CHUNKS {
        return Ok(());
    }
    let delta = build_rq_delta_manifest_for_file(
        cx,
        &manifest.merkle_root_hex,
        &source_entry.abs_path,
        manifest_entry.index,
        &manifest_entry.rel_path,
        manifest_entry.size,
        &manifest_entry.sha256_hex,
        RQ_DELTA_CHUNK_SIZE,
    )
    .await?;
    manifest.delta_manifest = Some(delta);
    match json_frame(FrameType::ObjectManifest, manifest) {
        Ok(frame)
            if frame.payload().len()
                <= usize::try_from(MAX_FRAME_SIZE)
                    .unwrap_or(usize::MAX)
                    .saturating_sub(RQ_DELTA_ENVELOPE_WIRE_BUDGET) => {}
        Ok(_) | Err(RqError::Frame(_)) => {
            manifest.delta_manifest = None;
            cx.trace_with_fields(
                "atp_rq.delta_manifest_fallback",
                &[
                    ("reason", "authenticated_envelope_budget"),
                    ("mode", "full_object"),
                ],
            );
        }
        Err(error) => return Err(error),
    }
    Ok(())
}

async fn validate_rq_delta_source_unchanged(
    cx: &Cx,
    manifest: &TransferManifest,
    entries: &[RqSourceEntry],
    config: &RqConfig,
) -> Result<(), RqError> {
    let delta = manifest.delta_manifest.as_ref().ok_or_else(|| {
        RqError::Control("cannot revalidate an RQ source without a delta manifest".to_string())
    })?;
    let entry = rq_delta_manifest_entry(manifest).ok_or_else(|| {
        RqError::Control("RQ delta source no longer has a supported transfer shape".to_string())
    })?;
    let [source] = entries else {
        return Err(RqError::Control(
            "RQ delta source must contain exactly one entry".to_string(),
        ));
    };
    let expected_metadata = rq_manifest_entry_metadata(manifest, &entry.rel_path);
    if read_rq_entry_metadata(&source.abs_path, &config.metadata_policy).await? != expected_metadata
    {
        return Err(RqError::Source(
            "RQ source metadata changed before delta no-op completion".to_string(),
        ));
    }
    let current = build_rq_delta_manifest_for_file(
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
        || read_rq_entry_metadata(&source.abs_path, &config.metadata_policy).await?
            != expected_metadata
    {
        return Err(RqError::Integrity(
            "RQ source changed before delta no-op completion".to_string(),
        ));
    }
    Ok(())
}

async fn build_rq_receiver_delta_request(
    cx: &Cx,
    dest_dir: &Path,
    config: &RqConfig,
    manifest: &TransferManifest,
) -> Result<DeltaObjectRequest, RqError> {
    cx.checkpoint().map_err(|_| RqError::Cancelled)?;
    let delta = manifest.delta_manifest.as_ref().ok_or_else(|| {
        RqError::Control("cannot build an RQ delta request without a delta manifest".to_string())
    })?;
    let entry = rq_delta_manifest_entry(manifest).ok_or_else(|| {
        RqError::Control("cannot build an RQ delta request for this transfer shape".to_string())
    })?;
    let full =
        || DeltaObjectRequest::full(delta.merkle_root_hex.clone(), None, "full_object_required");

    reject_existing_symlink(dest_dir).await?;
    let path = safe_base_for_root_name(dest_dir, &manifest.root_name)?;
    reject_destination_symlink_prefix(&path, &path).await?;
    let existing = match crate::fs::metadata(&path).await {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(full());
        }
        Err(error) => return Err(error.into()),
    };
    if !existing.is_file() || existing.len() != entry.size {
        return Ok(full());
    }
    let expected_metadata = rq_manifest_entry_metadata(manifest, &entry.rel_path);
    let receiver_metadata = match read_rq_entry_metadata(&path, &config.metadata_policy).await {
        Ok(metadata) => metadata,
        Err(RqError::Source(_)) => return Ok(full()),
        Err(error) => return Err(error),
    };
    if receiver_metadata != expected_metadata {
        return Ok(full());
    }

    let receiver_delta = match build_rq_delta_manifest_for_file(
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
        Err(RqError::Source(_)) => {
            return Ok(full());
        }
        Err(error) => return Err(error),
    };
    reject_destination_symlink_prefix(&path, &path).await?;
    if read_rq_entry_metadata(&path, &config.metadata_policy).await? != expected_metadata {
        return Ok(full());
    }
    if receiver_delta != *delta {
        return Ok(full());
    }

    Ok(DeltaObjectRequest {
        mode: DeltaWireMode::AlreadyInSync,
        fallback_reason: None,
        sender_merkle_root_hex: delta.merkle_root_hex.clone(),
        receiver_merkle_root_hex: Some(delta.merkle_root_hex.clone()),
        missing_bytes: 0,
        shared_chunks: u64::try_from(delta.chunks.len()).unwrap_or(u64::MAX),
        stale_chunks: 0,
        missing_chunks: Vec::new(),
    })
}

#[derive(Debug, Clone)]
struct RqSourceDirectory {
    rel_path: String,
    abs_path: PathBuf,
}

async fn collect_entries(
    root: &Path,
) -> Result<(String, bool, Vec<RqSourceEntry>, Vec<RqSourceDirectory>), RqError> {
    if path_is_link_or_reparse(root).await.map_err(RqError::Io)? {
        return Err(RqError::Source(format!(
            "{}: RQ does not support symlink or reparse-point sources; use TCP or QUIC with portable metadata",
            root.display()
        )));
    }

    let meta = crate::fs::metadata(root)
        .await
        .map_err(|e| RqError::Source(format!("{}: {e}", root.display())))?;
    let root_name = match root.file_name() {
        None => "transfer".to_string(),
        Some(name) => name
            .to_str()
            .ok_or_else(|| {
                RqError::Source(format!(
                    "{}: source file name is not valid Unicode",
                    root.display()
                ))
            })?
            .to_string(),
    };
    validate_portable_path_component(&root_name).map_err(|_| {
        RqError::Source(format!(
            "{}: source file name is not portable: {root_name:?}",
            root.display()
        ))
    })?;

    if meta.is_file() {
        return Ok((
            root_name.clone(),
            false,
            vec![RqSourceEntry {
                rel_path: root_name,
                abs_path: root.to_path_buf(),
                metadata: EntryMetadata::default(),
                source_offset: 0,
                source_len: None,
                members: Vec::new(),
                fragment: None,
            }],
            Vec::new(),
        ));
    }
    if meta.is_dir() {
        let mut entries = Vec::new();
        let mut empty_directories = Vec::new();
        collect_dir(root, String::new(), &mut entries, &mut empty_directories).await?;
        entries.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
        empty_directories.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
        return Ok((root_name, true, entries, empty_directories));
    }
    Err(RqError::Source(format!(
        "{}: not a regular file or directory",
        root.display()
    )))
}

async fn capture_source_metadata(
    entries: &mut [RqSourceEntry],
    policy: &MetadataPolicy,
    preserve_hardlinks: bool,
) -> Result<(), RqError> {
    let paths = entries
        .iter()
        .map(|entry| entry.abs_path.clone())
        .collect::<Vec<_>>();
    let policy = policy.clone();
    let captured = crate::runtime::spawn_blocking(move || {
        paths
            .iter()
            .map(|path| {
                let metadata = read_entry_metadata_sync(path, &policy)?;
                let identity = if preserve_hardlinks {
                    inode_key_if_regular_sync(path)?
                } else {
                    None
                };
                Ok::<_, StreamingError>((metadata, identity))
            })
            .collect::<Result<Vec<_>, _>>()
    })
    .await
    .map_err(|error| RqError::Source(error.into_message()))?;

    let mut hardlink_primaries = BTreeMap::<HardlinkIdentity, String>::new();
    for (entry, (metadata, identity)) in entries.iter_mut().zip(captured) {
        if !matches!(
            metadata.file_kind,
            crate::net::atp::transport_common::FileKind::Regular
        ) {
            return Err(RqError::Source(format!(
                "{}: RQ supports regular-file metadata only; found {:?}",
                entry.abs_path.display(),
                metadata.file_kind
            )));
        }
        if preserve_hardlinks && identity.is_none() {
            return Err(RqError::Source(format!(
                "{}: RQ cannot verify source hardlink identity on this filesystem; use TCP or QUIC",
                entry.rel_path
            )));
        }
        if let Some(identity) = identity {
            if let Some(primary) = hardlink_primaries.get(&identity) {
                return Err(RqError::Source(format!(
                    "{}: RQ cannot preserve hardlink identity with {primary}; use TCP or QUIC",
                    entry.rel_path
                )));
            }
            hardlink_primaries.insert(identity, entry.rel_path.clone());
        }
        entry.metadata = metadata;
    }
    Ok(())
}

async fn capture_rq_directory_metadata_manifest(
    root: &Path,
    empty_directories: &[RqSourceDirectory],
    policy: &MetadataPolicy,
) -> Result<DirectoryMetadataManifest, RqError> {
    let mut manifest = capture_directory_metadata_manifest(root, policy)
        .await
        .map_err(|error| RqError::Source(error.into_message()))?;
    if empty_directories.is_empty() {
        return Ok(manifest);
    }

    let directories = empty_directories.to_vec();
    let policy = policy.clone();
    let captured = crate::runtime::spawn_blocking(move || {
        directories
            .into_iter()
            .map(|directory| {
                match classify_path_link_sync(&directory.abs_path).map_err(|error| {
                    StreamingError::new(format!("{}: {error}", directory.abs_path.display()))
                })? {
                    PathLinkKind::NotLink => {}
                    PathLinkKind::Symlink(_) | PathLinkKind::UnsupportedReparse => {
                        return Err(StreamingError::new(format!(
                            "{}: RQ empty directory changed to a symlink or reparse point",
                            directory.abs_path.display()
                        )));
                    }
                }
                let mut children = std::fs::read_dir(&directory.abs_path).map_err(|error| {
                    StreamingError::new(format!("{}: {error}", directory.abs_path.display()))
                })?;
                if children
                    .next()
                    .transpose()
                    .map_err(|error| {
                        StreamingError::new(format!("{}: {error}", directory.abs_path.display()))
                    })?
                    .is_some()
                {
                    return Err(StreamingError::new(format!(
                        "{}: RQ empty directory gained entries during source preflight",
                        directory.abs_path.display()
                    )));
                }
                let metadata = read_entry_metadata_sync(&directory.abs_path, &policy)?;
                if !matches!(
                    metadata.file_kind,
                    crate::net::atp::transport_common::FileKind::Directory
                ) {
                    return Err(StreamingError::new(format!(
                        "{}: RQ empty directory changed filesystem kind",
                        directory.abs_path.display()
                    )));
                }
                Ok((directory.rel_path, metadata))
            })
            .collect::<Result<Vec<_>, StreamingError>>()
    })
    .await
    .map_err(|error| RqError::Source(error.into_message()))?;

    let mut existing = manifest
        .entries
        .iter()
        .map(|entry| entry.rel_path.clone())
        .collect::<BTreeSet<_>>();
    for (rel_path, metadata) in captured {
        if !existing.insert(rel_path.clone()) {
            return Err(RqError::Source(format!(
                "{rel_path}: RQ directory topology changed during source preflight"
            )));
        }
        manifest
            .entries
            .push(DirectoryMetadataEntry { rel_path, metadata });
    }
    manifest
        .entries
        .sort_by(|left, right| left.rel_path.cmp(&right.rel_path));
    Ok(manifest)
}

/// Directory-less commitment wrapper kept for test fixtures; production
/// callers commit through `rq_metadata_commitment_with_directories`.
#[cfg(test)]
fn rq_metadata_commitment(entries: &[(&str, &EntryMetadata)]) -> String {
    rq_metadata_commitment_with_directories(entries, None)
}

fn rq_metadata_commitment_with_directories(
    entries: &[(&str, &EntryMetadata)],
    directories: Option<&DirectoryMetadataManifest>,
) -> String {
    let mut sorted = entries.to_vec();
    sorted.sort_by(|a, b| a.0.cmp(b.0));
    let mut hasher = Sha256::new();
    hasher.update(b"asupersync.atp.rq.metadata-manifest.v1\0");
    hasher.update((sorted.len() as u64).to_be_bytes());
    for (path, _) in &sorted {
        hasher.update((path.len() as u64).to_be_bytes());
        hasher.update(path.as_bytes());
    }
    match metadata_commitment(&sorted) {
        Some(commitment) => {
            hasher.update([1]);
            hasher.update(commitment.as_bytes());
        }
        None => hasher.update([0]),
    }
    if let Some(directories) = directories {
        let directory_pairs = directories.commitment_pairs();
        hasher.update(b"asupersync.atp.rq.directory-metadata.v1\0");
        hasher.update((directory_pairs.len() as u64).to_be_bytes());
        match metadata_commitment(&directory_pairs) {
            Some(commitment) => {
                hasher.update([1]);
                hasher.update(commitment.as_bytes());
            }
            None => hasher.update([0]),
        }
    }
    hex_encode(&hasher.finalize())
}

fn metadata_manifest_from_source_entries(
    entries: &[RqSourceEntry],
    directories: DirectoryMetadataManifest,
) -> RqMetadataManifest {
    let pairs = entries
        .iter()
        .map(|entry| (entry.rel_path.as_str(), &entry.metadata))
        .collect::<Vec<_>>();
    let directories = (!directories.is_empty()).then_some(directories);
    let commitment_hex = rq_metadata_commitment_with_directories(&pairs, directories.as_ref());
    let entries = entries
        .iter()
        .filter(|entry| !entry.metadata.is_bare())
        .map(|entry| RqMetadataEntry {
            rel_path: entry.rel_path.clone(),
            metadata: entry.metadata.clone(),
        })
        .collect();
    RqMetadataManifest {
        version: RQ_METADATA_MANIFEST_VERSION,
        commitment_hex,
        entries,
        directories,
    }
}

/// Validate that `root` can be represented losslessly by the RQ wire format.
///
/// RQ transfers regular files plus committed metadata for their complete
/// directory tree, including nested empty directories. It fails closed for
/// symlinks/reparse points instead of silently following them.
pub async fn validate_source_compatibility(root: &Path) -> Result<(), RqError> {
    validate_source_compatibility_with_config(root, &RqConfig::default()).await
}

/// Validate RQ source topology and metadata with the exact real-send config.
///
/// Dry-run callers should use this form so requested hardlink preservation and
/// metadata capture fail at the same point as [`send_path`], before network I/O.
pub async fn validate_source_compatibility_with_config(
    root: &Path,
    config: &RqConfig,
) -> Result<(), RqError> {
    source_metadata_manifest_with_config(root, config)
        .await
        .map(|_| ())
}

/// Capture the exact versioned metadata block for a bonded RQ descriptor.
///
/// This performs the same topology, metadata-policy, and hardlink-fidelity
/// checks as a real RQ send before returning the mandatory protocol-v4
/// commitment.
pub async fn source_metadata_manifest_with_config(
    root: &Path,
    config: &RqConfig,
) -> Result<RqMetadataManifest, RqError> {
    let (_, is_directory, mut entries, empty_directories) = collect_entries(root).await?;
    capture_source_metadata(
        &mut entries,
        &config.metadata_policy,
        config.preserve_hardlinks,
    )
    .await?;
    let directories = if is_directory {
        capture_rq_directory_metadata_manifest(root, &empty_directories, &config.metadata_policy)
            .await?
    } else {
        DirectoryMetadataManifest::default()
    };
    Ok(metadata_manifest_from_source_entries(&entries, directories))
}

fn collect_dir<'a>(
    dir: &'a Path,
    prefix: String,
    out: &'a mut Vec<RqSourceEntry>,
    empty_directories: &'a mut Vec<RqSourceDirectory>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), RqError>> + Send + 'a>> {
    Box::pin(async move {
        let mut read_dir = crate::fs::read_dir(dir)
            .await
            .map_err(|e| RqError::Source(format!("{}: {e}", dir.display())))?;
        let mut children: Vec<(String, PathBuf, bool)> = Vec::new();
        while let Some(entry) = read_dir
            .next_entry()
            .await
            .map_err(|e| RqError::Source(format!("{}: {e}", dir.display())))?
        {
            let path = entry.path();
            if path_is_link_or_reparse(&path).await.map_err(RqError::Io)? {
                return Err(RqError::Source(format!(
                    "{}: RQ does not support symlink or reparse-point entries; use TCP or QUIC with portable metadata",
                    path.display()
                )));
            }
            let name = entry
                .file_name()
                .to_str()
                .ok_or_else(|| {
                    RqError::Source(format!(
                        "{}: source entry name is not valid Unicode",
                        path.display()
                    ))
                })?
                .to_string();
            validate_portable_path_component(&name).map_err(|_| {
                RqError::Source(format!(
                    "{}: source entry name is not portable: {name:?}",
                    path.display()
                ))
            })?;
            let ft = entry
                .file_type()
                .await
                .map_err(|e| RqError::Source(format!("{}: {e}", path.display())))?;
            children.push((name, path, ft.is_dir()));
        }
        children.sort_by(|a, b| a.0.cmp(&b.0));

        if children.is_empty() && !prefix.is_empty() {
            empty_directories.push(RqSourceDirectory {
                rel_path: prefix,
                abs_path: dir.to_path_buf(),
            });
            return Ok(());
        }

        for (name, path, is_dir) in children {
            let rel = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            if is_dir {
                collect_dir(&path, rel, out, empty_directories).await?;
            } else {
                out.push(RqSourceEntry {
                    rel_path: rel,
                    abs_path: path,
                    metadata: EntryMetadata::default(),
                    source_offset: 0,
                    source_len: None,
                    members: Vec::new(),
                    fragment: None,
                });
            }
        }
        Ok(())
    })
}

async fn source_entry_size(entry: &RqSourceEntry) -> Result<u64, RqError> {
    if let Some(len) = entry.source_len {
        return Ok(len);
    }
    crate::fs::metadata(&entry.abs_path)
        .await
        .map(|metadata| metadata.len())
        .map_err(|e| RqError::Source(format!("{}: {e}", entry.abs_path.display())))
}

async fn source_entry_sizes(entries: &[RqSourceEntry]) -> Result<Vec<u64>, RqError> {
    let mut sizes = Vec::with_capacity(entries.len());
    for entry in entries {
        sizes.push(source_entry_size(entry).await?);
    }
    Ok(sizes)
}

async fn source_entries_total_bytes(entries: &[RqSourceEntry]) -> Result<u64, RqError> {
    let mut total = 0u64;
    for entry in entries {
        let size = source_entry_size(entry).await?;
        total = total.checked_add(size).ok_or(RqError::TooLarge {
            size: u64::MAX,
            max: u64::MAX,
        })?;
    }
    Ok(total)
}

/// E-15 tree coalescing (send side): greedily pack sub-threshold files into fewer,
/// larger combined RaptorQ objects.
///
/// `entries` arrives in manifest (sorted `rel_path`) order. Files whose size is
/// `< PACK_THRESHOLD` are binned greedily, in order, into packs that hold at most
/// `PACK_TARGET.min(max_object_size(config.max_block_size))` bytes (a pack always
/// holds at least one file). A pack of **two or more** files is materialized as a
/// temp file holding the byte concatenation of
/// its members in order; the resulting [`RqSourceEntry`] points at that temp file
/// and carries the [`PackedMember`] offset/len/sha table. A pack of exactly one
/// file (a lone leftover small file, or a single small file with no neighbor) is
/// emitted unchanged (no temp, empty `members`) so it stays byte-identical to the
/// non-packing wire. Files `>= PACK_THRESHOLD` are always emitted unchanged.
///
/// Returns `(new_entries, logical_digests, tempdir)` where `logical_digests` holds
/// one [`EntryDigest`] per **logical file** (members flattened) — the input to the
/// LOGICAL merkle root. For the no-packing case `logical_digests` equals the
/// per-file digests the caller would have computed itself, so the merkle root is
/// byte-identical to prior transfers. `tempdir` (if any) owns every materialized
/// pack temp file and MUST be kept alive until the spray loop has finished reading
/// them; dropping it removes the temp files.
///
/// # Errors
///
/// Returns [`RqError::Source`] if a source file cannot be hashed or a pack temp
/// file cannot be created/written.
async fn pack_small_files(
    entries: Vec<RqSourceEntry>,
    config: &RqConfig,
) -> Result<
    (
        Vec<RqSourceEntry>,
        Vec<EntryDigest>,
        Option<tempfile::TempDir>,
    ),
    RqError,
> {
    pack_small_files_with_deferred_singleton_digests(entries, config, false).await
}

async fn pack_small_files_with_deferred_singleton_digests(
    entries: Vec<RqSourceEntry>,
    config: &RqConfig,
    defer_singleton_digests: bool,
) -> Result<
    (
        Vec<RqSourceEntry>,
        Vec<EntryDigest>,
        Option<tempfile::TempDir>,
    ),
    RqError,
> {
    let mut hash_buf = vec![0u8; RQ_STREAM_HASH_BUFFER_SIZE];
    // Packed objects are intentionally not split by E-12, so a pack must stay
    // inside the configured one-object SBN envelope. If a single small file is
    // larger than this cap it remains unpacked and `split_large_entries` handles
    // it as ranged objects.
    let symbol_size = usize::from(config.symbol_size.max(1));
    let pack_target = PACK_TARGET.min(
        u64::try_from(max_object_size(config.max_block_size.max(symbol_size))).unwrap_or(u64::MAX),
    );

    // Group consecutive small files into packs. Each `Vec<usize>` is a list of
    // indices into `entries` (the original sorted order is preserved so member
    // offsets and the logical-digest order are deterministic).
    let mut groups: Vec<Vec<usize>> = Vec::new();
    let mut current: Vec<usize> = Vec::new();
    let mut current_bytes: u64 = 0;
    for (idx, entry) in entries.iter().enumerate() {
        // Hash here purely to learn the size cheaply? No — hashing twice would
        // double the disk read. Instead size is read from metadata; the content
        // sha is computed once below (for packed members) or by the caller's
        // per-object loop (for unpacked entries via the temp/real abs_path).
        let size = crate::fs::metadata(&entry.abs_path)
            .await
            .map_err(|e| RqError::Source(format!("{}: {e}", entry.abs_path.display())))?
            .len();
        if size >= PACK_THRESHOLD {
            // Flush any in-progress small-file group, then emit this large file
            // as its own (unpacked) singleton group.
            if !current.is_empty() {
                groups.push(std::mem::take(&mut current));
                current_bytes = 0;
            }
            groups.push(vec![idx]);
            continue;
        }
        // Small file: would adding it overflow the current pack? Start a fresh
        // pack if so (but never split a pack to empty — a single oversized-for-
        // -target small file still forms its own pack).
        if !current.is_empty() && current_bytes.saturating_add(size) > pack_target {
            groups.push(std::mem::take(&mut current));
            current_bytes = 0;
        }
        current.push(idx);
        current_bytes = current_bytes.saturating_add(size);
    }
    if !current.is_empty() {
        groups.push(current);
    }

    // If no group holds 2+ files, packing would do nothing useful. Return the
    // entries unchanged and compute per-file logical digests (byte-identical to
    // the caller's prior per-file digest pass).
    let packs_anything = groups.iter().any(|g| g.len() >= 2);
    if !packs_anything {
        let mut logical_digests = Vec::with_capacity(entries.len());
        if !defer_singleton_digests {
            for entry in &entries {
                let (size, content_id, content_sha256) =
                    hash_file_streaming(&entry.abs_path, &mut hash_buf)
                        .await
                        .map_err(|e| RqError::Source(e.into_message()))?;
                logical_digests.push(EntryDigest {
                    rel_path: entry.rel_path.clone(),
                    size,
                    content_id,
                    content_sha256,
                });
            }
        }
        return Ok((entries, logical_digests, None));
    }

    let tempdir = tempfile::Builder::new()
        .prefix(".atp-rq-pack-")
        .tempdir()
        .map_err(RqError::Io)?;

    let mut new_entries: Vec<RqSourceEntry> = Vec::with_capacity(groups.len());
    let mut logical_digests: Vec<EntryDigest> = Vec::with_capacity(entries.len());

    for (pack_idx, group) in groups.iter().enumerate() {
        if group.len() < 2 {
            // Singleton (a lone small file or a >= threshold file): emit unchanged
            // and push its own logical digest. Byte-identical to today.
            let entry = &entries[group[0]];
            if !defer_singleton_digests {
                let (size, content_id, content_sha256) =
                    hash_file_streaming(&entry.abs_path, &mut hash_buf)
                        .await
                        .map_err(|e| RqError::Source(e.into_message()))?;
                logical_digests.push(EntryDigest {
                    rel_path: entry.rel_path.clone(),
                    size,
                    content_id,
                    content_sha256,
                });
            }
            new_entries.push(entry.clone());
            continue;
        }

        // 2+ small files → materialize a combined object.
        let pack_path = tempdir.path().join(format!("pack-{pack_idx}"));
        let mut pack_file = crate::fs::File::create(&pack_path)
            .await
            .map_err(|e| RqError::Source(format!("{}: {e}", pack_path.display())))?;
        let mut members: Vec<PackedMember> = Vec::with_capacity(group.len());
        let mut offset: u64 = 0;
        for &member_idx in group {
            let entry = &entries[member_idx];
            let (len, content_id, content_sha256) = append_file_to_pack_with_digest(
                &entry.abs_path,
                &pack_path,
                &mut pack_file,
                &mut hash_buf,
            )
            .await?;
            members.push(PackedMember {
                rel_path: entry.rel_path.clone(),
                offset,
                len,
                sha256_hex: hex_encode(&content_sha256),
            });
            logical_digests.push(EntryDigest {
                rel_path: entry.rel_path.clone(),
                size: len,
                content_id,
                content_sha256,
            });
            offset = offset.saturating_add(len);
        }
        pack_file
            .flush()
            .await
            .map_err(|e| RqError::Source(format!("{}: {e}", pack_path.display())))?;
        drop(pack_file);

        new_entries.push(RqSourceEntry {
            rel_path: format!(".atp-pack-{pack_idx}"),
            abs_path: pack_path,
            metadata: EntryMetadata::default(),
            source_offset: 0,
            source_len: None,
            members,
            fragment: None,
        });
    }

    Ok((new_entries, logical_digests, Some(tempdir)))
}

async fn append_file_to_pack_with_digest(
    path: &Path,
    pack_path: &Path,
    pack_file: &mut crate::fs::File,
    buf: &mut [u8],
) -> Result<(u64, crate::atp::object::ObjectId, [u8; 32]), RqError> {
    let mut src = crate::fs::File::open(path)
        .await
        .map_err(|e| RqError::Source(format!("{}: {e}", path.display())))?;
    let mut sha = Sha256::new();
    let mut cid = crate::atp::object::ContentId::streaming();
    let mut size = 0u64;
    loop {
        let n = src
            .read(buf)
            .await
            .map_err(|e| RqError::Source(format!("{}: {e}", path.display())))?;
        if n == 0 {
            break;
        }
        let chunk = &buf[..n];
        sha.update(chunk);
        cid.update(chunk);
        pack_file
            .write_all(chunk)
            .await
            .map_err(|e| RqError::Source(format!("{}: {e}", pack_path.display())))?;
        size = size.checked_add(n as u64).ok_or_else(|| {
            RqError::Coding(format!("{}: packed member size overflow", path.display()))
        })?;
    }
    Ok((
        size,
        crate::atp::object::ObjectId::content(cid.finalize()),
        sha.finalize().into(),
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ManifestDigestMode {
    Manifest,
    SourceStreamTrailer,
}

/// Split large unpacked entries into ordered RaptorQ objects while preserving the
/// logical file digest list used for the transfer merkle root.
async fn split_large_entries(
    entries: Vec<RqSourceEntry>,
    logical_digests: &[EntryDigest],
    config: &RqConfig,
) -> Result<Vec<RqSourceEntry>, RqError> {
    split_large_entries_with_digest_mode(
        entries,
        logical_digests,
        config,
        ManifestDigestMode::Manifest,
    )
    .await
}

async fn split_large_entries_with_digest_mode(
    entries: Vec<RqSourceEntry>,
    logical_digests: &[EntryDigest],
    config: &RqConfig,
    digest_mode: ManifestDigestMode,
) -> Result<Vec<RqSourceEntry>, RqError> {
    let symbol_size = usize::from(config.symbol_size.max(1));
    let block_size = config.max_block_size.max(symbol_size);
    let split_config =
        MultiObjectSplitConfig::new(u64::try_from(block_size).map_err(|_| {
            RqError::Coding(format!("max_block_size does not fit u64: {block_size}"))
        })?);

    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        if !entry.members.is_empty() {
            out.push(entry);
            continue;
        }

        let size = crate::fs::metadata(&entry.abs_path)
            .await
            .map_err(|e| RqError::Source(format!("{}: {e}", entry.abs_path.display())))?
            .len();
        let plan = plan_multi_object_split(size, split_config)
            .map_err(|e| RqError::Coding(e.to_string()))?;
        if !plan.is_split() {
            out.push(entry);
            continue;
        }

        let logical_digest = logical_digests
            .iter()
            .find(|digest| digest.rel_path == entry.rel_path);
        if digest_mode == ManifestDigestMode::Manifest && logical_digest.is_none() {
            return Err(RqError::Coding(format!(
                "large-entry split missing logical digest for {}",
                entry.rel_path
            )));
        }
        let shard_count = u32::try_from(plan.shard_count()).map_err(|_| {
            RqError::Coding(format!(
                "large-entry split produced too many shards for {}",
                entry.rel_path
            ))
        })?;
        let whole_sha256_hex = logical_digest
            .map(|digest| hex_encode(&digest.content_sha256))
            .unwrap_or_else(sha256_hex_placeholder);
        for shard in plan.shards {
            let object_rel_path = format!(".atp-fragment-{}-{}", out.len(), shard.shard_index);
            out.push(RqSourceEntry {
                rel_path: object_rel_path,
                abs_path: entry.abs_path.clone(),
                metadata: entry.metadata.clone(),
                source_offset: shard.logical_offset,
                source_len: Some(shard.len),
                members: Vec::new(),
                fragment: Some(LargeObjectFragment {
                    rel_path: entry.rel_path.clone(),
                    shard_index: shard.shard_index,
                    shard_count,
                    logical_offset: shard.logical_offset,
                    len: shard.len,
                    logical_size: plan.logical_size,
                    sha256_hex: whole_sha256_hex.clone(),
                }),
            });
        }
    }

    Ok(out)
}

/// Reduce an attacker-controlled `root_name` to a single safe path component
/// joined under `dest_dir`.
///
/// `manifest.root_name` arrives off the wire, and `Path::join` *replaces* the
/// base when its argument is absolute, so `dest_dir.join(&root_name)` with an
/// absolute (or separator-bearing) `root_name` would escape the destination
/// directory entirely — `crate::fs::write_atomic` validates with
/// `allow_absolute = true`, so it would not catch an absolute target. Senders
/// already set `root_name` to a bare file name (see `collect_entries`), so a
/// legitimate manifest is accepted unchanged while hostile or platform-
/// aliasing forms are rejected fail closed (matching `transport_tcp`).
fn safe_base_for_root_name(dest_dir: &Path, root_name: &str) -> Result<PathBuf, RqError> {
    validate_portable_path_component(root_name)
        .map_err(|_| RqError::Source(format!("unsafe manifest root_name: {root_name}")))?;
    Ok(dest_dir.join(root_name))
}

fn validate_rq_metadata_value(
    rel_path: &str,
    metadata: &EntryMetadata,
    expected_kind: crate::net::atp::transport_common::FileKind,
    config: &RqConfig,
) -> Result<(), RqError> {
    if metadata.file_kind != expected_kind || metadata.hardlink_target.is_some() {
        return Err(RqError::Frame(format!(
            "metadata manifest entry {rel_path} is not a plain {expected_kind:?}"
        )));
    }
    validate_entry_metadata_for_receive(rel_path, metadata, &config.metadata_policy).map_err(
        |error| {
            RqError::Frame(format!(
                "metadata manifest entry {rel_path} is denied: {error}"
            ))
        },
    )
}

fn rq_directory_metadata_has_fidelity_fields(metadata: &EntryMetadata) -> bool {
    metadata.unix_mode.is_some()
        || metadata.mtime_unix_secs.is_some()
        || metadata.mtime_nanos.is_some()
        || metadata.uid.is_some()
        || metadata.gid.is_some()
        || metadata.windows_attributes.is_some()
        || !metadata.xattrs.is_empty()
}

fn implicit_directory_paths(logical_paths: &BTreeSet<&str>) -> BTreeMap<String, String> {
    let mut directories = BTreeMap::new();
    for logical_path in logical_paths {
        let components = logical_path.split('/').collect::<Vec<_>>();
        let mut current = String::new();
        for component in components.iter().take(components.len().saturating_sub(1)) {
            if !current.is_empty() {
                current.push('/');
            }
            current.push_str(component);
            directories.insert(portable_path_collision_key(&current), current.clone());
        }
    }
    directories
}

fn validate_directory_metadata_manifest(
    directories: &DirectoryMetadataManifest,
    logical_paths: &BTreeSet<&str>,
    is_directory: bool,
    config: &RqConfig,
) -> Result<(), RqError> {
    if !is_directory && !directories.is_empty() {
        return Err(RqError::Frame(
            "single-file RQ manifest declares directory metadata".to_string(),
        ));
    }
    let expected = implicit_directory_paths(logical_paths);
    let logical_by_key = logical_paths
        .iter()
        .map(|path| (portable_path_collision_key(path), *path))
        .collect::<BTreeMap<_, _>>();
    if let Some(root) = &directories.root {
        if !rq_directory_metadata_has_fidelity_fields(root) {
            return Err(RqError::Frame(
                "directory metadata root carries no fidelity fields and must be omitted"
                    .to_string(),
            ));
        }
        validate_rq_metadata_value(
            ".",
            root,
            crate::net::atp::transport_common::FileKind::Directory,
            config,
        )?;
    }

    let mut seen = BTreeSet::new();
    let mut previous_rel_path: Option<&str> = None;
    for entry in &directories.entries {
        validate_manifest_rel_path(&entry.rel_path)?;
        if previous_rel_path.is_some_and(|previous| previous >= entry.rel_path.as_str()) {
            return Err(RqError::Frame(format!(
                "directory metadata entries are not strictly lexicographically increasing at {}",
                entry.rel_path
            )));
        }
        previous_rel_path = Some(&entry.rel_path);
        let key = portable_path_collision_key(&entry.rel_path);
        if !seen.insert(key) {
            return Err(RqError::Frame(format!(
                "duplicate directory metadata path (including case collision): {}",
                entry.rel_path
            )));
        }

        let mut prefix = String::new();
        for component in entry.rel_path.split('/') {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(component);
            if let Some(logical_file) = logical_by_key.get(&portable_path_collision_key(&prefix)) {
                return Err(RqError::Frame(format!(
                    "directory metadata path {} collides with or descends from logical file {logical_file}",
                    entry.rel_path
                )));
            }
        }

        if let Some(expected_path) = expected.get(&portable_path_collision_key(&entry.rel_path)) {
            if *expected_path != entry.rel_path {
                return Err(RqError::Frame(format!(
                    "directory metadata path {} aliases implicit directory {expected_path}",
                    entry.rel_path
                )));
            }
            if !rq_directory_metadata_has_fidelity_fields(&entry.metadata) {
                return Err(RqError::Frame(format!(
                    "implicit directory metadata entry {} carries no fidelity fields and must be omitted",
                    entry.rel_path
                )));
            }
        }
        validate_rq_metadata_value(
            &entry.rel_path,
            &entry.metadata,
            crate::net::atp::transport_common::FileKind::Directory,
            config,
        )?;
    }
    Ok(())
}

fn validate_metadata_manifest(
    metadata_manifest: Option<&RqMetadataManifest>,
    logical_paths: &BTreeSet<&str>,
    is_directory: bool,
    config: &RqConfig,
) -> Result<(), RqError> {
    let Some(metadata_manifest) = metadata_manifest else {
        return Err(RqError::Frame(
            "protocol-v4 manifest is missing its metadata commitment".to_string(),
        ));
    };
    if metadata_manifest.version != RQ_METADATA_MANIFEST_VERSION {
        return Err(RqError::Frame(format!(
            "unsupported RQ metadata manifest version {} (expected {RQ_METADATA_MANIFEST_VERSION})",
            metadata_manifest.version
        )));
    }
    validate_manifest_sha256_hex(
        "manifest metadata commitment",
        &metadata_manifest.commitment_hex,
    )?;
    if metadata_manifest
        .directories
        .as_ref()
        .is_some_and(DirectoryMetadataManifest::is_empty)
    {
        return Err(RqError::Frame(
            "directory metadata block is present but empty".to_string(),
        ));
    }
    let directory_records = metadata_manifest
        .directories
        .as_ref()
        .map_or(0, |directories| {
            directories
                .entries
                .len()
                .saturating_add(usize::from(directories.root.is_some()))
        });
    let metadata_records = metadata_manifest
        .entries
        .len()
        .saturating_add(directory_records);
    if metadata_records > MAX_MANIFEST_ENTRIES {
        return Err(RqError::Frame(format!(
            "metadata manifest declares {metadata_records} records (max {MAX_MANIFEST_ENTRIES})"
        )));
    }
    if metadata_manifest.entries.len() > logical_paths.len() {
        return Err(RqError::Frame(format!(
            "metadata manifest declares {} entries for {} logical files",
            metadata_manifest.entries.len(),
            logical_paths.len()
        )));
    }

    let logical_by_key = logical_paths
        .iter()
        .map(|path| (portable_path_collision_key(path), *path))
        .collect::<BTreeMap<_, _>>();
    let mut metadata_by_key = BTreeMap::<String, (&str, &EntryMetadata)>::new();
    for entry in &metadata_manifest.entries {
        validate_manifest_rel_path(&entry.rel_path)?;
        if entry.metadata.is_bare() {
            return Err(RqError::Frame(format!(
                "metadata manifest entry {} is bare and must be omitted",
                entry.rel_path
            )));
        }
        let key = portable_path_collision_key(&entry.rel_path);
        let Some(expected_path) = logical_by_key.get(&key) else {
            return Err(RqError::Frame(format!(
                "metadata manifest entry {} has no logical file",
                entry.rel_path
            )));
        };
        if *expected_path != entry.rel_path {
            return Err(RqError::Frame(format!(
                "metadata manifest path {} aliases logical path {expected_path}",
                entry.rel_path
            )));
        }
        if metadata_by_key
            .insert(key, (entry.rel_path.as_str(), &entry.metadata))
            .is_some()
        {
            return Err(RqError::Frame(format!(
                "duplicate metadata manifest path (including case collision): {}",
                entry.rel_path
            )));
        }
        validate_rq_metadata_value(
            &entry.rel_path,
            &entry.metadata,
            crate::net::atp::transport_common::FileKind::Regular,
            config,
        )?;
    }

    if let Some(directories) = &metadata_manifest.directories {
        validate_directory_metadata_manifest(directories, logical_paths, is_directory, config)?;
    }

    let bare_metadata = EntryMetadata::default();
    let canonical_refs = logical_paths
        .iter()
        .map(|path| {
            let key = portable_path_collision_key(path);
            let metadata = metadata_by_key
                .get(&key)
                .map_or(&bare_metadata, |(_, metadata)| *metadata);
            (*path, metadata)
        })
        .collect::<Vec<_>>();
    if rq_metadata_commitment_with_directories(
        &canonical_refs,
        metadata_manifest.directories.as_ref(),
    ) != metadata_manifest.commitment_hex
    {
        return Err(RqError::Frame(
            "manifest metadata commitment mismatch".to_string(),
        ));
    }
    Ok(())
}

/// Validate an incoming transfer manifest before allocating per-entry decoders.
///
/// The manifest is fully controlled by the peer. `total_bytes` alone is not a
/// sufficient memory bound because each entry size also drives RaptorQ decoder
/// metadata and each entry creates receiver bookkeeping.
fn validate_manifest(manifest: &TransferManifest, config: &RqConfig) -> Result<(), RqError> {
    if manifest.transfer_id.is_empty()
        || manifest.transfer_id.len() > 64
        || !manifest
            .transfer_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric())
    {
        return Err(RqError::Frame(format!(
            "unsafe manifest transfer_id: {}",
            manifest.transfer_id
        )));
    }
    validate_portable_path_component(&manifest.root_name).map_err(|_| {
        RqError::Source(format!("unsafe manifest root_name: {}", manifest.root_name))
    })?;
    if manifest.total_bytes > config.max_transfer_bytes {
        return Err(RqError::TooLarge {
            size: manifest.total_bytes,
            max: config.max_transfer_bytes,
        });
    }
    validate_manifest_sha256_hex("manifest merkle_root_hex", &manifest.merkle_root_hex)?;
    if manifest.entries.len() > MAX_MANIFEST_ENTRIES {
        return Err(RqError::Frame(format!(
            "manifest declares {} entries (max {MAX_MANIFEST_ENTRIES})",
            manifest.entries.len()
        )));
    }
    let content_records = manifest.entries.iter().try_fold(0usize, |count, entry| {
        count
            .checked_add(if entry.members.is_empty() {
                1
            } else {
                entry.members.len()
            })
            .ok_or_else(|| RqError::Frame("manifest content record count overflows".to_string()))
    })?;
    let directory_records = manifest
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.directories.as_ref())
        .map_or(0, |directories| {
            directories
                .entries
                .len()
                .saturating_add(usize::from(directories.root.is_some()))
        });
    let combined_records = content_records.saturating_add(directory_records);
    if combined_records > MAX_MANIFEST_ENTRIES {
        return Err(RqError::Frame(format!(
            "manifest declares {combined_records} combined content and directory records (max {MAX_MANIFEST_ENTRIES})"
        )));
    }
    let single_file_fragmented = !manifest.is_directory
        && !manifest.entries.is_empty()
        && manifest
            .entries
            .iter()
            .all(|entry| entry.fragment.is_some());
    if !manifest.is_directory && manifest.entries.len() != 1 && !single_file_fragmented {
        return Err(RqError::Frame(format!(
            "single-file transfer manifest declares {} entries",
            manifest.entries.len()
        )));
    }

    #[derive(Debug)]
    struct FragmentGroupValidation {
        rel_path: String,
        logical_size: u64,
        shard_count: u32,
        sha256_hex: String,
        shards: Vec<(u32, u64, u64)>,
    }

    let mut seen_object_rel_paths: BTreeSet<String> = BTreeSet::new();
    let mut seen_logical_rel_paths: BTreeSet<String> = BTreeSet::new();
    let mut fragment_groups: BTreeMap<String, FragmentGroupValidation> = BTreeMap::new();
    let declared_total =
        manifest
            .entries
            .iter()
            .enumerate()
            .try_fold(0u64, |acc, (position, entry)| {
                let expected = u32::try_from(position).map_err(|_| {
                    RqError::Frame("manifest contains too many indexed entries".to_string())
                })?;
                if entry.index != expected {
                    return Err(RqError::Frame(format!(
                        "manifest entry index {} does not match position {expected}",
                        entry.index
                    )));
                }
                validate_manifest_rel_path(&entry.rel_path)?;
                let object_path_key = portable_path_collision_key(&entry.rel_path);
                if !seen_object_rel_paths.insert(object_path_key) {
                    return Err(RqError::Frame(format!(
                        "duplicate manifest rel_path (including case collision): {}",
                        entry.rel_path
                    )));
                }
                validate_manifest_sha256_hex("manifest entry sha256_hex", &entry.sha256_hex)?;
                if let Some(fragment) = &entry.fragment {
                    if !entry.members.is_empty() {
                        return Err(RqError::Frame(format!(
                            "manifest entry {} cannot be both packed and fragmented",
                            entry.rel_path
                        )));
                    }
                    validate_manifest_rel_path(&fragment.rel_path)?;
                    validate_manifest_sha256_hex(
                        "manifest fragment sha256_hex",
                        &fragment.sha256_hex,
                    )?;
                    if fragment.shard_count == 0 || fragment.shard_index >= fragment.shard_count {
                        return Err(RqError::Frame(format!(
                            "fragment {} has invalid shard {}/{}",
                            fragment.rel_path, fragment.shard_index, fragment.shard_count
                        )));
                    }
                    if fragment.len != entry.size {
                        return Err(RqError::Frame(format!(
                            "fragment {} len {} does not match object {} size {}",
                            fragment.rel_path, fragment.len, entry.rel_path, entry.size
                        )));
                    }
                    let end = fragment
                        .logical_offset
                        .checked_add(fragment.len)
                        .ok_or_else(|| {
                            RqError::Frame(format!(
                                "fragment {} byte range overflows",
                                fragment.rel_path
                            ))
                        })?;
                    if end > fragment.logical_size {
                        return Err(RqError::Frame(format!(
                            "fragment {} range ends at {end} beyond logical size {}",
                            fragment.rel_path, fragment.logical_size
                        )));
                    }
                    let fragment_path_key = portable_path_collision_key(&fragment.rel_path);
                    let group = fragment_groups.entry(fragment_path_key).or_insert_with(|| {
                        FragmentGroupValidation {
                            rel_path: fragment.rel_path.clone(),
                            logical_size: fragment.logical_size,
                            shard_count: fragment.shard_count,
                            sha256_hex: fragment.sha256_hex.clone(),
                            shards: Vec::new(),
                        }
                    });
                    if group.rel_path != fragment.rel_path {
                        return Err(RqError::Frame(format!(
                            "duplicate logical rel_path by case: {} conflicts with {}",
                            fragment.rel_path, group.rel_path
                        )));
                    }
                    if group.logical_size != fragment.logical_size
                        || group.shard_count != fragment.shard_count
                        || group.sha256_hex != fragment.sha256_hex
                    {
                        return Err(RqError::Frame(format!(
                            "fragment {} metadata is inconsistent across shards",
                            fragment.rel_path
                        )));
                    }
                    group
                        .shards
                        .push((fragment.shard_index, fragment.logical_offset, fragment.len));
                } else if entry.members.is_empty()
                    && !seen_logical_rel_paths
                        .insert(portable_path_collision_key(&entry.rel_path))
                {
                    return Err(RqError::Frame(format!(
                        "duplicate logical rel_path (including case collision): {}",
                        entry.rel_path
                    )));
                }
                // E-15: a packed object carries a member offset table. Validate it
                // off the wire (member paths, contiguity, and that the member lens
                // tile the object exactly) so a hostile/malformed packed manifest
                // fails closed before any decoder is allocated. The synthetic object
                // `rel_path` (`.atp-pack-N`) is never committed; the member logical
                // paths are what land on disk and must be unique + safe.
                if !entry.members.is_empty() {
                    let mut expected_offset = 0u64;
                    for member in &entry.members {
                        validate_manifest_rel_path(&member.rel_path)?;
                        validate_manifest_sha256_hex(
                            "manifest packed member sha256_hex",
                            &member.sha256_hex,
                        )?;
                        if !seen_logical_rel_paths
                            .insert(portable_path_collision_key(&member.rel_path))
                        {
                            return Err(RqError::Frame(format!(
                                "duplicate packed member rel_path (including case collision): {}",
                                member.rel_path
                            )));
                        }
                        if member.offset != expected_offset {
                            return Err(RqError::Frame(format!(
                                "packed member {} offset {} is not contiguous (expected {expected_offset})",
                                member.rel_path, member.offset
                            )));
                        }
                        expected_offset = expected_offset.checked_add(member.len).ok_or_else(|| {
                            RqError::Frame(format!(
                                "packed member {} length overflow",
                                member.rel_path
                            ))
                        })?;
                    }
                    if expected_offset != entry.size {
                        return Err(RqError::Frame(format!(
                            "packed members cover {expected_offset} bytes but object {} declares {}",
                            entry.rel_path, entry.size
                        )));
                    }
                }
                acc.checked_add(entry.size).ok_or_else(|| {
                    RqError::Frame("manifest declared size sum overflows u64".to_string())
                })
            })?;
    if declared_total > config.max_transfer_bytes {
        return Err(RqError::TooLarge {
            size: declared_total,
            max: config.max_transfer_bytes,
        });
    }
    if single_file_fragmented && fragment_groups.len() != 1 {
        return Err(RqError::Frame(format!(
            "single-file fragmented manifest declares {} logical files",
            fragment_groups.len()
        )));
    }
    for (rel_path_key, group) in fragment_groups {
        let rel_path = group.rel_path;
        if !seen_logical_rel_paths.insert(rel_path_key) {
            return Err(RqError::Frame(format!(
                "duplicate logical rel_path (including case collision): {rel_path}"
            )));
        }
        if group.shards.len() != usize::try_from(group.shard_count).unwrap_or(usize::MAX) {
            return Err(RqError::Frame(format!(
                "fragment {rel_path} declares {} shards but manifest carries {}",
                group.shard_count,
                group.shards.len()
            )));
        }
        let mut shards = group.shards;
        shards.sort_by_key(|(shard_index, _, _)| *shard_index);
        let mut expected_offset = 0u64;
        for (position, (shard_index, offset, len)) in shards.iter().enumerate() {
            if *shard_index != u32::try_from(position).unwrap_or(u32::MAX) {
                return Err(RqError::Frame(format!(
                    "fragment {rel_path} has non-contiguous shard index {shard_index}"
                )));
            }
            if *offset != expected_offset {
                return Err(RqError::Frame(format!(
                    "fragment {rel_path} offset {offset} is not contiguous (expected {expected_offset})"
                )));
            }
            expected_offset = expected_offset.checked_add(*len).ok_or_else(|| {
                RqError::Frame(format!("fragment {rel_path} length sum overflows"))
            })?;
        }
        if expected_offset != group.logical_size {
            return Err(RqError::Frame(format!(
                "fragment {rel_path} shards cover {expected_offset} bytes but logical size is {}",
                group.logical_size
            )));
        }
    }
    let mut committed_paths = BTreeSet::<&str>::new();
    for entry in &manifest.entries {
        if let Some(fragment) = &entry.fragment {
            committed_paths.insert(fragment.rel_path.as_str());
        } else if entry.members.is_empty() {
            committed_paths.insert(entry.rel_path.as_str());
        } else {
            committed_paths.extend(entry.members.iter().map(|member| member.rel_path.as_str()));
        }
    }
    validate_portable_path_set(committed_paths.iter().copied())
        .map_err(|error| RqError::Frame(format!("unsafe manifest path tree: {error}")))?;
    validate_metadata_manifest(
        manifest.metadata.as_ref(),
        &committed_paths,
        manifest.is_directory,
        config,
    )?;
    validate_rq_delta_manifest(manifest)?;
    Ok(())
}

fn validate_rq_delta_manifest(manifest: &TransferManifest) -> Result<(), RqError> {
    let Some(delta) = manifest.delta_manifest.as_ref() else {
        return Ok(());
    };
    let Some(entry) = rq_delta_manifest_entry(manifest) else {
        return Err(RqError::Frame(
            "RQ delta manifest is supported only for one unpacked regular file".to_string(),
        ));
    };
    if u64::try_from(delta.chunks.len()).unwrap_or(u64::MAX) > RQ_DELTA_MAX_MANIFEST_CHUNKS {
        return Err(RqError::Frame(
            "RQ delta manifest declares too many chunks".to_string(),
        ));
    }
    if delta.schema != ATP_DELTA_CHUNK_MANIFEST_SCHEMA {
        return Err(RqError::Frame(format!(
            "unsupported RQ delta manifest schema: {}",
            delta.schema
        )));
    }
    if delta.tree_id != manifest.merkle_root_hex {
        return Err(RqError::Frame(
            "RQ delta manifest tree id does not match the transfer Merkle root".to_string(),
        ));
    }
    let max_chunk_size = usize::try_from(MAX_FRAME_SIZE)
        .unwrap_or(usize::MAX)
        .saturating_sub(12);
    if delta.chunk_size == 0 || delta.chunk_size > max_chunk_size {
        return Err(RqError::Frame(format!(
            "RQ delta manifest chunk size {} is outside 1..={max_chunk_size}",
            delta.chunk_size
        )));
    }
    if delta.total_size_bytes != manifest.total_bytes || delta.total_size_bytes != entry.size {
        return Err(RqError::Frame(format!(
            "RQ delta manifest size {} does not match transfer size {}",
            delta.total_size_bytes, manifest.total_bytes
        )));
    }
    let max_chunk_size = u64::try_from(delta.chunk_size).unwrap_or(u64::MAX);
    let mut planner_chunks = Vec::with_capacity(delta.chunks.len());
    let mut expected_offset = 0u64;
    for (position, chunk) in delta.chunks.iter().enumerate() {
        let expected_index = u32::try_from(position)
            .map_err(|_| RqError::Frame("too many RQ delta manifest chunks".to_string()))?;
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
            return Err(RqError::Frame(format!(
                "malformed RQ delta chunk at position {position}"
            )));
        }
        let content_id = ContentId::new(rq_decode_delta_root(
            &chunk.content_id_hex,
            "RQ delta chunk content id",
        )?);
        planner_chunks.push(CasChunkRef {
            index: chunk.index,
            byte_offset: chunk.stream_offset,
            size_bytes: chunk.size_bytes,
            content_id,
        });
        expected_offset = expected_offset
            .checked_add(chunk.size_bytes)
            .ok_or_else(|| RqError::Frame("RQ delta chunk offsets overflow".to_string()))?;
    }
    if expected_offset != delta.total_size_bytes {
        return Err(RqError::Frame(format!(
            "RQ delta chunks cover {expected_offset} bytes, expected {}",
            delta.total_size_bytes
        )));
    }
    let planner = PersistentChunkManifest::new(delta.tree_id.clone(), planner_chunks)
        .map_err(|error| RqError::Frame(format!("validate RQ delta manifest: {error}")))?;
    if planner.total_size_bytes != delta.total_size_bytes
        || planner.merkle_root.to_hex() != delta.merkle_root_hex
    {
        return Err(RqError::Frame(
            "RQ delta manifest chunk commitment mismatch".to_string(),
        ));
    }
    Ok(())
}

fn validate_manifest_sha256_hex(label: &str, value: &str) -> Result<(), RqError> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(RqError::Frame(format!("{label} must be 64 hex characters")));
    }
    Ok(())
}

fn sha256_hex_placeholder() -> String {
    "0".repeat(64)
}

fn validate_manifest_rel_path(rel: &str) -> Result<(), RqError> {
    validate_portable_relative_path(rel)
        .map_err(|_| RqError::Source(format!("unsafe manifest rel_path: {rel}")))
}

#[derive(Debug, Default)]
struct CompletionDigestIndex {
    entry_digests: BTreeMap<u32, (u64, String)>,
    logical_digests: BTreeMap<String, (u64, String)>,
    merkle_root_hex: Option<String>,
}

impl CompletionDigestIndex {
    fn from_round_complete(
        complete: &RqRoundComplete,
        manifest: &TransferManifest,
        require_source_stream_trailer: bool,
    ) -> Result<Self, RqError> {
        let mut index = Self::default();
        if let Some(root) = &complete.merkle_root_hex {
            validate_manifest_sha256_hex("ObjectComplete merkle_root_hex", root)?;
            index.merkle_root_hex = Some(root.clone());
        }

        let manifest_indexes: BTreeSet<u32> =
            manifest.entries.iter().map(|entry| entry.index).collect();
        for digest in &complete.entry_digests {
            validate_manifest_sha256_hex("ObjectComplete entry sha256_hex", &digest.sha256_hex)?;
            if !manifest_indexes.contains(&digest.index) {
                return Err(RqError::Frame(format!(
                    "ObjectComplete digest for unknown entry {}",
                    digest.index
                )));
            }
            if index
                .entry_digests
                .insert(digest.index, (digest.size, digest.sha256_hex.clone()))
                .is_some()
            {
                return Err(RqError::Frame(format!(
                    "duplicate ObjectComplete digest for entry {}",
                    digest.index
                )));
            }
        }

        for digest in &complete.logical_digests {
            validate_manifest_rel_path(&digest.rel_path)?;
            validate_manifest_sha256_hex("ObjectComplete logical sha256_hex", &digest.sha256_hex)?;
            if index
                .logical_digests
                .insert(
                    digest.rel_path.clone(),
                    (digest.size, digest.sha256_hex.clone()),
                )
                .is_some()
            {
                return Err(RqError::Frame(format!(
                    "duplicate ObjectComplete logical digest for {}",
                    digest.rel_path
                )));
            }
        }

        if require_source_stream_trailer {
            if index.merkle_root_hex.is_none() {
                return Err(RqError::Frame(
                    "control source stream ObjectComplete missing merkle_root_hex".to_string(),
                ));
            }
            for entry in &manifest.entries {
                if !index.entry_digests.contains_key(&entry.index) {
                    return Err(RqError::Frame(format!(
                        "control source stream ObjectComplete missing digest for entry {}",
                        entry.index
                    )));
                }
            }
        }

        Ok(index)
    }

    fn expected_entry<'a>(&'a self, entry: &'a ManifestEntry) -> (u64, &'a str) {
        self.entry_digests
            .get(&entry.index)
            .map_or((entry.size, entry.sha256_hex.as_str()), |(size, sha)| {
                (*size, sha.as_str())
            })
    }

    fn expected_logical<'a>(&'a self, rel_path: &str, size: u64, sha: &'a str) -> (u64, &'a str) {
        self.logical_digests
            .get(rel_path)
            .map_or((size, sha), |(trailer_size, trailer_sha)| {
                (*trailer_size, trailer_sha.as_str())
            })
    }

    fn expected_merkle_root<'a>(&'a self, manifest: &'a TransferManifest) -> &'a str {
        self.merkle_root_hex
            .as_deref()
            .unwrap_or(&manifest.merkle_root_hex)
    }
}

/// Join `base` with a forward-slash relative path, rejecting any component that
/// would escape `base`.
fn join_relative(base: &Path, rel: &str) -> Result<PathBuf, RqError> {
    let mut out = base.to_path_buf();
    for component in rel.split('/') {
        if component.is_empty() || component == "." {
            continue;
        }
        if component == ".." || component.contains('\\') || component.contains(':') {
            return Err(RqError::Source(format!(
                "unsafe path component in entry: {rel}"
            )));
        }
        out.push(component);
    }
    Ok(out)
}

fn transfer_id_hex(merkle_root_hex: &str, total_bytes: u64, file_count: usize) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"asupersync.atp.rq.transfer-id.v1\0");
    hasher.update(merkle_root_hex.as_bytes());
    hasher.update(total_bytes.to_be_bytes());
    hasher.update((file_count as u64).to_be_bytes());
    hex_encode(&hasher.finalize()[..16])
}

fn transfer_id_hex_from_structure(
    root_name: &str,
    is_directory: bool,
    total_bytes: u64,
    entries: &[ManifestEntry],
) -> String {
    let nonce = RQ_TRANSFER_SEQ.fetch_add(1, Ordering::Relaxed);
    let mut hasher = Sha256::new();
    hasher.update(b"asupersync.atp.rq.transfer-id.v3.structure\0");
    hasher.update(root_name.as_bytes());
    hasher.update([u8::from(is_directory)]);
    hasher.update(total_bytes.to_be_bytes());
    hasher.update((entries.len() as u64).to_be_bytes());
    hasher.update(std::process::id().to_be_bytes());
    hasher.update(nonce.to_be_bytes());
    for entry in entries {
        hasher.update(entry.index.to_be_bytes());
        hasher.update(entry.rel_path.as_bytes());
        hasher.update([0]);
        hasher.update(entry.size.to_be_bytes());
        if let Some(fragment) = &entry.fragment {
            hasher.update(b"fragment\0");
            hasher.update(fragment.rel_path.as_bytes());
            hasher.update([0]);
            hasher.update(fragment.shard_index.to_be_bytes());
            hasher.update(fragment.shard_count.to_be_bytes());
            hasher.update(fragment.logical_offset.to_be_bytes());
            hasher.update(fragment.len.to_be_bytes());
            hasher.update(fragment.logical_size.to_be_bytes());
        }
        for member in &entry.members {
            hasher.update(b"member\0");
            hasher.update(member.rel_path.as_bytes());
            hasher.update([0]);
            hasher.update(member.offset.to_be_bytes());
            hasher.update(member.len.to_be_bytes());
        }
    }
    hex_encode(&hasher.finalize()[..16])
}

// ─── UDP symbol datagram framing ─────────────────────────────────────────────

fn encode_symbol_datagram(
    tag: u64,
    entry: u32,
    sym: &Symbol,
    auth_tag: Option<&AuthenticationTag>,
) -> Vec<u8> {
    let data = sym.data();
    let auth_len = auth_tag.map_or(0, |_| TAG_SIZE);
    let mut out = Vec::with_capacity(DGRAM_HEADER + auth_len + data.len());
    out.extend_from_slice(&SYMBOL_MAGIC.to_be_bytes());
    out.extend_from_slice(&tag.to_be_bytes());
    out.extend_from_slice(&entry.to_be_bytes());
    out.push(sym.id().sbn());
    out.extend_from_slice(&sym.id().esi().to_be_bytes());
    out.push(u8::from(sym.kind().is_repair()));
    out.extend_from_slice(&u16::try_from(data.len()).unwrap_or(u16::MAX).to_be_bytes());
    if let Some(auth_tag) = auth_tag {
        out.extend_from_slice(auth_tag.as_bytes());
    }
    out.extend_from_slice(data);
    out
}

#[derive(Debug, Clone, Copy)]
struct ParsedDatagram {
    entry: u32,
    sbn: u8,
    esi: u32,
    kind: SymbolKind,
    auth_tag: Option<AuthenticationTag>,
    payload_len: usize,
    header_len: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SymbolDatagramParseError {
    TruncatedHeader { len: usize, min: usize },
    BadMagic { found: u32 },
    WrongTransferTag { found: u64, expected: u64 },
    PayloadTooLarge { declared: usize, max: usize },
    TruncatedPayload { len: usize, min: usize },
}

fn parse_symbol_header_checked(
    buf: &[u8],
    expect_tag: u64,
    auth_required: bool,
    max_payload_len: Option<usize>,
) -> Result<ParsedDatagram, SymbolDatagramParseError> {
    let header_len = if auth_required {
        AUTH_DGRAM_HEADER
    } else {
        DGRAM_HEADER
    };
    if buf.len() < header_len {
        return Err(SymbolDatagramParseError::TruncatedHeader {
            len: buf.len(),
            min: header_len,
        });
    }

    let found_magic = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if found_magic != SYMBOL_MAGIC {
        return Err(SymbolDatagramParseError::BadMagic { found: found_magic });
    }

    let tag = u64::from_be_bytes([
        buf[4], buf[5], buf[6], buf[7], buf[8], buf[9], buf[10], buf[11],
    ]);
    if tag != expect_tag {
        return Err(SymbolDatagramParseError::WrongTransferTag {
            found: tag,
            expected: expect_tag,
        });
    }

    let entry = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);
    let sbn = buf[16];
    let esi = u32::from_be_bytes([buf[17], buf[18], buf[19], buf[20]]);
    let kind = if buf[21] == 0 {
        SymbolKind::Source
    } else {
        SymbolKind::Repair
    };
    let payload_len = usize::from(u16::from_be_bytes([buf[22], buf[23]]));

    if let Some(max) = max_payload_len
        && payload_len > max
    {
        return Err(SymbolDatagramParseError::PayloadTooLarge {
            declared: payload_len,
            max,
        });
    }

    let auth_tag = if auth_required {
        let mut tag_bytes = [0u8; TAG_SIZE];
        tag_bytes.copy_from_slice(&buf[DGRAM_HEADER..AUTH_DGRAM_HEADER]);
        Some(AuthenticationTag::from_bytes(tag_bytes))
    } else {
        None
    };

    let min = header_len + payload_len;
    if buf.len() < min {
        return Err(SymbolDatagramParseError::TruncatedPayload {
            len: buf.len(),
            min,
        });
    }

    Ok(ParsedDatagram {
        entry,
        sbn,
        esi,
        kind,
        auth_tag,
        payload_len,
        header_len,
    })
}

fn parse_symbol_header(buf: &[u8], expect_tag: u64, auth_required: bool) -> Option<ParsedDatagram> {
    parse_symbol_header_checked(buf, expect_tag, auth_required, None).ok()
}

/// Fuzz-visible symbol-datagram parser result.
#[cfg(any(test, feature = "fuzz"))]
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RqSymbolDatagramFuzzParse {
    /// Manifest entry index carried by the datagram.
    pub entry: u32,
    /// RaptorQ source-block number.
    pub sbn: u8,
    /// RaptorQ encoding-symbol id.
    pub esi: u32,
    /// Whether the datagram carries a repair symbol.
    pub is_repair: bool,
    /// Optional per-symbol authentication tag bytes.
    pub auth_tag: Option<[u8; TAG_SIZE]>,
    /// Offset where the symbol payload begins.
    pub payload_offset: usize,
    /// Declared symbol payload length.
    pub payload_len: usize,
}

/// Typed fuzz-visible parser error for ATP-over-RaptorQ UDP symbol datagrams.
#[cfg(any(test, feature = "fuzz"))]
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RqSymbolDatagramFuzzError {
    /// The datagram ended before the required header.
    TruncatedHeader {
        /// Observed byte length.
        len: usize,
        /// Minimum required byte length.
        min: usize,
    },
    /// The magic prefix was not `ATRQ`.
    BadMagic {
        /// Observed magic value.
        found: u32,
    },
    /// The transfer tag did not match the expected transfer.
    WrongTransferTag {
        /// Observed transfer tag.
        found: u64,
        /// Expected transfer tag.
        expected: u64,
    },
    /// The declared payload length exceeds the fuzz harness budget.
    PayloadTooLarge {
        /// Declared payload length.
        declared: usize,
        /// Maximum payload length accepted by the harness.
        max: usize,
    },
    /// The datagram ended before the declared payload bytes.
    TruncatedPayload {
        /// Observed byte length.
        len: usize,
        /// Minimum required byte length.
        min: usize,
    },
}

#[cfg(any(test, feature = "fuzz"))]
impl From<SymbolDatagramParseError> for RqSymbolDatagramFuzzError {
    fn from(error: SymbolDatagramParseError) -> Self {
        match error {
            SymbolDatagramParseError::TruncatedHeader { len, min } => {
                Self::TruncatedHeader { len, min }
            }
            SymbolDatagramParseError::BadMagic { found } => Self::BadMagic { found },
            SymbolDatagramParseError::WrongTransferTag { found, expected } => {
                Self::WrongTransferTag { found, expected }
            }
            SymbolDatagramParseError::PayloadTooLarge { declared, max } => {
                Self::PayloadTooLarge { declared, max }
            }
            SymbolDatagramParseError::TruncatedPayload { len, min } => {
                Self::TruncatedPayload { len, min }
            }
        }
    }
}

/// Parse an ATP-over-RaptorQ UDP symbol datagram with typed errors for fuzzing.
#[cfg(any(test, feature = "fuzz"))]
#[doc(hidden)]
pub fn parse_symbol_datagram_for_fuzz(
    buf: &[u8],
    expect_tag: u64,
    auth_required: bool,
    max_payload_len: usize,
) -> Result<RqSymbolDatagramFuzzParse, RqSymbolDatagramFuzzError> {
    let parsed =
        parse_symbol_header_checked(buf, expect_tag, auth_required, Some(max_payload_len))?;
    Ok(RqSymbolDatagramFuzzParse {
        entry: parsed.entry,
        sbn: parsed.sbn,
        esi: parsed.esi,
        is_repair: parsed.kind.is_repair(),
        auth_tag: parsed.auth_tag.map(|tag| *tag.as_bytes()),
        payload_offset: parsed.header_len,
        payload_len: parsed.payload_len,
    })
}

// ─── Per-entry coding state ──────────────────────────────────────────────────

/// Compute the source-symbol count for an entry of `size` bytes given the
/// symbol size (`ceil(size / symbol_size)`, with a 1-symbol floor for empties).
#[cfg(test)]
fn source_symbol_count(size: u64, symbol_size: u16) -> usize {
    let s = u64::from(symbol_size.max(1));
    usize::try_from(size.div_ceil(s).max(1)).unwrap_or(usize::MAX)
}

#[cfg(test)]
fn max_block_source_symbol_count(size: u64, symbol_size: u16, max_block_size: usize) -> usize {
    if size == 0 {
        return 1;
    }
    let s = usize::from(symbol_size.max(1));
    let capped_block = usize::try_from(size)
        .unwrap_or(usize::MAX)
        .min(max_block_size.max(1));
    capped_block.div_ceil(s).max(1)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EncodeAheadBlock {
    sbn: u8,
    start: usize,
    len: usize,
    k: usize,
}

#[derive(Debug)]
struct EncodeAheadSymbol {
    entry: u32,
    symbol: Symbol,
}

impl EncodeAheadSymbol {
    fn from_encoded(entry: u32, encoded: EncodedSymbol) -> Self {
        Self {
            entry,
            symbol: encoded.into_symbol(),
        }
    }
}

#[derive(Debug, Default)]
struct EncodeAheadRing {
    slot: Option<EncodeAheadSymbol>,
}

impl EncodeAheadRing {
    const CAPACITY: usize = 1;

    fn push(&mut self, symbol: EncodeAheadSymbol) -> Result<(), RqError> {
        if self.slot.is_some() {
            return Err(RqError::Coding(format!(
                "M={} encode-ahead ring is full",
                Self::CAPACITY
            )));
        }
        self.slot = Some(symbol);
        Ok(())
    }

    fn pop(&mut self) -> Option<EncodeAheadSymbol> {
        self.slot.take()
    }

    fn is_empty(&self) -> bool {
        self.slot.is_none()
    }
}

fn encode_ahead_blocks(
    bytes_len: usize,
    config: &RqConfig,
) -> Result<Vec<EncodeAheadBlock>, RqError> {
    let symbol_size = usize::from(config.symbol_size);
    if symbol_size == 0 {
        return Err(RqError::Coding(
            "invalid configuration: symbol_size must be non-zero".to_string(),
        ));
    }
    let max_block_size = config.max_block_size;
    if max_block_size == 0 {
        return Err(RqError::Coding(
            "invalid configuration: max_block_size must be non-zero".to_string(),
        ));
    }

    if bytes_len == 0 {
        return Ok(Vec::new());
    }

    let max_total = max_object_size(max_block_size);
    if bytes_len > max_total {
        return Err(RqError::TooLarge {
            size: u64::try_from(bytes_len).unwrap_or(u64::MAX),
            max: u64::try_from(max_total).unwrap_or(u64::MAX),
        });
    }

    let mut blocks = Vec::new();
    let mut start = 0usize;
    while start < bytes_len {
        if blocks.len() >= MAX_SOURCE_BLOCKS {
            return Err(RqError::TooLarge {
                size: u64::try_from(bytes_len).unwrap_or(u64::MAX),
                max: u64::try_from(max_total).unwrap_or(u64::MAX),
            });
        }
        let sbn = u8::try_from(blocks.len()).map_err(|_| {
            RqError::Coding("encode-ahead source block number overflow".to_string())
        })?;
        let len = (bytes_len - start).min(max_block_size);
        let k = len.div_ceil(symbol_size);
        blocks.push(EncodeAheadBlock { sbn, start, len, k });
        start += len;
    }

    Ok(blocks)
}

fn effective_transfer_max_block_size(
    config: &RqConfig,
    entries: &[EntryDigest],
) -> Result<usize, RqError> {
    let mut max_entry_len = 0usize;
    for entry in entries {
        let len = usize::try_from(entry.size).map_err(|_| RqError::TooLarge {
            size: entry.size,
            max: u64::try_from(usize::MAX).unwrap_or(u64::MAX),
        })?;
        max_entry_len = max_entry_len.max(len);
    }
    effective_max_block_size_for_largest_entry(config, max_entry_len)
}

pub(in crate::net::atp) fn effective_max_block_size_for_largest_entry(
    config: &RqConfig,
    max_entry_len: usize,
) -> Result<usize, RqError> {
    let symbol_size = usize::from(config.symbol_size.max(1));
    let configured_max = config.max_block_size.max(symbol_size);
    // E-12: large logical files must be split into bounded RaptorQ objects before
    // this transfer-wide block size is chosen. If an unsplit entry still exceeds
    // the one-byte SBN envelope, fail closed instead of raising K and making lossy
    // huge-file decode quadratic.
    let max_supported = max_object_size(configured_max);
    if max_entry_len > max_supported {
        return Err(RqError::Coding(format!(
            "[ASUP-E803] ATP block-size planning failed: largest entry {max_entry_len} bytes exceeds supported max {max_supported} bytes"
        )));
    }

    let target = symbol_size
        .saturating_mul(TARGET_SOURCE_SYMBOLS_PER_BLOCK)
        .min(TARGET_STREAMING_BLOCK_BYTES);
    let min_for_block_limit = max_entry_len
        .div_ceil(MAX_SOURCE_BLOCKS)
        .max(symbol_size)
        .div_ceil(symbol_size)
        .saturating_mul(symbol_size);

    // For entries within `256 * configured_max` (<= ~2 GiB at defaults),
    // `min_for_block_limit <= configured_max`, so this preserves the bounded
    // streaming target while honoring the SBN envelope.
    Ok(target
        .max(min_for_block_limit)
        .min(configured_max)
        .max(symbol_size))
}

/// Sender-side encoder state for one entry. Holds only source metadata; each
/// encode-ahead block is read on demand so the sender never retains the whole
/// object in memory.
struct EntryEncoder {
    index: u32,
    object_id: ObjectId,
    abs_path: PathBuf,
    source_offset: usize,
    size: usize,
    /// Cumulative repair symbols already requested from the encoder, indexed by
    /// source block. Feedback rounds request more and send only the newly-minted
    /// ones at their TRUE encoder ESIs — a RaptorQ repair symbol's payload is
    /// bound to its ESI, so it must never be relabeled.
    repair_cursors: Vec<usize>,
}

/// Receiver-side decoder state for one entry.
struct EntryDecoder {
    index: u32,
    object_id: ObjectId,
    size: u64,
    /// `Option` so completed entries can drop decoder state after streaming all
    /// blocks to disk.
    pipeline: Option<DecodingPipeline>,
    complete: bool,
    staging_path: PathBuf,
    /// Entry-relative writes are offset by this amount inside `staging_path`.
    /// Normal entries keep zero; single-file large fragments share one logical
    /// staging file and write at their logical offset.
    staging_write_offset: u64,
    /// Size to pre-create for `staging_path`. This is usually `size`; shared
    /// fragment staging uses the whole logical file size.
    staging_file_len: u64,
    /// Allows multiple fragment decoders to open the same pre-created logical
    /// staging file instead of treating `AlreadyExists` as hostile.
    staging_shared: bool,
    staging_created: bool,
    staging_file: Option<crate::fs::File>,
    staging_cursor: Option<u64>,
    staging_unflushed_bytes: usize,
    cache_staging_file: bool,
    bytes_written: u64,
    max_block_size: usize,
    source_streaming: bool,
    source_blocks: Vec<SourceBlockProgress>,
    pending_decodes: Vec<PendingDecode>,
    source_write_buffer: Vec<u8>,
    source_write_buffer_offset: Option<u64>,
    /// Incremental SHA-256 + content-id over the control-source-stream bytes,
    /// folded in receive order (the source-stream path enforces strictly
    /// in-order contiguous writes, so this equals the post-stream digest).
    /// `Some` only on the reliable control-source-stream path; the lossy
    /// RaptorQ-datagram path leaves this `None` and verifies post-stream.
    inc: Option<crate::net::atp::transport_common::StagedEntryReceive>,
    /// Finalized `(size, content_id, content_sha256)` once the entry completes,
    /// letting commit skip the post-stream staging-file re-read+hash.
    inc_digest: Option<(u64, crate::atp::object::ObjectId, [u8; 32])>,
}

struct PendingDecode {
    block_sbn: u8,
    handle: crate::runtime::TaskHandle<BlockDecodeOutcome>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DecodeDispatch {
    Queued,
    NoProgress,
}

#[derive(Debug, Clone, Copy)]
struct DecodeDispatchOutcome {
    dispatch: DecodeDispatch,
    decode_stats: RqDecodeRoundStats,
}

impl DecodeDispatchOutcome {
    fn new(dispatch: DecodeDispatch, decode_stats: RqDecodeRoundStats) -> Self {
        Self {
            dispatch,
            decode_stats,
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct RqSymbolFeed {
    accepted: bool,
    source_auth_micros: u64,
    source_persist_micros: u64,
    pipeline_feed_micros: u64,
    block_persist_micros: u64,
    decode_dispatch_micros: u64,
    source_seed_micros: u64,
    decode_stats: RqDecodeRoundStats,
}

#[derive(Debug, Default, Clone, Copy)]
struct SourceStreamingSeedStats {
    seeded: u64,
    decode_stats: RqDecodeRoundStats,
}

fn should_cache_entry_staging_file(
    entry_size: u64,
    manifest_entries: usize,
    packed_members: usize,
) -> bool {
    let bounded_manifest = manifest_entries <= ENTRY_STAGING_FILE_CACHE_MAX_ENTRIES;
    let large_entry_cache = entry_size >= ENTRY_STAGING_FILE_CACHE_MIN_BYTES && bounded_manifest;
    let packed_tree_batch = packed_members > 0 && entry_size > 0 && bounded_manifest;

    large_entry_cache || packed_tree_batch
}

fn is_round_scoped_entry_staging_cache(dec: &EntryDecoder) -> bool {
    dec.cache_staging_file && dec.size < ENTRY_STAGING_FILE_CACHE_MIN_BYTES
}

fn entry_source_block_count_for_geometry(
    entry_size: u64,
    max_block_size: usize,
    observed_source_blocks: usize,
) -> usize {
    let max_block_size = u64::try_from(max_block_size.max(1)).unwrap_or(u64::MAX);
    let planned_blocks = usize::try_from(entry_size.div_ceil(max_block_size)).unwrap_or(usize::MAX);
    observed_source_blocks.max(planned_blocks).max(1)
}

fn entry_source_block_count(dec: &EntryDecoder) -> usize {
    entry_source_block_count_for_geometry(dec.size, dec.max_block_size, dec.source_blocks.len())
}

fn source_streaming_entry_complete(dec: &EntryDecoder) -> bool {
    !dec.source_blocks.is_empty() && dec.bytes_written == dec.size
}

fn single_file_fragment_staging_path(
    manifest: &TransferManifest,
    staging_dir: &Path,
) -> Option<PathBuf> {
    if manifest.is_directory || manifest.entries.is_empty() {
        return None;
    }

    let first_rel_path = manifest
        .entries
        .first()?
        .fragment
        .as_ref()?
        .rel_path
        .as_str();
    let all_same_fragment = manifest.entries.iter().all(|entry| {
        entry
            .fragment
            .as_ref()
            .is_some_and(|fragment| fragment.rel_path == first_rel_path)
    });
    all_same_fragment.then(|| {
        staging_dir
            .join(RQ_SINGLE_FILE_FRAGMENT_STAGING_DIR)
            .join("0")
    })
}

fn receive_staging_layout_for_entry(
    entry: &ManifestEntry,
    staging_dir: &Path,
    single_file_fragment_staging_path: Option<&Path>,
) -> (PathBuf, u64, u64, bool) {
    if let (Some(fragment), Some(staging_path)) =
        (entry.fragment.as_ref(), single_file_fragment_staging_path)
    {
        return (
            staging_path.to_path_buf(),
            fragment.logical_offset,
            fragment.logical_size,
            true,
        );
    }

    (
        staging_dir.join(entry.index.to_string()),
        0,
        entry.size,
        false,
    )
}

fn entry_staging_absolute_offset(
    dec: &EntryDecoder,
    offset: u64,
    len: usize,
) -> Result<u64, RqError> {
    let len = u64::try_from(len).unwrap_or(u64::MAX);
    let entry_end = offset
        .checked_add(len)
        .ok_or_else(|| RqError::Coding(format!("entry {} staging range overflow", dec.index)))?;
    if entry_end > dec.size {
        return Err(RqError::Frame(format!(
            "entry {} staging write range {}..{} overruns declared size {}",
            dec.index, offset, entry_end, dec.size
        )));
    }

    let absolute = dec
        .staging_write_offset
        .checked_add(offset)
        .ok_or_else(|| {
            RqError::Coding(format!(
                "entry {} shared staging offset overflow",
                dec.index
            ))
        })?;
    let absolute_end = absolute.checked_add(len).ok_or_else(|| {
        RqError::Coding(format!("entry {} shared staging range overflow", dec.index))
    })?;
    if absolute_end > dec.staging_file_len {
        return Err(RqError::Frame(format!(
            "entry {} staging write range {}..{} overruns staging file size {}",
            dec.index, absolute, absolute_end, dec.staging_file_len
        )));
    }

    Ok(absolute)
}

fn decoder_position_for_entry(decoders: &[EntryDecoder], entry: u32) -> Option<usize> {
    let direct = usize::try_from(entry).ok()?;
    if decoders
        .get(direct)
        .is_some_and(|decoder| decoder.index == entry)
    {
        return Some(direct);
    }
    decoders.iter().position(|decoder| decoder.index == entry)
}

/// Build the RaptorQ decode state for one UDP-fed manifest entry.
///
/// Shared by the single-source receive path (`receive_connection`) and the
/// bonded N-donor receive path (`receive_bonded`) so both configure the
/// per-entry [`DecodingPipeline`] identically — the z01bbr.8.5 invariant is
/// that a one-donor bonded receive is isomorphic to today's receive path.
#[allow(clippy::too_many_arguments)]
fn new_udp_entry_decode_state(
    e: &ManifestEntry,
    object_id: ObjectId,
    symbol_size: u16,
    receiver_max_block_size: usize,
    wire_max_block_size: u64,
    config: &RqConfig,
    symbol_auth: Option<&SecurityContext>,
    source_streaming: bool,
) -> (Option<DecodingPipeline>, bool, Vec<SourceBlockProgress>) {
    let dconfig = DecodingConfig {
        symbol_size,
        max_block_size: receiver_max_block_size,
        repair_overhead: config.repair_overhead,
        min_overhead: 0,
        // RQ repair rows are round-critical: dropping an undecoded
        // block's repair symbols makes the sender re-spray another
        // round. Keep them until block completion; mark_block_complete
        // clears the block immediately after decode.
        max_buffered_symbols: RQ_REPAIR_RECEIVE_SYMBOL_CAP_PER_BLOCK,
        block_timeout: std::time::Duration::from_secs(0),
        verify_auth: symbol_auth.is_some(),
    };
    let mut pipeline = if let Some(context) = symbol_auth {
        DecodingPipeline::with_auth(dconfig, context.clone())
    } else {
        DecodingPipeline::new(dconfig)
    };
    let params = object_params_for(object_id, e.size, symbol_size, wire_max_block_size);
    // set_object_params failure is a metadata bug, surfaced on first feed.
    if let Err(err) = pipeline.set_object_params(params) {
        rqtrace!(
            "receiver: entry {} set_object_params FAILED: {err:?} (size={}, blocks={}, k={})",
            e.index,
            e.size,
            params.source_blocks,
            params.symbols_per_block
        );
    }
    let source_blocks = source_block_progress_for(e.size, receiver_max_block_size, symbol_size);
    let entry_source_streaming = source_streaming && source_blocks.is_some();
    (
        Some(pipeline),
        entry_source_streaming,
        source_blocks.unwrap_or_default(),
    )
}

#[cfg(test)]
fn should_parallel_decode_entry_geometry(
    entry_size: u64,
    max_block_size: usize,
    observed_source_blocks: usize,
) -> bool {
    entry_size >= RQ_PARALLEL_DECODE_MIN_ENTRY_BYTES
        && entry_source_block_count_for_geometry(entry_size, max_block_size, observed_source_blocks)
            >= RQ_PARALLEL_DECODE_MIN_SOURCE_BLOCKS
}

fn should_parallel_decode_entry(dec: &EntryDecoder) -> bool {
    dec.size >= RQ_PARALLEL_DECODE_MIN_ENTRY_BYTES
        && entry_source_block_count(dec) >= RQ_PARALLEL_DECODE_MIN_SOURCE_BLOCKS
}

fn transfer_decode_size_gate(decoders: &[EntryDecoder]) -> usize {
    if decoders.is_empty() || decoders.iter().any(should_parallel_decode_entry) {
        RQ_MAX_PENDING_DECODE_JOBS_PER_TRANSFER_HARD
    } else {
        0
    }
}

fn entry_decode_width_budget(dec: &EntryDecoder, transfer_decode_width: usize) -> usize {
    if !should_parallel_decode_entry(dec) {
        return 0;
    }
    let block_count = entry_source_block_count(dec);
    block_count
        .min(RQ_MAX_PENDING_DECODE_JOBS_PER_ENTRY)
        .min(transfer_decode_width.max(1))
        .max(1)
}

#[cfg(test)]
fn entry_decode_width_budget_for_geometry(
    entry_size: u64,
    max_block_size: usize,
    observed_source_blocks: usize,
    transfer_decode_width: usize,
) -> usize {
    if !should_parallel_decode_entry_geometry(entry_size, max_block_size, observed_source_blocks) {
        return 0;
    }
    let block_count =
        entry_source_block_count_for_geometry(entry_size, max_block_size, observed_source_blocks);
    block_count
        .min(RQ_MAX_PENDING_DECODE_JOBS_PER_ENTRY)
        .min(transfer_decode_width.max(1))
        .max(1)
}

fn can_spawn_parallel_decode(pending_decodes: usize, entry_decode_width: usize) -> bool {
    entry_decode_width > 1 && pending_decodes < entry_decode_width
}

fn rq_decode_job_memory_estimate_bytes(max_block_size: usize, symbol_size: u16) -> usize {
    let retained_symbol_bytes = rq_max_buffered_symbols_per_block(max_block_size, symbol_size)
        .saturating_mul(usize::from(symbol_size.max(1)));
    retained_symbol_bytes
        .saturating_mul(RQ_DECODE_JOB_SYMBOL_MEMORY_MULTIPLIER)
        .max(RQ_DECODE_JOB_MEMORY_FLOOR_BYTES)
}

#[derive(Debug, Clone, Copy)]
struct RqDecodeWidthBudget {
    effective: usize,
    core_limit: usize,
    memory_limit: usize,
    job_memory_bytes: usize,
    max_block_size: usize,
}

fn rq_decode_reserved_io_cores(available: usize) -> usize {
    if available <= 1 {
        return 0;
    }
    (available / 4)
        .clamp(
            RQ_DECODE_MIN_CORES_RESERVED_FOR_IO,
            RQ_DECODE_MAX_CORES_RESERVED_FOR_IO,
        )
        .min(available.saturating_sub(1))
}

fn rq_decode_core_limit_for_available(available: usize) -> usize {
    available
        .saturating_sub(rq_decode_reserved_io_cores(available))
        .max(1)
        .min(RQ_MAX_PENDING_DECODE_JOBS_PER_TRANSFER_HARD)
}

fn rq_decode_core_limit() -> usize {
    static CORE_LIMIT: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *CORE_LIMIT.get_or_init(|| {
        let available = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
        rq_decode_core_limit_for_available(available)
    })
}

fn rq_decode_core_limit_for_cx(cx: &Cx) -> usize {
    // ATP CLI/daemon runtimes size a blocking pool explicitly for CPU-heavy
    // RaptorQ work. Prefer that live cap over process CPU discovery so cgroup
    // or container affinity quirks do not collapse receiver decode to one lane.
    cx.blocking_pool_handle()
        .map_or_else(rq_decode_core_limit, |pool| {
            rq_decode_core_limit_for_available(pool.current_max_threads())
        })
}

fn rq_decode_width_budget_snapshot_for_core_limit(
    decoders: &[EntryDecoder],
    symbol_size: u16,
    core_limit: usize,
) -> RqDecodeWidthBudget {
    let max_block_size = decoders
        .iter()
        .map(|decoder| decoder.max_block_size)
        .max()
        .unwrap_or(DEFAULT_MAX_BLOCK_SIZE);
    let job_memory_bytes = rq_decode_job_memory_estimate_bytes(max_block_size, symbol_size);
    let memory_limit = RQ_DECODE_JOB_MEMORY_BUDGET_BYTES
        .checked_div(job_memory_bytes)
        .unwrap_or(1)
        .max(1);
    let size_gate = transfer_decode_size_gate(decoders);
    RqDecodeWidthBudget {
        effective: core_limit.min(memory_limit).min(size_gate),
        core_limit,
        memory_limit,
        job_memory_bytes,
        max_block_size,
    }
}

#[cfg(test)]
fn rq_decode_width_budget_snapshot(
    decoders: &[EntryDecoder],
    symbol_size: u16,
) -> RqDecodeWidthBudget {
    rq_decode_width_budget_snapshot_for_core_limit(decoders, symbol_size, rq_decode_core_limit())
}

fn rq_decode_width_budget_snapshot_for_cx(
    cx: &Cx,
    decoders: &[EntryDecoder],
    symbol_size: u16,
) -> RqDecodeWidthBudget {
    rq_decode_width_budget_snapshot_for_core_limit(
        decoders,
        symbol_size,
        rq_decode_core_limit_for_cx(cx),
    )
}

fn rq_decode_width_budget_for_cx(cx: &Cx, decoders: &[EntryDecoder], symbol_size: u16) -> usize {
    rq_decode_width_budget_snapshot_for_cx(cx, decoders, symbol_size).effective
}

fn block_decode_pending(dec: &EntryDecoder, block_sbn: u8) -> bool {
    dec.pending_decodes
        .iter()
        .any(|pending| pending.block_sbn == block_sbn)
}

fn rq_pending_decode_jobs(decoders: &[EntryDecoder]) -> usize {
    decoders
        .iter()
        .map(|decoder| decoder.pending_decodes.len())
        .sum()
}

fn source_streaming_block_ready_to_seed(dec: &EntryDecoder, sbn: usize) -> bool {
    let Some(block) = dec.source_blocks.get(sbn) else {
        return false;
    };
    if block.complete {
        return false;
    }
    let Ok(block_sbn) = u8::try_from(sbn) else {
        return false;
    };
    let Some(status) = dec
        .pipeline
        .as_ref()
        .and_then(|pipeline| pipeline.block_status(block_sbn))
    else {
        return false;
    };
    let unseeded_sources = block
        .received
        .iter()
        .zip(&block.pipeline_seeded)
        .filter(|(received, seeded)| **received && !**seeded)
        .count();

    status.symbols_received.saturating_add(unseeded_sources) >= block.k
}

fn source_seed_symbol_plan(
    dec: &EntryDecoder,
    sbn: usize,
    esi: usize,
    symbol_size: usize,
) -> Result<Option<(usize, usize, Option<AuthenticationTag>)>, RqError> {
    let Some(block) = dec.source_blocks.get(sbn) else {
        return Ok(None);
    };
    if esi >= block.k || !block.received[esi] || block.pipeline_seeded[esi] || block.complete {
        return Ok(None);
    }

    let Some(within_block) = esi.checked_mul(symbol_size) else {
        return Err(RqError::Coding(format!(
            "entry {} source seed offset overflow",
            dec.index
        )));
    };
    if within_block >= block.len {
        return Ok(None);
    }

    let take = symbol_size.min(block.len - within_block);
    Ok(Some((within_block, take, block.auth_tags[esi])))
}

fn rq_max_buffered_symbols_per_block(max_block_size: usize, symbol_size: u16) -> usize {
    let symbol_size = usize::from(symbol_size.max(1));
    let k = max_block_size.div_ceil(symbol_size).max(1);
    let repair_extra = k.max(RQ_REPAIR_SYMBOL_RETENTION_MIN_EXTRA);
    k.saturating_add(repair_extra)
}

#[derive(Debug)]
struct SourceBlockProgress {
    start: u64,
    len: usize,
    k: usize,
    received: Vec<bool>,
    pipeline_seeded: Vec<bool>,
    auth_tags: Vec<Option<AuthenticationTag>>,
    received_count: usize,
    complete: bool,
}

/// Best-effort backstop for receive staging directories.
///
/// The RQ receiver creates a per-transfer staging directory before it starts
/// accepting untrusted UDP symbols. Normal and error exits should not leave
/// hidden payload fragments under the destination, and cancellation can drop the
/// future before it reaches a cooperative return path. This mirrors the TCP
/// transport's staging guard.
struct RqStagingDirGuard {
    dir: PathBuf,
    armed: bool,
}

impl RqStagingDirGuard {
    fn new(dir: PathBuf) -> Self {
        Self { dir, armed: true }
    }

    fn dir(&self) -> &Path {
        &self.dir
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for RqStagingDirGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
}

// ─── Public API: send ────────────────────────────────────────────────────────

/// Transfer the file or directory at `source` to `addr` (the receiver's TCP
/// control address) using RaptorQ symbols over UDP.
///
/// Returns the receiver's verified receipt. Fails closed on an unreachable peer,
/// a rejected handshake, a size-limit breach, a fountain loop that does not
/// converge, or a receiver integrity rejection.
pub async fn send_path(
    cx: &Cx,
    addr: SocketAddr,
    source: &Path,
    mut config: RqConfig,
    peer_id: &str,
) -> Result<SendReport, RqError> {
    cx.checkpoint().map_err(|_| RqError::Cancelled)?;
    if config.delta_control_timeout.is_zero() {
        return Err(RqError::Control(
            "RQ delta_control_timeout must be greater than zero".to_string(),
        ));
    }
    let symbol_auth = config.symbol_auth_context()?;
    let symbol_auth_enabled = symbol_auth.is_some();

    let (root_name, is_directory, mut raw_entries, empty_directories) =
        collect_entries(source).await?;
    capture_source_metadata(
        &mut raw_entries,
        &config.metadata_policy,
        config.preserve_hardlinks,
    )
    .await?;
    let directory_metadata = if is_directory {
        capture_rq_directory_metadata_manifest(source, &empty_directories, &config.metadata_policy)
            .await?
    } else {
        DirectoryMetadataManifest::default()
    };
    let preflight_total_bytes = source_entries_total_bytes(&raw_entries).await?;
    if preflight_total_bytes > config.max_transfer_bytes {
        return Err(RqError::TooLarge {
            size: preflight_total_bytes,
            max: config.max_transfer_bytes,
        });
    }
    let delta_hash_first_candidate = config.enable_delta
        && rq_delta_control_auth_context(&config).is_some()
        && !is_directory
        && raw_entries.len() == 1
        && preflight_total_bytes.div_ceil(u64::try_from(RQ_DELTA_CHUNK_SIZE).unwrap_or(u64::MAX))
            <= RQ_DELTA_MAX_MANIFEST_CHUNKS;
    let prefer_control_source_stream =
        control_source_stream_eligible(preflight_total_bytes, &config)
            && !delta_hash_first_candidate;
    if prefer_control_source_stream {
        let stream = match crate::time::timeout(
            cx.now(),
            DEFAULT_CONNECT_TIMEOUT,
            TcpStream::connect(addr),
        )
        .await
        {
            Ok(Ok(stream)) => stream,
            Ok(Err(err)) => {
                return Err(RqError::HandshakeRejected(format!(
                    "handshake unavailable while connecting to {addr}: {err}"
                )));
            }
            Err(_elapsed) => {
                return Err(RqError::HandshakeRejected(format!(
                    "handshake unavailable: connect to {addr} timed out after {DEFAULT_CONNECT_TIMEOUT:?}"
                )));
            }
        };
        tune_control_stream_for_bulk_source(&stream);
        let peer = stream.peer_addr().unwrap_or(addr);
        let mut control = FrameTransport::new(stream);
        let hello = json_frame(
            FrameType::Handshake,
            &Hello {
                protocol: ATP_RQ_PROTOCOL,
                role: "sender".to_string(),
                peer_id: peer_id.to_string(),
                symbol_size: config.symbol_size,
                max_block_size: config.max_block_size as u64,
                symbol_auth: symbol_auth_enabled,
                total_bytes: preflight_total_bytes,
                prefer_control_source_stream,
                delta_transfer_nonce: None,
                delta_client_auth_tag: None,
            },
        )?;
        control
            .send(&hello)
            .await
            .map_err(|err| sender_handshake_transport_error("send sender handshake", err))?;
        let ack = receive_sender_handshake_ack(cx, &mut control, DEFAULT_CONNECT_TIMEOUT).await?;
        if !ack.control_source_stream {
            return Err(RqError::HandshakeRejected(
                "receiver declined required control source stream".to_string(),
            ));
        }

        let prepared = prepare_control_source_transfer(
            root_name,
            is_directory,
            raw_entries,
            directory_metadata.clone(),
            &config,
            preflight_total_bytes,
        )
        .await?;
        let transfer_id = prepared.manifest.transfer_id.clone();
        let total_bytes = prepared.manifest.total_bytes;
        let mut encoders: Vec<EntryEncoder> = Vec::with_capacity(prepared.entries.len());
        for (i, (entry, size)) in prepared
            .entries
            .iter()
            .zip(prepared.object_sizes.iter())
            .enumerate()
        {
            let index = u32::try_from(i).unwrap_or(u32::MAX);
            let size = usize::try_from(*size).map_err(|_| RqError::TooLarge {
                size: *size,
                max: u64::try_from(usize::MAX).unwrap_or(u64::MAX),
            })?;
            let source_offset =
                usize::try_from(entry.source_offset).map_err(|_| RqError::TooLarge {
                    size: entry.source_offset,
                    max: u64::try_from(usize::MAX).unwrap_or(u64::MAX),
                })?;
            encoders.push(EntryEncoder {
                index,
                object_id: entry_object_id(&transfer_id, index),
                abs_path: entry.abs_path.clone(),
                source_offset,
                size,
                repair_cursors: Vec::new(),
            });
        }

        control
            .send(&json_frame(FrameType::ObjectManifest, &prepared.manifest)?)
            .await?;
        let digest_report = stream_control_source_entries(
            cx,
            &mut control,
            &encoders,
            &prepared.manifest,
            &prepared.precomputed_logical_digests,
            &transfer_id,
            symbol_auth.as_ref(),
        )
        .await?;
        if digest_report.bytes_streamed != total_bytes {
            return Err(RqError::Source(format!(
                "control source stream sent {} bytes, expected {total_bytes}",
                digest_report.bytes_streamed
            )));
        }
        let files = u32::try_from(digest_report.logical_digests.len()).unwrap_or(u32::MAX);
        let merkle_root_hex = digest_report.merkle_root_hex.clone();
        control
            .send(&json_frame(
                FrameType::ObjectComplete,
                &RqRoundComplete {
                    round_symbols_sent: 0,
                    entry_digests: digest_report.entry_digests,
                    logical_digests: digest_report.logical_digests,
                    merkle_root_hex: Some(merkle_root_hex.clone()),
                },
            )?)
            .await?;
        let reply = control.recv().await?;
        if reply.frame_type() != FrameType::Proof {
            return Err(RqError::Unexpected {
                got: reply.frame_type(),
                expected: "Proof",
            });
        }
        let receipt: ReceiveReceipt = parse_json(&reply)?;
        let _ = control
            .send(&Frame::empty(FrameType::Close).map_err(|e| RqError::Frame(e.to_string()))?)
            .await;
        if !receipt.committed {
            return Err(RqError::Integrity(
                receipt
                    .reason
                    .clone()
                    .unwrap_or_else(|| "receiver did not commit".to_string()),
            ));
        }
        return Ok(SendReport {
            transfer_id,
            bytes_sent: total_bytes,
            files,
            symbols_sent: 0,
            feedback_rounds: 0,
            merkle_root_hex,
            receipt,
            udp_send_acceleration: UdpSendAccelerationReport::default(),
            peer,
        });
    }

    // E-15: coalesce sub-threshold files into fewer/larger combined RaptorQ
    // objects. `entries` are the OBJECTS to spray (a packed entry's `abs_path`
    // points at a temp file holding the member concatenation); `logical_digests`
    // are the per-LOGICAL-FILE digests that drive the merkle root. For the
    // no-packing case `entries == raw_entries` and `logical_digests` equals the
    // per-file digests, so everything is byte-identical to a prior transfer. The
    // temp dir owns every pack temp file and must outlive the spray loop below.
    let metadata = metadata_manifest_from_source_entries(&raw_entries, directory_metadata);
    let (packed_entries, logical_digests, _pack_tempdir) =
        pack_small_files(raw_entries, &config).await?;
    let entries = split_large_entries(packed_entries, &logical_digests, &config).await?;

    let mut hash_buf = vec![0u8; RQ_STREAM_HASH_BUFFER_SIZE];
    // Per-OBJECT digests: size + sha of each entry's `abs_path` (the temp file for
    // packed entries). These feed the manifest entry size/sha (object-level verify)
    // and the effective block size — they describe the RaptorQ objects on the wire.
    let mut digests = Vec::with_capacity(entries.len());
    let mut total_bytes = 0u64;
    for entry in &entries {
        let (size, content_id, content_sha256) = hash_source_entry_streaming(entry, &mut hash_buf)
            .await
            .map_err(|e| RqError::Source(e.into_message()))?;
        total_bytes = total_bytes.checked_add(size).ok_or(RqError::TooLarge {
            size: u64::MAX,
            max: config.max_transfer_bytes,
        })?;
        if total_bytes > config.max_transfer_bytes {
            return Err(RqError::TooLarge {
                size: total_bytes,
                max: config.max_transfer_bytes,
            });
        }
        digests.push(EntryDigest {
            rel_path: entry.rel_path.clone(),
            size,
            content_id,
            content_sha256,
        });
    }
    config.max_block_size = effective_transfer_max_block_size(&config, &digests)?;

    // Merkle root is over the LOGICAL files (members flattened), identical on both
    // sides regardless of how files were packed into objects.
    let merkle_root_hex = flat_merkle_root_from_digests(&logical_digests);
    let manifest_entries: Vec<ManifestEntry> = entries
        .iter()
        .zip(digests.iter())
        .enumerate()
        .map(|(i, (entry, digest))| ManifestEntry {
            index: u32::try_from(i).unwrap_or(u32::MAX),
            rel_path: digest.rel_path.clone(),
            size: digest.size,
            sha256_hex: hex_encode(&digest.content_sha256),
            members: entry.members.clone(),
            fragment: entry.fragment.clone(),
        })
        .collect();
    let packed_objects = manifest_entries
        .iter()
        .filter(|e| !e.members.is_empty())
        .count();
    rqtrace!(
        "sender: E-15 pack: {} logical files -> {} RaptorQ objects ({} packed)",
        logical_digests.len(),
        manifest_entries.len(),
        packed_objects
    );
    let transfer_id = transfer_id_hex(&merkle_root_hex, total_bytes, manifest_entries.len());
    let tag = transfer_tag(&transfer_id);
    let mut manifest = TransferManifest {
        transfer_id: transfer_id.clone(),
        root_name,
        is_directory,
        total_bytes,
        merkle_root_hex: merkle_root_hex.clone(),
        metadata: Some(metadata),
        delta_manifest: None,
        entries: manifest_entries,
    };
    maybe_attach_rq_delta_manifest(cx, &mut manifest, &entries, &config).await?;
    let delta_auth = rq_delta_control_auth_context(&config).cloned();
    let delta_transfer_nonce = if manifest.delta_manifest.is_some() && delta_auth.is_some() {
        Some(fresh_rq_delta_nonce(cx, b"sender", None)?)
    } else {
        None
    };
    let prefer_control_source_stream = control_source_stream_eligible(total_bytes, &config);

    // Control plane: TCP connect + handshake.
    let stream = match crate::time::timeout(
        cx.now(),
        DEFAULT_CONNECT_TIMEOUT,
        TcpStream::connect(addr),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(err)) => {
            return Err(RqError::HandshakeRejected(format!(
                "handshake unavailable while connecting to {addr}: {err}"
            )));
        }
        Err(_elapsed) => {
            return Err(RqError::HandshakeRejected(format!(
                "handshake unavailable: connect to {addr} timed out after {DEFAULT_CONNECT_TIMEOUT:?}"
            )));
        }
    };
    if prefer_control_source_stream {
        tune_control_stream_for_bulk_source(&stream);
    }
    let peer = stream.peer_addr().unwrap_or(addr);
    let mut control = FrameTransport::new(stream);
    let mut hello = Hello {
        protocol: ATP_RQ_PROTOCOL,
        role: "sender".to_string(),
        peer_id: peer_id.to_string(),
        symbol_size: config.symbol_size,
        max_block_size: config.max_block_size as u64,
        symbol_auth: symbol_auth_enabled,
        total_bytes,
        prefer_control_source_stream,
        delta_transfer_nonce,
        delta_client_auth_tag: None,
    };
    if delta_transfer_nonce.is_some() {
        let context = delta_auth.as_ref().ok_or_else(|| {
            RqError::Authentication(
                "RQ delta offer is missing its strict sender authentication context".to_string(),
            )
        })?;
        hello.delta_client_auth_tag = Some(sign_rq_delta_hello(context, &hello)?);
    }
    let hello_frame = json_frame(FrameType::Handshake, &hello)?;
    if delta_transfer_nonce.is_some() {
        send_delta_control_frame(
            cx,
            &mut control,
            &hello_frame,
            config.delta_control_timeout,
            "send delta handshake",
        )
        .await
        .map_err(|error| sender_handshake_transport_error("send delta handshake", error))?;
    } else {
        control
            .send(&hello_frame)
            .await
            .map_err(|err| sender_handshake_transport_error("send sender handshake", err))?;
    }
    let ack_timeout = if delta_transfer_nonce.is_some() {
        config.delta_control_timeout
    } else {
        DEFAULT_CONNECT_TIMEOUT
    };
    let ack = receive_sender_handshake_ack(cx, &mut control, ack_timeout)
        .await
        .map_err(|error| {
            if delta_transfer_nonce.is_some() {
                RqError::Authentication(format!(
                    "authenticated RQ delta acknowledgement unavailable: {error}"
                ))
            } else {
                error
            }
        })?;
    let delta_handshake = if let Some(context) = delta_auth.as_ref() {
        validate_rq_delta_ack(context, &hello, &ack)?
    } else if ack.delta_transfer_nonce.is_some()
        || ack.delta_receiver_nonce.is_some()
        || ack.delta_destination_root.is_some()
        || ack.delta_server_auth_tag.is_some()
    {
        return Err(RqError::HandshakeRejected(
            "receiver returned unsolicited RQ delta binding fields".to_string(),
        ));
    } else {
        None
    };
    if ack.control_source_stream && !prefer_control_source_stream {
        return Err(RqError::HandshakeRejected(
            "receiver selected control source stream for an ineligible transfer".to_string(),
        ));
    }
    let control_source_stream = ack.control_source_stream;
    if delta_transfer_nonce.is_some() && delta_handshake.is_none() {
        manifest.delta_manifest = None;
    }
    let delta_session = match delta_handshake {
        Some(handshake) => Some(derive_rq_delta_session(
            handshake,
            peer_id,
            &ack.peer_id,
            &manifest,
        )?),
        None => None,
    };
    let mut udp_ports = if control_source_stream {
        SmallVec::<[u16; DEFAULT_UDP_FANOUT]>::new()
    } else {
        hello_ack_udp_ports(&ack)
    };
    rqtrace!(
        "sender: handshake ok, peer udp_ports={:?} control_source_stream={}",
        udp_ports.as_slice(),
        control_source_stream
    );

    let mut encoders: Vec<EntryEncoder> = Vec::with_capacity(entries.len());
    for (i, (entry, digest)) in entries.iter().zip(digests.iter()).enumerate() {
        let index = u32::try_from(i).unwrap_or(u32::MAX);
        let size = usize::try_from(digest.size).map_err(|_| RqError::TooLarge {
            size: digest.size,
            max: u64::try_from(usize::MAX).unwrap_or(u64::MAX),
        })?;
        let source_offset =
            usize::try_from(entry.source_offset).map_err(|_| RqError::TooLarge {
                size: entry.source_offset,
                max: u64::try_from(usize::MAX).unwrap_or(u64::MAX),
            })?;
        encoders.push(EntryEncoder {
            index,
            object_id: entry_object_id(&transfer_id, index),
            abs_path: entry.abs_path.clone(),
            source_offset,
            size,
            repair_cursors: Vec::new(),
        });
    }

    // Complete the authenticated delta-control exchange before opening a data
    // socket or emitting any object byte. A signed full-object request falls
    // through to the ordinary RaptorQ path; a live no-op closes here.
    if let Some(session) = delta_session {
        let context = delta_auth.as_ref().ok_or_else(|| {
            RqError::Authentication(
                "RQ delta session is missing its strict authentication context".to_string(),
            )
        })?;
        let envelope = make_rq_delta_manifest_envelope(context, session, &manifest)?;
        let manifest_frame = json_frame(FrameType::ObjectManifest, &envelope)?;
        send_delta_control_frame(
            cx,
            &mut control,
            &manifest_frame,
            config.delta_control_timeout,
            "send authenticated manifest",
        )
        .await?;
        let request_frame = recv_delta_control_frame(
            cx,
            &mut control,
            config.delta_control_timeout,
            "receive authenticated object request",
        )
        .await?;
        if request_frame.frame_type() != FrameType::ObjectRequest {
            return Err(RqError::Unexpected {
                got: request_frame.frame_type(),
                expected: "authenticated ObjectRequest",
            });
        }
        let request: RqDeltaObjectRequestEnvelope = parse_json(&request_frame)?;
        match validate_rq_delta_request_envelope(
            context,
            session,
            &manifest,
            &request,
            control_source_stream,
        )? {
            DeltaWireMode::FullObject => {
                udp_ports = advertised_udp_ports(request.udp_port, &request.udp_ports);
            }
            DeltaWireMode::AlreadyInSync => {
                validate_rq_delta_source_unchanged(cx, &manifest, &entries, &config).await?;
                let complete = make_rq_delta_complete(context, session, &manifest)?;
                let complete_frame = json_frame(FrameType::ObjectComplete, &complete)?;
                send_delta_control_frame(
                    cx,
                    &mut control,
                    &complete_frame,
                    config.delta_control_timeout,
                    "send authenticated zero completion",
                )
                .await?;
                let proof_frame = recv_delta_control_frame(
                    cx,
                    &mut control,
                    config.delta_control_timeout,
                    "receive authenticated no-op proof",
                )
                .await?;
                if proof_frame.frame_type() != FrameType::Proof {
                    return Err(RqError::Unexpected {
                        got: proof_frame.frame_type(),
                        expected: "authenticated Proof",
                    });
                }
                let proof: RqDeltaProofEnvelope = parse_json(&proof_frame)?;
                let receipt = validate_rq_delta_proof(context, session, &manifest, proof)?;
                let close = Frame::empty(FrameType::Close)
                    .map_err(|error| RqError::Frame(error.to_string()))?;
                send_delta_control_frame(
                    cx,
                    &mut control,
                    &close,
                    config.delta_control_timeout,
                    "send authenticated delta close",
                )
                .await?;
                return Ok(SendReport {
                    transfer_id,
                    bytes_sent: 0,
                    files: 1,
                    symbols_sent: 0,
                    feedback_rounds: 0,
                    merkle_root_hex,
                    receipt,
                    udp_send_acceleration: UdpSendAccelerationReport::default(),
                    peer,
                });
            }
            DeltaWireMode::DeltaChunks => {
                return Err(RqError::Control(
                    "RQ missing-chunk mode passed strict request validation".to_string(),
                ));
            }
        }
    } else {
        control
            .send(&json_frame(FrameType::ObjectManifest, &manifest)?)
            .await?;
    }

    if control_source_stream {
        let digest_report = stream_control_source_entries(
            cx,
            &mut control,
            &encoders,
            &manifest,
            &logical_digests,
            &transfer_id,
            symbol_auth.as_ref(),
        )
        .await?;
        if digest_report.bytes_streamed != total_bytes {
            return Err(RqError::Source(format!(
                "control source stream sent {} bytes, expected {total_bytes}",
                digest_report.bytes_streamed
            )));
        }
        let merkle_root_hex = digest_report.merkle_root_hex.clone();
        control
            .send(&json_frame(
                FrameType::ObjectComplete,
                &RqRoundComplete {
                    round_symbols_sent: 0,
                    entry_digests: digest_report.entry_digests,
                    logical_digests: digest_report.logical_digests,
                    merkle_root_hex: Some(merkle_root_hex.clone()),
                },
            )?)
            .await?;
        let reply = control.recv().await?;
        if reply.frame_type() != FrameType::Proof {
            return Err(RqError::Unexpected {
                got: reply.frame_type(),
                expected: "Proof",
            });
        }
        let receipt: ReceiveReceipt = parse_json(&reply)?;
        let _ = control
            .send(&Frame::empty(FrameType::Close).map_err(|e| RqError::Frame(e.to_string()))?)
            .await;
        if !receipt.committed {
            return Err(RqError::Integrity(
                receipt
                    .reason
                    .clone()
                    .unwrap_or_else(|| "receiver did not commit".to_string()),
            ));
        }
        return Ok(SendReport {
            transfer_id,
            bytes_sent: total_bytes,
            files: u32::try_from(logical_digests.len()).unwrap_or(u32::MAX),
            symbols_sent: 0,
            feedback_rounds: 0,
            merkle_root_hex,
            receipt,
            udp_send_acceleration: UdpSendAccelerationReport::default(),
            peer,
        });
    }

    // Data plane: open UDP sockets connected across the receiver's advertised UDP fanout.
    let fanout = config.udp_fanout.max(1);
    let mut adaptive = RqAdaptiveSendState::new(tag, &config, fanout);
    let local_unspec = if peer.ip().is_ipv4() {
        std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
    } else {
        std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
    };
    let mut sockets: Vec<UdpSocket> = Vec::with_capacity(fanout);
    for socket_index in 0..fanout {
        let udp_addr = receiver_udp_addr_for_socket(peer, &udp_ports, socket_index)?;
        let sock = UdpSocket::bind(SocketAddr::new(local_unspec, 0)).await?;
        sock.connect(udp_addr).await?;
        // Large send buffer absorbs bursts so the spray loop does not busy-spin
        // on `ENOBUFS`/`WouldBlock` (UDP sockets epoll-report writable even when
        // the send buffer is full).
        let _ = sock.tune_buffers(UdpBufferConfig {
            send_buffer_bytes: Some(16 * 1024 * 1024),
            recv_buffer_bytes: None,
        });
        sockets.push(sock);
    }

    let mut symbols_sent: u64 = 0;
    let mut rr = 0usize;
    let mut dropper = 0u32;
    let mut feedback_rounds = 0u32;
    let mut source_fec_fallback_active = false;
    let mut udp_send_acceleration = UdpSendAccelerationReport::default();

    // Parallel per-block encode is on by default while the transfer is small enough that the
    // receiver's recv buffer can absorb the burst (see PARALLEL_ENCODE_MAX_BYTES). Larger
    // loss-targeted transfers use a much smaller encode window: the pacer still owns wire rate,
    // but the sender is no longer forced to mint every source+repair block on one core.
    let parallel_encode_plan = parallel_encode_plan_for_transfer(total_bytes, &config);
    rqtrace!(
        "sender: encode_plan total_bytes={} entries={} parallel_encode_batch_blocks={}",
        total_bytes,
        manifest.entries.len(),
        parallel_encode_plan
            .map(|plan| plan.max_batch_blocks)
            .unwrap_or(0),
    );

    // Round 0: every entry, source symbols plus optional repair_overhead extra.
    let mut pending: BTreeSet<u32> = encoders.iter().map(|e| e.index).collect();
    let round0_small_clean_source_only = small_clean_source_only_round0(total_bytes, &config);
    let mut round_tuning =
        apply_small_clean_round0_source_only(total_bytes, &config, adaptive.round0_tuning(&config));
    if round0_small_clean_source_only {
        rqtrace!(
            "sender: round0_small_clean_source_only total_bytes={} repair_overhead={:.4}",
            total_bytes,
            round_tuning.repair_overhead
        );
    }
    // One token bucket owns the whole transfer. Recreating it per source/repair
    // spray would grant a fresh burst each time and overflow rate-capped qdiscs.
    let mut pacer =
        RqSprayPacer::new_round0(round_tuning.pacing, &config, round0_small_clean_source_only);
    let mut round_started = Instant::now();
    let mut round_symbols_start = symbols_sent;
    let mut round_delivery_sample_kind = RqDeliverySampleKind::InitialOrRepair;
    spray_round(
        cx,
        &mut control,
        &mut adaptive,
        &mut sockets,
        &mut rr,
        &mut symbols_sent,
        &mut dropper,
        tag,
        &mut encoders,
        &pending,
        &config,
        &mut pacer,
        &round_tuning,
        symbol_auth.as_ref(),
        &mut udp_send_acceleration,
        /* with_source */ true,
        round0_small_clean_source_only,
        parallel_encode_plan,
    )
    .await?;
    let mut round_send_wall = round_started.elapsed();
    rqtrace!("sender: round 0 sprayed, symbols_sent={symbols_sent}");

    // Feedback loop.
    let mut peak_sender_window_bytes = 0u64;
    loop {
        let control_wait_started = Instant::now();
        let sent_this_round = symbols_sent.saturating_sub(round_symbols_start);
        control
            .send(&json_frame(
                FrameType::ObjectComplete,
                &RqRoundComplete {
                    round_symbols_sent: sent_this_round,
                    ..RqRoundComplete::default()
                },
            )?)
            .await?;
        rqtrace!("sender: sent ObjectComplete, awaiting reply");
        let reply = control.recv().await?;
        let control_wait = control_wait_started.elapsed();
        let window_probe = RqSenderWindowProbe::new(
            pacer.pacing(),
            sent_this_round,
            config.symbol_size,
            round_send_wall,
            control_wait,
        );
        let window_probe_phase = match reply.frame_type() {
            FrameType::Proof => "proof",
            FrameType::ObjectRequest => "need_more",
            FrameType::KeepAlive => "keep_alive",
            _ => "other",
        };
        peak_sender_window_bytes = peak_sender_window_bytes.max(window_probe.peak_window_bytes());
        trace_sender_window_probe(
            window_probe_phase,
            feedback_rounds,
            window_probe,
            peak_sender_window_bytes,
            udp_send_acceleration,
        );
        rqtrace!("sender: got reply {:?}", reply.frame_type());
        match reply.frame_type() {
            FrameType::Proof => {
                adaptive.observe_probe_success(
                    &config,
                    sent_this_round,
                    round_send_wall,
                    control_wait,
                );
                let receipt: ReceiveReceipt = parse_json(&reply)?;
                let _ = control
                    .send(
                        &Frame::empty(FrameType::Close)
                            .map_err(|e| RqError::Frame(e.to_string()))?,
                    )
                    .await;
                if !receipt.committed {
                    return Err(RqError::Integrity(
                        receipt
                            .reason
                            .clone()
                            .unwrap_or_else(|| "receiver did not commit".to_string()),
                    ));
                }
                rqtrace!(
                    "sender: udp_send_acceleration flushes={} datagrams={} payload_bytes={} native_flushes={} native_datagrams={} gso_flushes={} gso_datagrams={} fallback_flushes={} fallback_datagrams={} partial_flushes={} error_flushes={}",
                    udp_send_acceleration.flushes,
                    udp_send_acceleration.datagrams,
                    udp_send_acceleration.payload_bytes,
                    udp_send_acceleration.native_batch_flushes,
                    udp_send_acceleration.native_batch_datagrams,
                    udp_send_acceleration.gso_flushes,
                    udp_send_acceleration.gso_datagrams,
                    udp_send_acceleration.fallback_flushes,
                    udp_send_acceleration.fallback_datagrams,
                    udp_send_acceleration.partial_flushes,
                    udp_send_acceleration.error_flushes,
                );
                return Ok(SendReport {
                    transfer_id,
                    bytes_sent: total_bytes,
                    files: u32::try_from(logical_digests.len()).unwrap_or(u32::MAX),
                    symbols_sent,
                    feedback_rounds,
                    merkle_root_hex,
                    receipt,
                    udp_send_acceleration,
                    peer,
                });
            }
            FrameType::KeepAlive => {
                adaptive.mark_control_peer_activity();
            }
            FrameType::ObjectRequest => {
                let need: NeedMore = parse_json(&reply)?;
                feedback_rounds += 1;
                if feedback_rounds > config.max_feedback_rounds {
                    return Err(RqError::NoConvergence {
                        rounds: feedback_rounds,
                        pending: need.pending.len(),
                    });
                }
                let source_symbols = need.source_symbols;
                let prior_pending_bytes = pending_bytes(&digests, &pending);
                let progress = RqNeedMoreProgress {
                    pending_rank: need.pending_rank,
                    pending_rank_columns: need.pending_rank_columns,
                    pending_rank_deficit: need.pending_rank_deficit,
                    pending_decode_jobs: need.pending_decode_jobs,
                };
                pending = need.pending.into_iter().collect();
                let fallback_received = sent_this_round.saturating_sub(
                    u64::try_from(pending.len())
                        .unwrap_or(u64::MAX)
                        .min(sent_this_round),
                );
                let received_this_round = need
                    .round_symbols_observed
                    .or(need.round_symbols_accepted)
                    .unwrap_or(fallback_received)
                    .min(sent_this_round);
                let feedback_delivery_bps =
                    received_this_round.saturating_mul(u64::from(config.symbol_size.max(1))) as f64
                        / finite_duration_s(round_send_wall);
                if pending.is_empty() {
                    // Receiver says nothing pending but did not send Proof yet;
                    // loop again to fetch the Proof.
                    continue;
                }
                // Wire loss for pacing/AIMD comes from ARRIVALS when the
                // receiver counted them: `round_symbols_observed` includes
                // duplicates and rank-stalled symbols — everything that
                // proved delivery. The receiver's `round_loss_fraction`
                // folds in usefulness (post-completion excess reads as
                // loss): on the 500M/broken cell it reported 0.59 while
                // arrivals proved 0.092, halving the AIMD rate every round
                // (MATRIX-207). Passing None here lets observe_need_more
                // derive loss from the arrival count itself.
                let pacing_round_loss_fraction = if need.round_symbols_observed.is_some() {
                    None
                } else {
                    need.round_loss_fraction
                };
                adaptive.observe_need_more_with_progress(
                    &config,
                    &digests,
                    &pending,
                    prior_pending_bytes,
                    progress,
                    sent_this_round,
                    received_this_round,
                    pacing_round_loss_fraction,
                    round_delivery_sample_kind,
                    round_send_wall,
                    control_wait,
                    total_bytes,
                );
                let measured_repair_overhead =
                    measured_feedback_repair_overhead(adaptive.last_round_loss_fraction);
                let source_fec_fallback_trigger = source_retransmit_needs_fec_fallback(
                    &config,
                    feedback_rounds,
                    source_symbols.len(),
                    adaptive.last_round_loss_fraction,
                );
                source_fec_fallback_active |= source_fec_fallback_trigger;
                round_tuning = if source_fec_fallback_active {
                    adaptive.source_fec_fallback_tuning(&config)
                } else {
                    adaptive.round_tuning(&config)
                };
                pacer.configure_with_shared_decision(
                    round_tuning.pacing,
                    adaptive.shared_rate_decision(),
                );
                let loss_pacing_cap_bps = adaptive.loss_pacing_cap_bps.unwrap_or(0);
                rqtrace!(
                    "sender: NeedMore round={feedback_rounds} pending={} source_requests={} sent_this_round={} received_this_round={} round_loss_fraction={:.4} measured_repair_overhead={:.4} fallback_trigger={} aimd_rate_bps={} loss_pacing_cap_bps={} send_wall_ms={} control_wait_ms={} delivery_rate_bps={:.0} bw_ema_bps={:.0} bw_trough_bps={:.0} repair_overhead={:.4} path_rate_bps={} repair_loss_ema={:.4} pacing_loss_ema={:.4} repair_loss_bar={:.4} pacing_loss_bar={:.4} fec_fallback={}",
                    pending.len(),
                    source_symbols.len(),
                    sent_this_round,
                    received_this_round,
                    adaptive.last_round_loss_fraction,
                    measured_repair_overhead,
                    source_fec_fallback_trigger,
                    adaptive.aimd_rate_bps,
                    loss_pacing_cap_bps,
                    round_send_wall.as_millis(),
                    control_wait.as_millis(),
                    feedback_delivery_bps,
                    adaptive.bw_ema_bps,
                    adaptive.bw_trough_bps,
                    round_tuning.repair_overhead,
                    round_tuning.pacing.path_rate_bps,
                    adaptive.loss_ema,
                    adaptive.pacing_loss_ema,
                    adaptive.loss_bar,
                    adaptive.pacing_loss_bar,
                    source_fec_fallback_active,
                );
                // A request list below the cap enumerates the ENTIRE residual
                // (collect_source_requests truncates at the limit): the
                // requested systematic symbols are exactly what the remaining
                // blocks are missing, so the blanket per-block fallback spray
                // would land almost entirely on already-complete blocks
                // (99.4% of a 78MB spray round rejected on 500M/broken,
                // MATRIX-207). Only spray when the list was truncated and the
                // true residual is unknown.
                let residual_fully_requested = !source_symbols.is_empty()
                    && (config.max_source_retransmit_requests == 0
                        || source_symbols.len() < config.max_source_retransmit_requests);
                let spray_fallback = source_fec_fallback_active && !residual_fully_requested;
                if source_symbols.is_empty() {
                    round_started = Instant::now();
                    round_symbols_start = symbols_sent;
                    // Fresh repair symbols (true encoder ESIs, via the
                    // cumulative cursor in each EntryEncoder) for the
                    // still-pending entries.
                    spray_round(
                        cx,
                        &mut control,
                        &mut adaptive,
                        &mut sockets,
                        &mut rr,
                        &mut symbols_sent,
                        &mut dropper,
                        tag,
                        &mut encoders,
                        &pending,
                        &config,
                        &mut pacer,
                        &round_tuning,
                        symbol_auth.as_ref(),
                        &mut udp_send_acceleration,
                        /* with_source */ false,
                        false,
                        parallel_encode_plan,
                    )
                    .await?;
                    round_send_wall = round_started.elapsed();
                    round_delivery_sample_kind = RqDeliverySampleKind::InitialOrRepair;
                } else {
                    round_started = Instant::now();
                    round_symbols_start = symbols_sent;
                    spray_source_requests(
                        cx,
                        &mut control,
                        &mut adaptive,
                        &mut sockets,
                        &mut rr,
                        &mut symbols_sent,
                        &mut dropper,
                        tag,
                        &encoders,
                        &source_symbols,
                        &config,
                        &mut pacer,
                        symbol_auth.as_ref(),
                        &mut udp_send_acceleration,
                    )
                    .await?;
                    if spray_fallback {
                        spray_round(
                            cx,
                            &mut control,
                            &mut adaptive,
                            &mut sockets,
                            &mut rr,
                            &mut symbols_sent,
                            &mut dropper,
                            tag,
                            &mut encoders,
                            &pending,
                            &config,
                            &mut pacer,
                            &round_tuning,
                            symbol_auth.as_ref(),
                            &mut udp_send_acceleration,
                            /* with_source */ false,
                            false,
                            parallel_encode_plan,
                        )
                        .await?;
                    }
                    round_send_wall = round_started.elapsed();
                    round_delivery_sample_kind = delivery_sample_kind_for_need_more_response(
                        source_symbols.len(),
                        spray_fallback,
                    );
                }
                let emitted_this_response = symbols_sent.saturating_sub(round_symbols_start);
                rqtrace!(
                    "sender: NeedMore response round={feedback_rounds} pending={} source_requests={} emitted_symbols={} total_symbols_sent={} max_feedback_rounds={} repair_overhead={:.4} fec_fallback={}",
                    pending.len(),
                    source_symbols.len(),
                    emitted_this_response,
                    symbols_sent,
                    config.max_feedback_rounds,
                    round_tuning.repair_overhead,
                    spray_fallback,
                );
            }
            other => {
                return Err(RqError::Unexpected {
                    got: other,
                    expected: "Proof | NeedMore | KeepAlive",
                });
            }
        }
    }
}

/// Legacy ceiling for per-round repair increments.
///
/// This preserves the old high-loss convergence cap while letting clean-link
/// feedback rounds avoid spraying a fixed K/4 parity burst for a sparse tail.
fn max_feedback_repair_batch_per_block(block_source_n: usize) -> usize {
    (block_source_n / 4).max(16)
}

/// Minimum fresh repair symbols emitted for a source-first repair-only feedback
/// round. A one-symbol tail is too fragile on lossy links: if that one repair
/// symbol drops, the receiver idles until the next control PTO or fails closed.
const SOURCE_FIRST_FEEDBACK_REPAIR_FLOOR_PER_BLOCK: usize = 4;

fn adaptive_feedback_repair_batch_per_block(block_source_n: usize, repair_overhead: f64) -> usize {
    if repair_overhead <= 1.0 {
        return SOURCE_FIRST_FEEDBACK_REPAIR_FLOOR_PER_BLOCK;
    }

    let matched = ((block_source_n as f64) * (repair_overhead - 1.0)).ceil() as usize;
    matched
        .max(SOURCE_FIRST_FEEDBACK_REPAIR_FLOOR_PER_BLOCK)
        .min(max_feedback_repair_batch_per_block(block_source_n))
}

fn initial_repair_target_per_block(block_source_n: usize, repair_overhead: f64) -> usize {
    if repair_overhead <= 1.0 {
        0
    } else {
        ((block_source_n as f64) * (repair_overhead - 1.0)).ceil() as usize
    }
}

fn repair_target_for_feedback_round(
    block_source_n: usize,
    already: usize,
    repair_overhead: f64,
) -> usize {
    let calibrated_total = initial_repair_target_per_block(block_source_n, repair_overhead);
    if calibrated_total > already {
        calibrated_total
    } else {
        already + adaptive_feedback_repair_batch_per_block(block_source_n, repair_overhead)
    }
}

fn source_retransmit_request_limit(config: &RqConfig, feedback_round: u32) -> Option<usize> {
    // Loss-target cells: round-0 FEC carries the bulk of the transfer, so by
    // the first feedback round most blocks have decoded and the residual is a
    // FEW rank-deficient blocks. Sparse systematic requests pinpoint exactly
    // those symbols; the blanket per-block fallback spray cannot (on the
    // 500M/broken cell 99.4% of a 78MB spray round landed on already-complete
    // blocks and was rejected, MATRIX-207). No round cap: the residual only
    // shrinks, so requests stay the cheapest mechanism every round.
    if round0_loss_target_repair_enabled(config) {
        return Some(config.max_source_retransmit_requests);
    }
    if config.repair_overhead <= 1.0
        && config.source_retransmit_rounds > 0
        && feedback_round <= config.source_retransmit_rounds
    {
        Some(config.max_source_retransmit_requests)
    } else {
        None
    }
}

fn source_retransmit_needs_fec_fallback(
    config: &RqConfig,
    feedback_round: u32,
    requested_sources: usize,
    measured_loss_fraction: f64,
) -> bool {
    if measured_feedback_repair_overhead(measured_loss_fraction) > 0.0 {
        return true;
    }
    if round0_loss_target_repair_enabled(config) {
        return true;
    }
    if config.repair_overhead > 1.0 || config.source_retransmit_rounds == 0 {
        return false;
    }
    let rank_only_or_repair_feedback = requested_sources == 0;
    let saturated_request = config.max_source_retransmit_requests != 0
        && requested_sources >= config.max_source_retransmit_requests;
    rank_only_or_repair_feedback
        || saturated_request
        || feedback_round >= config.source_retransmit_rounds
}

/// Above this total transfer size the parallel per-block encode is disabled and the sequential
/// (encode-paced) spray is used instead. The receiver sizes its UDP recv buffer to absorb the
/// parallel sender's burst, but that buffer is clamped near `net.core.rmem_max`; once a transfer
/// exceeds what the buffer can hold, an unpaced parallel burst would overrun the CPU-bound decoder
/// and trigger a feedback-round explosion. Below the cap the burst is absorbed and the encode
/// parallelism is a pure win. Parallel decode + a rate-paced encode-ahead ring are what lift this
/// cap for very large objects.
const PARALLEL_ENCODE_MAX_BYTES: u64 = 112 * 1024 * 1024;
const PARALLEL_ENCODE_HOST_MAX_BATCH_BLOCKS: usize = 64;
/// Lossy objects need encode parallelism to keep the 50 mbit bad link fed, but
/// they must not recreate the old full-transfer burst. Eight bounded RaptorQ
/// blocks is enough CPU fanout for the target link while keeping peak sender
/// symbol RAM well below the receiver's UDP buffer envelope.
const LOSSY_LARGE_PARALLEL_ENCODE_BATCH_BLOCKS: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ParallelEncodePlan {
    max_batch_blocks: usize,
}

fn parallel_encode_plan_for_transfer(
    total_bytes: u64,
    config: &RqConfig,
) -> Option<ParallelEncodePlan> {
    if round0_loss_target_repair_enabled(config) {
        Some(ParallelEncodePlan {
            max_batch_blocks: LOSSY_LARGE_PARALLEL_ENCODE_BATCH_BLOCKS,
        })
    } else if total_bytes <= PARALLEL_ENCODE_MAX_BYTES {
        Some(ParallelEncodePlan {
            max_batch_blocks: PARALLEL_ENCODE_HOST_MAX_BATCH_BLOCKS,
        })
    } else {
        None
    }
}

fn parallel_encode_window_blocks(plan: ParallelEncodePlan) -> usize {
    let host_batch = std::thread::available_parallelism()
        .map_or(4, std::num::NonZeroUsize::get)
        .clamp(2, PARALLEL_ENCODE_HOST_MAX_BATCH_BLOCKS);
    host_batch.min(
        plan.max_batch_blocks
            .clamp(2, PARALLEL_ENCODE_HOST_MAX_BATCH_BLOCKS),
    )
}

/// Upper bound on the number of source blocks we fan out across the blocking pool in one round.
/// Above this the manual block enumeration would risk diverging from the canonical encoder's `u8`
/// SBN envelope, so we fall back to the sequential encode-paced spray.
const MAX_RAPTORQ_SOURCE_BLOCKS: usize = 256;

/// Whether a round-0 (`with_source`) spray should fan its per-block RaptorQ solves out across the
/// runtime blocking pool. We parallelize only multi-block objects (a single/empty block would only
/// pay pool-dispatch latency and lose the small-object latency win), only while `parallel_encode`
/// is on (the transfer fits under [`PARALLEL_ENCODE_MAX_BYTES`]), and only within the `u8` SBN
/// envelope.
fn should_parallel_encode_source_blocks(
    block_count: usize,
    parallel_encode_plan: Option<ParallelEncodePlan>,
) -> bool {
    parallel_encode_plan.is_some() && block_count > 1 && block_count <= MAX_RAPTORQ_SOURCE_BLOCKS
}

/// Encode one RaptorQ source block (its `K` source symbols plus `repair_count` repair symbols) into
/// an owned `Vec<Symbol>`.
///
/// Runs on the blocking pool for [`spray_round`]'s parallel per-block encode.
/// [`EncodingPipeline::encode_single_block_with_repair`] preserves the exact object/SBN/ESI layout
/// the sequential per-block path would have produced for `sbn`, so the emitted symbols are
/// byte-identical regardless of which thread minted them — the speedup is a pure throughput
/// isomorphism (decode is order-independent and the receiver verifies sha256 + merkle). The error
/// is stringified because the closure crosses the `spawn_blocking` boundary, where the return type
/// need only be `Send`.
fn encode_block_symbols(
    cfg: &crate::config::EncodingConfig,
    object_id: ObjectId,
    sbn: u8,
    data: &[u8],
    repair_count: usize,
) -> Result<Vec<Symbol>, String> {
    let pool = SymbolPool::new(PoolConfig::default());
    let mut pipeline = EncodingPipeline::new(cfg.clone(), pool);
    let mut out = Vec::new();
    for encoded in pipeline.encode_single_block_with_repair(object_id, sbn, data, repair_count) {
        out.push(encoded.map_err(|e| e.to_string())?.into_symbol());
    }
    Ok(out)
}

fn source_symbol_from_block(
    object_id: ObjectId,
    sbn: u8,
    esi: usize,
    block_bytes: &[u8],
    symbol_size: usize,
) -> Result<Symbol, RqError> {
    let within_block = esi
        .checked_mul(symbol_size)
        .ok_or_else(|| RqError::Coding("source symbol offset overflow".to_string()))?;
    let esi = u32::try_from(esi)
        .map_err(|_| RqError::Coding(format!("source symbol ESI {esi} exceeds u32::MAX")))?;
    let mut payload = vec![0u8; symbol_size];
    if within_block < block_bytes.len() {
        let end = within_block
            .saturating_add(symbol_size)
            .min(block_bytes.len());
        payload[..end - within_block].copy_from_slice(&block_bytes[within_block..end]);
    }
    Ok(Symbol::new(
        SymbolId::new(object_id, sbn, esi),
        payload,
        SymbolKind::Source,
    ))
}

#[allow(clippy::too_many_arguments)]
async fn send_source_only_block_datagrams<S>(
    cx: &Cx,
    control: &mut FrameTransport<S>,
    adaptive: &mut RqAdaptiveSendState,
    sockets: &mut [UdpSocket],
    rr: &mut usize,
    symbols_sent: &mut u64,
    dropper: &mut u32,
    tag: u64,
    entry: u32,
    object_id: ObjectId,
    block: EncodeAheadBlock,
    block_bytes: &[u8],
    config: &RqConfig,
    pacer: &mut RqSprayPacer,
    symbol_auth: Option<&SecurityContext>,
    udp_send_acceleration: &mut UdpSendAccelerationReport,
) -> Result<usize, RqError>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let symbol_size = usize::from(config.symbol_size.max(1));
    let mut send_batch = RqPendingSendBatch::new(sockets.len());
    for esi in 0..block.k {
        let symbol = source_symbol_from_block(object_id, block.sbn, esi, block_bytes, symbol_size)?;
        queue_symbol_datagram(
            cx,
            control,
            adaptive,
            sockets,
            rr,
            symbols_sent,
            dropper,
            tag,
            entry,
            &symbol,
            config,
            pacer,
            symbol_auth,
            &mut send_batch,
            udp_send_acceleration,
        )
        .await?;
    }
    let report = send_batch.flush(sockets, symbols_sent).await?;
    udp_send_acceleration.observe_flush_report(report);
    service_rq_spray_control(cx, control, adaptive).await?;
    Ok(block.k)
}

/// Spray one round of symbols for the `pending` entries across the UDP sockets.
///
/// Round 0 (`with_source`) sends every block's source symbols plus optional
/// `repair_overhead` extra repair. Feedback rounds send only *newly minted*
/// repair symbols, identified per block by the encoder's own (sbn, esi) — the
/// repair payload is bound to its ESI, so it is emitted verbatim and never
/// relabeled. Per-block repair cursors advance so each round's repair is fresh
/// for every source block in a pending entry.
#[allow(clippy::too_many_arguments)]
async fn spray_round<S>(
    cx: &Cx,
    control: &mut FrameTransport<S>,
    adaptive: &mut RqAdaptiveSendState,
    sockets: &mut [UdpSocket],
    rr: &mut usize,
    symbols_sent: &mut u64,
    dropper: &mut u32,
    tag: u64,
    encoders: &mut [EntryEncoder],
    pending: &BTreeSet<u32>,
    config: &RqConfig,
    pacer: &mut RqSprayPacer,
    round_tuning: &RqRoundTuning,
    symbol_auth: Option<&SecurityContext>,
    udp_send_acceleration: &mut UdpSendAccelerationReport,
    with_source: bool,
    small_clean_source_only: bool,
    parallel_encode_plan: Option<ParallelEncodePlan>,
) -> Result<(), RqError>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    for enc in encoders.iter_mut().filter(|e| pending.contains(&e.index)) {
        cx.checkpoint().map_err(|_| RqError::Cancelled)?;
        let mut ring = EncodeAheadRing::default();
        let blocks = encode_ahead_blocks(enc.size, config)?;
        if enc.repair_cursors.len() > blocks.len() {
            enc.repair_cursors.truncate(blocks.len());
        }
        if enc.repair_cursors.len() < blocks.len() {
            enc.repair_cursors.resize(blocks.len(), 0);
        }

        let mut round0_blocks = 0usize;
        let mut round0_source_symbols = 0usize;
        let mut round0_repair_symbols = 0usize;
        let use_parallel_source_encode =
            with_source && should_parallel_encode_source_blocks(blocks.len(), parallel_encode_plan);
        if with_source && small_clean_source_only {
            for (block_index, block) in blocks.iter().copied().enumerate() {
                let read_start = enc.source_offset.checked_add(block.start).ok_or_else(|| {
                    RqError::Coding("encode source range offset overflow".to_string())
                })?;
                let block_bytes = read_source_range(&enc.abs_path, read_start, block.len).await?;
                let source_symbols = send_source_only_block_datagrams(
                    cx,
                    control,
                    adaptive,
                    sockets,
                    rr,
                    symbols_sent,
                    dropper,
                    tag,
                    enc.index,
                    enc.object_id,
                    block,
                    &block_bytes,
                    config,
                    pacer,
                    symbol_auth,
                    udp_send_acceleration,
                )
                .await?;
                round0_blocks = round0_blocks.saturating_add(1);
                round0_source_symbols = round0_source_symbols.saturating_add(source_symbols);
                enc.repair_cursors[block_index] = 0;
            }
        } else if use_parallel_source_encode {
            // Parallel per-block encode on the runtime blocking pool. Each RaptorQ source block
            // solves independently, so for multi-block objects we fan the K-symbol solves across
            // cores instead of grinding them one-at-a-time on a single core (the measured
            // large-file bottleneck: ~99% of one core for an 8 MiB / K=8192 block). Blocks are
            // encoded and sprayed in SBN order, so the wire output is byte-identical to the
            // sequential path — a pure throughput isomorphism (decode is order-independent; the
            // receiver verifies sha256 + merkle). Bounded BATCHES (degree = host parallelism) cap
            // peak symbol RAM at ~2x `par_batch` blocks (double-buffered below); the in-flight
            // window is joined on the checkpoint-cancel path so no encode task strands.
            let enc_cfg = crate::config::EncodingConfig {
                repair_overhead: round_tuning.repair_overhead,
                max_block_size: config.max_block_size,
                symbol_size: config.symbol_size,
                encoding_parallelism: 1,
                decoding_parallelism: 1,
            };
            let par_batch = parallel_encode_window_blocks(
                parallel_encode_plan.expect("parallel encode plan checked above"),
            );
            // Double-buffered encode-ahead: spawn window W+1's encodes BEFORE
            // draining window W, so the pool encodes the next window while the
            // pacer is emitting the current one. The serial spawn-join-spawn
            // shape stalled the paced spray ~300-400 ms per window (encode
            // latency un-overlapped with the ~4 s paced send), a ~7% realized
            // round-0 rate loss on the 10 mbit broken cell (MATRIX-209).
            // Steady state holds at most TWO windows of symbols; the pending
            // window is drained on the checkpoint-cancel path, and hard-error
            // unwinds drain via region close (quiescence).
            let mut pending: Vec<(
                usize,
                usize,
                usize,
                crate::runtime::TaskHandle<Result<Vec<Symbol>, String>>,
            )> = Vec::new();
            for window_start in (0..blocks.len()).step_by(par_batch) {
                if cx.checkpoint().is_err() {
                    for (_, _, _, mut handle) in pending.drain(..) {
                        let _ = handle.join(cx).await;
                    }
                    return Err(RqError::Cancelled);
                }
                let window_end = (window_start + par_batch).min(blocks.len());
                let window = &blocks[window_start..window_end];
                let mut spawned = Vec::with_capacity(window.len());
                for (window_offset, block) in window.iter().enumerate() {
                    // Disk reads are cheap relative to the RaptorQ solve, so read each block's
                    // source range here and hand the owned bytes to the pool task.
                    let read_start =
                        enc.source_offset.checked_add(block.start).ok_or_else(|| {
                            RqError::Coding("encode source range offset overflow".to_string())
                        })?;
                    let block_bytes =
                        read_source_range(&enc.abs_path, read_start, block.len).await?;
                    let object_id = enc.object_id;
                    let sbn = block.sbn;
                    let block_index = window_start + window_offset;
                    let repair =
                        initial_repair_target_per_block(block.k, round_tuning.repair_overhead);
                    let cfg = enc_cfg.clone();
                    let handle = cx
                        .spawn_blocking(move |_child| {
                            encode_block_symbols(&cfg, object_id, sbn, &block_bytes, repair)
                        })
                        .map_err(|e| RqError::Coding(format!("encode spawn failed: {e:?}")))?;
                    spawned.push((block_index, block.k, repair, handle));
                }
                for (block_index, source_symbols, target_repair, mut handle) in pending.drain(..) {
                    let syms = match handle.join(cx).await {
                        Ok(Ok(syms)) => syms,
                        Ok(Err(e)) => return Err(RqError::Coding(e)),
                        Err(join_err) => {
                            return Err(RqError::Coding(format!(
                                "encode task failed: {join_err:?}"
                            )));
                        }
                    };
                    send_symbol_datagrams(
                        cx,
                        control,
                        adaptive,
                        sockets,
                        rr,
                        symbols_sent,
                        dropper,
                        tag,
                        enc.index,
                        &syms,
                        config,
                        pacer,
                        symbol_auth,
                        udp_send_acceleration,
                    )
                    .await?;
                    round0_blocks = round0_blocks.saturating_add(1);
                    round0_source_symbols = round0_source_symbols.saturating_add(source_symbols);
                    round0_repair_symbols = round0_repair_symbols.saturating_add(target_repair);
                    enc.repair_cursors[block_index] = target_repair;
                }
                pending = spawned;
            }
            for (block_index, source_symbols, target_repair, mut handle) in pending {
                let syms = match handle.join(cx).await {
                    Ok(Ok(syms)) => syms,
                    Ok(Err(e)) => return Err(RqError::Coding(e)),
                    Err(join_err) => {
                        return Err(RqError::Coding(format!("encode task failed: {join_err:?}")));
                    }
                };
                send_symbol_datagrams(
                    cx,
                    control,
                    adaptive,
                    sockets,
                    rr,
                    symbols_sent,
                    dropper,
                    tag,
                    enc.index,
                    &syms,
                    config,
                    pacer,
                    symbol_auth,
                    udp_send_acceleration,
                )
                .await?;
                round0_blocks = round0_blocks.saturating_add(1);
                round0_source_symbols = round0_source_symbols.saturating_add(source_symbols);
                round0_repair_symbols = round0_repair_symbols.saturating_add(target_repair);
                enc.repair_cursors[block_index] = target_repair;
            }
        } else {
            let mut feedback_repair_blocks = 0usize;
            let mut feedback_source_symbols = 0usize;
            let mut feedback_repair_symbols = 0usize;
            let mut feedback_prior_repair_cursor = 0usize;
            let mut feedback_target_repair_cursor = 0usize;
            for (block_index, block) in blocks.iter().enumerate() {
                // Cumulative repair count requested from the encoder for this
                // block. The encoder always yields repair symbols at
                // deterministic ESIs starting at the block's K'; requesting
                // more just extends the tail. We skip the already-sent repair
                // symbols for this block and emit the rest at their TRUE ESIs.
                let already = enc.repair_cursors[block_index];
                let target_repair = if with_source {
                    initial_repair_target_per_block(block.k, round_tuning.repair_overhead)
                } else {
                    repair_target_for_feedback_round(block.k, already, round_tuning.repair_overhead)
                };
                let repair_count = target_repair.saturating_sub(already);
                if with_source {
                    round0_blocks = round0_blocks.saturating_add(1);
                    round0_source_symbols = round0_source_symbols.saturating_add(block.k);
                    round0_repair_symbols = round0_repair_symbols.saturating_add(target_repair);
                }
                if !with_source {
                    feedback_repair_blocks += 1;
                    feedback_source_symbols = feedback_source_symbols.saturating_add(block.k);
                    feedback_repair_symbols = feedback_repair_symbols.saturating_add(repair_count);
                    feedback_prior_repair_cursor =
                        feedback_prior_repair_cursor.saturating_add(already);
                    feedback_target_repair_cursor =
                        feedback_target_repair_cursor.saturating_add(target_repair);
                }
                if !with_source && repair_count == 0 {
                    enc.repair_cursors[block_index] = target_repair;
                    continue;
                }

                // The encoder's `Symbol` output owns its payload buffer, so buffers
                // allocated from `SymbolPool` are consumed rather than returned to
                // the pool. Keep the M=1 encode-ahead path unpooled; round sizing,
                // UDP pacing, and receiver-side limits own memory pressure.
                let pool = SymbolPool::new(PoolConfig::default());
                let mut pipeline = EncodingPipeline::new(
                    crate::config::EncodingConfig {
                        repair_overhead: round_tuning.repair_overhead,
                        max_block_size: config.max_block_size,
                        symbol_size: config.symbol_size,
                        encoding_parallelism: 1,
                        decoding_parallelism: 1,
                    },
                    pool,
                );
                let read_start = enc.source_offset.checked_add(block.start).ok_or_else(|| {
                    RqError::Coding("encode source range offset overflow".to_string())
                })?;
                let block_bytes = read_source_range(&enc.abs_path, read_start, block.len).await?;

                let mut send_batch = RqPendingSendBatch::new(sockets.len());
                if with_source {
                    for encoded in pipeline.encode_single_block_with_repair(
                        enc.object_id,
                        block.sbn,
                        &block_bytes,
                        target_repair,
                    ) {
                        let encoded = encoded.map_err(|e| RqError::Coding(e.to_string()))?;
                        ring.push(EncodeAheadSymbol::from_encoded(enc.index, encoded))?;
                        let produced = ring.pop().expect("M=1 ring drains immediately");
                        queue_symbol_datagram(
                            cx,
                            control,
                            adaptive,
                            sockets,
                            rr,
                            symbols_sent,
                            dropper,
                            tag,
                            produced.entry,
                            &produced.symbol,
                            config,
                            pacer,
                            symbol_auth,
                            &mut send_batch,
                            udp_send_acceleration,
                        )
                        .await?;
                        debug_assert!(ring.is_empty());
                    }
                } else {
                    for encoded in pipeline.encode_single_block_repair_range(
                        enc.object_id,
                        block.sbn,
                        &block_bytes,
                        already,
                        repair_count,
                    ) {
                        let encoded = encoded.map_err(|e| RqError::Coding(e.to_string()))?;
                        ring.push(EncodeAheadSymbol::from_encoded(enc.index, encoded))?;
                        let produced = ring.pop().expect("M=1 ring drains immediately");
                        queue_symbol_datagram(
                            cx,
                            control,
                            adaptive,
                            sockets,
                            rr,
                            symbols_sent,
                            dropper,
                            tag,
                            produced.entry,
                            &produced.symbol,
                            config,
                            pacer,
                            symbol_auth,
                            &mut send_batch,
                            udp_send_acceleration,
                        )
                        .await?;
                        debug_assert!(ring.is_empty());
                    }
                }
                let report = send_batch.flush(sockets, symbols_sent).await?;
                udp_send_acceleration.observe_flush_report(report);
                service_rq_spray_control(cx, control, adaptive).await?;
                enc.repair_cursors[block_index] = target_repair;
            }
            if !with_source {
                let source_symbols = feedback_source_symbols.max(1) as f64;
                let emitted_ratio = feedback_repair_symbols as f64 / source_symbols;
                let target_ratio = feedback_target_repair_cursor as f64 / source_symbols;
                rqtrace!(
                    "sender: repair_spray entry={} blocks={} source_symbols={} repair_overhead={:.4} emitted_repair_symbols={} emitted_repair_ratio={:.4} prior_repair_cursor={} target_repair_cursor={} target_repair_ratio={:.4} pending_entries={}",
                    enc.index,
                    feedback_repair_blocks,
                    feedback_source_symbols,
                    round_tuning.repair_overhead,
                    feedback_repair_symbols,
                    emitted_ratio,
                    feedback_prior_repair_cursor,
                    feedback_target_repair_cursor,
                    target_ratio,
                    pending.len(),
                );
            }
        }
        if with_source {
            let source_symbols = round0_source_symbols.max(1) as f64;
            let emitted_repair_ratio = round0_repair_symbols as f64 / source_symbols;
            let emitted_symbols = round0_source_symbols.saturating_add(round0_repair_symbols);
            rqtrace!(
                "sender: round0_source_spray entry={} blocks={} source_symbols={} repair_overhead={:.4} emitted_repair_symbols={} emitted_repair_ratio={:.4} emitted_symbols={} pacing_rate_Bps={} pending_entries={}",
                enc.index,
                round0_blocks,
                round0_source_symbols,
                round_tuning.repair_overhead,
                round0_repair_symbols,
                emitted_repair_ratio,
                emitted_symbols,
                pacer.pacing().rate_bytes_per_sec(),
                pending.len(),
            );
        }
    }
    Ok(())
}

fn apply_bonded_descriptor_config(
    descriptor: &BondTransferDescriptor,
    config: &mut RqConfig,
) -> Result<(), RqError> {
    if descriptor.symbol_size == 0 {
        return Err(RqError::Coding(
            "bonded donor descriptor has zero symbol_size".to_string(),
        ));
    }
    let max_block_size =
        usize::try_from(descriptor.max_block_size).map_err(|_| RqError::TooLarge {
            size: descriptor.max_block_size,
            max: u64::try_from(usize::MAX).unwrap_or(u64::MAX),
        })?;
    if max_block_size == 0 {
        return Err(RqError::Coding(
            "bonded donor descriptor has zero max_block_size".to_string(),
        ));
    }
    config.symbol_size = descriptor.symbol_size;
    config.max_block_size = max_block_size;
    Ok(())
}

fn bonded_initial_repair_symbols_per_block(config: &RqConfig) -> Result<u32, RqError> {
    let tuning = RqAdaptiveSendState::new(0, config, 1).round0_tuning(config);
    let block_source_n = usize::try_from(fixed_block_k(config)).map_err(|_| {
        RqError::Coding(format!(
            "bonded donor fixed block size does not fit usize: {}",
            fixed_block_k(config)
        ))
    })?;
    let repair = initial_repair_target_per_block(block_source_n, tuning.repair_overhead);
    u32::try_from(repair)
        .map_err(|_| RqError::Coding(format!("bonded donor repair budget too large: {repair}")))
}

fn bonded_receiver_endpoints(
    assignment: &DonorAssignment,
    receiver_endpoint: SocketAddr,
) -> Vec<SocketAddr> {
    let mut endpoints = Vec::with_capacity(assignment.receiver_udp_endpoints.len().max(1));
    endpoints.push(receiver_endpoint);
    for endpoint in &assignment.receiver_udp_endpoints {
        if !endpoints.contains(endpoint) {
            endpoints.push(*endpoint);
        }
    }
    endpoints
}

fn bonded_donor_entry_path(root_dir: &Path, rel_path: &str) -> Result<PathBuf, RqError> {
    if Path::new(rel_path).is_absolute() {
        return Err(RqError::Source(format!(
            "bonded donor rel_path escapes root: {rel_path}"
        )));
    }

    let mut out = root_dir.to_path_buf();
    let mut pushed = false;
    for component in rel_path.split('/') {
        if component.is_empty() || component == "." {
            continue;
        }
        if component == ".." || Path::new(component).components().count() != 1 {
            return Err(RqError::Source(format!(
                "bonded donor rel_path escapes root: {rel_path}"
            )));
        }
        out.push(component);
        pushed = true;
    }
    if pushed {
        Ok(out)
    } else {
        Err(RqError::Source(
            "bonded donor rel_path must name a file".to_string(),
        ))
    }
}

fn encode_bonded_donor_emission(
    emission: BondedDonorSymbolEmission,
    block_bytes: &[u8],
    config: &RqConfig,
) -> Result<Symbol, RqError> {
    let k = u32::from(emission.geometry.source_symbols);
    let symbol = if emission.esi < k {
        source_symbol_from_block(
            emission.geometry.object_id,
            emission.geometry.source_block_number,
            usize::try_from(emission.esi).map_err(|_| {
                RqError::Coding(format!(
                    "bonded donor source ESI does not fit usize: {}",
                    emission.esi
                ))
            })?,
            block_bytes,
            usize::from(config.symbol_size.max(1)),
        )?
    } else {
        let first_repair = usize::try_from(emission.esi - k).map_err(|_| {
            RqError::Coding(format!(
                "bonded donor repair ESI does not fit usize: {}",
                emission.esi
            ))
        })?;
        let mut pipeline = EncodingPipeline::new(
            crate::config::EncodingConfig {
                repair_overhead: config.repair_overhead,
                max_block_size: config.max_block_size,
                symbol_size: config.symbol_size,
                encoding_parallelism: 1,
                decoding_parallelism: 1,
            },
            SymbolPool::new(PoolConfig::default()),
        );
        let mut encoded = pipeline.encode_single_block_repair_range(
            emission.geometry.object_id,
            emission.geometry.source_block_number,
            block_bytes,
            first_repair,
            1,
        );
        let encoded = encoded
            .next()
            .ok_or_else(|| {
                RqError::Coding(format!(
                    "bonded donor encoder produced no repair symbol for esi {}",
                    emission.esi
                ))
            })?
            .map_err(|err| RqError::Coding(err.to_string()))?;
        encoded.symbol().clone()
    };

    if symbol.id() != emission.symbol_id() || symbol.kind() != emission.symbol_kind() {
        return Err(RqError::Coding(format!(
            "bonded donor encoded wrong symbol: expected sbn={} esi={} kind={:?}, got sbn={} esi={} kind={:?}",
            emission.geometry.source_block_number,
            emission.esi,
            emission.symbol_kind(),
            symbol.id().sbn(),
            symbol.id().esi(),
            symbol.kind(),
        )));
    }

    Ok(symbol)
}

#[allow(clippy::too_many_arguments)]
async fn queue_bonded_donor_datagram(
    cx: &Cx,
    sockets: &mut [UdpSocket],
    rr: &mut usize,
    symbols_sent: &mut u64,
    dropper: &mut u32,
    tag: u64,
    entry: u32,
    sym: &Symbol,
    config: &RqConfig,
    pacer: &mut RqSprayPacer,
    symbol_auth: Option<&SecurityContext>,
    send_batch: &mut RqPendingSendBatch,
    udp_send_acceleration: &mut UdpSendAccelerationReport,
) -> Result<(), RqError> {
    cx.checkpoint().map_err(|_| RqError::Cancelled)?;
    if config.debug_drop_one_in > 0 {
        *dropper = dropper.wrapping_add(1);
        if *dropper % config.debug_drop_one_in == 0 {
            return Ok(());
        }
    }

    pacer.before_send(cx).await?;
    let auth = symbol_auth.map(|ctx| ctx.sign_symbol(sym));
    let dgram =
        encode_symbol_datagram(tag, entry, sym, auth.as_ref().map(AuthenticatedSymbol::tag));
    let fanout = send_batch.fanout();
    let socket_index = *rr % fanout;
    *rr = rr.wrapping_add(1);
    send_batch.push(socket_index, dgram);
    pacer.observe_datagram_sent();
    if send_batch.should_flush() {
        let report = send_batch.flush(sockets, symbols_sent).await?;
        udp_send_acceleration.observe_flush_report(report);
    }
    Ok(())
}

async fn hash_source_entry_streaming(
    entry: &RqSourceEntry,
    buf: &mut [u8],
) -> Result<(u64, crate::atp::object::ObjectId, [u8; 32]), StreamingError> {
    if entry.source_offset == 0 && entry.source_len.is_none() {
        return hash_file_streaming(&entry.abs_path, buf).await;
    }
    let len = entry.source_len.ok_or_else(|| {
        StreamingError::new(format!(
            "{}: ranged source entry missing source_len",
            entry.abs_path.display()
        ))
    })?;
    hash_file_range_streaming(&entry.abs_path, entry.source_offset, len, buf).await
}

async fn hash_file_range_streaming(
    path: &Path,
    offset: u64,
    len: u64,
    buf: &mut [u8],
) -> Result<(u64, crate::atp::object::ObjectId, [u8; 32]), StreamingError> {
    let mut file = crate::fs::File::open(path)
        .await
        .map_err(|e| StreamingError::new(format!("{}: {e}", path.display())))?;
    file.seek(std::io::SeekFrom::Start(offset))
        .await
        .map_err(|e| StreamingError::new(format!("{}: {e}", path.display())))?;

    let mut sha = Sha256::new();
    let mut cid = crate::atp::object::ContentId::streaming();
    let mut remaining = len;
    let mut size = 0u64;
    while remaining > 0 {
        let want = usize::try_from(remaining.min(buf.len() as u64)).unwrap_or(buf.len());
        let n = file
            .read(&mut buf[..want])
            .await
            .map_err(|e| StreamingError::new(format!("{}: {e}", path.display())))?;
        if n == 0 {
            return Err(StreamingError::new(format!(
                "{}: short read while hashing source range offset={offset} len={len}",
                path.display()
            )));
        }
        sha.update(&buf[..n]);
        cid.update(&buf[..n]);
        let n_u64 = n as u64;
        remaining -= n_u64;
        size = size.saturating_add(n_u64);
    }

    Ok((
        size,
        crate::atp::object::ObjectId::content(cid.finalize()),
        sha.finalize().into(),
    ))
}

async fn read_source_range(path: &Path, offset: usize, len: usize) -> Result<Vec<u8>, RqError> {
    if len == 0 {
        return Ok(Vec::new());
    }
    let offset_u64 = u64::try_from(offset).map_err(|_| {
        RqError::Coding(format!(
            "{}: source range offset does not fit u64: {offset}",
            path.display()
        ))
    })?;
    let mut file = crate::fs::File::open(path)
        .await
        .map_err(|e| RqError::Source(format!("{}: {e}", path.display())))?;
    file.seek(std::io::SeekFrom::Start(offset_u64))
        .await
        .map_err(|e| RqError::Source(format!("{}: {e}", path.display())))?;
    let mut bytes = vec![0u8; len];
    file.read_exact(&mut bytes)
        .await
        .map_err(|e| RqError::Source(format!("{}: {e}", path.display())))?;
    Ok(bytes)
}

struct ControlSourcePreparedTransfer {
    entries: Vec<RqSourceEntry>,
    object_sizes: Vec<u64>,
    manifest: TransferManifest,
    precomputed_logical_digests: Vec<EntryDigest>,
    _pack_tempdir: Option<tempfile::TempDir>,
}

struct ControlSourceStreamDigestReport {
    bytes_streamed: u64,
    entry_digests: Vec<ObjectCompleteEntryDigest>,
    logical_digests: Vec<ObjectCompleteLogicalDigest>,
    merkle_root_hex: String,
}

async fn prepare_control_source_transfer(
    root_name: String,
    is_directory: bool,
    raw_entries: Vec<RqSourceEntry>,
    directory_metadata: DirectoryMetadataManifest,
    config: &RqConfig,
    expected_total_bytes: u64,
) -> Result<ControlSourcePreparedTransfer, RqError> {
    let metadata = metadata_manifest_from_source_entries(&raw_entries, directory_metadata);
    let (packed_entries, precomputed_logical_digests, pack_tempdir) =
        pack_small_files_with_deferred_singleton_digests(raw_entries, config, true).await?;
    let entries = split_large_entries_with_digest_mode(
        packed_entries,
        &precomputed_logical_digests,
        config,
        ManifestDigestMode::SourceStreamTrailer,
    )
    .await?;
    let object_sizes = source_entry_sizes(&entries).await?;
    let total_bytes = object_sizes
        .iter()
        .try_fold(0u64, |acc, size| acc.checked_add(*size))
        .ok_or(RqError::TooLarge {
            size: u64::MAX,
            max: config.max_transfer_bytes,
        })?;
    if total_bytes != expected_total_bytes {
        return Err(RqError::Source(format!(
            "source entry sizes changed while preparing control stream: expected {expected_total_bytes}, got {total_bytes}"
        )));
    }
    if total_bytes > config.max_transfer_bytes {
        return Err(RqError::TooLarge {
            size: total_bytes,
            max: config.max_transfer_bytes,
        });
    }

    let manifest_entries: Vec<ManifestEntry> = entries
        .iter()
        .zip(object_sizes.iter())
        .enumerate()
        .map(|(i, (entry, size))| ManifestEntry {
            index: u32::try_from(i).unwrap_or(u32::MAX),
            rel_path: entry.rel_path.clone(),
            size: *size,
            sha256_hex: sha256_hex_placeholder(),
            members: entry.members.clone(),
            fragment: entry.fragment.clone(),
        })
        .collect();
    let transfer_id =
        transfer_id_hex_from_structure(&root_name, is_directory, total_bytes, &manifest_entries);
    let manifest = TransferManifest {
        transfer_id,
        root_name,
        is_directory,
        total_bytes,
        merkle_root_hex: sha256_hex_placeholder(),
        metadata: Some(metadata),
        delta_manifest: None,
        entries: manifest_entries,
    };

    Ok(ControlSourcePreparedTransfer {
        entries,
        object_sizes,
        manifest,
        precomputed_logical_digests,
        _pack_tempdir: pack_tempdir,
    })
}

async fn stream_control_source_entries<S>(
    cx: &Cx,
    control: &mut FrameTransport<S>,
    encoders: &[EntryEncoder],
    manifest: &TransferManifest,
    precomputed_logical_digests: &[EntryDigest],
    transfer_id: &str,
    symbol_auth: Option<&SecurityContext>,
) -> Result<ControlSourceStreamDigestReport, RqError>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let mut buf = vec![0u8; control_source_data_chunk_bytes(symbol_auth.is_some())];
    let mut bytes_streamed = 0u64;
    let mut chunks = 0u64;
    let mut pending_flush_bytes = 0usize;
    let mut flushes = 0u64;
    let mut entry_digests = Vec::with_capacity(encoders.len());
    // The entry loop below emits the authoritative streamed digest for every
    // plain entry and every fragment group itself. Seed only the digests the
    // loop cannot produce — packed members, whose bytes ride inside a pack
    // object. The delta-capable main send path precomputes a digest for EVERY
    // logical file (it needs them for the manifest/transfer-id preflight), and
    // seeding those unfiltered emitted each plain/split file twice in the
    // ObjectComplete frame; the receiver fail-closes on any duplicate rel_path
    // (br-asupersync-lbfdvs).
    let loop_emitted: BTreeSet<&str> = manifest
        .entries
        .iter()
        .filter_map(|entry| {
            if let Some(fragment) = entry.fragment.as_ref() {
                Some(fragment.rel_path.as_str())
            } else if entry.members.is_empty() {
                Some(entry.rel_path.as_str())
            } else {
                None
            }
        })
        .collect();
    let mut logical_digests: Vec<EntryDigest> = precomputed_logical_digests
        .iter()
        .filter(|digest| !loop_emitted.contains(digest.rel_path.as_str()))
        .cloned()
        .collect();
    let mut logical_fragment_hashes: BTreeMap<
        String,
        crate::net::atp::transport_common::StagedEntryReceive,
    > = BTreeMap::new();
    for enc in encoders {
        cx.checkpoint().map_err(|_| RqError::Cancelled)?;
        let manifest_entry = manifest
            .entries
            .iter()
            .find(|entry| entry.index == enc.index)
            .ok_or_else(|| {
                RqError::Coding(format!(
                    "control source encoder {} missing manifest entry",
                    enc.index
                ))
            })?;
        let mut file = crate::fs::File::open(&enc.abs_path)
            .await
            .map_err(|e| RqError::Source(format!("{}: {e}", enc.abs_path.display())))?;
        let source_offset = u64::try_from(enc.source_offset).map_err(|_| {
            RqError::Source(format!(
                "{}: source offset does not fit u64: {}",
                enc.abs_path.display(),
                enc.source_offset
            ))
        })?;
        file.seek(std::io::SeekFrom::Start(source_offset))
            .await
            .map_err(|e| RqError::Source(format!("{}: {e}", enc.abs_path.display())))?;
        let mut remaining = u64::try_from(enc.size).map_err(|_| RqError::TooLarge {
            size: u64::MAX,
            max: u64::try_from(usize::MAX).unwrap_or(u64::MAX),
        })?;
        let mut offset = 0u64;
        let mut entry_hash =
            crate::net::atp::transport_common::StagedEntryReceive::new(enc.abs_path.clone());
        while remaining > 0 {
            cx.checkpoint().map_err(|_| RqError::Cancelled)?;
            let want = usize::try_from(remaining.min(buf.len() as u64)).unwrap_or(buf.len());
            let n = file
                .read(&mut buf[..want])
                .await
                .map_err(|e| RqError::Source(format!("{}: {e}", enc.abs_path.display())))?;
            if n == 0 {
                return Err(RqError::Source(format!(
                    "{}: short read while streaming control source entry {}",
                    enc.abs_path.display(),
                    enc.index
                )));
            }
            entry_hash.update_with_chunk(&buf[..n]);
            if let Some(fragment) = manifest_entry.fragment.as_ref() {
                let logical_hash = logical_fragment_hashes
                    .entry(fragment.rel_path.clone())
                    .or_insert_with(|| {
                        crate::net::atp::transport_common::StagedEntryReceive::new(PathBuf::from(
                            &fragment.rel_path,
                        ))
                    });
                logical_hash.update_with_chunk(&buf[..n]);
            }
            let written = control
                .send_control_source_data_unflushed(
                    transfer_id,
                    enc.index,
                    offset,
                    &buf[..n],
                    symbol_auth,
                )
                .await?;
            pending_flush_bytes = pending_flush_bytes.saturating_add(written);
            if pending_flush_bytes >= RQ_CONTROL_SOURCE_FLUSH_BYTES {
                control.flush().await?;
                pending_flush_bytes = 0;
                flushes = flushes.saturating_add(1);
            }
            let n_u64 = u64::try_from(n).unwrap_or(u64::MAX);
            offset = offset.saturating_add(n_u64);
            remaining -= n_u64;
            bytes_streamed = bytes_streamed.saturating_add(n_u64);
            chunks = chunks.saturating_add(1);
        }
        let (entry_digest, _path, _created) = entry_hash.finalize(manifest_entry.rel_path.clone());
        entry_digests.push(ObjectCompleteEntryDigest {
            index: enc.index,
            size: entry_digest.size,
            sha256_hex: hex_encode(&entry_digest.content_sha256),
        });
        if manifest_entry.fragment.is_none() && manifest_entry.members.is_empty() {
            logical_digests.push(entry_digest);
        }
    }
    if pending_flush_bytes > 0 {
        control.flush().await?;
        flushes = flushes.saturating_add(1);
    }
    for (rel_path, logical_hash) in logical_fragment_hashes {
        let (digest, _path, _created) = logical_hash.finalize(rel_path);
        logical_digests.push(digest);
    }
    let merkle_root_hex = flat_merkle_root_from_digests(&logical_digests);
    let logical_digests = logical_digests
        .into_iter()
        .map(|digest| ObjectCompleteLogicalDigest {
            rel_path: digest.rel_path,
            size: digest.size,
            sha256_hex: hex_encode(&digest.content_sha256),
        })
        .collect();
    rqtrace!(
        "sender: control_source_stream sent chunks={} bytes={} flushes={} flush_threshold_bytes={}",
        chunks,
        bytes_streamed,
        flushes,
        RQ_CONTROL_SOURCE_FLUSH_BYTES
    );
    Ok(ControlSourceStreamDigestReport {
        bytes_streamed,
        entry_digests,
        logical_digests,
        merkle_root_hex,
    })
}

#[allow(clippy::too_many_arguments)]
async fn spray_source_requests<S>(
    cx: &Cx,
    control: &mut FrameTransport<S>,
    adaptive: &mut RqAdaptiveSendState,
    sockets: &mut [UdpSocket],
    rr: &mut usize,
    symbols_sent: &mut u64,
    dropper: &mut u32,
    tag: u64,
    encoders: &[EntryEncoder],
    requests: &[SourceSymbolRequest],
    config: &RqConfig,
    pacer: &mut RqSprayPacer,
    symbol_auth: Option<&SecurityContext>,
    udp_send_acceleration: &mut UdpSendAccelerationReport,
) -> Result<(), RqError>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let mut send_batch = RqPendingSendBatch::new(sockets.len());
    for request in requests {
        let enc = encoders
            .iter()
            .find(|enc| enc.index == request.entry)
            .ok_or_else(|| {
                RqError::Coding(format!(
                    "receiver requested source symbol for unknown entry {}",
                    request.entry
                ))
            })?;
        let sym = source_symbol_for_request(enc, *request, config).await?;

        queue_symbol_datagram(
            cx,
            control,
            adaptive,
            sockets,
            rr,
            symbols_sent,
            dropper,
            tag,
            enc.index,
            &sym,
            config,
            pacer,
            symbol_auth,
            &mut send_batch,
            udp_send_acceleration,
        )
        .await?;
    }
    let report = send_batch.flush(sockets, symbols_sent).await?;
    udp_send_acceleration.observe_flush_report(report);
    service_rq_spray_control(cx, control, adaptive).await?;
    rqtrace!(
        "sender: retransmitted {} requested source symbols",
        requests.len()
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn send_symbol_datagrams<S>(
    cx: &Cx,
    control: &mut FrameTransport<S>,
    adaptive: &mut RqAdaptiveSendState,
    sockets: &mut [UdpSocket],
    rr: &mut usize,
    symbols_sent: &mut u64,
    dropper: &mut u32,
    tag: u64,
    entry: u32,
    symbols: &[Symbol],
    config: &RqConfig,
    pacer: &mut RqSprayPacer,
    symbol_auth: Option<&SecurityContext>,
    udp_send_acceleration: &mut UdpSendAccelerationReport,
) -> Result<(), RqError>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let mut send_batch = RqPendingSendBatch::new(sockets.len());
    for sym in symbols {
        queue_symbol_datagram(
            cx,
            control,
            adaptive,
            sockets,
            rr,
            symbols_sent,
            dropper,
            tag,
            entry,
            sym,
            config,
            pacer,
            symbol_auth,
            &mut send_batch,
            udp_send_acceleration,
        )
        .await?;
    }
    let report = send_batch.flush(sockets, symbols_sent).await?;
    udp_send_acceleration.observe_flush_report(report);
    service_rq_spray_control(cx, control, adaptive).await
}

#[allow(clippy::too_many_arguments)]
async fn queue_symbol_datagram<S>(
    cx: &Cx,
    control: &mut FrameTransport<S>,
    adaptive: &mut RqAdaptiveSendState,
    sockets: &mut [UdpSocket],
    rr: &mut usize,
    symbols_sent: &mut u64,
    dropper: &mut u32,
    tag: u64,
    entry: u32,
    sym: &Symbol,
    config: &RqConfig,
    pacer: &mut RqSprayPacer,
    symbol_auth: Option<&SecurityContext>,
    send_batch: &mut RqPendingSendBatch,
    udp_send_acceleration: &mut UdpSendAccelerationReport,
) -> Result<(), RqError>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    cx.checkpoint().map_err(|_| RqError::Cancelled)?;
    if config.debug_drop_one_in > 0 {
        *dropper = dropper.wrapping_add(1);
        if *dropper % config.debug_drop_one_in == 0 {
            return Ok(());
        }
    }

    pacer.before_send(cx).await?;
    let auth = symbol_auth.map(|ctx| ctx.sign_symbol(sym));
    let dgram =
        encode_symbol_datagram(tag, entry, sym, auth.as_ref().map(AuthenticatedSymbol::tag));
    let fanout = send_batch.fanout();
    let socket_index = *rr % fanout;
    *rr = rr.wrapping_add(1);
    send_batch.push(socket_index, dgram);
    pacer.observe_datagram_sent();
    if send_batch.should_flush() {
        let report = send_batch.flush(sockets, symbols_sent).await?;
        udp_send_acceleration.observe_flush_report(report);
        service_rq_spray_control(cx, control, adaptive).await?;
    }
    Ok(())
}

async fn service_rq_spray_control<S>(
    cx: &Cx,
    control: &mut FrameTransport<S>,
    adaptive: &mut RqAdaptiveSendState,
) -> Result<(), RqError>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    cx.checkpoint().map_err(|_| RqError::Cancelled)?;
    while let Some(frame) = control.try_recv_ready().await? {
        match frame.frame_type() {
            FrameType::KeepAlive => adaptive.mark_control_peer_activity(),
            FrameType::Close => {
                return Err(RqError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "peer closed control during RQ spray",
                )));
            }
            // The receiver converged (or wants more) and sent a terminal/feedback frame while we
            // are still spraying — a fast-transfer race. Do NOT error: stash the frame so the
            // post-spray feedback loop's `recv()` handles it (Proof -> finalize, ObjectRequest ->
            // next round). Stop draining now; remaining sprayed symbols are harmless (the receiver
            // ignores extras and the sha256+merkle commit gate still verifies). Fixes zz35zq.
            _ => {
                control.stashed = Some(frame);
                break;
            }
        }
    }

    if adaptive.next_control_keepalive_due() {
        let frame =
            Frame::empty(FrameType::KeepAlive).map_err(|err| RqError::Frame(err.to_string()))?;
        control.send(&frame).await?;
    }

    if adaptive.control_liveness_expired() {
        return Err(RqError::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!(
                "peer liveness expired during RQ spray after {} missed beacon probes",
                adaptive.missed_control_probes()
            ),
        )));
    }

    Ok(())
}

async fn source_symbol_for_request(
    enc: &EntryEncoder,
    request: SourceSymbolRequest,
    config: &RqConfig,
) -> Result<Symbol, RqError> {
    if request.entry != enc.index {
        return Err(RqError::Coding(format!(
            "source request entry mismatch: request={}, encoder={}",
            request.entry, enc.index
        )));
    }
    let symbol_size = usize::from(config.symbol_size.max(1));
    let block_start = usize::from(request.sbn)
        .checked_mul(config.max_block_size)
        .ok_or_else(|| RqError::Coding("source request block offset overflow".to_string()))?;
    if block_start >= enc.size {
        return Err(RqError::Coding(format!(
            "source request block {} outside entry {} ({} bytes)",
            request.sbn, enc.index, enc.size
        )));
    }

    let block_len = config.max_block_size.min(enc.size - block_start);
    let block_k = block_len.div_ceil(symbol_size).max(1);
    let esi = usize::try_from(request.esi)
        .map_err(|_| RqError::Coding("source request ESI does not fit usize".to_string()))?;
    if esi >= block_k {
        return Err(RqError::Coding(format!(
            "source request esi {} outside entry {} block {} K={}",
            request.esi, enc.index, request.sbn, block_k
        )));
    }

    let start = block_start + esi * symbol_size;
    let end = (start + symbol_size).min(block_start + block_len);
    let mut buffer = vec![0u8; symbol_size];
    if start < end {
        let read_start = enc
            .source_offset
            .checked_add(start)
            .ok_or_else(|| RqError::Coding("source request range offset overflow".to_string()))?;
        let bytes = read_source_range(&enc.abs_path, read_start, end - start).await?;
        buffer[..bytes.len()].copy_from_slice(&bytes);
    }
    Ok(Symbol::new(
        SymbolId::new(enc.object_id, request.sbn, request.esi),
        buffer,
        SymbolKind::Source,
    ))
}

// ─── Public API: receive ─────────────────────────────────────────────────────

/// Accept exactly one transfer (one control connection) on `control_listener`,
/// receiving symbols on a freshly-bound UDP socket, write to `dest_dir`, verify,
/// and return a report.
pub async fn receive_once(
    cx: &Cx,
    control_listener: &TcpListener,
    udp_bind_ip: &str,
    dest_dir: &Path,
    config: RqConfig,
    peer_id: &str,
) -> Result<ReceiveReport, RqError> {
    let (stream, peer) = match crate::time::timeout(
        cx.now(),
        config.accept_timeout,
        control_listener.accept(),
    )
    .await
    {
        Ok(Ok(accepted)) => accepted,
        Ok(Err(err)) => return Err(RqError::Io(err)),
        Err(_elapsed) => {
            return Err(RqError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("accept timed out after {:?}", config.accept_timeout),
            )));
        }
    };
    receive_connection(cx, stream, peer, udp_bind_ip, dest_dir, config, peer_id).await
}

async fn bind_rq_receiver_udp_fanout(
    udp_bind_ip: &str,
    total_bytes: u64,
    config: &RqConfig,
) -> Result<(RqReceiverUdpFanout, Vec<u16>, u16), RqError> {
    let bind_ip: std::net::IpAddr = udp_bind_ip.parse().map_err(|error| {
        RqError::Source(format!("invalid UDP bind ip '{udp_bind_ip}': {error}"))
    })?;
    let recv_buf_bytes = if total_bytes == 0 {
        16 * 1024 * 1024
    } else {
        usize::try_from(total_bytes.saturating_add(32 * 1024 * 1024))
            .unwrap_or(usize::MAX)
            .clamp(16 * 1024 * 1024, 120 * 1024 * 1024)
    };
    let udp = RqReceiverUdpFanout::bind(bind_ip, config.udp_fanout.max(1), recv_buf_bytes).await?;
    let udp_ports = udp.local_ports()?;
    let udp_port = udp_ports.first().copied().ok_or_else(|| {
        RqError::Io(std::io::Error::new(
            std::io::ErrorKind::NotConnected,
            "RQ receiver UDP fanout has no bound sockets",
        ))
    })?;
    rqtrace!(
        "receiver: udp fanout sockets={} ports={:?}",
        udp.len(),
        udp_ports
    );
    Ok((udp, udp_ports, udp_port))
}

/// Drive a single accepted control connection through the receive protocol.
pub async fn receive_connection(
    cx: &Cx,
    stream: TcpStream,
    peer: SocketAddr,
    udp_bind_ip: &str,
    dest_dir: &Path,
    config: RqConfig,
    peer_id: &str,
) -> Result<ReceiveReport, RqError> {
    if config.delta_control_timeout.is_zero() {
        return Err(RqError::Control(
            "RQ delta_control_timeout must be greater than zero".to_string(),
        ));
    }
    let symbol_auth = config.symbol_auth_context()?;
    let symbol_auth_enabled = symbol_auth.is_some();
    let should_tune_for_bulk_source = near_clean_control_source_stream_round0(&config);
    if should_tune_for_bulk_source {
        tune_control_stream_for_bulk_source(&stream);
    }
    let mut control = FrameTransport::new(stream);

    // Handshake.
    let hello_frame =
        match crate::time::timeout(cx.now(), config.accept_timeout, control.recv()).await {
            Ok(result) => result?,
            Err(_) => {
                return Err(RqError::HandshakeRejected(format!(
                    "sender did not provide an RQ handshake within {:?}",
                    config.accept_timeout
                )));
            }
        };
    if hello_frame.frame_type() != FrameType::Handshake {
        return Err(RqError::Unexpected {
            got: hello_frame.frame_type(),
            expected: "Handshake",
        });
    }
    let hello: Hello = parse_json(&hello_frame)?;
    let strict_delta_context = rq_delta_control_auth_context(&config);
    let authenticated_delta_nonce = validate_rq_delta_hello(strict_delta_context, &hello)?;
    let delta_offered = authenticated_delta_nonce.is_some();
    let accepted = hello.protocol == ATP_RQ_PROTOCOL
        && hello.role == "sender"
        && hello.symbol_auth == symbol_auth_enabled
        && hello.total_bytes <= config.max_transfer_bytes
        && (!delta_offered || config.udp_fanout.max(1) <= RQ_DELTA_MAX_ADVERTISED_UDP_PORTS);
    let control_source_stream = accepted
        && hello.prefer_control_source_stream
        && control_source_stream_eligible(hello.total_bytes, &config);

    let defer_udp_until_manifest_proof =
        accepted && delta_offered && config.enable_delta && !control_source_stream;
    let (mut udp, udp_ports, udp_port) = if !accepted {
        (None, Vec::new(), 0)
    } else if control_source_stream {
        rqtrace!(
            "receiver: control_source_stream accepted total_bytes={}",
            hello.total_bytes
        );
        (None, Vec::new(), 0)
    } else if defer_udp_until_manifest_proof {
        (None, Vec::new(), 0)
    } else {
        let (udp, udp_ports, udp_port) =
            bind_rq_receiver_udp_fanout(udp_bind_ip, hello.total_bytes, &config).await?;
        (Some(udp), udp_ports, udp_port)
    };

    let rejection_reason = if accepted {
        None
    } else if hello.protocol != ATP_RQ_PROTOCOL {
        Some(format!(
            "unsupported protocol {} (this peer speaks {ATP_RQ_PROTOCOL})",
            hello.protocol
        ))
    } else if hello.role != "sender" {
        Some("RQ control peer did not identify as sender".to_string())
    } else if hello.symbol_auth != symbol_auth_enabled {
        Some(format!(
            "symbol authentication mismatch: sender={}, receiver={symbol_auth_enabled}",
            hello.symbol_auth
        ))
    } else if hello.total_bytes > config.max_transfer_bytes {
        Some(format!(
            "transfer size {} exceeds receiver maximum {}",
            hello.total_bytes, config.max_transfer_bytes
        ))
    } else if delta_offered && config.udp_fanout.max(1) > RQ_DELTA_MAX_ADVERTISED_UDP_PORTS {
        Some(format!(
            "RQ delta receiver fanout {} exceeds protocol maximum {RQ_DELTA_MAX_ADVERTISED_UDP_PORTS}",
            config.udp_fanout.max(1)
        ))
    } else {
        Some("handshake rejected".to_string())
    };
    let mut ack = HelloAck {
        accepted,
        peer_id: peer_id.to_string(),
        udp_port,
        udp_ports,
        control_source_stream,
        reason: rejection_reason.clone(),
        delta_transfer_nonce: None,
        delta_receiver_nonce: None,
        delta_destination_root: None,
        delta_server_auth_tag: None,
    };
    let mut delta_handshake = None;
    let mut delta_destination_binding = None;
    if accepted && let Some(sender_nonce) = authenticated_delta_nonce {
        let context = strict_delta_context.ok_or_else(|| {
            RqError::Authentication(
                "accepted RQ delta offer is missing strict authentication".to_string(),
            )
        })?;
        ack.delta_transfer_nonce = Some(sender_nonce);
        if config.enable_delta {
            let receiver_nonce = fresh_rq_delta_nonce(cx, b"receiver", Some(sender_nonce))?;
            let destination_binding =
                new_rq_delta_destination_binding(cx, context, receiver_nonce, dest_dir)?;
            ack.delta_receiver_nonce = Some(receiver_nonce);
            ack.delta_destination_root = Some(destination_binding.commitment);
            delta_destination_binding = Some(destination_binding);
        }
        ack.delta_server_auth_tag = Some(sign_rq_delta_ack(context, &hello, &ack)?);
        if let (Some(receiver_nonce), Some(destination_root)) =
            (ack.delta_receiver_nonce, ack.delta_destination_root)
        {
            delta_handshake = Some(RqDeltaHandshakeContext {
                sender_nonce,
                receiver_nonce,
                destination_root,
                handshake_hash: rq_delta_ack_transcript_digest(&hello, &ack)?,
            });
        }
    }
    let ack_frame = json_frame(FrameType::HandshakeAck, &ack)?;
    if delta_offered && accepted {
        send_delta_control_frame(
            cx,
            &mut control,
            &ack_frame,
            config.delta_control_timeout,
            "send authenticated acknowledgement",
        )
        .await?;
    } else {
        control.send(&ack_frame).await?;
    }
    if !accepted {
        return Err(RqError::HandshakeRejected(
            rejection_reason.unwrap_or_else(|| "handshake rejected".to_string()),
        ));
    }

    // Manifest. An accepted delta offer uses a sender-authenticated envelope;
    // no destination state is inspected before that proof verifies.
    let manifest_frame = if delta_handshake.is_some() {
        recv_delta_control_frame(
            cx,
            &mut control,
            config.delta_control_timeout,
            "receive authenticated manifest",
        )
        .await?
    } else {
        match crate::time::timeout(cx.now(), config.accept_timeout, control.recv()).await {
            Ok(result) => result?,
            Err(_) => {
                return Err(RqError::HandshakeRejected(format!(
                    "sender did not provide an RQ manifest within {:?}",
                    config.accept_timeout
                )));
            }
        }
    };
    if manifest_frame.frame_type() != FrameType::ObjectManifest {
        return Err(RqError::Unexpected {
            got: manifest_frame.frame_type(),
            expected: "ObjectManifest",
        });
    }
    let manifest = if let Some(handshake) = delta_handshake {
        let context = strict_delta_context.ok_or_else(|| {
            RqError::Authentication(
                "RQ delta manifest arrived without strict authentication".to_string(),
            )
        })?;
        let envelope: RqDeltaManifestEnvelope = parse_json(&manifest_frame)?;
        let session =
            derive_rq_delta_session(handshake, &hello.peer_id, peer_id, &envelope.manifest)?;
        validate_rq_delta_manifest_envelope(context, session, &envelope)?;
        validate_manifest(&envelope.manifest, &config)?;
        if hello.total_bytes != envelope.manifest.total_bytes {
            return Err(RqError::Frame(format!(
                "authenticated handshake total_bytes {} does not match manifest total_bytes {}",
                hello.total_bytes, envelope.manifest.total_bytes
            )));
        }
        let destination_binding = delta_destination_binding.ok_or_else(|| {
            RqError::Authentication(
                "RQ delta receiver lost its private destination binding".to_string(),
            )
        })?;
        validate_rq_delta_destination_binding(
            &destination_binding,
            context,
            handshake.receiver_nonce,
            dest_dir,
        )?;

        let request =
            build_rq_receiver_delta_request(cx, dest_dir, &config, &envelope.manifest).await?;
        let (request_udp_port, request_udp_ports) =
            if request.mode == DeltaWireMode::FullObject && !control_source_stream {
                let (bound_udp, ports, primary) =
                    bind_rq_receiver_udp_fanout(udp_bind_ip, hello.total_bytes, &config).await?;
                udp = Some(bound_udp);
                (primary, ports)
            } else {
                (0, Vec::new())
            };
        let request_envelope = make_rq_delta_request_envelope(
            context,
            session,
            &envelope.manifest,
            request.clone(),
            request_udp_port,
            request_udp_ports,
        )?;
        let request_frame = json_frame(FrameType::ObjectRequest, &request_envelope)?;
        send_delta_control_frame(
            cx,
            &mut control,
            &request_frame,
            config.delta_control_timeout,
            "send authenticated object request",
        )
        .await?;

        match request.mode {
            DeltaWireMode::FullObject => envelope.manifest,
            DeltaWireMode::AlreadyInSync => {
                let complete_frame = recv_delta_control_frame(
                    cx,
                    &mut control,
                    config.delta_control_timeout,
                    "receive authenticated zero completion",
                )
                .await?;
                if complete_frame.frame_type() != FrameType::ObjectComplete {
                    return Err(RqError::Unexpected {
                        got: complete_frame.frame_type(),
                        expected: "authenticated ObjectComplete",
                    });
                }
                let complete: RqDeltaCompleteEnvelope = parse_json(&complete_frame)?;
                validate_rq_delta_complete(context, session, &envelope.manifest, &complete)?;
                validate_rq_delta_destination_binding(
                    &destination_binding,
                    context,
                    handshake.receiver_nonce,
                    dest_dir,
                )?;
                let revalidated =
                    build_rq_receiver_delta_request(cx, dest_dir, &config, &envelope.manifest)
                        .await?;
                if revalidated != request || revalidated.mode != DeltaWireMode::AlreadyInSync {
                    return Err(RqError::Integrity(
                        "RQ destination changed before the authenticated no-op proof".to_string(),
                    ));
                }
                let receipt = ReceiveReceipt {
                    committed: true,
                    bytes_received: 0,
                    files: 1,
                    sha_ok: true,
                    merkle_ok: true,
                    symbols_accepted: 0,
                    feedback_rounds: 0,
                    reason: None,
                    // Absolute receiver paths are deliberately not disclosed on
                    // the plaintext control stream.
                    committed_paths: Vec::new(),
                };
                let proof = make_rq_delta_proof(context, session, &envelope.manifest, receipt)?;
                let proof_frame = json_frame(FrameType::Proof, &proof)?;
                send_delta_control_frame(
                    cx,
                    &mut control,
                    &proof_frame,
                    config.delta_control_timeout,
                    "send authenticated no-op proof",
                )
                .await?;
                let close = recv_delta_control_frame(
                    cx,
                    &mut control,
                    config.delta_control_timeout,
                    "receive authenticated delta close",
                )
                .await?;
                if close.frame_type() != FrameType::Close {
                    return Err(RqError::Unexpected {
                        got: close.frame_type(),
                        expected: "Close",
                    });
                }
                let committed_path =
                    safe_base_for_root_name(dest_dir, &envelope.manifest.root_name)?;
                return Ok(ReceiveReport {
                    transfer_id: envelope.manifest.transfer_id,
                    bytes_received: 0,
                    files: 1,
                    committed: true,
                    symbols_accepted: 0,
                    feedback_rounds: 0,
                    committed_paths: vec![committed_path],
                    peer,
                });
            }
            DeltaWireMode::DeltaChunks => {
                return Err(RqError::Control(
                    "RQ receiver emitted unsupported missing-chunk mode".to_string(),
                ));
            }
        }
    } else {
        parse_and_validate_manifest_frame(&manifest_frame, &config)?
    };
    if hello.total_bytes != 0 && hello.total_bytes != manifest.total_bytes {
        return Err(RqError::Frame(format!(
            "handshake total_bytes {} does not match manifest total_bytes {}",
            hello.total_bytes, manifest.total_bytes
        )));
    }
    let symbol_size = hello.symbol_size;
    let receiver_max_block_size = usize::try_from(hello.max_block_size).map_err(|_| {
        RqError::Frame(format!(
            "peer max_block_size {} does not fit usize",
            hello.max_block_size
        ))
    })?;
    let mut staging_guard = create_receive_staging_guard(dest_dir, &manifest.transfer_id).await?;
    let staging_dir = staging_guard.dir().to_path_buf();
    let single_file_fragment_staging = single_file_fragment_staging_path(&manifest, &staging_dir);
    let source_streaming = config.repair_overhead <= 1.0 && config.source_retransmit_rounds > 0;

    // Per-entry decoders.
    let mut decoders: Vec<EntryDecoder> = manifest
        .entries
        .iter()
        .map(|e| {
            let object_id = entry_object_id(&manifest.transfer_id, e.index);
            let (staging_path, staging_write_offset, staging_file_len, staging_shared) =
                receive_staging_layout_for_entry(
                    e,
                    &staging_dir,
                    single_file_fragment_staging.as_deref(),
                );
            let (pipeline, entry_source_streaming, source_blocks) = if control_source_stream {
                (None, false, Vec::new())
            } else {
                new_udp_entry_decode_state(
                    e,
                    object_id,
                    symbol_size,
                    receiver_max_block_size,
                    hello.max_block_size,
                    &config,
                    symbol_auth.as_ref(),
                    source_streaming,
                )
            };
            EntryDecoder {
                index: e.index,
                object_id,
                size: e.size,
                pipeline,
                complete: e.size == 0,
                staging_path: staging_path.clone(),
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
                inc: control_source_stream.then(|| {
                    crate::net::atp::transport_common::StagedEntryReceive::new(staging_path)
                }),
                inc_digest: None,
                source_write_buffer: if control_source_stream {
                    Vec::new()
                } else {
                    Vec::with_capacity(RQ_SOURCE_STAGE_BUFFER_BYTES)
                },
                source_write_buffer_offset: None,
            }
        })
        .collect();

    let receive_result: Result<ReceiveReport, RqError> = async {
        if control_source_stream {
            return receive_control_source_stream(
            cx,
            &mut control,
            &manifest,
            symbol_auth.as_ref(),
            &mut decoders,
            dest_dir,
            peer,
        )
            .await;
        }

        let mut udp = udp.expect("UDP receiver is bound for non-control-source transfers");
    let tag = transfer_tag(&manifest.transfer_id);
    let mut symbols_accepted: u64 = 0;
    let mut round_stats = RqDatagramRoundStats::default();
    let mut feedback_rounds: u32 = 0;
    let trace_receiver_intake = std::env::var_os("ATP_RQ_TRACE").is_some();
    let datagram_header_len = if symbol_auth_enabled {
        AUTH_DGRAM_HEADER
    } else {
        DGRAM_HEADER
    };
    let mut rbuf = vec![0u8; usize::from(symbol_size) + datagram_header_len + 64];
    let mut round_wall_start = trace_receiver_intake.then(Instant::now);

    // Drive: alternate between draining UDP symbols and responding to the
    // sender's ObjectComplete on the control channel. We pump UDP between
    // control messages by racing a short-bounded recv against control readiness.
    loop {
        cx.checkpoint().map_err(|_| RqError::Cancelled)?;

        // First, drain any control message that is ready (ObjectComplete ends a
        // spray round). We do a blocking control.recv() because the sender only
        // sends ObjectComplete after finishing a spray round, and we have been
        // consuming UDP concurrently via the pump below.
        //
        // To keep v1 correct on the current runtime without a select primitive,
        // we structure it as: pump UDP until the control frame arrives.
        let frame = pump_until_control(
            cx,
            &mut control,
            &mut udp,
            tag,
            symbol_auth_enabled,
            symbol_auth.as_ref(),
            &mut rbuf,
            &mut decoders,
            symbol_size,
            &mut symbols_accepted,
            &mut round_stats,
            trace_receiver_intake,
        )
        .await?;
        rqtrace!(
            "receiver: pump returned {:?}, symbols_accepted={symbols_accepted}",
            frame.frame_type()
        );

        match frame.frame_type() {
            FrameType::ObjectComplete => {
                let round_complete = parse_round_complete(&frame)?;
                let completion_digests =
                    CompletionDigestIndex::from_round_complete(&round_complete, &manifest, false)?;
                let drained = drain_round_tail(
                    cx,
                    &mut udp,
                    tag,
                    symbol_auth_enabled,
                    symbol_auth.as_ref(),
                    &mut rbuf,
                    config.round_tail_drain,
                    &mut decoders,
                    symbol_size,
                    &mut symbols_accepted,
                    &mut round_stats,
                    trace_receiver_intake,
                )
                .await?;
                if drained > 0 {
                    rqtrace!("receiver: tail-drained {drained} datagrams after ObjectComplete");
                }
                let seed_stats = flush_and_seed_source_streaming_round_boundary(
                    cx,
                    &mut decoders,
                    symbol_size,
                    symbol_auth.as_ref(),
                )
                .await?;
                round_stats.record_decode_stats(seed_stats.decode_stats);
                if seed_stats.seeded > 0 {
                    rqtrace!(
                        "receiver: seeded {} source-streaming block(s) at round boundary",
                        seed_stats.seeded
                    );
                }
                let decode_width_budget = rq_decode_width_budget_for_cx(cx, &decoders, symbol_size);
                let pending_decode_jobs_before_join = rq_pending_decode_jobs(&decoders);
                let completed_decode_stats =
                    join_all_pending_decodes(cx, &mut decoders, decode_width_budget).await?;
                round_stats.record_decode_stats(completed_decode_stats);
                let pending_decode_jobs_after_join = rq_pending_decode_jobs(&decoders);
                if completed_decode_stats.attempts > 0 {
                    rqtrace!(
                        "receiver: finalized {} pending decode job(s) after ObjectComplete (decode_repair_attempts={} decode_source_complete_attempts={} completed_blocks={} stale_requeues={} decode_micros={} decode_join_wait_micros={} decode_apply_micros={} decode_persist_micros={} decode_queued_jobs={} decode_inline_jobs={} decode_spawn_denials={} decode_entry_cap_saturations={} decode_transfer_cap_saturations={} decode_pending_peak={})",
                        completed_decode_stats.attempts,
                        completed_decode_stats.repair_attempts,
                        completed_decode_stats.source_complete_attempts,
                        completed_decode_stats.completed_blocks,
                        completed_decode_stats.stale_requeues,
                        completed_decode_stats.decode_micros,
                        completed_decode_stats.join_wait_micros,
                        completed_decode_stats.apply_micros,
                        completed_decode_stats.persist_micros,
                        completed_decode_stats.queued_jobs,
                        completed_decode_stats.inline_jobs,
                        completed_decode_stats.spawn_denials,
                        completed_decode_stats.entry_cap_saturations,
                        completed_decode_stats.transfer_cap_saturations,
                        completed_decode_stats.pending_peak
                    );
                }
                flush_cached_entry_staging_files(&mut decoders).await?;

                let pending: Vec<u32> = decoders
                    .iter()
                    .filter(|d| !d.complete)
                    .map(|d| d.index)
                    .collect();
                let round_loss_fraction = receiver_round_loss_fraction(
                    round_stats.observed,
                    round_complete.round_symbols_sent,
                );
                let decode_budget =
                    rq_decode_width_budget_snapshot_for_cx(cx, &decoders, symbol_size);
                let round_wall_micros = elapsed_micros_since(round_wall_start);
                rqtrace!(
                    "receiver: ObjectComplete; {} of {} entries still pending round_symbols_sent={} round_symbols_observed={} round_symbols_accepted={} round_source_observed={} round_source_accepted={} round_repair_observed={} round_repair_accepted={} round_loss_fraction={:.4} intake_payload_bytes={} round_wall_micros={} round_wall_symbols_per_s={} round_wall_bytes_per_s={} intake_micros={} intake_symbols_per_s={} intake_bytes_per_s={} parse_micros={} feed_micros={} source_auth_micros={} source_persist_micros={} pipeline_feed_micros={} block_persist_micros={} decode_dispatch_micros={} source_seed_micros={} feed_other_micros={} recv_micros={} drain_micros={} decode_attempts={} decode_repair_attempts={} decode_source_complete_attempts={} decode_completed_blocks={} decode_stale_requeues={} decode_micros={} decode_join_wait_micros={} decode_apply_micros={} decode_persist_micros={} decode_queued_jobs={} decode_inline_jobs={} decode_spawn_denials={} decode_entry_cap_saturations={} decode_transfer_cap_saturations={} decode_pending_peak={} pending_decode_jobs_before_join={} pending_decode_jobs_after_join={} decode_width_budget={} decode_core_limit={} decode_memory_limit={} decode_job_memory_bytes={} decode_max_block_bytes={}",
                    pending.len(),
                    decoders.len(),
                    round_complete.round_symbols_sent,
                    round_stats.observed,
                    round_stats.accepted,
                    round_stats.source_observed,
                    round_stats.source_accepted,
                    round_stats.repair_observed,
                    round_stats.repair_accepted,
                    round_loss_fraction.unwrap_or(0.0),
                    round_stats.payload_bytes,
                    round_wall_micros,
                    rate_per_second(round_stats.observed, round_wall_micros),
                    rate_per_second(round_stats.payload_bytes, round_wall_micros),
                    round_stats.intake_micros(),
                    round_stats.intake_symbols_per_s(),
                    round_stats.intake_bytes_per_s(),
                    round_stats.parse_micros,
                    round_stats.feed_micros,
                    round_stats.source_auth_micros,
                    round_stats.source_persist_micros,
                    round_stats.pipeline_feed_micros,
                    round_stats.block_persist_micros,
                    round_stats.decode_dispatch_micros,
                    round_stats.source_seed_micros,
                    round_stats.feed_other_micros,
                    round_stats.recv_micros,
                    round_stats.drain_micros,
                    round_stats.decode_stats.attempts,
                    round_stats.decode_stats.repair_attempts,
                    round_stats.decode_stats.source_complete_attempts,
                    round_stats.decode_stats.completed_blocks,
                    round_stats.decode_stats.stale_requeues,
                    round_stats.decode_stats.decode_micros,
                    round_stats.decode_stats.join_wait_micros,
                    round_stats.decode_stats.apply_micros,
                    round_stats.decode_stats.persist_micros,
                    round_stats.decode_stats.queued_jobs,
                    round_stats.decode_stats.inline_jobs,
                    round_stats.decode_stats.spawn_denials,
                    round_stats.decode_stats.entry_cap_saturations,
                    round_stats.decode_stats.transfer_cap_saturations,
                    round_stats.decode_stats.pending_peak,
                    pending_decode_jobs_before_join,
                    pending_decode_jobs_after_join,
                    decode_budget.effective,
                    decode_budget.core_limit,
                    decode_budget.memory_limit,
                    decode_budget.job_memory_bytes,
                    decode_budget.max_block_size
                );
                trace_receiver_decode_profile(
                    "ObjectComplete",
                    feedback_rounds,
                    round_stats.decode_stats,
                    decode_budget.effective,
                );

                if pending.is_empty() {
                    // Verify + commit + Proof.
                    let receipt = verify_and_commit(
                        &manifest,
                        &mut decoders,
                        dest_dir,
                        symbols_accepted,
                        feedback_rounds,
                        &std::collections::BTreeMap::new(),
                        &completion_digests,
                    )
                    .await?;
                    control
                        .send(&json_frame(FrameType::Proof, &receipt)?)
                        .await?;
                    drain_sender_close_after_proof(cx, &mut control, "udp-round").await;
                    if !receipt.committed {
                        return Err(RqError::Integrity(
                            receipt
                                .reason
                                .unwrap_or_else(|| "verification failed".to_string()),
                        ));
                    }
                    let committed_paths: Vec<PathBuf> =
                        receipt.committed_paths.iter().map(PathBuf::from).collect();
                    return Ok(ReceiveReport {
                        transfer_id: manifest.transfer_id,
                        bytes_received: receipt.bytes_received,
                        files: receipt.files,
                        committed: true,
                        symbols_accepted,
                        feedback_rounds,
                        committed_paths,
                        peer,
                    });
                }

                // Ask for more symbols for the pending entries.
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
                    let _ = control.send(&json_frame(FrameType::Proof, &receipt)?).await;
                    return Err(RqError::NoConvergence {
                        rounds: feedback_rounds,
                        pending: pending.len(),
                    });
                }
                let source_symbols = source_retransmit_request_limit(&config, feedback_rounds)
                    .map_or_else(Vec::new, |limit| collect_source_requests(&decoders, limit));
                let progress = source_progress_for_pending(&decoders, &pending);
                if trace_receiver_intake {
                    rqtrace!(
                        "receiver: NeedMore round={feedback_rounds} pending={} source_requests={} round_symbols_sent={} round_symbols_observed={} round_symbols_accepted={} round_source_observed={} round_source_accepted={} round_repair_observed={} round_repair_accepted={} round_loss_fraction={:.4} symbols_accepted={} intake_payload_bytes={} round_wall_micros={} round_wall_symbols_per_s={} round_wall_bytes_per_s={} intake_micros={} intake_symbols_per_s={} intake_bytes_per_s={} parse_micros={} feed_micros={} source_auth_micros={} source_persist_micros={} pipeline_feed_micros={} block_persist_micros={} decode_dispatch_micros={} source_seed_micros={} feed_other_micros={} recv_micros={} drain_micros={} decode_attempts={} decode_repair_attempts={} decode_source_complete_attempts={} decode_completed_blocks={} decode_stale_requeues={} decode_micros={} decode_join_wait_micros={} decode_apply_micros={} decode_persist_micros={} decode_queued_jobs={} decode_inline_jobs={} decode_spawn_denials={} decode_entry_cap_saturations={} decode_transfer_cap_saturations={} decode_pending_peak={} decode_width_budget={} decode_core_limit={} decode_memory_limit={} decode_job_memory_bytes={} decode_max_block_bytes={} source_received={}/{} pending_decode_jobs={} rank={}/{} rank_deficit={} rank_blocks={}",
                        pending.len(),
                        source_symbols.len(),
                        round_complete.round_symbols_sent,
                        round_stats.observed,
                        round_stats.accepted,
                        round_stats.source_observed,
                        round_stats.source_accepted,
                        round_stats.repair_observed,
                        round_stats.repair_accepted,
                        round_loss_fraction.unwrap_or(0.0),
                        symbols_accepted,
                        round_stats.payload_bytes,
                        round_wall_micros,
                        rate_per_second(round_stats.observed, round_wall_micros),
                        rate_per_second(round_stats.payload_bytes, round_wall_micros),
                        round_stats.intake_micros(),
                        round_stats.intake_symbols_per_s(),
                        round_stats.intake_bytes_per_s(),
                        round_stats.parse_micros,
                        round_stats.feed_micros,
                        round_stats.source_auth_micros,
                        round_stats.source_persist_micros,
                        round_stats.pipeline_feed_micros,
                        round_stats.block_persist_micros,
                        round_stats.decode_dispatch_micros,
                        round_stats.source_seed_micros,
                        round_stats.feed_other_micros,
                        round_stats.recv_micros,
                        round_stats.drain_micros,
                        round_stats.decode_stats.attempts,
                        round_stats.decode_stats.repair_attempts,
                        round_stats.decode_stats.source_complete_attempts,
                        round_stats.decode_stats.completed_blocks,
                        round_stats.decode_stats.stale_requeues,
                        round_stats.decode_stats.decode_micros,
                        round_stats.decode_stats.join_wait_micros,
                        round_stats.decode_stats.apply_micros,
                        round_stats.decode_stats.persist_micros,
                        round_stats.decode_stats.queued_jobs,
                        round_stats.decode_stats.inline_jobs,
                        round_stats.decode_stats.spawn_denials,
                        round_stats.decode_stats.entry_cap_saturations,
                        round_stats.decode_stats.transfer_cap_saturations,
                        round_stats.decode_stats.pending_peak,
                        decode_budget.effective,
                        decode_budget.core_limit,
                        decode_budget.memory_limit,
                        decode_budget.job_memory_bytes,
                        decode_budget.max_block_size,
                        progress.source_received,
                        progress.source_needed,
                        progress.pending_decode_jobs,
                        progress.rank,
                        progress.rank_columns,
                        progress.rank_deficit,
                        progress.rank_blocks,
                    );
                    trace_receiver_decode_profile(
                        "NeedMore",
                        feedback_rounds,
                        round_stats.decode_stats,
                        decode_budget.effective,
                    );
                }

                control
                    .send(&json_frame(
                        FrameType::ObjectRequest,
                        &NeedMore {
                            pending,
                            source_symbols,
                            round_symbols_observed: Some(round_stats.observed),
                            round_symbols_accepted: Some(round_stats.accepted),
                            round_loss_fraction,
                            pending_rank: Some(usize_to_u64(progress.rank)),
                            pending_rank_columns: Some(usize_to_u64(progress.rank_columns)),
                            pending_rank_deficit: Some(usize_to_u64(progress.rank_deficit)),
                            pending_decode_jobs: Some(usize_to_u64(progress.pending_decode_jobs)),
                        },
                    )?)
                    .await?;
                round_stats = RqDatagramRoundStats::default();
                round_wall_start = trace_receiver_intake.then(Instant::now);
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
                    "sender closed control before transfer completed",
                )));
            }
            other => {
                return Err(RqError::Unexpected {
                    got: other,
                    expected: "ObjectComplete | KeepAlive",
                });
            }
        }
    }
    }
    .await;

    // Close every cached staging handle before cooperative removal. The armed
    // guard remains a cancellation/error backstop if Windows AV or sharing
    // contention still makes this explicit cleanup fail.
    drop(decoders);
    match crate::fs::remove_dir_all(&staging_dir).await {
        Ok(()) => staging_guard.disarm(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => staging_guard.disarm(),
        Err(error) if receive_result.is_ok() => return Err(RqError::Io(error)),
        Err(_) => {}
    }
    receive_result
}

#[allow(clippy::too_many_arguments)]
async fn apply_control_source_data_frame(
    frame: &Frame,
    transfer_id: &str,
    symbol_auth: Option<&SecurityContext>,
    decoders: &mut [EntryDecoder],
    manifest: &TransferManifest,
    logical: &mut BTreeMap<String, crate::net::atp::transport_common::StagedEntryReceive>,
    logical_done: &mut BTreeMap<String, (u64, crate::atp::object::ObjectId, [u8; 32])>,
) -> Result<usize, RqError> {
    let data = parse_control_source_data_frame(frame, transfer_id, symbol_auth)?;
    let pos = decoder_position_for_entry(decoders, data.entry).ok_or_else(|| {
        RqError::Frame(format!(
            "control source ObjectData for unknown entry {}",
            data.entry
        ))
    })?;
    let dec = &mut decoders[pos];
    let len_u64 = u64::try_from(data.data.len()).unwrap_or(u64::MAX);
    let end = data.offset.checked_add(len_u64).ok_or_else(|| {
        RqError::Frame(format!(
            "control source ObjectData entry {} offset overflow",
            data.entry
        ))
    })?;
    if data.offset != dec.bytes_written {
        return Err(RqError::Frame(format!(
            "control source ObjectData entry {} offset {} does not match expected {}",
            data.entry, data.offset, dec.bytes_written
        )));
    }
    if end > dec.size {
        return Err(RqError::Frame(format!(
            "control source ObjectData entry {} overruns declared size {}",
            data.entry, dec.size
        )));
    }
    if data.data.is_empty() {
        return Ok(0);
    }

    write_entry_staging_range(dec, data.offset, data.data).await?;
    // Fold the chunk into the incremental digest in receive order. The offset
    // == bytes_written guard above guarantees strictly in-order contiguous
    // bytes, so this equals a post-stream hash of the staged file.
    if let Some(inc) = dec.inc.as_mut() {
        inc.update_with_chunk(data.data);
    }
    // L2: for a fragmented logical file, also fold the chunk into a per-logical-
    // file running hash. Fragments stream in shard order and each is in-order,
    // so the concatenation of arrival-order chunks equals the logical file; this
    // lets commit skip the post-stream re-read of every fragment (the remaining
    // clean-link tail after the per-fragment inc-hash).
    if let Some(frag) = manifest
        .entries
        .iter()
        .find(|e| e.index == data.entry)
        .and_then(|e| e.fragment.as_ref())
    {
        let lh = logical.entry(frag.rel_path.clone()).or_insert_with(|| {
            crate::net::atp::transport_common::StagedEntryReceive::new(std::path::PathBuf::from(
                &frag.rel_path,
            ))
        });
        lh.update_with_chunk(data.data);
        if lh.bytes_written == frag.logical_size {
            if let Some(done) = logical.remove(&frag.rel_path) {
                let (d, _p, _c) = done.finalize(String::new());
                logical_done.insert(
                    frag.rel_path.clone(),
                    (d.size, d.content_id, d.content_sha256),
                );
            }
        }
    }
    dec.bytes_written = end;
    if dec.bytes_written == dec.size {
        dec.complete = true;
        dec.pipeline = None;
        close_cached_entry_staging_file(dec).await?;
        if let Some(inc) = dec.inc.take() {
            let (digest, _path, _created) = inc.finalize(String::new());
            dec.inc_digest = Some((digest.size, digest.content_id, digest.content_sha256));
        }
    }
    Ok(data.data.len())
}

async fn receive_control_source_stream<S>(
    cx: &Cx,
    control: &mut FrameTransport<S>,
    manifest: &TransferManifest,
    symbol_auth: Option<&SecurityContext>,
    decoders: &mut [EntryDecoder],
    dest_dir: &Path,
    peer: SocketAddr,
) -> Result<ReceiveReport, RqError>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let mut bytes_streamed = 0u64;
    let mut chunks = 0u64;
    // L2: per-logical-file running hashes for fragmented objects, finalized in
    // arrival order so commit can skip the post-stream fragment re-read.
    let mut logical: BTreeMap<String, crate::net::atp::transport_common::StagedEntryReceive> =
        BTreeMap::new();
    let mut logical_done: BTreeMap<String, (u64, crate::atp::object::ObjectId, [u8; 32])> =
        BTreeMap::new();
    loop {
        cx.checkpoint().map_err(|_| RqError::Cancelled)?;
        let frame = control.recv().await?;
        match frame.frame_type() {
            FrameType::ObjectData => {
                let n = apply_control_source_data_frame(
                    &frame,
                    &manifest.transfer_id,
                    symbol_auth,
                    decoders,
                    manifest,
                    &mut logical,
                    &mut logical_done,
                )
                .await?;
                bytes_streamed =
                    bytes_streamed.saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
                chunks = chunks.saturating_add(1);
            }
            FrameType::ObjectComplete => {
                let complete = parse_round_complete(&frame)?;
                let completion_digests =
                    CompletionDigestIndex::from_round_complete(&complete, manifest, true)?;
                flush_cached_entry_staging_files(decoders).await?;
                let pending: Vec<u32> = decoders
                    .iter()
                    .filter(|decoder| !decoder.complete)
                    .map(|decoder| decoder.index)
                    .collect();
                if !pending.is_empty() {
                    let receipt = ReceiveReceipt {
                        committed: false,
                        bytes_received: bytes_streamed,
                        files: u32::try_from(manifest.entries.len()).unwrap_or(u32::MAX),
                        sha_ok: false,
                        merkle_ok: false,
                        symbols_accepted: 0,
                        feedback_rounds: 0,
                        reason: Some(format!(
                            "control source stream ended with {} entries pending",
                            pending.len()
                        )),
                        committed_paths: Vec::new(),
                    };
                    let _ = control.send(&json_frame(FrameType::Proof, &receipt)?).await;
                    return Err(RqError::NoConvergence {
                        rounds: 0,
                        pending: pending.len(),
                    });
                }

                let receipt = verify_and_commit(
                    manifest,
                    decoders,
                    dest_dir,
                    0,
                    0,
                    &logical_done,
                    &completion_digests,
                )
                .await?;
                control
                    .send(&json_frame(FrameType::Proof, &receipt)?)
                    .await?;
                drain_sender_close_after_proof(cx, control, "control-source").await;
                if !receipt.committed {
                    return Err(RqError::Integrity(
                        receipt
                            .reason
                            .unwrap_or_else(|| "verification failed".to_string()),
                    ));
                }
                rqtrace!(
                    "receiver: control_source_stream committed chunks={} bytes={}",
                    chunks,
                    bytes_streamed
                );
                let committed_paths: Vec<PathBuf> =
                    receipt.committed_paths.iter().map(PathBuf::from).collect();
                return Ok(ReceiveReport {
                    transfer_id: manifest.transfer_id.clone(),
                    bytes_received: receipt.bytes_received,
                    files: receipt.files,
                    committed: true,
                    symbols_accepted: 0,
                    feedback_rounds: 0,
                    committed_paths,
                    peer,
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
                    "sender closed control before source stream completed",
                )));
            }
            other => {
                return Err(RqError::Unexpected {
                    got: other,
                    expected: "ObjectData | ObjectComplete | KeepAlive",
                });
            }
        }
    }
}

/// Feed one received symbol into an entry's decoding pipeline. Returns true if
/// the symbol was a well-formed candidate the pipeline accepted or considered
/// (used only for the accepted-datagram counter, not correctness).
fn source_block_progress_for(
    size: u64,
    max_block_size: usize,
    symbol_size: u16,
) -> Option<Vec<SourceBlockProgress>> {
    if size == 0 {
        return Some(Vec::new());
    }

    let mut blocks = Vec::new();
    let mut start = 0u64;
    let block_size = u64::try_from(max_block_size.max(1)).unwrap_or(u64::MAX);
    let symbol_size = u64::from(symbol_size.max(1));
    while start < size {
        if blocks.len() >= MAX_SOURCE_BLOCKS {
            return None;
        }
        let remaining = size - start;
        let len_u64 = remaining.min(block_size);
        let len = usize::try_from(len_u64).ok()?;
        let k = usize::try_from(len_u64.div_ceil(symbol_size)).ok()?.max(1);
        blocks.push(SourceBlockProgress {
            start,
            len,
            k,
            received: vec![false; k],
            pipeline_seeded: vec![false; k],
            auth_tags: vec![None; k],
            received_count: 0,
            complete: false,
        });
        start = start.checked_add(len_u64)?;
    }
    Some(blocks)
}

fn collect_source_requests(decoders: &[EntryDecoder], limit: usize) -> Vec<SourceSymbolRequest> {
    let mut requests = Vec::new();
    for decoder in decoders {
        if decoder.complete {
            continue;
        }
        if decoder.source_streaming {
            for (sbn, block) in decoder.source_blocks.iter().enumerate() {
                if block.complete {
                    continue;
                }
                for (esi, received) in block.received.iter().enumerate() {
                    if *received {
                        continue;
                    }
                    if limit != 0 && requests.len() >= limit {
                        return requests;
                    }
                    let Ok(esi) = u32::try_from(esi) else {
                        break;
                    };
                    requests.push(SourceSymbolRequest {
                        entry: decoder.index,
                        sbn: u8::try_from(sbn).unwrap_or(u8::MAX),
                        esi,
                    });
                }
            }
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
            |MissingSourceSymbol { sbn, esi }| SourceSymbolRequest {
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

#[derive(Debug, Default, Clone, Copy)]
struct PendingDecodeProgress {
    source_received: usize,
    source_needed: usize,
    pending_decode_jobs: usize,
    rank: usize,
    rank_columns: usize,
    rank_deficit: usize,
    rank_blocks: usize,
}

fn source_progress_for_pending(
    decoders: &[EntryDecoder],
    pending: &[u32],
) -> PendingDecodeProgress {
    let mut progress = PendingDecodeProgress::default();
    for decoder in decoders
        .iter()
        .filter(|decoder| pending.contains(&decoder.index))
    {
        progress.pending_decode_jobs = progress
            .pending_decode_jobs
            .saturating_add(decoder.pending_decodes.len());
        for (sbn, block) in decoder.source_blocks.iter().enumerate() {
            progress.source_received = progress
                .source_received
                .saturating_add(block.received_count);
            progress.source_needed = progress.source_needed.saturating_add(block.k);
            let Some(sbn) = u8::try_from(sbn).ok() else {
                continue;
            };
            let Some(status) = decoder
                .pipeline
                .as_ref()
                .and_then(|pipeline| pipeline.block_status(sbn))
            else {
                continue;
            };
            let Some(rank) = status.rank else {
                continue;
            };
            let deficit = status.rank_deficit.unwrap_or(0);
            progress.rank = progress.rank.saturating_add(rank);
            progress.rank_columns = progress
                .rank_columns
                .saturating_add(rank.saturating_add(deficit));
            progress.rank_deficit = progress.rank_deficit.saturating_add(deficit);
            progress.rank_blocks = progress.rank_blocks.saturating_add(1);
        }
    }
    progress
}

async fn feed_pipeline_auth_symbol_with_cx(
    cx: &Cx,
    dec: &mut EntryDecoder,
    parsed: &ParsedDatagram,
    auth: AuthenticatedSymbol,
    symbol_size: u16,
    symbol_auth: Option<&SecurityContext>,
    preverified: bool,
    allow_spawn_decode: bool,
    transfer_decode_width: usize,
    trace_intake: bool,
) -> Result<RqSymbolFeed, RqError> {
    let mut feed = RqSymbolFeed::default();
    if dec.pipeline.is_none() {
        return Ok(feed);
    }
    let pipeline_start = trace_intake.then(Instant::now);
    let result = if preverified {
        dec.pipeline
            .as_mut()
            .expect("checked above")
            .feed_preverified_streaming_block_deferred(auth)
    } else {
        dec.pipeline
            .as_mut()
            .expect("checked above")
            .feed_streaming_block_deferred(auth)
    };
    feed.pipeline_feed_micros = feed
        .pipeline_feed_micros
        .saturating_add(elapsed_micros_since(pipeline_start));
    let accepted = match result {
        Ok(DeferredSymbolAcceptResult::Decode(job)) => {
            let dispatch_start = trace_intake.then(Instant::now);
            let dispatch = dispatch_decode_job(
                cx,
                dec,
                job,
                "received repair/source symbol",
                allow_spawn_decode,
                transfer_decode_width,
            )
            .await?;
            feed.decode_dispatch_micros = feed
                .decode_dispatch_micros
                .saturating_add(elapsed_micros_since(dispatch_start));
            feed.decode_stats.merge(dispatch.decode_stats);
            true
        }
        Ok(DeferredSymbolAcceptResult::Immediate(SymbolAcceptResult::Accepted {
            received,
            needed,
        })) => {
            if received >= needed || received % 64 == 0 {
                rqtrace!(
                    "receiver: entry {} accepted sbn={} esi={} kind={:?} received={} needed={}",
                    dec.index,
                    parsed.sbn,
                    parsed.esi,
                    parsed.kind,
                    received,
                    needed
                );
            }
            true
        }
        Ok(DeferredSymbolAcceptResult::Immediate(SymbolAcceptResult::DecodingStarted {
            block_sbn,
        })) => {
            rqtrace!(
                "receiver: entry {} started decode block {} via esi={} kind={:?}",
                dec.index,
                block_sbn,
                parsed.esi,
                parsed.kind
            );
            true
        }
        Ok(DeferredSymbolAcceptResult::Immediate(SymbolAcceptResult::BlockComplete {
            block_sbn,
            data,
        })) => {
            let persist_start = trace_intake.then(Instant::now);
            persist_decoded_block(dec, block_sbn, &data).await?;
            feed.block_persist_micros = feed
                .block_persist_micros
                .saturating_add(elapsed_micros_since(persist_start));
            // `persist_decoded_block` may have already completed the entry via the source-block
            // tracker (mixed source+FEC, E-9). Otherwise fall back to the pipeline's own view
            // (the all-FEC / non-source-streaming path).
            if dec.complete
                || dec
                    .pipeline
                    .as_ref()
                    .is_some_and(DecodingPipeline::is_complete)
            {
                dec.complete = true;
                dec.pipeline = None;
            }
            rqtrace!(
                "receiver: entry {} completed block {} via esi={} kind={:?}",
                dec.index,
                block_sbn,
                parsed.esi,
                parsed.kind
            );
            true
        }
        Ok(DeferredSymbolAcceptResult::Immediate(SymbolAcceptResult::Duplicate)) => {
            rqtrace!(
                "receiver: entry {} duplicate sbn={} esi={} kind={:?}",
                dec.index,
                parsed.sbn,
                parsed.esi,
                parsed.kind
            );
            false
        }
        Ok(DeferredSymbolAcceptResult::Immediate(SymbolAcceptResult::Rejected(reason))) => {
            rqtrace!(
                "receiver: entry {} rejected sbn={} esi={} kind={:?} reason={:?}",
                dec.index,
                parsed.sbn,
                parsed.esi,
                parsed.kind,
                reason
            );
            false
        }
        Err(err) => {
            rqtrace!(
                "receiver: entry {} feed error sbn={} esi={} kind={:?}: {err}",
                dec.index,
                parsed.sbn,
                parsed.esi,
                parsed.kind
            );
            false
        }
    };
    if accepted && dec.source_streaming && parsed.kind.is_repair() {
        let seed_start = trace_intake.then(Instant::now);
        feed.decode_stats.merge(
            seed_source_streaming_pipeline(
                cx,
                dec,
                parsed.sbn,
                symbol_size,
                symbol_auth,
                allow_spawn_decode,
                transfer_decode_width,
            )
            .await?,
        );
        feed.source_seed_micros = feed
            .source_seed_micros
            .saturating_add(elapsed_micros_since(seed_start));
    }
    feed.accepted = accepted;
    Ok(feed)
}

async fn feed_symbol_with_cx(
    cx: &Cx,
    dec: &mut EntryDecoder,
    parsed: &ParsedDatagram,
    payload: &[u8],
    symbol_size: u16,
    symbol_auth: Option<&SecurityContext>,
    allow_spawn_decode: bool,
    transfer_decode_width: usize,
    trace_intake: bool,
) -> Result<RqSymbolFeed, RqError> {
    if dec.complete {
        return Ok(RqSymbolFeed::default());
    }
    if payload.len() != usize::from(symbol_size) {
        // RaptorQ symbols are fixed-size; ignore malformed/truncated payloads.
        // (The final block's short tail is zero-padded by the encoder, so all
        // emitted symbols are symbol_size bytes.)
        return Ok(RqSymbolFeed::default());
    }
    let mut feed = RqSymbolFeed::default();
    let mut pipeline_auth = None;
    if dec.source_streaming && parsed.kind.is_source() {
        if let Some(tag) = parsed.auth_tag {
            let Some(context) = symbol_auth else {
                return Ok(feed);
            };
            let sym = Symbol::new(
                SymbolId::new(dec.object_id, parsed.sbn, parsed.esi),
                payload.to_vec(),
                parsed.kind,
            );
            let mut auth = AuthenticatedSymbol::from_parts(sym, tag);
            let auth_start = trace_intake.then(Instant::now);
            if context.verify_authenticated_symbol(&mut auth).is_err() {
                feed.source_auth_micros = feed
                    .source_auth_micros
                    .saturating_add(elapsed_micros_since(auth_start));
                rqtrace!(
                    "receiver: entry {} rejected source-streamed sbn={} esi={} auth tag",
                    dec.index,
                    parsed.sbn,
                    parsed.esi
                );
                return Ok(feed);
            }
            feed.source_auth_micros = feed
                .source_auth_micros
                .saturating_add(elapsed_micros_since(auth_start));
            if auth.is_verified() {
                let persist_start = trace_intake.then(Instant::now);
                feed.accepted = persist_source_symbol(dec, parsed, payload, symbol_size).await?;
                feed.source_persist_micros = feed
                    .source_persist_micros
                    .saturating_add(elapsed_micros_since(persist_start));
                return Ok(feed);
            }
            pipeline_auth = Some(auth);
        } else if symbol_auth.is_some() {
            return Ok(feed);
        } else {
            let persist_start = trace_intake.then(Instant::now);
            feed.accepted = persist_source_symbol(dec, parsed, payload, symbol_size).await?;
            feed.source_persist_micros = feed
                .source_persist_micros
                .saturating_add(elapsed_micros_since(persist_start));
            return Ok(feed);
        }
    }
    let auth = if let Some(auth) = pipeline_auth {
        auth
    } else {
        let sym = Symbol::new(
            SymbolId::new(dec.object_id, parsed.sbn, parsed.esi),
            payload.to_vec(),
            parsed.kind,
        );
        if let Some(tag) = parsed.auth_tag {
            AuthenticatedSymbol::from_parts(sym, tag)
        } else {
            AuthenticatedSymbol::new_unauthenticated(sym)
        }
    };
    let pipeline_feed = feed_pipeline_auth_symbol_with_cx(
        cx,
        dec,
        parsed,
        auth,
        symbol_size,
        symbol_auth,
        false,
        allow_spawn_decode,
        transfer_decode_width,
        trace_intake,
    )
    .await?;
    feed.pipeline_feed_micros = feed
        .pipeline_feed_micros
        .saturating_add(pipeline_feed.pipeline_feed_micros);
    feed.block_persist_micros = feed
        .block_persist_micros
        .saturating_add(pipeline_feed.block_persist_micros);
    feed.decode_dispatch_micros = feed
        .decode_dispatch_micros
        .saturating_add(pipeline_feed.decode_dispatch_micros);
    feed.source_seed_micros = feed
        .source_seed_micros
        .saturating_add(pipeline_feed.source_seed_micros);
    feed.decode_stats.merge(pipeline_feed.decode_stats);
    feed.accepted = pipeline_feed.accepted;
    Ok(feed)
}

#[cfg(test)]
async fn feed_symbol(
    dec: &mut EntryDecoder,
    parsed: &ParsedDatagram,
    payload: &[u8],
    symbol_size: u16,
    symbol_auth: Option<&SecurityContext>,
) -> Result<bool, RqError> {
    let cx = Cx::for_testing();
    let feed = feed_symbol_with_cx(
        &cx,
        dec,
        parsed,
        payload,
        symbol_size,
        symbol_auth,
        true,
        RQ_MAX_PENDING_DECODE_JOBS_PER_TRANSFER_HARD,
        false,
    )
    .await?;
    while !dec.pending_decodes.is_empty() {
        let _ =
            join_one_pending_decode(&cx, dec, true, RQ_MAX_PENDING_DECODE_JOBS_PER_TRANSFER_HARD)
                .await?;
    }
    Ok(feed.accepted)
}

async fn dispatch_decode_job(
    cx: &Cx,
    dec: &mut EntryDecoder,
    job: BlockDecodeJob,
    trigger: &'static str,
    allow_spawn_decode: bool,
    transfer_decode_width: usize,
) -> Result<DecodeDispatchOutcome, RqError> {
    let block_sbn = job.sbn();
    let mut decode_stats =
        drain_ready_entry_decodes(cx, dec, allow_spawn_decode, transfer_decode_width).await?;
    if block_decode_pending(dec, block_sbn) {
        rqtrace!(
            "receiver: entry {} dropped duplicate decode job for block {} from {trigger}",
            dec.index,
            block_sbn
        );
        if let Some(pipeline) = dec.pipeline.as_mut() {
            pipeline.restore_decode_job(job);
        }
        return Ok(DecodeDispatchOutcome::new(
            DecodeDispatch::Queued,
            decode_stats,
        ));
    }

    let entry_decode_width = entry_decode_width_budget(dec, transfer_decode_width);
    if entry_decode_width <= 1 {
        while !dec.pending_decodes.is_empty() {
            let joined = join_one_pending_decode(cx, dec, false, transfer_decode_width).await?;
            decode_stats.merge(joined);
            if dec.complete || dec.pipeline.is_none() || block_decode_pending(dec, block_sbn) {
                return Ok(DecodeDispatchOutcome::new(
                    DecodeDispatch::NoProgress,
                    decode_stats,
                ));
            }
        }
        decode_stats.merge(
            finalize_decode_outcome(
                cx,
                dec,
                run_block_decode_job(job),
                false,
                transfer_decode_width,
            )
            .await?,
        );
        decode_stats.record_inline_job();
        rqtrace!(
            "receiver: entry {} ran decode block {} inline from {trigger} because entry size/block-count is below the parallel decode gate",
            dec.index,
            block_sbn
        );
        return Ok(DecodeDispatchOutcome::new(
            DecodeDispatch::NoProgress,
            decode_stats,
        ));
    }

    if !allow_spawn_decode {
        decode_stats.record_transfer_cap_saturation();
        let joined = join_one_pending_decode(cx, dec, false, transfer_decode_width).await?;
        decode_stats.merge(joined);
        rqtrace!(
            "receiver: entry {} joined {} pending decode job(s) before queueing block {} from {trigger} because transfer decode width is saturated",
            dec.index,
            joined.attempts,
            block_sbn
        );
        if dec.complete || dec.pipeline.is_none() || block_decode_pending(dec, block_sbn) {
            if let Some(pipeline) = dec.pipeline.as_mut() {
                pipeline.restore_decode_job(job);
            }
            return Ok(DecodeDispatchOutcome::new(
                DecodeDispatch::NoProgress,
                decode_stats,
            ));
        }
    }
    if !can_spawn_parallel_decode(dec.pending_decodes.len(), entry_decode_width) {
        decode_stats.record_entry_cap_saturation();
        let joined = join_one_pending_decode(cx, dec, false, transfer_decode_width).await?;
        decode_stats.merge(joined);
        rqtrace!(
            "receiver: entry {} joined {} pending decode job(s) before queueing block {} from {trigger} (entry_cap={entry_decode_width})",
            dec.index,
            joined.attempts,
            block_sbn
        );
        if dec.complete || dec.pipeline.is_none() || block_decode_pending(dec, block_sbn) {
            if let Some(pipeline) = dec.pipeline.as_mut() {
                pipeline.restore_decode_job(job);
            }
            return Ok(DecodeDispatchOutcome::new(
                DecodeDispatch::NoProgress,
                decode_stats,
            ));
        }
    }

    let retry_job = job.clone();
    match cx.spawn_blocking(move |_child| run_block_decode_job(job)) {
        Ok(handle) => {
            dec.pending_decodes
                .push(PendingDecode { block_sbn, handle });
            decode_stats.record_queued_job(dec.pending_decodes.len());
            rqtrace!(
                "receiver: entry {} queued parallel decode block {} from {trigger}",
                dec.index,
                block_sbn
            );
            Ok(DecodeDispatchOutcome::new(
                DecodeDispatch::Queued,
                decode_stats,
            ))
        }
        Err(crate::runtime::state::SpawnError::RuntimeUnavailable) => {
            decode_stats.record_spawn_denial();
            decode_stats.merge(
                finalize_decode_outcome(
                    cx,
                    dec,
                    run_block_decode_job(retry_job),
                    false,
                    transfer_decode_width,
                )
                .await?,
            );
            decode_stats.record_inline_job();
            rqtrace!(
                "receiver: entry {} ran decode block {} inline from {trigger} because no runtime spawn gateway is available",
                dec.index,
                block_sbn
            );
            Ok(DecodeDispatchOutcome::new(
                DecodeDispatch::NoProgress,
                decode_stats,
            ))
        }
        Err(err) => {
            decode_stats.record_spawn_denial();
            let joined = join_one_pending_decode(cx, dec, false, transfer_decode_width).await?;
            decode_stats.merge(joined);
            rqtrace!(
                "receiver: entry {} joined {} pending decode job(s) after spawn denial for block {} from {trigger}: {err:?}",
                dec.index,
                joined.attempts,
                block_sbn
            );
            if dec.complete || dec.pipeline.is_none() || block_decode_pending(dec, block_sbn) {
                if let Some(pipeline) = dec.pipeline.as_mut() {
                    pipeline.restore_decode_job(retry_job);
                }
                return Ok(DecodeDispatchOutcome::new(
                    DecodeDispatch::NoProgress,
                    decode_stats,
                ));
            }
            let restore_job = retry_job.clone();
            match cx.spawn_blocking(move |_child| run_block_decode_job(retry_job)) {
                Ok(handle) => {
                    dec.pending_decodes
                        .push(PendingDecode { block_sbn, handle });
                    decode_stats.record_queued_job(dec.pending_decodes.len());
                    rqtrace!(
                        "receiver: entry {} queued parallel decode block {} from {trigger} after spawn-denial backpressure",
                        dec.index,
                        block_sbn
                    );
                    Ok(DecodeDispatchOutcome::new(
                        DecodeDispatch::Queued,
                        decode_stats,
                    ))
                }
                Err(retry_err) => {
                    decode_stats.record_spawn_denial();
                    rqtrace!(
                        "receiver: entry {} deferred decode block {} from {trigger} after repeated spawn denial: {retry_err:?}",
                        dec.index,
                        block_sbn
                    );
                    if let Some(pipeline) = dec.pipeline.as_mut() {
                        pipeline.restore_decode_job(restore_job);
                    }
                    Ok(DecodeDispatchOutcome::new(
                        DecodeDispatch::NoProgress,
                        decode_stats,
                    ))
                }
            }
        }
    }
}

async fn seed_source_streaming_pipeline(
    cx: &Cx,
    dec: &mut EntryDecoder,
    target_sbn: u8,
    symbol_size: u16,
    symbol_auth: Option<&SecurityContext>,
    allow_spawn_decode: bool,
    transfer_decode_width: usize,
) -> Result<RqDecodeRoundStats, RqError> {
    let mut decode_stats = RqDecodeRoundStats::default();
    if dec.pipeline.is_none() {
        return Ok(decode_stats);
    }
    if block_decode_pending(dec, target_sbn) {
        return Ok(decode_stats);
    }
    let symbol_size = usize::from(symbol_size);
    let target_sbn_index = usize::from(target_sbn);
    if !source_streaming_block_ready_to_seed(dec, target_sbn_index) {
        return Ok(decode_stats);
    }
    flush_cached_entry_staging_file(dec).await?;
    let Some(mut reader) = crate::fs::File::open(&dec.staging_path).await.ok() else {
        return Ok(decode_stats);
    };

    // Seed only the repair block and only once retained repair equations plus staged source
    // symbols can reach K. This keeps lossy transfers from retaining source payloads for many
    // partially-repaired blocks while still feeding the same symbols before decode.
    if dec.source_blocks[target_sbn_index].complete {
        return Ok(decode_stats);
    }

    let sbn = target_sbn_index;
    let k = dec.source_blocks[sbn].k;
    let block_start = dec.source_blocks[sbn].start;
    let block_len = dec.source_blocks[sbn].len;
    let mut source_block = vec![0u8; block_len];
    // Seed reads MUST use the same shared-staging mapping the writers use:
    // `block_start` is ENTRY-relative, but `staging_path` is the SHARED
    // fragment for the whole logical object (large entries are E-12 shards
    // with `staging_write_offset` bases). Seeking the raw relative offset
    // read shard 0's bytes for every later shard, poisoning seeded source
    // symbols → InconsistentEquations when redundancy caught it, silent
    // rank-K-exact wrong solves (per-entry SHA mismatch) when it did not.
    // Entry 0 (base 0) was immune, which is why only later shards rejected
    // (c54to7, MATRIX-207).
    let absolute_block_start = entry_staging_absolute_offset(dec, block_start, block_len)?;
    reader
        .seek(std::io::SeekFrom::Start(absolute_block_start))
        .await?;
    reader.read_exact(&mut source_block).await?;

    for esi in 0..k {
        let Some((within_block, take, auth_tag)) =
            source_seed_symbol_plan(dec, sbn, esi, symbol_size)?
        else {
            continue;
        };
        let mut payload = vec![0u8; symbol_size];
        payload[..take].copy_from_slice(&source_block[within_block..within_block + take]);

        let sbn_u8 = u8::try_from(sbn).map_err(|_| {
            RqError::Coding(format!("entry {} source seed SBN overflow", dec.index))
        })?;
        let esi_u32 = u32::try_from(esi).map_err(|_| {
            RqError::Coding(format!("entry {} source seed ESI overflow", dec.index))
        })?;
        let symbol = Symbol::new(
            SymbolId::new(dec.object_id, sbn_u8, esi_u32),
            payload,
            SymbolKind::Source,
        );
        let preverified_source_seed = symbol_auth.is_some();
        let auth_symbol = if preverified_source_seed {
            let tag = auth_tag.ok_or_else(|| {
                RqError::Authentication(format!(
                    "entry {} source seed missing verified auth tag for sbn={sbn} esi={esi}",
                    dec.index
                ))
            })?;
            // Source-streaming tags are stored only after receiver-boundary
            // verification succeeds, so seeding the FEC pipeline must not pay a
            // second serial HMAC over the same staged source symbol.
            AuthenticatedSymbol::new_verified(symbol, tag)
        } else {
            AuthenticatedSymbol::new_unauthenticated(symbol)
        };
        let result = if preverified_source_seed {
            dec.pipeline
                .as_mut()
                .expect("checked above")
                .feed_preverified_streaming_block_deferred(auth_symbol)
        } else {
            dec.pipeline
                .as_mut()
                .expect("checked above")
                .feed_streaming_block_deferred(auth_symbol)
        };
        if result.is_ok() {
            dec.source_blocks[sbn].pipeline_seeded[esi] = true;
        }
        match result {
            Ok(DeferredSymbolAcceptResult::Immediate(SymbolAcceptResult::BlockComplete {
                block_sbn,
                data,
            })) => {
                persist_decoded_block(dec, block_sbn, &data).await?;
                // `persist_decoded_block` may have completed the entry (mixed source+FEC, E-9)
                // and already dropped the pipeline; stop seeding so the next loop iteration does
                // not touch a `None` pipeline.
                if dec.complete
                    || dec
                        .pipeline
                        .as_ref()
                        .is_some_and(DecodingPipeline::is_complete)
                {
                    dec.complete = true;
                    dec.pipeline = None;
                    return Ok(decode_stats);
                }
            }
            Ok(DeferredSymbolAcceptResult::Immediate(_)) => {}
            Ok(DeferredSymbolAcceptResult::Decode(job)) => {
                let dispatch = dispatch_decode_job(
                    cx,
                    dec,
                    job,
                    "source-streaming repair seed",
                    allow_spawn_decode,
                    transfer_decode_width,
                )
                .await?;
                decode_stats.merge(dispatch.decode_stats);
                match dispatch.dispatch {
                    DecodeDispatch::Queued => return Ok(decode_stats),
                    DecodeDispatch::NoProgress => {}
                }
            }
            Err(err) => {
                rqtrace!(
                    "receiver: entry {} source seed error sbn={} esi={}: {err}",
                    dec.index,
                    sbn,
                    esi
                );
            }
        }
    }

    Ok(decode_stats)
}

async fn flush_and_seed_source_streaming_round_boundary(
    cx: &Cx,
    decoders: &mut [EntryDecoder],
    symbol_size: u16,
    symbol_auth: Option<&SecurityContext>,
) -> Result<SourceStreamingSeedStats, RqError> {
    for dec in decoders.iter_mut() {
        flush_cached_entry_staging_file(dec).await?;
    }

    let mut seed_stats = SourceStreamingSeedStats::default();
    for decoder_index in 0..decoders.len() {
        let block_count = decoders[decoder_index].source_blocks.len();
        for sbn in 0..block_count {
            if decoders[decoder_index].complete || decoders[decoder_index].pipeline.is_none() {
                break;
            }
            if !source_streaming_block_ready_to_seed(&decoders[decoder_index], sbn) {
                continue;
            }
            let transfer_decode_width = rq_decode_width_budget_for_cx(cx, decoders, symbol_size);
            let allow_spawn_decode = rq_pending_decode_jobs(decoders) < transfer_decode_width;
            let Ok(block_sbn) = u8::try_from(sbn) else {
                break;
            };
            let decode_stats = seed_source_streaming_pipeline(
                cx,
                &mut decoders[decoder_index],
                block_sbn,
                symbol_size,
                symbol_auth,
                allow_spawn_decode,
                transfer_decode_width,
            )
            .await?;
            seed_stats.decode_stats.merge(decode_stats);
            seed_stats.seeded = seed_stats.seeded.saturating_add(1);
        }
    }
    Ok(seed_stats)
}

async fn persist_source_symbol(
    dec: &mut EntryDecoder,
    parsed: &ParsedDatagram,
    payload: &[u8],
    symbol_size: u16,
) -> Result<bool, RqError> {
    let sbn = usize::from(parsed.sbn);
    if sbn >= dec.source_blocks.len() {
        return Ok(false);
    }
    let Ok(esi) = usize::try_from(parsed.esi) else {
        return Ok(false);
    };
    let symbol_size = usize::from(symbol_size);
    let Some(within_block) = esi.checked_mul(symbol_size) else {
        return Err(RqError::Coding(format!(
            "entry {} source symbol offset overflow",
            dec.index
        )));
    };

    let (offset, take) = {
        let block = &dec.source_blocks[sbn];
        if block.complete || esi >= block.k || block.received[esi] || within_block >= block.len {
            return Ok(false);
        }
        let take = symbol_size.min(block.len - within_block);
        let offset = block
            .start
            .checked_add(u64::try_from(within_block).unwrap_or(u64::MAX))
            .ok_or_else(|| {
                RqError::Coding(format!("entry {} source symbol offset overflow", dec.index))
            })?;
        (offset, take)
    };

    write_source_staging_range(dec, offset, &payload[..take]).await?;

    let completed_now = {
        let block = &mut dec.source_blocks[sbn];
        if block.received[esi] {
            return Ok(false);
        }
        block.received[esi] = true;
        block.auth_tags[esi] = parsed.auth_tag;
        block.received_count = block.received_count.saturating_add(1);
        if block.received_count == block.k {
            block.complete = true;
            dec.bytes_written = dec
                .bytes_written
                .checked_add(u64::try_from(block.len).unwrap_or(u64::MAX))
                .ok_or_else(|| {
                    RqError::Coding(format!("entry {} byte counter overflow", dec.index))
                })?;
            true
        } else {
            false
        }
    };

    if completed_now {
        rqtrace!(
            "receiver: entry {} completed source-streamed block {}",
            dec.index,
            parsed.sbn
        );
    }
    if source_streaming_entry_complete(dec) {
        dec.complete = true;
        dec.pipeline = None;
        close_cached_entry_staging_file(dec).await?;
    }
    Ok(true)
}

async fn open_entry_staging_file(dec: &mut EntryDecoder) -> Result<crate::fs::File, RqError> {
    if let Some(parent) = dec.staging_path.parent() {
        crate::fs::create_dir_all(parent).await?;
    }

    if dec.staging_created {
        return Ok(crate::fs::File::options()
            .read(true)
            .write(true)
            .open(&dec.staging_path)
            .await?);
    }

    let file = crate::fs::File::create_new(&dec.staging_path)
        .await
        .map_err(|err| {
            if err.kind() == std::io::ErrorKind::AlreadyExists {
                if dec.staging_shared {
                    RqError::Io(err)
                } else {
                    RqError::Frame(format!(
                        "staging file already exists for entry {}",
                        dec.index
                    ))
                }
            } else {
                RqError::Io(err)
            }
        });
    let file = match file {
        Ok(file) => file,
        Err(RqError::Io(err))
            if dec.staging_shared && err.kind() == std::io::ErrorKind::AlreadyExists =>
        {
            crate::fs::File::options()
                .read(true)
                .write(true)
                .open(&dec.staging_path)
                .await?
        }
        Err(err) => return Err(err),
    };
    file.set_len(dec.staging_file_len).await?;
    dec.staging_created = true;
    Ok(file)
}

async fn close_cached_entry_staging_file(dec: &mut EntryDecoder) -> Result<(), RqError> {
    flush_source_write_buffer(dec).await?;
    if let Some(mut file) = dec.staging_file.take() {
        file.flush().await?;
    }
    dec.staging_cursor = None;
    dec.staging_unflushed_bytes = 0;
    Ok(())
}

/// Env-gated (`ATP_RQ_INCONSISTENT_AUDIT`) staged-bytes cross-dump for a
/// block whose decode rejected with InconsistentEquations (c54to7): one line
/// per source ESI with the received/seeded bitmap flags and the staged
/// payload fingerprint (same FNV-1a as the decoder-side symbol dump). A
/// seeded symbol whose decoder-side hash differs from the staged hash for
/// the same ESI pins seed-path poisoning; matching hashes with an
/// inconsistent solve point at the repair side instead. Best-effort: any IO
/// error just truncates the dump.
async fn audit_staging_block_dump(dec: &mut EntryDecoder, sbn: u8) {
    if std::env::var_os("ATP_RQ_INCONSISTENT_AUDIT").is_none() {
        return;
    }
    let sbn_index = usize::from(sbn);
    let Some(block) = dec.source_blocks.get(sbn_index) else {
        return;
    };
    let (k, block_start, block_len) = (block.k, block.start, block.len);
    let received: Vec<bool> = block.received.clone();
    let seeded: Vec<bool> = block.pipeline_seeded.clone();
    let Some(symbol_size) = dec
        .pipeline
        .as_ref()
        .map(|pipeline| usize::from(pipeline.config_symbol_size()))
        .filter(|size| *size > 0)
    else {
        return;
    };
    if flush_cached_entry_staging_file(dec).await.is_err() {
        return;
    }
    let Ok(mut reader) = crate::fs::File::open(&dec.staging_path).await else {
        return;
    };
    let Ok(absolute_block_start) = entry_staging_absolute_offset(dec, block_start, block_len)
    else {
        return;
    };
    let mut source_block = vec![0u8; block_len];
    if reader
        .seek(std::io::SeekFrom::Start(absolute_block_start))
        .await
        .is_err()
        || reader.read_exact(&mut source_block).await.is_err()
    {
        return;
    }
    eprintln!(
        "[RQ_AUDIT] staging_dump entry={} sbn={sbn} k={k} block_len={block_len} abs_start={absolute_block_start}",
        dec.index
    );
    // Hash the zero-PADDED symbol form (exactly how the seed path builds
    // pipeline symbols) so staged hashes compare 1:1 with the decoder-side
    // symbol dump, including the short final symbol.
    let mut padded = vec![0u8; symbol_size];
    for esi in 0..k {
        let within = esi.saturating_mul(symbol_size);
        if within >= block_len {
            break;
        }
        let take = symbol_size.min(block_len - within);
        padded.fill(0);
        padded[..take].copy_from_slice(&source_block[within..within + take]);
        eprintln!(
            "[RQ_AUDIT] staged entry={} sbn={sbn} esi={esi} received={} seeded={} take={take} h8={:016x}",
            dec.index,
            received.get(esi).copied().unwrap_or(false),
            seeded.get(esi).copied().unwrap_or(false),
            crate::decoding::audit_fnv1a64(&padded),
        );
    }
}

async fn flush_cached_entry_staging_file(dec: &mut EntryDecoder) -> Result<(), RqError> {
    if is_round_scoped_entry_staging_cache(dec) {
        return close_cached_entry_staging_file(dec).await;
    }
    flush_source_write_buffer(dec).await?;
    if let Some(file) = dec.staging_file.as_mut() {
        file.flush().await?;
    }
    dec.staging_unflushed_bytes = 0;
    Ok(())
}

async fn flush_cached_entry_staging_files(decoders: &mut [EntryDecoder]) -> Result<(), RqError> {
    for dec in decoders {
        flush_cached_entry_staging_file(dec).await?;
    }
    Ok(())
}

async fn write_entry_staging_range(
    dec: &mut EntryDecoder,
    offset: u64,
    data: &[u8],
) -> Result<(), RqError> {
    flush_source_write_buffer(dec).await?;
    write_entry_staging_range_unbuffered(dec, offset, data).await
}

async fn write_source_staging_range(
    dec: &mut EntryDecoder,
    offset: u64,
    data: &[u8],
) -> Result<(), RqError> {
    if data.is_empty() {
        return Ok(());
    }
    if !dec.cache_staging_file {
        return write_entry_staging_range_unbuffered(dec, offset, data).await;
    }

    let contiguous = dec.source_write_buffer_offset.is_some_and(|buffer_offset| {
        buffer_offset.checked_add(u64::try_from(dec.source_write_buffer.len()).unwrap_or(u64::MAX))
            == Some(offset)
    });

    if !contiguous
        || dec.source_write_buffer.len().saturating_add(data.len()) > RQ_SOURCE_STAGE_BUFFER_BYTES
    {
        flush_source_write_buffer(dec).await?;
    }

    if data.len() >= RQ_SOURCE_STAGE_BUFFER_BYTES {
        return write_entry_staging_range_unbuffered(dec, offset, data).await;
    }

    if dec.source_write_buffer.is_empty() {
        dec.source_write_buffer_offset = Some(offset);
    }
    dec.source_write_buffer.extend_from_slice(data);
    if dec.source_write_buffer.len() >= RQ_SOURCE_STAGE_BUFFER_BYTES {
        flush_source_write_buffer(dec).await?;
    }
    Ok(())
}

async fn flush_source_write_buffer(dec: &mut EntryDecoder) -> Result<(), RqError> {
    if dec.source_write_buffer.is_empty() {
        dec.source_write_buffer_offset = None;
        return Ok(());
    }

    let offset = dec.source_write_buffer_offset.take().ok_or_else(|| {
        RqError::Coding(format!(
            "entry {} source staging buffer missing offset",
            dec.index
        ))
    })?;
    let mut buffered = Vec::new();
    std::mem::swap(&mut buffered, &mut dec.source_write_buffer);
    let result = write_entry_staging_range_unbuffered(dec, offset, &buffered).await;
    buffered.clear();
    dec.source_write_buffer = buffered;
    result
}

async fn write_entry_staging_range_unbuffered(
    dec: &mut EntryDecoder,
    offset: u64,
    data: &[u8],
) -> Result<(), RqError> {
    let absolute_offset = entry_staging_absolute_offset(dec, offset, data.len())?;
    if dec.cache_staging_file {
        if dec.staging_file.is_none() {
            let file = open_entry_staging_file(dec).await?;
            dec.staging_file = Some(file);
            dec.staging_cursor = None;
            dec.staging_unflushed_bytes = 0;
        }

        let expected_cursor = dec.staging_cursor;
        let next_cursor = absolute_offset
            .checked_add(u64::try_from(data.len()).unwrap_or(u64::MAX))
            .ok_or_else(|| {
                RqError::Coding(format!("entry {} staging cursor overflow", dec.index))
            })?;
        let unflushed_bytes = dec.staging_unflushed_bytes.saturating_add(data.len());
        let should_flush = unflushed_bytes >= RQ_SOURCE_STAGE_BUFFER_BYTES;
        {
            let file = dec
                .staging_file
                .as_mut()
                .expect("staging file opened above");
            if expected_cursor != Some(absolute_offset) {
                file.seek(std::io::SeekFrom::Start(absolute_offset)).await?;
            } else if staging_cursor_audit_enabled() {
                // c54to7 diagnostic: validate the skip-seek invariant. The
                // cached-handle fast path assumes the shared fd offset always
                // equals the tracked cursor; a desync here silently lands
                // bytes at the wrong staging offset (per-entry SHA mismatch
                // at verify). Audit is env-gated (one extra lseek per
                // skip-eligible write) and self-heals by re-seeking.
                let actual = file.stream_position().await?;
                if actual != absolute_offset {
                    rqtrace!(
                        "receiver: entry {} STAGING_CURSOR_DESYNC expected={} actual={} len={}",
                        dec.index,
                        absolute_offset,
                        actual,
                        data.len()
                    );
                    file.seek(std::io::SeekFrom::Start(absolute_offset)).await?;
                }
            }
            file.write_all(data).await?;
            if should_flush {
                file.flush().await?;
            }
        }
        dec.staging_cursor = Some(next_cursor);
        dec.staging_unflushed_bytes = if should_flush { 0 } else { unflushed_bytes };
        return Ok(());
    }

    let mut file = open_entry_staging_file(dec).await?;
    file.seek(std::io::SeekFrom::Start(absolute_offset)).await?;
    file.write_all(data).await?;
    Ok(())
}

async fn create_receive_staging_guard(
    dest_dir: &Path,
    transfer_id: &str,
) -> Result<RqStagingDirGuard, RqError> {
    reject_rq_destination_ancestors(dest_dir).await?;
    crate::fs::create_dir_all(dest_dir).await?;
    reject_rq_destination_ancestors(dest_dir).await?;
    let dest_dir = dest_dir.to_path_buf();
    let transfer_id = transfer_id.to_string();
    let guard = crate::runtime::spawn_blocking_io(move || {
        for _ in 0..RQ_STAGING_CREATE_ATTEMPTS {
            let staging_seq = RQ_STAGING_SEQ.fetch_add(1, Ordering::Relaxed);
            let staging_nonce = OsEntropy.next_u64();
            let staging_dir = dest_dir.join(format!(
                ".atp-rq-staging-{transfer_id}-{staging_nonce:016x}-{staging_seq}"
            ));
            match std::fs::create_dir(&staging_dir) {
                Ok(()) => return Ok(RqStagingDirGuard::new(staging_dir)),
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(err) => return Err(err),
            }
        }

        Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!(
                "unable to create unique receiver staging directory for transfer {transfer_id}"
            ),
        ))
    })
    .await
    .map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            RqError::Frame(error.to_string())
        } else {
            RqError::Io(error)
        }
    })?;
    reject_rq_destination_ancestors(guard.dir()).await?;
    Ok(guard)
}

async fn reject_rq_destination_ancestors(path: &Path) -> Result<(), RqError> {
    for candidate in path.ancestors() {
        match path_is_link_or_reparse(candidate).await {
            Ok(true) => {
                return Err(RqError::Source(format!(
                    "destination path crosses existing symlink or reparse point: {}",
                    candidate.display()
                )));
            }
            Ok(false) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(RqError::Io(error)),
        }
    }
    Ok(())
}

// Full, uncached destination check used immediately before filesystem mutation.
// The earlier cached planning pass is only an optimization and cannot authorize
// a later write because another process may replace a previously missing prefix.
async fn reject_destination_symlink_prefix(base: &Path, out_path: &Path) -> Result<(), RqError> {
    let rel = out_path.strip_prefix(base).map_err(|_| {
        RqError::Source(format!(
            "destination path {} is outside safe base {}",
            out_path.display(),
            base.display()
        ))
    })?;

    for component in rel.components() {
        let Component::Normal(_) = component else {
            return Err(RqError::Source(format!(
                "unsafe destination component in {}",
                out_path.display()
            )));
        };
    }
    reject_rq_destination_ancestors(out_path).await
}

/// Planning-time variant that skips path prefixes already inspected in
/// `verified`. This catches ordinary conflicts cheaply across many files, but it
/// is not write authorization: every mutation repeats
/// [`reject_destination_symlink_prefix`] uncached immediately beforehand.
async fn reject_destination_symlink_prefix_cached(
    base: &Path,
    out_path: &Path,
    verified: &mut BTreeSet<PathBuf>,
) -> Result<(), RqError> {
    let rel = out_path.strip_prefix(base).map_err(|_| {
        RqError::Source(format!(
            "destination path {} is outside safe base {}",
            out_path.display(),
            base.display()
        ))
    })?;

    let mut current = base.to_path_buf();
    if verified.insert(current.clone()) {
        reject_existing_symlink(&current).await?;
    }
    for component in rel.components() {
        let Component::Normal(component) = component else {
            return Err(RqError::Source(format!(
                "unsafe destination component in {}",
                out_path.display()
            )));
        };
        current.push(component);
        if verified.insert(current.clone()) {
            reject_existing_symlink(&current).await?;
        }
    }
    Ok(())
}

async fn reject_existing_symlink(path: &Path) -> Result<(), RqError> {
    match path_is_link_or_reparse(path).await {
        Ok(true) => Err(RqError::Source(format!(
            "destination path crosses existing symlink or reparse point: {}",
            path.display()
        ))),
        Ok(false) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(RqError::Io(err)),
    }
}

async fn persist_decoded_block(
    dec: &mut EntryDecoder,
    block_sbn: u8,
    data: &[u8],
) -> Result<(), RqError> {
    let block_size = u64::try_from(dec.max_block_size).map_err(|_| {
        RqError::Coding(format!(
            "entry {} max_block_size does not fit u64: {}",
            dec.index, dec.max_block_size
        ))
    })?;
    let offset = u64::from(block_sbn)
        .checked_mul(block_size)
        .ok_or_else(|| RqError::Coding(format!("entry {} block offset overflow", dec.index)))?;
    let end = offset
        .checked_add(u64::try_from(data.len()).unwrap_or(u64::MAX))
        .ok_or_else(|| RqError::Coding(format!("entry {} block end overflow", dec.index)))?;
    if end > dec.size {
        return Err(RqError::Frame(format!(
            "decoded block {} for entry {} overruns declared size {}",
            block_sbn, dec.index, dec.size
        )));
    }

    write_entry_staging_range(dec, offset, data).await?;
    // E-9 fix: `source_blocks[sbn].complete` is the single source of truth for both completion
    // and byte accounting. A block decoded via FEC here can LATER also receive its final source
    // symbols via retransmit; if we do not mark it complete now, `persist_source_symbol` would
    // count this block's bytes a SECOND time (its `received_count == k` path), driving
    // `bytes_written` past the entry size and causing `verify_and_commit` to FALSELY reject a
    // byte-correct transfer as a "per-entry SHA-256 mismatch". Count the block exactly once and
    // mark it done so any late source symbol for it is ignored by `persist_source_symbol`.
    let block_idx = usize::from(block_sbn);
    let already_complete = dec
        .source_blocks
        .get(block_idx)
        .is_some_and(|block| block.complete);
    if !already_complete {
        dec.bytes_written = dec
            .bytes_written
            .checked_add(u64::try_from(data.len()).unwrap_or(u64::MAX))
            .ok_or_else(|| RqError::Coding(format!("entry {} byte counter overflow", dec.index)))?;
    }
    if let Some(block) = dec.source_blocks.get_mut(block_idx) {
        block.complete = true;
    }
    // When every source block is on disk (via source OR FEC) the entry is complete. This unifies
    // the previously-desynced completion trackers (`source_blocks[].complete` vs
    // `pipeline.is_complete()`) for the mixed source+FEC case, which is what NEITHER tracker fired
    // for before (→ the bad-regime non-convergence). Empty `source_blocks` = non-source-streaming
    // path, whose completion is still owned by `pipeline.is_complete()` at the call sites.
    if source_streaming_entry_complete(dec) {
        dec.complete = true;
        dec.pipeline = None;
        close_cached_entry_staging_file(dec).await?;
    }
    Ok(())
}

fn object_params_for(
    object_id: ObjectId,
    size: u64,
    symbol_size: u16,
    max_block_size: u64,
) -> ObjectParams {
    let max_block = usize::try_from(max_block_size).unwrap_or(DEFAULT_MAX_BLOCK_SIZE);
    let s = usize::from(symbol_size.max(1));
    let total = usize::try_from(size).unwrap_or(0);
    // Mirror the encoder's block plan: greedy max_block_size chunks.
    let mut blocks = 0u16;
    let mut max_k = 0usize;
    if total > 0 {
        let mut offset = 0usize;
        while offset < total {
            let len = (total - offset).min(max_block.max(1));
            let k = len.div_ceil(s);
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

#[derive(Debug, Clone)]
struct LargeObjectCommitShard {
    staging_path: PathBuf,
    staging_offset: u64,
    staging_shared: bool,
    fragment: LargeObjectFragment,
}

#[derive(Debug, Clone)]
struct PackedMemberWrite {
    offset: u64,
    len: u64,
    write_path: PathBuf,
    out_path: PathBuf,
    metadata: EntryMetadata,
}

/// Own every file a packed-member writer can leave behind.
///
/// The one-shot path runs in the blocking pool and can outlive a cancelled
/// receiver future. Keeping this guard inside that task until its result is
/// claimed ensures a dropped task result removes both the derived members and
/// their no-longer-needed packed source before the outer directory guard races
/// with them.
struct PackedMemberStagingGuard {
    paths: Vec<PathBuf>,
    parents: Vec<PathBuf>,
}

impl PackedMemberStagingGuard {
    fn new(pack_staging_path: &Path, members: &[PackedMemberWrite]) -> Self {
        let mut paths = members
            .iter()
            .map(|member| member.write_path.clone())
            .collect::<Vec<_>>();
        paths.push(pack_staging_path.to_path_buf());

        let mut parents = paths
            .iter()
            .filter_map(|path| path.parent().map(Path::to_path_buf))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        parents.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
        Self { paths, parents }
    }
}

impl Drop for PackedMemberStagingGuard {
    fn drop(&mut self) {
        for path in &self.paths {
            let _ = std::fs::remove_file(path);
        }
        for parent in &self.parents {
            let _ = std::fs::remove_dir(parent);
        }
    }
}

fn packed_member_staging_path(pack_staging_path: &Path, member_index: usize) -> PathBuf {
    let mut file_name = pack_staging_path.file_name().map_or_else(
        || std::ffi::OsString::from("rq-pack"),
        std::ffi::OsString::from,
    );
    file_name.push(format!(".member-{member_index}.staged"));
    pack_staging_path.with_file_name(file_name)
}

async fn apply_rq_entry_metadata(
    out_path: &Path,
    metadata: &EntryMetadata,
) -> Result<MetadataApplyReport, RqError> {
    if metadata.is_bare() {
        return Ok(MetadataApplyReport::default());
    }
    let report = apply_entry_metadata(out_path, metadata)
        .await
        .map_err(|error| RqError::Source(error.into_message()))?;
    for (field, reason) in &report.skipped {
        rqtrace!(
            "receiver: metadata field {field} skipped for {}: {reason}",
            out_path.display()
        );
    }
    for (required, field) in [
        (cfg!(unix) && metadata.unix_mode.is_some(), "mode"),
        (
            cfg!(any(unix, windows)) && metadata.mtime_unix_secs.is_some(),
            "mtime",
        ),
        (
            cfg!(windows) && metadata.windows_attributes.is_some(),
            "windows_attributes",
        ),
    ] {
        if required && !report.applied.contains(&field) {
            let reason = report
                .skipped
                .iter()
                .find_map(|(skipped, reason)| (*skipped == field).then_some(reason.as_str()))
                .unwrap_or("metadata field was not applied");
            return Err(RqError::Source(format!(
                "{}: required metadata field {field} was not preserved: {reason}",
                out_path.display()
            )));
        }
    }
    Ok(report)
}

fn split_rq_metadata_for_commit(
    metadata: &EntryMetadata,
) -> (EntryMetadata, Option<EntryMetadata>) {
    let before_commit = metadata.clone();
    #[cfg(windows)]
    {
        const FILE_ATTRIBUTE_READONLY: u32 = 0x0000_0001;
        if let Some(attributes) = metadata
            .windows_attributes
            .filter(|attributes| attributes & FILE_ATTRIBUTE_READONLY != 0)
        {
            let mut before_commit = before_commit;
            before_commit.windows_attributes = Some(attributes & !FILE_ATTRIBUTE_READONLY);
            // SetFileAttributesW replaces the complete attribute word, so the
            // post-commit record carries that word even though READONLY is the
            // only field intentionally deferred.
            let after_commit = EntryMetadata {
                windows_attributes: Some(attributes),
                ..EntryMetadata::default()
            };
            return (before_commit, Some(after_commit));
        }
    }
    (before_commit, None)
}

async fn prepare_rq_entry_metadata_for_commit(
    staging_path: &Path,
    metadata: &EntryMetadata,
) -> Result<Option<EntryMetadata>, RqError> {
    let (before_commit, after_commit) = split_rq_metadata_for_commit(metadata);
    apply_rq_entry_metadata(staging_path, &before_commit).await?;
    Ok(after_commit)
}

async fn apply_rq_directory_metadata(
    base: &Path,
    directories: &DirectoryMetadataManifest,
) -> Result<(), RqError> {
    let mut entries: Vec<&DirectoryMetadataEntry> = directories.entries.iter().collect();
    entries.sort_by(|left, right| {
        right
            .rel_path
            .split('/')
            .count()
            .cmp(&left.rel_path.split('/').count())
            .then_with(|| left.rel_path.cmp(&right.rel_path))
    });
    for entry in entries {
        let out_path = join_relative(base, &entry.rel_path)?;
        reject_destination_symlink_prefix(base, &out_path).await?;
        crate::fs::create_dir_all(&out_path).await?;
        reject_destination_symlink_prefix(base, &out_path).await?;
        apply_rq_entry_metadata(&out_path, &entry.metadata).await?;
    }
    if let Some(root) = &directories.root {
        reject_destination_symlink_prefix(base, base).await?;
        crate::fs::create_dir_all(base).await?;
        reject_destination_symlink_prefix(base, base).await?;
        apply_rq_entry_metadata(base, root).await?;
    }
    Ok(())
}

async fn hash_packed_members_streaming(
    staging_path: &Path,
    members: &[PackedMember],
    logical_digests: &mut Vec<EntryDigest>,
    logical_files: &mut u64,
    buf: &mut [u8],
) -> Result<bool, RqError> {
    let mut file = crate::fs::File::open(staging_path)
        .await
        .map_err(|e| RqError::Source(format!("{}: {e}", staging_path.display())))?;
    let mut cursor = 0u64;
    let mut sha_ok = true;

    for member in members {
        let next_cursor = member.offset.checked_add(member.len).ok_or_else(|| {
            RqError::Coding(format!(
                "{}: packed member {} byte range overflows",
                staging_path.display(),
                member.rel_path
            ))
        })?;
        if cursor != member.offset {
            file.seek(std::io::SeekFrom::Start(member.offset)).await?;
            cursor = member.offset;
        }

        let mut sha = Sha256::new();
        let mut content_id = crate::atp::object::ContentId::streaming();
        let mut remaining = member.len;
        while remaining > 0 {
            let want = usize::try_from(remaining.min(buf.len() as u64)).unwrap_or(buf.len());
            let n = file
                .read(&mut buf[..want])
                .await
                .map_err(|e| RqError::Source(format!("{}: {e}", staging_path.display())))?;
            if n == 0 {
                return Err(RqError::Source(format!(
                    "{}: short read while verifying packed member {}",
                    staging_path.display(),
                    member.rel_path
                )));
            }
            sha.update(&buf[..n]);
            content_id.update(&buf[..n]);
            remaining -= n as u64;
            cursor = cursor.saturating_add(n as u64);
        }

        let member_sha: [u8; 32] = sha.finalize().into();
        if hex_encode(&member_sha) != member.sha256_hex {
            sha_ok = false;
        }
        logical_digests.push(EntryDigest {
            rel_path: member.rel_path.clone(),
            size: member.len,
            content_id: crate::atp::object::ObjectId::content(content_id.finalize()),
            content_sha256: member_sha,
        });
        *logical_files = (*logical_files).saturating_add(1);
        cursor = next_cursor;
    }

    Ok(sha_ok)
}

/// One-shot packed-member commit cap: above this staged span the batch falls
/// back to the streaming cursor loop instead of materializing the span.
const PACKED_MEMBER_BATCH_ONESHOT_MAX_BYTES: u64 = 128 * 1024 * 1024;

/// Commit an entire packed small-file batch inside ONE blocking-pool task:
/// read the verified staged span once, then create/write every member with
/// raw `std::fs`. The serial async loop paid several pool round-trips per
/// tiny file (create + write + flush + staged reads ≈ thousands of
/// dispatches for a small tree), which is the commit_write tail rsync does
/// not pay (MATRIX-204/211). Parallel per-member writes buy little here —
/// same-directory creates serialize on the kernel dir lock — so the win is
/// eliminating dispatch overhead, not adding concurrency.
fn write_packed_member_batch_oneshot(
    staging_path: PathBuf,
    members: Vec<PackedMemberWrite>,
    span_start: u64,
    span_len: usize,
) -> std::io::Result<PackedMemberStagingGuard> {
    use std::io::{Read, Seek};

    let staging_guard = PackedMemberStagingGuard::new(&staging_path, &members);
    let mut staged = vec![0u8; span_len];
    let mut source = std::fs::File::open(&staging_path)?;
    source.seek(std::io::SeekFrom::Start(span_start))?;
    source.read_exact(&mut staged)?;
    drop(source);

    let mut created_parents: BTreeSet<PathBuf> = BTreeSet::new();
    for member in &members {
        if let Some(parent) = member.write_path.parent()
            && created_parents.insert(parent.to_path_buf())
        {
            std::fs::create_dir_all(parent)?;
        }
        let start = usize::try_from(member.offset - span_start)
            .map_err(|_| std::io::Error::other("packed member offset exceeds span"))?;
        let len = usize::try_from(member.len)
            .map_err(|_| std::io::Error::other("packed member length exceeds span"))?;
        let end = start
            .checked_add(len)
            .filter(|end| *end <= staged.len())
            .ok_or_else(|| std::io::Error::other("packed member range exceeds staged span"))?;
        std::fs::write(&member.write_path, &staged[start..end])?;
    }
    Ok(staging_guard)
}

async fn write_packed_member_batch(
    staging_path: &Path,
    members: &[PackedMemberWrite],
    buf: &mut [u8],
) -> Result<PackedMemberStagingGuard, RqError> {
    let span_start = members.iter().map(|member| member.offset).min();
    let span_end = members
        .iter()
        .map(|member| member.offset.saturating_add(member.len))
        .max();
    if let (Some(span_start), Some(span_end)) = (span_start, span_end)
        && members.len() > 1
        && span_end.saturating_sub(span_start) <= PACKED_MEMBER_BATCH_ONESHOT_MAX_BYTES
        && let Ok(span_len) = usize::try_from(span_end - span_start)
    {
        let staging = staging_path.to_path_buf();
        let batch = members.to_vec();
        let staging_display = staging_path.display().to_string();
        return crate::runtime::spawn_blocking_io(move || {
            write_packed_member_batch_oneshot(staging, batch, span_start, span_len)
        })
        .await
        .map_err(|e| RqError::Source(format!("{staging_display}: {e}")));
    }

    let staging_guard = PackedMemberStagingGuard::new(staging_path, members);
    let mut created_parents: BTreeSet<PathBuf> = BTreeSet::new();
    for member in members {
        if let Some(parent) = member.write_path.parent()
            && created_parents.insert(parent.to_path_buf())
        {
            crate::fs::create_dir_all(parent).await?;
        }
    }

    let mut source = crate::fs::File::open(staging_path)
        .await
        .map_err(|e| RqError::Source(format!("{}: {e}", staging_path.display())))?;
    let mut cursor = 0u64;

    for member in members {
        let next_cursor = member.offset.checked_add(member.len).ok_or_else(|| {
            RqError::Coding(format!(
                "{}: packed member destination {} byte range overflows",
                staging_path.display(),
                member.out_path.display()
            ))
        })?;
        if cursor != member.offset {
            source.seek(std::io::SeekFrom::Start(member.offset)).await?;
            cursor = member.offset;
        }

        let mut out = crate::fs::File::create(&member.write_path).await?;
        let mut remaining = member.len;
        while remaining > 0 {
            let want = usize::try_from(remaining.min(buf.len() as u64)).unwrap_or(buf.len());
            let n = source
                .read(&mut buf[..want])
                .await
                .map_err(|e| RqError::Source(format!("{}: {e}", staging_path.display())))?;
            if n == 0 {
                return Err(RqError::Source(format!(
                    "{}: short read while committing packed member {}",
                    staging_path.display(),
                    member.out_path.display()
                )));
            }
            out.write_all(&buf[..n]).await?;
            remaining -= n as u64;
            cursor = cursor.saturating_add(n as u64);
        }
        out.flush().await?;
        cursor = next_cursor;
    }

    Ok(staging_guard)
}

async fn hash_large_object_fragments(
    shards: &[LargeObjectCommitShard],
    buf: &mut [u8],
) -> Result<(u64, crate::atp::object::ObjectId, [u8; 32]), RqError> {
    let mut sha = Sha256::new();
    let mut cid = crate::atp::object::ContentId::streaming();
    let mut total = 0u64;
    for shard in shards {
        let mut file = crate::fs::File::open(&shard.staging_path)
            .await
            .map_err(|e| RqError::Source(format!("{}: {e}", shard.staging_path.display())))?;
        file.seek(std::io::SeekFrom::Start(shard.staging_offset))
            .await
            .map_err(|e| RqError::Source(format!("{}: {e}", shard.staging_path.display())))?;
        let mut remaining = shard.fragment.len;
        while remaining > 0 {
            let want = usize::try_from(remaining.min(buf.len() as u64)).unwrap_or(buf.len());
            let n = file
                .read(&mut buf[..want])
                .await
                .map_err(|e| RqError::Source(format!("{}: {e}", shard.staging_path.display())))?;
            if n == 0 {
                return Err(RqError::Source(format!(
                    "{}: short read while hashing fragment {}",
                    shard.staging_path.display(),
                    shard.fragment.rel_path
                )));
            }
            sha.update(&buf[..n]);
            cid.update(&buf[..n]);
            let n_u64 = n as u64;
            remaining -= n_u64;
            total = total.saturating_add(n_u64);
        }
    }
    Ok((
        total,
        crate::atp::object::ObjectId::content(cid.finalize()),
        sha.finalize().into(),
    ))
}

async fn write_large_object_fragments(
    shards: &[LargeObjectCommitShard],
    out_path: &Path,
    buf: &mut [u8],
) -> Result<(), RqError> {
    let mut out = crate::fs::File::create(out_path).await?;
    for shard in shards {
        let mut file = crate::fs::File::open(&shard.staging_path)
            .await
            .map_err(|e| RqError::Source(format!("{}: {e}", shard.staging_path.display())))?;
        file.seek(std::io::SeekFrom::Start(shard.staging_offset))
            .await
            .map_err(|e| RqError::Source(format!("{}: {e}", shard.staging_path.display())))?;
        let mut remaining = shard.fragment.len;
        while remaining > 0 {
            let want = usize::try_from(remaining.min(buf.len() as u64)).unwrap_or(buf.len());
            let n = file
                .read(&mut buf[..want])
                .await
                .map_err(|e| RqError::Source(format!("{}: {e}", shard.staging_path.display())))?;
            if n == 0 {
                return Err(RqError::Source(format!(
                    "{}: short read while committing fragment {}",
                    shard.staging_path.display(),
                    shard.fragment.rel_path
                )));
            }
            out.write_all(&buf[..n]).await?;
            remaining -= n as u64;
        }
    }
    out.flush().await?;
    Ok(())
}

fn contiguous_fragment_staging_path(shards: &[LargeObjectCommitShard]) -> Option<PathBuf> {
    let first = shards.first()?;
    if !first.staging_shared {
        return None;
    }
    let staging_path = &first.staging_path;
    let all_contiguous_shared = shards.iter().all(|shard| {
        shard.staging_shared
            && shard.staging_path == *staging_path
            && shard.staging_offset == shard.fragment.logical_offset
    });
    all_contiguous_shared.then(|| staging_path.clone())
}

fn assembled_fragment_staging_path(
    shards: &[LargeObjectCommitShard],
    commit_index: usize,
) -> Result<PathBuf, RqError> {
    let first = shards
        .first()
        .ok_or_else(|| RqError::Coding("fragment commit has no shards".to_string()))?;
    let mut file_name = first.staging_path.file_name().map_or_else(
        || std::ffi::OsString::from("rq-fragment"),
        std::ffi::OsString::from,
    );
    file_name.push(format!(".assembled-{commit_index}.staged"));
    Ok(first.staging_path.with_file_name(file_name))
}

async fn remove_failed_fragment_staging_file(path: &Path) -> Result<(), RqError> {
    match crate::fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(RqError::Io(err)),
    }
}

/// Verify every entry (SHA-256 + rebuilt merkle root) and, on success, atomically
/// write them to `dest_dir`.
///
/// E-15: an entry with non-empty `members` is a combined RaptorQ object; its
/// staging file is split into the member byte ranges, each member is verified
/// against its own SHA-256, and on commit the member files (not the packed
/// object) are written into place. The merkle root is rebuilt over the LOGICAL
/// files (members flattened), matching the sender's logical root. Verification is
/// fully separated from commit so a sha/merkle mismatch writes NOTHING.
async fn verify_and_commit(
    manifest: &TransferManifest,
    decoders: &mut [EntryDecoder],
    dest_dir: &Path,
    symbols_accepted: u64,
    feedback_rounds: u32,
    logical_precomputed: &BTreeMap<String, (u64, crate::atp::object::ObjectId, [u8; 32])>,
    completion_digests: &CompletionDigestIndex,
) -> Result<ReceiveReceipt, RqError> {
    let trace_commit = std::env::var_os("ATP_RQ_TRACE").is_some();
    let total_started = trace_commit.then(Instant::now);
    let mut close_flush_micros = 0u64;
    let mut verify_hash_micros = 0u64;
    let mut merkle_micros = 0u64;
    let mut commit_plan_micros = 0u64;
    let mut symlink_guard_micros = 0u64;
    let mut commit_write_micros = 0u64;
    let metadata_by_path = manifest
        .metadata
        .as_ref()
        .map(|metadata| {
            metadata
                .entries
                .iter()
                .map(|entry| (entry.rel_path.as_str(), &entry.metadata))
                .collect::<BTreeMap<_, _>>()
        })
        .unwrap_or_default();

    for d in decoders.iter_mut() {
        let close_started = trace_commit.then(Instant::now);
        close_cached_entry_staging_file(d).await?;
        if d.size == 0 && !d.staging_created {
            let mut file = open_entry_staging_file(d).await?;
            file.flush().await?;
        }
        close_flush_micros = close_flush_micros.saturating_add(elapsed_micros_since(close_started));
    }

    let mut sha_ok = true;
    let mut received: u64 = 0;
    // `logical_digests` holds one digest per LOGICAL file (members flattened) and
    // drives the merkle check, matching the sender's logical root.
    let mut logical_digests: Vec<EntryDigest> = Vec::with_capacity(manifest.entries.len());
    // One commit plan per entry: rename the staging file (unpacked) or split it
    // into member files (packed). Built only during verification; nothing is
    // written until the sha+merkle gate passes.
    enum EntryCommit {
        /// Unpacked entry: rename its staging file to a single destination.
        Rename {
            rel_path: String,
            staging_path: PathBuf,
            metadata: EntryMetadata,
        },
        /// Packed entry: split the staging file into member byte ranges.
        Split {
            staging_path: PathBuf,
            members: Vec<PackedMember>,
        },
        /// Large-file entry split into ordered RaptorQ objects: reassemble the
        /// shard staging files into one logical destination file.
        Fragments {
            rel_path: String,
            shards: Vec<LargeObjectCommitShard>,
            metadata: EntryMetadata,
        },
    }
    let mut commits: Vec<EntryCommit> = Vec::with_capacity(manifest.entries.len());
    let mut fragment_groups: BTreeMap<String, Vec<LargeObjectCommitShard>> = BTreeMap::new();
    let mut logical_files: u64 = 0;
    let mut hash_buf = vec![0u8; RQ_STREAM_HASH_BUFFER_SIZE];
    for e in &manifest.entries {
        let Some(decoder) = decoders.iter().find(|d| d.index == e.index) else {
            sha_ok = false;
            continue;
        };
        // Gate on the CONTENT-ADDRESSED truth (actual file size + SHA-256, checked just below),
        // NOT on the `bytes_written` side counter. `bytes_written` is kept for diagnostics but is
        // not load-bearing for the commit decision: a byte-correct file with a transiently
        // miscounted counter must commit (E-9 false-rejection). An incomplete or incorrect file is
        // still rejected by the size+hash check that follows — that is the authoritative gate.
        if !decoder.complete {
            sha_ok = false;
        }
        // Object-level integrity: the staging file's size + SHA-256 must match the
        // manifest entry. This applies to packed objects too (the concatenation).
        // Fast path: the reliable control-source-stream already folded every
        // in-order chunk into an incremental digest during receive, so reuse it
        // instead of re-reading + re-hashing the whole staging file (the
        // post-stream pass is otherwise the dominant clean-link tail). The lossy
        // RaptorQ-datagram path leaves `inc_digest` None and re-hashes here.
        let (size, content_id, content_sha256) =
            if let Some((sz, cid, sha)) = decoder.inc_digest.as_ref() {
                (*sz, cid.clone(), *sha)
            } else if e.fragment.is_some() {
                let hash_started = trace_commit.then(Instant::now);
                let r = hash_file_range_streaming(
                    &decoder.staging_path,
                    decoder.staging_write_offset,
                    e.size,
                    &mut hash_buf,
                )
                .await
                .map_err(|e| RqError::Source(e.into_message()))?;
                verify_hash_micros =
                    verify_hash_micros.saturating_add(elapsed_micros_since(hash_started));
                r
            } else {
                let hash_started = trace_commit.then(Instant::now);
                let r = hash_file_streaming(&decoder.staging_path, &mut hash_buf)
                    .await
                    .map_err(|e| RqError::Source(e.into_message()))?;
                verify_hash_micros =
                    verify_hash_micros.saturating_add(elapsed_micros_since(hash_started));
                r
            };
        received = received.saturating_add(size);
        let (expected_entry_size, expected_entry_sha256_hex) = completion_digests.expected_entry(e);
        if size != e.size
            || size != expected_entry_size
            || hex_encode(&content_sha256) != expected_entry_sha256_hex
        {
            sha_ok = false;
        }

        if let Some(fragment) = &e.fragment {
            fragment_groups
                .entry(fragment.rel_path.clone())
                .or_default()
                .push(LargeObjectCommitShard {
                    staging_path: decoder.staging_path.clone(),
                    staging_offset: decoder.staging_write_offset,
                    staging_shared: decoder.staging_shared,
                    fragment: fragment.clone(),
                });
        } else if e.members.is_empty() {
            // Normal single-file entry: its content IS the file (byte-identical to
            // the prior wire). Its own digest is the logical digest; rename on commit.
            logical_digests.push(EntryDigest {
                rel_path: e.rel_path.clone(),
                size,
                content_id,
                content_sha256,
            });
            logical_files = logical_files.saturating_add(1);
            commits.push(EntryCommit::Rename {
                rel_path: e.rel_path.clone(),
                staging_path: decoder.staging_path.clone(),
                metadata: metadata_by_path
                    .get(e.rel_path.as_str())
                    .map_or_else(EntryMetadata::default, |metadata| (*metadata).clone()),
            });
        } else {
            // E-15 packed object: split the staging file into member byte ranges,
            // verify each member's own SHA-256, and build a per-member logical
            // digest. The packed object itself is not committed.
            let hash_started = trace_commit.then(Instant::now);
            sha_ok &= hash_packed_members_streaming(
                &decoder.staging_path,
                &e.members,
                &mut logical_digests,
                &mut logical_files,
                &mut hash_buf,
            )
            .await?;
            verify_hash_micros =
                verify_hash_micros.saturating_add(elapsed_micros_since(hash_started));
            commits.push(EntryCommit::Split {
                staging_path: decoder.staging_path.clone(),
                members: e.members.clone(),
            });
        }
    }

    for (rel_path, mut shards) in fragment_groups {
        shards.sort_by_key(|shard| shard.fragment.shard_index);
        // L2 fast path: if the reliable source-stream already folded every
        // fragment (in arrival order) into a logical running hash, reuse it and
        // skip re-reading + re-hashing all fragment staging files. The lossy
        // datagram path leaves `logical_precomputed` empty and re-hashes here.
        let (size, content_id, content_sha256) =
            if let Some((sz, cid, sha)) = logical_precomputed.get(&rel_path) {
                (*sz, cid.clone(), *sha)
            } else {
                let hash_started = trace_commit.then(Instant::now);
                let r = hash_large_object_fragments(&shards, &mut hash_buf).await?;
                verify_hash_micros =
                    verify_hash_micros.saturating_add(elapsed_micros_since(hash_started));
                r
            };
        let Some(first) = shards.first() else {
            sha_ok = false;
            continue;
        };
        let (expected_logical_size, expected_logical_sha256_hex) = completion_digests
            .expected_logical(
                &rel_path,
                first.fragment.logical_size,
                &first.fragment.sha256_hex,
            );
        if size != first.fragment.logical_size
            || size != expected_logical_size
            || hex_encode(&content_sha256) != expected_logical_sha256_hex
        {
            sha_ok = false;
        }
        logical_digests.push(EntryDigest {
            rel_path: rel_path.clone(),
            size,
            content_id,
            content_sha256,
        });
        logical_files = logical_files.saturating_add(1);
        let metadata = metadata_by_path
            .get(rel_path.as_str())
            .map_or_else(EntryMetadata::default, |metadata| (*metadata).clone());
        commits.push(EntryCommit::Fragments {
            rel_path,
            shards,
            metadata,
        });
    }

    let merkle_started = trace_commit.then(Instant::now);
    let merkle_ok = flat_merkle_root_from_digests(&logical_digests)
        == completion_digests.expected_merkle_root(manifest);
    merkle_micros = merkle_micros.saturating_add(elapsed_micros_since(merkle_started));

    let committed = sha_ok && merkle_ok;
    let mut committed_paths: Vec<String> = Vec::new();
    if !committed {
        let mut cleaned_fragment_staging: BTreeSet<PathBuf> = BTreeSet::new();
        for commit in &commits {
            if let EntryCommit::Fragments { shards, .. } = commit
                && let Some(staging_path) = contiguous_fragment_staging_path(shards)
                && cleaned_fragment_staging.insert(staging_path.clone())
            {
                remove_failed_fragment_staging_file(&staging_path).await?;
            }
        }
    }
    if committed {
        // `root_name` is attacker-controlled off the wire; require one
        // portable component so hostile and platform-aliasing values cannot
        // escape or collide under `dest_dir`.
        let base = safe_base_for_root_name(dest_dir, &manifest.root_name)?;
        reject_existing_symlink(dest_dir).await?;
        if manifest.is_directory && manifest.entries.is_empty() {
            reject_destination_symlink_prefix(&base, &base).await?;
            crate::fs::create_dir_all(&base).await?;
            reject_destination_symlink_prefix(&base, &base).await?;
            committed_paths.push(base.display().to_string());
        }

        // Resolve every LOGICAL destination path, rejecting any symlink prefix,
        // before writing anything.
        let plan_started = trace_commit.then(Instant::now);
        enum CommitWrite {
            Rename {
                staging_path: PathBuf,
                out_path: PathBuf,
                metadata: EntryMetadata,
            },
            Members {
                staging_path: PathBuf,
                members: Vec<PackedMemberWrite>,
            },
            Fragments {
                shards: Vec<LargeObjectCommitShard>,
                staging_path: PathBuf,
                requires_assembly: bool,
                out_path: PathBuf,
                metadata: EntryMetadata,
            },
        }
        let mut writes: Vec<CommitWrite> = Vec::with_capacity(logical_digests.len());
        for commit in &commits {
            match commit {
                EntryCommit::Rename {
                    rel_path,
                    staging_path,
                    metadata,
                } => {
                    let out_path = if manifest.is_directory {
                        join_relative(&base, rel_path)?
                    } else {
                        base.clone()
                    };
                    writes.push(CommitWrite::Rename {
                        staging_path: staging_path.clone(),
                        out_path,
                        metadata: metadata.clone(),
                    });
                }
                EntryCommit::Split {
                    staging_path,
                    members,
                } => {
                    // A packed object only ever occurs inside a directory transfer
                    // (the single-file path never packs), so members join under base.
                    let mut member_writes = Vec::with_capacity(members.len());
                    for (member_index, member) in members.iter().enumerate() {
                        let out_path = join_relative(&base, &member.rel_path)?;
                        member_writes.push(PackedMemberWrite {
                            offset: member.offset,
                            len: member.len,
                            write_path: packed_member_staging_path(staging_path, member_index),
                            out_path,
                            metadata: metadata_by_path
                                .get(member.rel_path.as_str())
                                .map_or_else(EntryMetadata::default, |metadata| {
                                    (*metadata).clone()
                                }),
                        });
                    }
                    writes.push(CommitWrite::Members {
                        staging_path: staging_path.clone(),
                        members: member_writes,
                    });
                }
                EntryCommit::Fragments {
                    rel_path,
                    shards,
                    metadata,
                } => {
                    let out_path = if manifest.is_directory {
                        join_relative(&base, rel_path)?
                    } else {
                        base.clone()
                    };
                    let (staging_path, requires_assembly) =
                        if let Some(staging_path) = contiguous_fragment_staging_path(shards) {
                            (staging_path, false)
                        } else {
                            (assembled_fragment_staging_path(shards, writes.len())?, true)
                        };
                    writes.push(CommitWrite::Fragments {
                        shards: shards.clone(),
                        staging_path,
                        requires_assembly,
                        out_path,
                        metadata: metadata.clone(),
                    });
                }
            }
        }
        commit_plan_micros = commit_plan_micros.saturating_add(elapsed_micros_since(plan_started));

        let symlink_started = trace_commit.then(Instant::now);
        // Dedup the planning-time prefix checks across paths. This rejects
        // ordinary conflicts before any write; every mutation below repeats an
        // uncached full-path check to catch prefixes replaced after this pass.
        let mut verified_prefixes: BTreeSet<PathBuf> = BTreeSet::new();
        for write in &writes {
            match write {
                CommitWrite::Rename { out_path, .. } | CommitWrite::Fragments { out_path, .. } => {
                    reject_destination_symlink_prefix_cached(
                        &base,
                        out_path,
                        &mut verified_prefixes,
                    )
                    .await?;
                }
                CommitWrite::Members { members, .. } => {
                    for member in members {
                        reject_destination_symlink_prefix_cached(
                            &base,
                            &member.out_path,
                            &mut verified_prefixes,
                        )
                        .await?;
                    }
                }
            }
        }
        symlink_guard_micros =
            symlink_guard_micros.saturating_add(elapsed_micros_since(symlink_started));

        let write_started = trace_commit.then(Instant::now);
        for write in writes {
            match write {
                CommitWrite::Rename {
                    staging_path,
                    out_path,
                    metadata,
                } => {
                    let deferred_metadata =
                        prepare_rq_entry_metadata_for_commit(&staging_path, &metadata).await?;
                    reject_destination_symlink_prefix(&base, &out_path).await?;
                    if let Some(parent) = out_path.parent() {
                        crate::fs::create_dir_all(parent).await?;
                    }
                    reject_destination_symlink_prefix(&base, &out_path).await?;
                    commit_staged_regular_file_transactionally(&staging_path, &out_path)
                        .await
                        .map_err(|error| RqError::Source(error.into_message()))?;
                    if let Some(deferred_metadata) = deferred_metadata {
                        apply_rq_entry_metadata(&out_path, &deferred_metadata).await?;
                    }
                    committed_paths.push(out_path.display().to_string());
                }
                CommitWrite::Members {
                    staging_path,
                    members,
                } => {
                    // Re-read the verified member byte ranges from the packed
                    // staging file once, in offset order. This preserves the
                    // per-file outputs while avoiding one staging open/seek and
                    // one allocation per small tree file.
                    let _member_staging_guard =
                        write_packed_member_batch(&staging_path, &members, &mut hash_buf).await?;
                    let mut deferred_metadata = Vec::with_capacity(members.len());
                    for member in &members {
                        deferred_metadata.push(
                            prepare_rq_entry_metadata_for_commit(
                                &member.write_path,
                                &member.metadata,
                            )
                            .await?,
                        );
                    }
                    for member in &members {
                        reject_destination_symlink_prefix(&base, &member.out_path).await?;
                        if let Some(parent) = member.out_path.parent() {
                            crate::fs::create_dir_all(parent).await?;
                        }
                        reject_destination_symlink_prefix(&base, &member.out_path).await?;
                        commit_staged_regular_file_transactionally(
                            &member.write_path,
                            &member.out_path,
                        )
                        .await
                        .map_err(|error| RqError::Source(error.into_message()))?;
                    }
                    for (member, deferred_metadata) in members.iter().zip(deferred_metadata) {
                        if let Some(deferred_metadata) = deferred_metadata {
                            apply_rq_entry_metadata(&member.out_path, &deferred_metadata).await?;
                        }
                    }
                    committed_paths.extend(
                        members
                            .into_iter()
                            .map(|member| member.out_path.display().to_string()),
                    );
                }
                CommitWrite::Fragments {
                    shards,
                    staging_path,
                    requires_assembly,
                    out_path,
                    metadata,
                } => {
                    if requires_assembly {
                        write_large_object_fragments(&shards, &staging_path, &mut hash_buf).await?;
                    }
                    let deferred_metadata =
                        prepare_rq_entry_metadata_for_commit(&staging_path, &metadata).await?;
                    reject_destination_symlink_prefix(&base, &out_path).await?;
                    if let Some(parent) = out_path.parent() {
                        crate::fs::create_dir_all(parent).await?;
                    }
                    reject_destination_symlink_prefix(&base, &out_path).await?;
                    commit_staged_regular_file_transactionally(&staging_path, &out_path)
                        .await
                        .map_err(|error| RqError::Source(error.into_message()))?;
                    if let Some(deferred_metadata) = deferred_metadata {
                        apply_rq_entry_metadata(&out_path, &deferred_metadata).await?;
                    }
                    committed_paths.push(out_path.display().to_string());
                }
            }
        }
        if let Some(directories) = manifest
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.directories.as_ref())
            && !directories.is_empty()
        {
            apply_rq_directory_metadata(&base, directories).await?;
        }
        commit_write_micros =
            commit_write_micros.saturating_add(elapsed_micros_since(write_started));
    }

    rqtrace!(
        "receiver: verify_commit committed={} sha_ok={} merkle_ok={} bytes_received={} logical_files={} committed_paths={} feedback_rounds={} close_flush_micros={} verify_hash_micros={} merkle_micros={} commit_plan_micros={} symlink_guard_micros={} commit_write_micros={} total_micros={}",
        committed,
        sha_ok,
        merkle_ok,
        received,
        logical_files,
        committed_paths.len(),
        feedback_rounds,
        close_flush_micros,
        verify_hash_micros,
        merkle_micros,
        commit_plan_micros,
        symlink_guard_micros,
        commit_write_micros,
        elapsed_micros_since(total_started),
    );

    Ok(ReceiveReceipt {
        committed,
        bytes_received: received,
        files: u32::try_from(logical_files).unwrap_or(u32::MAX),
        sha_ok,
        merkle_ok,
        symbols_accepted,
        feedback_rounds,
        reason: if committed {
            None
        } else if !sha_ok {
            Some("per-entry SHA-256 mismatch".to_string())
        } else {
            Some("merkle-root mismatch".to_string())
        },
        committed_paths,
    })
}

fn parse_symbol_datagram_payload(
    buf: &[u8],
    n: usize,
    tag: u64,
    auth_required: bool,
) -> Option<(ParsedDatagram, &[u8])> {
    let parsed = parse_symbol_header(&buf[..n], tag, auth_required)?;
    let start = parsed.header_len;
    let end = start + parsed.payload_len;
    if end > n {
        return None;
    }
    Some((parsed, &buf[start..end]))
}

#[derive(Debug, Default, Clone, Copy)]
struct RqDatagramIngest {
    observed: bool,
    accepted: bool,
    source_observed: bool,
    source_accepted: bool,
    repair_observed: bool,
    repair_accepted: bool,
    payload_bytes: u64,
    // Per-symbol receiver-intake stage timing. `feed_micros` is the legacy
    // aggregate; the sub-stages below make large-lossy traces identify the
    // exact feed bottleneck instead of blaming RaptorQ solve width.
    parse_micros: u64,
    feed_micros: u64,
    source_auth_micros: u64,
    source_persist_micros: u64,
    pipeline_feed_micros: u64,
    block_persist_micros: u64,
    decode_dispatch_micros: u64,
    source_seed_micros: u64,
    feed_other_micros: u64,
    decode_stats: RqDecodeRoundStats,
}

struct PlainSourceBatchSymbol<'a> {
    decoder_index: usize,
    sbn: usize,
    esi: usize,
    offset: u64,
    take: usize,
    payload: &'a [u8],
    parse_micros: u64,
}

struct PlainSourceBatchRun {
    decoder_index: usize,
    sbn: usize,
    first_esi: usize,
    next_esi: usize,
    offset: u64,
    data: Vec<u8>,
    symbols: u64,
    payload_bytes: u64,
    parse_micros: u64,
}

impl PlainSourceBatchRun {
    fn new(symbol: PlainSourceBatchSymbol<'_>) -> Self {
        let mut run = Self {
            decoder_index: symbol.decoder_index,
            sbn: symbol.sbn,
            first_esi: symbol.esi,
            next_esi: symbol.esi,
            offset: symbol.offset,
            data: Vec::with_capacity(symbol.take),
            symbols: 0,
            payload_bytes: 0,
            parse_micros: 0,
        };
        run.absorb(symbol);
        run
    }

    fn can_absorb(&self, symbol: &PlainSourceBatchSymbol<'_>) -> bool {
        if self.decoder_index != symbol.decoder_index
            || self.sbn != symbol.sbn
            || self.next_esi != symbol.esi
        {
            return false;
        }
        self.offset
            .checked_add(u64::try_from(self.data.len()).unwrap_or(u64::MAX))
            == Some(symbol.offset)
    }

    fn absorb(&mut self, symbol: PlainSourceBatchSymbol<'_>) {
        self.next_esi = symbol.esi.saturating_add(1);
        self.symbols = self.symbols.saturating_add(1);
        self.payload_bytes = self
            .payload_bytes
            .saturating_add(u64::try_from(symbol.payload.len()).unwrap_or(u64::MAX));
        self.parse_micros = self.parse_micros.saturating_add(symbol.parse_micros);
        self.data.extend_from_slice(&symbol.payload[..symbol.take]);
    }
}

#[derive(Clone)]
struct AuthSourceBatchSymbol {
    decoder_index: usize,
    object_id: ObjectId,
    sbn: usize,
    sbn_wire: u8,
    esi: usize,
    esi_wire: u32,
    offset: u64,
    take: usize,
    payload: Vec<u8>,
    auth_tag: AuthenticationTag,
    parse_micros: u64,
}

struct VerifiedAuthSourceBatchSymbol {
    symbol: AuthSourceBatchSymbol,
    verified: bool,
}

struct AuthSourceBatchRun {
    decoder_index: usize,
    sbn: usize,
    first_esi: usize,
    next_esi: usize,
    offset: u64,
    data: Vec<u8>,
    auth_tags: Vec<AuthenticationTag>,
    symbols: u64,
}

impl AuthSourceBatchRun {
    fn new(symbol: AuthSourceBatchSymbol) -> Self {
        let mut run = Self {
            decoder_index: symbol.decoder_index,
            sbn: symbol.sbn,
            first_esi: symbol.esi,
            next_esi: symbol.esi,
            offset: symbol.offset,
            data: Vec::with_capacity(symbol.take),
            auth_tags: Vec::with_capacity(1),
            symbols: 0,
        };
        run.absorb(symbol);
        run
    }

    fn can_absorb(&self, symbol: &AuthSourceBatchSymbol) -> bool {
        if self.decoder_index != symbol.decoder_index
            || self.sbn != symbol.sbn
            || self.next_esi != symbol.esi
        {
            return false;
        }
        self.offset
            .checked_add(u64::try_from(self.data.len()).unwrap_or(u64::MAX))
            == Some(symbol.offset)
    }

    fn absorb(&mut self, symbol: AuthSourceBatchSymbol) {
        self.next_esi = symbol.esi.saturating_add(1);
        self.symbols = self.symbols.saturating_add(1);
        self.data.extend_from_slice(&symbol.payload[..symbol.take]);
        self.auth_tags.push(symbol.auth_tag);
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct RqDecodeRoundStats {
    attempts: u64,
    repair_attempts: u64,
    source_complete_attempts: u64,
    completed_blocks: u64,
    stale_requeues: u64,
    decode_micros: u64,
    join_wait_micros: u64,
    apply_micros: u64,
    persist_micros: u64,
    queued_jobs: u64,
    inline_jobs: u64,
    spawn_denials: u64,
    entry_cap_saturations: u64,
    transfer_cap_saturations: u64,
    pending_peak: u64,
}

impl RqDecodeRoundStats {
    fn merge(&mut self, other: Self) {
        self.attempts = self.attempts.saturating_add(other.attempts);
        self.repair_attempts = self.repair_attempts.saturating_add(other.repair_attempts);
        self.source_complete_attempts = self
            .source_complete_attempts
            .saturating_add(other.source_complete_attempts);
        self.completed_blocks = self.completed_blocks.saturating_add(other.completed_blocks);
        self.stale_requeues = self.stale_requeues.saturating_add(other.stale_requeues);
        self.decode_micros = self.decode_micros.saturating_add(other.decode_micros);
        self.join_wait_micros = self.join_wait_micros.saturating_add(other.join_wait_micros);
        self.apply_micros = self.apply_micros.saturating_add(other.apply_micros);
        self.persist_micros = self.persist_micros.saturating_add(other.persist_micros);
        self.queued_jobs = self.queued_jobs.saturating_add(other.queued_jobs);
        self.inline_jobs = self.inline_jobs.saturating_add(other.inline_jobs);
        self.spawn_denials = self.spawn_denials.saturating_add(other.spawn_denials);
        self.entry_cap_saturations = self
            .entry_cap_saturations
            .saturating_add(other.entry_cap_saturations);
        self.transfer_cap_saturations = self
            .transfer_cap_saturations
            .saturating_add(other.transfer_cap_saturations);
        self.pending_peak = self.pending_peak.max(other.pending_peak);
    }

    fn record_attempt(&mut self, kind: BlockDecodeKind, elapsed: Duration) {
        self.attempts = self.attempts.saturating_add(1);
        match kind {
            BlockDecodeKind::SourceComplete => {
                self.source_complete_attempts = self.source_complete_attempts.saturating_add(1);
            }
            BlockDecodeKind::RaptorQRepair => {
                self.repair_attempts = self.repair_attempts.saturating_add(1);
            }
        }
        self.decode_micros = self
            .decode_micros
            .saturating_add(duration_micros_saturating(elapsed));
    }

    fn record_join_wait(&mut self, elapsed: Duration) {
        self.join_wait_micros = self
            .join_wait_micros
            .saturating_add(duration_micros_saturating(elapsed));
    }

    fn record_queued_job(&mut self, pending_jobs: usize) {
        self.queued_jobs = self.queued_jobs.saturating_add(1);
        self.pending_peak = self
            .pending_peak
            .max(u64::try_from(pending_jobs).unwrap_or(u64::MAX));
    }

    fn record_inline_job(&mut self) {
        self.inline_jobs = self.inline_jobs.saturating_add(1);
    }

    fn record_spawn_denial(&mut self) {
        self.spawn_denials = self.spawn_denials.saturating_add(1);
    }

    fn record_entry_cap_saturation(&mut self) {
        self.entry_cap_saturations = self.entry_cap_saturations.saturating_add(1);
    }

    fn record_transfer_cap_saturation(&mut self) {
        self.transfer_cap_saturations = self.transfer_cap_saturations.saturating_add(1);
    }
}

fn trace_receiver_decode_profile(
    phase: &str,
    feedback_round: u32,
    stats: RqDecodeRoundStats,
    decode_width_budget: usize,
) {
    rqtrace!(
        "receiver: decode_profile phase={} feedback_round={} decode_attempts={} decode_repair_attempts={} decode_source_complete_attempts={} decode_completed_blocks={} decode_stale_requeues={} decode_micros={} decode_join_wait_micros={} decode_apply_micros={} decode_persist_micros={} decode_queued_jobs={} decode_inline_jobs={} decode_spawn_denials={} decode_entry_cap_saturations={} decode_transfer_cap_saturations={} decode_pending_peak={} decode_width_budget={}",
        phase,
        feedback_round,
        stats.attempts,
        stats.repair_attempts,
        stats.source_complete_attempts,
        stats.completed_blocks,
        stats.stale_requeues,
        stats.decode_micros,
        stats.join_wait_micros,
        stats.apply_micros,
        stats.persist_micros,
        stats.queued_jobs,
        stats.inline_jobs,
        stats.spawn_denials,
        stats.entry_cap_saturations,
        stats.transfer_cap_saturations,
        stats.pending_peak,
        decode_width_budget,
    );
}

#[derive(Debug, Default, Clone, Copy)]
struct RqDatagramRoundStats {
    observed: u64,
    accepted: u64,
    source_observed: u64,
    source_accepted: u64,
    repair_observed: u64,
    repair_accepted: u64,
    payload_bytes: u64,
    // LEVER-R1 receiver-intake throughput instrumentation (sums over the round).
    parse_micros: u64,
    feed_micros: u64,
    source_auth_micros: u64,
    source_persist_micros: u64,
    pipeline_feed_micros: u64,
    block_persist_micros: u64,
    decode_dispatch_micros: u64,
    source_seed_micros: u64,
    feed_other_micros: u64,
    recv_micros: u64,
    drain_micros: u64,
    decode_stats: RqDecodeRoundStats,
}

impl RqDatagramRoundStats {
    fn record(&mut self, ingest: RqDatagramIngest) {
        if ingest.observed {
            self.observed = self.observed.saturating_add(1);
            self.payload_bytes = self.payload_bytes.saturating_add(ingest.payload_bytes);
        }
        if ingest.accepted {
            self.accepted = self.accepted.saturating_add(1);
        }
        if ingest.source_observed {
            self.source_observed = self.source_observed.saturating_add(1);
        }
        if ingest.source_accepted {
            self.source_accepted = self.source_accepted.saturating_add(1);
        }
        if ingest.repair_observed {
            self.repair_observed = self.repair_observed.saturating_add(1);
        }
        if ingest.repair_accepted {
            self.repair_accepted = self.repair_accepted.saturating_add(1);
        }
        self.parse_micros = self.parse_micros.saturating_add(ingest.parse_micros);
        self.feed_micros = self.feed_micros.saturating_add(ingest.feed_micros);
        self.source_auth_micros = self
            .source_auth_micros
            .saturating_add(ingest.source_auth_micros);
        self.source_persist_micros = self
            .source_persist_micros
            .saturating_add(ingest.source_persist_micros);
        self.pipeline_feed_micros = self
            .pipeline_feed_micros
            .saturating_add(ingest.pipeline_feed_micros);
        self.block_persist_micros = self
            .block_persist_micros
            .saturating_add(ingest.block_persist_micros);
        self.decode_dispatch_micros = self
            .decode_dispatch_micros
            .saturating_add(ingest.decode_dispatch_micros);
        self.source_seed_micros = self
            .source_seed_micros
            .saturating_add(ingest.source_seed_micros);
        self.feed_other_micros = self
            .feed_other_micros
            .saturating_add(ingest.feed_other_micros);
        self.decode_stats.merge(ingest.decode_stats);
    }

    fn merge(&mut self, other: Self) {
        self.observed = self.observed.saturating_add(other.observed);
        self.accepted = self.accepted.saturating_add(other.accepted);
        self.source_observed = self.source_observed.saturating_add(other.source_observed);
        self.source_accepted = self.source_accepted.saturating_add(other.source_accepted);
        self.repair_observed = self.repair_observed.saturating_add(other.repair_observed);
        self.repair_accepted = self.repair_accepted.saturating_add(other.repair_accepted);
        self.payload_bytes = self.payload_bytes.saturating_add(other.payload_bytes);
        self.parse_micros = self.parse_micros.saturating_add(other.parse_micros);
        self.feed_micros = self.feed_micros.saturating_add(other.feed_micros);
        self.source_auth_micros = self
            .source_auth_micros
            .saturating_add(other.source_auth_micros);
        self.source_persist_micros = self
            .source_persist_micros
            .saturating_add(other.source_persist_micros);
        self.pipeline_feed_micros = self
            .pipeline_feed_micros
            .saturating_add(other.pipeline_feed_micros);
        self.block_persist_micros = self
            .block_persist_micros
            .saturating_add(other.block_persist_micros);
        self.decode_dispatch_micros = self
            .decode_dispatch_micros
            .saturating_add(other.decode_dispatch_micros);
        self.source_seed_micros = self
            .source_seed_micros
            .saturating_add(other.source_seed_micros);
        self.feed_other_micros = self
            .feed_other_micros
            .saturating_add(other.feed_other_micros);
        self.recv_micros = self.recv_micros.saturating_add(other.recv_micros);
        self.drain_micros = self.drain_micros.saturating_add(other.drain_micros);
        self.decode_stats.merge(other.decode_stats);
    }

    fn record_decode_stats(&mut self, decode_stats: RqDecodeRoundStats) {
        self.decode_stats.merge(decode_stats);
    }

    fn record_recv_elapsed(&mut self, elapsed: Duration) {
        self.recv_micros = self
            .recv_micros
            .saturating_add(duration_micros_saturating(elapsed));
    }

    fn record_tail_drain_elapsed(&mut self, elapsed: Duration) {
        self.drain_micros = self
            .drain_micros
            .saturating_add(duration_micros_saturating(elapsed));
    }

    fn intake_micros(self) -> u64 {
        self.parse_micros.saturating_add(self.feed_micros)
    }

    fn intake_symbols_per_s(self) -> u64 {
        rate_per_second(self.observed, self.intake_micros())
    }

    fn intake_bytes_per_s(self) -> u64 {
        rate_per_second(self.payload_bytes, self.intake_micros())
    }
}

fn duration_micros_saturating(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

fn elapsed_micros_since(started: Option<Instant>) -> u64 {
    started.map_or(0, |instant| duration_micros_saturating(instant.elapsed()))
}

fn rate_per_second(units: u64, elapsed_micros: u64) -> u64 {
    if elapsed_micros == 0 {
        return 0;
    }
    let rate = u128::from(units).saturating_mul(1_000_000) / u128::from(elapsed_micros);
    u64::try_from(rate).unwrap_or(u64::MAX)
}

fn rq_auth_verify_width_for_cx(cx: &Cx, symbols: usize) -> usize {
    if symbols < RQ_AUTH_VERIFY_PARALLEL_MIN_SYMBOLS {
        return 1;
    }
    if cx.blocking_pool_handle().is_none() {
        return 1;
    }
    let chunks_by_size = symbols.div_ceil(RQ_AUTH_VERIFY_TARGET_CHUNK_SYMBOLS).max(1);
    rq_decode_core_limit_for_cx(cx).min(chunks_by_size).max(1)
}

async fn feed_datagram_to_decoders(
    cx: &Cx,
    buf: &[u8],
    n: usize,
    tag: u64,
    auth_required: bool,
    symbol_auth: Option<&SecurityContext>,
    decoders: &mut [EntryDecoder],
    symbol_size: u16,
    trace_intake: bool,
) -> Result<RqDatagramIngest, RqError> {
    let parse_start = trace_intake.then(Instant::now);
    let parsed_opt = parse_symbol_datagram_payload(buf, n, tag, auth_required);
    let parse_micros = elapsed_micros_since(parse_start);
    let Some((parsed, payload)) = parsed_opt else {
        return Ok(RqDatagramIngest::default());
    };
    let Some(pos) = decoder_position_for_entry(decoders, parsed.entry) else {
        return Ok(RqDatagramIngest::default());
    };
    let mut decode_stats = RqDecodeRoundStats::default();
    let source_streaming_source = decoders[pos].source_streaming && parsed.kind.is_source();
    let (allow_spawn_decode, decode_width_budget) = if source_streaming_source {
        (false, 0)
    } else {
        let decode_width_budget = rq_decode_width_budget_for_cx(cx, decoders, symbol_size);
        let mut pending_decode_jobs = rq_pending_decode_jobs(decoders);
        if pending_decode_jobs >= decode_width_budget {
            decode_stats
                .merge(drain_ready_decodes(cx, decoders, false, decode_width_budget).await?);
            pending_decode_jobs = rq_pending_decode_jobs(decoders);
        }
        (
            pending_decode_jobs < decode_width_budget,
            decode_width_budget,
        )
    };
    let feed_start = trace_intake.then(Instant::now);
    let feed = feed_symbol_with_cx(
        cx,
        &mut decoders[pos],
        &parsed,
        payload,
        symbol_size,
        symbol_auth,
        allow_spawn_decode,
        decode_width_budget,
        trace_intake,
    )
    .await?;
    decode_stats.merge(feed.decode_stats);
    let feed_micros = elapsed_micros_since(feed_start);
    let feed_accounted_micros = feed
        .source_auth_micros
        .saturating_add(feed.source_persist_micros)
        .saturating_add(feed.pipeline_feed_micros)
        .saturating_add(feed.block_persist_micros)
        .saturating_add(feed.decode_dispatch_micros)
        .saturating_add(feed.source_seed_micros);
    let source_symbol = parsed.kind.is_source();
    let repair_symbol = parsed.kind.is_repair();
    Ok(RqDatagramIngest {
        observed: true,
        accepted: feed.accepted,
        source_observed: source_symbol,
        source_accepted: source_symbol && feed.accepted,
        repair_observed: repair_symbol,
        repair_accepted: repair_symbol && feed.accepted,
        payload_bytes: u64::try_from(payload.len()).unwrap_or(u64::MAX),
        parse_micros,
        feed_micros,
        source_auth_micros: feed.source_auth_micros,
        source_persist_micros: feed.source_persist_micros,
        pipeline_feed_micros: feed.pipeline_feed_micros,
        block_persist_micros: feed.block_persist_micros,
        decode_dispatch_micros: feed.decode_dispatch_micros,
        source_seed_micros: feed.source_seed_micros,
        feed_other_micros: feed_micros.saturating_sub(feed_accounted_micros),
        decode_stats,
    })
}

fn plain_source_batch_symbols<'a>(
    batch: &'a crate::net::UdpRecvBatch,
    tag: u64,
    decoders: &[EntryDecoder],
    symbol_size: u16,
    trace_intake: bool,
) -> Option<Vec<PlainSourceBatchSymbol<'a>>> {
    if batch.packets.is_empty() {
        return Some(Vec::new());
    }

    let mut symbols = Vec::with_capacity(batch.packets.len());
    let symbol_size = usize::from(symbol_size);
    if symbol_size == 0 {
        return None;
    }
    let mut seen = BTreeSet::new();
    for packet in &batch.packets {
        let parse_start = trace_intake.then(Instant::now);
        let (parsed, payload) =
            parse_symbol_datagram_payload(&packet.payload, packet.payload.len(), tag, false)?;
        let parse_micros = elapsed_micros_since(parse_start);
        if !parsed.kind.is_source() || payload.len() != symbol_size {
            return None;
        }
        let decoder_index = decoder_position_for_entry(decoders, parsed.entry)?;
        let decoder = &decoders[decoder_index];
        if decoder.complete || !decoder.source_streaming {
            return None;
        }
        let sbn = usize::from(parsed.sbn);
        let esi = usize::try_from(parsed.esi).ok()?;
        if !seen.insert((decoder_index, sbn, esi)) {
            return None;
        }
        let within_block = esi.checked_mul(symbol_size)?;
        let block = decoder.source_blocks.get(sbn)?;
        if block.complete || esi >= block.k || block.received[esi] || within_block >= block.len {
            return None;
        }
        let take = symbol_size.min(block.len - within_block);
        let offset = block.start.checked_add(u64::try_from(within_block).ok()?)?;
        symbols.push(PlainSourceBatchSymbol {
            decoder_index,
            sbn,
            esi,
            offset,
            take,
            payload,
            parse_micros,
        });
    }

    Some(symbols)
}

async fn persist_plain_source_batch_run(
    dec: &mut EntryDecoder,
    run: &PlainSourceBatchRun,
) -> Result<u64, RqError> {
    if run.symbols == 0 {
        return Ok(0);
    }
    let Some(block) = dec.source_blocks.get(run.sbn) else {
        return Ok(0);
    };
    if block.complete || run.next_esi > block.k {
        return Ok(0);
    }
    for esi in run.first_esi..run.next_esi {
        if block.received[esi] {
            return Ok(0);
        }
    }

    write_source_staging_range(dec, run.offset, &run.data).await?;

    let completed_now = {
        let block = &mut dec.source_blocks[run.sbn];
        for esi in run.first_esi..run.next_esi {
            if block.received[esi] {
                continue;
            }
            block.received[esi] = true;
            block.auth_tags[esi] = None;
            block.received_count = block.received_count.saturating_add(1);
        }
        if block.received_count == block.k {
            block.complete = true;
            dec.bytes_written = dec
                .bytes_written
                .checked_add(u64::try_from(block.len).unwrap_or(u64::MAX))
                .ok_or_else(|| {
                    RqError::Coding(format!("entry {} byte counter overflow", dec.index))
                })?;
            true
        } else {
            false
        }
    };

    if completed_now {
        rqtrace!(
            "receiver: entry {} completed source-streamed block {} from plain-source batch",
            dec.index,
            run.sbn
        );
    }
    if source_streaming_entry_complete(dec) {
        dec.complete = true;
        dec.pipeline = None;
        close_cached_entry_staging_file(dec).await?;
    }
    Ok(run.symbols)
}

async fn flush_plain_source_batch_run(
    stats: &mut RqDatagramRoundStats,
    decoders: &mut [EntryDecoder],
    run: Option<PlainSourceBatchRun>,
    trace_intake: bool,
) -> Result<(), RqError> {
    let Some(run) = run else {
        return Ok(());
    };
    let persist_start = trace_intake.then(Instant::now);
    let accepted = persist_plain_source_batch_run(&mut decoders[run.decoder_index], &run).await?;
    let persist_micros = elapsed_micros_since(persist_start);
    stats.observed = stats.observed.saturating_add(run.symbols);
    stats.accepted = stats.accepted.saturating_add(accepted);
    stats.source_observed = stats.source_observed.saturating_add(run.symbols);
    stats.source_accepted = stats.source_accepted.saturating_add(accepted);
    stats.payload_bytes = stats.payload_bytes.saturating_add(run.payload_bytes);
    stats.parse_micros = stats.parse_micros.saturating_add(run.parse_micros);
    stats.feed_micros = stats.feed_micros.saturating_add(persist_micros);
    stats.source_persist_micros = stats.source_persist_micros.saturating_add(persist_micros);
    Ok(())
}

async fn try_feed_plain_source_datagram_batch(
    batch: &crate::net::UdpRecvBatch,
    tag: u64,
    decoders: &mut [EntryDecoder],
    symbol_size: u16,
    trace_intake: bool,
) -> Option<Result<RqDatagramRoundStats, RqError>> {
    let symbols = plain_source_batch_symbols(batch, tag, decoders, symbol_size, trace_intake)?;
    let mut stats = RqDatagramRoundStats::default();
    let mut run = None;
    for symbol in symbols {
        let starts_new_run = run
            .as_ref()
            .is_some_and(|active: &PlainSourceBatchRun| !active.can_absorb(&symbol));
        if starts_new_run
            && let Err(err) =
                flush_plain_source_batch_run(&mut stats, decoders, run.take(), trace_intake).await
        {
            return Some(Err(err));
        }
        if let Some(active) = run.as_mut() {
            active.absorb(symbol);
        } else {
            run = Some(PlainSourceBatchRun::new(symbol));
        }
    }
    if let Err(err) = flush_plain_source_batch_run(&mut stats, decoders, run, trace_intake).await {
        return Some(Err(err));
    }

    Some(Ok(stats))
}

fn authenticated_source_batch_symbols(
    batch: &crate::net::UdpRecvBatch,
    tag: u64,
    decoders: &[EntryDecoder],
    symbol_size: u16,
    trace_intake: bool,
) -> Option<Vec<AuthSourceBatchSymbol>> {
    let mut symbols = Vec::with_capacity(batch.packets.len());
    let symbol_size = usize::from(symbol_size);
    if symbol_size == 0 {
        return None;
    }
    let mut seen = BTreeSet::new();
    for packet in &batch.packets {
        let parse_start = trace_intake.then(Instant::now);
        let (parsed, payload) =
            parse_symbol_datagram_payload(&packet.payload, packet.payload.len(), tag, true)?;
        let parse_micros = elapsed_micros_since(parse_start);
        if !parsed.kind.is_source() || payload.len() != symbol_size {
            return None;
        }
        let auth_tag = parsed.auth_tag?;
        let decoder_index = decoder_position_for_entry(decoders, parsed.entry)?;
        let decoder = &decoders[decoder_index];
        if decoder.complete || !decoder.source_streaming {
            return None;
        }
        let sbn = usize::from(parsed.sbn);
        let esi = usize::try_from(parsed.esi).ok()?;
        if !seen.insert((decoder_index, sbn, esi)) {
            return None;
        }
        let within_block = esi.checked_mul(symbol_size)?;
        let block = decoder.source_blocks.get(sbn)?;
        if block.complete || esi >= block.k || block.received[esi] || within_block >= block.len {
            return None;
        }
        let take = symbol_size.min(block.len - within_block);
        let offset = block.start.checked_add(u64::try_from(within_block).ok()?)?;
        symbols.push(AuthSourceBatchSymbol {
            decoder_index,
            object_id: decoder.object_id,
            sbn,
            sbn_wire: parsed.sbn,
            esi,
            esi_wire: parsed.esi,
            offset,
            take,
            payload: payload.to_vec(),
            auth_tag,
            parse_micros,
        });
    }
    Some(symbols)
}

fn verify_auth_source_batch_chunk(
    context: SecurityContext,
    symbols: Vec<AuthSourceBatchSymbol>,
) -> Vec<VerifiedAuthSourceBatchSymbol> {
    symbols
        .into_iter()
        .map(|mut symbol| {
            let auth_symbol = Symbol::new(
                SymbolId::new(symbol.object_id, symbol.sbn_wire, symbol.esi_wire),
                symbol.payload.clone(),
                SymbolKind::Source,
            );
            let mut auth = AuthenticatedSymbol::from_parts(auth_symbol, symbol.auth_tag);
            let verified =
                context.verify_authenticated_symbol(&mut auth).is_ok() && auth.is_verified();
            if verified {
                symbol.payload = auth.into_symbol().into_data();
            }
            VerifiedAuthSourceBatchSymbol { symbol, verified }
        })
        .collect()
}

async fn verify_auth_source_batch_symbols(
    cx: &Cx,
    context: &SecurityContext,
    symbols: Vec<AuthSourceBatchSymbol>,
    trace_intake: bool,
) -> Result<(Vec<VerifiedAuthSourceBatchSymbol>, u64), RqError> {
    let auth_start = trace_intake.then(Instant::now);
    let width = rq_auth_verify_width_for_cx(cx, symbols.len());
    if width <= 1 {
        return Ok((
            verify_auth_source_batch_chunk(context.clone(), symbols),
            elapsed_micros_since(auth_start),
        ));
    }
    let chunk_len = symbols
        .len()
        .div_ceil(width)
        .max(RQ_AUTH_VERIFY_TARGET_CHUNK_SYMBOLS);
    let mut pending = Vec::new();
    for chunk in symbols.chunks(chunk_len) {
        let chunk = chunk.to_vec();
        let inline_chunk = chunk.clone();
        let spawn_context = context.clone();
        let inline_context = context.clone();
        match cx.spawn_blocking(move |_child| verify_auth_source_batch_chunk(spawn_context, chunk))
        {
            Ok(handle) => pending.push(Ok(handle)),
            Err(_) => pending.push(Err(verify_auth_source_batch_chunk(
                inline_context,
                inline_chunk,
            ))),
        }
    }
    let mut verified = Vec::new();
    for pending_chunk in pending {
        match pending_chunk {
            Ok(mut handle) => verified.extend(handle.join(cx).await.map_err(|join_err| {
                RqError::Authentication(format!(
                    "RQ source auth verification worker failed: {join_err:?}"
                ))
            })?),
            Err(mut inline) => verified.append(&mut inline),
        }
    }
    Ok((verified, elapsed_micros_since(auth_start)))
}

async fn persist_auth_source_batch_run(
    dec: &mut EntryDecoder,
    run: &AuthSourceBatchRun,
) -> Result<u64, RqError> {
    if run.symbols == 0 {
        return Ok(0);
    }
    let Some(block) = dec.source_blocks.get(run.sbn) else {
        return Ok(0);
    };
    if block.complete || run.next_esi > block.k {
        return Ok(0);
    }
    let expected_tags = run.next_esi.saturating_sub(run.first_esi);
    if run.auth_tags.len() != expected_tags {
        return Err(RqError::Coding(format!(
            "entry {} authenticated source batch tag count mismatch: have {} expected {}",
            dec.index,
            run.auth_tags.len(),
            expected_tags
        )));
    }
    for esi in run.first_esi..run.next_esi {
        if block.received[esi] {
            return Ok(0);
        }
    }
    write_source_staging_range(dec, run.offset, &run.data).await?;
    let completed_now = {
        let block = &mut dec.source_blocks[run.sbn];
        for (tag_index, esi) in (run.first_esi..run.next_esi).enumerate() {
            if block.received[esi] {
                continue;
            }
            block.received[esi] = true;
            block.auth_tags[esi] = Some(run.auth_tags[tag_index]);
            block.received_count = block.received_count.saturating_add(1);
        }
        if block.received_count == block.k {
            block.complete = true;
            dec.bytes_written = dec
                .bytes_written
                .checked_add(u64::try_from(block.len).unwrap_or(u64::MAX))
                .ok_or_else(|| {
                    RqError::Coding(format!("entry {} byte counter overflow", dec.index))
                })?;
            true
        } else {
            false
        }
    };
    if completed_now {
        rqtrace!(
            "receiver: entry {} completed source-streamed block {} from auth-source batch",
            dec.index,
            run.sbn
        );
    }
    if source_streaming_entry_complete(dec) {
        dec.complete = true;
        dec.pipeline = None;
        close_cached_entry_staging_file(dec).await?;
    }
    Ok(run.symbols)
}

async fn flush_auth_source_batch_run(
    stats: &mut RqDatagramRoundStats,
    decoders: &mut [EntryDecoder],
    run: Option<AuthSourceBatchRun>,
    trace_intake: bool,
) -> Result<(), RqError> {
    let Some(run) = run else {
        return Ok(());
    };
    let persist_start = trace_intake.then(Instant::now);
    let accepted = persist_auth_source_batch_run(&mut decoders[run.decoder_index], &run).await?;
    let persist_micros = elapsed_micros_since(persist_start);
    stats.accepted = stats.accepted.saturating_add(accepted);
    stats.source_accepted = stats.source_accepted.saturating_add(accepted);
    stats.feed_micros = stats.feed_micros.saturating_add(persist_micros);
    stats.source_persist_micros = stats.source_persist_micros.saturating_add(persist_micros);
    Ok(())
}

async fn try_feed_authenticated_source_datagram_batch(
    cx: &Cx,
    batch: &crate::net::UdpRecvBatch,
    tag: u64,
    context: &SecurityContext,
    decoders: &mut [EntryDecoder],
    symbol_size: u16,
    trace_intake: bool,
) -> Option<Result<RqDatagramRoundStats, RqError>> {
    if context.mode() == AuthMode::Disabled {
        return None;
    }
    let symbols =
        authenticated_source_batch_symbols(batch, tag, decoders, symbol_size, trace_intake)?;
    let mut stats = RqDatagramRoundStats::default();
    for symbol in &symbols {
        stats.observed = stats.observed.saturating_add(1);
        stats.source_observed = stats.source_observed.saturating_add(1);
        stats.payload_bytes = stats
            .payload_bytes
            .saturating_add(u64::try_from(symbol.payload.len()).unwrap_or(u64::MAX));
        stats.parse_micros = stats.parse_micros.saturating_add(symbol.parse_micros);
    }
    let (verified, auth_micros) =
        match verify_auth_source_batch_symbols(cx, context, symbols, trace_intake).await {
            Ok(verified) => verified,
            Err(err) => return Some(Err(err)),
        };
    stats.source_auth_micros = stats.source_auth_micros.saturating_add(auth_micros);
    stats.feed_micros = stats.feed_micros.saturating_add(auth_micros);
    let mut run = None;
    for verified_symbol in verified {
        let symbol = verified_symbol.symbol;
        if !verified_symbol.verified {
            rqtrace!(
                "receiver: entry {} rejected source-streamed batch sbn={} esi={} auth tag",
                decoders[symbol.decoder_index].index,
                symbol.sbn,
                symbol.esi
            );
            continue;
        }
        let starts_new_run = run
            .as_ref()
            .is_some_and(|active: &AuthSourceBatchRun| !active.can_absorb(&symbol));
        if starts_new_run
            && let Err(err) =
                flush_auth_source_batch_run(&mut stats, decoders, run.take(), trace_intake).await
        {
            return Some(Err(err));
        }
        if let Some(active) = run.as_mut() {
            active.absorb(symbol);
        } else {
            run = Some(AuthSourceBatchRun::new(symbol));
        }
    }
    if let Err(err) = flush_auth_source_batch_run(&mut stats, decoders, run, trace_intake).await {
        return Some(Err(err));
    }
    Some(Ok(stats))
}

async fn feed_datagram_batch_to_decoders(
    cx: &Cx,
    batch: &crate::net::UdpRecvBatch,
    tag: u64,
    auth_required: bool,
    symbol_auth: Option<&SecurityContext>,
    decoders: &mut [EntryDecoder],
    symbol_size: u16,
    trace_intake: bool,
) -> Result<RqDatagramRoundStats, RqError> {
    if !auth_required
        && symbol_auth.is_none()
        && rq_pending_decode_jobs(decoders) == 0
        && let Some(result) =
            try_feed_plain_source_datagram_batch(batch, tag, decoders, symbol_size, trace_intake)
                .await
    {
        let mut stats = result?;
        stats.record_decode_stats(drain_ready_decodes_if_pending(cx, decoders, symbol_size).await?);
        return Ok(stats);
    }
    if auth_required
        && rq_pending_decode_jobs(decoders) == 0
        && let Some(context) = symbol_auth
        && let Some(result) = try_feed_authenticated_source_datagram_batch(
            cx,
            batch,
            tag,
            context,
            decoders,
            symbol_size,
            trace_intake,
        )
        .await
    {
        let mut stats = result?;
        stats.record_decode_stats(drain_ready_decodes_if_pending(cx, decoders, symbol_size).await?);
        return Ok(stats);
    }
    let mut stats = RqDatagramRoundStats::default();
    for packet in &batch.packets {
        stats.record(
            feed_datagram_to_decoders(
                cx,
                &packet.payload,
                packet.payload.len(),
                tag,
                auth_required,
                symbol_auth,
                decoders,
                symbol_size,
                trace_intake,
            )
            .await?,
        );
    }
    stats.record_decode_stats(drain_ready_decodes_if_pending(cx, decoders, symbol_size).await?);
    Ok(stats)
}

async fn drain_ready_decodes_if_pending(
    cx: &Cx,
    decoders: &mut [EntryDecoder],
    symbol_size: u16,
) -> Result<RqDecodeRoundStats, RqError> {
    if rq_pending_decode_jobs(decoders) == 0 {
        return Ok(RqDecodeRoundStats::default());
    }
    let decode_width_budget = rq_decode_width_budget_for_cx(cx, decoders, symbol_size);
    drain_ready_decodes(cx, decoders, true, decode_width_budget).await
}

#[derive(Debug, Default, Clone, Copy)]
struct DecodeApplyOutcome {
    completed: bool,
    persist_micros: u64,
}

async fn apply_decode_result(
    dec: &mut EntryDecoder,
    result: SymbolAcceptResult,
    decode_elapsed: Duration,
) -> Result<DecodeApplyOutcome, RqError> {
    let decode_micros = duration_micros_saturating(decode_elapsed);
    match result {
        SymbolAcceptResult::BlockComplete { block_sbn, data } => {
            let persist_start = Instant::now();
            persist_decoded_block(dec, block_sbn, &data).await?;
            let persist_micros = duration_micros_saturating(persist_start.elapsed());
            if dec.complete
                || dec
                    .pipeline
                    .as_ref()
                    .is_some_and(DecodingPipeline::is_complete)
            {
                dec.complete = true;
                dec.pipeline = None;
            }
            rqtrace!(
                "receiver: entry {} completed parallel decode block {} decode_micros={}",
                dec.index,
                block_sbn,
                decode_micros
            );
            Ok(DecodeApplyOutcome {
                completed: true,
                persist_micros,
            })
        }
        SymbolAcceptResult::Rejected(reason) => {
            rqtrace!(
                "receiver: entry {} parallel decode rejected reason={reason:?} decode_micros={}",
                dec.index,
                decode_micros
            );
            Ok(DecodeApplyOutcome::default())
        }
        SymbolAcceptResult::Accepted { .. }
        | SymbolAcceptResult::DecodingStarted { .. }
        | SymbolAcceptResult::Duplicate => Ok(DecodeApplyOutcome::default()),
    }
}

async fn finalize_decode_outcome(
    cx: &Cx,
    dec: &mut EntryDecoder,
    outcome: BlockDecodeOutcome,
    allow_spawn_decode: bool,
    transfer_decode_width: usize,
) -> Result<RqDecodeRoundStats, RqError> {
    let mut stats = RqDecodeRoundStats::default();
    let decode_elapsed = outcome.elapsed();
    let outcome_sbn = outcome.sbn();
    stats.record_attempt(outcome.kind(), decode_elapsed);
    let Some(pipeline) = dec.pipeline.as_mut() else {
        return Ok(stats);
    };
    let apply_start = Instant::now();
    match pipeline.finish_decode_job_deferred(outcome) {
        DeferredSymbolAcceptResult::Immediate(result) => {
            let audit_inconsistent = matches!(
                &result,
                SymbolAcceptResult::Rejected(RejectReason::InconsistentEquations)
            );
            let applied = apply_decode_result(dec, result, decode_elapsed).await?;
            if audit_inconsistent {
                audit_staging_block_dump(dec, outcome_sbn).await;
            }
            stats.apply_micros = stats
                .apply_micros
                .saturating_add(duration_micros_saturating(apply_start.elapsed()));
            stats.persist_micros = stats.persist_micros.saturating_add(applied.persist_micros);
            if applied.completed {
                stats.completed_blocks = stats.completed_blocks.saturating_add(1);
            }
        }
        DeferredSymbolAcceptResult::Decode(job) => {
            let block_sbn = job.sbn();
            let decode_micros = duration_micros_saturating(decode_elapsed);
            stats.apply_micros = stats
                .apply_micros
                .saturating_add(duration_micros_saturating(apply_start.elapsed()));
            rqtrace!(
                "receiver: entry {} requeued stale parallel decode block {} decode_micros={}",
                dec.index,
                block_sbn,
                decode_micros
            );
            stats.stale_requeues = stats.stale_requeues.saturating_add(1);
            stats.merge(
                queue_stale_decode_retry(cx, dec, job, allow_spawn_decode, transfer_decode_width)
                    .await?,
            );
        }
    }
    Ok(stats)
}

async fn queue_stale_decode_retry(
    cx: &Cx,
    dec: &mut EntryDecoder,
    job: BlockDecodeJob,
    allow_spawn_decode: bool,
    transfer_decode_width: usize,
) -> Result<RqDecodeRoundStats, RqError> {
    let mut stats = RqDecodeRoundStats::default();
    let block_sbn = job.sbn();
    if dec.complete || dec.pipeline.is_none() {
        return Ok(stats);
    }
    if block_decode_pending(dec, block_sbn) {
        if let Some(pipeline) = dec.pipeline.as_mut() {
            pipeline.restore_decode_job(job);
        }
        return Ok(stats);
    }

    let entry_decode_width = entry_decode_width_budget(dec, transfer_decode_width);
    if entry_decode_width <= 1 {
        let outcome = run_block_decode_job(job);
        let decode_elapsed = outcome.elapsed();
        stats.record_attempt(outcome.kind(), decode_elapsed);
        let Some(pipeline) = dec.pipeline.as_mut() else {
            return Ok(stats);
        };
        let apply_start = Instant::now();
        let result = pipeline.finish_decode_job(outcome);
        let applied = apply_decode_result(dec, result, decode_elapsed).await?;
        stats.apply_micros = stats
            .apply_micros
            .saturating_add(duration_micros_saturating(apply_start.elapsed()));
        stats.persist_micros = stats.persist_micros.saturating_add(applied.persist_micros);
        stats.record_inline_job();
        if applied.completed {
            stats.completed_blocks = stats.completed_blocks.saturating_add(1);
        }
        rqtrace!(
            "receiver: entry {} ran stale decode retry block {} inline because entry size/block-count is below the parallel decode gate",
            dec.index,
            block_sbn
        );
        return Ok(stats);
    }
    if !allow_spawn_decode
        || !can_spawn_parallel_decode(dec.pending_decodes.len(), entry_decode_width)
    {
        if !allow_spawn_decode {
            stats.record_transfer_cap_saturation();
        } else {
            stats.record_entry_cap_saturation();
        }
        if let Some(pipeline) = dec.pipeline.as_mut() {
            pipeline.restore_decode_job(job);
        }
        rqtrace!(
            "receiver: entry {} deferred stale decode retry for block {} because decode width is saturated (entry_cap={entry_decode_width})",
            dec.index,
            block_sbn
        );
        return Ok(stats);
    }

    let inline_job = job.clone();
    match cx.spawn_blocking(move |_child| run_block_decode_job(job)) {
        Ok(handle) => {
            dec.pending_decodes
                .push(PendingDecode { block_sbn, handle });
            stats.record_queued_job(dec.pending_decodes.len());
            Ok(stats)
        }
        Err(crate::runtime::state::SpawnError::RuntimeUnavailable) => {
            stats.record_spawn_denial();
            let outcome = run_block_decode_job(inline_job);
            let decode_elapsed = outcome.elapsed();
            stats.record_attempt(outcome.kind(), decode_elapsed);
            let Some(pipeline) = dec.pipeline.as_mut() else {
                return Ok(stats);
            };
            let apply_start = Instant::now();
            let result = pipeline.finish_decode_job(outcome);
            let applied = apply_decode_result(dec, result, decode_elapsed).await?;
            stats.apply_micros = stats
                .apply_micros
                .saturating_add(duration_micros_saturating(apply_start.elapsed()));
            stats.persist_micros = stats.persist_micros.saturating_add(applied.persist_micros);
            stats.record_inline_job();
            if applied.completed {
                stats.completed_blocks = stats.completed_blocks.saturating_add(1);
            }
            Ok(stats)
        }
        Err(err) => {
            stats.record_spawn_denial();
            if let Some(pipeline) = dec.pipeline.as_mut() {
                pipeline.restore_decode_job(inline_job);
            }
            rqtrace!(
                "receiver: entry {} deferred stale decode retry for block {} after spawn denial: {err:?}",
                dec.index,
                block_sbn
            );
            Ok(stats)
        }
    }
}

async fn drain_ready_decodes(
    cx: &Cx,
    decoders: &mut [EntryDecoder],
    allow_spawn_decode: bool,
    transfer_decode_width: usize,
) -> Result<RqDecodeRoundStats, RqError> {
    let mut stats = RqDecodeRoundStats::default();
    for dec in decoders {
        stats.merge(
            drain_ready_entry_decodes(cx, dec, allow_spawn_decode, transfer_decode_width).await?,
        );
    }
    Ok(stats)
}

async fn join_all_pending_decodes(
    cx: &Cx,
    decoders: &mut [EntryDecoder],
    transfer_decode_width: usize,
) -> Result<RqDecodeRoundStats, RqError> {
    let mut stats = RqDecodeRoundStats::default();
    for dec in decoders {
        while let Some(mut pending) = dec.pending_decodes.pop() {
            stats.merge(
                join_pending_decode(cx, dec, &mut pending, true, transfer_decode_width).await?,
            );
        }
    }
    Ok(stats)
}

async fn drain_ready_entry_decodes(
    cx: &Cx,
    dec: &mut EntryDecoder,
    allow_spawn_decode: bool,
    transfer_decode_width: usize,
) -> Result<RqDecodeRoundStats, RqError> {
    let mut stats = RqDecodeRoundStats::default();
    let mut i = 0usize;
    while i < dec.pending_decodes.len() {
        if !dec.pending_decodes[i].handle.is_finished() {
            i += 1;
            continue;
        }
        let mut pending = dec.pending_decodes.swap_remove(i);
        stats.merge(
            join_pending_decode(
                cx,
                dec,
                &mut pending,
                allow_spawn_decode,
                transfer_decode_width,
            )
            .await?,
        );
    }
    Ok(stats)
}

async fn join_one_pending_decode(
    cx: &Cx,
    dec: &mut EntryDecoder,
    allow_spawn_decode: bool,
    transfer_decode_width: usize,
) -> Result<RqDecodeRoundStats, RqError> {
    let Some(mut pending) = dec.pending_decodes.pop() else {
        return Ok(RqDecodeRoundStats::default());
    };
    join_pending_decode(
        cx,
        dec,
        &mut pending,
        allow_spawn_decode,
        transfer_decode_width,
    )
    .await
}

async fn join_pending_decode(
    cx: &Cx,
    dec: &mut EntryDecoder,
    pending: &mut PendingDecode,
    allow_spawn_decode: bool,
    transfer_decode_width: usize,
) -> Result<RqDecodeRoundStats, RqError> {
    let block_sbn = pending.block_sbn;
    let join_start = Instant::now();
    let outcome = pending.handle.join(cx).await.map_err(|join_err| {
        RqError::Coding(format!(
            "decode task failed for entry {} block {}: {join_err:?}",
            dec.index, block_sbn
        ))
    })?;
    let join_wait = join_start.elapsed();
    let mut stats =
        finalize_decode_outcome(cx, dec, outcome, allow_spawn_decode, transfer_decode_width)
            .await?;
    stats.record_join_wait(join_wait);
    Ok(stats)
}

/// Pump UDP symbol datagrams into the decoders until a control frame arrives.
///
/// The sender finishes a spray round and *then* sends `ObjectComplete` on TCP,
/// so by interleaving `udp.recv` with `control.recv` we absorb the bulk symbols
/// and return as soon as the round's control marker lands. The UDP branch mirrors
/// native QUIC's `recv_batch_from` pump: one readiness-driven receive drains all
/// immediately-ready packets, then full batches get a bounded quiet-drain pass.
async fn pump_until_control<S>(
    cx: &Cx,
    control: &mut FrameTransport<S>,
    udp: &mut RqReceiverUdpFanout,
    tag: u64,
    auth_required: bool,
    symbol_auth: Option<&SecurityContext>,
    rbuf: &mut [u8],
    decoders: &mut [EntryDecoder],
    symbol_size: u16,
    symbols_accepted: &mut u64,
    round_stats: &mut RqDatagramRoundStats,
    trace_intake: bool,
) -> Result<Frame, RqError>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    use std::future::poll_fn;
    use std::pin::Pin;
    use std::task::Poll;

    enum Ready {
        Control(usize),
        Udp {
            socket_index: usize,
            batch: crate::net::UdpRecvBatch,
        },
    }

    let packet_size = rbuf.len();
    let mut cbuf = vec![0u8; 65536];
    let mut pumped: u64 = 0;
    loop {
        cx.checkpoint().map_err(|_| RqError::Cancelled)?;
        round_stats
            .record_decode_stats(drain_ready_decodes_if_pending(cx, decoders, symbol_size).await?);

        // 1) First, non-blockingly drain whatever the control codec already has
        //    buffered (a prior read may have pulled the frame in with symbols).
        if let Some(frame) = control
            .codec
            .decode(&mut control.rbuf)
            .map_err(|e| RqError::Frame(e.to_string()))?
        {
            rqtrace!(
                "pump: returning {:?} after {pumped} udp datagrams",
                frame.frame_type()
            );
            return Ok(frame);
        }

        // 2) Poll both the control stream and a readiness-driven UDP fanout batch.
        //    Whichever is ready makes progress; if only UDP is ready we keep
        //    pumping symbols. Both register their waker via task_cx, so the task
        //    parks until EITHER fd is ready — a biased two-way select.
        let recv_started = trace_intake.then(Instant::now);
        let ready = {
            poll_fn(|task_cx| {
                // UDP first so bulk data drains promptly under load.
                match udp.poll_recv_batch_any(task_cx, RQ_INBOUND_PUMP_BATCH, packet_size) {
                    Poll::Ready(Ok((socket_index, batch))) => {
                        return Poll::Ready(Ok::<Ready, std::io::Error>(Ready::Udp {
                            socket_index,
                            batch,
                        }));
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => {}
                }
                let mut read_buf = ReadBuf::new(&mut cbuf);
                match Pin::new(&mut control.stream).poll_read(task_cx, &mut read_buf) {
                    Poll::Ready(Ok(())) => Poll::Ready(Ok(Ready::Control(read_buf.filled().len()))),
                    Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                    Poll::Pending => Poll::Pending,
                }
            })
            .await?
        };
        let recv_elapsed = recv_started.map(|started| started.elapsed());

        match ready {
            Ready::Udp {
                socket_index,
                mut batch,
            } => {
                let mut received_len = batch.packets.len();
                let mut batches = 1usize;
                let mut stats = feed_datagram_batch_to_decoders(
                    cx,
                    &batch,
                    tag,
                    auth_required,
                    symbol_auth,
                    decoders,
                    symbol_size,
                    trace_intake,
                )
                .await?;
                if let Some(elapsed) = recv_elapsed {
                    stats.record_recv_elapsed(elapsed);
                }
                pumped = pumped.saturating_add(stats.observed);
                *symbols_accepted = (*symbols_accepted).saturating_add(stats.accepted);
                round_stats.merge(stats);
                round_stats.record_decode_stats(
                    drain_ready_decodes_if_pending(cx, decoders, symbol_size).await?,
                );
                udp.recycle_recv_batch(&mut batch, RQ_INBOUND_PUMP_BATCH);

                while received_len == RQ_INBOUND_PUMP_BATCH {
                    if batches >= RQ_INBOUND_PUMP_MAX_DRAIN_BATCHES {
                        rqtrace!(
                            "pump: udp batch drain budget exhausted after {batches} batches and {pumped} accepted datagrams"
                        );
                        break;
                    }

                    let tail_recv_started = trace_intake.then(Instant::now);
                    let mut tail = match crate::time::timeout(
                        cx.now(),
                        RQ_INBOUND_PUMP_DRAIN_GRACE,
                        udp.recv_batch_from_socket(
                            socket_index,
                            RQ_INBOUND_PUMP_BATCH,
                            packet_size,
                        ),
                    )
                    .await
                    {
                        Ok(Ok(batch)) => batch,
                        Ok(Err(e)) => return Err(RqError::Io(e)),
                        Err(_elapsed) => break,
                    };
                    let tail_recv_elapsed = tail_recv_started.map(|started| started.elapsed());
                    received_len = tail.packets.len();
                    if received_len == 0 {
                        break;
                    }
                    let mut stats = feed_datagram_batch_to_decoders(
                        cx,
                        &tail,
                        tag,
                        auth_required,
                        symbol_auth,
                        decoders,
                        symbol_size,
                        trace_intake,
                    )
                    .await?;
                    if let Some(elapsed) = tail_recv_elapsed {
                        stats.record_tail_drain_elapsed(elapsed);
                    }
                    pumped = pumped.saturating_add(stats.observed);
                    *symbols_accepted = (*symbols_accepted).saturating_add(stats.accepted);
                    round_stats.merge(stats);
                    round_stats.record_decode_stats(
                        drain_ready_decodes_if_pending(cx, decoders, symbol_size).await?,
                    );
                    udp.recycle_recv_batch(&mut tail, RQ_INBOUND_PUMP_BATCH);
                    batches = batches.saturating_add(1);
                }
            }
            Ready::Control(n) => {
                if n == 0 {
                    return Err(RqError::Io(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "control stream closed mid-transfer",
                    )));
                }
                control.rbuf.extend_from_slice(&cbuf[..n]);
                if let Some(frame) = control
                    .codec
                    .decode(&mut control.rbuf)
                    .map_err(|e| RqError::Frame(e.to_string()))?
                {
                    return Ok(frame);
                }
            }
        }
    }
}

/// Drain UDP symbols that raced behind the TCP round marker.
///
/// `ObjectComplete` only proves the sender has finished a spray round; it does
/// not prove the receiver has drained every datagram already queued locally. The
/// drain stops after a quiet window with no matching ATP-RQ symbol, with a hard
/// cap of 8x that window so stale or hostile UDP traffic cannot pin the task.
async fn drain_round_tail(
    cx: &Cx,
    udp: &mut RqReceiverUdpFanout,
    tag: u64,
    auth_required: bool,
    symbol_auth: Option<&SecurityContext>,
    rbuf: &mut [u8],
    quiet_window: Duration,
    decoders: &mut [EntryDecoder],
    symbol_size: u16,
    symbols_accepted: &mut u64,
    round_stats: &mut RqDatagramRoundStats,
    trace_intake: bool,
) -> Result<u64, RqError> {
    if quiet_window.is_zero() {
        return Ok(0);
    }

    use std::future::poll_fn;
    use std::pin::Pin;
    use std::task::Poll;

    let mut quiet_sleep = crate::time::Sleep::after(cx.now_for_observability(), quiet_window);
    let hard_cap = quiet_window.saturating_mul(8).max(Duration::from_millis(1));
    let mut hard_sleep = crate::time::Sleep::after(cx.now_for_observability(), hard_cap);
    let mut drained = 0u64;

    loop {
        cx.checkpoint().map_err(|_| RqError::Cancelled)?;

        let drain_started = trace_intake.then(Instant::now);
        let ready = poll_fn(|task_cx| {
            if Pin::new(&mut hard_sleep).poll(task_cx).is_ready() {
                return Poll::Ready(Ok::<Option<usize>, std::io::Error>(None));
            }

            match udp.poll_recv_any(task_cx, rbuf) {
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
        let drain_elapsed = drain_started.map(|started| started.elapsed());

        let Some(n) = ready else {
            return Ok(drained);
        };

        let ingest = feed_datagram_to_decoders(
            cx,
            rbuf,
            n,
            tag,
            auth_required,
            symbol_auth,
            decoders,
            symbol_size,
            trace_intake,
        )
        .await?;
        if ingest.observed {
            drained += 1;
            round_stats.record(ingest);
            if let Some(elapsed) = drain_elapsed {
                round_stats.record_tail_drain_elapsed(elapsed);
            }
            if ingest.accepted {
                *symbols_accepted = (*symbols_accepted).saturating_add(1);
            }
            quiet_sleep.reset_after(cx.now_for_observability(), quiet_window);
        }
        round_stats
            .record_decode_stats(drain_ready_decodes_if_pending(cx, decoders, symbol_size).await?);

        if drained > 0 && drained % 512 == 0 {
            crate::runtime::yield_now().await;
        }
    }
}

/// Run a persistent accept loop, handling each control connection as one
/// receive.
///
/// Returns when the capability context is cancelled. Connection-level errors are
/// reported via `on_result` and do not stop the loop.
pub async fn serve<F>(
    cx: &Cx,
    control_listener: TcpListener,
    udp_bind_ip: String,
    dest_dir: PathBuf,
    config: RqConfig,
    peer_id: String,
    mut on_result: F,
) -> Result<(), RqError>
where
    F: FnMut(Result<ReceiveReport, RqError>),
{
    loop {
        if cx.is_cancel_requested() {
            return Ok(());
        }
        let (stream, peer) = control_listener.accept().await?;
        let result = receive_connection(
            cx,
            stream,
            peer,
            &udp_bind_ip,
            &dest_dir,
            config.clone(),
            &peer_id,
        )
        .await;
        on_result(result);
    }
}

#[cfg(test)]
#[path = "transport_rq_tests.rs"]
mod tests;
