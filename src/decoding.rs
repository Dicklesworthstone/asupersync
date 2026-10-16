//! RaptorQ decoding pipeline (Phase 0).
//!
//! This module provides a deterministic, block-oriented decoding pipeline that
//! reconstructs original data from a set of received symbols. The current
//! implementation mirrors the systematic RaptorQ encoder: it solves for
//! intermediate symbols using the precode constraints and LT repair rows, then
//! reconstitutes source symbols deterministically for testing.

use crate::error::{Error, ErrorKind};
use crate::raptorq::decoder::{
    DecodeError as RaptorDecodeError, InactivationDecoder, MAX_ALLOWED_ESI, RankStatus,
    ReceivedSymbol,
};
use crate::raptorq::systematic::{SystematicError, SystematicParams};
use crate::security::{AuthenticatedSymbol, SecurityContext};
use crate::types::symbol_set::{InsertResult, SymbolSet, ThresholdConfig};
use crate::types::{ObjectId, ObjectParams, Symbol, SymbolId, SymbolKind};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

const REPAIR_RETENTION_MIN_SLACK: usize = 128;
const REPAIR_RETENTION_MAX_SLACK: usize = 2048;

const AUTO_REPAIR_RETENTION_MIN_EXTRA_SYMBOLS: usize = 256;
const AUTO_REPAIR_RETENTION_MAX_EXTRA_SYMBOLS: usize = 8192;

/// Errors produced by the decoding pipeline.
#[derive(Debug, thiserror::Error)]
pub enum DecodingError {
    /// Authentication failed for a symbol.
    #[error("authentication failed for symbol {symbol_id}")]
    AuthenticationFailed {
        /// The symbol that failed authentication.
        symbol_id: SymbolId,
    },
    /// Not enough symbols to decode.
    #[error("insufficient symbols: have {received}, need {needed}")]
    InsufficientSymbols {
        /// Received symbol count.
        received: usize,
        /// Needed symbol count.
        needed: usize,
    },
    /// Matrix inversion failed during decoding.
    #[error("matrix inversion failed: {reason}")]
    MatrixInversionFailed {
        /// Reason for failure.
        reason: String,
    },
    /// Block timed out before decoding completed.
    #[error("block timeout after {elapsed:?}")]
    BlockTimeout {
        /// Block number.
        sbn: u8,
        /// Elapsed time.
        elapsed: Duration,
    },
    /// Inconsistent metadata for a block or object.
    #[error("inconsistent block metadata: {sbn} {details}")]
    InconsistentMetadata {
        /// Block number.
        sbn: u8,
        /// Details of the inconsistency.
        details: String,
    },
    /// Symbol size mismatch.
    #[error("symbol size mismatch: expected {expected}, got {actual}")]
    SymbolSizeMismatch {
        /// Expected size in bytes.
        expected: u16,
        /// Actual size in bytes.
        actual: usize,
    },
}

impl From<DecodingError> for Error {
    fn from(err: DecodingError) -> Self {
        match &err {
            DecodingError::AuthenticationFailed { .. } => Self::new(ErrorKind::CorruptedSymbol),
            DecodingError::InsufficientSymbols { .. } => Self::new(ErrorKind::InsufficientSymbols),
            DecodingError::MatrixInversionFailed { .. }
            | DecodingError::InconsistentMetadata { .. }
            | DecodingError::SymbolSizeMismatch { .. } => Self::new(ErrorKind::DecodingFailed),
            DecodingError::BlockTimeout { .. } => Self::new(ErrorKind::ThresholdTimeout),
        }
        .with_message(err.to_string())
    }
}

/// Reasons a symbol may be rejected by the decoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    /// Symbol belongs to a different object.
    WrongObjectId,
    /// Authentication failed.
    AuthenticationFailed,
    /// Symbol size mismatch.
    SymbolSizeMismatch,
    /// Block already decoded.
    BlockAlreadyDecoded,
    /// Decode failed due to insufficient rank.
    InsufficientRank,
    /// Decode failed due to inconsistent equations.
    InconsistentEquations,
    /// Invalid or inconsistent metadata.
    InvalidMetadata,
    /// Memory or buffer limit reached.
    MemoryLimitReached,
}

/// Result of feeding a symbol into the decoder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SymbolAcceptResult {
    /// Symbol accepted and stored.
    Accepted {
        /// Symbols received for the block.
        received: usize,
        /// Estimated symbols needed for decode.
        needed: usize,
    },
    /// Decoding started for the block.
    DecodingStarted {
        /// Block number being decoded.
        block_sbn: u8,
    },
    /// Block fully decoded.
    BlockComplete {
        /// Block number.
        block_sbn: u8,
        /// Decoded block data.
        data: Vec<u8>,
    },
    /// Duplicate symbol ignored.
    Duplicate,
    /// Symbol rejected.
    Rejected(RejectReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
enum FeedDecodeMode {
    Inline,
    Deferred,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FeedAuthPolicy {
    VerifyInPipeline,
    // The pre-verified feed path has no wasm caller yet (browser feeds
    // always verify in-pipeline); native transports construct it.
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    CallerVerified,
}

/// Result of a feed that may defer the CPU-heavy RaptorQ solve to a blocking
/// worker.
#[derive(Debug)]
pub(crate) enum DeferredSymbolAcceptResult {
    /// The symbol was handled synchronously.
    Immediate(SymbolAcceptResult),
    /// The block reached decode threshold and should be solved off the caller's
    /// hot receive path.
    Decode(BlockDecodeJob),
}

/// Owned RaptorQ block-decode job.
#[derive(Debug, Clone)]
pub(crate) struct BlockDecodeJob {
    sbn: u8,
    plan: BlockPlan,
    symbols: Vec<Symbol>,
    source_symbols: usize,
    symbol_size: usize,
    retain_decoded_block: bool,
}

impl BlockDecodeJob {
    #[must_use]
    pub(crate) const fn sbn(&self) -> u8 {
        self.sbn
    }
}

#[derive(Debug)]
enum BlockDecodeResolution {
    Complete(Vec<u8>),
    Retry {
        reason: RejectReason,
        symbols: Vec<Symbol>,
    },
    Failed {
        reason: RejectReason,
        symbols: Vec<Symbol>,
    },
}

/// Which path produced a block-decode outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BlockDecodeKind {
    /// The block had every source symbol, so no RaptorQ matrix solve was needed.
    SourceComplete,
    /// The block required repair rows and a RaptorQ matrix solve.
    RaptorQRepair,
}

/// Output from a [`BlockDecodeJob`]. Feed it back through
/// [`DecodingPipeline::finish_decode_job`] to update pipeline state.
#[derive(Debug)]
pub(crate) struct BlockDecodeOutcome {
    sbn: u8,
    input_symbols: usize,
    retain_decoded_block: bool,
    // Read only by the native audit/telemetry consumers; the browser
    // profile records outcomes without re-reading these fields.
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    kind: BlockDecodeKind,
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    elapsed: Duration,
    resolution: BlockDecodeResolution,
}

/// FNV-1a 64 over a byte slice — the cheap payload fingerprint used by the
/// `ATP_RQ_INCONSISTENT_AUDIT` probe (c54to7): stable, dependency-free, and
/// enough to tell "same bytes" from "poisoned bytes" across audit dumps.
#[must_use]
pub(crate) fn audit_fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Env-gated (`ATP_RQ_INCONSISTENT_AUDIT`) equation-set dump when a block
/// solve rejects: one line per input symbol with its payload fingerprint.
/// Offline cross-check against the transport layer's staged-bytes dump for
/// the same block identifies WHICH symbol carried poisoned bytes (seeded
/// source vs wire repair) — the c54to7 residual-inconsistency probe.
fn audit_inconsistent_reject(sbn: u8, k: usize, symbols: &[Symbol], label: &str) {
    if std::env::var_os("ATP_RQ_INCONSISTENT_AUDIT").is_none() {
        return;
    }
    eprintln!(
        "[RQ_AUDIT] decode_reject sbn={sbn} k={k} n_symbols={} label={label}",
        symbols.len()
    );
    for symbol in symbols {
        eprintln!(
            "[RQ_AUDIT] sym sbn={} esi={} kind={:?} len={} h8={:016x}",
            symbol.sbn(),
            symbol.esi(),
            symbol.kind(),
            symbol.data().len(),
            audit_fnv1a64(symbol.data()),
        );
    }
}

/// Runs an owned block-decode job. Intended for `Cx::spawn_blocking`.
#[must_use]
pub(crate) fn run_block_decode_job(job: BlockDecodeJob) -> BlockDecodeOutcome {
    let BlockDecodeJob {
        sbn,
        plan,
        symbols,
        source_symbols,
        symbol_size,
        retain_decoded_block,
    } = job;
    let input_symbols = symbols.len();
    let started = Instant::now();
    let source_complete = (source_symbols >= plan.k)
        .then(|| complete_block_data_from_source_symbols(&plan, &symbols))
        .flatten();
    let (kind, resolution) = match source_complete {
        Some(data) => (
            BlockDecodeKind::SourceComplete,
            BlockDecodeResolution::Complete(data),
        ),
        None => {
            let resolution = match decode_block_data(&plan, &symbols, symbol_size) {
                Ok(data) => BlockDecodeResolution::Complete(data),
                Err(DecodingError::InsufficientSymbols { .. }) => BlockDecodeResolution::Retry {
                    reason: RejectReason::InsufficientRank,
                    symbols,
                },
                // A singular matrix is RANK DEFICIENCY, not inconsistency —
                // and at N == K it is EXPECTED RaptorQ behavior, not a bug:
                // RFC 6330's decode failure probability at exactly K symbols
                // is ~1e-2 (~1e-4 at K+1, ~1e-6 at K+2). With
                // repair_overhead = 1.0 every block's first solve fires at
                // exactly K, so a 500M sharded transfer (~900-1000 K-exact
                // solves) sees a handful of these per run; the Retry path
                // collects one more symbol and succeeds. Labeling this
                // InconsistentEquations sent a P1 correctness hunt after
                // spec-expected noise (br-asupersync-c54to7: traced audit
                // showed all residual rejects rank-K-exact with ZERO payload
                // mismatches across 1,192 seeded-vs-staged comparisons).
                // InconsistentEquations is reserved for the unexpected-error
                // fallback below, where the ATP_RQ_INCONSISTENT_AUDIT dump
                // fires loudly.
                Err(DecodingError::MatrixInversionFailed { .. }) => {
                    audit_inconsistent_reject(sbn, plan.k, &symbols, "rank_deficient_singular");
                    BlockDecodeResolution::Retry {
                        reason: RejectReason::InsufficientRank,
                        symbols,
                    }
                }
                Err(DecodingError::InconsistentMetadata { .. }) => BlockDecodeResolution::Failed {
                    reason: RejectReason::InvalidMetadata,
                    symbols,
                },
                Err(DecodingError::SymbolSizeMismatch { .. }) => BlockDecodeResolution::Failed {
                    reason: RejectReason::SymbolSizeMismatch,
                    symbols,
                },
                Err(_) => {
                    audit_inconsistent_reject(sbn, plan.k, &symbols, "decode_failed_other");
                    BlockDecodeResolution::Failed {
                        reason: RejectReason::InconsistentEquations,
                        symbols,
                    }
                }
            };
            (BlockDecodeKind::RaptorQRepair, resolution)
        }
    };
    BlockDecodeOutcome {
        sbn,
        input_symbols,
        retain_decoded_block,
        kind,
        elapsed: started.elapsed().max(Duration::from_nanos(1)),
        resolution,
    }
}

impl BlockDecodeOutcome {
    // The three accessors below serve native audit/staging consumers
    // (the c54to7 cross-dump and transport telemetry); the browser
    // profile has no caller yet, mirroring this file's wasm precedent.
    #[must_use]
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub(crate) fn elapsed(&self) -> Duration {
        self.elapsed
    }

    /// Block this outcome belongs to (the `ATP_RQ_INCONSISTENT_AUDIT`
    /// staging cross-dump needs it at the reject site, c54to7).
    #[must_use]
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub(crate) fn sbn(&self) -> u8 {
        self.sbn
    }

    #[must_use]
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub(crate) fn kind(&self) -> BlockDecodeKind {
        self.kind
    }
}

/// Configuration for decoding operations.
#[derive(Debug, Clone)]
pub struct DecodingConfig {
    /// Symbol size in bytes (must match encoding).
    pub symbol_size: u16,
    /// Maximum source block size in bytes.
    pub max_block_size: usize,
    /// Repair overhead factor (e.g., 1.05 = 5% extra symbols).
    pub repair_overhead: f64,
    /// Minimum extra symbols beyond K.
    pub min_overhead: usize,
    /// Maximum symbols to buffer per block (0 = unlimited).
    pub max_buffered_symbols: usize,
    /// Block timeout (not enforced in Phase 0).
    pub block_timeout: Duration,
    /// Whether to verify authentication tags.
    pub verify_auth: bool,
}

impl Default for DecodingConfig {
    /// br-asupersync-b1fojq: the default is **fail-closed** —
    /// `verify_auth: true`. A `DecodingPipeline` built from
    /// `DecodingConfig::default()` rejects every symbol unless an
    /// [`SecurityContext`] is installed (see [`DecodingPipeline::with_auth`])
    /// and the symbol authenticates. Previously the default was
    /// `verify_auth: false`, so a default-config pipeline authenticated
    /// NOTHING and silently accepted forged/unauthenticated symbols
    /// (decode-matrix poisoning). Callers that legitimately decode without
    /// per-symbol authentication (erasure-only / integrity-vs-manifest
    /// transports, or paths that authenticate each symbol upstream) must opt
    /// out **explicitly** via [`DecodingConfig::without_auth`] or by setting
    /// `verify_auth: false` in a literal — the insecure choice is no longer
    /// the default.
    fn default() -> Self {
        Self {
            symbol_size: 256,
            max_block_size: 1024 * 1024,
            repair_overhead: 1.05,
            min_overhead: 0,
            max_buffered_symbols: 8192,
            block_timeout: Duration::from_secs(30),
            verify_auth: true,
        }
    }
}

impl DecodingConfig {
    /// Explicit, **insecure** opt-out from per-symbol authentication.
    ///
    /// br-asupersync-b1fojq: returns the same configuration as
    /// [`DecodingConfig::default`] except `verify_auth` is `false`, so the
    /// resulting [`DecodingPipeline`] accepts symbols WITHOUT verifying an
    /// authentication tag. This is the correct configuration only when the
    /// caller does not need anti-forgery at the symbol layer — e.g.
    /// erasure-only recovery, integrity-vs-manifest transports, or pipelines
    /// that authenticate every symbol upstream before feeding it. Acceptance
    /// is still surfaced via [`DecodingPipeline::skipped_verifications`] and a
    /// one-time WARN. Prefer [`DecodingConfig::default`] (fail-closed) for any
    /// path that ingests symbols from an untrusted peer.
    #[must_use]
    pub fn without_auth() -> Self {
        Self {
            verify_auth: false,
            ..Self::default()
        }
    }
}

/// Progress summary for decoding.
#[derive(Debug, Clone, Copy)]
pub struct DecodingProgress {
    /// Blocks fully decoded.
    pub blocks_complete: usize,
    /// Total blocks expected (if known).
    pub blocks_total: Option<usize>,
    /// Total symbols received.
    pub symbols_received: usize,
    /// Estimated symbols needed to complete decode.
    pub symbols_needed_estimate: usize,
}

/// Per-block status.
#[derive(Debug, Clone, Copy)]
pub struct BlockStatus {
    /// Block number.
    pub sbn: u8,
    /// Symbols received for this block.
    pub symbols_received: usize,
    /// Estimated symbols needed for this block.
    pub symbols_needed: usize,
    /// Independent equation rank for this block, when computable.
    pub rank: Option<usize>,
    /// Additional independent equations required for full rank, when computable.
    pub rank_deficit: Option<usize>,
    /// Block state.
    pub state: BlockStateKind,
}

/// Missing systematic source symbol for an incomplete source block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MissingSourceSymbol {
    /// Source block number.
    pub sbn: u8,
    /// Encoding symbol id within the source block.
    pub esi: u32,
}

/// High-level block state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockStateKind {
    /// Collecting symbols.
    Collecting,
    /// Decoding in progress.
    Decoding,
    /// Decoded successfully.
    Decoded,
    /// Decoding failed.
    Failed,
}

#[derive(Debug)]
struct BlockDecoder {
    state: BlockDecodingState,
    decoded: Option<Vec<u8>>,
}

#[derive(Debug, Default, Clone, Copy)]
struct PipelineBlockCounts {
    source_symbols: usize,
    repair_symbols: usize,
}

impl PipelineBlockCounts {
    const fn total(self) -> usize {
        self.source_symbols + self.repair_symbols
    }
}

#[derive(Debug)]
enum BlockDecodingState {
    Collecting,
    Decoding,
    Decoded,
    Failed,
}

/// Main decoding pipeline.
#[derive(Debug)]
pub struct DecodingPipeline {
    config: DecodingConfig,
    symbols: SymbolSet,
    accepted_symbols_total: usize,
    block_symbol_counts: HashMap<u8, PipelineBlockCounts>,
    inflight_decode_symbols: HashSet<SymbolId>,
    blocks: HashMap<u8, BlockDecoder>,
    completed_blocks: HashSet<u8>,
    object_id: Option<ObjectId>,
    object_size: Option<u64>,
    block_plans: Option<Vec<BlockPlan>>,
    block_plan_by_sbn: [Option<usize>; 256],
    auth_context: Option<SecurityContext>,
    /// br-asupersync-f4mdcr: count of symbols accepted with
    /// authentication INTENTIONALLY skipped because
    /// `config.verify_auth = false`. Surfaced via
    /// [`Self::skipped_verifications`] so operators alerting on
    /// "authenticated symbol pipeline" health have an audit trail
    /// instead of silent acceptance.
    skipped_verifications: u64,
    /// br-asupersync-f4mdcr: tracks whether we have already emitted
    /// the one-time WARN log for the verify-auth-disabled path. The
    /// log is emitted once per pipeline instance to avoid spamming
    /// per-symbol log lines while still giving operators a visible
    /// signal that auth is off.
    verify_auth_disabled_warned: bool,
    /// br-asupersync-w9yojl: the last rank analysis of each block, keyed on
    /// the block's received symbol set. A rank depends only on which
    /// equations are present, so a feedback round that saw no new symbol for
    /// a block reuses it instead of rebuilding the block's whole constraint
    /// system. At most one entry per block.
    rank_cache: parking_lot::Mutex<HashMap<u8, (BlockSymbolsKey, Option<RankStatus>)>>,
    /// Rank analyses actually run, for the rank-cache tests.
    #[cfg(test)]
    rank_analyses: std::sync::atomic::AtomicUsize,
}

impl DecodingPipeline {
    /// Configured symbol size — the `ATP_RQ_INCONSISTENT_AUDIT` staging
    /// cross-dump (c54to7) needs it to mirror seed-symbol zero-padding.
    #[must_use]
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub(crate) fn config_symbol_size(&self) -> u16 {
        self.config.symbol_size
    }

    /// Creates a new decoding pipeline.
    #[must_use]
    pub fn new(config: DecodingConfig) -> Self {
        let threshold = ThresholdConfig::new(
            config.repair_overhead,
            config.min_overhead,
            config.max_buffered_symbols,
        );
        Self {
            config,
            symbols: SymbolSet::with_config(threshold),
            accepted_symbols_total: 0,
            block_symbol_counts: HashMap::new(),
            inflight_decode_symbols: HashSet::new(),
            blocks: HashMap::new(),
            completed_blocks: HashSet::new(),
            object_id: None,
            object_size: None,
            block_plans: None,
            block_plan_by_sbn: [None; 256],
            auth_context: None,
            skipped_verifications: 0,
            verify_auth_disabled_warned: false,
            rank_cache: parking_lot::Mutex::new(HashMap::new()),
            #[cfg(test)]
            rank_analyses: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// br-asupersync-f4mdcr: total number of `feed()` calls that
    /// accepted a symbol with authentication INTENTIONALLY skipped
    /// because `config.verify_auth = false`. Operators can scrape
    /// this counter via the runtime's observability surface to alert
    /// on misconfigured pipelines that quietly disable auth in
    /// production. Pre-fix the skip was silent — no log, no counter,
    /// no observability hook fired — so a deployment that misset
    /// `verify_auth = false` accepted unauthenticated symbols
    /// without any operator-visible signal.
    #[must_use]
    #[inline]
    pub const fn skipped_verifications(&self) -> u64 {
        self.skipped_verifications
    }

    /// Creates a new decoding pipeline with authentication enabled.
    #[must_use]
    pub fn with_auth(config: DecodingConfig, ctx: SecurityContext) -> Self {
        let mut pipeline = Self::new(config);
        pipeline.auth_context = Some(ctx);
        pipeline
    }

    /// Sets object parameters (object size, symbol size, and block layout).
    pub fn set_object_params(&mut self, params: ObjectParams) -> Result<(), DecodingError> {
        if params.symbol_size != self.config.symbol_size {
            return Err(DecodingError::SymbolSizeMismatch {
                expected: self.config.symbol_size,
                actual: params.symbol_size as usize,
            });
        }
        if let Some(existing) = self.object_id {
            if existing != params.object_id {
                return Err(DecodingError::InconsistentMetadata {
                    sbn: 0,
                    details: format!(
                        "object id mismatch: expected {existing:?}, got {:?}",
                        params.object_id
                    ),
                });
            }
        }
        let plans = plan_blocks(
            params.object_size as usize,
            usize::from(params.symbol_size),
            self.config.max_block_size,
        )?;
        validate_object_params_layout(params, &plans)?;
        let block_plan_by_sbn = block_plan_index_by_sbn(&plans);
        self.object_id = Some(params.object_id);
        self.object_size = Some(params.object_size);
        self.block_plans = Some(plans);
        self.block_plan_by_sbn = block_plan_by_sbn;
        self.configure_auto_buffer_limit();
        self.configure_block_k();
        Ok(())
    }

    /// The effective per-block symbol-accept cap (`0` means unbounded).
    ///
    /// With `max_buffered_symbols == 0`, [`set_object_params`](Self::set_object_params)
    /// sizes this to cover K (plus repair slack) via `configure_auto_buffer_limit`;
    /// with a fixed nonzero `max_buffered_symbols` it stays at that value and does
    /// not scale with K.
    #[must_use]
    pub fn block_accept_cap(&self) -> usize {
        self.symbols.max_per_block()
    }

    /// Feeds a received authenticated symbol into the pipeline.
    pub fn feed(
        &mut self,
        auth_symbol: AuthenticatedSymbol,
    ) -> Result<SymbolAcceptResult, DecodingError> {
        self.feed_with_retention(auth_symbol, true)
    }

    /// Feeds a received authenticated symbol and returns an owned decode job
    /// when the block reaches threshold. Unlike
    /// [`Self::feed_streaming_block_deferred`], completed block data is retained
    /// in this pipeline so existing full-object commit paths can still call
    /// [`Self::into_data`] after joining the decode job.
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub(crate) fn feed_deferred(
        &mut self,
        auth_symbol: AuthenticatedSymbol,
    ) -> Result<DeferredSymbolAcceptResult, DecodingError> {
        self.feed_with_retention_and_mode(
            auth_symbol,
            true,
            FeedDecodeMode::Deferred,
            FeedAuthPolicy::VerifyInPipeline,
        )
    }

    /// Feeds a streaming symbol and returns an owned decode job when the block
    /// reaches threshold. The caller must run the job and pass its outcome to
    /// [`Self::finish_decode_job`].
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub(crate) fn feed_streaming_block_deferred(
        &mut self,
        auth_symbol: AuthenticatedSymbol,
    ) -> Result<DeferredSymbolAcceptResult, DecodingError> {
        self.feed_with_retention_and_mode(
            auth_symbol,
            false,
            FeedDecodeMode::Deferred,
            FeedAuthPolicy::VerifyInPipeline,
        )
    }

    /// Feeds a streaming symbol that the caller has already authenticated with
    /// the same security context guarding this receive pipeline.
    ///
    /// This is intentionally `pub(crate)` and separate from the normal feed
    /// methods: a bare verified bit is not generally transferable between
    /// trust domains, but transport-level batch verifiers can prove the tag once
    /// at the receiver boundary and then preserve decoder ordering without a
    /// second serial HMAC.
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub(crate) fn feed_preverified_streaming_block_deferred(
        &mut self,
        auth_symbol: AuthenticatedSymbol,
    ) -> Result<DeferredSymbolAcceptResult, DecodingError> {
        self.feed_with_retention_and_mode(
            auth_symbol,
            false,
            FeedDecodeMode::Deferred,
            FeedAuthPolicy::CallerVerified,
        )
    }

    fn feed_with_retention(
        &mut self,
        auth_symbol: AuthenticatedSymbol,
        retain_decoded_block: bool,
    ) -> Result<SymbolAcceptResult, DecodingError> {
        match self.feed_with_retention_and_mode(
            auth_symbol,
            retain_decoded_block,
            FeedDecodeMode::Inline,
            FeedAuthPolicy::VerifyInPipeline,
        )? {
            DeferredSymbolAcceptResult::Immediate(result) => Ok(result),
            DeferredSymbolAcceptResult::Decode(job) => Ok(SymbolAcceptResult::DecodingStarted {
                block_sbn: job.sbn(),
            }),
        }
    }

    fn feed_with_retention_and_mode(
        &mut self,
        mut auth_symbol: AuthenticatedSymbol,
        retain_decoded_block: bool,
        mode: FeedDecodeMode,
        auth_policy: FeedAuthPolicy,
    ) -> Result<DeferredSymbolAcceptResult, DecodingError> {
        if matches!(auth_policy, FeedAuthPolicy::CallerVerified) {
            if !auth_symbol.is_verified() {
                return Ok(DeferredSymbolAcceptResult::Immediate(
                    SymbolAcceptResult::Rejected(RejectReason::AuthenticationFailed),
                ));
            }
        } else if self.config.verify_auth {
            match &self.auth_context {
                Some(ctx) => {
                    if ctx.verify_authenticated_symbol(&mut auth_symbol).is_err()
                        || !auth_symbol.is_verified()
                    {
                        return Ok(DeferredSymbolAcceptResult::Immediate(
                            SymbolAcceptResult::Rejected(RejectReason::AuthenticationFailed),
                        ));
                    }
                }
                None => {
                    // A bare `verified` bit does not identify which key or verifier vouched for
                    // the symbol. Without an auth context, we cannot authenticate deterministically
                    // and must fail closed.
                    return Ok(DeferredSymbolAcceptResult::Immediate(
                        SymbolAcceptResult::Rejected(RejectReason::AuthenticationFailed),
                    ));
                }
            }
        } else if !self.verify_auth_disabled_warned {
            // br-asupersync-f4mdcr: auth is disabled by configuration.
            // The pre-fix shape silently accepted the symbol with NO
            // log, NO counter, NO observability hook — operators
            // alerting on `starvation_events: 0, priority_inversions: 0`
            // had no way to detect a deployment that quietly turned
            // off auth. Now we emit a one-time WARN per pipeline
            // instance and expose accepted-symbol counts via
            // [`Self::skipped_verifications`].
            self.verify_auth_disabled_warned = true;
            crate::tracing_compat::warn!(
                target: "asupersync::decoding",
                "br-asupersync-f4mdcr: DecodingPipeline configured \
                 with verify_auth=false; subsequent symbols are accepted \
                 without authentication. Skipped count is exposed via \
                 DecodingPipeline::skipped_verifications()."
            );
        }

        let symbol = auth_symbol.into_symbol();

        if symbol.len() != usize::from(self.config.symbol_size) {
            return Ok(DeferredSymbolAcceptResult::Immediate(
                SymbolAcceptResult::Rejected(RejectReason::SymbolSizeMismatch),
            ));
        }

        if let Some(object_id) = self.object_id {
            if object_id != symbol.object_id() {
                return Ok(DeferredSymbolAcceptResult::Immediate(
                    SymbolAcceptResult::Rejected(RejectReason::WrongObjectId),
                ));
            }
        } else {
            self.object_id = Some(symbol.object_id());
        }

        let symbol_id = symbol.id();
        let sbn = symbol.sbn();
        let kind = symbol.kind();
        if self.block_plans.is_some() && self.block_plan(sbn).is_none() {
            return Ok(DeferredSymbolAcceptResult::Immediate(
                SymbolAcceptResult::Rejected(RejectReason::InvalidMetadata),
            ));
        }
        if self.completed_blocks.contains(&sbn) {
            return Ok(DeferredSymbolAcceptResult::Immediate(
                SymbolAcceptResult::Rejected(RejectReason::BlockAlreadyDecoded),
            ));
        }
        // A symbol no decode of its block can use is refused here, before it
        // is retained: once retained it fails every decode of the block and is
        // restored afterwards, so the block never decodes.
        if let Some(plan) = self.block_plan(sbn)
            && !esi_fits_block(kind, symbol.esi(), plan.k)
        {
            return Ok(DeferredSymbolAcceptResult::Immediate(
                SymbolAcceptResult::Rejected(RejectReason::InvalidMetadata),
            ));
        }
        if self.inflight_decode_symbols.contains(&symbol_id) {
            return Ok(DeferredSymbolAcceptResult::Immediate(
                SymbolAcceptResult::Duplicate,
            ));
        }
        if kind.is_repair() && !self.symbols.contains(&symbol_id) {
            self.configure_block_k();
            if self.repair_retention_saturated(sbn) {
                return Ok(DeferredSymbolAcceptResult::Immediate(
                    SymbolAcceptResult::Rejected(RejectReason::MemoryLimitReached),
                ));
            }
        }

        // Ensure block entry exists
        self.blocks.entry(sbn).or_insert_with(|| BlockDecoder {
            state: BlockDecodingState::Collecting,
            decoded: None,
        });

        let insert_result = self.symbols.insert(symbol);
        match insert_result {
            InsertResult::Duplicate => Ok(DeferredSymbolAcceptResult::Immediate(
                SymbolAcceptResult::Duplicate,
            )),
            InsertResult::MemoryLimitReached | InsertResult::BlockLimitReached { .. } => {
                Ok(DeferredSymbolAcceptResult::Immediate(
                    SymbolAcceptResult::Rejected(RejectReason::MemoryLimitReached),
                ))
            }
            InsertResult::Inserted {
                block_progress,
                threshold_reached: _,
            } => {
                self.accepted_symbols_total = self.accepted_symbols_total.saturating_add(1);
                if !self.config.verify_auth {
                    self.skipped_verifications = self.skipped_verifications.saturating_add(1);
                }
                let counts = self.block_symbol_counts.entry(sbn).or_default();
                match kind {
                    SymbolKind::Source => counts.source_symbols += 1,
                    SymbolKind::Repair => counts.repair_symbols += 1,
                }
                let received = counts.total();
                let source_received = counts.source_symbols;

                if block_progress.k.is_none() {
                    self.configure_block_k();
                }

                let progress = self
                    .symbols
                    .block_progress(sbn)
                    .copied()
                    .unwrap_or(block_progress);
                let k = self
                    .block_plan(sbn)
                    .map(|plan| plan.k)
                    .or_else(|| progress.k.map(usize::from));
                let needed = k.map_or(0, |k| {
                    required_symbols(
                        u16::try_from(k).unwrap_or(u16::MAX),
                        self.config.repair_overhead,
                        self.config.min_overhead,
                    )
                });
                if k.is_some_and(|k| source_received >= k || received >= needed) {
                    if matches!(mode, FeedDecodeMode::Deferred) && self.block_is_decoding(sbn) {
                        return Ok(DeferredSymbolAcceptResult::Immediate(
                            SymbolAcceptResult::Accepted { received, needed },
                        ));
                    }

                    // Update state to Decoding
                    if let Some(block) = self.blocks.get_mut(&sbn) {
                        block.state = BlockDecodingState::Decoding;
                    }
                    if matches!(mode, FeedDecodeMode::Deferred) {
                        if let Some(job) = self.prepare_decode_job(sbn, retain_decoded_block) {
                            return Ok(DeferredSymbolAcceptResult::Decode(job));
                        }
                    } else if let Some(result) = self.try_decode_block(sbn, retain_decoded_block) {
                        return Ok(DeferredSymbolAcceptResult::Immediate(result));
                    }
                }

                // Reset state to Collecting (if not decoded)
                if let Some(block) = self.blocks.get_mut(&sbn) {
                    if !matches!(
                        block.state,
                        BlockDecodingState::Decoded | BlockDecodingState::Failed
                    ) {
                        block.state = BlockDecodingState::Collecting;
                    }
                }
                Ok(DeferredSymbolAcceptResult::Immediate(
                    SymbolAcceptResult::Accepted { received, needed },
                ))
            }
        }
    }

    /// Feeds a batch of symbols.
    pub fn feed_batch(
        &mut self,
        symbols: impl Iterator<Item = AuthenticatedSymbol>,
    ) -> Vec<Result<SymbolAcceptResult, DecodingError>> {
        symbols.map(|symbol| self.feed(symbol)).collect()
    }

    /// Returns true if all expected blocks are decoded.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        let Some(plans) = &self.block_plans else {
            return false;
        };
        self.completed_blocks.len() == plans.len()
    }

    /// Returns decoding progress.
    #[must_use]
    pub fn progress(&self) -> DecodingProgress {
        let blocks_total = self.block_plans.as_ref().map(Vec::len);
        let symbols_received = self.accepted_symbols_total;
        let symbols_needed_estimate = self.block_plans.as_ref().map_or(0, |plans| {
            sum_required_symbols(plans, self.config.repair_overhead, self.config.min_overhead)
        });

        DecodingProgress {
            blocks_complete: self.completed_blocks.len(),
            blocks_total,
            symbols_received,
            symbols_needed_estimate,
        }
    }

    /// Returns how many symbols a block has received, if it is known.
    ///
    /// The count [`Self::block_status`] reports, without the rank analysis
    /// that call also runs (a dense constraint-matrix build and elimination,
    /// O(L^2) work for a block of L intermediate symbols). Use this on
    /// per-symbol paths.
    #[must_use]
    pub fn block_symbols_received(&self, sbn: u8) -> Option<usize> {
        self.symbols
            .block_progress(sbn)
            .map(|progress| progress.total())
    }

    /// Returns per-block status if known.
    #[must_use]
    pub fn block_status(&self, sbn: u8) -> Option<BlockStatus> {
        let progress = self.symbols.block_progress(sbn)?;
        let state = self
            .blocks
            .get(&sbn)
            .map_or(BlockStateKind::Collecting, |block| match block.state {
                BlockDecodingState::Collecting => BlockStateKind::Collecting,
                BlockDecodingState::Decoding => BlockStateKind::Decoding,
                BlockDecodingState::Decoded => BlockStateKind::Decoded,
                BlockDecodingState::Failed => BlockStateKind::Failed,
            });

        let symbols_needed = progress.k.map_or(0, |k| {
            required_symbols(k, self.config.repair_overhead, self.config.min_overhead)
        });
        let rank_status = self.block_rank_status(sbn);

        Some(BlockStatus {
            sbn,
            symbols_received: progress.total(),
            symbols_needed,
            rank: rank_status.map(|status| status.rank),
            rank_deficit: rank_status.map(|status| status.deficit),
            state,
        })
    }

    /// Consumes the pipeline and returns decoded data if complete.
    pub fn into_data(self) -> Result<Vec<u8>, DecodingError> {
        let Some(plans) = &self.block_plans else {
            return Err(DecodingError::InconsistentMetadata {
                sbn: 0,
                details: "object parameters not set".to_string(),
            });
        };
        if !self.is_complete() {
            let received = self.accepted_symbols_total;
            let needed =
                sum_required_symbols(plans, self.config.repair_overhead, self.config.min_overhead);
            return Err(DecodingError::InsufficientSymbols { received, needed });
        }

        let mut output = Vec::with_capacity(self.object_size.unwrap_or(0) as usize);
        for plan in plans {
            let block = self
                .blocks
                .get(&plan.sbn)
                .and_then(|b| b.decoded.as_ref())
                .ok_or_else(|| DecodingError::InconsistentMetadata {
                    sbn: plan.sbn,
                    details: "missing decoded block".to_string(),
                })?;
            output.extend_from_slice(block);
        }

        if let Some(size) = self.object_size {
            output.truncate(size as usize);
        }

        Ok(output)
    }

    fn configure_block_k(&mut self) {
        let Some(plans) = &self.block_plans else {
            return;
        };
        for plan in plans {
            let k = u16::try_from(plan.k).unwrap_or(u16::MAX);
            let _ = self.symbols.set_block_k(plan.sbn, k);
        }
    }

    fn configure_auto_buffer_limit(&mut self) {
        if self.config.max_buffered_symbols != 0 {
            return;
        }
        let Some(plans) = &self.block_plans else {
            return;
        };
        let max_k = plans.iter().map(|plan| plan.k).max().unwrap_or(0);
        if max_k == 0 {
            return;
        }
        let extra = max_k.clamp(
            AUTO_REPAIR_RETENTION_MIN_EXTRA_SYMBOLS,
            AUTO_REPAIR_RETENTION_MAX_EXTRA_SYMBOLS,
        );
        self.symbols.set_max_per_block(max_k.saturating_add(extra));
    }

    fn try_decode_block(
        &mut self,
        sbn: u8,
        retain_decoded_block: bool,
    ) -> Option<SymbolAcceptResult> {
        if let Some(result) = self.try_complete_source_block(sbn, retain_decoded_block) {
            return Some(result);
        }

        let job = self.prepare_decode_job(sbn, retain_decoded_block)?;
        let outcome = run_block_decode_job(job);
        Some(self.finish_inline_decode_job(outcome))
    }

    fn try_complete_source_block(
        &mut self,
        sbn: u8,
        retain_decoded_block: bool,
    ) -> Option<SymbolAcceptResult> {
        let block_plan = self.block_plan(sbn)?.clone();
        // O(1) gate (br-asupersync-atp-dataplane-redesign-317hxr.29, drhadc lever):
        // try_complete_from_source_symbols allocates + copies the ENTIRE block on every
        // call and returns None until all k source symbols are present. Called per source
        // symbol, that is O(k^2) alloc/copy per block — the clean-link receiver-intake
        // wall (MATRIX-23 feed_micros). Skip it until the maintained source count reaches
        // k; source symbols are never evicted, so the count is exact.
        if self
            .block_symbol_counts
            .get(&sbn)
            .map_or(0, |counts| counts.source_symbols)
            < block_plan.k
        {
            return None;
        }
        let block_data = self.try_complete_from_source_symbols(&block_plan)?;

        self.mark_block_complete(sbn, retain_decoded_block.then(|| block_data.clone()));

        Some(SymbolAcceptResult::BlockComplete {
            block_sbn: sbn,
            data: block_data,
        })
    }

    fn prepare_decode_job(
        &mut self,
        sbn: u8,
        retain_decoded_block: bool,
    ) -> Option<BlockDecodeJob> {
        let block_plan = self.block_plan(sbn)?.clone();
        if block_plan.k == 0 {
            return None;
        }

        // O(1) gate (br-asupersync-atp-dataplane-redesign-317hxr.29, drhadc lever):
        // skip cloning every received block symbol until at least k symbols
        // (source+repair) are available to decode. Called per symbol, the old
        // clone-then-`len() < k` was O(k^2) clone per block. The authoritative
        // `symbols.len() < k` check below is retained as a backstop in case repair
        // retention eviction leaves the count ahead of the live symbol set.
        let counts = self
            .block_symbol_counts
            .get(&sbn)
            .copied()
            .unwrap_or_default();
        if counts.total() < block_plan.k {
            return None;
        }

        let symbols = self.symbols.take_block_symbols(sbn);
        if symbols.len() < block_plan.k {
            self.restore_decode_symbols(sbn, symbols);
            return None;
        }
        self.remember_decode_job_symbols(&symbols);

        Some(BlockDecodeJob {
            sbn,
            plan: block_plan,
            symbols,
            source_symbols: counts.source_symbols,
            symbol_size: usize::from(self.config.symbol_size),
            retain_decoded_block,
        })
    }

    fn block_is_decoding(&self, sbn: u8) -> bool {
        self.blocks
            .get(&sbn)
            .is_some_and(|block| matches!(block.state, BlockDecodingState::Decoding))
    }

    fn repair_retention_saturated(&self, sbn: u8) -> bool {
        let Some(cap) = self.repair_retention_cap(sbn) else {
            return false;
        };
        self.block_symbol_counts
            .get(&sbn)
            .is_some_and(|counts| counts.total() >= cap)
    }

    fn repair_retention_cap(&self, sbn: u8) -> Option<usize> {
        let k = self.block_plan(sbn).map(|plan| plan.k).or_else(|| {
            self.symbols
                .block_progress(sbn)
                .and_then(|progress| progress.k.map(usize::from))
        })?;
        if k == 0 {
            return Some(0);
        }
        let needed = required_symbols(
            u16::try_from(k).unwrap_or(u16::MAX),
            self.config.repair_overhead,
            self.config.min_overhead,
        );
        let slack = k.clamp(REPAIR_RETENTION_MIN_SLACK, REPAIR_RETENTION_MAX_SLACK);
        let minimum_safe_cap = needed.max(k);
        let dynamic_cap = needed.saturating_add(slack).max(k);
        let configured_cap = self.config.max_buffered_symbols;
        Some(if configured_cap == 0 {
            dynamic_cap
        } else {
            configured_cap.max(minimum_safe_cap)
        })
    }

    fn finish_inline_decode_job(&mut self, outcome: BlockDecodeOutcome) -> SymbolAcceptResult {
        let BlockDecodeOutcome {
            sbn,
            input_symbols: _,
            retain_decoded_block,
            kind: _,
            elapsed: _,
            resolution,
        } = outcome;
        match resolution {
            BlockDecodeResolution::Complete(block_data) => {
                self.mark_block_complete(sbn, retain_decoded_block.then(|| block_data.clone()));
                SymbolAcceptResult::BlockComplete {
                    block_sbn: sbn,
                    data: block_data,
                }
            }
            BlockDecodeResolution::Retry { reason, symbols } => {
                self.restore_decode_symbols(sbn, symbols);
                if let Some(block) = self.blocks.get_mut(&sbn) {
                    block.state = BlockDecodingState::Collecting;
                }
                SymbolAcceptResult::Rejected(reason)
            }
            BlockDecodeResolution::Failed { reason, symbols } => {
                self.restore_decode_symbols(sbn, symbols);
                if let Some(block) = self.blocks.get_mut(&sbn) {
                    block.state = BlockDecodingState::Failed;
                }
                SymbolAcceptResult::Rejected(reason)
            }
        }
    }

    /// Finalizes a previously deferred decode job and updates block state.
    #[must_use]
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub(crate) fn finish_decode_job(&mut self, outcome: BlockDecodeOutcome) -> SymbolAcceptResult {
        match self.finish_decode_job_deferred(outcome) {
            DeferredSymbolAcceptResult::Immediate(result) => result,
            DeferredSymbolAcceptResult::Decode(job) => {
                let outcome = run_block_decode_job(job);
                self.finish_inline_decode_job(outcome)
            }
        }
    }

    /// Finalizes a previously deferred decode job without running any CPU-heavy
    /// retry inline. If newer symbols arrived while the job was in flight, the
    /// caller gets a fresh owned job that can be sent back through its blocking
    /// decode queue.
    #[must_use]
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub(crate) fn finish_decode_job_deferred(
        &mut self,
        outcome: BlockDecodeOutcome,
    ) -> DeferredSymbolAcceptResult {
        let BlockDecodeOutcome {
            sbn,
            input_symbols,
            retain_decoded_block,
            kind: _,
            elapsed: _,
            resolution,
        } = outcome;
        if self.completed_blocks.contains(&sbn) {
            return DeferredSymbolAcceptResult::Immediate(SymbolAcceptResult::Rejected(
                RejectReason::BlockAlreadyDecoded,
            ));
        }

        match resolution {
            BlockDecodeResolution::Complete(block_data) => {
                self.mark_block_complete(sbn, retain_decoded_block.then(|| block_data.clone()));
                DeferredSymbolAcceptResult::Immediate(SymbolAcceptResult::BlockComplete {
                    block_sbn: sbn,
                    data: block_data,
                })
            }
            BlockDecodeResolution::Retry { reason, symbols } => {
                if let Some(block) = self.blocks.get_mut(&sbn) {
                    block.state = BlockDecodingState::Collecting;
                }
                self.restore_decode_symbols(sbn, symbols);
                let current_symbols = self.symbols.symbols_for_block(sbn).count();
                if current_symbols > input_symbols {
                    if let Some(job) = self.prepare_decode_job(sbn, retain_decoded_block) {
                        if let Some(block) = self.blocks.get_mut(&sbn) {
                            block.state = BlockDecodingState::Decoding;
                        }
                        return DeferredSymbolAcceptResult::Decode(job);
                    }
                }
                DeferredSymbolAcceptResult::Immediate(SymbolAcceptResult::Rejected(reason))
            }
            BlockDecodeResolution::Failed { reason, symbols } => {
                self.restore_decode_symbols(sbn, symbols);
                if let Some(block) = self.blocks.get_mut(&sbn) {
                    block.state = BlockDecodingState::Failed;
                }
                DeferredSymbolAcceptResult::Immediate(SymbolAcceptResult::Rejected(reason))
            }
        }
    }

    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub(crate) fn cancel_decode_job(&mut self, sbn: u8) {
        if self.completed_blocks.contains(&sbn) {
            return;
        }
        if let Some(block) = self.blocks.get_mut(&sbn) {
            if matches!(block.state, BlockDecodingState::Decoding) {
                block.state = BlockDecodingState::Collecting;
            }
        }
    }

    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub(crate) fn restore_decode_job(&mut self, job: BlockDecodeJob) {
        let sbn = job.sbn;
        if self.completed_blocks.contains(&sbn) {
            for symbol in &job.symbols {
                self.inflight_decode_symbols.remove(&symbol.id());
            }
            return;
        }
        self.cancel_decode_job(sbn);
        self.restore_decode_symbols(sbn, job.symbols);
    }

    fn remember_decode_job_symbols(&mut self, symbols: &[Symbol]) {
        for symbol in symbols {
            self.inflight_decode_symbols.insert(symbol.id());
        }
    }

    fn restore_decode_symbols(&mut self, sbn: u8, symbols: Vec<Symbol>) {
        for symbol in symbols {
            self.inflight_decode_symbols.remove(&symbol.id());
            debug_assert_eq!(symbol.sbn(), sbn);
            let _ = self.symbols.restore_retained(symbol);
        }
    }

    fn forget_inflight_decode_symbols_for_block(&mut self, sbn: u8) {
        self.inflight_decode_symbols
            .retain(|symbol_id| symbol_id.sbn() != sbn);
    }

    fn try_complete_from_source_symbols(&self, block_plan: &BlockPlan) -> Option<Vec<u8>> {
        let object_id = self.object_id?;
        let mut block_data = Vec::with_capacity(block_plan.len);
        for esi in 0..block_plan.k {
            let esi = u32::try_from(esi).ok()?;
            let id = SymbolId::new(object_id, block_plan.sbn, esi);
            let symbol = self.symbols.get(&id)?;
            if symbol.kind() != SymbolKind::Source {
                return None;
            }
            let remaining = block_plan.len.saturating_sub(block_data.len());
            if remaining == 0 {
                break;
            }
            let take = remaining.min(symbol.data().len());
            block_data.extend_from_slice(&symbol.data()[..take]);
        }
        (block_data.len() == block_plan.len).then_some(block_data)
    }

    fn mark_block_complete(&mut self, sbn: u8, retained_block: Option<Vec<u8>>) {
        if let Some(block) = self.blocks.get_mut(&sbn) {
            block.state = BlockDecodingState::Decoded;
            block.decoded = retained_block;
        }
        self.completed_blocks.insert(sbn);
        self.forget_inflight_decode_symbols_for_block(sbn);
        self.symbols.clear_block(sbn);
        self.block_symbol_counts.remove(&sbn);
    }

    fn block_plan(&self, sbn: u8) -> Option<&BlockPlan> {
        let idx = self.block_plan_by_sbn[usize::from(sbn)]?;
        self.block_plans.as_ref()?.get(idx)
    }

    fn block_rank_status(&self, sbn: u8) -> Option<RankStatus> {
        let block_plan = self.block_plan(sbn)?.clone();
        // The ATP QUIC receiver asks for every block's status on every
        // feedback round; an unchanged block reuses its last analysis
        // (br-asupersync-w9yojl).
        let key = BlockSymbolsKey::of(&block_plan, self.symbols.symbols_for_block(sbn));
        if let Some((cached_key, status)) = self.rank_cache.lock().get(&sbn) {
            if *cached_key == key {
                return *status;
            }
        }
        #[cfg(test)]
        self.rank_analyses
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let symbols: Vec<Symbol> = self.symbols.symbols_for_block(sbn).cloned().collect();
        let status =
            rank_status_for_block(&block_plan, &symbols, usize::from(self.config.symbol_size)).ok();
        self.rank_cache.lock().insert(sbn, (key, status));
        status
    }

    /// Returns missing systematic source symbols for incomplete blocks.
    ///
    /// This is used by ATP-RQ as a cheap first feedback step: retransmitting a
    /// sparse set of missing systematic symbols avoids constructing the
    /// CPU-heavy RaptorQ repair encoder when the receiver only dropped a few
    /// datagrams. `limit == 0` means unbounded.
    #[must_use]
    pub fn missing_source_symbols(&self, limit: usize) -> Vec<MissingSourceSymbol> {
        let Some(object_id) = self.object_id else {
            return Vec::new();
        };
        let Some(plans) = &self.block_plans else {
            return Vec::new();
        };

        let mut missing = Vec::new();
        for plan in plans {
            if self.completed_blocks.contains(&plan.sbn) {
                continue;
            }
            for esi in 0..plan.k {
                let Ok(esi) = u32::try_from(esi) else {
                    break;
                };
                let id = SymbolId::new(object_id, plan.sbn, esi);
                if !self.symbols.contains(&id) && !self.inflight_decode_symbols.contains(&id) {
                    missing.push(MissingSourceSymbol { sbn: plan.sbn, esi });
                    if limit != 0 && missing.len() >= limit {
                        return missing;
                    }
                }
            }
        }
        missing
    }
}

#[derive(Debug, Clone)]
struct BlockPlan {
    sbn: u8,
    len: usize,
    k: usize,
}

/// What a block's rank analysis depends on: its plan and the identity and
/// length of each received symbol (payload bytes do not change a rank). The
/// two order-independent hash folds make a changed symbol set look different.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BlockSymbolsKey {
    k: usize,
    len: usize,
    count: usize,
    sum: u64,
    xor: u64,
}

impl BlockSymbolsKey {
    fn of<'a>(plan: &BlockPlan, symbols: impl Iterator<Item = &'a Symbol>) -> Self {
        use std::hash::{Hash, Hasher};
        let mut key = Self {
            k: plan.k,
            len: plan.len,
            count: 0,
            sum: 0,
            xor: 0,
        };
        for symbol in symbols {
            let mut hasher = std::hash::DefaultHasher::new();
            symbol.id().hash(&mut hasher);
            symbol.len().hash(&mut hasher);
            let hash = hasher.finish();
            key.count += 1;
            key.sum = key.sum.wrapping_add(hash);
            key.xor ^= hash.rotate_left(29).wrapping_mul(0x9e37_79b9_7f4a_7c15);
        }
        key
    }
}

fn plan_blocks(
    object_size: usize,
    symbol_size: usize,
    max_block_size: usize,
) -> Result<Vec<BlockPlan>, DecodingError> {
    if object_size == 0 {
        return Ok(Vec::new());
    }

    if symbol_size == 0 {
        return Err(DecodingError::InconsistentMetadata {
            sbn: 0,
            details: "symbol_size must be > 0".to_string(),
        });
    }

    let max_blocks = u8::MAX as usize + 1;
    let max_total = max_block_size.saturating_mul(max_blocks);
    if object_size > max_total {
        return Err(DecodingError::InconsistentMetadata {
            sbn: 0,
            details: format!("object size {object_size} exceeds limit {max_total}"),
        });
    }

    let mut blocks = Vec::new();
    let mut offset = 0;
    let mut sbn: u8 = 0;

    while offset < object_size {
        let len = usize::min(max_block_size, object_size - offset);
        let k = len.div_ceil(symbol_size);
        blocks.push(BlockPlan { sbn, len, k });
        offset += len;
        sbn = sbn.wrapping_add(1);
    }

    Ok(blocks)
}

fn block_plan_index_by_sbn(plans: &[BlockPlan]) -> [Option<usize>; 256] {
    let mut index = [None; 256];
    for (idx, plan) in plans.iter().enumerate() {
        index[usize::from(plan.sbn)] = Some(idx);
    }
    index
}

fn validate_object_params_layout(
    params: ObjectParams,
    plans: &[BlockPlan],
) -> Result<(), DecodingError> {
    let declared_blocks = usize::from(params.source_blocks);
    let declared_k = usize::from(params.symbols_per_block);

    if plans.is_empty() {
        if declared_blocks == 0 && declared_k == 0 {
            return Ok(());
        }
        if declared_blocks == 1 {
            return Ok(());
        }
        return Err(DecodingError::InconsistentMetadata {
            sbn: 0,
            details: format!(
                "object params layout mismatch: empty object expects either 0 blocks / 0 symbols-per-block or a single empty sentinel block, got {declared_blocks} block(s) with {declared_k} symbols/block"
            ),
        });
    }

    let expected_blocks = plans.len();
    if declared_blocks != expected_blocks {
        return Err(DecodingError::InconsistentMetadata {
            sbn: 0,
            details: format!(
                "object params block count mismatch: expected {expected_blocks}, got {declared_blocks}"
            ),
        });
    }

    let expected_k = plans.iter().map(|plan| plan.k).max().unwrap_or(0);
    if declared_k != expected_k {
        return Err(DecodingError::InconsistentMetadata {
            sbn: 0,
            details: format!(
                "object params symbols_per_block mismatch: expected {expected_k}, got {declared_k}"
            ),
        });
    }

    // br-asupersync-qokghh: reject K outside the RFC 6330 systematic-index
    // table BEFORE decode_block reaches InactivationDecoder::new, which
    // would otherwise panic via SystematicParams::for_source_block. A
    // peer-supplied symbols_per_block (u16, 0..65535) or a misconfigured
    // DecodingConfig (e.g., symbol_size=1 with default max_block_size)
    // can drive K above the 56403 max; surface that as a typed
    // InconsistentMetadata at validation time.
    let symbol_size = usize::from(params.symbol_size);
    if symbol_size > 0 {
        for plan in plans {
            if let Err(err) = SystematicParams::try_for_source_block(plan.k, symbol_size) {
                return Err(DecodingError::InconsistentMetadata {
                    sbn: plan.sbn,
                    details: format!(
                        "block K={} exceeds RFC 6330 systematic-index table: {err:?}",
                        plan.k
                    ),
                });
            }
        }
    }

    Ok(())
}

fn required_symbols(k: u16, overhead: f64, min_overhead: usize) -> usize {
    if k == 0 {
        return 0;
    }
    let raw = (f64::from(k) * overhead).ceil();
    let minimum_threshold = usize::from(k).saturating_add(min_overhead);
    if raw.is_nan() {
        return minimum_threshold;
    }
    if raw.is_sign_positive() && !raw.is_finite() {
        return usize::MAX;
    }
    if raw.is_sign_negative() {
        return minimum_threshold;
    }
    #[allow(clippy::cast_sign_loss)]
    let factor_threshold = raw as usize;
    // `overhead` already encodes the total-symbol target; `min_overhead` is a
    // floor on extra symbols beyond K, not an additional increment on top.
    factor_threshold.max(minimum_threshold)
}

fn sum_required_symbols(plans: &[BlockPlan], overhead: f64, min_overhead: usize) -> usize {
    plans.iter().fold(0usize, |acc, plan| {
        acc.saturating_add(required_symbols(
            u16::try_from(plan.k).unwrap_or(u16::MAX),
            overhead,
            min_overhead,
        ))
    })
}

/// Whether a symbol's ESI can take part in decoding a block of `k` source
/// symbols: a source ESI names one of the K source symbols, and a repair ESI
/// starts at K and stays within the range the decoder admits.
fn esi_fits_block(kind: SymbolKind, esi: u32, k: usize) -> bool {
    let esi_index = esi as usize;
    match kind {
        SymbolKind::Source => esi_index < k,
        SymbolKind::Repair => esi_index >= k && esi <= MAX_ALLOWED_ESI,
    }
}

fn received_symbols_for_block(
    plan: &BlockPlan,
    symbols: &[Symbol],
    decoder: &InactivationDecoder,
) -> Result<Vec<ReceivedSymbol>, DecodingError> {
    let k = plan.k;
    let mut received = decoder.constraint_symbols();
    received.reserve(symbols.len());

    for symbol in symbols {
        match symbol.kind() {
            SymbolKind::Source => {
                let esi = symbol.esi() as usize;
                if esi >= k {
                    return Err(DecodingError::InconsistentMetadata {
                        sbn: plan.sbn,
                        details: format!("source esi {esi} >= k {k}"),
                    });
                }
                received.push(ReceivedSymbol::source(symbol.esi(), symbol.data().to_vec()));
            }
            SymbolKind::Repair => {
                let (columns, coefficients) = match decoder.repair_equation(symbol.esi()) {
                    Ok(equation) => equation,
                    Err(SystematicError::RepairEsiBelowK { esi, k }) => {
                        return Err(DecodingError::InconsistentMetadata {
                            sbn: plan.sbn,
                            details: format!("repair esi {esi} < first repair esi {k}"),
                        });
                    }
                    Err(SystematicError::EsiOverflow { esi, padding_delta }) => {
                        return Err(DecodingError::InconsistentMetadata {
                            sbn: plan.sbn,
                            details: format!(
                                "repair esi {esi} overflows RFC repair-ISI padding delta {padding_delta}"
                            ),
                        });
                    }
                };
                received.push(ReceivedSymbol {
                    esi: symbol.esi(),
                    is_source: false,
                    columns,
                    coefficients,
                    data: symbol.data().to_vec(),
                });
            }
        }
    }

    Ok(received)
}

fn rank_status_for_block(
    plan: &BlockPlan,
    symbols: &[Symbol],
    symbol_size: usize,
) -> Result<RankStatus, DecodingError> {
    if plan.k == 0 {
        return Ok(RankStatus {
            rank: 0,
            columns: 0,
            deficit: 0,
        });
    }

    let object_id = symbols.first().map_or(ObjectId::NIL, Symbol::object_id);
    let block_seed = seed_for_block(object_id, plan.sbn);
    let decoder = InactivationDecoder::new(plan.k, symbol_size, block_seed);
    let received = received_symbols_for_block(plan, symbols, &decoder)?;
    decoder.rank_status(&received).map_err(|err| match err {
        RaptorDecodeError::SymbolSizeMismatch { expected, actual } => {
            DecodingError::SymbolSizeMismatch {
                expected: u16::try_from(expected).unwrap_or(u16::MAX),
                actual,
            }
        }
        RaptorDecodeError::SymbolEquationArityMismatch {
            esi,
            columns,
            coefficients,
        } => DecodingError::InconsistentMetadata {
            sbn: plan.sbn,
            details: format!(
                "symbol {esi} has mismatched equation vectors: columns={columns}, coefficients={coefficients}"
            ),
        },
        RaptorDecodeError::ColumnIndexOutOfRange {
            esi,
            column,
            max_valid,
        } => DecodingError::InconsistentMetadata {
            sbn: plan.sbn,
            details: format!(
                "symbol {esi} references out-of-range column {column} (valid < {max_valid})"
            ),
        },
        RaptorDecodeError::SourceEsiOutOfRange { esi, max_valid } => {
            DecodingError::InconsistentMetadata {
                sbn: plan.sbn,
                details: format!(
                    "source symbol {esi} falls outside the systematic domain (valid < {max_valid})"
                ),
            }
        }
        RaptorDecodeError::InvalidSourceSymbolEquation {
            esi,
            expected_column,
        } => DecodingError::InconsistentMetadata {
            sbn: plan.sbn,
            details: format!(
                "source symbol {esi} must use the identity equation for column {expected_column}"
            ),
        },
        other => DecodingError::MatrixInversionFailed {
            reason: format!("{other:?}"),
        },
    })
}

#[allow(clippy::too_many_lines)]
fn decode_block(
    plan: &BlockPlan,
    symbols: &[Symbol],
    symbol_size: usize,
) -> Result<Vec<Symbol>, DecodingError> {
    let k = plan.k;
    if symbols.len() < k {
        return Err(DecodingError::InsufficientSymbols {
            received: symbols.len(),
            needed: k,
        });
    }

    let object_id = symbols.first().map_or(ObjectId::NIL, Symbol::object_id);
    let block_seed = seed_for_block(object_id, plan.sbn);
    let decoder = InactivationDecoder::new(k, symbol_size, block_seed);
    let received = received_symbols_for_block(plan, symbols, &decoder)?;

    let result = match decoder.decode(&received) {
        Ok(result) => result,
        Err(err) => {
            let mapped = match err {
                RaptorDecodeError::InsufficientSymbols { received, required } => {
                    DecodingError::InsufficientSymbols {
                        received,
                        needed: required,
                    }
                }
                RaptorDecodeError::SingularMatrix { row } => DecodingError::MatrixInversionFailed {
                    reason: format!("singular matrix at row {row}"),
                },
                RaptorDecodeError::SymbolSizeMismatch { expected, actual } => {
                    DecodingError::SymbolSizeMismatch {
                        expected: u16::try_from(expected).unwrap_or(u16::MAX),
                        actual,
                    }
                }
                RaptorDecodeError::SymbolEquationArityMismatch {
                    esi,
                    columns,
                    coefficients,
                } => DecodingError::InconsistentMetadata {
                    sbn: plan.sbn,
                    details: format!(
                        "symbol {esi} has mismatched equation vectors: columns={columns}, coefficients={coefficients}"
                    ),
                },
                RaptorDecodeError::ColumnIndexOutOfRange {
                    esi,
                    column,
                    max_valid,
                } => DecodingError::InconsistentMetadata {
                    sbn: plan.sbn,
                    details: format!(
                        "symbol {esi} references out-of-range column {column} (valid < {max_valid})"
                    ),
                },
                RaptorDecodeError::SourceEsiOutOfRange { esi, max_valid } => {
                    DecodingError::InconsistentMetadata {
                        sbn: plan.sbn,
                        details: format!(
                            "source symbol {esi} falls outside the systematic domain (valid < {max_valid})"
                        ),
                    }
                }
                RaptorDecodeError::InvalidSourceSymbolEquation {
                    esi,
                    expected_column,
                } => DecodingError::InconsistentMetadata {
                    sbn: plan.sbn,
                    details: format!(
                        "source symbol {esi} must use the identity equation for column {expected_column}"
                    ),
                },
                RaptorDecodeError::CorruptDecodedOutput {
                    esi,
                    byte_index,
                    expected,
                    actual,
                } => DecodingError::MatrixInversionFailed {
                    reason: format!(
                        "decoded output verification failed at symbol {esi}, byte {byte_index}: expected 0x{expected:02x}, actual 0x{actual:02x}"
                    ),
                },
                RaptorDecodeError::ComputeBudgetExhausted {
                    used,
                    requested,
                    max,
                } => DecodingError::MatrixInversionFailed {
                    reason: format!(
                        "compute budget exhausted: used {used}, requested {requested}, max {max}"
                    ),
                },
                RaptorDecodeError::EsiRateLimitExceeded {
                    esi,
                    column_count,
                    max_columns,
                } => DecodingError::InconsistentMetadata {
                    sbn: plan.sbn,
                    details: format!(
                        "ESI rate limit exceeded: symbol {esi} would generate {column_count} columns (max {max_columns})"
                    ),
                },
            };
            return Err(mapped);
        }
    };

    // 4. Construct decoded symbols from the source data returned by the decoder.
    // InactivationDecoder::decode already extracts the first K intermediate symbols
    // into `result.source`, which corresponds exactly to the systematic source data.
    let mut decoded_symbols = Vec::with_capacity(k);
    for (esi, data) in result.source.into_iter().enumerate() {
        decoded_symbols.push(Symbol::new(
            SymbolId::new(object_id, plan.sbn, esi as u32),
            data,
            SymbolKind::Source,
        ));
    }

    Ok(decoded_symbols)
}

fn decode_block_data(
    plan: &BlockPlan,
    symbols: &[Symbol],
    symbol_size: usize,
) -> Result<Vec<u8>, DecodingError> {
    let decoded_symbols = decode_block(plan, symbols, symbol_size)?;
    let mut block_data = Vec::with_capacity(plan.len);
    for symbol in &decoded_symbols {
        block_data.extend_from_slice(symbol.data());
    }
    block_data.truncate(plan.len);
    Ok(block_data)
}

fn complete_block_data_from_source_symbols(
    plan: &BlockPlan,
    symbols: &[Symbol],
) -> Option<Vec<u8>> {
    if plan.k == 0 {
        return Some(Vec::new());
    }

    let mut source_payloads = vec![None; plan.k];
    for symbol in symbols {
        if symbol.kind() != SymbolKind::Source {
            continue;
        }
        let esi = usize::try_from(symbol.esi()).ok()?;
        if esi < plan.k {
            source_payloads[esi] = Some(symbol.data());
        }
    }

    let mut block_data = Vec::with_capacity(plan.len);
    for payload in source_payloads {
        let payload = payload?;
        let remaining = plan.len.saturating_sub(block_data.len());
        if remaining == 0 {
            break;
        }
        let take = remaining.min(payload.len());
        block_data.extend_from_slice(&payload[..take]);
    }

    (block_data.len() == plan.len).then_some(block_data)
}

fn seed_for_block(object_id: ObjectId, sbn: u8) -> u64 {
    seed_for(object_id, sbn, 0)
}

fn seed_for(object_id: ObjectId, sbn: u8, esi: u32) -> u64 {
    let obj = object_id.as_u128();
    let hi = (obj >> 64) as u64;
    let lo = obj as u64;
    let mut seed = hi ^ lo.rotate_left(13);
    seed ^= u64::from(sbn) << 56;
    seed ^= u64::from(esi);
    if seed == 0 { 1 } else { seed }
}

#[cfg(test)]
#[path = "decoding_inline_tests.rs"]
mod tests;
