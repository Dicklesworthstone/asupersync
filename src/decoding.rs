//! RaptorQ decoding pipeline (Phase 0).
//!
//! This module provides a deterministic, block-oriented decoding pipeline that
//! reconstructs original data from a set of received symbols. The current
//! implementation mirrors the systematic RaptorQ encoder: it solves for
//! intermediate symbols using the precode constraints and LT repair rows, then
//! reconstitutes source symbols deterministically for testing.

use crate::error::{Error, ErrorKind};
use crate::raptorq::decoder::{
    DecodeError as RaptorDecodeError, InactivationDecoder, RankStatus, ReceivedSymbol,
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
    Retry(RejectReason),
    Failed(RejectReason),
}

/// Output from a [`BlockDecodeJob`]. Feed it back through
/// [`DecodingPipeline::finish_decode_job`] to update pipeline state.
#[derive(Debug)]
pub(crate) struct BlockDecodeOutcome {
    sbn: u8,
    input_symbols: usize,
    retain_decoded_block: bool,
    elapsed: Duration,
    resolution: BlockDecodeResolution,
}

/// Runs an owned block-decode job. Intended for `Cx::spawn_blocking`.
#[must_use]
pub(crate) fn run_block_decode_job(job: BlockDecodeJob) -> BlockDecodeOutcome {
    let started = Instant::now();
    let resolution =
        if let Some(data) = complete_block_data_from_source_symbols(&job.plan, &job.symbols) {
            BlockDecodeResolution::Complete(data)
        } else {
            match decode_block_data(&job.plan, &job.symbols, job.symbol_size) {
                Ok(data) => BlockDecodeResolution::Complete(data),
                Err(DecodingError::InsufficientSymbols { .. }) => {
                    BlockDecodeResolution::Retry(RejectReason::InsufficientRank)
                }
                Err(DecodingError::MatrixInversionFailed { .. }) => {
                    BlockDecodeResolution::Retry(RejectReason::InconsistentEquations)
                }
                Err(DecodingError::InconsistentMetadata { .. }) => {
                    BlockDecodeResolution::Failed(RejectReason::InvalidMetadata)
                }
                Err(DecodingError::SymbolSizeMismatch { .. }) => {
                    BlockDecodeResolution::Failed(RejectReason::SymbolSizeMismatch)
                }
                Err(_) => BlockDecodeResolution::Failed(RejectReason::InconsistentEquations),
            }
        };
    BlockDecodeOutcome {
        sbn: job.sbn,
        input_symbols: job.symbols.len(),
        retain_decoded_block: job.retain_decoded_block,
        elapsed: started.elapsed().max(Duration::from_nanos(1)),
        resolution,
    }
}

impl BlockDecodeOutcome {
    #[must_use]
    pub(crate) fn elapsed(&self) -> Duration {
        self.elapsed
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
    blocks: HashMap<u8, BlockDecoder>,
    completed_blocks: HashSet<u8>,
    object_id: Option<ObjectId>,
    object_size: Option<u64>,
    block_plans: Option<Vec<BlockPlan>>,
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
}

impl DecodingPipeline {
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
            blocks: HashMap::new(),
            completed_blocks: HashSet::new(),
            object_id: None,
            object_size: None,
            block_plans: None,
            auth_context: None,
            skipped_verifications: 0,
            verify_auth_disabled_warned: false,
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
        self.object_id = Some(params.object_id);
        self.object_size = Some(params.object_size);
        self.block_plans = Some(plans);
        self.configure_auto_buffer_limit();
        self.configure_block_k();
        Ok(())
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
    pub(crate) fn feed_deferred(
        &mut self,
        auth_symbol: AuthenticatedSymbol,
    ) -> Result<DeferredSymbolAcceptResult, DecodingError> {
        self.feed_with_retention_and_mode(auth_symbol, true, FeedDecodeMode::Deferred)
    }

    /// Feeds a streaming symbol and returns an owned decode job when the block
    /// reaches threshold. The caller must run the job and pass its outcome to
    /// [`Self::finish_decode_job`].
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub(crate) fn feed_streaming_block_deferred(
        &mut self,
        auth_symbol: AuthenticatedSymbol,
    ) -> Result<DeferredSymbolAcceptResult, DecodingError> {
        self.feed_with_retention_and_mode(auth_symbol, false, FeedDecodeMode::Deferred)
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
    ) -> Result<DeferredSymbolAcceptResult, DecodingError> {
        if self.config.verify_auth {
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
        let block_data = self.try_complete_from_source_symbols(&block_plan)?;

        self.mark_block_complete(sbn, retain_decoded_block.then(|| block_data.clone()));

        Some(SymbolAcceptResult::BlockComplete {
            block_sbn: sbn,
            data: block_data,
        })
    }

    fn prepare_decode_job(&self, sbn: u8, retain_decoded_block: bool) -> Option<BlockDecodeJob> {
        let block_plan = self.block_plan(sbn)?.clone();
        if block_plan.k == 0 {
            return None;
        }

        let symbols: Vec<Symbol> = self.symbols.symbols_for_block(sbn).cloned().collect();
        if symbols.len() < block_plan.k {
            return None;
        }

        Some(BlockDecodeJob {
            sbn,
            plan: block_plan,
            symbols,
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
            BlockDecodeResolution::Retry(reason) => {
                if let Some(block) = self.blocks.get_mut(&sbn) {
                    block.state = BlockDecodingState::Collecting;
                }
                SymbolAcceptResult::Rejected(reason)
            }
            BlockDecodeResolution::Failed(reason) => {
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
            BlockDecodeResolution::Retry(reason) => {
                if let Some(block) = self.blocks.get_mut(&sbn) {
                    block.state = BlockDecodingState::Collecting;
                }
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
            BlockDecodeResolution::Failed(reason) => {
                if let Some(block) = self.blocks.get_mut(&sbn) {
                    block.state = BlockDecodingState::Failed;
                }
                DeferredSymbolAcceptResult::Immediate(SymbolAcceptResult::Rejected(reason))
            }
        }
    }

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
        self.symbols.clear_block(sbn);
        self.block_symbol_counts.remove(&sbn);
    }

    fn block_plan(&self, sbn: u8) -> Option<&BlockPlan> {
        self.block_plans
            .as_ref()
            .and_then(|plans| plans.iter().find(|plan| plan.sbn == sbn))
    }

    fn block_rank_status(&self, sbn: u8) -> Option<RankStatus> {
        let block_plan = self.block_plan(sbn)?.clone();
        let symbols: Vec<Symbol> = self.symbols.symbols_for_block(sbn).cloned().collect();
        rank_status_for_block(&block_plan, &symbols, usize::from(self.config.symbol_size)).ok()
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
                if !self.symbols.contains(&id) {
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
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::encoding::EncodingPipeline;
    use crate::types::resource::{PoolConfig, SymbolPool};

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn pool() -> SymbolPool {
        SymbolPool::new(PoolConfig {
            symbol_size: 256,
            initial_size: 64,
            max_size: 64,
            allow_growth: false,
            growth_increment: 0,
        })
    }

    fn encoding_config() -> crate::config::EncodingConfig {
        crate::config::EncodingConfig {
            symbol_size: 256,
            max_block_size: 1024,
            repair_overhead: 1.05,
            encoding_parallelism: 1,
            decoding_parallelism: 1,
        }
    }

    fn decoder_with_params(
        config: &crate::config::EncodingConfig,
        object_id: ObjectId,
        data_len: usize,
        repair_overhead: f64,
        min_overhead: usize,
    ) -> DecodingPipeline {
        let mut decoder = DecodingPipeline::new(DecodingConfig {
            symbol_size: config.symbol_size,
            max_block_size: config.max_block_size,
            repair_overhead,
            min_overhead,
            max_buffered_symbols: 8192,
            block_timeout: Duration::from_secs(30),
            verify_auth: false,
        });
        let symbols_per_block = (data_len.div_ceil(usize::from(config.symbol_size))) as u16;
        decoder
            .set_object_params(ObjectParams::new(
                object_id,
                data_len as u64,
                config.symbol_size,
                1,
                symbols_per_block,
            ))
            .expect("params");
        decoder
    }

    #[test]
    fn missing_source_symbols_reports_absent_source_esis() {
        init_test("missing_source_symbols_reports_absent_source_esis");
        let config = encoding_config();
        let mut encoder = EncodingPipeline::new(config.clone(), pool());
        let object_id = ObjectId::new_for_test(101);
        let data = vec![7u8; 768];
        let mut decoder = decoder_with_params(&config, object_id, data.len(), 1.0, 0);

        for encoded in encoder.encode_with_repair(object_id, &data, 0) {
            let symbol = encoded.expect("encode").into_symbol();
            if symbol.esi() == 1 {
                continue;
            }
            decoder
                .feed(AuthenticatedSymbol::new_unauthenticated(symbol))
                .expect("feed");
        }

        assert_eq!(
            decoder.missing_source_symbols(0),
            vec![MissingSourceSymbol { sbn: 0, esi: 1 }]
        );
        assert_eq!(
            decoder.missing_source_symbols(1),
            vec![MissingSourceSymbol { sbn: 0, esi: 1 }]
        );
    }

    #[test]
    fn decode_roundtrip_sources_only() {
        init_test("decode_roundtrip_sources_only");
        let config = encoding_config();
        let mut encoder = EncodingPipeline::new(config.clone(), pool());
        let object_id = ObjectId::new_for_test(1);
        let data = vec![42u8; 512];
        let symbols: Vec<Symbol> = encoder
            .encode_with_repair(object_id, &data, 0)
            .map(|res| res.unwrap().into_symbol())
            .collect();

        let mut decoder = decoder_with_params(&config, object_id, data.len(), 1.0, 0);

        for symbol in symbols {
            let auth = AuthenticatedSymbol::from_parts(
                symbol,
                crate::security::tag::AuthenticationTag::zero(),
            );
            let _ = decoder.feed(auth).unwrap();
        }

        let decoded_data = decoder.into_data().expect("decoded");
        let ok = decoded_data == data;
        crate::assert_with_log!(ok, "decoded data", data, decoded_data);
        crate::test_complete!("decode_roundtrip_sources_only");
    }

    #[test]
    fn decode_roundtrip_out_of_order() {
        init_test("decode_roundtrip_out_of_order");
        let config = encoding_config();
        let mut encoder = EncodingPipeline::new(config.clone(), pool());
        let object_id = ObjectId::new_for_test(2);
        let data = vec![7u8; 768];
        let mut symbols: Vec<Symbol> = encoder
            .encode_with_repair(object_id, &data, 2)
            .map(|res| res.expect("encode").into_symbol())
            .collect();

        symbols.reverse();

        let mut decoder =
            decoder_with_params(&config, object_id, data.len(), config.repair_overhead, 0);

        for symbol in symbols {
            let auth = AuthenticatedSymbol::from_parts(
                symbol,
                crate::security::tag::AuthenticationTag::zero(),
            );
            let _ = decoder.feed(auth).expect("feed");
        }

        let decoded_data = decoder.into_data().expect("decoded");
        let ok = decoded_data == data;
        crate::assert_with_log!(ok, "decoded data", data, decoded_data);
        crate::test_complete!("decode_roundtrip_out_of_order");
    }

    #[test]
    fn reject_wrong_object_id() {
        init_test("reject_wrong_object_id");
        let config = encoding_config();
        let mut encoder = EncodingPipeline::new(config.clone(), pool());
        let object_id_a = ObjectId::new_for_test(10);
        let object_id_b = ObjectId::new_for_test(11);
        let data = vec![1u8; 128];

        let mut decoder =
            decoder_with_params(&config, object_id_a, data.len(), config.repair_overhead, 0);

        let symbol_b = encoder
            .encode_with_repair(object_id_b, &data, 0)
            .next()
            .expect("symbol")
            .expect("encode")
            .into_symbol();
        let auth = AuthenticatedSymbol::from_parts(
            symbol_b,
            crate::security::tag::AuthenticationTag::zero(),
        );

        let result = decoder.feed(auth).expect("feed");
        let expected = SymbolAcceptResult::Rejected(RejectReason::WrongObjectId);
        let ok = result == expected;
        crate::assert_with_log!(ok, "wrong object id", expected, result);
        crate::test_complete!("reject_wrong_object_id");
    }

    #[test]
    fn reject_symbol_size_mismatch() {
        init_test("reject_symbol_size_mismatch");
        let config = encoding_config();
        let mut decoder = DecodingPipeline::new(DecodingConfig {
            symbol_size: config.symbol_size,
            max_block_size: config.max_block_size,
            repair_overhead: config.repair_overhead,
            min_overhead: 0,
            max_buffered_symbols: 8192,
            block_timeout: Duration::from_secs(30),
            verify_auth: false,
        });

        let symbol = Symbol::new(
            SymbolId::new(ObjectId::new_for_test(20), 0, 0),
            vec![0u8; 8],
            SymbolKind::Source,
        );
        let auth = AuthenticatedSymbol::from_parts(
            symbol,
            crate::security::tag::AuthenticationTag::zero(),
        );
        let result = decoder.feed(auth).expect("feed");
        let expected = SymbolAcceptResult::Rejected(RejectReason::SymbolSizeMismatch);
        let ok = result == expected;
        crate::assert_with_log!(ok, "symbol size mismatch", expected, result);
        crate::test_complete!("reject_symbol_size_mismatch");
    }

    #[test]
    fn reject_invalid_metadata_esi_out_of_range() {
        init_test("reject_invalid_metadata_esi_out_of_range");
        let mut decoder = DecodingPipeline::new(DecodingConfig {
            symbol_size: 8,
            max_block_size: 8,
            repair_overhead: 1.0,
            min_overhead: 0,
            max_buffered_symbols: 8192,
            block_timeout: Duration::from_secs(30),
            verify_auth: false,
        });
        let object_id = ObjectId::new_for_test(21);
        decoder
            .set_object_params(ObjectParams::new(object_id, 8, 8, 1, 1))
            .expect("params");

        let symbol = Symbol::new(
            SymbolId::new(object_id, 0, 1),
            vec![0u8; 8],
            SymbolKind::Source,
        );
        let auth = AuthenticatedSymbol::from_parts(
            symbol,
            crate::security::tag::AuthenticationTag::zero(),
        );

        let result = decoder.feed(auth).expect("feed");
        let expected = SymbolAcceptResult::Rejected(RejectReason::InvalidMetadata);
        let ok = result == expected;
        crate::assert_with_log!(ok, "invalid metadata", expected, result);
        crate::test_complete!("reject_invalid_metadata_esi_out_of_range");
    }

    #[test]
    fn reject_invalid_metadata_repair_esi_overflow_without_panicking() {
        init_test("reject_invalid_metadata_repair_esi_overflow_without_panicking");
        let mut decoder = DecodingPipeline::new(DecodingConfig {
            symbol_size: 8,
            max_block_size: 16,
            repair_overhead: 1.0,
            min_overhead: 0,
            max_buffered_symbols: 8192,
            block_timeout: Duration::from_secs(30),
            verify_auth: false,
        });
        let object_id = ObjectId::new_for_test(22);
        decoder
            .set_object_params(ObjectParams::new(object_id, 16, 8, 1, 2))
            .expect("params");

        let source = Symbol::new(
            SymbolId::new(object_id, 0, 0),
            vec![0x11; 8],
            SymbolKind::Source,
        );
        let repair = Symbol::new(
            SymbolId::new(object_id, 0, u32::MAX),
            vec![0x22; 8],
            SymbolKind::Repair,
        );

        let first = decoder
            .feed(AuthenticatedSymbol::from_parts(
                source,
                crate::security::tag::AuthenticationTag::zero(),
            ))
            .expect("feed source");
        let first_ok = matches!(first, SymbolAcceptResult::Accepted { .. });
        crate::assert_with_log!(first_ok, "source accepted before threshold", true, first_ok);

        let result = decoder
            .feed(AuthenticatedSymbol::from_parts(
                repair,
                crate::security::tag::AuthenticationTag::zero(),
            ))
            .expect("feed repair overflow");
        let expected = SymbolAcceptResult::Rejected(RejectReason::InvalidMetadata);
        let ok = result == expected;
        crate::assert_with_log!(
            ok,
            "repair overflow rejected as invalid metadata",
            expected,
            result
        );

        crate::test_complete!("reject_invalid_metadata_repair_esi_overflow_without_panicking");
    }

    #[test]
    fn reject_invalid_metadata_out_of_layout_sbn_without_buffering() {
        init_test("reject_invalid_metadata_out_of_layout_sbn_without_buffering");
        let mut decoder = DecodingPipeline::new(DecodingConfig {
            symbol_size: 8,
            max_block_size: 8,
            repair_overhead: 1.0,
            min_overhead: 0,
            max_buffered_symbols: 8192,
            block_timeout: Duration::from_secs(30),
            verify_auth: false,
        });
        let object_id = ObjectId::new_for_test(23);
        decoder
            .set_object_params(ObjectParams::new(object_id, 8, 8, 1, 1))
            .expect("params");

        let result = decoder
            .feed(AuthenticatedSymbol::from_parts(
                Symbol::new(
                    SymbolId::new(object_id, 1, 0),
                    vec![0x33; 8],
                    SymbolKind::Source,
                ),
                crate::security::tag::AuthenticationTag::zero(),
            ))
            .expect("feed out-of-layout block");
        let expected = SymbolAcceptResult::Rejected(RejectReason::InvalidMetadata);
        let ok = result == expected;
        crate::assert_with_log!(ok, "out-of-layout sbn rejected", expected, result);

        let progress = decoder.progress();
        crate::assert_with_log!(
            progress.symbols_received == 0,
            "rejected out-of-layout block must not advance buffered symbol count",
            0,
            progress.symbols_received
        );
        crate::assert_with_log!(
            decoder.block_status(1).is_none(),
            "rejected out-of-layout block must not create block state",
            true,
            decoder.block_status(1).is_some()
        );

        crate::test_complete!("reject_invalid_metadata_out_of_layout_sbn_without_buffering");
    }

    #[test]
    fn duplicate_symbol_before_decode() {
        init_test("duplicate_symbol_before_decode");
        let config = encoding_config();
        let mut encoder = EncodingPipeline::new(config.clone(), pool());
        let object_id = ObjectId::new_for_test(30);
        // Ensure K > 1 so the first symbol cannot complete the block decode.
        let data = vec![9u8; 512];

        let symbol = encoder
            .encode_with_repair(object_id, &data, 0)
            .next()
            .expect("symbol")
            .expect("encode")
            .into_symbol();

        let mut decoder = decoder_with_params(&config, object_id, data.len(), 1.5, 1);

        let first = decoder
            .feed(AuthenticatedSymbol::from_parts(
                symbol.clone(),
                crate::security::tag::AuthenticationTag::zero(),
            ))
            .expect("feed");
        let accepted = matches!(
            first,
            SymbolAcceptResult::Accepted { .. } | SymbolAcceptResult::DecodingStarted { .. }
        );
        crate::assert_with_log!(accepted, "first accepted", true, accepted);

        let second = decoder
            .feed(AuthenticatedSymbol::from_parts(
                symbol,
                crate::security::tag::AuthenticationTag::zero(),
            ))
            .expect("feed");
        let expected = SymbolAcceptResult::Duplicate;
        let ok = second == expected;
        crate::assert_with_log!(ok, "second duplicate", expected, second);
        crate::test_complete!("duplicate_symbol_before_decode");
    }

    #[test]
    fn into_data_reports_insufficient_symbols() {
        init_test("into_data_reports_insufficient_symbols");
        let config = encoding_config();
        let mut encoder = EncodingPipeline::new(config.clone(), pool());
        let object_id = ObjectId::new_for_test(40);
        let data = vec![5u8; 512];

        let mut decoder =
            decoder_with_params(&config, object_id, data.len(), config.repair_overhead, 0);

        let symbol = encoder
            .encode_with_repair(object_id, &data, 0)
            .next()
            .expect("symbol")
            .expect("encode")
            .into_symbol();
        let auth = AuthenticatedSymbol::from_parts(
            symbol,
            crate::security::tag::AuthenticationTag::zero(),
        );
        let _ = decoder.feed(auth).expect("feed");

        let err = decoder
            .into_data()
            .expect_err("expected insufficient symbols");
        let insufficient = matches!(err, DecodingError::InsufficientSymbols { .. });
        crate::assert_with_log!(insufficient, "insufficient symbols", true, insufficient);
        crate::test_complete!("into_data_reports_insufficient_symbols");
    }

    // ---- DecodingError Display ----

    #[test]
    fn decoding_error_display_authentication_failed() {
        let err = DecodingError::AuthenticationFailed {
            symbol_id: SymbolId::new(ObjectId::new_for_test(1), 0, 0),
        };
        let msg = err.to_string();
        assert!(msg.contains("authentication failed"), "{msg}");
    }

    #[test]
    fn decoding_error_display_insufficient_symbols() {
        let err = DecodingError::InsufficientSymbols {
            received: 3,
            needed: 10,
        };
        assert_eq!(err.to_string(), "insufficient symbols: have 3, need 10");
    }

    #[test]
    fn decoding_error_display_matrix_inversion() {
        let err = DecodingError::MatrixInversionFailed {
            reason: "rank deficient".into(),
        };
        assert_eq!(err.to_string(), "matrix inversion failed: rank deficient");
    }

    #[test]
    fn decoding_error_display_block_timeout() {
        let err = DecodingError::BlockTimeout {
            sbn: 2,
            elapsed: Duration::from_millis(1500),
        };
        let msg = err.to_string();
        assert!(msg.contains("block timeout"), "{msg}");
        assert!(msg.contains("1.5"), "{msg}");
    }

    #[test]
    fn decoding_error_display_inconsistent_metadata() {
        let err = DecodingError::InconsistentMetadata {
            sbn: 0,
            details: "mismatch".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("inconsistent block metadata"), "{msg}");
        assert!(msg.contains("mismatch"), "{msg}");
    }

    #[test]
    fn decoding_error_display_symbol_size_mismatch() {
        let err = DecodingError::SymbolSizeMismatch {
            expected: 256,
            actual: 128,
        };
        assert_eq!(
            err.to_string(),
            "symbol size mismatch: expected 256, got 128"
        );
    }

    // ---- DecodingError -> Error conversion ----

    #[test]
    fn decoding_error_into_error_auth() {
        let err = DecodingError::AuthenticationFailed {
            symbol_id: SymbolId::new(ObjectId::new_for_test(1), 0, 0),
        };
        let error: crate::error::Error = err.into();
        assert_eq!(error.kind(), crate::error::ErrorKind::CorruptedSymbol);
    }

    #[test]
    fn decoding_error_into_error_insufficient() {
        let err = DecodingError::InsufficientSymbols {
            received: 1,
            needed: 5,
        };
        let error: crate::error::Error = err.into();
        assert_eq!(error.kind(), crate::error::ErrorKind::InsufficientSymbols);
    }

    #[test]
    fn decoding_error_into_error_matrix() {
        let err = DecodingError::MatrixInversionFailed {
            reason: "singular".into(),
        };
        let error: crate::error::Error = err.into();
        assert_eq!(error.kind(), crate::error::ErrorKind::DecodingFailed);
    }

    #[test]
    fn decoding_error_into_error_timeout() {
        let err = DecodingError::BlockTimeout {
            sbn: 0,
            elapsed: Duration::from_secs(30),
        };
        let error: crate::error::Error = err.into();
        assert_eq!(error.kind(), crate::error::ErrorKind::ThresholdTimeout);
    }

    #[test]
    fn decoding_error_into_error_inconsistent() {
        let err = DecodingError::InconsistentMetadata {
            sbn: 1,
            details: "x".into(),
        };
        let error: crate::error::Error = err.into();
        assert_eq!(error.kind(), crate::error::ErrorKind::DecodingFailed);
    }

    #[test]
    fn decoding_error_into_error_size_mismatch() {
        let err = DecodingError::SymbolSizeMismatch {
            expected: 256,
            actual: 64,
        };
        let error: crate::error::Error = err.into();
        assert_eq!(error.kind(), crate::error::ErrorKind::DecodingFailed);
    }

    // ---- RejectReason ----

    #[test]
    fn reject_reason_variants_are_eq() {
        assert_eq!(RejectReason::WrongObjectId, RejectReason::WrongObjectId);
        assert_ne!(
            RejectReason::AuthenticationFailed,
            RejectReason::SymbolSizeMismatch
        );
    }

    #[test]
    fn reject_reason_debug() {
        let dbg = format!("{:?}", RejectReason::BlockAlreadyDecoded);
        assert_eq!(dbg, "BlockAlreadyDecoded");
    }

    // ---- SymbolAcceptResult ----

    #[test]
    fn symbol_accept_result_accepted_eq() {
        let a = SymbolAcceptResult::Accepted {
            received: 3,
            needed: 5,
        };
        let b = SymbolAcceptResult::Accepted {
            received: 3,
            needed: 5,
        };
        assert_eq!(a, b);
    }

    #[test]
    fn symbol_accept_result_duplicate_eq() {
        assert_eq!(SymbolAcceptResult::Duplicate, SymbolAcceptResult::Duplicate);
    }

    #[test]
    fn symbol_accept_result_rejected_eq() {
        let a = SymbolAcceptResult::Rejected(RejectReason::MemoryLimitReached);
        let b = SymbolAcceptResult::Rejected(RejectReason::MemoryLimitReached);
        assert_eq!(a, b);
    }

    #[test]
    fn symbol_accept_result_variants_ne() {
        assert_ne!(
            SymbolAcceptResult::Duplicate,
            SymbolAcceptResult::Rejected(RejectReason::WrongObjectId)
        );
    }

    // ---- DecodingConfig default ----

    #[test]
    fn decoding_config_default_values() {
        let cfg = DecodingConfig::default();
        assert_eq!(cfg.symbol_size, 256);
        assert_eq!(cfg.max_block_size, 1024 * 1024);
        assert!((cfg.repair_overhead - 1.05).abs() < f64::EPSILON);
        assert_eq!(cfg.min_overhead, 0);
        assert_eq!(cfg.max_buffered_symbols, 8192);
        assert_eq!(cfg.block_timeout, Duration::from_secs(30));
        assert!(cfg.verify_auth);
    }

    #[test]
    fn required_symbols_uses_total_factor_and_minimum_extra_floor() {
        assert_eq!(required_symbols(0, 1.05, 3), 0);
        assert_eq!(required_symbols(10, 1.05, 3), 13);
        assert_eq!(required_symbols(10, 1.5, 1), 15);
        assert_eq!(required_symbols(10, 0.5, 0), 10);
        assert_eq!(required_symbols(10, f64::NAN, 3), 13);
        assert_eq!(required_symbols(10, f64::INFINITY, 3), usize::MAX);
    }

    // ---- BlockStateKind ----

    #[test]
    fn block_state_kind_eq_and_debug() {
        assert_eq!(BlockStateKind::Collecting, BlockStateKind::Collecting);
        assert_ne!(BlockStateKind::Collecting, BlockStateKind::Decoded);
        assert_eq!(format!("{:?}", BlockStateKind::Failed), "Failed");
        assert_eq!(format!("{:?}", BlockStateKind::Decoding), "Decoding");
    }

    // ---- DecodingPipeline construction ----

    #[test]
    fn pipeline_new_starts_empty() {
        let pipeline = DecodingPipeline::new(DecodingConfig::default());
        let progress = pipeline.progress();
        assert_eq!(progress.blocks_complete, 0);
        assert_eq!(progress.symbols_received, 0);
    }

    #[test]
    fn pipeline_set_object_params_rejects_mismatched_symbol_size() {
        let mut pipeline = DecodingPipeline::new(DecodingConfig {
            symbol_size: 256,
            ..DecodingConfig::without_auth()
        });
        let params = ObjectParams::new(ObjectId::new_for_test(1), 1024, 128, 1, 8);
        let err = pipeline.set_object_params(params).unwrap_err();
        assert!(matches!(err, DecodingError::SymbolSizeMismatch { .. }));
    }

    #[test]
    fn pipeline_set_object_params_rejects_inconsistent_object_id() {
        let config = encoding_config();
        let oid1 = ObjectId::new_for_test(1);
        let oid2 = ObjectId::new_for_test(2);

        let mut pipeline = DecodingPipeline::new(DecodingConfig {
            symbol_size: config.symbol_size,
            ..DecodingConfig::without_auth()
        });
        pipeline
            .set_object_params(ObjectParams::new(oid1, 512, config.symbol_size, 1, 2))
            .expect("first set_object_params");
        let err = pipeline
            .set_object_params(ObjectParams::new(oid2, 512, config.symbol_size, 1, 2))
            .unwrap_err();
        assert!(matches!(err, DecodingError::InconsistentMetadata { .. }));
    }

    #[test]
    fn pipeline_set_object_params_same_id_is_ok() {
        let config = encoding_config();
        let oid = ObjectId::new_for_test(1);

        let mut pipeline = DecodingPipeline::new(DecodingConfig {
            symbol_size: config.symbol_size,
            ..DecodingConfig::without_auth()
        });
        pipeline
            .set_object_params(ObjectParams::new(oid, 512, config.symbol_size, 1, 2))
            .expect("first");
        pipeline
            .set_object_params(ObjectParams::new(oid, 512, config.symbol_size, 1, 2))
            .expect("second with same id should succeed");
    }

    #[test]
    fn pipeline_set_object_params_rejects_k_above_rfc_systematic_max() {
        // br-asupersync-qokghh: a misconfigured DecodingConfig (here:
        // symbol_size=1 with default max_block_size=1MB) drives K above
        // the RFC 6330 systematic-index table maximum (56,403). Without
        // the validation guard, decode_block would later panic via
        // SystematicParams::for_source_block; with the guard the error
        // is surfaced as a typed InconsistentMetadata at the validation
        // boundary so callers can react instead of crashing the
        // decoder.
        let object_id = ObjectId::new_for_test(0xDE);
        let mut pipeline = DecodingPipeline::new(DecodingConfig {
            symbol_size: 1,
            max_block_size: 1024 * 1024,
            ..DecodingConfig::without_auth()
        });
        // 65_000 bytes / 1-byte-symbols = 65_000 symbols/block — exceeds
        // the RFC max of 56,403.
        let err = pipeline
            .set_object_params(ObjectParams::new(object_id, 65_000, 1, 1, 65_000))
            .unwrap_err();
        assert!(
            matches!(err, DecodingError::InconsistentMetadata { .. }),
            "expected InconsistentMetadata, got {err:?}"
        );
        assert!(
            err.to_string().contains("RFC 6330 systematic-index table"),
            "expected RFC bound message, got: {err}"
        );
    }

    #[test]
    fn pipeline_set_object_params_rejects_declared_block_count_drift() {
        let config = encoding_config();
        let object_id = ObjectId::new_for_test(104);

        let mut pipeline = DecodingPipeline::new(DecodingConfig {
            symbol_size: config.symbol_size,
            max_block_size: config.max_block_size,
            ..DecodingConfig::without_auth()
        });
        let err = pipeline
            .set_object_params(ObjectParams::new(object_id, 1536, config.symbol_size, 1, 4))
            .unwrap_err();
        assert!(matches!(err, DecodingError::InconsistentMetadata { .. }));
        assert!(
            err.to_string().contains("block count mismatch"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn pipeline_set_object_params_rejects_total_k_metadata_for_multi_block_object() {
        let config = encoding_config();
        let object_id = ObjectId::new_for_test(105);

        let mut pipeline = DecodingPipeline::new(DecodingConfig {
            symbol_size: config.symbol_size,
            max_block_size: config.max_block_size,
            ..DecodingConfig::without_auth()
        });
        let err = pipeline
            .set_object_params(ObjectParams::new(object_id, 2048, config.symbol_size, 2, 8))
            .unwrap_err();
        assert!(matches!(err, DecodingError::InconsistentMetadata { .. }));
        assert!(
            err.to_string().contains("symbols_per_block mismatch"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn pipeline_set_object_params_failure_does_not_latch_object_identity() {
        let config = encoding_config();
        let invalid_object_id = ObjectId::new_for_test(106);
        let valid_object_id = ObjectId::new_for_test(107);

        let mut pipeline = DecodingPipeline::new(DecodingConfig {
            symbol_size: config.symbol_size,
            max_block_size: config.max_block_size,
            ..DecodingConfig::without_auth()
        });
        let err = pipeline
            .set_object_params(ObjectParams::new(
                invalid_object_id,
                2048,
                config.symbol_size,
                2,
                8,
            ))
            .unwrap_err();
        assert!(matches!(err, DecodingError::InconsistentMetadata { .. }));

        pipeline
            .set_object_params(ObjectParams::new(
                valid_object_id,
                512,
                config.symbol_size,
                1,
                2,
            ))
            .expect("failed set_object_params must not poison object identity");
    }

    #[test]
    fn pipeline_set_object_params_accepts_empty_object_single_block_sentinel_metadata() {
        let config = encoding_config();
        let object_id = ObjectId::new_for_test(108);

        let mut pipeline = DecodingPipeline::new(DecodingConfig {
            symbol_size: config.symbol_size,
            max_block_size: config.max_block_size,
            ..DecodingConfig::without_auth()
        });
        pipeline
            .set_object_params(ObjectParams::new(
                object_id,
                0,
                config.symbol_size,
                1,
                config
                    .max_block_size
                    .div_ceil(usize::from(config.symbol_size))
                    .try_into()
                    .expect("sentinel block K should fit in u16"),
            ))
            .expect("empty object sentinel metadata should be accepted");

        assert!(pipeline.is_complete());
        assert_eq!(pipeline.progress().blocks_total, Some(0));
        assert_eq!(
            pipeline.into_data().expect("empty object should decode"),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn pipeline_set_object_params_accepts_full_256_block_boundary() {
        let config = crate::config::EncodingConfig {
            symbol_size: 8,
            max_block_size: 8,
            ..encoding_config()
        };
        let object_id = ObjectId::new_for_test(109);

        let mut pipeline = DecodingPipeline::new(DecodingConfig {
            symbol_size: config.symbol_size,
            max_block_size: config.max_block_size,
            ..DecodingConfig::without_auth()
        });
        pipeline
            .set_object_params(ObjectParams::new(
                object_id,
                u64::try_from(config.max_block_size * 256).expect("boundary object size fits u64"),
                config.symbol_size,
                256,
                1,
            ))
            .expect("256-block metadata boundary should be representable");

        assert_eq!(pipeline.progress().blocks_total, Some(256));
    }

    // ---- Gap tests ----

    #[test]
    fn feed_batch_returns_results_per_symbol() {
        init_test("feed_batch_returns_results_per_symbol");
        let config = encoding_config();
        let mut encoder = EncodingPipeline::new(config.clone(), pool());
        let object_id = ObjectId::new_for_test(100);
        let data = vec![0xAAu8; 768]; // 3 source symbols at 256 bytes each

        let symbols: Vec<AuthenticatedSymbol> = encoder
            .encode_with_repair(object_id, &data, 0)
            .map(|res| {
                AuthenticatedSymbol::from_parts(
                    res.unwrap().into_symbol(),
                    crate::security::tag::AuthenticationTag::zero(),
                )
            })
            .take(3)
            .collect();

        let mut decoder = decoder_with_params(&config, object_id, data.len(), 1.5, 1);

        let results = decoder.feed_batch(symbols.into_iter());
        let len = results.len();
        let expected_len = 3usize;
        crate::assert_with_log!(len == expected_len, "batch length", expected_len, len);
        for (i, r) in results.iter().enumerate() {
            let is_ok = r.is_ok();
            crate::assert_with_log!(is_ok, &format!("result[{i}] is Ok"), true, is_ok);
        }
        crate::test_complete!("feed_batch_returns_results_per_symbol");
    }

    #[test]
    fn skipped_verifications_count_only_inserted_symbols() {
        init_test("skipped_verifications_count_only_inserted_symbols");
        let config = encoding_config();
        let object_id = ObjectId::new_for_test(103);
        let mut decoder = DecodingPipeline::new(DecodingConfig {
            symbol_size: config.symbol_size,
            max_block_size: config.max_block_size,
            verify_auth: false,
            ..DecodingConfig::without_auth()
        });
        decoder
            .set_object_params(ObjectParams::new(object_id, 512, config.symbol_size, 1, 2))
            .expect("set object params");

        let wrong_object = Symbol::new(
            SymbolId::new(ObjectId::new_for_test(104), 0, 0),
            vec![0u8; usize::from(config.symbol_size)],
            SymbolKind::Source,
        );
        let result = decoder
            .feed(AuthenticatedSymbol::from_parts(
                wrong_object,
                crate::security::tag::AuthenticationTag::zero(),
            ))
            .expect("wrong-object feed should not error");
        assert_eq!(
            result,
            SymbolAcceptResult::Rejected(RejectReason::WrongObjectId)
        );
        assert_eq!(decoder.skipped_verifications(), 0);

        let valid = Symbol::new(
            SymbolId::new(object_id, 0, 0),
            vec![1u8; usize::from(config.symbol_size)],
            SymbolKind::Source,
        );
        let result = decoder
            .feed(AuthenticatedSymbol::from_parts(
                valid.clone(),
                crate::security::tag::AuthenticationTag::zero(),
            ))
            .expect("valid feed should not error");
        assert!(matches!(result, SymbolAcceptResult::Accepted { .. }));
        assert_eq!(decoder.skipped_verifications(), 1);

        let result = decoder
            .feed(AuthenticatedSymbol::from_parts(
                valid,
                crate::security::tag::AuthenticationTag::zero(),
            ))
            .expect("duplicate feed should not error");
        assert_eq!(result, SymbolAcceptResult::Duplicate);
        assert_eq!(decoder.skipped_verifications(), 1);

        crate::test_complete!("skipped_verifications_count_only_inserted_symbols");
    }

    #[test]
    fn is_complete_false_without_params() {
        init_test("is_complete_false_without_params");
        let pipeline = DecodingPipeline::new(DecodingConfig::default());
        let complete = pipeline.is_complete();
        crate::assert_with_log!(!complete, "is_complete without params", false, complete);
        crate::test_complete!("is_complete_false_without_params");
    }

    #[test]
    fn is_complete_true_after_all_blocks_decoded() {
        init_test("is_complete_true_after_all_blocks_decoded");
        let config = encoding_config();
        let mut encoder = EncodingPipeline::new(config.clone(), pool());
        let object_id = ObjectId::new_for_test(101);
        let data = vec![42u8; 512];
        let symbols: Vec<Symbol> = encoder
            .encode_with_repair(object_id, &data, 0)
            .map(|res| res.unwrap().into_symbol())
            .collect();

        let mut decoder = decoder_with_params(&config, object_id, data.len(), 1.0, 0);

        for symbol in symbols {
            let auth = AuthenticatedSymbol::from_parts(
                symbol,
                crate::security::tag::AuthenticationTag::zero(),
            );
            let _ = decoder.feed(auth).unwrap();
        }

        let complete = decoder.is_complete();
        crate::assert_with_log!(complete, "is_complete after all blocks", true, complete);
        crate::test_complete!("is_complete_true_after_all_blocks_decoded");
    }

    #[test]
    fn progress_reports_blocks_total_after_params() {
        init_test("progress_reports_blocks_total_after_params");
        let config = encoding_config();
        let object_id = ObjectId::new_for_test(102);

        let mut pipeline = DecodingPipeline::new(DecodingConfig {
            symbol_size: config.symbol_size,
            max_block_size: 1024,
            ..DecodingConfig::without_auth()
        });
        // data_len=512 < max_block_size=1024 => 1 block
        let k = (512usize).div_ceil(usize::from(config.symbol_size)) as u16;
        pipeline
            .set_object_params(ObjectParams::new(object_id, 512, config.symbol_size, 1, k))
            .expect("set params");

        let progress = pipeline.progress();
        let blocks_total = progress.blocks_total;
        let expected_blocks = Some(1usize);
        crate::assert_with_log!(
            blocks_total == expected_blocks,
            "blocks_total",
            expected_blocks,
            blocks_total
        );
        let estimate = progress.symbols_needed_estimate;
        let positive = estimate > 0;
        crate::assert_with_log!(positive, "symbols_needed_estimate > 0", true, positive);
        crate::test_complete!("progress_reports_blocks_total_after_params");
    }

    #[test]
    fn progress_symbols_needed_estimate_does_not_double_count_min_overhead() {
        init_test("progress_symbols_needed_estimate_does_not_double_count_min_overhead");
        let object_id = ObjectId::new_for_test(1020);
        let symbol_size = 256u16;
        let k = 10u16;
        let data_len = usize::from(symbol_size) * usize::from(k);

        let mut pipeline = DecodingPipeline::new(DecodingConfig {
            symbol_size,
            max_block_size: 4096,
            repair_overhead: 1.05,
            min_overhead: 3,
            max_buffered_symbols: 8192,
            block_timeout: Duration::from_secs(30),
            verify_auth: false,
        });
        pipeline
            .set_object_params(ObjectParams::new(
                object_id,
                data_len as u64,
                symbol_size,
                1,
                k,
            ))
            .expect("set params");

        let progress = pipeline.progress();
        assert_eq!(progress.blocks_total, Some(1));
        assert_eq!(progress.symbols_needed_estimate, 13);
        crate::test_complete!(
            "progress_symbols_needed_estimate_does_not_double_count_min_overhead"
        );
    }

    #[test]
    fn progress_symbols_needed_estimate_saturates_for_infinite_overhead() {
        init_test("progress_symbols_needed_estimate_saturates_for_infinite_overhead");
        let object_id = ObjectId::new_for_test(1021);
        let symbol_size = 256u16;
        let data_len = 2048usize;

        let mut pipeline = DecodingPipeline::new(DecodingConfig {
            symbol_size,
            max_block_size: 1024,
            repair_overhead: f64::INFINITY,
            min_overhead: 0,
            max_buffered_symbols: 8192,
            block_timeout: Duration::from_secs(30),
            verify_auth: false,
        });
        pipeline
            .set_object_params(ObjectParams::new(
                object_id,
                data_len as u64,
                symbol_size,
                2,
                4,
            ))
            .expect("set params");

        let progress = pipeline.progress();
        assert_eq!(progress.blocks_total, Some(2));
        assert_eq!(progress.symbols_needed_estimate, usize::MAX);
        crate::test_complete!("progress_symbols_needed_estimate_saturates_for_infinite_overhead");
    }

    #[test]
    fn block_status_none_for_unknown_block() {
        init_test("block_status_none_for_unknown_block");
        let config = encoding_config();
        let object_id = ObjectId::new_for_test(103);

        let mut pipeline = DecodingPipeline::new(DecodingConfig {
            symbol_size: config.symbol_size,
            max_block_size: config.max_block_size,
            ..DecodingConfig::without_auth()
        });
        let k = (512usize).div_ceil(usize::from(config.symbol_size)) as u16;
        pipeline
            .set_object_params(ObjectParams::new(object_id, 512, config.symbol_size, 1, k))
            .expect("set params");

        let status = pipeline.block_status(99);
        let is_none = status.is_none();
        crate::assert_with_log!(is_none, "block_status(99) is None", true, is_none);
        crate::test_complete!("block_status_none_for_unknown_block");
    }

    #[test]
    fn block_status_collecting_after_partial_feed() {
        init_test("block_status_collecting_after_partial_feed");
        let config = encoding_config();
        let mut encoder = EncodingPipeline::new(config.clone(), pool());
        let object_id = ObjectId::new_for_test(104);
        let data = vec![0xBBu8; 512];

        let first_symbol = encoder
            .encode_with_repair(object_id, &data, 0)
            .next()
            .expect("symbol")
            .expect("encode")
            .into_symbol();

        // Use high overhead so 1 symbol doesn't trigger decode
        let mut decoder = decoder_with_params(&config, object_id, data.len(), 1.5, 1);

        let auth = AuthenticatedSymbol::from_parts(
            first_symbol,
            crate::security::tag::AuthenticationTag::zero(),
        );
        let _ = decoder.feed(auth).expect("feed");

        let status = decoder.block_status(0);
        let is_some = status.is_some();
        crate::assert_with_log!(is_some, "block_status(0) is Some", true, is_some);

        let status = status.unwrap();
        let state = status.state;
        let expected_state = BlockStateKind::Collecting;
        crate::assert_with_log!(
            state == expected_state,
            "state is Collecting",
            expected_state,
            state
        );
        let received = status.symbols_received;
        let expected_received = 1usize;
        crate::assert_with_log!(
            received == expected_received,
            "symbols_received",
            expected_received,
            received
        );
        let rank_is_available = status.rank.is_some();
        crate::assert_with_log!(rank_is_available, "rank available", true, rank_is_available);
        let rank_deficit_positive = status.rank_deficit.is_some_and(|deficit| deficit > 0);
        crate::assert_with_log!(
            rank_deficit_positive,
            "rank_deficit positive",
            true,
            rank_deficit_positive
        );
        crate::test_complete!("block_status_collecting_after_partial_feed");
    }

    #[test]
    fn block_status_decoded_after_complete() {
        init_test("block_status_decoded_after_complete");
        let config = encoding_config();
        let mut encoder = EncodingPipeline::new(config.clone(), pool());
        let object_id = ObjectId::new_for_test(105);
        let data = vec![42u8; 512];
        let symbols: Vec<Symbol> = encoder
            .encode_with_repair(object_id, &data, 0)
            .map(|res| res.unwrap().into_symbol())
            .collect();

        let mut decoder = decoder_with_params(&config, object_id, data.len(), 1.0, 0);

        for symbol in symbols {
            let auth = AuthenticatedSymbol::from_parts(
                symbol,
                crate::security::tag::AuthenticationTag::zero(),
            );
            let _ = decoder.feed(auth).unwrap();
        }

        // Block 0 should now be decoded; symbols are cleared but block state persists.
        // After decode, symbols are cleared so block_progress returns None.
        // The completed_blocks set tracks completion separately.
        let _status = decoder.block_status(0);
        let complete = decoder.is_complete();
        crate::assert_with_log!(complete, "is_complete", true, complete);

        // Verify via completed_blocks indirectly: feeding another sbn=0 symbol
        // should give BlockAlreadyDecoded
        let extra = Symbol::new(
            SymbolId::new(object_id, 0, 99),
            vec![0u8; usize::from(config.symbol_size)],
            SymbolKind::Source,
        );
        let auth =
            AuthenticatedSymbol::from_parts(extra, crate::security::tag::AuthenticationTag::zero());
        let result = decoder.feed(auth).expect("feed");
        let expected = SymbolAcceptResult::Rejected(RejectReason::BlockAlreadyDecoded);
        let ok = result == expected;
        crate::assert_with_log!(ok, "block already decoded", expected, result);
        crate::test_complete!("block_status_decoded_after_complete");
    }

    #[test]
    fn streaming_source_complete_block_returns_data_without_retaining_copy() {
        init_test("streaming_source_complete_block_returns_data_without_retaining_copy");
        let config = encoding_config();
        let mut encoder = EncodingPipeline::new(config.clone(), pool());
        let object_id = ObjectId::new_for_test(205);
        let data = (0..700).map(|i| (i % 251) as u8).collect::<Vec<_>>();
        let symbols = encoder
            .encode_with_repair(object_id, &data, 0)
            .map(|res| res.expect("source symbol").into_symbol())
            .collect::<Vec<_>>();

        let mut decoder = decoder_with_params(&config, object_id, data.len(), 1.0, 0);
        let mut completed = None;
        let mut deferred_jobs = 0usize;
        for symbol in symbols {
            let auth = AuthenticatedSymbol::from_parts(
                symbol,
                crate::security::tag::AuthenticationTag::zero(),
            );
            match decoder
                .feed_streaming_block_deferred(auth)
                .expect("feed streaming source")
            {
                DeferredSymbolAcceptResult::Immediate(SymbolAcceptResult::BlockComplete {
                    ..
                }) => {
                    panic!("source-complete deferred feed must return a decode job");
                }
                DeferredSymbolAcceptResult::Immediate(_) => {}
                DeferredSymbolAcceptResult::Decode(job) => {
                    deferred_jobs = deferred_jobs.saturating_add(1);
                    let result = decoder.finish_decode_job(run_block_decode_job(job));
                    if let SymbolAcceptResult::BlockComplete { data, .. } = result {
                        completed = Some(data);
                    }
                }
            }
        }

        crate::assert_with_log!(
            deferred_jobs == 1,
            "source-complete deferred feed queues one blocking job",
            1,
            deferred_jobs
        );
        let decoded = completed.expect("source-complete block");
        crate::assert_with_log!(decoded == data, "decoded source block", data, decoded);
        let complete = decoder.is_complete();
        crate::assert_with_log!(complete, "decoder complete", true, complete);
        let retained = decoder
            .blocks
            .get(&0)
            .and_then(|block| block.decoded.as_ref());
        crate::assert_with_log!(
            retained.is_none(),
            "streaming decode should not retain block copy",
            true,
            retained.is_none()
        );
        crate::test_complete!(
            "streaming_source_complete_block_returns_data_without_retaining_copy"
        );
    }

    #[test]
    fn block_already_decoded_reject() {
        init_test("block_already_decoded_reject");
        let config = encoding_config();
        let mut encoder = EncodingPipeline::new(config.clone(), pool());
        let object_id = ObjectId::new_for_test(106);
        let data = vec![42u8; 512];
        let symbols: Vec<Symbol> = encoder
            .encode_with_repair(object_id, &data, 0)
            .map(|res| res.unwrap().into_symbol())
            .collect();

        let mut decoder = decoder_with_params(&config, object_id, data.len(), 1.0, 0);

        for symbol in symbols {
            let auth = AuthenticatedSymbol::from_parts(
                symbol,
                crate::security::tag::AuthenticationTag::zero(),
            );
            let _ = decoder.feed(auth).unwrap();
        }

        // Feed one more symbol for sbn=0
        let extra = Symbol::new(
            SymbolId::new(object_id, 0, 0),
            vec![0u8; usize::from(config.symbol_size)],
            SymbolKind::Source,
        );
        let auth =
            AuthenticatedSymbol::from_parts(extra, crate::security::tag::AuthenticationTag::zero());
        let result = decoder.feed(auth).expect("feed");
        let expected = SymbolAcceptResult::Rejected(RejectReason::BlockAlreadyDecoded);
        let ok = result == expected;
        crate::assert_with_log!(ok, "block already decoded reject", expected, result);
        crate::test_complete!("block_already_decoded_reject");
    }

    #[test]
    fn verify_auth_no_context_unverified_symbol_errors() {
        init_test("verify_auth_no_context_unverified_symbol_errors");
        let config = encoding_config();
        let mut decoder = DecodingPipeline::new(DecodingConfig {
            symbol_size: config.symbol_size,
            max_block_size: config.max_block_size,
            verify_auth: true,
            ..DecodingConfig::without_auth()
        });

        let symbol = Symbol::new(
            SymbolId::new(ObjectId::new_for_test(107), 0, 0),
            vec![0u8; usize::from(config.symbol_size)],
            SymbolKind::Source,
        );
        // from_parts creates an unverified symbol
        let auth = AuthenticatedSymbol::from_parts(
            symbol,
            crate::security::tag::AuthenticationTag::zero(),
        );

        let result = decoder.feed(auth);
        let is_ok = result.is_ok();
        crate::assert_with_log!(
            is_ok,
            "unverified with no context is rejected safely",
            true,
            is_ok
        );

        let accept = result.unwrap();
        let expected = SymbolAcceptResult::Rejected(RejectReason::AuthenticationFailed);
        crate::assert_with_log!(
            accept == expected,
            "rejected as auth failed",
            expected,
            accept
        );
        crate::test_complete!("verify_auth_no_context_unverified_symbol_errors");
    }

    #[test]
    fn verify_auth_no_context_preverified_symbol_rejected() {
        init_test("verify_auth_no_context_preverified_symbol_rejected");
        let config = encoding_config();
        let mut decoder = DecodingPipeline::new(DecodingConfig {
            symbol_size: config.symbol_size,
            max_block_size: config.max_block_size,
            verify_auth: true,
            ..DecodingConfig::without_auth()
        });

        let symbol = Symbol::new(
            SymbolId::new(ObjectId::new_for_test(108), 0, 0),
            vec![0u8; usize::from(config.symbol_size)],
            SymbolKind::Source,
        );
        let auth = crate::security::SecurityContext::for_testing(108).sign_symbol(&symbol);

        let result = decoder.feed(auth);
        let is_ok = result.is_ok();
        crate::assert_with_log!(is_ok, "preverified symbol rejected safely", true, is_ok);
        let accept = result.unwrap();
        let expected = SymbolAcceptResult::Rejected(RejectReason::AuthenticationFailed);
        crate::assert_with_log!(
            accept == expected,
            "result is auth rejection without verifier context",
            expected,
            accept
        );
        crate::test_complete!("verify_auth_no_context_preverified_symbol_rejected");
    }

    #[test]
    fn with_auth_rejects_bad_tag() {
        init_test("with_auth_rejects_bad_tag");
        let config = encoding_config();
        let mut decoder = DecodingPipeline::with_auth(
            DecodingConfig {
                symbol_size: config.symbol_size,
                max_block_size: config.max_block_size,
                verify_auth: true,
                ..DecodingConfig::without_auth()
            },
            crate::security::SecurityContext::for_testing(42),
        );

        let symbol = Symbol::new(
            SymbolId::new(ObjectId::new_for_test(109), 0, 0),
            vec![0u8; usize::from(config.symbol_size)],
            SymbolKind::Source,
        );
        // zero tag is wrong for any real key
        let auth = AuthenticatedSymbol::from_parts(
            symbol,
            crate::security::tag::AuthenticationTag::zero(),
        );

        let result = decoder.feed(auth).expect("feed should not return Err");
        let expected = SymbolAcceptResult::Rejected(RejectReason::AuthenticationFailed);
        let ok = result == expected;
        crate::assert_with_log!(ok, "bad tag rejected", expected, result);
        crate::test_complete!("with_auth_rejects_bad_tag");
    }

    #[test]
    fn source_first_with_auth_verifies_hmac_before_fast_path_completion() {
        init_test("source_first_with_auth_verifies_hmac_before_fast_path_completion");
        let config = encoding_config();
        let mut encoder = EncodingPipeline::new(config.clone(), pool());
        let object_id = ObjectId::new_for_test(111);
        let data = (0..700).map(|i| (i % 251) as u8).collect::<Vec<_>>();
        let security = crate::security::SecurityContext::for_testing(111);
        let mut decoder = DecodingPipeline::with_auth(
            DecodingConfig {
                symbol_size: config.symbol_size,
                max_block_size: config.max_block_size,
                repair_overhead: 1.0,
                min_overhead: 0,
                max_buffered_symbols: 8192,
                block_timeout: Duration::from_secs(30),
                verify_auth: true,
            },
            security.clone(),
        );
        decoder
            .set_object_params(ObjectParams::new(
                object_id,
                data.len() as u64,
                config.symbol_size,
                1,
                data.len().div_ceil(usize::from(config.symbol_size)) as u16,
            ))
            .expect("params");

        let source_symbols = encoder
            .encode_with_repair(object_id, &data, 0)
            .map(|res| res.expect("encode source").into_symbol())
            .collect::<Vec<_>>();

        let mut completed = None;
        for symbol in source_symbols {
            let signed = security.sign_symbol(&symbol);
            let tag = *signed.tag();
            if let SymbolAcceptResult::BlockComplete { data, .. } = decoder
                .feed(AuthenticatedSymbol::from_parts(signed.into_symbol(), tag))
                .expect("feed signed source")
            {
                completed = Some(data);
            }
        }

        assert_eq!(completed.expect("source-first completion"), data);
        assert!(decoder.is_complete());
        assert_eq!(decoder.skipped_verifications(), 0);
        crate::test_complete!("source_first_with_auth_verifies_hmac_before_fast_path_completion");
    }

    #[test]
    fn source_first_with_auth_rejects_permissive_hmac_mismatch() {
        init_test("source_first_with_auth_rejects_permissive_hmac_mismatch");
        let config = encoding_config();
        let object_id = ObjectId::new_for_test(112);
        let signer = crate::security::SecurityContext::for_testing(112);
        let verifier = crate::security::SecurityContext::for_testing_with_mode(
            113,
            crate::security::AuthMode::Permissive,
        );
        let mut decoder = DecodingPipeline::with_auth(
            DecodingConfig {
                symbol_size: config.symbol_size,
                max_block_size: config.max_block_size,
                repair_overhead: 1.0,
                min_overhead: 0,
                max_buffered_symbols: 8192,
                block_timeout: Duration::from_secs(30),
                verify_auth: true,
            },
            verifier,
        );
        decoder
            .set_object_params(ObjectParams::new(object_id, 512, config.symbol_size, 1, 2))
            .expect("params");

        let symbol = Symbol::new(
            SymbolId::new(object_id, 0, 0),
            vec![7u8; usize::from(config.symbol_size)],
            SymbolKind::Source,
        );
        let signed = signer.sign_symbol(&symbol);
        let tag = *signed.tag();
        let result = decoder
            .feed(AuthenticatedSymbol::from_parts(signed.into_symbol(), tag))
            .expect("feed mismatched signed source");

        assert_eq!(
            result,
            SymbolAcceptResult::Rejected(RejectReason::AuthenticationFailed)
        );
        assert!(!decoder.is_complete());
        assert_eq!(decoder.progress().symbols_received, 0);
        crate::test_complete!("source_first_with_auth_rejects_permissive_hmac_mismatch");
    }

    /// br-asupersync-b1fojq: the default decode configuration MUST be
    /// fail-closed (`verify_auth = true`). This test locks the secure default
    /// in place so a future change cannot silently reintroduce the fail-open
    /// posture, and verifies the explicit opt-out
    /// [`DecodingConfig::without_auth`] differs from the default ONLY in
    /// `verify_auth`.
    #[test]
    fn default_config_is_fail_closed() {
        init_test("default_config_is_fail_closed");
        let secure = DecodingConfig::default();
        crate::assert_with_log!(
            secure.verify_auth,
            "DecodingConfig::default() is fail-closed (verify_auth=true)",
            true,
            secure.verify_auth
        );

        let insecure = DecodingConfig::without_auth();
        crate::assert_with_log!(
            !insecure.verify_auth,
            "DecodingConfig::without_auth() opts out (verify_auth=false)",
            false,
            insecure.verify_auth
        );

        let fields_match = insecure.symbol_size == secure.symbol_size
            && insecure.max_block_size == secure.max_block_size
            && insecure.repair_overhead.to_bits() == secure.repair_overhead.to_bits()
            && insecure.min_overhead == secure.min_overhead
            && insecure.max_buffered_symbols == secure.max_buffered_symbols
            && insecure.block_timeout == secure.block_timeout;
        crate::assert_with_log!(
            fields_match,
            "without_auth differs from default only in verify_auth",
            true,
            fields_match
        );
        crate::test_complete!("default_config_is_fail_closed");
    }

    /// br-asupersync-b1fojq: end-to-end proof that a pipeline built from the
    /// default config (no [`SecurityContext`] installed) REJECTS an
    /// unauthenticated symbol instead of silently accepting it. Pre-fix the
    /// default was `verify_auth = false`, so this exact symbol would have been
    /// accepted (decode-matrix poisoning).
    #[test]
    fn default_config_pipeline_rejects_unauthenticated_symbol() {
        init_test("default_config_pipeline_rejects_unauthenticated_symbol");
        let mut decoder = DecodingPipeline::new(DecodingConfig::default());
        let symbol = Symbol::new(
            SymbolId::new(ObjectId::new_for_test(201), 0, 0),
            vec![0u8; usize::from(DecodingConfig::default().symbol_size)],
            SymbolKind::Source,
        );
        let auth = AuthenticatedSymbol::from_parts(
            symbol,
            crate::security::tag::AuthenticationTag::zero(),
        );
        let result = decoder.feed(auth).expect("feed should not return Err");
        let expected = SymbolAcceptResult::Rejected(RejectReason::AuthenticationFailed);
        let ok = result == expected;
        crate::assert_with_log!(
            ok,
            "default-config pipeline rejects unauthenticated symbol",
            expected,
            result
        );
        crate::test_complete!("default_config_pipeline_rejects_unauthenticated_symbol");
    }

    #[test]
    fn multi_block_roundtrip() {
        init_test("multi_block_roundtrip");
        let config = crate::config::EncodingConfig {
            symbol_size: 256,
            max_block_size: 1024,
            repair_overhead: 1.05,
            encoding_parallelism: 1,
            decoding_parallelism: 1,
        };
        let mut encoder = EncodingPipeline::new(config.clone(), pool());
        let object_id = ObjectId::new_for_test(110);
        let data: Vec<u8> = (0u32..2048).map(|i| (i % 251) as u8).collect();

        let symbols: Vec<Symbol> = encoder
            .encode_with_repair(object_id, &data, 0)
            .map(|res| res.unwrap().into_symbol())
            .collect();

        let mut decoder = DecodingPipeline::new(DecodingConfig {
            symbol_size: config.symbol_size,
            max_block_size: config.max_block_size,
            repair_overhead: 1.0,
            min_overhead: 0,
            max_buffered_symbols: 8192,
            block_timeout: Duration::from_secs(30),
            verify_auth: false,
        });

        // Compute block plan matching what the encoder does
        let symbol_size = usize::from(config.symbol_size);
        let num_blocks = data.len().div_ceil(config.max_block_size);
        let mut full_block_k: u16 = 0;
        for b in 0..num_blocks {
            let block_start = b * config.max_block_size;
            let block_len = usize::min(config.max_block_size, data.len() - block_start);
            let k = block_len.div_ceil(symbol_size) as u16;
            full_block_k = full_block_k.max(k);
        }
        decoder
            .set_object_params(ObjectParams::new(
                object_id,
                data.len() as u64,
                config.symbol_size,
                num_blocks as u16,
                full_block_k,
            ))
            .expect("set params");

        for symbol in symbols {
            let auth = AuthenticatedSymbol::from_parts(
                symbol,
                crate::security::tag::AuthenticationTag::zero(),
            );
            let _ = decoder.feed(auth).unwrap();
        }

        let complete = decoder.is_complete();
        crate::assert_with_log!(complete, "multi-block is_complete", true, complete);

        let decoded_data = decoder.into_data().expect("decoded");
        let ok = decoded_data == data;
        crate::assert_with_log!(
            ok,
            "multi-block roundtrip data",
            data.len(),
            decoded_data.len()
        );
        crate::test_complete!("multi_block_roundtrip");
    }

    #[test]
    fn deferred_streaming_feed_finishes_via_decode_job() {
        init_test("deferred_streaming_feed_finishes_via_decode_job");
        let config = crate::config::EncodingConfig {
            symbol_size: 4,
            max_block_size: 8,
            repair_overhead: 1.0,
            encoding_parallelism: 1,
            decoding_parallelism: 1,
        };
        let object_id = ObjectId::new_for_test(113);
        let data = b"ABCDEFGH".to_vec();
        let encoder_pool = SymbolPool::new(PoolConfig {
            symbol_size: config.symbol_size,
            initial_size: 16,
            max_size: 16,
            allow_growth: false,
            growth_increment: 0,
        });
        let mut encoder = EncodingPipeline::new(config.clone(), encoder_pool);
        let mut source_zero = None;
        let mut first_repair = None;
        for encoded in encoder.encode_single_block_with_repair(object_id, 0, &data, 1) {
            let symbol = encoded.expect("encode").into_symbol();
            match symbol.kind() {
                SymbolKind::Source if symbol.esi() == 0 => source_zero = Some(symbol),
                SymbolKind::Repair if first_repair.is_none() => first_repair = Some(symbol),
                _ => {}
            }
        }

        let mut decoder = DecodingPipeline::new(DecodingConfig {
            symbol_size: config.symbol_size,
            max_block_size: config.max_block_size,
            repair_overhead: 1.0,
            min_overhead: 0,
            max_buffered_symbols: 8192,
            block_timeout: Duration::from_secs(30),
            verify_auth: false,
        });
        decoder
            .set_object_params(ObjectParams::new(
                object_id,
                data.len() as u64,
                config.symbol_size,
                1,
                2,
            ))
            .expect("set params");

        let first = decoder
            .feed_streaming_block_deferred(AuthenticatedSymbol::new_unauthenticated(
                source_zero.expect("source zero"),
            ))
            .expect("feed source");
        assert!(matches!(
            first,
            DeferredSymbolAcceptResult::Immediate(SymbolAcceptResult::Accepted { .. })
        ));

        let second = decoder
            .feed_streaming_block_deferred(AuthenticatedSymbol::new_unauthenticated(
                first_repair.expect("repair"),
            ))
            .expect("feed repair");
        let DeferredSymbolAcceptResult::Decode(job) = second else {
            panic!("second symbol should start deferred decode");
        };

        let outcome = run_block_decode_job(job);
        assert!(
            outcome.elapsed().as_nanos() > 0,
            "deferred decode jobs must record solve wall time for receiver profiling"
        );
        let result = decoder.finish_decode_job(outcome);
        match result {
            SymbolAcceptResult::BlockComplete {
                block_sbn,
                data: got,
            } => {
                assert_eq!(block_sbn, 0);
                assert_eq!(got, data);
            }
            other => panic!("deferred decode should complete block, got {other:?}"),
        }
        assert!(decoder.is_complete());
        crate::test_complete!("deferred_streaming_feed_finishes_via_decode_job");
    }

    #[test]
    fn deferred_streaming_feed_does_not_spawn_duplicate_decode_for_pending_block() {
        init_test("deferred_streaming_feed_does_not_spawn_duplicate_decode_for_pending_block");
        let config = crate::config::EncodingConfig {
            symbol_size: 4,
            max_block_size: 8,
            repair_overhead: 1.0,
            encoding_parallelism: 1,
            decoding_parallelism: 1,
        };
        let object_id = ObjectId::new_for_test(114);
        let data = b"ABCDEFGH".to_vec();
        let encoder_pool = SymbolPool::new(PoolConfig {
            symbol_size: config.symbol_size,
            initial_size: 16,
            max_size: 16,
            allow_growth: false,
            growth_increment: 0,
        });
        let mut encoder = EncodingPipeline::new(config.clone(), encoder_pool);
        let mut source_zero = None;
        let mut repairs = Vec::new();
        for encoded in encoder.encode_single_block_with_repair(object_id, 0, &data, 2) {
            let symbol = encoded.expect("encode").into_symbol();
            match symbol.kind() {
                SymbolKind::Source if symbol.esi() == 0 => source_zero = Some(symbol),
                SymbolKind::Repair => repairs.push(symbol),
                _ => {}
            }
        }
        assert!(
            repairs.len() >= 2,
            "test fixture must provide at least two repair symbols"
        );

        let mut decoder = DecodingPipeline::new(DecodingConfig {
            symbol_size: config.symbol_size,
            max_block_size: config.max_block_size,
            repair_overhead: 1.0,
            min_overhead: 0,
            max_buffered_symbols: 8192,
            block_timeout: Duration::from_secs(30),
            verify_auth: false,
        });
        decoder
            .set_object_params(ObjectParams::new(
                object_id,
                data.len() as u64,
                config.symbol_size,
                1,
                2,
            ))
            .expect("set params");

        let first = decoder
            .feed_streaming_block_deferred(AuthenticatedSymbol::new_unauthenticated(
                source_zero.expect("source zero"),
            ))
            .expect("feed source");
        assert!(matches!(
            first,
            DeferredSymbolAcceptResult::Immediate(SymbolAcceptResult::Accepted { .. })
        ));

        let started = decoder
            .feed_streaming_block_deferred(AuthenticatedSymbol::new_unauthenticated(
                repairs.remove(0),
            ))
            .expect("feed first repair");
        let DeferredSymbolAcceptResult::Decode(job) = started else {
            panic!("first repair should start deferred decode");
        };

        let duplicate = decoder
            .feed_streaming_block_deferred(AuthenticatedSymbol::new_unauthenticated(
                repairs.remove(0),
            ))
            .expect("feed second repair while decode pending");
        assert!(
            matches!(
                duplicate,
                DeferredSymbolAcceptResult::Immediate(SymbolAcceptResult::Accepted { .. })
            ),
            "extra symbols for a pending block must not spawn duplicate decode jobs: {duplicate:?}"
        );

        let outcome = run_block_decode_job(job);
        let result = decoder.finish_decode_job(outcome);
        match result {
            SymbolAcceptResult::BlockComplete {
                block_sbn,
                data: got,
            } => {
                assert_eq!(block_sbn, 0);
                assert_eq!(got, data);
            }
            other => panic!("deferred decode should complete block, got {other:?}"),
        }
        assert!(decoder.is_complete());
        crate::test_complete!(
            "deferred_streaming_feed_does_not_spawn_duplicate_decode_for_pending_block"
        );
    }

    #[test]
    fn deferred_retry_rechecks_symbols_buffered_during_pending_decode() {
        init_test("deferred_retry_rechecks_symbols_buffered_during_pending_decode");
        let config = crate::config::EncodingConfig {
            symbol_size: 4,
            max_block_size: 8,
            repair_overhead: 1.0,
            encoding_parallelism: 1,
            decoding_parallelism: 1,
        };
        let object_id = ObjectId::new_for_test(115);
        let data = b"ABCDEFGH".to_vec();
        let encoder_pool = SymbolPool::new(PoolConfig {
            symbol_size: config.symbol_size,
            initial_size: 16,
            max_size: 16,
            allow_growth: false,
            growth_increment: 0,
        });
        let mut encoder = EncodingPipeline::new(config.clone(), encoder_pool);
        let mut source_zero = None;
        let mut repairs = Vec::new();
        for encoded in encoder.encode_single_block_with_repair(object_id, 0, &data, 2) {
            let symbol = encoded.expect("encode").into_symbol();
            match symbol.kind() {
                SymbolKind::Source if symbol.esi() == 0 => source_zero = Some(symbol),
                SymbolKind::Repair => repairs.push(symbol),
                _ => {}
            }
        }
        assert!(
            repairs.len() >= 2,
            "test fixture must provide two repair symbols"
        );

        let mut decoder = DecodingPipeline::new(DecodingConfig {
            symbol_size: config.symbol_size,
            max_block_size: config.max_block_size,
            repair_overhead: 1.0,
            min_overhead: 0,
            max_buffered_symbols: 8192,
            block_timeout: Duration::from_secs(30),
            verify_auth: false,
        });
        decoder
            .set_object_params(ObjectParams::new(
                object_id,
                data.len() as u64,
                config.symbol_size,
                1,
                2,
            ))
            .expect("set params");

        let first = decoder
            .feed_streaming_block_deferred(AuthenticatedSymbol::new_unauthenticated(
                source_zero.expect("source zero"),
            ))
            .expect("feed source zero");
        assert!(matches!(
            first,
            DeferredSymbolAcceptResult::Immediate(SymbolAcceptResult::Accepted { .. })
        ));

        let started = decoder
            .feed_streaming_block_deferred(AuthenticatedSymbol::new_unauthenticated(
                repairs.remove(0),
            ))
            .expect("feed repair");
        let DeferredSymbolAcceptResult::Decode(job) = started else {
            panic!("repair should start deferred decode");
        };

        let buffered = decoder
            .feed_streaming_block_deferred(AuthenticatedSymbol::new_unauthenticated(
                repairs.remove(0),
            ))
            .expect("feed second repair while decode pending");
        assert!(
            matches!(
                buffered,
                DeferredSymbolAcceptResult::Immediate(SymbolAcceptResult::Accepted { .. })
            ),
            "new symbols accepted during a pending decode must stay buffered: {buffered:?}"
        );

        let stale_retry = BlockDecodeOutcome {
            sbn: job.sbn(),
            input_symbols: 2,
            retain_decoded_block: false,
            elapsed: Duration::ZERO,
            resolution: BlockDecodeResolution::Retry(RejectReason::InconsistentEquations),
        };
        let retry = decoder.finish_decode_job_deferred(stale_retry);
        let DeferredSymbolAcceptResult::Decode(retry_job) = retry else {
            panic!("stale deferred retry should return a fresh decode job, got {retry:?}");
        };
        assert!(
            !decoder.is_complete(),
            "deferred retry must not run the heavy decode inline"
        );

        let result = decoder.finish_decode_job(run_block_decode_job(retry_job));
        match result {
            SymbolAcceptResult::BlockComplete {
                block_sbn,
                data: got,
            } => {
                assert_eq!(block_sbn, 0);
                assert_eq!(got, data);
            }
            other => panic!("stale deferred retry should recheck buffered symbols, got {other:?}"),
        }
        assert!(decoder.is_complete());
        crate::test_complete!("deferred_retry_rechecks_symbols_buffered_during_pending_decode");
    }

    #[test]
    fn multi_block_roundtrip_respects_partial_last_block_metadata() {
        init_test("multi_block_roundtrip_respects_partial_last_block_metadata");
        let config = crate::config::EncodingConfig {
            symbol_size: 4,
            max_block_size: 6,
            repair_overhead: 1.0,
            encoding_parallelism: 1,
            decoding_parallelism: 1,
        };
        let encoder_pool = SymbolPool::new(PoolConfig {
            symbol_size: config.symbol_size,
            initial_size: 16,
            max_size: 16,
            allow_growth: false,
            growth_increment: 0,
        });
        let mut encoder = EncodingPipeline::new(config.clone(), encoder_pool);
        let object_id = ObjectId::new_for_test(112);
        let data = b"ABCDEFGHIJKLM".to_vec();

        let symbols: Vec<Symbol> = encoder
            .encode_with_repair(object_id, &data, 0)
            .map(|res| res.expect("encode").into_symbol())
            .collect();

        let mut decoder = DecodingPipeline::new(DecodingConfig {
            symbol_size: config.symbol_size,
            max_block_size: config.max_block_size,
            repair_overhead: 1.0,
            min_overhead: 0,
            max_buffered_symbols: 8192,
            block_timeout: Duration::from_secs(30),
            verify_auth: false,
        });
        decoder
            .set_object_params(ObjectParams::new(
                object_id,
                data.len() as u64,
                config.symbol_size,
                3,
                2,
            ))
            .expect("set params for uneven multi-block object");

        let expected_blocks = Some(3usize);
        let blocks_total = decoder.progress().blocks_total;
        crate::assert_with_log!(
            blocks_total == expected_blocks,
            "partial last block count",
            expected_blocks,
            blocks_total
        );

        for symbol in symbols {
            let auth = AuthenticatedSymbol::from_parts(
                symbol,
                crate::security::tag::AuthenticationTag::zero(),
            );
            let _ = decoder.feed(auth).expect("feed");
        }

        let complete = decoder.is_complete();
        crate::assert_with_log!(
            complete,
            "partial last block roundtrip is_complete",
            true,
            complete
        );

        let decoded_data = decoder.into_data().expect("decoded");
        let ok = decoded_data == data;
        crate::assert_with_log!(
            ok,
            "partial last block roundtrip data",
            data.len(),
            decoded_data.len()
        );
        crate::test_complete!("multi_block_roundtrip_respects_partial_last_block_metadata");
    }

    #[test]
    fn multi_block_progress_retains_cumulative_symbols_after_block_completion() {
        init_test("multi_block_progress_retains_cumulative_symbols_after_block_completion");
        let config = crate::config::EncodingConfig {
            symbol_size: 256,
            max_block_size: 1024,
            repair_overhead: 1.05,
            encoding_parallelism: 1,
            decoding_parallelism: 1,
        };
        let mut encoder = EncodingPipeline::new(config.clone(), pool());
        let object_id = ObjectId::new_for_test(111);
        let data: Vec<u8> = (0u32..2048).map(|i| (i % 251) as u8).collect();

        let mut block_zero_symbols: Vec<Symbol> = encoder
            .encode_with_repair(object_id, &data, 0)
            .map(|res| res.expect("encode").into_symbol())
            .filter(|symbol| symbol.sbn() == 0)
            .collect();
        block_zero_symbols.sort_by_key(Symbol::esi);
        assert_eq!(block_zero_symbols.len(), 4);

        let mut decoder = DecodingPipeline::new(DecodingConfig {
            symbol_size: config.symbol_size,
            max_block_size: config.max_block_size,
            repair_overhead: 1.0,
            min_overhead: 0,
            max_buffered_symbols: 8192,
            block_timeout: Duration::from_secs(30),
            verify_auth: false,
        });
        decoder
            .set_object_params(ObjectParams::new(
                object_id,
                data.len() as u64,
                config.symbol_size,
                2,
                4,
            ))
            .expect("set params");

        for symbol in block_zero_symbols {
            let auth = AuthenticatedSymbol::from_parts(
                symbol,
                crate::security::tag::AuthenticationTag::zero(),
            );
            let _ = decoder.feed(auth).expect("feed");
        }

        assert_eq!(decoder.progress().blocks_complete, 1);
        assert_eq!(decoder.progress().blocks_total, Some(2));
        assert_eq!(decoder.progress().symbols_received, 4);
        assert_eq!(decoder.progress().symbols_needed_estimate, 8);

        let err = decoder.into_data().expect_err("block one is still missing");
        assert!(matches!(
            err,
            DecodingError::InsufficientSymbols {
                received: 4,
                needed: 8
            }
        ));
        crate::test_complete!(
            "multi_block_progress_retains_cumulative_symbols_after_block_completion"
        );
    }

    #[test]
    fn into_data_no_params_errors() {
        init_test("into_data_no_params_errors");
        let pipeline = DecodingPipeline::new(DecodingConfig::default());
        let result = pipeline.into_data();
        let is_err = result.is_err();
        crate::assert_with_log!(is_err, "into_data without params errors", true, is_err);
        let err = result.unwrap_err();
        let msg = err.to_string();
        let contains = msg.contains("object parameters not set");
        crate::assert_with_log!(
            contains,
            "error message contains expected text",
            true,
            contains
        );
        crate::test_complete!("into_data_no_params_errors");
    }

    // --- wave 76 trait coverage ---

    #[test]
    fn reject_reason_debug_clone_copy_eq() {
        let r = RejectReason::WrongObjectId;
        let r2 = r; // Copy
        let r3 = r;
        assert_eq!(r, r2);
        assert_eq!(r, r3);
        assert_ne!(r, RejectReason::AuthenticationFailed);
        assert_ne!(r, RejectReason::SymbolSizeMismatch);
        assert_ne!(r, RejectReason::BlockAlreadyDecoded);
        assert_ne!(r, RejectReason::InsufficientRank);
        assert_ne!(r, RejectReason::InconsistentEquations);
        assert_ne!(r, RejectReason::InvalidMetadata);
        assert_ne!(r, RejectReason::MemoryLimitReached);
        let dbg = format!("{r:?}");
        assert!(dbg.contains("WrongObjectId"));
    }

    #[test]
    fn symbol_accept_result_debug_clone_eq() {
        let a = SymbolAcceptResult::Accepted {
            received: 3,
            needed: 5,
        };
        let a2 = a.clone();
        assert_eq!(a, a2);
        assert_ne!(a, SymbolAcceptResult::Duplicate);
        let r = SymbolAcceptResult::Rejected(RejectReason::InvalidMetadata);
        let r2 = r.clone();
        assert_eq!(r, r2);
        let dbg = format!("{a:?}");
        assert!(dbg.contains("Accepted"));
    }

    #[test]
    fn block_state_kind_debug_clone_copy_eq() {
        let s = BlockStateKind::Collecting;
        let s2 = s; // Copy
        let s3 = s;
        assert_eq!(s, s2);
        assert_eq!(s, s3);
        assert_ne!(s, BlockStateKind::Decoding);
        assert_ne!(s, BlockStateKind::Decoded);
        assert_ne!(s, BlockStateKind::Failed);
        let dbg = format!("{s:?}");
        assert!(dbg.contains("Collecting"));
    }
}
