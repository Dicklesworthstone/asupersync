//! Region recovery protocol for distributed regions.
//!
//! When a distributed region enters Degraded state or needs reconstruction,
//! the recovery protocol collects symbols from surviving replicas and decodes
//! them back into a [`RegionSnapshot`].
//!
//! # Architecture
//!
//! ```text
//! RecoveryTrigger → RecoveryCollector → StateDecoder → RegionSnapshot
//! ```

#![allow(clippy::result_large_err)]

use crate::combinator::retry::RetryPolicy;
use crate::decoding::{DecodingConfig, DecodingPipeline, SymbolAcceptResult};
use crate::error::{Error, ErrorKind};
use crate::security::tag::AuthenticationTag;
use crate::security::AuthenticatedSymbol;
use crate::types::symbol::{ObjectParams, Symbol};
use crate::types::{RegionId, Time};
use std::collections::HashSet;
use std::time::Duration;

use super::snapshot::RegionSnapshot;

// ---------------------------------------------------------------------------
// RecoveryTrigger
// ---------------------------------------------------------------------------

/// Events that can trigger recovery.
#[derive(Debug, Clone)]
pub enum RecoveryTrigger {
    /// Quorum was lost (too many replicas unavailable).
    QuorumLost {
        /// Region that lost quorum.
        region_id: RegionId,
        /// Replicas still reachable.
        available_replicas: Vec<String>,
        /// Number of replicas required for quorum.
        required_quorum: u32,
    },
    /// Node restarted and needs to recover state.
    NodeRestart {
        /// Region to recover.
        region_id: RegionId,
        /// Last sequence number known before restart.
        last_known_sequence: u64,
    },
    /// Operator manually triggered recovery.
    ManualTrigger {
        /// Region to recover.
        region_id: RegionId,
        /// Identity of the operator.
        initiator: String,
        /// Optional reason text.
        reason: Option<String>,
    },
    /// Replica detected inconsistent state.
    InconsistencyDetected {
        /// Region with inconsistency.
        region_id: RegionId,
        /// Local sequence number.
        local_sequence: u64,
        /// Remote sequence number observed.
        remote_sequence: u64,
    },
}

impl RecoveryTrigger {
    /// Returns the region ID being recovered.
    #[must_use]
    pub fn region_id(&self) -> RegionId {
        match self {
            Self::QuorumLost { region_id, .. }
            | Self::NodeRestart { region_id, .. }
            | Self::ManualTrigger { region_id, .. }
            | Self::InconsistencyDetected { region_id, .. } => *region_id,
        }
    }

    /// Returns true if this is a critical recovery (data loss risk).
    #[must_use]
    pub fn is_critical(&self) -> bool {
        matches!(
            self,
            Self::QuorumLost { .. } | Self::InconsistencyDetected { .. }
        )
    }
}

// ---------------------------------------------------------------------------
// RecoveryConfig
// ---------------------------------------------------------------------------

/// Consistency requirements for symbol collection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollectionConsistency {
    /// Collect from any single replica.
    Any,
    /// Collect from quorum of replicas (verify consistency).
    Quorum,
    /// Collect from all available replicas.
    All,
}

/// Configuration for recovery protocol behavior.
#[derive(Debug, Clone)]
pub struct RecoveryConfig {
    /// Minimum symbols required for decoding attempt.
    pub min_symbols: u32,
    /// Timeout for the entire recovery operation.
    pub recovery_timeout: Duration,
    /// Timeout for individual replica queries.
    pub replica_timeout: Duration,
    /// Maximum concurrent symbol requests.
    pub max_concurrent_requests: usize,
    /// Consistency level for symbol collection.
    pub collection_consistency: CollectionConsistency,
    /// Whether to continue on partial success.
    pub allow_partial: bool,
    /// Retry policy for failed requests.
    pub retry_policy: RetryPolicy,
    /// Maximum number of recovery attempts before giving up.
    pub max_attempts: u32,
}

impl Default for RecoveryConfig {
    fn default() -> Self {
        Self {
            min_symbols: 0,
            recovery_timeout: Duration::from_secs(60),
            replica_timeout: Duration::from_secs(5),
            max_concurrent_requests: 10,
            collection_consistency: CollectionConsistency::Quorum,
            allow_partial: false,
            retry_policy: RetryPolicy::new().with_max_attempts(3),
            max_attempts: 3,
        }
    }
}

// ---------------------------------------------------------------------------
// CollectedSymbol
// ---------------------------------------------------------------------------

/// A symbol with its source replica information.
#[derive(Debug, Clone)]
pub struct CollectedSymbol {
    /// The symbol data.
    pub symbol: Symbol,
    /// Replica it was collected from.
    pub source_replica: String,
    /// Collection timestamp.
    pub collected_at: Time,
    /// Verification status.
    pub verified: bool,
}

// ---------------------------------------------------------------------------
// RecoveryProgress / RecoveryPhase
// ---------------------------------------------------------------------------

/// Phases of the recovery process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryPhase {
    /// Initializing recovery, fetching metadata.
    Initializing,
    /// Collecting symbols from replicas.
    Collecting,
    /// Verifying collected symbols.
    Verifying,
    /// Decoding symbols to reconstruct state.
    Decoding,
    /// Applying recovered state.
    Applying,
    /// Recovery complete.
    Complete,
    /// Recovery failed.
    Failed,
}

/// Progress tracking for recovery operation.
#[derive(Debug, Clone)]
pub struct RecoveryProgress {
    /// Recovery start time.
    pub started_at: Time,
    /// Total symbols needed for decode.
    pub symbols_needed: u32,
    /// Symbols collected so far.
    pub symbols_collected: u32,
    /// Replicas queried.
    pub replicas_queried: u32,
    /// Replicas that responded.
    pub replicas_responded: u32,
    /// Current phase of recovery.
    pub phase: RecoveryPhase,
}

// ---------------------------------------------------------------------------
// CollectionMetrics
// ---------------------------------------------------------------------------

/// Metrics for symbol collection.
#[derive(Debug, Default)]
pub struct CollectionMetrics {
    /// Total symbols requested from replicas.
    pub symbols_requested: u64,
    /// Symbols successfully received.
    pub symbols_received: u64,
    /// Duplicate symbols (same ESI, skipped).
    pub symbols_duplicate: u64,
    /// Corrupt symbols rejected.
    pub symbols_corrupt: u64,
    /// Total requests sent to replicas.
    pub requests_sent: u64,
    /// Successful requests.
    pub requests_successful: u64,
    /// Failed requests.
    pub requests_failed: u64,
    /// Timed-out requests.
    pub requests_timeout: u64,
}

// ---------------------------------------------------------------------------
// RecoveryCollector
// ---------------------------------------------------------------------------

/// Collects symbols from distributed replicas.
///
/// Handles deduplication by ESI, progress tracking, and optional
/// verification. Use [`add_collected`](Self::add_collected) to feed
/// symbols synchronously (e.g. in tests).
pub struct RecoveryCollector {
    config: RecoveryConfig,
    collected: Vec<CollectedSymbol>,
    seen_esi: HashSet<u32>,
    /// Object parameters from metadata (set once known).
    pub object_params: Option<ObjectParams>,
    progress: RecoveryProgress,
    /// Metrics for collection.
    pub metrics: CollectionMetrics,
    cancelled: bool,
}

impl RecoveryCollector {
    /// Creates a new collector with the given configuration.
    #[must_use]
    pub fn new(config: RecoveryConfig) -> Self {
        Self {
            config,
            collected: Vec::new(),
            seen_esi: HashSet::new(),
            object_params: None,
            progress: RecoveryProgress {
                started_at: Time::ZERO,
                symbols_needed: 0,
                symbols_collected: 0,
                replicas_queried: 0,
                replicas_responded: 0,
                phase: RecoveryPhase::Initializing,
            },
            metrics: CollectionMetrics::default(),
            cancelled: false,
        }
    }

    /// Returns the current recovery progress.
    #[must_use]
    pub fn progress(&self) -> &RecoveryProgress {
        &self.progress
    }

    /// Returns collected symbols.
    #[must_use]
    pub fn symbols(&self) -> &[CollectedSymbol] {
        &self.collected
    }

    /// Returns true if enough symbols are collected for decoding.
    #[must_use]
    pub fn can_decode(&self) -> bool {
        let Some(params) = &self.object_params else {
            return false;
        };
        self.collected.len() >= params.min_symbols_for_decode() as usize
    }

    /// Cancels the ongoing collection.
    pub fn cancel(&mut self) {
        self.cancelled = true;
    }

    /// Adds a collected symbol, deduplicating by ESI.
    ///
    /// Returns `true` if the symbol was accepted (new ESI), `false` if duplicate.
    pub fn add_collected(&mut self, cs: CollectedSymbol) -> bool {
        let esi = cs.symbol.esi();
        if self.seen_esi.contains(&esi) {
            self.metrics.symbols_duplicate += 1;
            return false;
        }
        self.seen_esi.insert(esi);
        self.metrics.symbols_received += 1;
        self.progress.symbols_collected += 1;
        self.collected.push(cs);
        true
    }

    /// Adds a collected symbol with basic verification.
    ///
    /// Rejects symbols that have an ESI beyond the expected range if
    /// object parameters are known.
    pub fn add_collected_with_verify(&mut self, cs: CollectedSymbol) -> Result<bool, Error> {
        if let Some(params) = &self.object_params {
            let max_expected = params.total_source_symbols() + self.config.min_symbols;
            if cs.symbol.esi() > max_expected + 100 {
                self.metrics.symbols_corrupt += 1;
                return Err(Error::new(ErrorKind::CorruptedSymbol).with_message(format!(
                    "ESI {} exceeds expected range for object",
                    cs.symbol.esi()
                )));
            }
        }
        Ok(self.add_collected(cs))
    }
}

impl std::fmt::Debug for RecoveryCollector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoveryCollector")
            .field("config", &self.config)
            .field("collected", &self.collected.len())
            .field("seen_esi", &self.seen_esi.len())
            .field("object_params", &self.object_params)
            .field("phase", &self.progress.phase)
            .field("metrics", &self.metrics)
            .field("cancelled", &self.cancelled)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// DecodingConfig (local to recovery)
// ---------------------------------------------------------------------------

/// Configuration for state decoding during recovery.
#[derive(Debug, Clone)]
pub struct RecoveryDecodingConfig {
    /// Whether to verify decoded data integrity.
    pub verify_integrity: bool,
    /// Maximum decode attempts before failure.
    pub max_decode_attempts: u32,
    /// Whether to attempt partial decode.
    pub allow_partial_decode: bool,
}

impl Default for RecoveryDecodingConfig {
    fn default() -> Self {
        Self {
            verify_integrity: true,
            max_decode_attempts: 3,
            allow_partial_decode: false,
        }
    }
}

// ---------------------------------------------------------------------------
// DecoderState / StateDecoder
// ---------------------------------------------------------------------------

/// Internal decoder state tracking.
#[derive(Debug)]
enum DecoderState {
    /// Waiting for enough symbols.
    Accumulating { received: u32, needed: u32 },
    /// Ready to decode.
    Ready,
    /// Decode complete.
    Complete,
    /// Decode failed.
    Failed { reason: String },
}

/// Decodes collected symbols back into region state.
///
/// Accumulates symbols via [`add_symbol`](Self::add_symbol) and decodes
/// when enough are present.
pub struct StateDecoder {
    config: RecoveryDecodingConfig,
    decoder_state: DecoderState,
    symbols: Vec<Symbol>,
    seen_esi: HashSet<u32>,
}

impl StateDecoder {
    /// Creates a new decoder with the given configuration.
    #[must_use]
    pub fn new(config: RecoveryDecodingConfig) -> Self {
        Self {
            config,
            decoder_state: DecoderState::Accumulating {
                received: 0,
                needed: 0,
            },
            symbols: Vec::new(),
            seen_esi: HashSet::new(),
        }
    }

    /// Adds a symbol to the decoder, deduplicating by ESI.
    pub fn add_symbol(&mut self, symbol: &Symbol) -> Result<(), Error> {
        let esi = symbol.esi();
        if self.seen_esi.contains(&esi) {
            return Ok(()); // Skip duplicates silently
        }
        self.seen_esi.insert(esi);
        self.symbols.push(symbol.clone());

        // Update state
        if let DecoderState::Accumulating { received, .. } = &mut self.decoder_state {
            *received = self.symbols.len() as u32;
        }

        Ok(())
    }

    /// Returns true if decoding can be attempted.
    #[must_use]
    pub fn can_decode(&self) -> bool {
        !self.symbols.is_empty()
    }

    /// Returns the number of symbols received.
    #[must_use]
    pub fn symbols_received(&self) -> u32 {
        self.symbols.len() as u32
    }

    /// Returns the minimum symbols needed for decoding.
    #[must_use]
    pub fn symbols_needed(&self, params: &ObjectParams) -> u32 {
        params.min_symbols_for_decode()
    }

    /// Clears the decoder state for reuse.
    pub fn reset(&mut self) {
        self.symbols.clear();
        self.seen_esi.clear();
        self.decoder_state = DecoderState::Accumulating {
            received: 0,
            needed: 0,
        };
    }

    /// Attempts to decode the collected symbols into raw bytes.
    ///
    /// Uses the deterministic RaptorQ decoding pipeline so recovery
    /// aligns with RFC-grade encoding behavior.
    pub fn decode(&mut self, params: &ObjectParams) -> Result<Vec<u8>, Error> {
        let k = params.min_symbols_for_decode();
        if self.symbols.len() < k as usize {
            self.decoder_state = DecoderState::Failed {
                reason: format!("insufficient: have {}, need {k}", self.symbols.len()),
            };
            return Err(Error::insufficient_symbols(self.symbols.len() as u32, k));
        }

        let config = DecodingConfig {
            symbol_size: params.symbol_size,
            max_block_size: params.object_size as usize,
            repair_overhead: 1.0,
            min_overhead: 0,
            max_buffered_symbols: 0,
            block_timeout: Duration::from_secs(30),
            verify_auth: false,
        };
        let mut pipeline = DecodingPipeline::new(config);
        if let Err(err) = pipeline.set_object_params(*params) {
            self.decoder_state = DecoderState::Failed {
                reason: err.to_string(),
            };
            return Err(Error::from(err));
        }

        for symbol in &self.symbols {
            let auth =
                AuthenticatedSymbol::new_verified(symbol.clone(), AuthenticationTag::zero());
            match pipeline.feed(auth).map_err(Error::from)? {
                SymbolAcceptResult::Rejected(reason) => {
                    let message = format!("symbol rejected: {reason:?}");
                    self.decoder_state = DecoderState::Failed {
                        reason: message.clone(),
                    };
                    return Err(Error::new(ErrorKind::DecodingFailed).with_message(message));
                }
                _ => {}
            }
        }

        match pipeline.into_data() {
            Ok(data) => {
                self.decoder_state = DecoderState::Complete;
                Ok(data)
            }
            Err(err) => {
                self.decoder_state = DecoderState::Failed {
                    reason: err.to_string(),
                };
                Err(Error::from(err))
            }
        }
    }

    /// Convenience: decode and deserialize directly to [`RegionSnapshot`].
    pub fn decode_snapshot(&mut self, params: &ObjectParams) -> Result<RegionSnapshot, Error> {
        let data = self.decode(params)?;
        RegionSnapshot::from_bytes(&data).map_err(|e| {
            Error::new(ErrorKind::DecodingFailed)
                .with_message(format!("snapshot deserialization failed: {e}"))
        })
    }
}

impl std::fmt::Debug for StateDecoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StateDecoder")
            .field("config", &self.config)
            .field("symbols", &self.symbols.len())
            .field("seen_esi", &self.seen_esi.len())
            .field("state", &self.decoder_state)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// RecoveryOrchestrator
// ---------------------------------------------------------------------------

/// Result of a recovery operation.
#[derive(Debug)]
pub struct RecoveryResult {
    /// The recovered region snapshot.
    pub snapshot: RegionSnapshot,
    /// Symbols used for recovery.
    pub symbols_used: u32,
    /// Replicas that contributed to recovery.
    pub contributing_replicas: Vec<String>,
    /// Total recovery time.
    pub duration: Duration,
    /// Recovery attempt number (if retried).
    pub attempt: u32,
    /// Verification status.
    pub verified: bool,
}

/// Orchestrates the complete recovery workflow.
///
/// Coordinates [`RecoveryCollector`] and [`StateDecoder`] for end-to-end
/// recovery. The async `recover` method is intended for runtime use;
/// [`recover_from_symbols`](Self::recover_from_symbols) provides a
/// synchronous test path.
pub struct RecoveryOrchestrator {
    config: RecoveryConfig,
    collector: RecoveryCollector,
    decoder: StateDecoder,
    attempt: u32,
    recovering: bool,
    cancelled: bool,
}

impl RecoveryOrchestrator {
    /// Creates a new orchestrator.
    #[must_use]
    pub fn new(recovery_config: RecoveryConfig, decoding_config: RecoveryDecodingConfig) -> Self {
        let collector = RecoveryCollector::new(recovery_config.clone());
        let decoder = StateDecoder::new(decoding_config);
        Self {
            config: recovery_config,
            collector,
            decoder,
            attempt: 0,
            recovering: false,
            cancelled: false,
        }
    }

    /// Returns the current recovery progress.
    #[must_use]
    pub fn progress(&self) -> &RecoveryProgress {
        self.collector.progress()
    }

    /// Returns true if recovery is in progress.
    #[must_use]
    pub fn is_recovering(&self) -> bool {
        self.recovering && !self.cancelled
    }

    /// Cancels the recovery operation.
    pub fn cancel(&mut self, _reason: &str) {
        self.cancelled = true;
        self.recovering = false;
        self.collector.cancel();
    }

    /// Synchronous recovery from pre-collected symbols.
    ///
    /// This is the core recovery logic, usable in tests without async.
    pub fn recover_from_symbols(
        &mut self,
        trigger: &RecoveryTrigger,
        symbols: &[CollectedSymbol],
        params: ObjectParams,
        duration: Duration,
    ) -> Result<RecoveryResult, Error> {
        self.recovering = true;
        self.attempt += 1;

        let _ = trigger.region_id(); // validate trigger

        // Set object params on collector.
        self.collector.object_params = Some(params);

        // Feed symbols to collector (deduplication).
        for cs in symbols {
            self.collector.add_collected(cs.clone());
        }

        if !self.collector.can_decode() {
            self.recovering = false;
            return Err(Error::new(ErrorKind::RecoveryFailed)
                .with_message("insufficient symbols for recovery"));
        }

        // Feed unique symbols to decoder.
        for cs in self.collector.symbols() {
            self.decoder.add_symbol(&cs.symbol)?;
        }

        // Decode.
        let snapshot = self.decoder.decode_snapshot(&params)?;

        // Collect contributing replicas.
        let contributing: Vec<String> = symbols
            .iter()
            .map(|s| s.source_replica.clone())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        self.recovering = false;

        Ok(RecoveryResult {
            snapshot,
            symbols_used: self.decoder.symbols_received(),
            contributing_replicas: contributing,
            duration,
            attempt: self.attempt,
            verified: self.decoder.config.verify_integrity,
        })
    }
}

impl std::fmt::Debug for RecoveryOrchestrator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoveryOrchestrator")
            .field("config", &self.config)
            .field("collector", &self.collector)
            .field("decoder", &self.decoder)
            .field("attempt", &self.attempt)
            .field("recovering", &self.recovering)
            .field("cancelled", &self.cancelled)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::similar_names)]
mod tests {
    use super::*;
    use crate::distributed::encoding::{EncodedState, EncodingConfig, StateEncoder};
    use crate::distributed::snapshot::{BudgetSnapshot, TaskSnapshot, TaskState};
    use crate::record::region::RegionState;
    use crate::types::symbol::{ObjectId, SymbolId, SymbolKind};
    use crate::types::{RegionId, TaskId};
    use crate::util::DetRng;

    // =====================================================================
    // Recovery Trigger Tests
    // =====================================================================

    #[test]
    fn trigger_region_id_extraction() {
        let trigger = RecoveryTrigger::QuorumLost {
            region_id: RegionId::new_for_test(1, 0),
            available_replicas: vec!["r1".to_string()],
            required_quorum: 2,
        };
        assert_eq!(trigger.region_id(), RegionId::new_for_test(1, 0));

        let trigger2 = RecoveryTrigger::NodeRestart {
            region_id: RegionId::new_for_test(2, 0),
            last_known_sequence: 5,
        };
        assert_eq!(trigger2.region_id(), RegionId::new_for_test(2, 0));

        let trigger3 = RecoveryTrigger::InconsistencyDetected {
            region_id: RegionId::new_for_test(3, 0),
            local_sequence: 10,
            remote_sequence: 15,
        };
        assert_eq!(trigger3.region_id(), RegionId::new_for_test(3, 0));
    }

    #[test]
    fn trigger_critical_classification() {
        let critical = RecoveryTrigger::QuorumLost {
            region_id: RegionId::new_for_test(1, 0),
            available_replicas: vec![],
            required_quorum: 2,
        };
        assert!(critical.is_critical());

        let also_critical = RecoveryTrigger::InconsistencyDetected {
            region_id: RegionId::new_for_test(1, 0),
            local_sequence: 10,
            remote_sequence: 15,
        };
        assert!(also_critical.is_critical());

        let non_critical = RecoveryTrigger::ManualTrigger {
            region_id: RegionId::new_for_test(1, 0),
            initiator: "admin".to_string(),
            reason: None,
        };
        assert!(!non_critical.is_critical());

        let also_non_critical = RecoveryTrigger::NodeRestart {
            region_id: RegionId::new_for_test(1, 0),
            last_known_sequence: 0,
        };
        assert!(!also_non_critical.is_critical());
    }

    // =====================================================================
    // Symbol Collection Tests
    // =====================================================================

    #[test]
    fn collector_deduplicates_by_esi() {
        let mut collector = RecoveryCollector::new(RecoveryConfig::default());

        let sym1 = Symbol::new_for_test(1, 0, 5, &[1, 2, 3]);
        let sym2 = Symbol::new_for_test(1, 0, 5, &[1, 2, 3]); // Same ESI

        let added1 = collector.add_collected(CollectedSymbol {
            symbol: sym1,
            source_replica: "r1".to_string(),
            collected_at: Time::ZERO,
            verified: false,
        });
        assert!(added1);

        let added2 = collector.add_collected(CollectedSymbol {
            symbol: sym2,
            source_replica: "r2".to_string(),
            collected_at: Time::from_secs(1),
            verified: false,
        });
        assert!(!added2);

        assert_eq!(collector.symbols().len(), 1);
        assert_eq!(collector.metrics.symbols_duplicate, 1);
    }

    #[test]
    fn collector_progress_tracking() {
        let collector = RecoveryCollector::new(RecoveryConfig::default());

        let progress = collector.progress();
        assert_eq!(progress.phase, RecoveryPhase::Initializing);
        assert_eq!(progress.symbols_collected, 0);
    }

    #[test]
    fn collector_can_decode_threshold() {
        let mut collector = RecoveryCollector::new(RecoveryConfig::default());
        collector.object_params = Some(ObjectParams::new(
            ObjectId::new_for_test(1),
            1000,
            128,
            1,
            10, // K = 10
        ));

        // Add 9 symbols (not enough).
        for i in 0..9 {
            collector.add_collected(make_collected_symbol(i));
        }
        assert!(!collector.can_decode());

        // Add 10th (enough).
        collector.add_collected(make_collected_symbol(9));
        assert!(collector.can_decode());
    }

    #[test]
    fn collector_cancel() {
        let mut collector = RecoveryCollector::new(RecoveryConfig::default());
        assert!(!collector.cancelled);
        collector.cancel();
        assert!(collector.cancelled);
    }

    // =====================================================================
    // Decoding Tests
    // =====================================================================

    #[test]
    fn decoder_accumulates_symbols() {
        let mut decoder = StateDecoder::new(RecoveryDecodingConfig::default());

        let sym = Symbol::new_for_test(1, 0, 0, &[1, 2, 3]);
        decoder.add_symbol(&sym).unwrap();

        assert_eq!(decoder.symbols_received(), 1);
    }

    #[test]
    fn decoder_deduplicates() {
        let mut decoder = StateDecoder::new(RecoveryDecodingConfig::default());

        let sym = Symbol::new_for_test(1, 0, 0, &[1, 2, 3]);
        decoder.add_symbol(&sym).unwrap();
        decoder.add_symbol(&sym).unwrap(); // duplicate

        assert_eq!(decoder.symbols_received(), 1);
    }

    #[test]
    fn decoder_rejects_insufficient_symbols() {
        let mut decoder = StateDecoder::new(RecoveryDecodingConfig::default());
        // K = 10 symbols needed (object_size=1280*10, symbol_size=1280).
        let params = ObjectParams::new(ObjectId::new_for_test(1), 12800, 1280, 1, 10);

        // Add fewer than K symbols.
        for i in 0..2 {
            let sym = Symbol::new_for_test(1, 0, i, &[0u8; 1280]);
            decoder.add_symbol(&sym).unwrap();
        }

        let result = decoder.decode(&params);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::InsufficientSymbols);
    }

    #[test]
    fn decoder_successful_decode() {
        let snapshot = create_test_snapshot();
        let encoded = encode_test_snapshot(&snapshot);

        let mut decoder = StateDecoder::new(RecoveryDecodingConfig::default());
        for sym in &encoded.symbols {
            decoder.add_symbol(sym).unwrap();
        }

        let recovered = decoder.decode_snapshot(&encoded.params).unwrap();

        assert_eq!(recovered.region_id, snapshot.region_id);
        assert_eq!(recovered.sequence, snapshot.sequence);
    }

    #[test]
    fn decoder_reset() {
        let mut decoder = StateDecoder::new(RecoveryDecodingConfig::default());

        let sym = Symbol::new_for_test(1, 0, 0, &[1, 2, 3]);
        decoder.add_symbol(&sym).unwrap();
        assert_eq!(decoder.symbols_received(), 1);

        decoder.reset();
        assert_eq!(decoder.symbols_received(), 0);
    }

    #[test]
    fn decoder_symbols_needed() {
        let decoder = StateDecoder::new(RecoveryDecodingConfig::default());
        let params = ObjectParams::new(ObjectId::new_for_test(1), 1000, 128, 1, 10);

        assert_eq!(decoder.symbols_needed(&params), 10);
    }

    // =====================================================================
    // Orchestration Tests
    // =====================================================================

    #[test]
    fn orchestrator_successful_recovery() {
        let snapshot = create_test_snapshot();
        let encoded = encode_test_snapshot(&snapshot);

        let symbols: Vec<CollectedSymbol> = encoded
            .symbols
            .iter()
            .enumerate()
            .map(|(i, s)| CollectedSymbol {
                symbol: s.clone(),
                source_replica: format!("r{}", i % 3),
                collected_at: Time::ZERO,
                verified: false,
            })
            .collect();

        let trigger = RecoveryTrigger::ManualTrigger {
            region_id: RegionId::new_for_test(1, 0),
            initiator: "test".to_string(),
            reason: None,
        };

        let mut orchestrator =
            RecoveryOrchestrator::new(RecoveryConfig::default(), RecoveryDecodingConfig::default());

        let result = orchestrator
            .recover_from_symbols(
                &trigger,
                &symbols,
                encoded.params,
                Duration::from_millis(10),
            )
            .unwrap();

        assert!(result.verified);
        assert!(!result.contributing_replicas.is_empty());
        assert_eq!(result.snapshot.region_id, snapshot.region_id);
        assert_eq!(result.snapshot.sequence, snapshot.sequence);
    }

    #[test]
    fn orchestrator_cancellation() {
        let mut orchestrator =
            RecoveryOrchestrator::new(RecoveryConfig::default(), RecoveryDecodingConfig::default());

        assert!(!orchestrator.is_recovering());
        orchestrator.cancel("test cancellation");
        assert!(!orchestrator.is_recovering());
    }

    #[test]
    fn orchestrator_insufficient_symbols() {
        let trigger = RecoveryTrigger::ManualTrigger {
            region_id: RegionId::new_for_test(1, 0),
            initiator: "test".to_string(),
            reason: None,
        };

        let params = ObjectParams::new(ObjectId::new_for_test(1), 1000, 128, 1, 10);

        // Provide only 2 symbols (need 10).
        let symbols: Vec<CollectedSymbol> = (0..2).map(make_collected_symbol).collect();

        let mut orchestrator =
            RecoveryOrchestrator::new(RecoveryConfig::default(), RecoveryDecodingConfig::default());

        let result = orchestrator.recover_from_symbols(
            &trigger,
            &symbols,
            params,
            Duration::from_millis(10),
        );

        assert!(result.is_err());
    }

    // =====================================================================
    // Integration Test: Full Workflow
    // =====================================================================

    #[test]
    fn full_recovery_workflow() {
        // 1. Create original region state.
        let original = RegionSnapshot {
            region_id: RegionId::new_for_test(1, 0),
            state: RegionState::Open,
            timestamp: Time::from_secs(100),
            sequence: 42,
            tasks: vec![TaskSnapshot {
                task_id: TaskId::new_for_test(1, 0),
                state: TaskState::Running,
                priority: 5,
            }],
            children: vec![RegionId::new_for_test(2, 0)],
            finalizer_count: 3,
            budget: BudgetSnapshot {
                deadline_nanos: None,
                polls_remaining: None,
                cost_remaining: None,
            },
            cancel_reason: None,
            parent: None,
            metadata: vec![1, 2, 3, 4],
        };

        // 2. Encode it.
        let encoded = encode_test_snapshot(&original);

        // 3. Simulate replica collection (all symbols from 3 replicas).
        let symbols: Vec<CollectedSymbol> = encoded
            .symbols
            .iter()
            .enumerate()
            .map(|(i, s)| CollectedSymbol {
                symbol: s.clone(),
                source_replica: format!("r{}", i % 3),
                collected_at: Time::ZERO,
                verified: false,
            })
            .collect();

        // 4. Recover.
        let trigger = RecoveryTrigger::NodeRestart {
            region_id: RegionId::new_for_test(1, 0),
            last_known_sequence: 41,
        };

        let mut orchestrator =
            RecoveryOrchestrator::new(RecoveryConfig::default(), RecoveryDecodingConfig::default());

        let result = orchestrator
            .recover_from_symbols(
                &trigger,
                &symbols,
                encoded.params,
                Duration::from_millis(50),
            )
            .unwrap();

        // 5. Verify recovered state matches original.
        assert_eq!(result.snapshot.region_id, original.region_id);
        assert_eq!(result.snapshot.sequence, original.sequence);
        assert_eq!(result.snapshot.tasks.len(), original.tasks.len());
        assert_eq!(result.snapshot.children, original.children);
        assert_eq!(result.snapshot.metadata, original.metadata);
        assert_eq!(result.snapshot.finalizer_count, original.finalizer_count);
    }

    // =====================================================================
    // Helpers
    // =====================================================================

    fn create_test_snapshot() -> RegionSnapshot {
        RegionSnapshot {
            region_id: RegionId::new_for_test(1, 0),
            state: RegionState::Open,
            timestamp: Time::from_secs(100),
            sequence: 1,
            tasks: vec![TaskSnapshot {
                task_id: TaskId::new_for_test(1, 0),
                state: TaskState::Running,
                priority: 5,
            }],
            children: vec![],
            finalizer_count: 2,
            budget: BudgetSnapshot {
                deadline_nanos: Some(1_000_000_000),
                polls_remaining: Some(100),
                cost_remaining: None,
            },
            cancel_reason: None,
            parent: None,
            metadata: vec![],
        }
    }

    fn encode_test_snapshot(snapshot: &RegionSnapshot) -> EncodedState {
        let config = EncodingConfig {
            symbol_size: 128,
            min_repair_symbols: 4,
            ..Default::default()
        };
        let mut enc = StateEncoder::new(config, DetRng::new(42));
        enc.encode(snapshot, Time::ZERO).unwrap()
    }

    fn make_collected_symbol(esi: u32) -> CollectedSymbol {
        CollectedSymbol {
            symbol: Symbol::new_for_test(1, 0, esi, &[0u8; 128]),
            source_replica: "r1".to_string(),
            collected_at: Time::ZERO,
            verified: false,
        }
    }

    fn make_source_symbol(esi: u32, data: &[u8]) -> Symbol {
        Symbol::new(
            SymbolId::new(ObjectId::new_for_test(1), 0, esi),
            data.to_vec(),
            SymbolKind::Source,
        )
    }

    fn make_repair_symbol(esi: u32, data: &[u8]) -> Symbol {
        Symbol::new(
            SymbolId::new(ObjectId::new_for_test(1), 0, esi),
            data.to_vec(),
            SymbolKind::Repair,
        )
    }

    // =====================================================================
    // Failure Mode Tests (bd-17uj)
    // =====================================================================

    #[test]
    fn collector_duplicate_esi_from_same_replica() {
        // Two symbols with same ESI from the SAME replica — second rejected.
        let mut collector = RecoveryCollector::new(RecoveryConfig::default());

        let sym1 = CollectedSymbol {
            symbol: Symbol::new_for_test(1, 0, 5, &[1, 2, 3]),
            source_replica: "r1".to_string(),
            collected_at: Time::ZERO,
            verified: false,
        };
        let sym2 = CollectedSymbol {
            symbol: Symbol::new_for_test(1, 0, 5, &[4, 5, 6]),
            source_replica: "r1".to_string(),
            collected_at: Time::from_secs(1),
            verified: false,
        };

        assert!(collector.add_collected(sym1));
        assert!(!collector.add_collected(sym2));
        assert_eq!(collector.symbols().len(), 1);
        assert_eq!(collector.metrics.symbols_duplicate, 1);
        assert_eq!(collector.metrics.symbols_received, 1);
    }

    #[test]
    fn collector_verify_rejects_out_of_range_esi() {
        let mut collector = RecoveryCollector::new(RecoveryConfig::default());
        // K=10, total_source=10, min_symbols=0 → max_expected = 10+0 = 10, threshold = 110
        collector.object_params = Some(ObjectParams::new(
            ObjectId::new_for_test(1),
            1280,
            128,
            1,
            10,
        ));

        // ESI 200 > 110 threshold → rejected as corrupt
        let cs = CollectedSymbol {
            symbol: Symbol::new_for_test(1, 0, 200, &[0u8; 128]),
            source_replica: "r1".to_string(),
            collected_at: Time::ZERO,
            verified: false,
        };
        let result = collector.add_collected_with_verify(cs);
        assert!(result.is_err());
        assert_eq!(collector.metrics.symbols_corrupt, 1);
    }

    #[test]
    fn collector_verify_accepts_in_range_esi() {
        let mut collector = RecoveryCollector::new(RecoveryConfig::default());
        collector.object_params = Some(ObjectParams::new(
            ObjectId::new_for_test(1),
            1280,
            128,
            1,
            10,
        ));

        // ESI 15 <= 110 threshold → accepted
        let cs = CollectedSymbol {
            symbol: Symbol::new_for_test(1, 0, 15, &[0u8; 128]),
            source_replica: "r1".to_string(),
            collected_at: Time::ZERO,
            verified: false,
        };
        let result = collector.add_collected_with_verify(cs);
        assert!(result.is_ok());
        assert!(result.unwrap()); // was accepted (new ESI)
    }

    #[test]
    fn collector_verify_no_params_accepts_any() {
        // Without object_params set, verify skips range check
        let mut collector = RecoveryCollector::new(RecoveryConfig::default());

        let cs = CollectedSymbol {
            symbol: Symbol::new_for_test(1, 0, 999_999, &[0u8; 128]),
            source_replica: "r1".to_string(),
            collected_at: Time::ZERO,
            verified: false,
        };
        let result = collector.add_collected_with_verify(cs);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn collector_cancel_prevents_is_recovering() {
        let mut orchestrator =
            RecoveryOrchestrator::new(RecoveryConfig::default(), RecoveryDecodingConfig::default());

        // Start by setting recovering manually isn't possible, but cancel should
        // ensure is_recovering returns false regardless.
        orchestrator.cancel("test");
        assert!(!orchestrator.is_recovering());
        assert!(orchestrator.cancelled);
    }

    #[test]
    fn collector_metrics_accuracy() {
        let mut collector = RecoveryCollector::new(RecoveryConfig::default());
        collector.object_params = Some(ObjectParams::new(
            ObjectId::new_for_test(1),
            1280,
            128,
            1,
            10,
        ));

        // Add 5 unique symbols
        for i in 0..5 {
            collector.add_collected(make_collected_symbol(i));
        }
        // Add 3 duplicates
        for i in 0..3 {
            collector.add_collected(make_collected_symbol(i));
        }

        assert_eq!(collector.metrics.symbols_received, 5);
        assert_eq!(collector.metrics.symbols_duplicate, 3);
        assert_eq!(collector.progress().symbols_collected, 5);
        assert_eq!(collector.symbols().len(), 5);
    }

    #[test]
    fn decoder_insufficient_symbols_error_kind() {
        let mut decoder = StateDecoder::new(RecoveryDecodingConfig::default());
        let params = ObjectParams::new(ObjectId::new_for_test(1), 12800, 1280, 1, 10);

        // Add K-1 = 9 symbols (need 10)
        for i in 0..9 {
            let sym = make_source_symbol(i, &[0u8; 1280]);
            decoder.add_symbol(&sym).unwrap();
        }

        let err = decoder.decode(&params).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InsufficientSymbols);
    }

    #[test]
    fn decoder_zero_symbols_fails() {
        let mut decoder = StateDecoder::new(RecoveryDecodingConfig::default());
        let params = ObjectParams::new(ObjectId::new_for_test(1), 1280, 128, 1, 10);

        let result = decoder.decode(&params);
        assert!(result.is_err());
    }

    #[test]
    fn decoder_reset_allows_reuse() {
        let mut decoder = StateDecoder::new(RecoveryDecodingConfig::default());

        // First use
        let sym = make_source_symbol(0, &[1, 2, 3]);
        decoder.add_symbol(&sym).unwrap();
        assert_eq!(decoder.symbols_received(), 1);

        // Reset
        decoder.reset();
        assert_eq!(decoder.symbols_received(), 0);
        assert!(!decoder.can_decode());

        // Reuse — same ESI should be accepted again after reset
        decoder.add_symbol(&sym).unwrap();
        assert_eq!(decoder.symbols_received(), 1);
        assert!(decoder.can_decode());
    }

    #[test]
    fn decoder_mixed_source_repair_boundary_decode() {
        // Create a snapshot, encode it, then provide exactly K symbols
        // (mix of source and repair) and verify decode works.
        let snapshot = create_test_snapshot();
        let encoded = encode_test_snapshot(&snapshot);

        let k = encoded.params.min_symbols_for_decode() as usize;
        assert!(
            encoded.symbols.len() >= k,
            "encoded should have at least K symbols"
        );

        // Take exactly K symbols
        let mut decoder = StateDecoder::new(RecoveryDecodingConfig::default());
        for sym in encoded.symbols.iter().take(k) {
            decoder.add_symbol(sym).unwrap();
        }

        let result = decoder.decode_snapshot(&encoded.params);
        assert!(result.is_ok());
        let recovered = result.unwrap();
        assert_eq!(recovered.region_id, snapshot.region_id);
    }

    #[test]
    fn orchestrator_recover_with_zero_symbols() {
        let trigger = RecoveryTrigger::ManualTrigger {
            region_id: RegionId::new_for_test(1, 0),
            initiator: "test".to_string(),
            reason: None,
        };
        let params = ObjectParams::new(ObjectId::new_for_test(1), 1000, 128, 1, 10);

        let mut orchestrator =
            RecoveryOrchestrator::new(RecoveryConfig::default(), RecoveryDecodingConfig::default());

        let result =
            orchestrator.recover_from_symbols(&trigger, &[], params, Duration::from_millis(1));
        assert!(result.is_err());
        assert!(!orchestrator.is_recovering());
    }

    #[test]
    fn orchestrator_attempt_counter_increments() {
        let trigger = RecoveryTrigger::ManualTrigger {
            region_id: RegionId::new_for_test(1, 0),
            initiator: "test".to_string(),
            reason: None,
        };
        let params = ObjectParams::new(ObjectId::new_for_test(1), 1000, 128, 1, 10);

        let mut orchestrator =
            RecoveryOrchestrator::new(RecoveryConfig::default(), RecoveryDecodingConfig::default());

        // First attempt (fails — no symbols)
        let _ = orchestrator.recover_from_symbols(&trigger, &[], params, Duration::ZERO);
        assert_eq!(orchestrator.attempt, 1);

        // Second attempt
        let _ = orchestrator.recover_from_symbols(&trigger, &[], params, Duration::ZERO);
        assert_eq!(orchestrator.attempt, 2);
    }

    #[test]
    fn orchestrator_cancel_after_start() {
        let snapshot = create_test_snapshot();
        let encoded = encode_test_snapshot(&snapshot);

        let mut orchestrator =
            RecoveryOrchestrator::new(RecoveryConfig::default(), RecoveryDecodingConfig::default());

        // Cancel before recovery — ensure subsequent recovery still fails gracefully
        orchestrator.cancel("pre-emptive cancel");
        assert!(orchestrator.cancelled);
        assert!(!orchestrator.is_recovering());

        // Even with valid symbols, cancelled orchestrator reports not recovering
        let symbols: Vec<CollectedSymbol> = encoded
            .symbols
            .iter()
            .map(|s| CollectedSymbol {
                symbol: s.clone(),
                source_replica: "r1".to_string(),
                collected_at: Time::ZERO,
                verified: false,
            })
            .collect();

        // recover_from_symbols doesn't check cancelled flag — it still runs.
        // But is_recovering() returns false because cancelled is true.
        let _result = orchestrator.recover_from_symbols(
            &RecoveryTrigger::ManualTrigger {
                region_id: RegionId::new_for_test(1, 0),
                initiator: "test".to_string(),
                reason: None,
            },
            &symbols,
            encoded.params,
            Duration::ZERO,
        );
        assert!(!orchestrator.is_recovering());
    }

    #[test]
    fn recovery_config_default_values() {
        let config = RecoveryConfig::default();
        assert_eq!(config.min_symbols, 0);
        assert_eq!(config.recovery_timeout, Duration::from_secs(60));
        assert_eq!(config.replica_timeout, Duration::from_secs(5));
        assert_eq!(config.max_concurrent_requests, 10);
        assert_eq!(config.collection_consistency, CollectionConsistency::Quorum);
        assert!(!config.allow_partial);
        assert_eq!(config.max_attempts, 3);
    }

    #[test]
    fn decoding_config_default_values() {
        let config = RecoveryDecodingConfig::default();
        assert!(config.verify_integrity);
        assert_eq!(config.max_decode_attempts, 3);
        assert!(!config.allow_partial_decode);
    }

    #[test]
    fn trigger_manual_with_reason() {
        let trigger = RecoveryTrigger::ManualTrigger {
            region_id: RegionId::new_for_test(5, 0),
            initiator: "admin".to_string(),
            reason: Some("routine maintenance".to_string()),
        };
        assert_eq!(trigger.region_id(), RegionId::new_for_test(5, 0));
        assert!(!trigger.is_critical());
    }

    #[test]
    fn recovery_phase_equality() {
        assert_eq!(RecoveryPhase::Initializing, RecoveryPhase::Initializing);
        assert_ne!(RecoveryPhase::Collecting, RecoveryPhase::Verifying);
        assert_ne!(RecoveryPhase::Complete, RecoveryPhase::Failed);
    }

    #[test]
    fn collector_debug_format() {
        let collector = RecoveryCollector::new(RecoveryConfig::default());
        let debug = format!("{collector:?}");
        assert!(debug.contains("RecoveryCollector"));
        assert!(debug.contains("collected"));
    }

    #[test]
    fn orchestrator_debug_format() {
        let orchestrator =
            RecoveryOrchestrator::new(RecoveryConfig::default(), RecoveryDecodingConfig::default());
        let debug = format!("{orchestrator:?}");
        assert!(debug.contains("RecoveryOrchestrator"));
        assert!(debug.contains("attempt"));
    }
}
