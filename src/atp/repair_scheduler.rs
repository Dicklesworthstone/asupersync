//! Multi-source RaptorQ repair scheduling for ATP swarm transfers.
//!
//! Implements peer scoring, symbol usefulness evaluation, and scheduling algorithms
//! for efficient repair symbol collection from multiple sources in ATP swarm mode.

use crate::atp::object::ObjectId;
use crate::error::Result;
use crate::error::{Error, ErrorKind};
use crate::types::Time;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::time::Duration;
#[cfg(feature = "tracing-integration")]
use tracing::{debug, info, warn};

// Provide no-op tracing macros when tracing is disabled
#[cfg(not(feature = "tracing-integration"))]
macro_rules! debug {
    ($($arg:tt)*) => {};
}
#[cfg(not(feature = "tracing-integration"))]
macro_rules! info {
    ($($arg:tt)*) => {};
}
#[cfg(not(feature = "tracing-integration"))]
macro_rules! warn {
    ($($arg:tt)*) => {};
}

/// Configuration for multi-source repair scheduling
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepairSchedulerConfig {
    /// Maximum number of concurrent peer connections
    pub max_concurrent_peers: usize,
    /// Maximum symbols to request per peer per batch
    pub max_symbols_per_peer_batch: usize,
    /// Minimum decode usefulness threshold for symbol requests
    pub min_decode_usefulness_threshold: f64,
    /// Peer scoring weights
    pub peer_scoring_weights: PeerScoringWeights,
    /// Symbol timeout duration
    pub symbol_timeout_duration: Duration,
    /// Maximum retries per symbol
    pub max_symbol_retries: u32,
    /// Enable malicious peer detection
    pub enable_malicious_detection: bool,
    /// Trust decay factor per failed symbol
    pub trust_decay_factor: f64,
}

impl Default for RepairSchedulerConfig {
    fn default() -> Self {
        Self {
            max_concurrent_peers: 8,
            max_symbols_per_peer_batch: 16,
            min_decode_usefulness_threshold: 0.1,
            peer_scoring_weights: PeerScoringWeights::default(),
            symbol_timeout_duration: Duration::from_secs(30),
            max_symbol_retries: 3,
            enable_malicious_detection: true,
            trust_decay_factor: 0.95,
        }
    }
}

/// Weights for peer scoring algorithm
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerScoringWeights {
    /// Path quality weight (latency, bandwidth, loss rate)
    pub path_quality: f64,
    /// Upload budget availability weight
    pub upload_budget: f64,
    /// Symbol rarity weight (how rare the symbols this peer has)
    pub symbol_rarity: f64,
    /// Decode usefulness weight (how useful symbols are for decode progress)
    pub decode_usefulness: f64,
    /// Trust score weight (historical reliability)
    pub trust: f64,
    /// Relay cost weight (cost to route through this peer)
    pub relay_cost: f64,
    /// Churn probability weight (likelihood peer will disconnect)
    pub churn_probability: f64,
}

impl Default for PeerScoringWeights {
    fn default() -> Self {
        Self {
            path_quality: 0.25,
            upload_budget: 0.15,
            symbol_rarity: 0.20,
            decode_usefulness: 0.25,
            trust: 0.10,
            relay_cost: -0.05,        // Negative because higher cost is worse
            churn_probability: -0.10, // Negative because higher churn is worse
        }
    }
}

/// Unique identifier for a peer in the swarm
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PeerId {
    /// Peer's network address
    pub address: SocketAddr,
    /// Peer's public key hash (for authentication)
    pub key_hash: [u8; 32],
}

impl PeerId {
    /// Create a new peer ID
    pub fn new(address: SocketAddr, key_hash: [u8; 32]) -> Self {
        Self { address, key_hash }
    }

    /// Get a string representation for logging
    pub fn as_string(&self) -> String {
        format!("{}#{}", self.address, hex::encode(&self.key_hash[..8]))
    }
}

/// Information about a peer's capabilities and state
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// Peer identifier
    pub peer_id: PeerId,
    /// Available repair symbols for the current transfer
    pub available_symbols: BTreeSet<u32>,
    /// Path quality metrics
    pub path_quality: PathQuality,
    /// Upload budget remaining
    pub upload_budget_bytes: u64,
    /// Trust score (0.0 to 1.0)
    pub trust_score: f64,
    /// Relay cost per byte
    pub relay_cost_per_byte: f64,
    /// Churn probability (0.0 to 1.0)
    pub churn_probability: f64,
    /// Last seen timestamp
    pub last_seen: Time,
    /// Authentication domain
    pub auth_domain: String,
}

/// Path quality metrics for a peer
#[derive(Debug, Clone)]
pub struct PathQuality {
    /// Round-trip latency in milliseconds
    pub latency_ms: f64,
    /// Available bandwidth in bytes per second
    pub bandwidth_bps: u64,
    /// Packet loss rate (0.0 to 1.0)
    pub loss_rate: f64,
    /// Jitter in milliseconds
    pub jitter_ms: f64,
}

impl PathQuality {
    /// Calculate overall path quality score (0.0 to 1.0, higher is better)
    pub fn quality_score(&self) -> f64 {
        let latency_score = (1000.0 - self.latency_ms.min(1000.0)) / 1000.0;
        let bandwidth_score = (self.bandwidth_bps as f64 / 1_000_000.0).min(1.0); // Normalize to 1Mbps
        let loss_score = 1.0 - self.loss_rate;
        let jitter_score = (100.0 - self.jitter_ms.min(100.0)) / 100.0;

        latency_score * 0.3 + bandwidth_score * 0.4 + loss_score * 0.2 + jitter_score * 0.1
    }
}

/// Information about a repair symbol request
#[derive(Debug, Clone)]
pub struct RepairSymbolRequest {
    /// Symbol index in the repair group
    pub symbol_index: u32,
    /// Peer to request from
    pub peer_id: PeerId,
    /// Request timestamp
    pub requested_at: Time,
    /// Expected usefulness for decode progress
    pub decode_usefulness: f64,
    /// Number of retries so far
    pub retry_count: u32,
    /// Timeout timestamp
    pub timeout_at: Time,
}

/// Reason why a symbol or peer was rejected
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RejectionReason {
    /// Malicious peer detected
    MaliciousPeer { evidence: String },
    /// Symbol data is stale or outdated
    StaleSymbol { age_ms: u64 },
    /// Authentication failed
    AuthenticationFailed { domain_mismatch: bool },
    /// Wrong repair group
    WrongGroup { expected: String, received: String },
    /// Wrong transfer manifest
    WrongTransfer { expected_object_id: String },
    /// Low decode usefulness
    LowUsefulness { usefulness: f64, threshold: f64 },
    /// Symbol already received
    DuplicateSymbol,
    /// Requested peer disappeared before delivering the assigned symbol
    PeerUnavailable { peer: String },
    /// Peer exceeded budget
    BudgetExceeded { available: u64, requested: u64 },
    /// Peer trust score too low
    LowTrustScore { score: f64, threshold: f64 },
}

impl std::fmt::Display for RejectionReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RejectionReason::MaliciousPeer { evidence } => {
                write!(f, "malicious peer detected: {}", evidence)
            }
            RejectionReason::StaleSymbol { age_ms } => {
                write!(f, "stale symbol (age: {}ms)", age_ms)
            }
            RejectionReason::AuthenticationFailed { domain_mismatch } => {
                if *domain_mismatch {
                    write!(f, "authentication domain mismatch")
                } else {
                    write!(f, "authentication failed")
                }
            }
            RejectionReason::WrongGroup { expected, received } => {
                write!(
                    f,
                    "wrong repair group (expected: {}, received: {})",
                    expected, received
                )
            }
            RejectionReason::WrongTransfer { expected_object_id } => {
                write!(f, "wrong transfer (expected: {})", expected_object_id)
            }
            RejectionReason::LowUsefulness {
                usefulness,
                threshold,
            } => {
                write!(
                    f,
                    "low decode usefulness ({:.3} < {:.3})",
                    usefulness, threshold
                )
            }
            RejectionReason::DuplicateSymbol => write!(f, "duplicate symbol"),
            RejectionReason::PeerUnavailable { peer } => {
                write!(f, "peer unavailable before symbol delivery: {}", peer)
            }
            RejectionReason::BudgetExceeded {
                available,
                requested,
            } => {
                write!(
                    f,
                    "budget exceeded ({} available, {} requested)",
                    available, requested
                )
            }
            RejectionReason::LowTrustScore { score, threshold } => {
                write!(f, "low trust score ({:.3} < {:.3})", score, threshold)
            }
        }
    }
}

/// Upper bound on how many recent rejected requests are retained for
/// diagnostics. A long-lived, churny transfer can reject an unbounded number of
/// symbols (timeouts, hijacks, low-trust peers); retaining every one of them
/// would leak memory for the lifetime of the scheduler. Older rejections are
/// dropped past this cap while `rejected_total` keeps the lifetime count.
const MAX_RETAINED_REJECTIONS: usize = 256;

/// Multi-source repair scheduler for RaptorQ symbols
#[derive(Debug)]
pub struct MultiSourceRepairScheduler {
    config: RepairSchedulerConfig,
    #[allow(dead_code)]
    object_id: ObjectId,
    #[allow(dead_code)]
    repair_group_id: String,
    k_prime: u32, // Number of source symbols needed
    // BTreeMap (not HashMap) so peer iteration — and therefore tie-broken peer
    // selection in `select_best_peer_for_symbol` — is deterministic, satisfying
    // the lab-runtime replayability convention (br-asupersync-yms9p9 F8).
    peers: BTreeMap<PeerId, PeerInfo>,
    received_symbols: HashSet<u32>,
    pending_requests: HashMap<u32, RepairSymbolRequest>,
    symbol_retry_counts: HashMap<u32, u32>,
    rejected_requests: VecDeque<(RepairSymbolRequest, RejectionReason)>,
    /// Lifetime count of rejected symbol requests (not bounded by retention).
    rejected_total: u64,
    decode_matrix: DecodeMatrix,
    symbol_rarity_map: HashMap<u32, f64>,
}

impl MultiSourceRepairScheduler {
    /// Create a new multi-source repair scheduler
    pub fn new(
        config: RepairSchedulerConfig,
        object_id: ObjectId,
        repair_group_id: String,
        k_prime: u32,
    ) -> Self {
        Self {
            config,
            object_id,
            repair_group_id,
            k_prime,
            peers: BTreeMap::new(),
            received_symbols: HashSet::new(),
            pending_requests: HashMap::new(),
            symbol_retry_counts: HashMap::new(),
            rejected_requests: VecDeque::new(),
            rejected_total: 0,
            decode_matrix: DecodeMatrix::new(k_prime),
            symbol_rarity_map: HashMap::new(),
        }
    }

    /// Register a peer with the scheduler
    pub fn register_peer(&mut self, peer_info: PeerInfo) -> Result<()> {
        self.validate_peer(&peer_info)?;

        info!(
            "Registering peer {} with {} symbols",
            peer_info.peer_id.as_string(),
            peer_info.available_symbols.len()
        );

        self.peers.insert(peer_info.peer_id.clone(), peer_info);
        self.recalculate_symbol_rarity();
        Ok(())
    }

    /// Remove a peer from the scheduler
    pub fn unregister_peer(&mut self, peer_id: &PeerId) {
        if let Some(_peer_info) = self.peers.remove(peer_id) {
            info!("Unregistering peer {}", peer_id.as_string());

            // Retire any pending requests from this peer through the same
            // accounting path as timeouts/rejections. Dropping them silently
            // would reset the symbol retry budget under churn and let a
            // flapping peer make a symbol retry forever.
            let mut cancelled_requests = Vec::new();
            self.pending_requests.retain(|_, request| {
                if request.peer_id == *peer_id {
                    cancelled_requests.push(request.clone());
                    false
                } else {
                    true
                }
            });
            for request in cancelled_requests {
                self.record_request_failure(
                    request,
                    RejectionReason::PeerUnavailable {
                        peer: peer_id.as_string(),
                    },
                );
            }

            // Update symbol rarity after peer removal
            self.recalculate_symbol_rarity();
        }
    }

    /// Schedule next batch of symbol requests based on current decode state.
    ///
    /// `now` is the caller-provided runtime time. Production callers can pass
    /// runtime time, and lab callers can pass virtual time; the scheduler does
    /// not consult host wall-clock state.
    pub fn schedule_next_batch_at(&mut self, now: Time) -> Result<Vec<RepairSymbolRequest>> {
        let mut requests = Vec::new();

        // Remove timed-out requests
        self.cleanup_timed_out_requests(now);

        // Calculate how many symbols we still need
        let symbols_needed = self.calculate_symbols_needed();
        if symbols_needed == 0 {
            debug!("No additional symbols needed for decode");
            return Ok(requests);
        }

        // Score all peers
        let peer_scores = self.calculate_peer_scores();

        // Get most useful symbols to request
        let useful_symbols = self.get_most_useful_symbols(symbols_needed);

        // Schedule requests using peer scores and symbol usefulness, enforcing
        // per-peer batch fairness so no single peer monopolizes the batch.
        let mut per_peer_assigned: HashMap<PeerId, usize> = HashMap::new();
        for symbol_index in useful_symbols {
            let can_add_new_peer = per_peer_assigned.len() < self.config.max_concurrent_peers;
            if let Some(best_peer) = self.select_best_peer_for_symbol(
                symbol_index,
                &peer_scores,
                &per_peer_assigned,
                can_add_new_peer,
            ) {
                let decode_usefulness = self.calculate_symbol_decode_usefulness(symbol_index);
                let retry_count = self.retry_count_for_symbol(symbol_index);

                let request = RepairSymbolRequest {
                    symbol_index,
                    peer_id: best_peer.clone(),
                    requested_at: now,
                    decode_usefulness,
                    retry_count,
                    timeout_at: now + self.config.symbol_timeout_duration,
                };

                requests.push(request.clone());
                self.pending_requests.insert(symbol_index, request);
                *per_peer_assigned.entry(best_peer).or_insert(0) += 1;

                if requests.len()
                    >= self.config.max_concurrent_peers * self.config.max_symbols_per_peer_batch
                {
                    break;
                }
            }
        }

        info!("Scheduled {} symbol requests for decode", requests.len());
        Ok(requests)
    }

    /// Process received symbol and update decode state
    pub fn process_received_symbol(
        &mut self,
        symbol_index: u32,
        symbol_data: &[u8],
        from_peer: &PeerId,
    ) -> Result<SymbolProcessResult> {
        // Validate the symbol
        if let Err(reason) = self.validate_received_symbol(symbol_index, symbol_data, from_peer) {
            warn!(
                "Rejecting symbol {} from {}: {}",
                symbol_index,
                from_peer.as_string(),
                reason
            );

            // An unauthorized sender (wrong peer or unregistered) must NOT
            // consume the legitimate outstanding request — otherwise a forged
            // response could cancel an honest peer's pending symbol. Penalize
            // the forging sender's trust instead and leave the request intact.
            // Request-level rejections (e.g. a low-trust assigned peer) do
            // retire the request so it can be rescheduled.
            if matches!(reason, RejectionReason::MaliciousPeer { .. }) {
                if self.config.enable_malicious_detection {
                    self.update_peer_trust(from_peer, false);
                }
            } else if let Some(request) = self.pending_requests.remove(&symbol_index) {
                self.record_request_failure(request, reason.clone());
            }

            return Ok(SymbolProcessResult::Rejected { reason });
        }

        // Accept the symbol
        self.received_symbols.insert(symbol_index);
        self.pending_requests.remove(&symbol_index);
        self.symbol_retry_counts.remove(&symbol_index);

        // Update decode matrix
        let decode_contribution = self.decode_matrix.add_symbol(symbol_index, symbol_data)?;

        // Update peer trust positively
        self.update_peer_trust(from_peer, true);

        info!(
            "Accepted symbol {} from {} (contribution: {:.3})",
            symbol_index,
            from_peer.as_string(),
            decode_contribution
        );

        Ok(SymbolProcessResult::Accepted {
            decode_contribution,
            decode_complete: self.is_decode_complete(),
        })
    }

    /// Check if enough symbols have been received for successful decode
    pub fn is_decode_complete(&self) -> bool {
        self.decode_matrix.can_decode() && self.received_symbols.len() >= self.k_prime as usize
    }

    /// Get current decode progress statistics
    pub fn get_decode_progress(&self) -> DecodeProgress {
        DecodeProgress {
            symbols_received: self.received_symbols.len(),
            symbols_needed: self.k_prime as usize,
            decode_progress_ratio: self.decode_matrix.decode_progress(),
            pending_requests: self.pending_requests.len(),
            active_peers: self.peers.len(),
            rejected_symbols: self.rejected_total as usize,
        }
    }

    /// Validate peer information and compatibility
    fn validate_peer(&self, peer_info: &PeerInfo) -> Result<()> {
        // Check authentication domain compatibility
        if peer_info.auth_domain != self.expected_auth_domain() {
            return Err(Error::new(ErrorKind::ProtocolError));
        }

        // Check if peer has any useful symbols
        if peer_info.available_symbols.is_empty() {
            return Err(Error::new(ErrorKind::NodeUnavailable));
        }

        // Check trust threshold
        if peer_info.trust_score < 0.1 {
            return Err(Error::new(ErrorKind::ConnectionRefused));
        }

        Ok(())
    }

    /// Calculate peer scores for scheduling decisions
    fn calculate_peer_scores(&self) -> HashMap<PeerId, f64> {
        let mut scores = HashMap::new();

        for (peer_id, peer_info) in &self.peers {
            let score = self.calculate_individual_peer_score(peer_info);
            scores.insert(peer_id.clone(), score);
        }

        scores
    }

    /// Calculate score for an individual peer
    fn calculate_individual_peer_score(&self, peer_info: &PeerInfo) -> f64 {
        let weights = &self.config.peer_scoring_weights;

        let path_quality = peer_info.path_quality.quality_score();
        let upload_budget = (peer_info.upload_budget_bytes as f64 / 1_000_000.0).min(1.0); // Normalize to 1MB
        let symbol_rarity = self.calculate_peer_symbol_rarity(peer_info);
        let decode_usefulness = self.calculate_peer_decode_usefulness(peer_info);
        let trust = peer_info.trust_score;
        // `relay_cost` / `churn_probability` weights are negative ("higher is
        // worse"), so they must multiply the raw *bad* metric, not an inverted
        // goodness value. Inverting first and then applying a negative weight
        // double-negated, penalizing cheap/stable peers the most.
        let relay_cost = (peer_info.relay_cost_per_byte * 1000.0).min(1.0); // Normalize to [0,1]
        let churn = peer_info.churn_probability;

        weights.path_quality * path_quality
            + weights.upload_budget * upload_budget
            + weights.symbol_rarity * symbol_rarity
            + weights.decode_usefulness * decode_usefulness
            + weights.trust * trust
            + weights.relay_cost * relay_cost
            + weights.churn_probability * churn
    }

    /// Calculate symbol rarity for a peer's available symbols
    fn calculate_peer_symbol_rarity(&self, peer_info: &PeerInfo) -> f64 {
        if peer_info.available_symbols.is_empty() {
            return 0.0;
        }

        let total_rarity: f64 = peer_info
            .available_symbols
            .iter()
            .map(|symbol| self.symbol_rarity_map.get(symbol).unwrap_or(&1.0))
            .sum();

        total_rarity / peer_info.available_symbols.len() as f64
    }

    /// Calculate decode usefulness for a peer's symbols
    fn calculate_peer_decode_usefulness(&self, peer_info: &PeerInfo) -> f64 {
        if peer_info.available_symbols.is_empty() {
            return 0.0;
        }

        let total_usefulness: f64 = peer_info
            .available_symbols
            .iter()
            .map(|&symbol| self.calculate_symbol_decode_usefulness(symbol))
            .sum();

        total_usefulness / peer_info.available_symbols.len() as f64
    }

    /// Select best peer for requesting a specific symbol
    fn select_best_peer_for_symbol(
        &self,
        symbol_index: u32,
        peer_scores: &HashMap<PeerId, f64>,
        per_peer_assigned: &HashMap<PeerId, usize>,
        can_add_new_peer: bool,
    ) -> Option<PeerId> {
        let mut best_peer = None;
        let mut best_score = f64::NEG_INFINITY;

        for (peer_id, peer_info) in &self.peers {
            if !peer_info.available_symbols.contains(&symbol_index) {
                continue;
            }

            // Per-peer batch fairness: never let one peer exceed its share of
            // the batch, and don't introduce a brand-new peer once the
            // concurrency cap is reached. Without these guards a single argmax
            // peer could be assigned every symbol in the batch (up to the
            // global product cap), starving healthier peers.
            let already_assigned = per_peer_assigned.get(peer_id).copied().unwrap_or(0);
            if already_assigned >= self.config.max_symbols_per_peer_batch {
                continue;
            }
            if already_assigned == 0 && !can_add_new_peer {
                continue;
            }

            if let Some(&base_score) = peer_scores.get(peer_id) {
                // Adjust score for this specific symbol
                let symbol_usefulness = self.calculate_symbol_decode_usefulness(symbol_index);
                let adjusted_score = base_score * (1.0 + symbol_usefulness);

                if adjusted_score > best_score {
                    best_score = adjusted_score;
                    best_peer = Some(peer_id.clone());
                }
            }
        }

        best_peer
    }

    /// Recalculate symbol rarity for all symbols
    fn recalculate_symbol_rarity(&mut self) {
        let mut all_symbols = HashSet::new();
        for peer in self.peers.values() {
            all_symbols.extend(&peer.available_symbols);
        }

        self.symbol_rarity_map.clear();
        for &symbol in &all_symbols {
            let peer_count = self
                .peers
                .values()
                .filter(|peer| peer.available_symbols.contains(&symbol))
                .count() as f64;

            if peer_count > 0.0 {
                let rarity = 1.0 / peer_count;
                self.symbol_rarity_map.insert(symbol, rarity);
            } else {
                self.symbol_rarity_map.remove(&symbol);
            }
        }
    }

    /// Get most useful symbols to request for decode progress
    fn get_most_useful_symbols(&self, count: usize) -> Vec<u32> {
        let mut symbol_usefulness: Vec<(u32, f64)> = Vec::new();

        // Find all available symbols we don't have yet
        for peer in self.peers.values() {
            for &symbol in &peer.available_symbols {
                if !self.received_symbols.contains(&symbol)
                    && !self.pending_requests.contains_key(&symbol)
                    && self.symbol_has_retries_remaining(symbol)
                {
                    let usefulness = self.calculate_symbol_decode_usefulness(symbol);
                    if usefulness >= self.config.min_decode_usefulness_threshold {
                        symbol_usefulness.push((symbol, usefulness));
                    }
                }
            }
        }

        // Sort by usefulness (descending)
        symbol_usefulness.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        let mut seen_symbols = HashSet::new();
        symbol_usefulness.retain(|(symbol, _)| seen_symbols.insert(*symbol));

        symbol_usefulness
            .into_iter()
            .take(count)
            .map(|(symbol, _)| symbol)
            .collect()
    }

    // Additional helper methods...
    fn calculate_symbols_needed(&self) -> usize {
        // Need is measured against decode RANK (linearly-independent symbols),
        // not the raw received count: a linearly-dependent symbol raises the
        // received count without advancing rank, so counting received symbols
        // would report "0 needed" while `can_decode()` is still false —
        // stalling the transfer forever.
        (self.k_prime as usize).saturating_sub(self.decode_matrix.decode_rank)
    }

    fn calculate_symbol_decode_usefulness(&self, symbol_index: u32) -> f64 {
        self.decode_matrix.symbol_usefulness(symbol_index)
    }

    fn cleanup_timed_out_requests(&mut self, now: Time) {
        let timed_out: Vec<u32> = self
            .pending_requests
            .iter()
            .filter(|(_, request)| now > request.timeout_at)
            .map(|(&symbol, _)| symbol)
            .collect();

        for symbol in timed_out {
            if let Some(request) = self.pending_requests.remove(&symbol) {
                warn!(
                    "Request for symbol {} from {} timed out",
                    symbol,
                    request.peer_id.as_string()
                );

                // A peer that let its assigned symbol time out is an unreliable
                // source; decay its trust so the scheduler stops re-selecting a
                // dead/slow peer for the re-request and gives healthier peers a
                // turn. Without this, a departed peer keeps full trust and is
                // chosen again, stalling the symbol indefinitely.
                self.update_peer_trust(&request.peer_id, false);

                let reason = RejectionReason::StaleSymbol {
                    age_ms: now.duration_since(request.requested_at) / 1_000_000,
                };
                self.record_request_failure(request, reason);
            }
        }
    }

    fn retry_count_for_symbol(&self, symbol_index: u32) -> u32 {
        self.symbol_retry_counts
            .get(&symbol_index)
            .copied()
            .unwrap_or(0)
    }

    fn symbol_has_retries_remaining(&self, symbol_index: u32) -> bool {
        self.retry_count_for_symbol(symbol_index) <= self.config.max_symbol_retries
    }

    fn record_request_failure(&mut self, request: RepairSymbolRequest, reason: RejectionReason) {
        let next_retry_count = self
            .retry_count_for_symbol(request.symbol_index)
            .max(request.retry_count)
            .saturating_add(1);
        self.symbol_retry_counts
            .insert(request.symbol_index, next_retry_count);
        self.record_rejection(request, reason);
    }

    /// Record a rejected symbol request for diagnostics while bounding the
    /// retained history. The lifetime count is tracked separately so progress
    /// statistics stay accurate even after older rejections are evicted.
    fn record_rejection(&mut self, request: RepairSymbolRequest, reason: RejectionReason) {
        self.rejected_total = self.rejected_total.saturating_add(1);
        self.rejected_requests.push_back((request, reason));
        while self.rejected_requests.len() > MAX_RETAINED_REJECTIONS {
            self.rejected_requests.pop_front();
        }
    }

    fn validate_received_symbol(
        &self,
        symbol_index: u32,
        _symbol_data: &[u8],
        from_peer: &PeerId,
    ) -> std::result::Result<(), RejectionReason> {
        // We must have an outstanding request for this symbol; otherwise it is
        // unsolicited (or a duplicate of one already resolved).
        let Some(request) = self.pending_requests.get(&symbol_index) else {
            return Err(RejectionReason::DuplicateSymbol);
        };

        // Bind the response to the peer the symbol was actually requested from.
        // Accepting a symbol from any other sender lets an attacker hijack an
        // honest peer's request and poison the decode matrix for that index.
        if &request.peer_id != from_peer {
            return Err(RejectionReason::MaliciousPeer {
                evidence: format!(
                    "symbol {symbol_index} was requested from {} but delivered by {}",
                    request.peer_id.as_string(),
                    from_peer.as_string()
                ),
            });
        }

        // The sender must be a registered peer. An unknown sender would
        // otherwise bypass trust gating entirely (the previous `if let Some`
        // silently skipped the trust check whenever the peer was absent).
        let Some(peer_info) = self.peers.get(from_peer) else {
            return Err(RejectionReason::MaliciousPeer {
                evidence: format!(
                    "symbol {symbol_index} delivered by unregistered peer {}",
                    from_peer.as_string()
                ),
            });
        };
        if peer_info.trust_score < 0.1 {
            return Err(RejectionReason::LowTrustScore {
                score: peer_info.trust_score,
                threshold: 0.1,
            });
        }

        // Additional validation would go here (manifest verification, etc.)
        Ok(())
    }

    fn update_peer_trust(&mut self, peer_id: &PeerId, successful: bool) {
        if let Some(peer_info) = self.peers.get_mut(peer_id) {
            if successful {
                peer_info.trust_score = (peer_info.trust_score * 0.95 + 0.05).min(1.0);
            } else {
                peer_info.trust_score *= self.config.trust_decay_factor;
            }
        }
    }

    fn expected_auth_domain(&self) -> String {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(b"asupersync.atp.repair.auth-domain.v1\0");
        hasher.update(self.object_id.hash_bytes());
        hasher.update((self.repair_group_id.len() as u64).to_le_bytes());
        hasher.update(self.repair_group_id.as_bytes());
        let digest: [u8; 32] = hasher.finalize().into();
        format!("atp-repair:{}", hex::encode(&digest[..12]))
    }
}

/// Result of processing a received symbol
#[derive(Debug)]
pub enum SymbolProcessResult {
    /// Symbol was accepted and contributed to decode
    Accepted {
        decode_contribution: f64,
        decode_complete: bool,
    },
    /// Symbol was rejected for the given reason
    Rejected { reason: RejectionReason },
}

/// Current decode progress information
#[derive(Debug, Clone)]
pub struct DecodeProgress {
    pub symbols_received: usize,
    pub symbols_needed: usize,
    pub decode_progress_ratio: f64,
    pub pending_requests: usize,
    pub active_peers: usize,
    pub rejected_symbols: usize,
}

/// Decode matrix for tracking RaptorQ symbol contributions
#[derive(Debug)]
pub struct DecodeMatrix {
    k_prime: u32,
    received_symbols: HashSet<u32>,
    decode_rank: usize,
    basis_rows: Vec<Vec<u64>>,
}

impl DecodeMatrix {
    fn new(k_prime: u32) -> Self {
        Self {
            k_prime,
            received_symbols: HashSet::new(),
            decode_rank: 0,
            basis_rows: vec![Vec::new(); k_prime as usize],
        }
    }

    fn add_symbol(&mut self, symbol_index: u32, symbol_data: &[u8]) -> Result<f64> {
        if self.k_prime == 0 {
            return Ok(0.0);
        }
        if self.received_symbols.insert(symbol_index) {
            let row = self.symbol_vector(symbol_index, symbol_data);
            let contribution = if self.insert_basis_row(row) {
                1.0 / self.k_prime as f64
            } else {
                0.0
            };
            Ok(contribution)
        } else {
            Ok(0.0)
        }
    }

    fn can_decode(&self) -> bool {
        self.decode_rank >= self.k_prime as usize
    }

    fn decode_progress(&self) -> f64 {
        if self.k_prime == 0 {
            return 1.0;
        }
        self.decode_rank as f64 / self.k_prime as f64
    }

    fn symbol_usefulness(&self, symbol_index: u32) -> f64 {
        if self.k_prime == 0 {
            return 0.0;
        }
        if self.received_symbols.contains(&symbol_index) {
            0.0 // Already have this symbol
        } else if self.can_decode() {
            0.1 // Minimal usefulness if we can already decode
        } else {
            // Higher usefulness if we're missing more symbols
            let missing_ratio = 1.0 - self.decode_progress();
            missing_ratio.max(0.1)
        }
    }

    fn symbol_vector(&self, symbol_index: u32, symbol_data: &[u8]) -> Vec<u64> {
        let width = self.k_prime as usize;
        let word_count = width.div_ceil(64);
        let mut row = vec![0u64; word_count];

        if symbol_index < self.k_prime {
            Self::set_bit(&mut row, symbol_index as usize);
            return row;
        }

        use sha2::{Digest, Sha256};

        let mut filled = 0usize;
        let mut counter = 0u64;
        while filled < word_count {
            let mut hasher = Sha256::new();
            hasher.update(b"asupersync.atp.repair.decode-row.v1\0");
            hasher.update(symbol_index.to_le_bytes());
            hasher.update(counter.to_le_bytes());
            hasher.update((symbol_data.len() as u64).to_le_bytes());
            hasher.update(symbol_data);
            let digest: [u8; 32] = hasher.finalize().into();
            for chunk in digest.chunks_exact(8) {
                if filled == word_count {
                    break;
                }
                let mut word = [0u8; 8];
                word.copy_from_slice(chunk);
                row[filled] = u64::from_le_bytes(word);
                filled += 1;
            }
            counter = counter.saturating_add(1);
        }

        let extra_bits = word_count * 64 - width;
        if extra_bits > 0 {
            let keep_bits = 64 - extra_bits;
            if let Some(last) = row.last_mut() {
                *last &= (1u64 << keep_bits).saturating_sub(1);
            }
        }

        if row.iter().all(|word| *word == 0) {
            Self::set_bit(&mut row, symbol_index as usize % width);
        }

        row
    }

    fn insert_basis_row(&mut self, mut row: Vec<u64>) -> bool {
        for pivot in 0..self.k_prime as usize {
            if !Self::bit_is_set(&row, pivot) {
                continue;
            }
            if self.basis_rows[pivot].is_empty() {
                self.basis_rows[pivot] = row;
                self.decode_rank += 1;
                return true;
            }
            for (word, basis_word) in row.iter_mut().zip(&self.basis_rows[pivot]) {
                *word ^= *basis_word;
            }
        }
        false
    }

    fn set_bit(row: &mut [u64], index: usize) {
        let word = index / 64;
        let bit = index % 64;
        if let Some(value) = row.get_mut(word) {
            *value |= 1u64 << bit;
        }
    }

    fn bit_is_set(row: &[u64], index: usize) -> bool {
        let word = index / 64;
        let bit = index % 64;
        row.get(word)
            .is_some_and(|value| value & (1u64 << bit) != 0)
    }
}

#[cfg(test)]
#[path = "repair_scheduler_inline_tests.rs"]
mod tests;
