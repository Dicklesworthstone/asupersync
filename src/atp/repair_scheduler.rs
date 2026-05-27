//! Multi-source RaptorQ repair scheduling for ATP swarm transfers.
//!
//! Implements peer scoring, symbol usefulness evaluation, and scheduling algorithms
//! for efficient repair symbol collection from multiple sources in ATP swarm mode.

use crate::atp::object::ObjectId;
use crate::error::Result;
use crate::error::{Error, ErrorKind};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::SocketAddr;
use std::time::{Duration, SystemTime};
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
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
    pub last_seen: SystemTime,
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
    pub requested_at: SystemTime,
    /// Expected usefulness for decode progress
    pub decode_usefulness: f64,
    /// Number of retries so far
    pub retry_count: u32,
    /// Timeout timestamp
    pub timeout_at: SystemTime,
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

/// Multi-source repair scheduler for RaptorQ symbols
#[derive(Debug)]
pub struct MultiSourceRepairScheduler {
    config: RepairSchedulerConfig,
    #[allow(dead_code)]
    object_id: ObjectId,
    #[allow(dead_code)]
    repair_group_id: String,
    k_prime: u32, // Number of source symbols needed
    peers: HashMap<PeerId, PeerInfo>,
    received_symbols: HashSet<u32>,
    pending_requests: HashMap<u32, RepairSymbolRequest>,
    rejected_requests: Vec<(RepairSymbolRequest, RejectionReason)>,
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
            peers: HashMap::new(),
            received_symbols: HashSet::new(),
            pending_requests: HashMap::new(),
            rejected_requests: Vec::new(),
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

        // Update symbol rarity map
        self.update_symbol_rarity(&peer_info.available_symbols);

        self.peers.insert(peer_info.peer_id.clone(), peer_info);
        Ok(())
    }

    /// Remove a peer from the scheduler
    pub fn unregister_peer(&mut self, peer_id: &PeerId) {
        if let Some(_peer_info) = self.peers.remove(peer_id) {
            info!("Unregistering peer {}", peer_id.as_string());

            // Cancel any pending requests from this peer
            self.pending_requests
                .retain(|_, request| request.peer_id != *peer_id);

            // Update symbol rarity after peer removal
            self.recalculate_symbol_rarity();
        }
    }

    /// Schedule next batch of symbol requests based on current decode state
    pub fn schedule_next_batch(&mut self) -> Result<Vec<RepairSymbolRequest>> {
        let mut requests = Vec::new();
        let now = SystemTime::now();

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

        // Schedule requests using peer scores and symbol usefulness
        for symbol_index in useful_symbols {
            if let Some(best_peer) = self.select_best_peer_for_symbol(symbol_index, &peer_scores) {
                let decode_usefulness = self.calculate_symbol_decode_usefulness(symbol_index);

                let request = RepairSymbolRequest {
                    symbol_index,
                    peer_id: best_peer.clone(),
                    requested_at: now,
                    decode_usefulness,
                    retry_count: 0,
                    timeout_at: now + self.config.symbol_timeout_duration,
                };

                requests.push(request.clone());
                self.pending_requests.insert(symbol_index, request);

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

            // Record rejection
            if let Some(request) = self.pending_requests.remove(&symbol_index) {
                self.rejected_requests.push((request, reason.clone()));
            }

            // Update peer trust if malicious behavior detected
            if matches!(reason, RejectionReason::MaliciousPeer { .. }) {
                self.update_peer_trust(from_peer, false);
            }

            return Ok(SymbolProcessResult::Rejected { reason });
        }

        // Accept the symbol
        self.received_symbols.insert(symbol_index);
        self.pending_requests.remove(&symbol_index);

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
            rejected_symbols: self.rejected_requests.len(),
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
        let relay_cost = 1.0 - (peer_info.relay_cost_per_byte * 1000.0).min(1.0); // Invert and normalize
        let churn_stability = 1.0 - peer_info.churn_probability;

        weights.path_quality * path_quality
            + weights.upload_budget * upload_budget
            + weights.symbol_rarity * symbol_rarity
            + weights.decode_usefulness * decode_usefulness
            + weights.trust * trust
            + weights.relay_cost * relay_cost
            + weights.churn_probability * churn_stability
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
    ) -> Option<PeerId> {
        let mut best_peer = None;
        let mut best_score = 0.0;

        for (peer_id, peer_info) in &self.peers {
            if !peer_info.available_symbols.contains(&symbol_index) {
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

    /// Update symbol rarity map when peers change
    fn update_symbol_rarity(&mut self, symbols: &BTreeSet<u32>) {
        for &symbol in symbols {
            let peer_count = self
                .peers
                .values()
                .filter(|peer| peer.available_symbols.contains(&symbol))
                .count() as f64
                + 1.0; // +1 for the new peer

            // Rarity is inverse of availability (rare = fewer peers have it)
            let rarity = 1.0 / peer_count;
            self.symbol_rarity_map.insert(symbol, rarity);
        }
    }

    /// Recalculate symbol rarity for all symbols
    fn recalculate_symbol_rarity(&mut self) {
        let mut all_symbols = HashSet::new();
        for peer in self.peers.values() {
            all_symbols.extend(&peer.available_symbols);
        }

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
        symbol_usefulness.dedup_by_key(|&mut (symbol, _)| symbol);

        symbol_usefulness
            .into_iter()
            .take(count)
            .map(|(symbol, _)| symbol)
            .collect()
    }

    // Additional helper methods...
    fn calculate_symbols_needed(&self) -> usize {
        (self.k_prime as usize).saturating_sub(self.received_symbols.len())
    }

    fn calculate_symbol_decode_usefulness(&self, symbol_index: u32) -> f64 {
        self.decode_matrix.symbol_usefulness(symbol_index)
    }

    fn cleanup_timed_out_requests(&mut self, now: SystemTime) {
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

                let reason = RejectionReason::StaleSymbol {
                    age_ms: now
                        .duration_since(request.requested_at)
                        .unwrap_or_default()
                        .as_millis() as u64,
                };
                self.rejected_requests.push((request, reason));
            }
        }
    }

    fn validate_received_symbol(
        &self,
        symbol_index: u32,
        _symbol_data: &[u8],
        from_peer: &PeerId,
    ) -> std::result::Result<(), RejectionReason> {
        // Check if we were expecting this symbol
        if !self.pending_requests.contains_key(&symbol_index) {
            return Err(RejectionReason::DuplicateSymbol);
        }

        // Check peer trust
        if let Some(peer_info) = self.peers.get(from_peer) {
            if peer_info.trust_score < 0.1 {
                return Err(RejectionReason::LowTrustScore {
                    score: peer_info.trust_score,
                    threshold: 0.1,
                });
            }
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
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn create_test_peer_id(port: u16) -> PeerId {
        PeerId::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
            [port as u8; 32],
        )
    }

    fn create_test_peer_info(
        scheduler: &MultiSourceRepairScheduler,
        peer_id: PeerId,
        symbols: Vec<u32>,
    ) -> PeerInfo {
        PeerInfo {
            peer_id,
            available_symbols: symbols.into_iter().collect(),
            path_quality: PathQuality {
                latency_ms: 50.0,
                bandwidth_bps: 1_000_000,
                loss_rate: 0.01,
                jitter_ms: 5.0,
            },
            upload_budget_bytes: 1_000_000,
            trust_score: 0.8,
            relay_cost_per_byte: 0.001,
            churn_probability: 0.1,
            last_seen: SystemTime::now(),
            auth_domain: scheduler.expected_auth_domain(),
        }
    }

    #[test]
    fn test_repair_scheduler_creation() {
        let scheduler = MultiSourceRepairScheduler::new(
            RepairSchedulerConfig::default(),
            crate::atp::object::ObjectId::content(crate::atp::object::ContentId::new([1u8; 32])),
            "test-group".to_string(),
            10,
        );

        assert_eq!(scheduler.k_prime, 10);
        assert!(scheduler.peers.is_empty());
    }

    #[test]
    fn test_peer_registration() {
        let mut scheduler = MultiSourceRepairScheduler::new(
            RepairSchedulerConfig::default(),
            crate::atp::object::ObjectId::content(crate::atp::object::ContentId::new([1u8; 32])),
            "test-group".to_string(),
            10,
        );

        let peer_id = create_test_peer_id(8001);
        let peer_info = create_test_peer_info(&scheduler, peer_id.clone(), vec![1, 2, 3, 4, 5]);

        assert!(scheduler.register_peer(peer_info).is_ok());
        assert!(scheduler.peers.contains_key(&peer_id));
    }

    #[test]
    fn test_peer_scoring() {
        let mut scheduler = MultiSourceRepairScheduler::new(
            RepairSchedulerConfig::default(),
            crate::atp::object::ObjectId::content(crate::atp::object::ContentId::new([1u8; 32])),
            "test-group".to_string(),
            10,
        );

        // Add peers with different qualities
        let high_quality_peer = create_test_peer_id(8001);
        let high_quality_info =
            create_test_peer_info(&scheduler, high_quality_peer.clone(), vec![1, 2, 3]);

        let low_quality_peer = create_test_peer_id(8002);
        let mut low_quality_info =
            create_test_peer_info(&scheduler, low_quality_peer.clone(), vec![4, 5, 6]);
        low_quality_info.path_quality.latency_ms = 200.0;
        low_quality_info.trust_score = 0.3;

        scheduler.register_peer(high_quality_info).unwrap();
        scheduler.register_peer(low_quality_info).unwrap();

        let scores = scheduler.calculate_peer_scores();

        let high_score = scores.get(&high_quality_peer).unwrap();
        let low_score = scores.get(&low_quality_peer).unwrap();

        assert!(
            high_score > low_score,
            "High quality peer should have better score"
        );
    }

    #[test]
    fn test_symbol_rarity_calculation() {
        let mut scheduler = MultiSourceRepairScheduler::new(
            RepairSchedulerConfig::default(),
            crate::atp::object::ObjectId::content(crate::atp::object::ContentId::new([1u8; 32])),
            "test-group".to_string(),
            10,
        );

        // Peer 1 has symbols 1, 2, 3
        let peer1 = create_test_peer_info(&scheduler, create_test_peer_id(8001), vec![1, 2, 3]);
        // Peer 2 has symbols 2, 3, 4 (symbol 2 and 3 are common)
        let peer2 = create_test_peer_info(&scheduler, create_test_peer_id(8002), vec![2, 3, 4]);

        scheduler.register_peer(peer1).unwrap();
        scheduler.register_peer(peer2).unwrap();

        // Symbol 1 should be rarer (only peer1 has it)
        let rarity_1 = scheduler.symbol_rarity_map.get(&1).unwrap();
        let rarity_2 = scheduler.symbol_rarity_map.get(&2).unwrap();

        assert!(
            rarity_1 > rarity_2,
            "Symbol 1 should be rarer than symbol 2"
        );
    }

    #[test]
    fn test_symbol_request_scheduling() {
        let mut scheduler = MultiSourceRepairScheduler::new(
            RepairSchedulerConfig::default(),
            crate::atp::object::ObjectId::content(crate::atp::object::ContentId::new([1u8; 32])),
            "test-group".to_string(),
            5,
        );

        let peer_info =
            create_test_peer_info(&scheduler, create_test_peer_id(8001), vec![1, 2, 3, 4, 5]);
        scheduler.register_peer(peer_info).unwrap();

        let requests = scheduler.schedule_next_batch().unwrap();

        assert!(!requests.is_empty(), "Should schedule some requests");
        assert!(requests.len() <= 5, "Should not request more than needed");
    }

    #[test]
    fn test_symbol_processing() {
        let mut scheduler = MultiSourceRepairScheduler::new(
            RepairSchedulerConfig::default(),
            crate::atp::object::ObjectId::content(crate::atp::object::ContentId::new([1u8; 32])),
            "test-group".to_string(),
            3,
        );

        let peer_id = create_test_peer_id(8001);
        let peer_info = create_test_peer_info(&scheduler, peer_id.clone(), vec![1, 2, 3]);
        scheduler.register_peer(peer_info).unwrap();

        // Schedule a request
        let requests = scheduler.schedule_next_batch().unwrap();
        assert!(!requests.is_empty());

        // Process received symbol
        let symbol_data = vec![0u8; 100];
        let result = scheduler
            .process_received_symbol(1, &symbol_data, &peer_id)
            .unwrap();

        match result {
            SymbolProcessResult::Accepted {
                decode_contribution,
                ..
            } => {
                assert!(decode_contribution > 0.0);
            }
            SymbolProcessResult::Rejected { .. } => {
                panic!("Symbol should have been accepted");
            }
        }

        assert!(scheduler.received_symbols.contains(&1));
    }

    #[test]
    fn test_decode_progress() {
        let mut scheduler = MultiSourceRepairScheduler::new(
            RepairSchedulerConfig::default(),
            crate::atp::object::ObjectId::content(crate::atp::object::ContentId::new([1u8; 32])),
            "test-group".to_string(),
            3,
        );

        let progress = scheduler.get_decode_progress();
        assert_eq!(progress.symbols_received, 0);
        assert_eq!(progress.symbols_needed, 3);
        assert!(!scheduler.is_decode_complete());

        // Add some symbols
        scheduler.received_symbols.insert(1);
        scheduler.decode_matrix.add_symbol(1, &[0u8; 100]).unwrap();

        let progress = scheduler.get_decode_progress();
        assert_eq!(progress.symbols_received, 1);
        assert!(progress.decode_progress_ratio > 0.0);
    }
}
