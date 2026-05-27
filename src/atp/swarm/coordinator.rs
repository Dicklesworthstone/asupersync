//! ATP Swarm Coordinator - Orchestrates multi-peer transfer coordination.
//!
//! The SwarmCoordinator manages piece requests, peer quality assessment,
//! and transfer optimization across multiple peers in the swarm.

use super::{
    MailboxTransferId, PeerId, PeerQuality, PeerSelector, PieceAssignment, PieceId, PieceMap,
    PieceSelectionStrategy, PieceTracker, QualityMetrics, SwarmConfig, SwarmError, SwarmEvent,
    SwarmPeer, SwarmQualityMetrics, SwarmResult, SwarmTransferStatus, swarm_time_now,
};
use crate::cx::Cx;
use crate::types::Time;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

/// Central coordinator for swarm-based transfers.
#[derive(Debug)]
pub struct SwarmCoordinator {
    /// Configuration for swarm behavior
    config: SwarmConfig,

    /// Active transfers being coordinated
    active_transfers: HashMap<MailboxTransferId, SwarmTransfer>,

    /// Known peers in the swarm
    peers: HashMap<PeerId, SwarmPeer>,

    /// Piece selection strategy instance
    strategy: Box<dyn PiecePicker + Send + Sync>,

    /// Peer quality assessor
    peer_selector: PeerSelector,

    /// Piece availability tracker
    piece_tracker: PieceTracker,

    /// Quality metrics collector
    quality_metrics: QualityMetrics,

    /// Event sink for observability
    event_sink: Option<crate::channel::mpsc::Sender<SwarmEvent>>,
}

/// Internal representation of an active swarm transfer.
#[derive(Debug)]
struct SwarmTransfer {
    /// Transfer metadata
    metadata: SwarmTransferMetadata,

    /// Current transfer status
    status: SwarmTransferStatus,

    /// Active piece requests
    active_requests: HashMap<PieceId, PieceRequest>,

    /// Completed pieces
    completed_pieces: HashSet<PieceId>,

    /// Transfer start time
    started_at: Instant,

    /// Last activity timestamp
    last_activity: Instant,
}

/// Metadata for a swarm transfer.
#[derive(Debug, Clone)]
struct SwarmTransferMetadata {
    /// Object being transferred
    object_id: String,

    /// Total size of the object
    total_size: u64,

    /// Number of pieces required
    piece_count: u64,

    /// Piece size for this transfer
    piece_size: u32,

    /// Content hash for verification
    content_hash: String,
}

/// Active piece request tracking.
#[derive(Debug)]
struct PieceRequest {
    /// Target peer for this request
    peer_id: PeerId,

    /// Request start time
    requested_at: Instant,

    /// Request timeout
    timeout: Instant,

    /// Retry count
    retry_count: u32,

    /// Priority level
    priority: u32,
}

impl SwarmCoordinator {
    /// Create a new swarm coordinator with the given configuration.
    pub fn new(config: SwarmConfig) -> Self {
        let strategy = match config.piece_selection_strategy {
            PieceSelectionStrategy::RarestFirst => {
                Box::new(RarestFirstStrategy::new()) as Box<dyn PiecePicker + Send + Sync>
            }
            PieceSelectionStrategy::Sequential => {
                Box::new(SequentialStrategy::new()) as Box<dyn PiecePicker + Send + Sync>
            }
            PieceSelectionStrategy::Random => {
                Box::new(RandomStrategy::new()) as Box<dyn PiecePicker + Send + Sync>
            }
            PieceSelectionStrategy::Adaptive => {
                Box::new(AdaptiveStrategy::new()) as Box<dyn PiecePicker + Send + Sync>
            }
            PieceSelectionStrategy::Endgame => {
                Box::new(EndgameStrategy::new()) as Box<dyn PiecePicker + Send + Sync>
            }
        };

        Self {
            config,
            active_transfers: HashMap::new(),
            peers: HashMap::new(),
            strategy,
            peer_selector: PeerSelector::new(),
            piece_tracker: PieceTracker::new(),
            quality_metrics: QualityMetrics::new(),
            event_sink: None,
        }
    }

    /// Set event sink for observability.
    pub fn set_event_sink(&mut self, sink: crate::channel::mpsc::Sender<SwarmEvent>) {
        self.event_sink = Some(sink);
    }

    /// Start a new swarm transfer.
    pub async fn start_swarm_transfer(
        &mut self,
        cx: &Cx,
        object_id: String,
        total_size: u64,
        piece_count: u64,
        available_peers: Vec<SwarmPeer>,
        piece_map: PieceMap,
    ) -> SwarmResult<MailboxTransferId> {
        let transfer_id = MailboxTransferId::new();

        // Validate configuration
        if available_peers.is_empty() {
            return Err(SwarmError::NoPeersAvailable {
                details: "No peers provided for transfer".to_string(),
            });
        }

        if piece_count == 0 {
            return Err(SwarmError::ConfigurationError {
                details: "swarm transfer requires at least one piece".to_string(),
            });
        }

        if available_peers.len() > self.config.max_peers {
            cx.trace("Too many peers provided, selecting subset");
        }

        // Select optimal peer subset
        let selected_peers = self.peer_selector.select_peers(
            &available_peers,
            self.config.max_peers,
            self.config.peer_quality_threshold,
        )?;

        // Add peers to coordinator
        for peer in selected_peers {
            self.add_peer(cx, peer.clone()).await?;
        }

        // Initialize piece tracker
        self.piece_tracker
            .initialize_transfer(&transfer_id, &piece_map)?;

        // Create transfer metadata
        let piece_size = if piece_map.piece_size == 0 {
            total_size
                .saturating_add(piece_count - 1)
                .checked_div(piece_count)
                .unwrap_or(1)
                .clamp(1, u64::from(u32::MAX)) as u32
        } else {
            piece_map.piece_size
        };
        let content_hash = if piece_map.content_hash.is_empty() {
            Self::derive_content_hash(&object_id, total_size, piece_count, piece_size)
        } else {
            piece_map.content_hash.clone()
        };

        let metadata = SwarmTransferMetadata {
            object_id: object_id.clone(),
            total_size,
            piece_count,
            piece_size,
            content_hash,
        };

        // Create transfer status
        let status = SwarmTransferStatus {
            transfer_id,
            total_pieces: piece_count,
            completed_pieces: 0,
            pending_pieces: 0,
            remaining_pieces: piece_count,
            active_peers: self.peers.clone(),
            download_rate: 0.0,
            upload_rate: 0.0,
            estimated_completion: None,
            quality_metrics: SwarmQualityMetrics {
                avg_peer_response_time: Duration::from_secs(1),
                verification_failure_rate: 0.0,
                peer_churn_rate: 0.0,
                avg_piece_redundancy: available_peers.len() as f64,
                incentive_balance_score: 1.0,
                health_score: 1.0,
            },
        };

        // Create internal transfer
        let transfer = SwarmTransfer {
            metadata,
            status,
            active_requests: HashMap::new(),
            completed_pieces: HashSet::new(),
            started_at: Instant::now(),
            last_activity: Instant::now(),
        };

        self.active_transfers.insert(transfer_id, transfer);
        self.quality_metrics.start_transfer_tracking(transfer_id);

        // Emit start event
        self.emit_event(
            cx,
            SwarmEvent::TransferStarted {
                transfer_id,
                object_id,
                total_pieces: piece_count,
                peer_count: self.peers.len(),
            },
        )
        .await;

        cx.trace(&format!(
            "Started swarm transfer {} with {} peers",
            transfer_id,
            self.peers.len()
        ));

        Ok(transfer_id)
    }

    /// Add a peer to the swarm.
    pub async fn add_peer(&mut self, cx: &Cx, peer: SwarmPeer) -> SwarmResult<()> {
        let peer_id = peer.peer_id.clone();

        // Validate peer quality
        if peer.quality.overall_score < self.config.peer_quality_threshold {
            return Err(SwarmError::PeerQualityBelowThreshold {
                peer_id,
                quality: peer.quality.overall_score,
                threshold: self.config.peer_quality_threshold,
            });
        }

        let is_new_peer = !self.peers.contains_key(&peer_id);
        if is_new_peer {
            self.quality_metrics.start_peer_tracking(peer_id.clone());
        }
        self.emit_event(
            cx,
            SwarmEvent::PeerJoined {
                peer_id: peer_id.clone(),
                available_pieces: peer.available_pieces.clone(),
                capabilities: peer.capabilities.clone(),
            },
        )
        .await;

        self.peers.insert(peer_id, peer);
        Ok(())
    }

    /// Remove a peer from the swarm.
    pub async fn remove_peer(
        &mut self,
        cx: &Cx,
        peer_id: &PeerId,
        reason: String,
    ) -> SwarmResult<()> {
        if let Some(peer) = self.peers.remove(peer_id) {
            let contributed_pieces = peer.available_pieces.len() as u64;
            self.quality_metrics.remove_peer_tracking(peer_id);

            // Emit leave event
            self.emit_event(
                cx,
                SwarmEvent::PeerLeft {
                    peer_id: peer_id.clone(),
                    reason,
                    contributed_pieces,
                },
            )
            .await;
        }

        Ok(())
    }

    /// Generate piece assignments for active transfers.
    pub async fn assign_pieces(
        &mut self,
        cx: &Cx,
        transfer_id: &MailboxTransferId,
    ) -> SwarmResult<Vec<PieceAssignment>> {
        if !self.active_transfers.contains_key(transfer_id) {
            return Err(SwarmError::TransferNotFound {
                transfer_id: *transfer_id,
            });
        }

        // Get pieces that need to be requested
        let needed_pieces = self.piece_tracker.get_needed_pieces(transfer_id)?;
        if needed_pieces.is_empty() {
            return Ok(Vec::new());
        }

        let assignment_budget = self
            .config
            .max_pieces_per_peer
            .saturating_mul(self.peers.len().max(1));

        // Select pieces using strategy
        let selected_pieces =
            self.strategy
                .select_pieces(&needed_pieces, &self.peers, assignment_budget)?;

        let mut assignments = Vec::new();
        let now = swarm_time_now();

        for piece_id in selected_pieces {
            let active_loads = self.active_loads_for_transfer(transfer_id)?;
            let peer_id =
                self.peer_selector
                    .select_peer_for_piece(&piece_id, &self.peers, &active_loads)?;

            let priority = {
                let transfer =
                    self.active_transfers
                        .get(transfer_id)
                        .ok_or(SwarmError::TransferNotFound {
                            transfer_id: *transfer_id,
                        })?;
                self.calculate_piece_priority(&piece_id, transfer)
            };

            let assignment = PieceAssignment {
                peer_id: peer_id.clone(),
                piece_id,
                priority,
                estimated_completion: Time::from_nanos(
                    now.as_nanos() + 30_000_000_000, // 30 seconds default
                ),
                retry_count: 0,
                assigned_at: now,
            };

            // Track the request
            let request = PieceRequest {
                peer_id: peer_id.clone(),
                requested_at: Instant::now(),
                timeout: Instant::now() + self.config.piece_request_timeout,
                retry_count: 0,
                priority: assignment.priority,
            };

            if let Some(transfer) = self.active_transfers.get_mut(transfer_id) {
                transfer.active_requests.insert(piece_id, request);
                transfer.status.pending_pieces = transfer.active_requests.len() as u64;
                transfer.last_activity = Instant::now();
            }
            if let Some(peer) = self.peers.get_mut(&peer_id) {
                peer.pending_requests.insert(piece_id);
            }
            self.piece_tracker
                .mark_piece_requested(transfer_id, piece_id, peer_id.clone())?;
            let event_priority = assignment.priority;
            assignments.push(assignment);

            // Emit request event
            self.emit_event(
                cx,
                SwarmEvent::PieceRequested {
                    peer_id,
                    piece_id,
                    priority: event_priority,
                },
            )
            .await;
        }

        cx.trace(&format!(
            "Generated {} piece assignments for transfer {}",
            assignments.len(),
            transfer_id
        ));

        Ok(assignments)
    }

    /// Mark a piece as received and verified.
    pub async fn mark_piece_received(
        &mut self,
        cx: &Cx,
        transfer_id: &MailboxTransferId,
        piece_id: PieceId,
        peer_id: &PeerId,
        verification_status: String,
    ) -> SwarmResult<()> {
        let (
            download_time,
            piece_size,
            transfer_complete,
            total_pieces,
            duration,
            object_id,
            total_size,
            content_hash,
        ) = {
            let transfer =
                self.active_transfers
                    .get_mut(transfer_id)
                    .ok_or(SwarmError::TransferNotFound {
                        transfer_id: *transfer_id,
                    })?;

            let request = transfer.active_requests.remove(&piece_id);
            let download_time = request
                .as_ref()
                .map_or(Duration::from_secs(0), |r| r.requested_at.elapsed());

            transfer.completed_pieces.insert(piece_id);
            transfer.status.completed_pieces = transfer.completed_pieces.len() as u64;
            transfer.status.pending_pieces = transfer.active_requests.len() as u64;
            transfer.status.remaining_pieces = transfer
                .status
                .total_pieces
                .saturating_sub(transfer.status.completed_pieces);
            transfer.last_activity = Instant::now();

            (
                download_time,
                transfer.metadata.piece_size,
                transfer.status.remaining_pieces == 0,
                transfer.status.total_pieces,
                transfer.started_at.elapsed(),
                transfer.metadata.object_id.clone(),
                transfer.metadata.total_size,
                transfer.metadata.content_hash.clone(),
            )
        };

        // Update piece tracker
        self.piece_tracker
            .mark_piece_completed(transfer_id, piece_id)?;
        self.quality_metrics
            .record_verification_success(transfer_id);
        self.quality_metrics
            .record_peer_response_time(transfer_id, peer_id, download_time);

        if let Some(peer) = self.peers.get_mut(peer_id) {
            peer.pending_requests.remove(&piece_id);
            peer.quality.successful_transfers = peer.quality.successful_transfers.saturating_add(1);

            if download_time > Duration::ZERO && piece_size > 0 {
                let bytes_per_sec = f64::from(piece_size) / download_time.as_secs_f64().max(0.001);
                peer.quality.download_speed =
                    (peer.quality.download_speed * 0.8) + (bytes_per_sec * 0.2);
                self.quality_metrics
                    .record_peer_download_speed(peer_id, bytes_per_sec);
            }
            peer.quality.overall_score = Self::calculate_peer_score(&peer.quality);
        }

        // Emit completion event
        self.emit_event(
            cx,
            SwarmEvent::PieceReceived {
                peer_id: peer_id.clone(),
                piece_id,
                verification_status,
                download_time,
            },
        )
        .await;

        // Check if transfer is complete
        if transfer_complete {
            cx.trace(&format!(
                "Completed swarm transfer {transfer_id} for object {object_id} ({total_size} bytes, {content_hash})"
            ));
            self.emit_event(
                cx,
                SwarmEvent::TransferCompleted {
                    transfer_id: *transfer_id,
                    duration,
                    total_pieces,
                    peer_count: self.peers.len(),
                    avg_quality: self.calculate_average_peer_quality(),
                },
            )
            .await;
            self.quality_metrics.complete_transfer_tracking(transfer_id);
        }

        Ok(())
    }

    /// Handle piece verification failure.
    pub async fn handle_piece_verification_failed(
        &mut self,
        cx: &Cx,
        transfer_id: &MailboxTransferId,
        piece_id: PieceId,
        peer_id: &PeerId,
        error: String,
    ) -> SwarmResult<()> {
        let base_timeout = self.config.piece_request_timeout;
        let retry_remaining = {
            let transfer =
                self.active_transfers
                    .get_mut(transfer_id)
                    .ok_or(SwarmError::TransferNotFound {
                        transfer_id: *transfer_id,
                    })?;

            let mut retry_remaining = false;
            if let Some(mut request) = transfer.active_requests.remove(&piece_id) {
                request.retry_count = request.retry_count.saturating_add(1);

                if request.retry_count < 3 {
                    request.requested_at = Instant::now();
                    request.timeout =
                        Instant::now() + base_timeout.mul_f64(1.0 + f64::from(request.retry_count));
                    request.priority = request.priority.saturating_add(25);
                    transfer.active_requests.insert(piece_id, request);
                    retry_remaining = true;
                }
            }
            transfer.status.pending_pieces = transfer.active_requests.len() as u64;
            transfer.last_activity = Instant::now();
            retry_remaining
        };

        if !retry_remaining {
            self.piece_tracker
                .mark_piece_failed(transfer_id, piece_id, error.clone())?;
        }
        self.quality_metrics
            .record_verification_failure(transfer_id);

        // Update peer quality
        if let Some(peer) = self.peers.get_mut(peer_id) {
            if !retry_remaining {
                peer.pending_requests.remove(&piece_id);
            }
            peer.quality.verification_failures =
                peer.quality.verification_failures.saturating_add(1);
            peer.quality.failed_transfers = peer.quality.failed_transfers.saturating_add(1);
            peer.quality.overall_score = Self::calculate_peer_score(&peer.quality);
        }

        // Emit failure event
        self.emit_event(
            cx,
            SwarmEvent::PieceVerificationFailed {
                peer_id: peer_id.clone(),
                piece_id,
                error_details: error,
            },
        )
        .await;

        Ok(())
    }

    /// Get current status of a transfer.
    pub fn get_transfer_status(
        &self,
        transfer_id: &MailboxTransferId,
    ) -> Option<&SwarmTransferStatus> {
        self.active_transfers.get(transfer_id).map(|t| &t.status)
    }

    /// Check for timeouts and handle cleanup.
    pub async fn process_timeouts(&mut self, cx: &Cx) -> SwarmResult<()> {
        let now = Instant::now();
        let mut timed_out_requests = Vec::new();

        for (transfer_id, transfer) in &mut self.active_transfers {
            let mut expired_requests = Vec::new();

            for (piece_id, request) in &transfer.active_requests {
                if now > request.timeout {
                    expired_requests.push(*piece_id);
                }
            }

            for piece_id in expired_requests {
                if let Some(request) = transfer.active_requests.remove(&piece_id) {
                    timed_out_requests.push((*transfer_id, piece_id, request.peer_id.clone()));
                }
            }
        }

        let timed_out_count = timed_out_requests.len();
        for (transfer_id, piece_id, peer_id) in timed_out_requests {
            self.handle_piece_verification_failed(
                cx,
                &transfer_id,
                piece_id,
                &peer_id,
                "Request timeout".to_string(),
            )
            .await?;
        }

        if timed_out_count > 0 {
            cx.trace(&format!("Processed {} timed out requests", timed_out_count));
        }

        Ok(())
    }

    /// Calculate priority for a piece from rarity, retry pressure, and transfer frontier.
    fn calculate_piece_priority(&self, piece_id: &PieceId, transfer: &SwarmTransfer) -> u32 {
        let availability = self
            .peers
            .values()
            .filter(|peer| peer.available_pieces.contains(piece_id))
            .count() as u32;
        let rarity_boost = match availability {
            0 => 0,
            1 => 600,
            2 => 350,
            3 => 200,
            _ => 100,
        };

        let retry_boost = transfer
            .active_requests
            .get(piece_id)
            .map_or(0, |request| request.retry_count.saturating_mul(75));

        let frontier_boost = if transfer.completed_pieces.is_empty() {
            transfer
                .metadata
                .piece_count
                .saturating_sub(piece_id.as_u64())
                .min(100) as u32
        } else {
            let next_frontier = (0..transfer.metadata.piece_count)
                .map(PieceId::new)
                .find(|candidate| !transfer.completed_pieces.contains(candidate))
                .unwrap_or(*piece_id);
            let distance = piece_id.as_u64().abs_diff(next_frontier.as_u64());
            100_u32.saturating_sub(distance.min(100) as u32)
        };

        let active_penalty = if transfer.active_requests.contains_key(piece_id) {
            150
        } else {
            0
        };

        100_u32
            .saturating_add(rarity_boost)
            .saturating_add(retry_boost)
            .saturating_add(frontier_boost)
            .saturating_sub(active_penalty)
    }

    /// Calculate average peer quality across the swarm.
    fn calculate_average_peer_quality(&self) -> f64 {
        if self.peers.is_empty() {
            return 0.0;
        }

        let total: f64 = self
            .peers
            .values()
            .map(|peer| peer.quality.overall_score)
            .sum();

        total / self.peers.len() as f64
    }

    /// Calculate peer score based on quality metrics.
    fn calculate_peer_score(quality: &PeerQuality) -> f64 {
        let total_transfers = quality
            .successful_transfers
            .saturating_add(quality.failed_transfers);
        let observed_success = if total_transfers == 0 {
            quality.reliability
        } else {
            quality.successful_transfers as f64 / total_transfers as f64
        };
        let verification_score = 1.0
            / (1.0
                + quality.verification_failures as f64
                    / quality.successful_transfers.saturating_add(1) as f64);
        let latency_score = (1.0 / (1.0 + quality.avg_response_time.as_secs_f64())).clamp(0.0, 1.0);
        let download_score = (quality.download_speed / 10_000_000.0).clamp(0.0, 1.0);
        let upload_score = (quality.upload_speed / 10_000_000.0).clamp(0.0, 1.0);

        (observed_success * 0.30
            + quality.reliability.clamp(0.0, 1.0) * 0.20
            + verification_score * 0.20
            + latency_score * 0.15
            + download_score * 0.10
            + upload_score * 0.05)
            .clamp(0.0, 1.0)
    }

    fn active_loads_for_transfer(
        &self,
        transfer_id: &MailboxTransferId,
    ) -> SwarmResult<HashMap<PeerId, usize>> {
        let transfer =
            self.active_transfers
                .get(transfer_id)
                .ok_or(SwarmError::TransferNotFound {
                    transfer_id: *transfer_id,
                })?;

        let mut loads = HashMap::new();
        for request in transfer.active_requests.values() {
            *loads.entry(request.peer_id.clone()).or_insert(0) += 1;
        }
        Ok(loads)
    }

    fn derive_content_hash(
        object_id: &str,
        total_size: u64,
        piece_count: u64,
        piece_size: u32,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(object_id.as_bytes());
        hasher.update(total_size.to_le_bytes());
        hasher.update(piece_count.to_le_bytes());
        hasher.update(piece_size.to_le_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }

    /// Emit an event to the event sink.
    async fn emit_event(&self, cx: &Cx, event: SwarmEvent) {
        if let Some(ref sink) = self.event_sink {
            let _ = sink.send(cx, event).await;
        }
    }
}

#[derive(Debug)]
struct RarestFirstStrategy;
#[derive(Debug)]
struct SequentialStrategy;
#[derive(Debug)]
struct RandomStrategy;
#[derive(Debug)]
struct AdaptiveStrategy;
#[derive(Debug)]
struct EndgameStrategy;

impl RarestFirstStrategy {
    fn new() -> Self {
        Self
    }
}

impl SequentialStrategy {
    fn new() -> Self {
        Self
    }
}

impl RandomStrategy {
    fn new() -> Self {
        Self
    }
}

impl AdaptiveStrategy {
    fn new() -> Self {
        Self
    }
}

impl EndgameStrategy {
    fn new() -> Self {
        Self
    }
}

trait PiecePicker: std::fmt::Debug {
    fn select_pieces(
        &self,
        needed_pieces: &[PieceId],
        peers: &HashMap<PeerId, SwarmPeer>,
        max_pieces: usize,
    ) -> SwarmResult<Vec<PieceId>>;
}

impl PiecePicker for RarestFirstStrategy {
    fn select_pieces(
        &self,
        needed_pieces: &[PieceId],
        peers: &HashMap<PeerId, SwarmPeer>,
        max_pieces: usize,
    ) -> SwarmResult<Vec<PieceId>> {
        let mut pieces: Vec<(PieceId, usize, f64)> = needed_pieces
            .iter()
            .filter_map(|piece_id| {
                let mut availability = 0_usize;
                let mut best_peer_score = 0.0_f64;
                for peer in peers.values() {
                    if peer.available_pieces.contains(piece_id) {
                        availability += 1;
                        best_peer_score = best_peer_score.max(peer.quality.overall_score);
                    }
                }
                (availability > 0).then_some((*piece_id, availability, best_peer_score))
            })
            .collect();

        pieces.sort_by(|a, b| {
            a.1.cmp(&b.1)
                .then_with(|| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal))
                .then_with(|| a.0.as_u64().cmp(&b.0.as_u64()))
        });

        Ok(pieces
            .into_iter()
            .take(max_pieces)
            .map(|(piece_id, _, _)| piece_id)
            .collect())
    }
}

impl PiecePicker for SequentialStrategy {
    fn select_pieces(
        &self,
        needed_pieces: &[PieceId],
        peers: &HashMap<PeerId, SwarmPeer>,
        max_pieces: usize,
    ) -> SwarmResult<Vec<PieceId>> {
        let mut pieces: Vec<PieceId> = needed_pieces
            .iter()
            .copied()
            .filter(|piece_id| {
                peers
                    .values()
                    .any(|peer| peer.available_pieces.contains(piece_id))
            })
            .collect();
        pieces.sort_by_key(|p| p.as_u64());
        Ok(pieces.into_iter().take(max_pieces).collect())
    }
}

impl PiecePicker for RandomStrategy {
    fn select_pieces(
        &self,
        needed_pieces: &[PieceId],
        peers: &HashMap<PeerId, SwarmPeer>,
        max_pieces: usize,
    ) -> SwarmResult<Vec<PieceId>> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut peer_salt = DefaultHasher::new();
        let mut peer_ids: Vec<&str> = peers.keys().map(|peer_id| peer_id.as_str()).collect();
        peer_ids.sort_unstable();
        for peer_id in peer_ids {
            peer_id.hash(&mut peer_salt);
        }
        let salt = peer_salt.finish();

        let mut pieces: Vec<PieceId> = needed_pieces
            .iter()
            .copied()
            .filter(|piece_id| {
                peers
                    .values()
                    .any(|peer| peer.available_pieces.contains(piece_id))
            })
            .collect();
        pieces.sort_by_key(|p| {
            let mut hasher = DefaultHasher::new();
            salt.hash(&mut hasher);
            p.hash(&mut hasher);
            hasher.finish()
        });
        Ok(pieces.into_iter().take(max_pieces).collect())
    }
}

impl PiecePicker for AdaptiveStrategy {
    fn select_pieces(
        &self,
        needed_pieces: &[PieceId],
        peers: &HashMap<PeerId, SwarmPeer>,
        max_pieces: usize,
    ) -> SwarmResult<Vec<PieceId>> {
        let rarest = RarestFirstStrategy.select_pieces(needed_pieces, peers, max_pieces)?;
        if rarest.len() >= max_pieces {
            return Ok(rarest);
        }

        let sequential = SequentialStrategy.select_pieces(needed_pieces, peers, max_pieces)?;
        let mut selected = rarest;
        for piece_id in sequential {
            if selected.len() >= max_pieces {
                break;
            }
            if !selected.contains(&piece_id) {
                selected.push(piece_id);
            }
        }
        Ok(selected)
    }
}

impl PiecePicker for EndgameStrategy {
    fn select_pieces(
        &self,
        needed_pieces: &[PieceId],
        peers: &HashMap<PeerId, SwarmPeer>,
        max_pieces: usize,
    ) -> SwarmResult<Vec<PieceId>> {
        let mut pieces: Vec<(PieceId, usize)> = needed_pieces
            .iter()
            .filter_map(|piece_id| {
                let availability = peers
                    .values()
                    .filter(|peer| peer.available_pieces.contains(piece_id))
                    .count();
                (availability > 0).then_some((*piece_id, availability))
            })
            .collect();

        pieces.sort_by_key(|(piece_id, availability)| (*availability, piece_id.as_u64()));
        Ok(pieces
            .into_iter()
            .take(max_pieces)
            .map(|(piece_id, _)| piece_id)
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atp::swarm::{PeerCapabilities, PeerReputation};
    use std::collections::BTreeSet;

    fn test_peer(id: &str, pieces: impl IntoIterator<Item = PieceId>) -> SwarmPeer {
        SwarmPeer {
            peer_id: PeerId::new(id),
            endpoint: "127.0.0.1:8080".parse().unwrap(),
            available_pieces: pieces.into_iter().collect::<BTreeSet<_>>(),
            quality: PeerQuality {
                overall_score: 0.9,
                ..Default::default()
            },
            reputation: PeerReputation::default(),
            last_seen: swarm_time_now(),
            pending_requests: BTreeSet::new(),
            capabilities: PeerCapabilities::default(),
        }
    }

    #[test]
    fn test_coordinator_creation() {
        let config = SwarmConfig::default();
        let coordinator = SwarmCoordinator::new(config);

        assert_eq!(coordinator.peers.len(), 0);
        assert_eq!(coordinator.active_transfers.len(), 0);
    }

    #[test]
    fn test_piece_priority_calculation() {
        let coordinator = SwarmCoordinator::new(SwarmConfig::default());
        let transfer = SwarmTransfer {
            metadata: SwarmTransferMetadata {
                object_id: "test".to_string(),
                total_size: 1000,
                piece_count: 10,
                piece_size: 100,
                content_hash: "test".to_string(),
            },
            status: SwarmTransferStatus {
                transfer_id: MailboxTransferId::new(),
                total_pieces: 10,
                completed_pieces: 0,
                pending_pieces: 0,
                remaining_pieces: 10,
                active_peers: HashMap::new(),
                download_rate: 0.0,
                upload_rate: 0.0,
                estimated_completion: None,
                quality_metrics: SwarmQualityMetrics {
                    avg_peer_response_time: Duration::from_secs(1),
                    verification_failure_rate: 0.0,
                    peer_churn_rate: 0.0,
                    avg_piece_redundancy: 1.0,
                    incentive_balance_score: 1.0,
                    health_score: 1.0,
                },
            },
            active_requests: HashMap::new(),
            completed_pieces: HashSet::new(),
            started_at: Instant::now(),
            last_activity: Instant::now(),
        };

        let priority = coordinator.calculate_piece_priority(&PieceId::new(1), &transfer);
        assert!(priority >= 100);
    }

    #[test]
    fn test_piece_selection_strategies() {
        let needed_pieces = vec![PieceId::new(1), PieceId::new(2), PieceId::new(3)];
        let peers = std::iter::once((
            PeerId::new("peer-a"),
            test_peer(
                "peer-a",
                [PieceId::new(1), PieceId::new(2), PieceId::new(3)],
            ),
        ))
        .collect::<HashMap<_, _>>();

        let sequential = SequentialStrategy::new();
        let selected = sequential.select_pieces(&needed_pieces, &peers, 2).unwrap();
        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0], PieceId::new(1));
        assert_eq!(selected[1], PieceId::new(2));
    }
}
