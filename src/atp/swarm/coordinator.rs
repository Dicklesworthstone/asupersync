//! ATP Swarm Coordinator - Orchestrates multi-peer transfer coordination.
//!
//! The SwarmCoordinator manages piece requests, peer quality assessment,
//! and transfer optimization across multiple peers in the swarm.

use super::*;
use crate::atp::mailbox::{MailboxClient, MailboxConfig};
use crate::cx::Cx;
use crate::types::{Outcome, Time};
use anyhow::{Context, Result};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
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
    strategy: Box<dyn PieceSelectionStrategy + Send + Sync>,

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
                Box::new(RarestFirstStrategy::new()) as Box<dyn PieceSelectionStrategy + Send + Sync>
            }
            PieceSelectionStrategy::Sequential => {
                Box::new(SequentialStrategy::new()) as Box<dyn PieceSelectionStrategy + Send + Sync>
            }
            PieceSelectionStrategy::Random => {
                Box::new(RandomStrategy::new()) as Box<dyn PieceSelectionStrategy + Send + Sync>
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
            self.add_peer(peer.clone()).await?;
        }

        // Initialize piece tracker
        self.piece_tracker.initialize_transfer(&transfer_id, &piece_map)?;

        // Create transfer metadata
        let metadata = SwarmTransferMetadata {
            object_id: object_id.clone(),
            total_size,
            piece_count,
            piece_size: (total_size / piece_count) as u32,
            content_hash: format!("sha256:{}", object_id), // Placeholder
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

        // Emit start event
        self.emit_event(cx, SwarmEvent::TransferStarted {
            transfer_id,
            object_id,
            total_pieces: piece_count,
            peer_count: self.peers.len(),
        }).await;

        cx.trace(&format!("Started swarm transfer {} with {} peers",
                         transfer_id.0, self.peers.len()));

        Ok(transfer_id)
    }

    /// Add a peer to the swarm.
    pub async fn add_peer(&mut self, peer: SwarmPeer) -> SwarmResult<()> {
        let peer_id = peer.peer_id.clone();

        // Validate peer quality
        if peer.quality.overall_score < self.config.peer_quality_threshold {
            return Err(SwarmError::PeerQualityBelowThreshold {
                peer_id,
                quality: peer.quality.overall_score,
                threshold: self.config.peer_quality_threshold,
            });
        }

        // TODO: Need Cx parameter - remove temporary implementation
        // self.emit_event(cx, SwarmEvent::PeerJoined {
        //     peer_id: peer_id.clone(),
        //     available_pieces: peer.available_pieces.clone(),
        //     capabilities: peer.capabilities.clone(),
        // }).await;

        self.peers.insert(peer_id, peer);
        Ok(())
    }

    /// Remove a peer from the swarm.
    pub async fn remove_peer(&mut self, cx: &Cx, peer_id: &PeerId, reason: String) -> SwarmResult<()> {
        if let Some(peer) = self.peers.remove(peer_id) {
            let contributed_pieces = peer.available_pieces.len() as u64;

            // Emit leave event
            self.emit_event(cx, SwarmEvent::PeerLeft {
                peer_id: peer_id.clone(),
                reason,
                contributed_pieces,
            }).await;
        }

        Ok(())
    }

    /// Generate piece assignments for active transfers.
    pub async fn assign_pieces(
        &mut self,
        cx: &Cx,
        transfer_id: &MailboxTransferId,
    ) -> SwarmResult<Vec<PieceAssignment>> {
        let transfer = self.active_transfers.get_mut(transfer_id)
            .ok_or_else(|| SwarmError::TransferNotFound {
                transfer_id: *transfer_id,
            })?;

        // Get pieces that need to be requested
        let needed_pieces = self.piece_tracker.get_needed_pieces(transfer_id)?;
        if needed_pieces.is_empty() {
            return Ok(Vec::new());
        }

        // Select pieces using strategy
        let selected_pieces = self.strategy.select_pieces(
            &needed_pieces,
            &self.peers,
            self.config.max_pieces_per_peer,
        )?;

        let mut assignments = Vec::new();
        let now = Time::now();

        for piece_id in selected_pieces {
            // Find best peer for this piece
            let peer_id = self.peer_selector.select_peer_for_piece(
                &piece_id,
                &self.peers,
                &transfer.active_requests,
            )?;

            let assignment = PieceAssignment {
                peer_id: peer_id.clone(),
                piece_id,
                priority: self.calculate_piece_priority(&piece_id, transfer),
                estimated_completion: Time::from_nanos(
                    now.as_nanos() + 30_000_000_000 // 30 seconds default
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

            transfer.active_requests.insert(piece_id, request);
            assignments.push(assignment);

            // Emit request event
            self.emit_event(cx, SwarmEvent::PieceRequested {
                peer_id,
                piece_id,
                priority: assignment.priority,
            }).await;
        }

        transfer.last_activity = Instant::now();
        cx.trace(&format!("Generated {} piece assignments for transfer {}",
                         assignments.len(), transfer_id.0));

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
        let transfer = self.active_transfers.get_mut(transfer_id)
            .ok_or_else(|| SwarmError::TransferNotFound {
                transfer_id: *transfer_id,
            })?;

        // Remove from active requests
        let request = transfer.active_requests.remove(&piece_id);
        let download_time = request.map(|r| r.requested_at.elapsed())
            .unwrap_or(Duration::from_secs(0));

        // Mark as completed
        transfer.completed_pieces.insert(piece_id);
        transfer.status.completed_pieces = transfer.completed_pieces.len() as u64;
        transfer.status.remaining_pieces = transfer.status.total_pieces - transfer.status.completed_pieces;
        transfer.last_activity = Instant::now();

        // Update piece tracker
        self.piece_tracker.mark_piece_completed(transfer_id, piece_id)?;

        // Emit completion event
        self.emit_event(cx, SwarmEvent::PieceReceived {
            peer_id: peer_id.clone(),
            piece_id,
            verification_status,
            download_time,
        }).await;

        // Check if transfer is complete
        if transfer.status.remaining_pieces == 0 {
            let duration = transfer.started_at.elapsed();
            self.emit_event(cx, SwarmEvent::TransferCompleted {
                transfer_id: *transfer_id,
                duration,
                total_pieces: transfer.status.total_pieces,
                peer_count: self.peers.len(),
                avg_quality: self.calculate_average_peer_quality(),
            }).await;
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
        let transfer = self.active_transfers.get_mut(transfer_id)
            .ok_or_else(|| SwarmError::TransferNotFound {
                transfer_id: *transfer_id,
            })?;

        // Remove failed request
        if let Some(mut request) = transfer.active_requests.remove(&piece_id) {
            request.retry_count += 1;

            // Check if we should retry
            if request.retry_count < 3 {
                transfer.active_requests.insert(piece_id, request);
            }
        }

        // Update peer quality
        if let Some(peer) = self.peers.get_mut(peer_id) {
            peer.quality.verification_failures += 1;
            peer.quality.overall_score = self.calculate_peer_score(&peer.quality);
        }

        // Emit failure event
        self.emit_event(cx, SwarmEvent::PieceVerificationFailed {
            peer_id: peer_id.clone(),
            piece_id,
            error_details: error,
        }).await;

        Ok(())
    }

    /// Get current status of a transfer.
    pub fn get_transfer_status(&self, transfer_id: &MailboxTransferId) -> Option<&SwarmTransferStatus> {
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

        // Handle timed out requests
        for (transfer_id, piece_id, peer_id) in timed_out_requests {
            self.handle_piece_verification_failed(
                &transfer_id,
                piece_id,
                &peer_id,
                "Request timeout".to_string(),
            ).await?;
        }

        if !timed_out_requests.is_empty() {
            cx.trace(&format!("Processed {} timed out requests", timed_out_requests.len()));
        }

        Ok(())
    }

    /// Calculate priority for a piece based on various factors.
    fn calculate_piece_priority(&self, _piece_id: &PieceId, _transfer: &SwarmTransfer) -> u32 {
        // For now, use simple priority calculation
        // In a real implementation, this would consider:
        // - Rarity of the piece
        // - Position in sequential download
        // - Dependencies on other pieces
        100
    }

    /// Calculate average peer quality across the swarm.
    fn calculate_average_peer_quality(&self) -> f64 {
        if self.peers.is_empty() {
            return 0.0;
        }

        let total: f64 = self.peers.values()
            .map(|peer| peer.quality.overall_score)
            .sum();

        total / self.peers.len() as f64
    }

    /// Calculate peer score based on quality metrics.
    fn calculate_peer_score(&self, quality: &PeerQuality) -> f64 {
        // Simple scoring function - real implementation would be more sophisticated
        let base_score = 1.0;
        let failure_penalty = (quality.verification_failures as f64) * 0.1;
        let latency_penalty = quality.avg_response_time.as_secs_f64() / 10.0;

        (base_score - failure_penalty - latency_penalty).max(0.0).min(1.0)
    }

    /// Emit an event to the event sink.
    async fn emit_event(&self, cx: &Cx, event: SwarmEvent) {
        if let Some(ref sink) = self.event_sink {
            let _ = sink.send(cx, event).await;
        }
    }
}

/// Placeholder for transfer start event.
#[derive(Debug, Clone)]
struct TransferStarted {
    transfer_id: MailboxTransferId,
    object_id: String,
    total_pieces: u64,
    peer_count: usize,
}

// Placeholder strategy implementations
struct RarestFirstStrategy;
struct SequentialStrategy;
struct RandomStrategy;

impl RarestFirstStrategy {
    fn new() -> Self { Self }
}

impl SequentialStrategy {
    fn new() -> Self { Self }
}

impl RandomStrategy {
    fn new() -> Self { Self }
}

// Trait for piece selection strategies
trait PieceSelectionStrategy {
    fn select_pieces(
        &self,
        needed_pieces: &[PieceId],
        peers: &HashMap<PeerId, SwarmPeer>,
        max_per_peer: usize,
    ) -> SwarmResult<Vec<PieceId>>;
}

impl PieceSelectionStrategy for RarestFirstStrategy {
    fn select_pieces(
        &self,
        needed_pieces: &[PieceId],
        peers: &HashMap<PeerId, SwarmPeer>,
        max_per_peer: usize,
    ) -> SwarmResult<Vec<PieceId>> {
        // Simple implementation - select up to max_per_peer pieces
        Ok(needed_pieces.iter()
           .take(max_per_peer)
           .copied()
           .collect())
    }
}

impl PieceSelectionStrategy for SequentialStrategy {
    fn select_pieces(
        &self,
        needed_pieces: &[PieceId],
        peers: &HashMap<PeerId, SwarmPeer>,
        max_per_peer: usize,
    ) -> SwarmResult<Vec<PieceId>> {
        // Sort by piece ID for sequential selection
        let mut pieces = needed_pieces.to_vec();
        pieces.sort_by_key(|p| p.as_u64());
        Ok(pieces.into_iter().take(max_per_peer).collect())
    }
}

impl PieceSelectionStrategy for RandomStrategy {
    fn select_pieces(
        &self,
        needed_pieces: &[PieceId],
        peers: &HashMap<PeerId, SwarmPeer>,
        max_per_peer: usize,
    ) -> SwarmResult<Vec<PieceId>> {
        // Simple random selection
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut pieces = needed_pieces.to_vec();
        pieces.sort_by_key(|p| {
            let mut hasher = DefaultHasher::new();
            p.hash(&mut hasher);
            hasher.finish()
        });
        Ok(pieces.into_iter().take(max_per_peer).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(priority, 100);
    }

    #[test]
    fn test_piece_selection_strategies() {
        let needed_pieces = vec![PieceId::new(1), PieceId::new(2), PieceId::new(3)];
        let peers = HashMap::new();

        let sequential = SequentialStrategy::new();
        let selected = sequential.select_pieces(&needed_pieces, &peers, 2).unwrap();
        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0], PieceId::new(1));
        assert_eq!(selected[1], PieceId::new(2));
    }
}