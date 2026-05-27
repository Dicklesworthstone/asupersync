//! ATP Swarm Peer Selection - Quality-aware peer selection and management.
//!
//! Implements peer quality assessment, selection algorithms, and reputation
//! tracking for optimal swarm performance.

use super::{PeerId, PieceId, SwarmError, SwarmPeer, SwarmResult, swarm_time_now};
use crate::types::Time;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

/// Manages peer selection and quality assessment for swarm transfers.
#[derive(Debug)]
pub struct PeerSelector {
    /// Peer quality history
    quality_history: HashMap<PeerId, QualityHistory>,

    /// Selection algorithm configuration
    selection_config: PeerSelectionConfig,
}

/// Configuration for peer selection algorithms.
#[derive(Debug, Clone)]
pub struct PeerSelectionConfig {
    /// Weight for download speed in selection
    pub speed_weight: f64,

    /// Weight for reliability in selection
    pub reliability_weight: f64,

    /// Weight for latency in selection
    pub latency_weight: f64,

    /// Weight for reputation in selection
    pub reputation_weight: f64,

    /// Minimum acceptable peer score
    pub min_peer_score: f64,

    /// Maximum peer evaluation age
    pub max_evaluation_age: Duration,
}

impl Default for PeerSelectionConfig {
    fn default() -> Self {
        Self {
            speed_weight: 0.3,
            reliability_weight: 0.3,
            latency_weight: 0.2,
            reputation_weight: 0.2,
            min_peer_score: 0.3,
            max_evaluation_age: Duration::from_secs(300), // 5 minutes
        }
    }
}

/// Historical quality data for a peer.
#[derive(Debug, Clone)]
pub struct QualityHistory {
    /// Recent evaluations
    evaluations: Vec<QualityEvaluation>,

    /// Long-term reputation score
    reputation_score: f64,

    /// Total successful transfers
    successful_transfers: u64,

    /// Total failed transfers
    failed_transfers: u64,
}

/// Single quality evaluation for a peer.
#[derive(Debug, Clone)]
pub(crate) struct QualityEvaluation {
    /// Evaluation timestamp
    timestamp: Time,

    /// Download speed (bytes/sec)
    download_speed: f64,

    /// Average latency
    latency: Duration,

    /// Reliability score (0.0 to 1.0)
    reliability: f64,

    /// Overall quality score
    quality_score: f64,
}

/// Quality metrics for peer assessment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerQuality {
    /// Overall quality score (0.0 to 1.0)
    pub overall_score: f64,

    /// Download throughput (bytes/sec)
    pub download_speed: f64,

    /// Upload throughput (bytes/sec)
    pub upload_speed: f64,

    /// Average response time
    pub avg_response_time: Duration,

    /// Connection reliability (0.0 to 1.0)
    pub reliability: f64,

    /// Number of successful transfers
    pub successful_transfers: u64,

    /// Number of failed transfers
    pub failed_transfers: u64,

    /// Number of verification failures
    pub verification_failures: u64,

    /// Last quality assessment time
    pub last_updated: Time,
}

impl Default for PeerQuality {
    fn default() -> Self {
        Self {
            overall_score: 0.5,
            download_speed: 1_000_000.0, // 1 MB/s default
            upload_speed: 1_000_000.0,
            avg_response_time: Duration::from_millis(100),
            reliability: 0.8,
            successful_transfers: 0,
            failed_transfers: 0,
            verification_failures: 0,
            last_updated: swarm_time_now(),
        }
    }
}

/// Reputation and incentive tracking for a peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerReputation {
    /// Long-term reputation score
    pub reputation_score: f64,

    /// Data uploaded to this peer (bytes)
    pub bytes_uploaded: u64,

    /// Data downloaded from this peer (bytes)
    pub bytes_downloaded: u64,

    /// Reciprocity ratio (uploaded/downloaded)
    pub reciprocity_ratio: f64,

    /// Incentive tokens earned
    pub tokens_earned: u64,

    /// Incentive tokens spent
    pub tokens_spent: u64,

    /// Join timestamp
    pub joined_at: Time,

    /// Number of sessions
    pub session_count: u64,

    /// Cooperation score (0.0 to 1.0)
    pub cooperation_score: f64,
}

impl Default for PeerReputation {
    fn default() -> Self {
        Self {
            reputation_score: 0.5,
            bytes_uploaded: 0,
            bytes_downloaded: 0,
            reciprocity_ratio: 1.0,
            tokens_earned: 0,
            tokens_spent: 0,
            joined_at: swarm_time_now(),
            session_count: 0,
            cooperation_score: 0.8,
        }
    }
}

/// Path quality assessment for network connections.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathQuality {
    /// Round-trip time
    pub rtt: Duration,

    /// Packet loss rate (0.0 to 1.0)
    pub packet_loss: f64,

    /// Bandwidth estimate (bytes/sec)
    pub bandwidth: f64,

    /// Jitter variance
    pub jitter: Duration,

    /// Number of hops
    pub hop_count: u32,

    /// Path stability score
    pub stability: f64,
}

impl Default for PathQuality {
    fn default() -> Self {
        Self {
            rtt: Duration::from_millis(50),
            packet_loss: 0.01,
            bandwidth: 10_000_000.0, // 10 MB/s
            jitter: Duration::from_millis(5),
            hop_count: 10,
            stability: 0.9,
        }
    }
}

/// Composite peer score combining multiple quality factors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerScore {
    /// Overall composite score
    pub composite_score: f64,

    /// Speed component
    pub speed_score: f64,

    /// Reliability component
    pub reliability_score: f64,

    /// Latency component (lower is better)
    pub latency_score: f64,

    /// Reputation component
    pub reputation_score: f64,

    /// Calculation timestamp
    pub calculated_at: Time,
}

impl PeerSelector {
    /// Create a new peer selector with default configuration.
    pub fn new() -> Self {
        Self {
            quality_history: HashMap::new(),
            selection_config: PeerSelectionConfig::default(),
        }
    }

    /// Create a peer selector with custom configuration.
    pub fn with_config(config: PeerSelectionConfig) -> Self {
        Self {
            quality_history: HashMap::new(),
            selection_config: config,
        }
    }

    /// Select optimal peers from available candidates.
    pub fn select_peers(
        &self,
        candidates: &[SwarmPeer],
        max_peers: usize,
        quality_threshold: f64,
    ) -> SwarmResult<Vec<SwarmPeer>> {
        if candidates.is_empty() {
            return Err(SwarmError::NoPeersAvailable {
                details: "No candidate peers provided".to_string(),
            });
        }

        // Filter peers by quality threshold
        let qualified_peers: Vec<&SwarmPeer> = candidates
            .iter()
            .filter(|peer| peer.quality.overall_score >= quality_threshold)
            .collect();

        if qualified_peers.is_empty() {
            return Err(SwarmError::NoPeersAvailable {
                details: format!(
                    "No peers meet quality threshold {} (best: {})",
                    quality_threshold,
                    candidates
                        .iter()
                        .map(|p| p.quality.overall_score)
                        .fold(0.0_f64, f64::max)
                ),
            });
        }

        // Calculate scores for qualified peers
        let mut scored_peers: Vec<(f64, &SwarmPeer)> = qualified_peers
            .into_iter()
            .map(|peer| {
                let score = self.calculate_peer_score(peer);
                (score.composite_score, peer)
            })
            .collect();

        // Sort by score (highest first)
        scored_peers.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));

        // Select top peers up to max_peers
        let selected = scored_peers
            .into_iter()
            .take(max_peers)
            .map(|(_, peer)| peer.clone())
            .collect();

        Ok(selected)
    }

    /// Select the best peer for requesting a specific piece.
    pub fn select_peer_for_piece(
        &self,
        piece_id: &PieceId,
        available_peers: &HashMap<PeerId, SwarmPeer>,
        active_loads: &HashMap<PeerId, usize>,
    ) -> SwarmResult<PeerId> {
        let mut candidates = Vec::new();

        for (peer_id, peer) in available_peers {
            if peer.available_pieces.contains(piece_id) {
                let active_count =
                    active_loads.get(peer_id).copied().unwrap_or(0) + peer.pending_requests.len();

                if active_count < peer.capabilities.max_concurrent_uploads {
                    let score = self.calculate_peer_score(peer);
                    let load_headroom: f64 = 1.0
                        - (active_count as f64 / peer.capabilities.max_concurrent_uploads as f64);
                    candidates.push((
                        score.composite_score * 0.85 + load_headroom.clamp(0.0, 1.0) * 0.15,
                        peer_id.clone(),
                    ));
                }
            }
        }

        if candidates.is_empty() {
            return Err(SwarmError::NoPeersAvailable {
                details: format!("No peers available for piece {}", piece_id.as_u64()),
            });
        }

        // Sort by score and select best
        candidates.sort_by(|a, b| {
            b.0.partial_cmp(&a.0)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.1.as_str().cmp(b.1.as_str()))
        });

        Ok(candidates[0].1.clone())
    }

    /// Calculate composite score for a peer.
    pub fn calculate_peer_score(&self, peer: &SwarmPeer) -> PeerScore {
        let config = &self.selection_config;

        // Speed score (normalized)
        let speed_score = (peer.quality.download_speed / 10_000_000.0).min(1.0);

        // Reliability score
        let total_transfers = peer.quality.successful_transfers + peer.quality.failed_transfers;
        let reliability_score = if total_transfers > 0 {
            peer.quality.successful_transfers as f64 / total_transfers as f64
        } else {
            peer.quality.reliability
        };

        // Latency score (inverse - lower latency is better)
        let latency_ms = peer.quality.avg_response_time.as_millis() as f64;
        let latency_score = (1000.0 / (latency_ms + 100.0)).min(1.0);

        // Reputation score
        let reputation_score = peer.reputation.reputation_score;

        // Composite score
        let composite_score = (speed_score * config.speed_weight)
            + (reliability_score * config.reliability_weight)
            + (latency_score * config.latency_weight)
            + (reputation_score * config.reputation_weight);

        PeerScore {
            composite_score: composite_score.clamp(0.0, 1.0),
            speed_score,
            reliability_score,
            latency_score,
            reputation_score,
            calculated_at: swarm_time_now(),
        }
    }

    /// Update quality metrics for a peer after a transfer.
    pub fn update_peer_quality(
        &mut self,
        peer_id: &PeerId,
        download_speed: f64,
        latency: Duration,
        success: bool,
    ) {
        let evaluation = QualityEvaluation {
            timestamp: swarm_time_now(),
            download_speed,
            latency,
            reliability: if success { 1.0 } else { 0.0 },
            quality_score: self.calculate_quality_score(download_speed, latency, success),
        };

        let history = self
            .quality_history
            .entry(peer_id.clone())
            .or_insert_with(|| QualityHistory {
                evaluations: Vec::new(),
                reputation_score: 0.5,
                successful_transfers: 0,
                failed_transfers: 0,
            });

        history.evaluations.push(evaluation);

        // Update success/failure counts
        if success {
            history.successful_transfers += 1;
        } else {
            history.failed_transfers += 1;
        }

        // Trim old evaluations
        let cutoff_time = Time::from_nanos(
            swarm_time_now()
                .as_nanos()
                .saturating_sub(self.selection_config.max_evaluation_age.as_nanos() as u64),
        );

        history
            .evaluations
            .retain(|eval| eval.timestamp > cutoff_time);

        // Update reputation score
        history.reputation_score = Self::calculate_reputation_score(history);
    }

    /// Calculate quality score from metrics.
    fn calculate_quality_score(
        &self,
        download_speed: f64,
        latency: Duration,
        success: bool,
    ) -> f64 {
        let speed_factor = (download_speed / 1_000_000.0).min(1.0); // Normalize to 1 MB/s
        let latency_factor = (1000.0 / (latency.as_millis() as f64 + 100.0)).min(1.0);
        let success_factor = if success { 1.0 } else { 0.1 };

        (speed_factor * 0.4 + latency_factor * 0.3 + success_factor * 0.3).clamp(0.0, 1.0)
    }

    /// Calculate reputation score from history.
    fn calculate_reputation_score(history: &QualityHistory) -> f64 {
        if history.evaluations.is_empty() {
            return history.reputation_score;
        }

        // Calculate recent average quality
        let recent_quality: f64 = history
            .evaluations
            .iter()
            .map(|eval| {
                let speed_score = (eval.download_speed / 1_000_000.0).clamp(0.0, 1.0);
                let latency_score = (1.0 / (1.0 + eval.latency.as_secs_f64())).clamp(0.0, 1.0);
                eval.quality_score * 0.50
                    + speed_score * 0.20
                    + latency_score * 0.15
                    + eval.reliability.clamp(0.0, 1.0) * 0.15
            })
            .sum::<f64>()
            / history.evaluations.len() as f64;

        // Calculate success rate
        let total_transfers = history.successful_transfers + history.failed_transfers;
        let success_rate = if total_transfers > 0 {
            history.successful_transfers as f64 / total_transfers as f64
        } else {
            0.5
        };

        // Weighted average of recent quality and long-term success rate
        (recent_quality * 0.6 + success_rate * 0.4).clamp(0.0, 1.0)
    }

    /// Get quality history for a peer.
    pub fn get_quality_history(&self, peer_id: &PeerId) -> Option<&QualityHistory> {
        self.quality_history.get(peer_id)
    }

    /// Clean up old quality data.
    pub fn cleanup_old_data(&mut self) {
        let cutoff_time = Time::from_nanos(swarm_time_now().as_nanos().saturating_sub(
            (self.selection_config.max_evaluation_age.as_nanos() as u64).saturating_mul(2),
        ));

        for history in self.quality_history.values_mut() {
            history
                .evaluations
                .retain(|eval| eval.timestamp > cutoff_time);
        }

        // Remove peers with no recent data
        self.quality_history
            .retain(|_, history| !history.evaluations.is_empty());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atp::swarm::PeerCapabilities;
    use std::collections::BTreeSet;

    fn create_test_peer(id: &str, quality_score: f64, download_speed: f64) -> SwarmPeer {
        SwarmPeer {
            peer_id: PeerId::new(id),
            endpoint: "127.0.0.1:8080".parse().unwrap(),
            available_pieces: BTreeSet::new(),
            quality: PeerQuality {
                overall_score: quality_score,
                download_speed,
                ..Default::default()
            },
            reputation: PeerReputation::default(),
            last_seen: swarm_time_now(),
            pending_requests: BTreeSet::new(),
            capabilities: PeerCapabilities::default(),
        }
    }

    #[test]
    fn test_peer_selector_creation() {
        let selector = PeerSelector::new();
        assert_eq!(selector.quality_history.len(), 0);
    }

    #[test]
    fn test_select_peers_empty_candidates() {
        let selector = PeerSelector::new();
        let result = selector.select_peers(&[], 5, 0.5);
        assert!(result.is_err());
    }

    #[test]
    fn test_select_peers_quality_filtering() {
        let selector = PeerSelector::new();
        let candidates = vec![
            create_test_peer("peer1", 0.8, 1000000.0),
            create_test_peer("peer2", 0.3, 500000.0), // Below threshold
            create_test_peer("peer3", 0.7, 2000000.0),
        ];

        let selected = selector.select_peers(&candidates, 5, 0.5).unwrap();
        assert_eq!(selected.len(), 2);

        let selected_ids: Vec<_> = selected.iter().map(|p| p.peer_id.as_str()).collect();
        assert!(selected_ids.contains(&"peer1"));
        assert!(selected_ids.contains(&"peer3"));
        assert!(!selected_ids.contains(&"peer2"));
    }

    #[test]
    fn test_select_peers_max_limit() {
        let selector = PeerSelector::new();
        let candidates = vec![
            create_test_peer("peer1", 0.9, 1000000.0),
            create_test_peer("peer2", 0.8, 1500000.0),
            create_test_peer("peer3", 0.7, 2000000.0),
        ];

        let selected = selector.select_peers(&candidates, 2, 0.5).unwrap();
        assert_eq!(selected.len(), 2);
    }

    #[test]
    fn test_calculate_peer_score() {
        let selector = PeerSelector::new();
        let peer = create_test_peer("test", 0.8, 5000000.0);

        let score = selector.calculate_peer_score(&peer);
        assert!(score.composite_score > 0.0);
        assert!(score.composite_score <= 1.0);
        assert!(score.speed_score > 0.0);
        assert!(score.reliability_score > 0.0);
    }

    #[test]
    fn test_update_peer_quality() {
        let mut selector = PeerSelector::new();
        let peer_id = PeerId::new("test-peer");

        selector.update_peer_quality(&peer_id, 1_000_000.0, Duration::from_millis(100), true);

        let history = selector.get_quality_history(&peer_id).unwrap();
        assert_eq!(history.evaluations.len(), 1);
        assert_eq!(history.successful_transfers, 1);
        assert_eq!(history.failed_transfers, 0);
    }

    #[test]
    fn test_cleanup_old_data() {
        let mut selector = PeerSelector::with_config(PeerSelectionConfig {
            max_evaluation_age: Duration::from_millis(100),
            ..Default::default()
        });

        let peer_id = PeerId::new("test-peer");

        selector.update_peer_quality(&peer_id, 1_000_000.0, Duration::from_millis(100), true);

        // Wait for data to become old
        std::thread::sleep(Duration::from_millis(200));

        selector.cleanup_old_data();

        // History should be cleaned up
        assert!(selector.get_quality_history(&peer_id).is_none());
    }
}
