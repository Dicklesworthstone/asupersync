//! ATP Swarm Piece Tracker - Tracks piece availability and download progress.
//!
//! Manages the state of which pieces are available from which peers,
//! tracks download progress, and coordinates piece requests.

use super::{PeerId, PieceId, SwarmError, SwarmResult, swarm_time_now};
use crate::atp::mailbox::MailboxTransferId;
use crate::types::Time;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

/// Tracks piece availability and download state across transfers.
#[derive(Debug)]
pub struct PieceTracker {
    /// Per-transfer piece maps
    transfer_maps: HashMap<MailboxTransferId, TransferPieceMap>,

    /// Global piece availability across all peers
    global_availability: HashMap<PieceId, HashSet<PeerId>>,
}

/// Piece availability and progress for a single transfer.
#[derive(Debug, Clone)]
struct TransferPieceMap {
    /// Total number of pieces in transfer
    total_pieces: u64,

    /// Pieces and their current status
    piece_status: HashMap<PieceId, PieceStatus>,

    /// Pieces available from each peer
    peer_pieces: HashMap<PeerId, BTreeSet<PieceId>>,

    /// Redundancy count for each piece
    redundancy: HashMap<PieceId, u32>,
}

/// Map of piece availability across the swarm.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PieceMap {
    /// Total number of pieces
    pub total_pieces: u64,

    /// Size of each piece in bytes
    pub piece_size: u32,

    /// Pieces available from each peer
    pub peer_availability: HashMap<PeerId, BTreeSet<PieceId>>,

    /// Content hash for verification
    pub content_hash: String,

    /// Creation timestamp
    pub created_at: Time,
}

/// Status of an individual piece.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub enum PieceStatus {
    /// Piece is needed and not yet requested
    #[default]
    Needed,

    /// Piece has been requested from a peer
    Requested {
        /// Time when request was sent
        requested_at: Time,
        /// Peer from which piece was requested
        peer_id: PeerId,
    },

    /// Piece is currently being downloaded
    Downloading {
        /// Download start time
        started_at: Time,
        /// Peer providing the piece
        peer_id: PeerId,
        /// Progress percentage (0.0 to 1.0)
        progress: f64,
    },

    /// Piece download completed successfully
    Completed {
        /// Completion time
        completed_at: Time,
        /// Peer that provided the piece
        peer_id: PeerId,
    },

    /// Piece download failed
    Failed {
        /// Failure time
        failed_at: Time,
        /// Peer that failed to provide piece
        peer_id: PeerId,
        /// Failure reason
        reason: String,
    },

    /// Piece is being verified
    Verifying {
        /// Verification start time
        started_at: Time,
        /// Peer that provided the piece
        peer_id: PeerId,
    },
}

/// Statistics about piece distribution and redundancy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PieceDistributionStats {
    /// Total unique pieces tracked
    pub total_unique_pieces: u64,

    /// Average redundancy factor
    pub avg_redundancy: f64,

    /// Minimum redundancy (rarest piece)
    pub min_redundancy: u32,

    /// Maximum redundancy
    pub max_redundancy: u32,

    /// Pieces with only one peer (rarest)
    pub rarest_pieces: Vec<PieceId>,

    /// Distribution of redundancy levels
    pub redundancy_distribution: BTreeMap<u32, u32>,
}

impl PieceMap {
    /// Create a new piece map.
    pub fn new(total_pieces: u64, piece_size: u32, content_hash: String) -> Self {
        Self {
            total_pieces,
            piece_size,
            peer_availability: HashMap::new(),
            content_hash,
            created_at: swarm_time_now(),
        }
    }

    /// Add piece availability for a peer.
    pub fn add_peer_pieces(&mut self, peer_id: PeerId, pieces: BTreeSet<PieceId>) {
        self.peer_availability.insert(peer_id, pieces);
    }

    /// Get all peers that have a specific piece.
    pub fn get_peers_for_piece(&self, piece_id: &PieceId) -> Vec<PeerId> {
        self.peer_availability
            .iter()
            .filter_map(|(peer_id, pieces): (&PeerId, &BTreeSet<PieceId>)| {
                if pieces.contains(piece_id) {
                    Some(peer_id.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Calculate redundancy for a piece.
    pub fn get_piece_redundancy(&self, piece_id: &PieceId) -> u32 {
        self.peer_availability
            .values()
            .filter(|pieces: &&BTreeSet<PieceId>| pieces.contains(piece_id))
            .count() as u32
    }

    /// Get statistics about piece distribution.
    pub fn get_distribution_stats(&self) -> PieceDistributionStats {
        let mut redundancy_counts = HashMap::new();

        // Calculate redundancy for each piece
        for piece_id in 0..self.total_pieces {
            let piece_id = PieceId::new(piece_id);
            let redundancy = self.get_piece_redundancy(&piece_id);
            redundancy_counts.insert(piece_id, redundancy);
        }

        let redundancy_values: Vec<u32> = redundancy_counts.values().copied().collect();
        let avg_redundancy = if redundancy_values.is_empty() {
            0.0
        } else {
            redundancy_values.iter().sum::<u32>() as f64 / redundancy_values.len() as f64
        };

        let min_redundancy = redundancy_values.iter().min().copied().unwrap_or(0);
        let max_redundancy = redundancy_values.iter().max().copied().unwrap_or(0);

        // Find rarest pieces
        let rarest_pieces: Vec<PieceId> = redundancy_counts
            .iter()
            .filter(|&(_, &redundancy)| redundancy == min_redundancy)
            .map(|(piece_id, _)| *piece_id)
            .collect();

        // Build redundancy distribution
        let mut redundancy_distribution = BTreeMap::new();
        for &redundancy in &redundancy_values {
            *redundancy_distribution.entry(redundancy).or_insert(0) += 1;
        }

        PieceDistributionStats {
            total_unique_pieces: self.total_pieces,
            avg_redundancy,
            min_redundancy,
            max_redundancy,
            rarest_pieces,
            redundancy_distribution,
        }
    }
}

impl PieceTracker {
    /// Create a new piece tracker.
    pub fn new() -> Self {
        Self {
            transfer_maps: HashMap::new(),
            global_availability: HashMap::new(),
        }
    }

    /// Initialize tracking for a new transfer.
    pub fn initialize_transfer(
        &mut self,
        transfer_id: &MailboxTransferId,
        piece_map: &PieceMap,
    ) -> SwarmResult<()> {
        // Create piece status map
        let mut piece_status = HashMap::new();
        for piece_id in 0..piece_map.total_pieces {
            piece_status.insert(PieceId::new(piece_id), PieceStatus::Needed);
        }

        // Build redundancy map
        let mut redundancy = HashMap::new();
        for piece_id in 0..piece_map.total_pieces {
            let piece_id = PieceId::new(piece_id);
            redundancy.insert(piece_id, piece_map.get_piece_redundancy(&piece_id));
        }

        let transfer_map = TransferPieceMap {
            total_pieces: piece_map.total_pieces,
            piece_status,
            peer_pieces: piece_map.peer_availability.clone(),
            redundancy,
        };

        self.transfer_maps.insert(*transfer_id, transfer_map);

        // Update global availability
        for (peer_id, pieces) in &piece_map.peer_availability {
            for piece_id in pieces {
                self.global_availability
                    .entry(*piece_id)
                    .or_default()
                    .insert(peer_id.clone());
            }
        }

        Ok(())
    }

    /// Get pieces that still need to be downloaded for a transfer.
    pub fn get_needed_pieces(&self, transfer_id: &MailboxTransferId) -> SwarmResult<Vec<PieceId>> {
        let transfer_map =
            self.transfer_maps
                .get(transfer_id)
                .ok_or(SwarmError::TransferNotFound {
                    transfer_id: *transfer_id,
                })?;

        let needed_pieces: Vec<PieceId> = transfer_map
            .piece_status
            .iter()
            .filter_map(|(piece_id, status)| match status {
                PieceStatus::Needed | PieceStatus::Failed { .. } => Some(*piece_id),
                _ => None,
            })
            .collect();

        Ok(needed_pieces)
    }

    /// Get pieces sorted by rarity (rarest first).
    pub fn get_pieces_by_rarity(
        &self,
        transfer_id: &MailboxTransferId,
    ) -> SwarmResult<Vec<PieceId>> {
        let transfer_map =
            self.transfer_maps
                .get(transfer_id)
                .ok_or(SwarmError::TransferNotFound {
                    transfer_id: *transfer_id,
                })?;

        let needed_pieces = self.get_needed_pieces(transfer_id)?;

        let mut rarity_sorted: Vec<(PieceId, u32)> = needed_pieces
            .into_iter()
            .map(|piece_id| {
                let redundancy = transfer_map.redundancy.get(&piece_id).copied().unwrap_or(0);
                (piece_id, redundancy)
            })
            .collect();

        // Sort by redundancy (ascending - rarest first)
        rarity_sorted.sort_by_key(|(_, redundancy)| *redundancy);

        Ok(rarity_sorted
            .into_iter()
            .map(|(piece_id, _)| piece_id)
            .collect())
    }

    /// Mark a piece as requested.
    pub fn mark_piece_requested(
        &mut self,
        transfer_id: &MailboxTransferId,
        piece_id: PieceId,
        peer_id: PeerId,
    ) -> SwarmResult<()> {
        let transfer_map =
            self.transfer_maps
                .get_mut(transfer_id)
                .ok_or(SwarmError::TransferNotFound {
                    transfer_id: *transfer_id,
                })?;

        transfer_map.piece_status.insert(
            piece_id,
            PieceStatus::Requested {
                requested_at: swarm_time_now(),
                peer_id,
            },
        );

        Ok(())
    }

    /// Mark a piece as downloading.
    pub fn mark_piece_downloading(
        &mut self,
        transfer_id: &MailboxTransferId,
        piece_id: PieceId,
        peer_id: PeerId,
    ) -> SwarmResult<()> {
        let transfer_map =
            self.transfer_maps
                .get_mut(transfer_id)
                .ok_or(SwarmError::TransferNotFound {
                    transfer_id: *transfer_id,
                })?;

        transfer_map.piece_status.insert(
            piece_id,
            PieceStatus::Downloading {
                started_at: swarm_time_now(),
                peer_id,
                progress: 0.0,
            },
        );

        Ok(())
    }

    /// Update download progress for a piece.
    pub fn update_piece_progress(
        &mut self,
        transfer_id: &MailboxTransferId,
        piece_id: PieceId,
        progress: f64,
    ) -> SwarmResult<()> {
        let transfer_map =
            self.transfer_maps
                .get_mut(transfer_id)
                .ok_or(SwarmError::TransferNotFound {
                    transfer_id: *transfer_id,
                })?;

        if let Some(PieceStatus::Downloading {
            started_at,
            peer_id,
            ..
        }) = transfer_map.piece_status.get(&piece_id)
        {
            transfer_map.piece_status.insert(
                piece_id,
                PieceStatus::Downloading {
                    started_at: *started_at,
                    peer_id: peer_id.clone(),
                    progress: progress.clamp(0.0, 1.0),
                },
            );
        }

        Ok(())
    }

    /// Mark a piece as completed.
    pub fn mark_piece_completed(
        &mut self,
        transfer_id: &MailboxTransferId,
        piece_id: PieceId,
    ) -> SwarmResult<()> {
        let transfer_map =
            self.transfer_maps
                .get_mut(transfer_id)
                .ok_or(SwarmError::TransferNotFound {
                    transfer_id: *transfer_id,
                })?;

        // Get peer ID from current status
        let peer_id = match transfer_map.piece_status.get(&piece_id) {
            Some(
                PieceStatus::Requested { peer_id, .. }
                | PieceStatus::Downloading { peer_id, .. }
                | PieceStatus::Verifying { peer_id, .. },
            ) => peer_id.clone(),
            _ => {
                return Err(SwarmError::InvalidPieceState {
                    piece_id,
                    current_state: "not requested, downloading, or verifying".to_string(),
                });
            }
        };

        transfer_map.piece_status.insert(
            piece_id,
            PieceStatus::Completed {
                completed_at: swarm_time_now(),
                peer_id,
            },
        );

        Ok(())
    }

    /// Mark a piece as failed.
    pub fn mark_piece_failed(
        &mut self,
        transfer_id: &MailboxTransferId,
        piece_id: PieceId,
        reason: String,
    ) -> SwarmResult<()> {
        let transfer_map =
            self.transfer_maps
                .get_mut(transfer_id)
                .ok_or(SwarmError::TransferNotFound {
                    transfer_id: *transfer_id,
                })?;

        // Get peer ID from current status
        let peer_id = match transfer_map.piece_status.get(&piece_id) {
            Some(
                PieceStatus::Downloading { peer_id, .. }
                | PieceStatus::Verifying { peer_id, .. }
                | PieceStatus::Requested { peer_id, .. },
            ) => peer_id.clone(),
            _ => PeerId::new("unknown"),
        };

        transfer_map.piece_status.insert(
            piece_id,
            PieceStatus::Failed {
                failed_at: swarm_time_now(),
                peer_id,
                reason,
            },
        );

        Ok(())
    }

    /// Get status of a specific piece.
    pub fn get_piece_status(
        &self,
        transfer_id: &MailboxTransferId,
        piece_id: &PieceId,
    ) -> SwarmResult<PieceStatus> {
        let transfer_map =
            self.transfer_maps
                .get(transfer_id)
                .ok_or(SwarmError::TransferNotFound {
                    transfer_id: *transfer_id,
                })?;

        transfer_map
            .piece_status
            .get(piece_id)
            .cloned()
            .ok_or(SwarmError::PieceNotFound {
                piece_id: *piece_id,
            })
    }

    /// Get transfer progress statistics.
    pub fn get_transfer_progress(
        &self,
        transfer_id: &MailboxTransferId,
    ) -> SwarmResult<TransferProgress> {
        let transfer_map =
            self.transfer_maps
                .get(transfer_id)
                .ok_or(SwarmError::TransferNotFound {
                    transfer_id: *transfer_id,
                })?;

        let mut progress = TransferProgress::default();
        progress.total_pieces = transfer_map.total_pieces;

        for status in transfer_map.piece_status.values() {
            match status {
                PieceStatus::Needed => progress.needed += 1,
                PieceStatus::Requested { .. } => progress.requested += 1,
                PieceStatus::Downloading { .. } => progress.downloading += 1,
                PieceStatus::Completed { .. } => progress.completed += 1,
                PieceStatus::Failed { .. } => progress.failed += 1,
                PieceStatus::Verifying { .. } => progress.verifying += 1,
            }
        }

        progress.completion_percentage = if progress.total_pieces > 0 {
            (progress.completed as f64 / progress.total_pieces as f64) * 100.0
        } else {
            0.0
        };

        Ok(progress)
    }

    /// Clean up completed transfers.
    pub fn cleanup_transfer(&mut self, transfer_id: &MailboxTransferId) {
        if let Some(transfer_map) = self.transfer_maps.remove(transfer_id) {
            let mut empty_piece_entries = Vec::new();

            for pieces in transfer_map.peer_pieces.values() {
                for piece_id in pieces {
                    if let Some(peer_set) = self.global_availability.get_mut(piece_id) {
                        for peer_id in transfer_map.peer_pieces.keys() {
                            peer_set.remove(peer_id);
                        }
                        if peer_set.is_empty() {
                            empty_piece_entries.push(*piece_id);
                        }
                    }
                }
            }

            for piece_id in empty_piece_entries {
                self.global_availability.remove(&piece_id);
            }
        }
    }

    /// Return the tracked redundancy for a piece in a transfer.
    pub fn get_piece_redundancy(
        &self,
        transfer_id: &MailboxTransferId,
        piece_id: &PieceId,
    ) -> SwarmResult<u32> {
        let transfer_map =
            self.transfer_maps
                .get(transfer_id)
                .ok_or(SwarmError::TransferNotFound {
                    transfer_id: *transfer_id,
                })?;

        transfer_map
            .redundancy
            .get(piece_id)
            .copied()
            .ok_or(SwarmError::PieceNotFound {
                piece_id: *piece_id,
            })
    }

    /// Get pieces available from a specific peer.
    pub fn get_peer_pieces(
        &self,
        transfer_id: &MailboxTransferId,
        peer_id: &PeerId,
    ) -> SwarmResult<BTreeSet<PieceId>> {
        let transfer_map =
            self.transfer_maps
                .get(transfer_id)
                .ok_or(SwarmError::TransferNotFound {
                    transfer_id: *transfer_id,
                })?;

        Ok(transfer_map
            .peer_pieces
            .get(peer_id)
            .cloned()
            .unwrap_or_default())
    }
}

/// Progress statistics for a transfer.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TransferProgress {
    /// Total number of pieces
    pub total_pieces: u64,

    /// Pieces still needed
    pub needed: u64,

    /// Pieces requested but not yet downloading
    pub requested: u64,

    /// Pieces currently downloading
    pub downloading: u64,

    /// Pieces being verified
    pub verifying: u64,

    /// Pieces completed successfully
    pub completed: u64,

    /// Pieces that failed
    pub failed: u64,

    /// Overall completion percentage
    pub completion_percentage: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_piece_map() -> PieceMap {
        let mut piece_map = PieceMap::new(10, 1024, "test-hash".to_string());

        let peer1 = PeerId::new("peer1");
        let peer2 = PeerId::new("peer2");

        piece_map.add_peer_pieces(peer1, (0..5).map(PieceId::new).collect());
        piece_map.add_peer_pieces(peer2, (3..10).map(PieceId::new).collect());

        piece_map
    }

    #[test]
    fn test_piece_tracker_creation() {
        let tracker = PieceTracker::new();
        assert_eq!(tracker.transfer_maps.len(), 0);
        assert_eq!(tracker.global_availability.len(), 0);
    }

    #[test]
    fn test_initialize_transfer() {
        let mut tracker = PieceTracker::new();
        let piece_map = create_test_piece_map();
        let transfer_id = MailboxTransferId::new();

        let result = tracker.initialize_transfer(&transfer_id, &piece_map);
        assert!(result.is_ok());
        assert!(tracker.transfer_maps.contains_key(&transfer_id));
    }

    #[test]
    fn test_get_needed_pieces() {
        let mut tracker = PieceTracker::new();
        let piece_map = create_test_piece_map();
        let transfer_id = MailboxTransferId::new();

        tracker
            .initialize_transfer(&transfer_id, &piece_map)
            .unwrap();
        let needed = tracker.get_needed_pieces(&transfer_id).unwrap();

        assert_eq!(needed.len(), 10); // All pieces initially needed
    }

    #[test]
    fn test_piece_status_transitions() {
        let mut tracker = PieceTracker::new();
        let piece_map = create_test_piece_map();
        let transfer_id = MailboxTransferId::new();
        let piece_id = PieceId::new(0);
        let peer_id = PeerId::new("peer1");

        tracker
            .initialize_transfer(&transfer_id, &piece_map)
            .unwrap();

        // Test requested -> downloading -> completed
        tracker
            .mark_piece_requested(&transfer_id, piece_id, peer_id.clone())
            .unwrap();
        let status = tracker.get_piece_status(&transfer_id, &piece_id).unwrap();
        assert!(matches!(status, PieceStatus::Requested { .. }));

        tracker
            .mark_piece_downloading(&transfer_id, piece_id, peer_id.clone())
            .unwrap();
        let status = tracker.get_piece_status(&transfer_id, &piece_id).unwrap();
        assert!(matches!(status, PieceStatus::Downloading { .. }));

        tracker
            .mark_piece_completed(&transfer_id, piece_id)
            .unwrap();
        let status = tracker.get_piece_status(&transfer_id, &piece_id).unwrap();
        assert!(matches!(status, PieceStatus::Completed { .. }));
    }

    #[test]
    fn test_transfer_progress() {
        let mut tracker = PieceTracker::new();
        let piece_map = create_test_piece_map();
        let transfer_id = MailboxTransferId::new();

        tracker
            .initialize_transfer(&transfer_id, &piece_map)
            .unwrap();

        // Complete one piece
        let piece_id = PieceId::new(0);
        let peer_id = PeerId::new("peer1");
        tracker
            .mark_piece_downloading(&transfer_id, piece_id, peer_id)
            .unwrap();
        tracker
            .mark_piece_completed(&transfer_id, piece_id)
            .unwrap();

        let progress = tracker.get_transfer_progress(&transfer_id).unwrap();
        assert_eq!(progress.total_pieces, 10);
        assert_eq!(progress.completed, 1);
        assert_eq!(progress.needed, 9);
        assert_eq!(progress.completion_percentage, 10.0);
    }

    #[test]
    fn test_piece_map_redundancy() {
        let piece_map = create_test_piece_map();

        // Piece 0: only on peer1 (redundancy 1)
        assert_eq!(piece_map.get_piece_redundancy(&PieceId::new(0)), 1);

        // Piece 4: on both peers (redundancy 2)
        assert_eq!(piece_map.get_piece_redundancy(&PieceId::new(4)), 2);

        // Piece 8: only on peer2 (redundancy 1)
        assert_eq!(piece_map.get_piece_redundancy(&PieceId::new(8)), 1);

        let stats = piece_map.get_distribution_stats();
        assert_eq!(stats.min_redundancy, 1);
        assert_eq!(stats.max_redundancy, 2);
    }

    #[test]
    fn test_pieces_by_rarity() {
        let mut tracker = PieceTracker::new();
        let piece_map = create_test_piece_map();
        let transfer_id = MailboxTransferId::new();

        tracker
            .initialize_transfer(&transfer_id, &piece_map)
            .unwrap();
        let by_rarity = tracker.get_pieces_by_rarity(&transfer_id).unwrap();

        // Should be sorted with rarest pieces (redundancy 1) first
        assert_eq!(by_rarity.len(), 10);
    }
}

// Additional error types needed for piece tracker
impl SwarmError {
    pub fn transfer_not_found(transfer_id: MailboxTransferId) -> Self {
        SwarmError::TransferNotFound { transfer_id }
    }

    pub fn piece_not_found(piece_id: PieceId) -> Self {
        SwarmError::PieceNotFound { piece_id }
    }

    pub fn invalid_piece_state(piece_id: PieceId, current_state: String) -> Self {
        SwarmError::InvalidPieceState {
            piece_id,
            current_state,
        }
    }
}

// Add missing error variants to the main SwarmError enum in mod.rs
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PieceTrackerError {
    #[error("Transfer not found: {transfer_id}")]
    TransferNotFound { transfer_id: MailboxTransferId },

    #[error("Piece not found: {piece_id:?}")]
    PieceNotFound { piece_id: PieceId },

    #[error("Invalid piece state for {piece_id:?}: {current_state}")]
    InvalidPieceState {
        piece_id: PieceId,
        current_state: String,
    },
}
