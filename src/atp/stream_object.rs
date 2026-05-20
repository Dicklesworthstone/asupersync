//! StreamObject rolling manifests and early consumer safety.
//!
//! This module implements rolling manifests for mutable stream objects that
//! allows consumers to start processing verified prefix ranges before the
//! entire stream is complete, while maintaining safety guarantees.

use crate::atp::object::{ObjectId, ManifestId, ContentId};
use crate::atp::manifest::{ChunkBoundary, ChunkMetadata};
use crate::net::atp::protocol::outcome::{AtpOutcome, AtpError};
use crate::types::outcome::Outcome;
use std::collections::{BTreeMap, BTreeSet};
use std::time::SystemTime;

/// Rolling manifest epoch representing a verified prefix of a stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamEpoch {
    /// Epoch sequence number (monotonically increasing).
    pub epoch_sequence: u64,
    /// Object identifier for this stream.
    pub object_id: ObjectId,
    /// Byte range that this epoch covers.
    pub byte_range: ByteRange,
    /// State of this epoch.
    pub state: EpochState,
    /// Chunk boundaries covered by this epoch.
    pub chunk_boundaries: Vec<ChunkBoundary>,
    /// Manifest hash for this epoch.
    pub epoch_manifest_hash: [u8; 32],
    /// Creation timestamp.
    pub created_at: SystemTime,
    /// Producer signature (if available).
    pub producer_signature: Option<Vec<u8>>,
}

impl StreamEpoch {
    /// Create a new stream epoch.
    #[must_use]
    pub fn new(
        epoch_sequence: u64,
        object_id: ObjectId,
        byte_range: ByteRange,
        state: EpochState,
        chunk_boundaries: Vec<ChunkBoundary>,
    ) -> Self {
        let epoch_manifest_hash = Self::compute_epoch_hash(&object_id, epoch_sequence, &byte_range, &chunk_boundaries);

        Self {
            epoch_sequence,
            object_id,
            byte_range,
            state,
            chunk_boundaries,
            epoch_manifest_hash,
            created_at: SystemTime::now(),
            producer_signature: None,
        }
    }

    /// Compute deterministic hash for this epoch.
    fn compute_epoch_hash(
        object_id: &ObjectId,
        epoch_sequence: u64,
        byte_range: &ByteRange,
        chunk_boundaries: &[ChunkBoundary],
    ) -> [u8; 32] {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();

        // Hash object ID
        object_id.hash_bytes().hash(&mut hasher);

        // Hash epoch sequence
        epoch_sequence.hash(&mut hasher);

        // Hash byte range
        byte_range.start.hash(&mut hasher);
        byte_range.end.hash(&mut hasher);

        // Hash chunk boundaries
        for boundary in chunk_boundaries {
            boundary.index.hash(&mut hasher);
            boundary.offset.hash(&mut hasher);
            boundary.size_bytes.hash(&mut hasher);
            boundary.content_hash.hash(&mut hasher);
        }

        let hash_val = hasher.finish();
        let mut hash = [0u8; 32];
        hash[..8].copy_from_slice(&hash_val.to_be_bytes());
        hash
    }

    /// Check if this epoch is verified and safe to consume.
    #[must_use]
    pub const fn is_verified(&self) -> bool {
        matches!(self.state, EpochState::Verified | EpochState::Final)
    }

    /// Check if this epoch is the final epoch of the stream.
    #[must_use]
    pub const fn is_final(&self) -> bool {
        matches!(self.state, EpochState::Final)
    }

    /// Check if this epoch is still provisional.
    #[must_use]
    pub const fn is_provisional(&self) -> bool {
        matches!(self.state, EpochState::Provisional)
    }

    /// Get the total size of verified content in this epoch.
    #[must_use]
    pub const fn verified_size(&self) -> u64 {
        self.byte_range.size()
    }

    /// Sign this epoch with producer signature.
    pub fn sign(&mut self, signature: Vec<u8>) {
        self.producer_signature = Some(signature);
    }
}

/// Byte range covered by a stream epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ByteRange {
    /// Start byte offset (inclusive).
    pub start: u64,
    /// End byte offset (exclusive).
    pub end: u64,
}

impl ByteRange {
    /// Create a new byte range.
    #[must_use]
    pub const fn new(start: u64, end: u64) -> Self {
        Self { start, end }
    }

    /// Get the size of this range.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    /// Check if this range is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.start >= self.end
    }

    /// Check if this range contains a specific byte offset.
    #[must_use]
    pub const fn contains(&self, offset: u64) -> bool {
        offset >= self.start && offset < self.end
    }

    /// Check if this range overlaps with another range.
    #[must_use]
    pub const fn overlaps(&self, other: &Self) -> bool {
        self.start < other.end && other.start < self.end
    }

    /// Merge two adjacent or overlapping ranges.
    #[must_use]
    pub const fn merge(&self, other: &Self) -> Option<Self> {
        if self.overlaps(other) || self.end == other.start || other.end == self.start {
            Some(Self {
                start: if self.start < other.start { self.start } else { other.start },
                end: if self.end > other.end { self.end } else { other.end },
            })
        } else {
            None
        }
    }
}

/// State of a stream epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EpochState {
    /// Epoch is still being produced (provisional).
    Provisional,
    /// Epoch has been verified and is safe to consume.
    Verified,
    /// Epoch is the final epoch of the stream.
    Final,
    /// Epoch was invalidated due to error or cancellation.
    Invalidated,
}

impl EpochState {
    /// Check if consumers can safely process this epoch.
    #[must_use]
    pub const fn is_consumable(&self) -> bool {
        matches!(self, Self::Verified | Self::Final)
    }
}

/// Rolling manifest for a stream object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamManifest {
    /// Stream object identifier.
    pub object_id: ObjectId,
    /// All epochs in chronological order.
    pub epochs: Vec<StreamEpoch>,
    /// Current stream state.
    pub stream_state: StreamState,
    /// Total verified bytes across all epochs.
    pub total_verified_bytes: u64,
    /// Total provisional bytes.
    pub total_provisional_bytes: u64,
    /// Final manifest hash (only set when stream is complete).
    pub final_manifest_hash: Option<[u8; 32]>,
    /// Creation timestamp.
    pub created_at: SystemTime,
    /// Last update timestamp.
    pub updated_at: SystemTime,
}

impl StreamManifest {
    /// Create a new stream manifest.
    #[must_use]
    pub fn new(object_id: ObjectId) -> Self {
        let now = SystemTime::now();
        Self {
            object_id,
            epochs: Vec::new(),
            stream_state: StreamState::Active,
            total_verified_bytes: 0,
            total_provisional_bytes: 0,
            final_manifest_hash: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// Add a new epoch to the manifest.
    pub fn add_epoch(&mut self, epoch: StreamEpoch) -> AtpOutcome<()> {
        // Validate epoch sequence
        if let Some(last_epoch) = self.epochs.last() {
            if epoch.epoch_sequence <= last_epoch.epoch_sequence {
                return Outcome::err(AtpError::Protocol(
                    crate::net::atp::protocol::outcome::ProtocolError::UnexpectedFrame
                ));
            }
        }

        // Validate byte range continuity
        if let Some(last_epoch) = self.epochs.last() {
            if epoch.byte_range.start != last_epoch.byte_range.end {
                return Outcome::err(AtpError::Protocol(
                    crate::net::atp::protocol::outcome::ProtocolError::UnexpectedFrame
                ));
            }
        } else if epoch.byte_range.start != 0 {
            // First epoch must start at byte 0
            return Outcome::err(AtpError::Protocol(
                crate::net::atp::protocol::outcome::ProtocolError::UnexpectedFrame
            ));
        }

        // Update totals based on epoch state
        match epoch.state {
            EpochState::Verified | EpochState::Final => {
                self.total_verified_bytes += epoch.byte_range.size();
            }
            EpochState::Provisional => {
                self.total_provisional_bytes += epoch.byte_range.size();
            }
            EpochState::Invalidated => {
                // Invalidated epochs don't contribute to totals
            }
        }

        // Mark stream as complete if this is a final epoch
        if epoch.is_final() {
            self.stream_state = StreamState::Complete;
            self.final_manifest_hash = Some(self.compute_final_hash());
        }

        self.epochs.push(epoch);
        self.updated_at = SystemTime::now();

        Outcome::ok(())
    }

    /// Promote a provisional epoch to verified state.
    pub fn verify_epoch(&mut self, epoch_sequence: u64) -> AtpOutcome<()> {
        if let Some(epoch) = self.epochs.iter_mut().find(|e| e.epoch_sequence == epoch_sequence) {
            if epoch.state == EpochState::Provisional {
                epoch.state = EpochState::Verified;

                // Update totals
                let size = epoch.byte_range.size();
                self.total_provisional_bytes = self.total_provisional_bytes.saturating_sub(size);
                self.total_verified_bytes += size;

                self.updated_at = SystemTime::now();
                return Outcome::ok(());
            }
        }

        Outcome::err(AtpError::Protocol(
            crate::net::atp::protocol::outcome::ProtocolError::SessionStateMismatch
        ))
    }

    /// Invalidate an epoch due to error or cancellation.
    pub fn invalidate_epoch(&mut self, epoch_sequence: u64) -> AtpOutcome<()> {
        if let Some(epoch) = self.epochs.iter_mut().find(|e| e.epoch_sequence == epoch_sequence) {
            let size = epoch.byte_range.size();

            // Update totals based on previous state
            match epoch.state {
                EpochState::Verified | EpochState::Final => {
                    self.total_verified_bytes = self.total_verified_bytes.saturating_sub(size);
                }
                EpochState::Provisional => {
                    self.total_provisional_bytes = self.total_provisional_bytes.saturating_sub(size);
                }
                EpochState::Invalidated => {
                    // Already invalidated
                    return Outcome::ok(());
                }
            }

            epoch.state = EpochState::Invalidated;
            self.updated_at = SystemTime::now();

            return Outcome::ok(());
        }

        Outcome::err(AtpError::Protocol(
            crate::net::atp::protocol::outcome::ProtocolError::SessionStateMismatch
        ))
    }

    /// Get verified epochs safe for consumption.
    #[must_use]
    pub fn verified_epochs(&self) -> Vec<&StreamEpoch> {
        self.epochs.iter().filter(|e| e.is_verified()).collect()
    }

    /// Get provisional epochs not yet safe to consume.
    #[must_use]
    pub fn provisional_epochs(&self) -> Vec<&StreamEpoch> {
        self.epochs.iter().filter(|e| e.is_provisional()).collect()
    }

    /// Get the latest verified byte offset.
    #[must_use]
    pub fn latest_verified_offset(&self) -> u64 {
        self.verified_epochs()
            .iter()
            .map(|e| e.byte_range.end)
            .max()
            .unwrap_or(0)
    }

    /// Check if the stream is complete.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        matches!(self.stream_state, StreamState::Complete)
    }

    /// Get resumption checkpoint for a given byte offset.
    #[must_use]
    pub fn resumption_checkpoint(&self, target_offset: u64) -> Option<ResumptionCheckpoint> {
        // Find the last verified epoch that covers or precedes the target offset
        let mut best_epoch: Option<&StreamEpoch> = None;

        for epoch in self.verified_epochs() {
            if epoch.byte_range.end <= target_offset {
                best_epoch = Some(epoch);
            }
        }

        best_epoch.map(|epoch| ResumptionCheckpoint {
            epoch_sequence: epoch.epoch_sequence,
            byte_offset: epoch.byte_range.end,
            manifest_hash: epoch.epoch_manifest_hash,
        })
    }

    /// Compute final manifest hash for completed streams.
    fn compute_final_hash(&self) -> [u8; 32] {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();

        // Hash object ID
        self.object_id.hash_bytes().hash(&mut hasher);

        // Hash all verified epochs in order
        for epoch in &self.epochs {
            if epoch.is_verified() {
                epoch.epoch_manifest_hash.hash(&mut hasher);
            }
        }

        let hash_val = hasher.finish();
        let mut hash = [0u8; 32];
        hash[..8].copy_from_slice(&hash_val.to_be_bytes());
        hash
    }
}

/// Stream state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StreamState {
    /// Stream is actively being produced.
    Active,
    /// Stream is complete and finalized.
    Complete,
    /// Stream was cancelled by producer.
    Cancelled,
    /// Stream encountered an error.
    Failed,
}

/// Resumption checkpoint for stream recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResumptionCheckpoint {
    /// Last successfully processed epoch.
    pub epoch_sequence: u64,
    /// Byte offset to resume from.
    pub byte_offset: u64,
    /// Manifest hash at checkpoint.
    pub manifest_hash: [u8; 32],
}

/// Consumer safety guard for prefix consumption.
#[derive(Debug, Clone)]
pub struct PrefixConsumer {
    /// Stream manifest reference.
    manifest: StreamManifest,
    /// Current consumption offset.
    consumption_offset: u64,
    /// Safety policy for consumption.
    safety_policy: ConsumptionPolicy,
}

impl PrefixConsumer {
    /// Create a new prefix consumer.
    #[must_use]
    pub fn new(manifest: StreamManifest, safety_policy: ConsumptionPolicy) -> Self {
        Self {
            manifest,
            consumption_offset: 0,
            safety_policy,
        }
    }

    /// Check if data is available for consumption at the current offset.
    #[must_use]
    pub fn data_available(&self) -> bool {
        match self.safety_policy {
            ConsumptionPolicy::VerifiedOnly => {
                self.consumption_offset < self.manifest.latest_verified_offset()
            }
            ConsumptionPolicy::AllowProvisional => {
                self.consumption_offset < (self.manifest.total_verified_bytes + self.manifest.total_provisional_bytes)
            }
        }
    }

    /// Get the next safe range for consumption.
    #[must_use]
    pub fn next_safe_range(&self) -> Option<ByteRange> {
        match self.safety_policy {
            ConsumptionPolicy::VerifiedOnly => {
                let max_offset = self.manifest.latest_verified_offset();
                if self.consumption_offset < max_offset {
                    Some(ByteRange::new(self.consumption_offset, max_offset))
                } else {
                    None
                }
            }
            ConsumptionPolicy::AllowProvisional => {
                let max_offset = self.manifest.total_verified_bytes + self.manifest.total_provisional_bytes;
                if self.consumption_offset < max_offset {
                    Some(ByteRange::new(self.consumption_offset, max_offset))
                } else {
                    None
                }
            }
        }
    }

    /// Advance consumption offset after processing data.
    pub fn advance_consumption(&mut self, bytes_consumed: u64) {
        self.consumption_offset += bytes_consumed;
    }

    /// Get consumption progress as a percentage.
    #[must_use]
    pub fn consumption_progress(&self) -> f64 {
        let total_available = match self.safety_policy {
            ConsumptionPolicy::VerifiedOnly => self.manifest.total_verified_bytes,
            ConsumptionPolicy::AllowProvisional => {
                self.manifest.total_verified_bytes + self.manifest.total_provisional_bytes
            }
        };

        if total_available == 0 {
            0.0
        } else {
            (self.consumption_offset as f64 / total_available as f64) * 100.0
        }
    }
}

/// Policy for prefix consumption safety.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsumptionPolicy {
    /// Only consume verified epochs.
    VerifiedOnly,
    /// Allow consumption of provisional epochs (with caveats).
    AllowProvisional,
}

/// Proof bundle record for stream consumption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamProofRecord {
    /// Stream object identifier.
    pub object_id: ObjectId,
    /// Epochs that were consumed.
    pub consumed_epochs: Vec<u64>,
    /// Final consumption offset.
    pub final_offset: u64,
    /// Consumption policy used.
    pub consumption_policy: String,
    /// Whether the stream was fully consumed.
    pub fully_consumed: bool,
    /// Verification timestamp.
    pub verified_at: SystemTime,
    /// Consumer signature (if available).
    pub consumer_signature: Option<Vec<u8>>,
}

impl StreamProofRecord {
    /// Create a new stream proof record.
    #[must_use]
    pub fn new(
        object_id: ObjectId,
        consumed_epochs: Vec<u64>,
        final_offset: u64,
        consumption_policy: ConsumptionPolicy,
        fully_consumed: bool,
    ) -> Self {
        Self {
            object_id,
            consumed_epochs,
            final_offset,
            consumption_policy: match consumption_policy {
                ConsumptionPolicy::VerifiedOnly => "verified_only".to_string(),
                ConsumptionPolicy::AllowProvisional => "allow_provisional".to_string(),
            },
            fully_consumed,
            verified_at: SystemTime::now(),
            consumer_signature: None,
        }
    }

    /// Sign this proof record.
    pub fn sign(&mut self, signature: Vec<u8>) {
        self.consumer_signature = Some(signature);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_object_id() -> ObjectId {
        ObjectId::content(ContentId::new([1u8; 32]))
    }

    #[test]
    fn test_byte_range_operations() {
        let range1 = ByteRange::new(0, 100);
        let range2 = ByteRange::new(100, 200);
        let range3 = ByteRange::new(50, 150);

        assert_eq!(range1.size(), 100);
        assert!(!range1.is_empty());
        assert!(range1.contains(50));
        assert!(!range1.contains(100));

        // Adjacent ranges don't overlap but can merge
        assert!(!range1.overlaps(&range2));
        assert!(range1.merge(&range2).is_some());

        // Overlapping ranges
        assert!(range1.overlaps(&range3));
        let merged = range1.merge(&range3).unwrap();
        assert_eq!(merged, ByteRange::new(0, 150));
    }

    #[test]
    fn test_stream_epoch_creation() {
        let object_id = test_object_id();
        let byte_range = ByteRange::new(0, 1024);
        let chunk_boundaries = vec![];

        let epoch = StreamEpoch::new(
            1,
            object_id.clone(),
            byte_range,
            EpochState::Verified,
            chunk_boundaries,
        );

        assert_eq!(epoch.epoch_sequence, 1);
        assert_eq!(epoch.object_id, object_id);
        assert_eq!(epoch.byte_range, byte_range);
        assert!(epoch.is_verified());
        assert!(!epoch.is_final());
        assert!(!epoch.is_provisional());
        assert_eq!(epoch.verified_size(), 1024);
    }

    #[test]
    fn test_stream_manifest_lifecycle() {
        let object_id = test_object_id();
        let mut manifest = StreamManifest::new(object_id.clone());

        assert!(!manifest.is_complete());
        assert_eq!(manifest.total_verified_bytes, 0);
        assert_eq!(manifest.verified_epochs().len(), 0);

        // Add first epoch
        let epoch1 = StreamEpoch::new(
            1,
            object_id.clone(),
            ByteRange::new(0, 1024),
            EpochState::Verified,
            vec![],
        );
        manifest.add_epoch(epoch1).unwrap();

        assert_eq!(manifest.total_verified_bytes, 1024);
        assert_eq!(manifest.verified_epochs().len(), 1);

        // Add provisional epoch
        let epoch2 = StreamEpoch::new(
            2,
            object_id.clone(),
            ByteRange::new(1024, 2048),
            EpochState::Provisional,
            vec![],
        );
        manifest.add_epoch(epoch2).unwrap();

        assert_eq!(manifest.total_provisional_bytes, 1024);
        assert_eq!(manifest.provisional_epochs().len(), 1);

        // Verify provisional epoch
        manifest.verify_epoch(2).unwrap();
        assert_eq!(manifest.total_verified_bytes, 2048);
        assert_eq!(manifest.total_provisional_bytes, 0);

        // Add final epoch
        let epoch3 = StreamEpoch::new(
            3,
            object_id.clone(),
            ByteRange::new(2048, 3072),
            EpochState::Final,
            vec![],
        );
        manifest.add_epoch(epoch3).unwrap();

        assert!(manifest.is_complete());
        assert!(manifest.final_manifest_hash.is_some());
    }

    #[test]
    fn test_prefix_consumer() {
        let object_id = test_object_id();
        let mut manifest = StreamManifest::new(object_id.clone());

        // Add verified epoch
        let epoch1 = StreamEpoch::new(
            1,
            object_id.clone(),
            ByteRange::new(0, 1024),
            EpochState::Verified,
            vec![],
        );
        manifest.add_epoch(epoch1).unwrap();

        // Add provisional epoch
        let epoch2 = StreamEpoch::new(
            2,
            object_id.clone(),
            ByteRange::new(1024, 2048),
            EpochState::Provisional,
            vec![],
        );
        manifest.add_epoch(epoch2).unwrap();

        // Test verified-only consumer
        let mut consumer = PrefixConsumer::new(manifest.clone(), ConsumptionPolicy::VerifiedOnly);
        assert!(consumer.data_available());

        let safe_range = consumer.next_safe_range().unwrap();
        assert_eq!(safe_range, ByteRange::new(0, 1024));

        consumer.advance_consumption(512);
        assert_eq!(consumer.consumption_progress(), 50.0);

        // Test provisional-allowing consumer
        let mut consumer_prov = PrefixConsumer::new(manifest, ConsumptionPolicy::AllowProvisional);
        let safe_range_prov = consumer_prov.next_safe_range().unwrap();
        assert_eq!(safe_range_prov, ByteRange::new(0, 2048));
    }

    #[test]
    fn test_resumption_checkpoint() {
        let object_id = test_object_id();
        let mut manifest = StreamManifest::new(object_id.clone());

        // Add multiple verified epochs
        for i in 0..3 {
            let epoch = StreamEpoch::new(
                i + 1,
                object_id.clone(),
                ByteRange::new(i * 1024, (i + 1) * 1024),
                EpochState::Verified,
                vec![],
            );
            manifest.add_epoch(epoch).unwrap();
        }

        // Test checkpoint at middle of stream
        let checkpoint = manifest.resumption_checkpoint(2500);
        assert!(checkpoint.is_some());

        let cp = checkpoint.unwrap();
        assert_eq!(cp.epoch_sequence, 2); // Last epoch that ends before 2500
        assert_eq!(cp.byte_offset, 2048); // End of epoch 2
    }

    #[test]
    fn test_stream_proof_record() {
        let object_id = test_object_id();
        let consumed_epochs = vec![1, 2, 3];

        let mut proof = StreamProofRecord::new(
            object_id.clone(),
            consumed_epochs.clone(),
            3072,
            ConsumptionPolicy::VerifiedOnly,
            true,
        );

        assert_eq!(proof.object_id, object_id);
        assert_eq!(proof.consumed_epochs, consumed_epochs);
        assert_eq!(proof.final_offset, 3072);
        assert_eq!(proof.consumption_policy, "verified_only");
        assert!(proof.fully_consumed);
        assert!(proof.consumer_signature.is_none());

        // Test signing
        proof.sign(vec![0xFF; 64]);
        assert!(proof.consumer_signature.is_some());
    }

    #[test]
    fn test_epoch_validation() {
        let object_id = test_object_id();
        let mut manifest = StreamManifest::new(object_id.clone());

        // First epoch must start at 0
        let invalid_epoch = StreamEpoch::new(
            1,
            object_id.clone(),
            ByteRange::new(100, 200), // Invalid start
            EpochState::Verified,
            vec![],
        );
        assert!(manifest.add_epoch(invalid_epoch).is_err());

        // Valid first epoch
        let valid_epoch1 = StreamEpoch::new(
            1,
            object_id.clone(),
            ByteRange::new(0, 100),
            EpochState::Verified,
            vec![],
        );
        assert!(manifest.add_epoch(valid_epoch1).is_ok());

        // Second epoch must be continuous
        let invalid_epoch2 = StreamEpoch::new(
            2,
            object_id.clone(),
            ByteRange::new(200, 300), // Gap from 100-200
            EpochState::Verified,
            vec![],
        );
        assert!(manifest.add_epoch(invalid_epoch2).is_err());

        // Valid continuous epoch
        let valid_epoch2 = StreamEpoch::new(
            2,
            object_id.clone(),
            ByteRange::new(100, 200),
            EpochState::Verified,
            vec![],
        );
        assert!(manifest.add_epoch(valid_epoch2).is_ok());
    }
}