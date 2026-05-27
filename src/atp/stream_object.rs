//! StreamObject rolling manifests and early consumer safety.
//!
//! This module implements rolling manifests for mutable stream objects that
//! allows consumers to start processing verified prefix ranges before the
//! entire stream is complete, while maintaining safety guarantees.

use crate::atp::manifest::ChunkBoundary;
use crate::atp::object::ObjectId;
use crate::net::atp::protocol::outcome::{AtpError, AtpOutcome};
use crate::types::outcome::Outcome;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

/// Stable schema for stream prefix proof artifacts.
pub const STREAM_PREFIX_PROOF_ARTIFACT_SCHEMA: &str = "asupersync.atp.stream-prefix-proof.v1";

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
        let epoch_manifest_hash =
            Self::compute_epoch_hash(&object_id, epoch_sequence, &byte_range, &chunk_boundaries);

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
        let mut hasher = Sha256::new();

        hasher.update(b"asupersync.stream_epoch.v1");
        hasher.update(object_id.hash_bytes());
        hasher.update(epoch_sequence.to_be_bytes());
        hasher.update(byte_range.start.to_be_bytes());
        hasher.update(byte_range.end.to_be_bytes());
        hasher.update((chunk_boundaries.len() as u64).to_be_bytes());
        for boundary in chunk_boundaries {
            hasher.update(boundary.index.to_be_bytes());
            hasher.update(boundary.byte_offset.to_be_bytes());
            hasher.update(boundary.size_bytes.to_be_bytes());
            hasher.update(boundary.content_hash);
        }

        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hasher.finalize());
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
                start: if self.start < other.start {
                    self.start
                } else {
                    other.start
                },
                end: if self.end > other.end {
                    self.end
                } else {
                    other.end
                },
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
        if matches!(
            self.stream_state,
            StreamState::Complete | StreamState::Cancelled | StreamState::Failed
        ) {
            return Outcome::err(AtpError::Protocol(
                crate::net::atp::protocol::outcome::ProtocolError::SessionStateMismatch,
            ));
        }

        // Validate epoch sequence
        if let Some(last_epoch) = self.epochs.last() {
            if epoch.epoch_sequence <= last_epoch.epoch_sequence {
                return Outcome::err(AtpError::Protocol(
                    crate::net::atp::protocol::outcome::ProtocolError::UnexpectedFrame,
                ));
            }
        }

        // Validate byte range continuity
        if let Some(last_epoch) = self.epochs.last() {
            if epoch.byte_range.start != last_epoch.byte_range.end {
                return Outcome::err(AtpError::Protocol(
                    crate::net::atp::protocol::outcome::ProtocolError::UnexpectedFrame,
                ));
            }
        } else if epoch.byte_range.start != 0 {
            // First epoch must start at byte 0
            return Outcome::err(AtpError::Protocol(
                crate::net::atp::protocol::outcome::ProtocolError::UnexpectedFrame,
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
        if let Some(epoch) = self
            .epochs
            .iter_mut()
            .find(|e| e.epoch_sequence == epoch_sequence)
        {
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
            crate::net::atp::protocol::outcome::ProtocolError::SessionStateMismatch,
        ))
    }

    /// Invalidate an epoch due to error or cancellation.
    pub fn invalidate_epoch(&mut self, epoch_sequence: u64) -> AtpOutcome<()> {
        if let Some(epoch) = self
            .epochs
            .iter_mut()
            .find(|e| e.epoch_sequence == epoch_sequence)
        {
            let size = epoch.byte_range.size();

            // Update totals based on previous state
            match epoch.state {
                EpochState::Verified | EpochState::Final => {
                    self.total_verified_bytes = self.total_verified_bytes.saturating_sub(size);
                }
                EpochState::Provisional => {
                    self.total_provisional_bytes =
                        self.total_provisional_bytes.saturating_sub(size);
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
            crate::net::atp::protocol::outcome::ProtocolError::SessionStateMismatch,
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

    /// Get the contiguous verified prefix end offset.
    #[must_use]
    pub fn verified_prefix_end(&self) -> u64 {
        self.consumable_prefix_end(ConsumptionPolicy::VerifiedOnly)
    }

    /// Get the contiguous prefix end offset exposed under a consumption policy.
    #[must_use]
    pub fn consumable_prefix_end(&self, policy: ConsumptionPolicy) -> u64 {
        let mut expected_start = 0;

        for epoch in &self.epochs {
            if epoch.byte_range.start != expected_start {
                break;
            }

            let consumable = matches!(
                (policy, epoch.state),
                (
                    ConsumptionPolicy::VerifiedOnly,
                    EpochState::Verified | EpochState::Final
                ) | (
                    ConsumptionPolicy::AllowProvisional,
                    EpochState::Verified | EpochState::Final | EpochState::Provisional,
                )
            );

            if !consumable {
                break;
            }

            expected_start = epoch.byte_range.end;
        }

        expected_start
    }

    /// Check if the stream is complete.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        matches!(self.stream_state, StreamState::Complete)
    }

    /// Get resumption checkpoint for a given byte offset.
    #[must_use]
    pub fn resumption_checkpoint(&self, target_offset: u64) -> Option<ResumptionCheckpoint> {
        // Resume checkpoints must follow the same prefix-safety rule as
        // consumers: a later verified epoch is not safe if an earlier epoch was
        // invalidated or is still provisional.
        let mut expected_start = 0;
        let mut best_epoch = None;

        for epoch in &self.epochs {
            if epoch.byte_range.start != expected_start || !epoch.is_verified() {
                break;
            }

            if epoch.byte_range.end <= target_offset {
                best_epoch = Some(epoch);
            }

            expected_start = epoch.byte_range.end;
        }

        best_epoch.map(|epoch| ResumptionCheckpoint {
            epoch_sequence: epoch.epoch_sequence,
            byte_offset: epoch.byte_range.end,
            manifest_hash: epoch.epoch_manifest_hash,
        })
    }

    /// Compute final manifest hash for completed streams.
    fn compute_final_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();

        hasher.update(b"asupersync.stream_manifest.v1");
        hasher.update(self.object_id.hash_bytes());
        for epoch in &self.epochs {
            if epoch.is_verified() {
                hasher.update(epoch.epoch_sequence.to_be_bytes());
                hasher.update(epoch.epoch_manifest_hash);
            }
        }

        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hasher.finalize());
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

/// Result of refreshing a consumer against a newer stream manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrefixRefresh {
    /// Safe prefix before the manifest refresh.
    pub previous_prefix_end: u64,
    /// Safe prefix after the manifest refresh.
    pub available_prefix_end: u64,
    /// Consumer offset after the refresh.
    pub consumption_offset: u64,
    /// Previously consumed range that is no longer safe under the new manifest.
    pub invalidated_consumed_range: Option<ByteRange>,
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

    fn available_prefix_end(&self) -> u64 {
        self.manifest.consumable_prefix_end(self.safety_policy)
    }

    /// Refresh this consumer with a newer manifest for the same stream.
    ///
    /// If the new manifest invalidates bytes that were already consumed, the
    /// consumer rewinds to the new safe prefix and reports the invalidated
    /// range so callers can discard or replay side effects.
    pub fn refresh_manifest(&mut self, manifest: StreamManifest) -> AtpOutcome<PrefixRefresh> {
        if manifest.object_id != self.manifest.object_id {
            return Outcome::err(AtpError::Protocol(
                crate::net::atp::protocol::outcome::ProtocolError::SessionStateMismatch,
            ));
        }

        let previous_prefix_end = self.available_prefix_end();
        self.manifest = manifest;
        let available_prefix_end = self.available_prefix_end();
        let invalidated_consumed_range = if self.consumption_offset > available_prefix_end {
            Some(ByteRange::new(
                available_prefix_end,
                self.consumption_offset,
            ))
        } else {
            None
        };

        if invalidated_consumed_range.is_some() {
            self.consumption_offset = available_prefix_end;
        }

        Outcome::ok(PrefixRefresh {
            previous_prefix_end,
            available_prefix_end,
            consumption_offset: self.consumption_offset,
            invalidated_consumed_range,
        })
    }

    /// Refresh the manifest and produce a proof/log exposure record.
    pub fn refresh_manifest_with_exposure_record(
        &mut self,
        manifest: StreamManifest,
        invalidation_reason: Option<String>,
        replay_pointer: Option<String>,
    ) -> AtpOutcome<(PrefixRefresh, PrefixExposureRecord)> {
        match self.refresh_manifest(manifest) {
            Outcome::Ok(refresh) => {
                let mut exposure = self.exposure_record(replay_pointer);

                if let Some(invalidated_range) = refresh.invalidated_consumed_range {
                    exposure.prefix_range = Some(invalidated_range);
                    exposure.verified_state = PrefixVerifiedState::Invalidated;
                    exposure.exposure_decision = PrefixExposureDecision::Withhold;
                    exposure.invalidation_reason = Some(invalidation_reason.unwrap_or_else(|| {
                        "manifest refresh invalidated a previously consumed prefix".to_string()
                    }));
                }

                Outcome::ok((refresh, exposure))
            }
            Outcome::Err(err) => Outcome::Err(err),
            Outcome::Cancelled(reason) => Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => Outcome::Panicked(payload),
        }
    }

    /// Check if data is available for consumption at the current offset.
    #[must_use]
    pub fn data_available(&self) -> bool {
        self.consumption_offset < self.available_prefix_end()
    }

    /// Get the next safe range for consumption.
    #[must_use]
    pub fn next_safe_range(&self) -> Option<ByteRange> {
        let max_offset = self.available_prefix_end();
        if self.consumption_offset < max_offset {
            Some(ByteRange::new(self.consumption_offset, max_offset))
        } else {
            None
        }
    }

    /// Advance consumption offset after processing data.
    pub fn advance_consumption(&mut self, bytes_consumed: u64) {
        self.consumption_offset = self
            .consumption_offset
            .saturating_add(bytes_consumed)
            .min(self.available_prefix_end());
    }

    /// Build the proof/log record for the current prefix exposure decision.
    #[must_use]
    pub fn exposure_record(&self, replay_pointer: Option<String>) -> PrefixExposureRecord {
        let prefix_range = self.next_safe_range();
        let verified_prefix_end = self.manifest.verified_prefix_end();
        let (verified_state, exposure_decision) = match prefix_range {
            Some(range) if range.end <= verified_prefix_end => (
                PrefixVerifiedState::Verified,
                PrefixExposureDecision::Expose,
            ),
            Some(_) => (
                PrefixVerifiedState::Provisional,
                PrefixExposureDecision::Expose,
            ),
            None => (
                PrefixVerifiedState::NoConsumablePrefix,
                PrefixExposureDecision::Withhold,
            ),
        };

        PrefixExposureRecord::new(
            self.manifest.object_id.clone(),
            prefix_range,
            verified_state,
            exposure_decision,
            self.safety_policy,
            replay_pointer,
        )
    }

    /// Get consumption progress as a percentage.
    #[must_use]
    pub fn consumption_progress(&self) -> f64 {
        let total_available = self.available_prefix_end();

        if total_available == 0 {
            0.0
        } else {
            (self.consumption_offset.min(total_available) as f64 / total_available as f64) * 100.0
        }
    }
}

/// Policy for prefix consumption safety.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsumptionPolicy {
    /// Only consume verified epochs.
    VerifiedOnly,
    /// Allow consumption of provisional epochs (with caveats).
    AllowProvisional,
}

impl ConsumptionPolicy {
    /// Stable policy identifier for proof and log artifacts.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::VerifiedOnly => "verified_only",
            Self::AllowProvisional => "allow_provisional",
        }
    }
}

/// Verification state recorded for a prefix exposure decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrefixVerifiedState {
    /// No prefix is currently safe to expose.
    NoConsumablePrefix,
    /// The exposed prefix contains only verified epochs.
    Verified,
    /// The exposed prefix includes provisional epochs under explicit policy.
    Provisional,
    /// Previously exposed bytes were invalidated by a later manifest.
    Invalidated,
}

impl PrefixVerifiedState {
    /// Stable identifier for proof and log artifacts.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoConsumablePrefix => "no_consumable_prefix",
            Self::Verified => "verified",
            Self::Provisional => "provisional",
            Self::Invalidated => "invalidated",
        }
    }
}

/// Consumer exposure decision for a stream prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrefixExposureDecision {
    /// The prefix may be exposed to the consumer.
    Expose,
    /// The prefix must be withheld from the consumer.
    Withhold,
}

impl PrefixExposureDecision {
    /// Stable identifier for proof and log artifacts.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Expose => "expose",
            Self::Withhold => "withhold",
        }
    }
}

/// Serializable proof/log artifact for a stream prefix exposure decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrefixExposureArtifact {
    /// Full stream object identifier.
    pub object_id: String,
    /// Hex-encoded object hash for parser-friendly correlation.
    pub object_hash: String,
    /// Prefix range considered by the decision.
    pub prefix_range: Option<ByteRange>,
    /// Stable verification state string.
    pub verified_state: String,
    /// Stable consumer exposure decision string.
    pub exposure_decision: String,
    /// Reason a previously exposed prefix was invalidated, if any.
    pub invalidation_reason: Option<String>,
    /// Deterministic replay pointer for reproducing the decision.
    pub replay_pointer: Option<String>,
    /// Consumption policy used for the decision.
    pub consumption_policy: String,
    /// Record timestamp as Unix nanoseconds, saturated for portable JSON.
    pub recorded_at_unix_nanos: u64,
}

/// Serializable stream proof artifact for prefix-first consumption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamPrefixProofArtifact {
    /// Stable schema identifier.
    pub schema_version: String,
    /// Full stream object identifier.
    pub object_id: String,
    /// Hex-encoded object hash for parser-friendly correlation.
    pub object_hash: String,
    /// Epochs that were consumed.
    pub consumed_epochs: Vec<u64>,
    /// Final consumption offset.
    pub final_offset: u64,
    /// Consumption policy used.
    pub consumption_policy: String,
    /// Whether the stream was fully consumed.
    pub fully_consumed: bool,
    /// Prefix exposure records that justify early consumer visibility.
    pub prefix_exposures: Vec<PrefixExposureArtifact>,
    /// Verification timestamp as Unix nanoseconds, saturated for portable JSON.
    pub verified_at_unix_nanos: u64,
    /// Hex-encoded consumer signature, if available.
    pub consumer_signature_hex: Option<String>,
}

/// Proof/log record for a prefix exposure decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrefixExposureRecord {
    /// Stream object identifier.
    pub object_id: ObjectId,
    /// Prefix range considered by the decision.
    pub prefix_range: Option<ByteRange>,
    /// Verification state for the considered prefix.
    pub verified_state: PrefixVerifiedState,
    /// Consumer-facing exposure decision.
    pub exposure_decision: PrefixExposureDecision,
    /// Reason a previously exposed prefix was invalidated, if any.
    pub invalidation_reason: Option<String>,
    /// Deterministic replay pointer for reproducing the decision.
    pub replay_pointer: Option<String>,
    /// Consumption policy used for the decision.
    pub consumption_policy: String,
    /// Time the record was produced.
    pub recorded_at: SystemTime,
}

impl PrefixExposureRecord {
    /// Create a new prefix exposure record.
    #[must_use]
    pub fn new(
        object_id: ObjectId,
        prefix_range: Option<ByteRange>,
        verified_state: PrefixVerifiedState,
        exposure_decision: PrefixExposureDecision,
        consumption_policy: ConsumptionPolicy,
        replay_pointer: Option<String>,
    ) -> Self {
        Self {
            object_id,
            prefix_range,
            verified_state,
            exposure_decision,
            invalidation_reason: None,
            replay_pointer,
            consumption_policy: consumption_policy.as_str().to_string(),
            recorded_at: SystemTime::now(),
        }
    }

    /// Convert this in-memory record into a stable serializable artifact.
    #[must_use]
    pub fn to_artifact(&self) -> PrefixExposureArtifact {
        PrefixExposureArtifact {
            object_id: object_id_artifact_id(&self.object_id),
            object_hash: self.object_id.as_hex(),
            prefix_range: self.prefix_range,
            verified_state: self.verified_state.as_str().to_string(),
            exposure_decision: self.exposure_decision.as_str().to_string(),
            invalidation_reason: self.invalidation_reason.clone(),
            replay_pointer: self.replay_pointer.clone(),
            consumption_policy: self.consumption_policy.clone(),
            recorded_at_unix_nanos: system_time_unix_nanos(self.recorded_at),
        }
    }
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
    /// Prefix exposure records that justify early consumer visibility.
    pub prefix_exposures: Vec<PrefixExposureRecord>,
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
            consumption_policy: consumption_policy.as_str().to_string(),
            fully_consumed,
            prefix_exposures: Vec::new(),
            verified_at: SystemTime::now(),
            consumer_signature: None,
        }
    }

    /// Attach a prefix exposure record to this proof record.
    pub fn record_prefix_exposure(&mut self, exposure: PrefixExposureRecord) {
        self.prefix_exposures.push(exposure);
    }

    /// Sign this proof record.
    pub fn sign(&mut self, signature: Vec<u8>) {
        self.consumer_signature = Some(signature);
    }

    /// Convert this proof record into a stable serializable artifact.
    #[must_use]
    pub fn to_artifact(&self) -> StreamPrefixProofArtifact {
        StreamPrefixProofArtifact {
            schema_version: STREAM_PREFIX_PROOF_ARTIFACT_SCHEMA.to_string(),
            object_id: object_id_artifact_id(&self.object_id),
            object_hash: self.object_id.as_hex(),
            consumed_epochs: self.consumed_epochs.clone(),
            final_offset: self.final_offset,
            consumption_policy: self.consumption_policy.clone(),
            fully_consumed: self.fully_consumed,
            prefix_exposures: self
                .prefix_exposures
                .iter()
                .map(PrefixExposureRecord::to_artifact)
                .collect(),
            verified_at_unix_nanos: system_time_unix_nanos(self.verified_at),
            consumer_signature_hex: self.consumer_signature.as_ref().map(hex::encode),
        }
    }
}

fn object_id_artifact_id(object_id: &ObjectId) -> String {
    let kind = match object_id {
        ObjectId::Content(_) => "content",
        ObjectId::Manifest(_) => "manifest",
    };
    format!("{kind}:{}", object_id.as_hex())
}

fn system_time_unix_nanos(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH).map_or(0, |duration| {
        u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
    })
}

// Additional StreamObject methods for ATP-E4 early usability support
impl StreamManifest {
    /// Mark a chunk range as verified for early consumption.
    pub fn mark_chunk_verified(&mut self, start_offset: u64, size: u64) -> AtpOutcome<()> {
        let epoch_id = self.epochs.len() as u64 + 1;
        let byte_range = ByteRange::new(start_offset, start_offset + size);
        let epoch = StreamEpoch::new(
            epoch_id,
            self.object_id.clone(),
            byte_range,
            EpochState::Verified,
            vec![],
        );

        self.add_epoch(epoch)
    }

    /// Check if large streams require explicit prefix policy.
    pub fn requires_explicit_prefix_policy(&self) -> bool {
        self.expected_total_bytes()
            .is_some_and(|size| size > 10_000_000) // 10MB threshold
    }

    /// Check if consumption policy allows reading a given range.
    pub fn check_consumption_policy(
        &self,
        start_offset: u64,
        size: u64,
        policy: ConsumptionPolicy,
    ) -> bool {
        let end_offset = start_offset + size;
        let available_end = self.consumable_prefix_end(policy);
        end_offset <= available_end
    }

    /// Mark stream as cancelled with reason.
    pub fn mark_cancelled(&mut self, _reason: &str) {
        // Add cancellation marker epoch
        let cancellation_epoch = StreamEpoch::new(
            self.epochs.len() as u64 + 1,
            self.object_id.clone(),
            ByteRange::new(
                self.consumable_prefix_end(ConsumptionPolicy::VerifiedOnly),
                self.consumable_prefix_end(ConsumptionPolicy::VerifiedOnly),
            ),
            EpochState::Invalidated,
            vec![],
        );

        let _ = self.add_epoch(cancellation_epoch);
        self.stream_state = StreamState::Cancelled;
    }

    /// Invalidate content from a given offset due to verification failure.
    pub fn invalidate_from_offset(&mut self, offset: u64, _reason: &str) {
        // Remove or mark invalid any epochs that start at or after the offset
        self.epochs.retain(|epoch| epoch.byte_range.start < offset);

        // Add invalidation marker
        let invalidation_epoch = StreamEpoch::new(
            self.epochs.len() as u64 + 1,
            self.object_id.clone(),
            ByteRange::new(offset, offset),
            EpochState::Invalidated,
            vec![],
        );

        let _ = self.add_epoch(invalidation_epoch);
    }

    /// Get expected total bytes for this stream.
    pub fn expected_total_bytes(&self) -> Option<u64> {
        // Implementation would check manifest metadata
        self.epochs.last().map(|e| e.byte_range.end)
    }
}

impl EpochState {
    pub fn is_verified(&self) -> bool {
        matches!(self, EpochState::Verified | EpochState::Final)
    }

    pub fn is_provisional(&self) -> bool {
        matches!(self, EpochState::Provisional)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atp::manifest::ChunkStrategy;
    use crate::atp::object::ContentId;

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
    fn epoch_hash_uses_full_deterministic_sha256() {
        let object_id = test_object_id();
        let boundary = ChunkBoundary {
            index: 7,
            byte_offset: 128,
            size_bytes: 256,
            content_hash: [0x5a; 32],
            strategy: ChunkStrategy::ContentDefined,
            metadata: None,
        };

        let hash_a = StreamEpoch::compute_epoch_hash(
            &object_id,
            3,
            &ByteRange::new(128, 384),
            std::slice::from_ref(&boundary),
        );
        let hash_b = StreamEpoch::compute_epoch_hash(
            &object_id,
            3,
            &ByteRange::new(128, 384),
            std::slice::from_ref(&boundary),
        );
        let hash_c = StreamEpoch::compute_epoch_hash(
            &object_id,
            4,
            &ByteRange::new(128, 384),
            std::slice::from_ref(&boundary),
        );

        assert_eq!(hash_a, hash_b);
        assert_ne!(hash_a, hash_c);
        assert!(hash_a[8..].iter().any(|&byte| byte != 0));
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
        let consumer_prov = PrefixConsumer::new(manifest, ConsumptionPolicy::AllowProvisional);
        let safe_range_prov = consumer_prov.next_safe_range().unwrap();
        assert_eq!(safe_range_prov, ByteRange::new(0, 2048));
    }

    #[test]
    fn prefix_exposure_record_includes_verified_prefix_proof_fields() {
        let object_id = test_object_id();
        let mut manifest = StreamManifest::new(object_id.clone());

        manifest
            .add_epoch(StreamEpoch::new(
                1,
                object_id.clone(),
                ByteRange::new(0, 100),
                EpochState::Verified,
                vec![],
            ))
            .unwrap();
        manifest
            .add_epoch(StreamEpoch::new(
                2,
                object_id.clone(),
                ByteRange::new(100, 200),
                EpochState::Provisional,
                vec![],
            ))
            .unwrap();

        let consumer = PrefixConsumer::new(manifest, ConsumptionPolicy::VerifiedOnly);
        let record = consumer.exposure_record(Some("replay:prefix-verified".to_string()));

        assert_eq!(record.object_id, object_id);
        assert_eq!(record.prefix_range, Some(ByteRange::new(0, 100)));
        assert_eq!(record.verified_state, PrefixVerifiedState::Verified);
        assert_eq!(record.exposure_decision, PrefixExposureDecision::Expose);
        assert_eq!(record.invalidation_reason, None);
        assert_eq!(
            record.replay_pointer.as_deref(),
            Some("replay:prefix-verified")
        );
        assert_eq!(record.consumption_policy, "verified_only");
    }

    #[test]
    fn prefix_exposure_record_marks_provisional_policy_caveat() {
        let object_id = test_object_id();
        let mut manifest = StreamManifest::new(object_id.clone());

        manifest
            .add_epoch(StreamEpoch::new(
                1,
                object_id.clone(),
                ByteRange::new(0, 100),
                EpochState::Verified,
                vec![],
            ))
            .unwrap();
        manifest
            .add_epoch(StreamEpoch::new(
                2,
                object_id.clone(),
                ByteRange::new(100, 200),
                EpochState::Provisional,
                vec![],
            ))
            .unwrap();

        let consumer = PrefixConsumer::new(manifest, ConsumptionPolicy::AllowProvisional);
        let record = consumer.exposure_record(Some("replay:prefix-provisional".to_string()));

        assert_eq!(record.object_id, object_id);
        assert_eq!(record.prefix_range, Some(ByteRange::new(0, 200)));
        assert_eq!(record.verified_state, PrefixVerifiedState::Provisional);
        assert_eq!(record.exposure_decision, PrefixExposureDecision::Expose);
        assert_eq!(record.consumption_policy, "allow_provisional");
        assert_eq!(
            record.replay_pointer.as_deref(),
            Some("replay:prefix-provisional")
        );
    }

    #[test]
    fn verified_only_prefix_stops_before_provisional_gap() {
        let object_id = test_object_id();
        let mut manifest = StreamManifest::new(object_id.clone());

        manifest
            .add_epoch(StreamEpoch::new(
                1,
                object_id.clone(),
                ByteRange::new(0, 100),
                EpochState::Verified,
                vec![],
            ))
            .unwrap();
        manifest
            .add_epoch(StreamEpoch::new(
                2,
                object_id.clone(),
                ByteRange::new(100, 200),
                EpochState::Provisional,
                vec![],
            ))
            .unwrap();
        manifest
            .add_epoch(StreamEpoch::new(
                3,
                object_id,
                ByteRange::new(200, 300),
                EpochState::Verified,
                vec![],
            ))
            .unwrap();

        assert_eq!(manifest.latest_verified_offset(), 300);
        assert_eq!(manifest.verified_prefix_end(), 100);

        let mut consumer = PrefixConsumer::new(manifest, ConsumptionPolicy::VerifiedOnly);
        assert_eq!(consumer.next_safe_range(), Some(ByteRange::new(0, 100)));

        consumer.advance_consumption(100);
        assert!(!consumer.data_available());
        assert_eq!(consumer.next_safe_range(), None);
    }

    #[test]
    fn provisional_policy_prefix_stops_before_invalidated_gap() {
        let object_id = test_object_id();
        let mut manifest = StreamManifest::new(object_id.clone());

        manifest
            .add_epoch(StreamEpoch::new(
                1,
                object_id.clone(),
                ByteRange::new(0, 100),
                EpochState::Verified,
                vec![],
            ))
            .unwrap();
        manifest
            .add_epoch(StreamEpoch::new(
                2,
                object_id.clone(),
                ByteRange::new(100, 200),
                EpochState::Invalidated,
                vec![],
            ))
            .unwrap();
        manifest
            .add_epoch(StreamEpoch::new(
                3,
                object_id,
                ByteRange::new(200, 300),
                EpochState::Verified,
                vec![],
            ))
            .unwrap();

        let consumer = PrefixConsumer::new(manifest, ConsumptionPolicy::AllowProvisional);
        assert_eq!(consumer.next_safe_range(), Some(ByteRange::new(0, 100)));
    }

    #[test]
    fn prefix_consumer_advance_caps_at_available_prefix() {
        let object_id = test_object_id();
        let mut manifest = StreamManifest::new(object_id.clone());

        manifest
            .add_epoch(StreamEpoch::new(
                1,
                object_id,
                ByteRange::new(0, 1024),
                EpochState::Verified,
                vec![],
            ))
            .unwrap();

        let mut consumer = PrefixConsumer::new(manifest, ConsumptionPolicy::VerifiedOnly);
        consumer.advance_consumption(2048);

        assert_eq!(consumer.consumption_progress(), 100.0);
        assert_eq!(consumer.next_safe_range(), None);
    }

    #[test]
    fn prefix_consumer_refresh_reports_invalidated_consumed_bytes() {
        let object_id = test_object_id();
        let mut manifest = StreamManifest::new(object_id.clone());

        manifest
            .add_epoch(StreamEpoch::new(
                1,
                object_id.clone(),
                ByteRange::new(0, 100),
                EpochState::Verified,
                vec![],
            ))
            .unwrap();
        manifest
            .add_epoch(StreamEpoch::new(
                2,
                object_id.clone(),
                ByteRange::new(100, 200),
                EpochState::Provisional,
                vec![],
            ))
            .unwrap();

        let mut consumer =
            PrefixConsumer::new(manifest.clone(), ConsumptionPolicy::AllowProvisional);
        assert_eq!(consumer.next_safe_range(), Some(ByteRange::new(0, 200)));
        consumer.advance_consumption(200);

        manifest.invalidate_epoch(2).unwrap();
        let refresh = consumer.refresh_manifest(manifest).unwrap();

        assert_eq!(refresh.previous_prefix_end, 200);
        assert_eq!(refresh.available_prefix_end, 100);
        assert_eq!(
            refresh.invalidated_consumed_range,
            Some(ByteRange::new(100, 200))
        );
        assert_eq!(refresh.consumption_offset, 100);
        assert_eq!(consumer.next_safe_range(), None);
    }

    #[test]
    fn refresh_with_exposure_record_logs_invalidation_reason_and_replay() {
        let object_id = test_object_id();
        let mut manifest = StreamManifest::new(object_id.clone());

        manifest
            .add_epoch(StreamEpoch::new(
                1,
                object_id.clone(),
                ByteRange::new(0, 100),
                EpochState::Verified,
                vec![],
            ))
            .unwrap();
        manifest
            .add_epoch(StreamEpoch::new(
                2,
                object_id.clone(),
                ByteRange::new(100, 200),
                EpochState::Provisional,
                vec![],
            ))
            .unwrap();

        let mut consumer =
            PrefixConsumer::new(manifest.clone(), ConsumptionPolicy::AllowProvisional);
        consumer.advance_consumption(200);

        manifest.invalidate_epoch(2).unwrap();
        let (refresh, record) = consumer
            .refresh_manifest_with_exposure_record(
                manifest,
                Some("epoch 2 manifest hash mismatch".to_string()),
                Some("replay:prefix-invalidated".to_string()),
            )
            .unwrap();

        assert_eq!(
            refresh.invalidated_consumed_range,
            Some(ByteRange::new(100, 200))
        );
        assert_eq!(record.object_id, object_id);
        assert_eq!(record.prefix_range, Some(ByteRange::new(100, 200)));
        assert_eq!(record.verified_state, PrefixVerifiedState::Invalidated);
        assert_eq!(record.exposure_decision, PrefixExposureDecision::Withhold);
        assert_eq!(
            record.invalidation_reason.as_deref(),
            Some("epoch 2 manifest hash mismatch")
        );
        assert_eq!(
            record.replay_pointer.as_deref(),
            Some("replay:prefix-invalidated")
        );
    }

    #[test]
    fn prefix_consumer_refresh_rejects_different_object() {
        let object_id = test_object_id();
        let mut manifest = StreamManifest::new(object_id.clone());
        manifest
            .add_epoch(StreamEpoch::new(
                1,
                object_id,
                ByteRange::new(0, 100),
                EpochState::Verified,
                vec![],
            ))
            .unwrap();

        let mut consumer = PrefixConsumer::new(manifest, ConsumptionPolicy::VerifiedOnly);
        let other_manifest = StreamManifest::new(ObjectId::content(ContentId::new([2u8; 32])));

        assert!(consumer.refresh_manifest(other_manifest).is_err());
    }

    #[test]
    fn resumption_checkpoint_stops_before_invalidated_gap() {
        let object_id = test_object_id();
        let mut manifest = StreamManifest::new(object_id.clone());

        manifest
            .add_epoch(StreamEpoch::new(
                1,
                object_id.clone(),
                ByteRange::new(0, 100),
                EpochState::Verified,
                vec![],
            ))
            .unwrap();
        manifest
            .add_epoch(StreamEpoch::new(
                2,
                object_id.clone(),
                ByteRange::new(100, 200),
                EpochState::Invalidated,
                vec![],
            ))
            .unwrap();
        manifest
            .add_epoch(StreamEpoch::new(
                3,
                object_id,
                ByteRange::new(200, 300),
                EpochState::Verified,
                vec![],
            ))
            .unwrap();

        let checkpoint = manifest.resumption_checkpoint(300).unwrap();
        assert_eq!(checkpoint.epoch_sequence, 1);
        assert_eq!(checkpoint.byte_offset, 100);
    }

    #[test]
    fn resumption_checkpoint_advances_after_provisional_gap_is_verified() {
        let object_id = test_object_id();
        let mut manifest = StreamManifest::new(object_id.clone());

        manifest
            .add_epoch(StreamEpoch::new(
                1,
                object_id.clone(),
                ByteRange::new(0, 100),
                EpochState::Verified,
                vec![],
            ))
            .unwrap();
        manifest
            .add_epoch(StreamEpoch::new(
                2,
                object_id.clone(),
                ByteRange::new(100, 200),
                EpochState::Provisional,
                vec![],
            ))
            .unwrap();
        manifest
            .add_epoch(StreamEpoch::new(
                3,
                object_id,
                ByteRange::new(200, 300),
                EpochState::Verified,
                vec![],
            ))
            .unwrap();

        let checkpoint_before = manifest.resumption_checkpoint(300).unwrap();
        assert_eq!(checkpoint_before.epoch_sequence, 1);
        assert_eq!(checkpoint_before.byte_offset, 100);

        manifest.verify_epoch(2).unwrap();
        let checkpoint_after = manifest.resumption_checkpoint(300).unwrap();
        assert_eq!(checkpoint_after.epoch_sequence, 3);
        assert_eq!(checkpoint_after.byte_offset, 300);
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
        assert!(proof.prefix_exposures.is_empty());
        assert!(proof.consumer_signature.is_none());

        // Test signing
        proof.sign(vec![0xFF; 64]);
        assert!(proof.consumer_signature.is_some());
    }

    #[test]
    fn stream_proof_record_collects_prefix_exposure_records() {
        let object_id = test_object_id();
        let exposure = PrefixExposureRecord::new(
            object_id.clone(),
            Some(ByteRange::new(0, 1024)),
            PrefixVerifiedState::Verified,
            PrefixExposureDecision::Expose,
            ConsumptionPolicy::VerifiedOnly,
            Some("replay:proof-exposure".to_string()),
        );
        let mut proof = StreamProofRecord::new(
            object_id,
            vec![1],
            1024,
            ConsumptionPolicy::VerifiedOnly,
            false,
        );

        proof.record_prefix_exposure(exposure);

        assert_eq!(proof.prefix_exposures.len(), 1);
        assert_eq!(
            proof.prefix_exposures[0].replay_pointer.as_deref(),
            Some("replay:proof-exposure")
        );
        assert_eq!(
            proof.prefix_exposures[0].prefix_range,
            Some(ByteRange::new(0, 1024))
        );
    }

    #[test]
    fn prefix_exposure_artifact_serializes_required_log_fields() -> Result<(), serde_json::Error> {
        let object_id = test_object_id();
        let mut exposure = PrefixExposureRecord::new(
            object_id.clone(),
            Some(ByteRange::new(100, 200)),
            PrefixVerifiedState::Invalidated,
            PrefixExposureDecision::Withhold,
            ConsumptionPolicy::AllowProvisional,
            Some("replay:prefix-artifact".to_string()),
        );
        exposure.invalidation_reason = Some("epoch manifest hash mismatch".to_string());

        let artifact = exposure.to_artifact();
        let json = serde_json::to_value(&artifact)?;

        assert_eq!(artifact.object_id, object_id_artifact_id(&object_id));
        assert_eq!(artifact.object_hash, object_id.as_hex());
        assert_eq!(artifact.prefix_range, Some(ByteRange::new(100, 200)));
        assert_eq!(artifact.verified_state, "invalidated");
        assert_eq!(artifact.exposure_decision, "withhold");
        assert_eq!(
            artifact.invalidation_reason.as_deref(),
            Some("epoch manifest hash mismatch")
        );
        assert_eq!(
            artifact.replay_pointer.as_deref(),
            Some("replay:prefix-artifact")
        );
        assert_eq!(artifact.consumption_policy, "allow_provisional");
        assert_eq!(json["prefix_range"]["start"], 100);
        assert_eq!(json["verified_state"], "invalidated");
        Ok(())
    }

    #[test]
    fn stream_prefix_proof_artifact_round_trips_exposure_records() -> Result<(), serde_json::Error>
    {
        let object_id = test_object_id();
        let exposure = PrefixExposureRecord::new(
            object_id.clone(),
            Some(ByteRange::new(0, 1024)),
            PrefixVerifiedState::Verified,
            PrefixExposureDecision::Expose,
            ConsumptionPolicy::VerifiedOnly,
            Some("replay:stream-proof".to_string()),
        );
        let mut proof = StreamProofRecord::new(
            object_id.clone(),
            vec![1, 2],
            1024,
            ConsumptionPolicy::VerifiedOnly,
            false,
        );
        proof.record_prefix_exposure(exposure);
        proof.sign(vec![0xAB, 0xCD]);

        let artifact = proof.to_artifact();
        let encoded = serde_json::to_string(&artifact)?;
        let decoded: StreamPrefixProofArtifact = serde_json::from_str(&encoded)?;

        assert_eq!(decoded.schema_version, STREAM_PREFIX_PROOF_ARTIFACT_SCHEMA);
        assert_eq!(decoded.object_id, object_id_artifact_id(&object_id));
        assert_eq!(decoded.object_hash, object_id.as_hex());
        assert_eq!(decoded.consumed_epochs, vec![1, 2]);
        assert_eq!(decoded.final_offset, 1024);
        assert_eq!(decoded.consumption_policy, "verified_only");
        assert!(!decoded.fully_consumed);
        assert_eq!(decoded.consumer_signature_hex.as_deref(), Some("abcd"));
        assert_eq!(decoded.prefix_exposures.len(), 1);
        assert_eq!(
            decoded.prefix_exposures[0].prefix_range,
            Some(ByteRange::new(0, 1024))
        );
        assert_eq!(decoded.prefix_exposures[0].verified_state, "verified");
        assert_eq!(decoded.prefix_exposures[0].exposure_decision, "expose");
        assert_eq!(
            decoded.prefix_exposures[0].replay_pointer.as_deref(),
            Some("replay:stream-proof")
        );
        Ok(())
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
