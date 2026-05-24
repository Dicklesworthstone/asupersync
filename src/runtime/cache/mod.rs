//! Content-addressed artifact cache for high-RAM agent-swarm workloads.
//!
//! The cache keeps proof logs, trace bundles, fixture blobs, and crashpack
//! payloads in reference-counted [`Bytes`](crate::bytes::Bytes) storage. A
//! handoff clones only the reference-counted handle, not the backing bytes, so
//! large artifacts can move between runtime controllers without another large
//! allocation.

use crate::bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use thiserror::Error;

const DEFAULT_MAX_RESIDENT_BYTES: u64 = 256 * 1024 * 1024 * 1024;
const DEFAULT_MAX_OWNER_RESIDENT_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const DEFAULT_MAX_ARTIFACTS: usize = 4096;
const FNV_OFFSET: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 0x100000001b3;
const BPS_DENOMINATOR: u64 = 10_000;

/// Stable content address for a cached artifact.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ArtifactId(String);

impl ArtifactId {
    /// Build a stable id from artifact bytes.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut hash = FNV_OFFSET;
        for &byte in bytes {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(FNV_PRIME);
        }

        Self(format!("aa1:{:016x}:{hash:016x}", bytes.len()))
    }

    /// Return the stable text form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ArtifactId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Owner metadata that scopes artifact visibility.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ArtifactOwner {
    /// Agent, worker, or controller that produced the artifact.
    pub agent_id: String,
    /// Optional bead or issue id associated with the artifact.
    pub bead_id: Option<String>,
    /// Capability scope required to retrieve the artifact.
    pub capability_scope: String,
}

impl ArtifactOwner {
    /// Create owner metadata and trim the capability scope used for access.
    #[must_use]
    pub fn new(
        agent_id: impl Into<String>,
        bead_id: Option<String>,
        capability_scope: impl Into<String>,
    ) -> Self {
        Self {
            agent_id: agent_id.into(),
            bead_id,
            capability_scope: normalize_scope(capability_scope.into()),
        }
    }

    #[must_use]
    fn owner_key(&self) -> String {
        match &self.bead_id {
            Some(bead_id) if !bead_id.trim().is_empty() => {
                format!("{}:{bead_id}", self.agent_id.trim())
            }
            _ => self.agent_id.trim().to_string(),
        }
    }
}

/// Retention policy attached to an artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactRetentionPolicy {
    /// Higher values survive quota eviction longer.
    pub priority: u8,
    /// Optional deterministic lab step after which the artifact is stale.
    pub expires_at_step: Option<u64>,
    /// Whether the payload may be spilled to disk instead of evicted.
    pub spill_to_disk_allowed: bool,
}

impl Default for ArtifactRetentionPolicy {
    fn default() -> Self {
        Self {
            priority: 128,
            expires_at_step: None,
            spill_to_disk_allowed: false,
        }
    }
}

impl ArtifactRetentionPolicy {
    #[must_use]
    fn merge(self, other: Self) -> Self {
        Self {
            priority: self.priority.max(other.priority),
            expires_at_step: min_optional(self.expires_at_step, other.expires_at_step),
            spill_to_disk_allowed: self.spill_to_disk_allowed && other.spill_to_disk_allowed,
        }
    }
}

/// Redaction class for operator-visible artifact metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactRedactionClass {
    /// Public metadata.
    Public,
    /// Internal build or proof data.
    Internal,
    /// Sensitive data may be present.
    Sensitive,
    /// Secrets may be present and must be treated as redacted.
    Secret,
}

/// Redaction metadata associated with a cached artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactRedactionMetadata {
    /// Highest known redaction class for this artifact.
    pub class: ArtifactRedactionClass,
    /// True when the payload may contain secret material.
    pub contains_secrets: bool,
    /// Stable redacted field names for replay receipts.
    pub redacted_fields: Vec<String>,
}

impl Default for ArtifactRedactionMetadata {
    fn default() -> Self {
        Self {
            class: ArtifactRedactionClass::Internal,
            contains_secrets: false,
            redacted_fields: Vec::new(),
        }
    }
}

impl ArtifactRedactionMetadata {
    #[must_use]
    fn merge(mut self, other: &Self) -> Self {
        self.class = self.class.max(other.class);
        self.contains_secrets |= other.contains_secrets;
        for field in &other.redacted_fields {
            if !self.redacted_fields.iter().any(|known| known == field) {
                self.redacted_fields.push(field.clone());
            }
        }
        self.redacted_fields.sort();
        self
    }
}

/// Replay pointer for proof bundles and deterministic lab artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactReplayReference {
    /// Schema or trace family that can replay this artifact.
    pub replay_schema: String,
    /// Stable replay pointer, path, or trace id.
    pub replay_pointer: String,
}

impl ArtifactReplayReference {
    /// Build a replay reference.
    #[must_use]
    pub fn new(replay_schema: impl Into<String>, replay_pointer: impl Into<String>) -> Self {
        Self {
            replay_schema: replay_schema.into(),
            replay_pointer: replay_pointer.into(),
        }
    }
}

/// NUMA locality hint carried with an artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NumaArtifactHint {
    /// Preferred node for consumers, if known.
    pub preferred_node: Option<u16>,
    /// Node where the artifact is currently resident, if known.
    pub resident_node: Option<u16>,
    /// Locality confidence in basis points.
    pub locality_score_bps: u16,
}

impl NumaArtifactHint {
    #[must_use]
    const fn is_remote(self) -> bool {
        matches!(
            (self.preferred_node, self.resident_node),
            (Some(preferred), Some(resident)) if preferred != resident
        )
    }
}

/// Cache limits and pressure thresholds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactCacheConfig {
    /// Maximum resident bytes retained in memory.
    pub max_resident_bytes: u64,
    /// Optional per-owner resident byte budget.
    pub max_owner_resident_bytes: Option<u64>,
    /// Maximum number of retained artifacts.
    pub max_artifacts: usize,
    /// Pressure threshold where callers should begin spilling or evicting.
    pub high_pressure_bps: u16,
}

impl Default for ArtifactCacheConfig {
    fn default() -> Self {
        Self {
            max_resident_bytes: DEFAULT_MAX_RESIDENT_BYTES,
            max_owner_resident_bytes: Some(DEFAULT_MAX_OWNER_RESIDENT_BYTES),
            max_artifacts: DEFAULT_MAX_ARTIFACTS,
            high_pressure_bps: 8_500,
        }
    }
}

/// Request to place an artifact in the cache.
#[derive(Debug, Clone)]
pub struct ArtifactPutRequest {
    /// Artifact bytes. Cloning this value must not clone the backing payload.
    pub bytes: Bytes,
    /// Owner and capability scope for retrieval.
    pub owner: ArtifactOwner,
    /// Retention and spill policy.
    pub retention: ArtifactRetentionPolicy,
    /// Redaction metadata for operator receipts.
    pub redaction: ArtifactRedactionMetadata,
    /// Replay reference for deterministic proof bundles.
    pub replay_ref: ArtifactReplayReference,
    /// Optional NUMA locality hint.
    pub numa_hint: Option<NumaArtifactHint>,
}

impl ArtifactPutRequest {
    /// Build a put request.
    #[must_use]
    pub fn new(
        bytes: Bytes,
        owner: ArtifactOwner,
        retention: ArtifactRetentionPolicy,
        redaction: ArtifactRedactionMetadata,
        replay_ref: ArtifactReplayReference,
        numa_hint: Option<NumaArtifactHint>,
    ) -> Self {
        Self {
            bytes,
            owner,
            retention,
            redaction,
            replay_ref,
            numa_hint,
        }
    }
}

/// Linear reservation for a put that has not been committed yet.
#[derive(Debug, Clone)]
pub struct ArtifactPutReservation {
    request: ArtifactPutRequest,
    artifact_id: ArtifactId,
    size_bytes: u64,
}

impl ArtifactPutReservation {
    /// Id computed for the reservation bytes.
    #[must_use]
    pub fn artifact_id(&self) -> &ArtifactId {
        &self.artifact_id
    }

    /// Number of bytes that would become resident if committed.
    #[must_use]
    pub const fn size_bytes(&self) -> u64 {
        self.size_bytes
    }
}

/// Receipt returned when a pending put is aborted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactAbortReceipt {
    /// Artifact id that was never made resident.
    pub artifact_id: ArtifactId,
    /// Bytes intentionally not admitted.
    pub aborted_bytes: u64,
    /// Stable reason for replay.
    pub reason: String,
}

/// Cache decision returned by a committed put.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactCacheDecision {
    /// Artifact id for the put.
    pub artifact_id: ArtifactId,
    /// True when resident bytes increased for a new artifact.
    pub stored_new_bytes: bool,
    /// Bytes currently resident after the decision.
    pub resident_bytes: u64,
    /// Logical duplicate bytes avoided by content addressing.
    pub duplicate_bytes_avoided: u64,
    /// Deterministic evictions performed before insertion.
    pub evictions: Vec<CacheEvictionRecord>,
}

/// Zero-copy handoff returned by a cache hit.
#[derive(Debug, Clone)]
pub struct ArtifactHandoff {
    /// Artifact id.
    pub artifact_id: ArtifactId,
    /// Shared byte handle.
    pub bytes: Bytes,
    /// Size of the shared byte handle.
    pub size_bytes: u64,
    /// Replay reference carried from the cache entry.
    pub replay_ref: ArtifactReplayReference,
    /// Optional NUMA locality hint.
    pub numa_hint: Option<NumaArtifactHint>,
    /// True when handoff avoided a payload copy.
    pub zero_copy: bool,
}

/// Receipt describing the cache lookup that produced a handoff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactGetReceipt {
    /// Artifact id.
    pub artifact_id: ArtifactId,
    /// True when lookup was a hit.
    pub hit: bool,
    /// Resident bytes at lookup time.
    pub resident_bytes: u64,
    /// Hit count after this lookup.
    pub hit_count: u64,
    /// Capability scope used for the lookup.
    pub capability_scope: String,
}

/// Reason an artifact left memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheEvictionReason {
    /// Artifact expired at a deterministic lab step.
    Expired,
    /// Resident byte quota required eviction.
    ResidentByteQuota,
    /// Artifact-count quota required eviction.
    ArtifactCountQuota,
}

/// Deterministic eviction record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheEvictionRecord {
    /// Evicted artifact id.
    pub artifact_id: ArtifactId,
    /// Resident bytes released.
    pub size_bytes: u64,
    /// Eviction reason.
    pub reason: CacheEvictionReason,
    /// Owner key for operator receipts.
    pub owner_key: String,
    /// Replay pointer associated with the artifact.
    pub replay_pointer: String,
    /// NUMA hint associated with the evicted artifact.
    pub numa_hint: Option<NumaArtifactHint>,
}

/// Entry metadata exposed in snapshots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactCacheEntrySnapshot {
    /// Artifact id.
    pub artifact_id: ArtifactId,
    /// Resident bytes.
    pub size_bytes: u64,
    /// Primary owner key.
    pub owner_key: String,
    /// Number of authorized scopes.
    pub scope_count: usize,
    /// Number of owners that have proved possession of this content.
    pub owner_count: usize,
    /// Retention policy.
    pub retention: ArtifactRetentionPolicy,
    /// Redaction metadata.
    pub redaction: ArtifactRedactionMetadata,
    /// Cache hit count.
    pub hit_count: u64,
    /// NUMA hint.
    pub numa_hint: Option<NumaArtifactHint>,
    /// Replay reference.
    pub replay_ref: ArtifactReplayReference,
}

/// Memory pressure snapshot for admission and lab projections.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactMemoryPressureSnapshot {
    /// Resident bytes retained in memory.
    pub resident_bytes: u64,
    /// Configured resident byte limit.
    pub max_resident_bytes: u64,
    /// Hot resident bytes, derived from hits and high retention priority.
    pub hot_resident_bytes: u64,
    /// Cold resident bytes.
    pub cold_resident_bytes: u64,
    /// Resident bytes that may be spilled to disk.
    pub spill_eligible_bytes: u64,
    /// Resident bytes whose current NUMA node differs from the preferred node.
    pub remote_numa_bytes: u64,
    /// Pressure in basis points.
    pub pressure_bps: u16,
    /// True once pressure crosses the configured threshold.
    pub high_pressure: bool,
    /// Logical duplicate bytes avoided since cache creation.
    pub duplicate_bytes_avoided: u64,
    /// Number of retained artifacts.
    pub artifact_count: usize,
}

/// Cache errors.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ArtifactCacheError {
    /// Capability scope is empty.
    #[error("artifact capability scope must be nonempty")]
    EmptyCapabilityScope,
    /// Artifact is too large for the resident quota.
    #[error("artifact {artifact_id} has {size_bytes} bytes, above quota {quota_bytes}")]
    ArtifactExceedsQuota {
        /// Artifact id.
        artifact_id: ArtifactId,
        /// Artifact size.
        size_bytes: u64,
        /// Quota.
        quota_bytes: u64,
    },
    /// Owner quota would be exceeded.
    #[error(
        "owner {owner_key} would exceed resident quota: current {current_bytes} + incoming {incoming_bytes} > {quota_bytes}"
    )]
    OwnerQuotaExceeded {
        /// Owner key.
        owner_key: String,
        /// Current owner-attributed bytes.
        current_bytes: u64,
        /// Incoming bytes.
        incoming_bytes: u64,
        /// Quota.
        quota_bytes: u64,
    },
    /// Artifact is stale for the requested step.
    #[error("artifact {artifact_id} expired at step {expired_at_step}")]
    StaleArtifact {
        /// Artifact id.
        artifact_id: ArtifactId,
        /// Expiry step.
        expired_at_step: u64,
    },
    /// Capability scope is not authorized for the artifact.
    #[error("capability scope {capability_scope} cannot access artifact {artifact_id}")]
    AccessDenied {
        /// Artifact id.
        artifact_id: ArtifactId,
        /// Requested scope.
        capability_scope: String,
    },
}

#[derive(Debug, Clone)]
struct ArtifactEntry {
    artifact_id: ArtifactId,
    bytes: Bytes,
    primary_owner_key: String,
    owner_keys: BTreeSet<String>,
    authorized_scopes: BTreeSet<String>,
    retention: ArtifactRetentionPolicy,
    redaction: ArtifactRedactionMetadata,
    replay_ref: ArtifactReplayReference,
    numa_hint: Option<NumaArtifactHint>,
    size_bytes: u64,
    inserted_seq: u64,
    last_access_seq: u64,
    hit_count: u64,
}

/// High-RAM artifact cache with deterministic admission and eviction.
#[derive(Debug, Clone)]
pub struct ArtifactCache {
    config: ArtifactCacheConfig,
    entries: BTreeMap<ArtifactId, ArtifactEntry>,
    resident_bytes: u64,
    duplicate_bytes_avoided: u64,
    sequence: u64,
}

impl Default for ArtifactCache {
    fn default() -> Self {
        Self::new(ArtifactCacheConfig::default())
    }
}

impl ArtifactCache {
    /// Create an empty cache.
    #[must_use]
    pub fn new(config: ArtifactCacheConfig) -> Self {
        Self {
            config,
            entries: BTreeMap::new(),
            resident_bytes: 0,
            duplicate_bytes_avoided: 0,
            sequence: 0,
        }
    }

    /// Current cache configuration.
    #[must_use]
    pub const fn config(&self) -> &ArtifactCacheConfig {
        &self.config
    }

    /// Begin a put without mutating resident cache state.
    ///
    /// Dropping or aborting the returned reservation leaves resident bytes
    /// unchanged, which is the synchronous cancel-safe boundary for large puts.
    pub fn begin_put(
        &self,
        request: ArtifactPutRequest,
    ) -> Result<ArtifactPutReservation, ArtifactCacheError> {
        if request.owner.capability_scope.is_empty() {
            return Err(ArtifactCacheError::EmptyCapabilityScope);
        }

        let artifact_id = ArtifactId::from_bytes(request.bytes.as_ref());
        let size_bytes = usize_to_u64(request.bytes.len());
        if size_bytes > self.config.max_resident_bytes {
            return Err(ArtifactCacheError::ArtifactExceedsQuota {
                artifact_id,
                size_bytes,
                quota_bytes: self.config.max_resident_bytes,
            });
        }

        Ok(ArtifactPutReservation {
            request,
            artifact_id,
            size_bytes,
        })
    }

    /// Abort a pending put reservation.
    #[must_use]
    pub fn abort_put(
        &self,
        reservation: ArtifactPutReservation,
        reason: impl Into<String>,
    ) -> ArtifactAbortReceipt {
        ArtifactAbortReceipt {
            artifact_id: reservation.artifact_id,
            aborted_bytes: reservation.size_bytes,
            reason: reason.into(),
        }
    }

    /// Commit a pending put reservation at a deterministic lab step.
    pub fn commit_put(
        &mut self,
        reservation: ArtifactPutReservation,
        now_step: u64,
    ) -> Result<ArtifactCacheDecision, ArtifactCacheError> {
        if let Some(expiry) = reservation.request.retention.expires_at_step {
            if expiry <= now_step {
                return Err(ArtifactCacheError::StaleArtifact {
                    artifact_id: reservation.artifact_id,
                    expired_at_step: expiry,
                });
            }
        }

        let mut evictions = self.evict_expired(now_step);
        if let Some(entry) = self.entries.get_mut(&reservation.artifact_id) {
            self.sequence = self.sequence.saturating_add(1);
            let owner_key = reservation.request.owner.owner_key();
            entry.owner_keys.insert(owner_key);
            entry
                .authorized_scopes
                .insert(reservation.request.owner.capability_scope.clone());
            entry.retention = entry.retention.merge(reservation.request.retention);
            entry.redaction = entry
                .redaction
                .clone()
                .merge(&reservation.request.redaction);
            entry.last_access_seq = self.sequence;
            entry.hit_count = entry.hit_count.saturating_add(1);
            if entry.numa_hint.is_none() {
                entry.numa_hint = reservation.request.numa_hint;
            }
            self.duplicate_bytes_avoided = self
                .duplicate_bytes_avoided
                .saturating_add(reservation.size_bytes);

            return Ok(ArtifactCacheDecision {
                artifact_id: entry.artifact_id.clone(),
                stored_new_bytes: false,
                resident_bytes: self.resident_bytes,
                duplicate_bytes_avoided: self.duplicate_bytes_avoided,
                evictions,
            });
        }

        self.enforce_owner_quota(&reservation)?;
        evictions.extend(self.evict_for_insert(reservation.size_bytes));

        self.sequence = self.sequence.saturating_add(1);
        let owner_key = reservation.request.owner.owner_key();
        let mut owner_keys = BTreeSet::new();
        owner_keys.insert(owner_key.clone());
        let mut authorized_scopes = BTreeSet::new();
        authorized_scopes.insert(reservation.request.owner.capability_scope.clone());

        let entry = ArtifactEntry {
            artifact_id: reservation.artifact_id.clone(),
            bytes: reservation.request.bytes,
            primary_owner_key: owner_key,
            owner_keys,
            authorized_scopes,
            retention: reservation.request.retention,
            redaction: reservation.request.redaction,
            replay_ref: reservation.request.replay_ref,
            numa_hint: reservation.request.numa_hint,
            size_bytes: reservation.size_bytes,
            inserted_seq: self.sequence,
            last_access_seq: self.sequence,
            hit_count: 0,
        };
        self.resident_bytes = self.resident_bytes.saturating_add(entry.size_bytes);
        self.entries.insert(entry.artifact_id.clone(), entry);

        Ok(ArtifactCacheDecision {
            artifact_id: reservation.artifact_id,
            stored_new_bytes: true,
            resident_bytes: self.resident_bytes,
            duplicate_bytes_avoided: self.duplicate_bytes_avoided,
            evictions,
        })
    }

    /// Retrieve an artifact as a zero-copy handoff.
    pub fn get_at_step(
        &mut self,
        artifact_id: &ArtifactId,
        capability_scope: &str,
        now_step: u64,
    ) -> Result<Option<(ArtifactHandoff, ArtifactGetReceipt)>, ArtifactCacheError> {
        let normalized_scope = normalize_scope(capability_scope);
        if normalized_scope.is_empty() {
            return Err(ArtifactCacheError::EmptyCapabilityScope);
        }

        let Some(entry) = self.entries.get(artifact_id) else {
            return Ok(None);
        };
        if let Some(expiry) = entry.retention.expires_at_step {
            if expiry <= now_step {
                let id = artifact_id.clone();
                self.remove_entry(artifact_id, CacheEvictionReason::Expired);
                return Err(ArtifactCacheError::StaleArtifact {
                    artifact_id: id,
                    expired_at_step: expiry,
                });
            }
        }
        if !entry.authorized_scopes.contains(&normalized_scope) {
            return Err(ArtifactCacheError::AccessDenied {
                artifact_id: artifact_id.clone(),
                capability_scope: normalized_scope,
            });
        }

        self.sequence = self.sequence.saturating_add(1);
        let entry = self
            .entries
            .get_mut(artifact_id)
            .expect("entry exists after access checks");
        entry.hit_count = entry.hit_count.saturating_add(1);
        entry.last_access_seq = self.sequence;

        let handoff = ArtifactHandoff {
            artifact_id: entry.artifact_id.clone(),
            bytes: entry.bytes.clone(),
            size_bytes: entry.size_bytes,
            replay_ref: entry.replay_ref.clone(),
            numa_hint: entry.numa_hint,
            zero_copy: true,
        };
        let receipt = ArtifactGetReceipt {
            artifact_id: entry.artifact_id.clone(),
            hit: true,
            resident_bytes: self.resident_bytes,
            hit_count: entry.hit_count,
            capability_scope: normalized_scope,
        };
        Ok(Some((handoff, receipt)))
    }

    /// Build a deterministic snapshot of all entries.
    #[must_use]
    pub fn entry_snapshots(&self) -> Vec<ArtifactCacheEntrySnapshot> {
        self.entries.values().map(ArtifactEntry::snapshot).collect()
    }

    /// Build a memory pressure snapshot for admission and lab models.
    #[must_use]
    pub fn memory_pressure_snapshot(&self) -> ArtifactMemoryPressureSnapshot {
        let hot_resident_bytes = self
            .entries
            .values()
            .filter(|entry| entry.is_hot())
            .map(|entry| entry.size_bytes)
            .sum();
        let spill_eligible_bytes = self
            .entries
            .values()
            .filter(|entry| entry.retention.spill_to_disk_allowed)
            .map(|entry| entry.size_bytes)
            .sum();
        let remote_numa_bytes = self
            .entries
            .values()
            .filter(|entry| entry.numa_hint.is_some_and(NumaArtifactHint::is_remote))
            .map(|entry| entry.size_bytes)
            .sum();
        let pressure_bps = ratio_bps(self.resident_bytes, self.config.max_resident_bytes);

        ArtifactMemoryPressureSnapshot {
            resident_bytes: self.resident_bytes,
            max_resident_bytes: self.config.max_resident_bytes,
            hot_resident_bytes,
            cold_resident_bytes: self.resident_bytes.saturating_sub(hot_resident_bytes),
            spill_eligible_bytes,
            remote_numa_bytes,
            pressure_bps,
            high_pressure: pressure_bps >= self.config.high_pressure_bps,
            duplicate_bytes_avoided: self.duplicate_bytes_avoided,
            artifact_count: self.entries.len(),
        }
    }

    fn enforce_owner_quota(
        &self,
        reservation: &ArtifactPutReservation,
    ) -> Result<(), ArtifactCacheError> {
        let Some(quota_bytes) = self.config.max_owner_resident_bytes else {
            return Ok(());
        };
        let owner_key = reservation.request.owner.owner_key();
        let current_bytes: u64 = self
            .entries
            .values()
            .filter(|entry| entry.owner_keys.contains(&owner_key))
            .map(|entry| entry.size_bytes)
            .sum();
        if current_bytes.saturating_add(reservation.size_bytes) > quota_bytes {
            return Err(ArtifactCacheError::OwnerQuotaExceeded {
                owner_key,
                current_bytes,
                incoming_bytes: reservation.size_bytes,
                quota_bytes,
            });
        }
        Ok(())
    }

    fn evict_expired(&mut self, now_step: u64) -> Vec<CacheEvictionRecord> {
        let expired: Vec<_> = self
            .entries
            .values()
            .filter(|entry| {
                entry
                    .retention
                    .expires_at_step
                    .is_some_and(|step| step <= now_step)
            })
            .map(|entry| entry.artifact_id.clone())
            .collect();

        expired
            .into_iter()
            .filter_map(|artifact_id| self.remove_entry(&artifact_id, CacheEvictionReason::Expired))
            .collect()
    }

    fn evict_for_insert(&mut self, incoming_bytes: u64) -> Vec<CacheEvictionRecord> {
        let mut evictions = Vec::new();
        while self.entries.len().saturating_add(1) > self.config.max_artifacts {
            let Some(candidate) = self.next_eviction_candidate() else {
                break;
            };
            if let Some(record) =
                self.remove_entry(&candidate, CacheEvictionReason::ArtifactCountQuota)
            {
                evictions.push(record);
            }
        }

        while self.resident_bytes.saturating_add(incoming_bytes) > self.config.max_resident_bytes {
            let Some(candidate) = self.next_eviction_candidate() else {
                break;
            };
            if let Some(record) =
                self.remove_entry(&candidate, CacheEvictionReason::ResidentByteQuota)
            {
                evictions.push(record);
            }
        }
        evictions
    }

    fn next_eviction_candidate(&self) -> Option<ArtifactId> {
        self.entries
            .values()
            .min_by_key(|entry| {
                (
                    entry.retention.priority,
                    entry.hit_count,
                    entry.last_access_seq,
                    entry.inserted_seq,
                    entry.artifact_id.clone(),
                )
            })
            .map(|entry| entry.artifact_id.clone())
    }

    fn remove_entry(
        &mut self,
        artifact_id: &ArtifactId,
        reason: CacheEvictionReason,
    ) -> Option<CacheEvictionRecord> {
        let entry = self.entries.remove(artifact_id)?;
        self.resident_bytes = self.resident_bytes.saturating_sub(entry.size_bytes);
        Some(CacheEvictionRecord {
            artifact_id: entry.artifact_id,
            size_bytes: entry.size_bytes,
            reason,
            owner_key: entry.primary_owner_key,
            replay_pointer: entry.replay_ref.replay_pointer,
            numa_hint: entry.numa_hint,
        })
    }
}

impl ArtifactEntry {
    #[must_use]
    const fn is_hot(&self) -> bool {
        self.hit_count > 0 || self.retention.priority >= 192
    }

    #[must_use]
    fn snapshot(&self) -> ArtifactCacheEntrySnapshot {
        ArtifactCacheEntrySnapshot {
            artifact_id: self.artifact_id.clone(),
            size_bytes: self.size_bytes,
            owner_key: self.primary_owner_key.clone(),
            scope_count: self.authorized_scopes.len(),
            owner_count: self.owner_keys.len(),
            retention: self.retention,
            redaction: self.redaction.clone(),
            hit_count: self.hit_count,
            numa_hint: self.numa_hint,
            replay_ref: self.replay_ref.clone(),
        }
    }
}

fn normalize_scope(scope: impl AsRef<str>) -> String {
    scope
        .as_ref()
        .trim()
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .collect::<Vec<_>>()
        .join("/")
}

const fn min_optional(left: Option<u64>, right: Option<u64>) -> Option<u64> {
    match (left, right) {
        (Some(left), Some(right)) => Some(if left < right { left } else { right }),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

fn ratio_bps(numerator: u64, denominator: u64) -> u16 {
    if denominator == 0 {
        return u16::MAX;
    }
    let scaled =
        u128::from(numerator).saturating_mul(u128::from(BPS_DENOMINATOR)) / u128::from(denominator);
    u16::try_from(scaled).unwrap_or(u16::MAX)
}

fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner(scope: &str) -> ArtifactOwner {
        ArtifactOwner::new("agent-a", Some("asupersync-oxqrae.4".to_string()), scope)
    }

    fn replay(pointer: &str) -> ArtifactReplayReference {
        ArtifactReplayReference::new("asupersync.test.replay.v1", pointer)
    }

    fn request(bytes: &'static [u8], scope: &str, priority: u8) -> ArtifactPutRequest {
        ArtifactPutRequest::new(
            Bytes::from_static(bytes),
            owner(scope),
            ArtifactRetentionPolicy {
                priority,
                expires_at_step: None,
                spill_to_disk_allowed: true,
            },
            ArtifactRedactionMetadata::default(),
            replay("trace://cache-test"),
            Some(NumaArtifactHint {
                preferred_node: Some(0),
                resident_node: Some(0),
                locality_score_bps: 9_500,
            }),
        )
    }

    #[test]
    fn content_address_identity_deduplicates_resident_bytes() {
        let mut cache = ArtifactCache::new(ArtifactCacheConfig {
            max_resident_bytes: 1024,
            max_owner_resident_bytes: None,
            max_artifacts: 8,
            high_pressure_bps: 8_500,
        });

        let first = cache
            .begin_put(request(b"proof-log", "scope/a", 128))
            .unwrap();
        let artifact_id = first.artifact_id().clone();
        let decision = cache.commit_put(first, 0).unwrap();
        assert!(decision.stored_new_bytes);
        assert_eq!(decision.resident_bytes, 9);

        let duplicate = cache
            .begin_put(request(b"proof-log", "./scope//a", 128))
            .unwrap();
        assert_eq!(duplicate.artifact_id(), &artifact_id);
        let decision = cache.commit_put(duplicate, 1).unwrap();
        assert!(!decision.stored_new_bytes);
        assert_eq!(decision.resident_bytes, 9);
        assert_eq!(decision.duplicate_bytes_avoided, 9);
    }

    #[test]
    fn aborting_put_reservation_does_not_change_resident_bytes() {
        let cache = ArtifactCache::new(ArtifactCacheConfig {
            max_resident_bytes: 64,
            max_owner_resident_bytes: None,
            max_artifacts: 8,
            high_pressure_bps: 8_500,
        });

        let reservation = cache
            .begin_put(request(b"cancelled", "scope/a", 128))
            .unwrap();
        let receipt = cache.abort_put(reservation, "cx-cancelled");

        assert_eq!(receipt.aborted_bytes, 9);
        assert_eq!(cache.memory_pressure_snapshot().resident_bytes, 0);
    }

    #[test]
    fn get_returns_zero_copy_handoff_and_receipt() {
        let mut cache = ArtifactCache::new(ArtifactCacheConfig {
            max_resident_bytes: 1024,
            max_owner_resident_bytes: None,
            max_artifacts: 8,
            high_pressure_bps: 8_500,
        });
        let reservation = cache
            .begin_put(request(b"trace-bundle", "proof/read", 200))
            .unwrap();
        let artifact_id = reservation.artifact_id().clone();
        cache.commit_put(reservation, 0).unwrap();

        let (handoff, receipt) = cache
            .get_at_step(&artifact_id, "proof/read", 1)
            .unwrap()
            .expect("cache hit");

        assert!(handoff.zero_copy);
        assert_eq!(handoff.bytes.as_ref(), b"trace-bundle");
        assert_eq!(handoff.size_bytes, 12);
        assert!(receipt.hit);
        assert_eq!(receipt.hit_count, 1);
        assert_eq!(cache.memory_pressure_snapshot().hot_resident_bytes, 12);
    }

    #[test]
    fn quota_eviction_is_deterministic_and_prefers_cold_low_priority() {
        let mut cache = ArtifactCache::new(ArtifactCacheConfig {
            max_resident_bytes: 16,
            max_owner_resident_bytes: None,
            max_artifacts: 8,
            high_pressure_bps: 8_500,
        });
        let cold = cache.begin_put(request(b"cold-low", "scope/a", 1)).unwrap();
        let cold_id = cold.artifact_id().clone();
        cache.commit_put(cold, 0).unwrap();
        let hot = cache
            .begin_put(request(b"hot-high", "scope/a", 200))
            .unwrap();
        cache.commit_put(hot, 1).unwrap();

        let incoming = cache
            .begin_put(request(b"incoming", "scope/a", 128))
            .unwrap();
        let decision = cache.commit_put(incoming, 2).unwrap();

        assert_eq!(decision.evictions.len(), 1);
        assert_eq!(decision.evictions[0].artifact_id, cold_id);
        assert_eq!(
            decision.evictions[0].reason,
            CacheEvictionReason::ResidentByteQuota
        );
    }

    #[test]
    fn stale_artifacts_are_rejected_and_removed() {
        let mut cache = ArtifactCache::new(ArtifactCacheConfig {
            max_resident_bytes: 1024,
            max_owner_resident_bytes: None,
            max_artifacts: 8,
            high_pressure_bps: 8_500,
        });
        let mut put = request(b"short-lived", "scope/a", 128);
        put.retention.expires_at_step = Some(2);
        let reservation = cache.begin_put(put).unwrap();
        let artifact_id = reservation.artifact_id().clone();
        cache.commit_put(reservation, 0).unwrap();

        let error = cache
            .get_at_step(&artifact_id, "scope/a", 2)
            .expect_err("stale lookup must fail");

        assert!(matches!(error, ArtifactCacheError::StaleArtifact { .. }));
        assert_eq!(cache.memory_pressure_snapshot().resident_bytes, 0);
    }

    #[test]
    fn memory_pressure_snapshot_accounts_for_numa_and_spill_policy() {
        let mut cache = ArtifactCache::new(ArtifactCacheConfig {
            max_resident_bytes: 20,
            max_owner_resident_bytes: None,
            max_artifacts: 8,
            high_pressure_bps: 5_000,
        });
        let mut put = request(b"remote-node", "scope/a", 200);
        put.numa_hint = Some(NumaArtifactHint {
            preferred_node: Some(0),
            resident_node: Some(1),
            locality_score_bps: 6_000,
        });
        let reservation = cache.begin_put(put).unwrap();
        cache.commit_put(reservation, 0).unwrap();

        let snapshot = cache.memory_pressure_snapshot();
        assert_eq!(snapshot.resident_bytes, 11);
        assert_eq!(snapshot.hot_resident_bytes, 11);
        assert_eq!(snapshot.remote_numa_bytes, 11);
        assert_eq!(snapshot.spill_eligible_bytes, 11);
        assert_eq!(snapshot.pressure_bps, 5_500);
        assert!(snapshot.high_pressure);
    }
}
