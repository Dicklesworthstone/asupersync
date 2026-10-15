//! Local ATP inbox state, receive grants, and daemon diagnostics.

use crate::atp::quota::{QuotaAllocation, QuotaBucket, QuotaError, QuotaLedger};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};

/// Stable object graph digest used by inbox and cache records.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ObjectDigest([u8; 32]);

impl ObjectDigest {
    /// Build a digest from canonical object graph hash bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Return the digest as lowercase hex.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Return a redacted display token for logs and human diagnostics.
    #[must_use]
    pub fn redacted(&self) -> String {
        format!("sha256:{}...", &self.to_hex()[..12])
    }
}

impl fmt::Display for ObjectDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sha256:{}", &self.to_hex()[..16])
    }
}

/// Actions that an ATP daemon allow rule may grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AllowAction {
    /// Read an object graph or local path.
    Read,
    /// Write into a local path.
    Write,
    /// Receive an offered transfer into the local inbox.
    Receive,
    /// Share a local graph with another peer.
    Share,
    /// Cache verified graph content locally.
    Cache,
    /// Seed cached graph content to authorized peers.
    Seed,
}

impl AllowAction {
    /// Stable lowercase action name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Receive => "receive",
            Self::Share => "share",
            Self::Cache => "cache",
            Self::Seed => "seed",
        }
    }
}

/// Scope covered by an ATP daemon allow rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantScope {
    /// Permit the action for any ATP resource.
    Any,
    /// Permit inbox resources only.
    Inbox,
    /// Permit paths under the prefix.
    PathPrefix(PathBuf),
    /// Permit one object graph root.
    ObjectGraph(ObjectDigest),
    /// Permit cache operations for object types and optional byte limit.
    Cache {
        /// Empty means every object type is accepted.
        object_types: BTreeSet<String>,
        /// Maximum bytes accepted by this scope.
        max_bytes: Option<u64>,
    },
}

impl GrantScope {
    /// Return true when the scope covers a local path.
    #[must_use]
    pub fn covers_path(&self, path: &Path) -> bool {
        match self {
            Self::Any => true,
            Self::Inbox => path
                .components()
                .any(|component| component.as_os_str() == "inbox"),
            Self::PathPrefix(prefix) => path.starts_with(prefix),
            Self::ObjectGraph(_) | Self::Cache { .. } => false,
        }
    }

    /// Return true when the scope covers an object graph root.
    #[must_use]
    pub fn covers_object(&self, root: &ObjectDigest) -> bool {
        match self {
            Self::Any => true,
            Self::ObjectGraph(allowed_root) => allowed_root == root,
            Self::Inbox | Self::PathPrefix(_) | Self::Cache { .. } => false,
        }
    }

    /// Return true when the scope covers a cache operation.
    #[must_use]
    pub fn covers_cache(&self, object_type: &str, bytes: u64) -> bool {
        match self {
            Self::Any => true,
            Self::Cache {
                object_types,
                max_bytes,
            } => {
                let type_ok = object_types.is_empty() || object_types.contains(object_type);
                let size_ok = max_bytes.is_none_or(|limit| bytes <= limit);
                type_ok && size_ok
            }
            Self::Inbox | Self::PathPrefix(_) | Self::ObjectGraph(_) => false,
        }
    }
}

/// Per-grant quota limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct GrantQuota {
    /// Maximum bytes accepted by one operation.
    pub max_bytes: Option<u64>,
    /// Maximum items accepted by one operation.
    pub max_items: Option<u64>,
}

impl GrantQuota {
    /// Return true when byte and item counts fit inside the quota.
    #[must_use]
    pub fn permits(self, bytes: u64, items: u64) -> bool {
        let bytes_ok = self.max_bytes.is_none_or(|limit| bytes <= limit);
        let items_ok = self.max_items.is_none_or(|limit| items <= limit);
        bytes_ok && items_ok
    }
}

/// Persistent receive/share/cache grant tracked by the daemon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiveGrant {
    /// Stable grant identifier.
    pub id: String,
    /// Peer, actor, or daemon principal that owns the grant.
    pub subject: String,
    /// Actions authorized by this grant.
    pub actions: BTreeSet<AllowAction>,
    /// Resource scope authorized by this grant.
    pub scope: GrantScope,
    /// Quota limits enforced before work starts.
    pub quota: GrantQuota,
    /// Expiry as seconds since Unix epoch; callers supply the clock.
    pub expires_at_epoch_secs: Option<u64>,
    /// Revoked grants fail closed even if they are not expired.
    pub revoked: bool,
}

impl ReceiveGrant {
    /// Create a non-expiring grant with no quota.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        subject: impl Into<String>,
        actions: BTreeSet<AllowAction>,
        scope: GrantScope,
    ) -> Self {
        Self {
            id: id.into(),
            subject: subject.into(),
            actions,
            scope,
            quota: GrantQuota::default(),
            expires_at_epoch_secs: None,
            revoked: false,
        }
    }

    /// Attach a quota to the grant.
    #[must_use]
    pub const fn with_quota(mut self, quota: GrantQuota) -> Self {
        self.quota = quota;
        self
    }

    /// Attach an expiry to the grant.
    #[must_use]
    pub const fn with_expiry(mut self, expires_at_epoch_secs: u64) -> Self {
        self.expires_at_epoch_secs = Some(expires_at_epoch_secs);
        self
    }

    /// Revoke the grant in place.
    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    /// Return true if the grant is neither expired nor revoked.
    #[must_use]
    pub fn is_active(&self, now_epoch_secs: u64) -> bool {
        !self.revoked
            && self
                .expires_at_epoch_secs
                .is_none_or(|expires_at| now_epoch_secs <= expires_at)
    }

    /// Check a path-scoped operation.
    #[must_use]
    pub fn allows_path(
        &self,
        action: AllowAction,
        path: &Path,
        bytes: u64,
        now_epoch_secs: u64,
    ) -> bool {
        self.is_active(now_epoch_secs)
            && self.actions.contains(&action)
            && self.scope.covers_path(path)
            && self.quota.permits(bytes, 1)
    }

    /// Check an object-scoped operation.
    #[must_use]
    pub fn allows_object(
        &self,
        action: AllowAction,
        root: &ObjectDigest,
        bytes: u64,
        items: u64,
        now_epoch_secs: u64,
    ) -> bool {
        self.is_active(now_epoch_secs)
            && self.actions.contains(&action)
            && self.scope.covers_object(root)
            && self.quota.permits(bytes, items)
    }

    /// Check a cache-scoped operation.
    #[must_use]
    pub fn allows_cache(
        &self,
        action: AllowAction,
        object_type: &str,
        bytes: u64,
        items: u64,
        now_epoch_secs: u64,
    ) -> bool {
        self.is_active(now_epoch_secs)
            && self.actions.contains(&action)
            && self.scope.covers_cache(object_type, bytes)
            && self.quota.permits(bytes, items)
    }

    /// Check a cache operation tied to one verified object graph root.
    #[must_use]
    pub fn allows_cache_entry(
        &self,
        action: AllowAction,
        root: &ObjectDigest,
        object_type: &str,
        bytes: u64,
        items: u64,
        now_epoch_secs: u64,
    ) -> bool {
        self.is_active(now_epoch_secs)
            && self.actions.contains(&action)
            && (self.scope.covers_object(root) || self.scope.covers_cache(object_type, bytes))
            && self.quota.permits(bytes, items)
    }
}

/// Local inbox item lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InboxState {
    /// Remote peer has advertised a graph but no local action has happened.
    Pending,
    /// Offer metadata is stored and visible in the inbox.
    Offered,
    /// Receive is actively running.
    Active,
    /// Receive is paused and resumable.
    Paused,
    /// Receive failed and may need user action.
    Failed,
    /// Receive was cancelled.
    Cancelled,
    /// Graph was stored in the offline mailbox.
    MailboxStored,
    /// Graph is present in the local cache.
    Cached,
    /// Graph is being seeded from cache.
    Seeded,
    /// Receive completed successfully.
    Completed,
}

impl InboxState {
    /// Stable lowercase state name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Offered => "offered",
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::MailboxStored => "mailbox_stored",
            Self::Cached => "cached",
            Self::Seeded => "seeded",
            Self::Completed => "completed",
        }
    }

    /// Return true when no further receive work should be scheduled.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Failed | Self::Cancelled | Self::Completed)
    }
}

impl fmt::Display for InboxState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Incoming transfer offer accepted into the local inbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboxOffer {
    /// Stable inbox item identifier.
    pub item_id: String,
    /// Root digest of the offered object graph.
    pub object_root: ObjectDigest,
    /// Peer that offered the graph.
    pub source_peer: String,
    /// Local destination path requested by the offer.
    pub destination_path: PathBuf,
    /// Total bytes expected by the manifest.
    pub bytes_total: u64,
    /// Current manifest generation.
    pub manifest_epoch: u64,
    /// Caller-supplied timestamp in seconds since Unix epoch.
    pub offered_at_epoch_secs: u64,
}

/// Privacy class for an object stored by an offline ATP mailbox relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MailboxStorageClass {
    /// Relay storage may see routing metadata but not object payload bytes.
    EndToEndEncrypted,
    /// Payload bytes are intentionally public under an explicit policy id.
    ExplicitlyPublic,
}

impl MailboxStorageClass {
    /// Stable lowercase storage-class name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EndToEndEncrypted => "end_to_end_encrypted",
            Self::ExplicitlyPublic => "explicitly_public",
        }
    }
}

/// Privacy policy attached to an offline mailbox storage record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailboxPrivacyPolicy {
    /// Whether the relay stores encrypted or explicitly public bytes.
    pub storage_class: MailboxStorageClass,
    /// True when stored bytes are encrypted before the relay accepts them.
    pub encrypted_at_rest: bool,
    /// Stable public-data policy id required for explicitly public storage.
    pub public_policy_id: Option<String>,
    /// Maximum visible source-peer characters in mailbox metadata diagnostics.
    pub metadata_peer_visible_chars: usize,
}

impl MailboxPrivacyPolicy {
    /// Build the default private mailbox policy.
    #[must_use]
    pub const fn encrypted() -> Self {
        Self {
            storage_class: MailboxStorageClass::EndToEndEncrypted,
            encrypted_at_rest: true,
            public_policy_id: None,
            metadata_peer_visible_chars: 8,
        }
    }

    /// Build an explicitly public mailbox policy.
    #[must_use]
    pub fn explicitly_public(policy_id: impl Into<String>) -> Self {
        Self {
            storage_class: MailboxStorageClass::ExplicitlyPublic,
            encrypted_at_rest: false,
            public_policy_id: Some(policy_id.into()),
            metadata_peer_visible_chars: 8,
        }
    }

    /// Validate the storage privacy invariant before accepting relay custody.
    pub fn validate(&self) -> Result<(), MailboxSecurityError> {
        match self.storage_class {
            MailboxStorageClass::EndToEndEncrypted if self.encrypted_at_rest => Ok(()),
            MailboxStorageClass::EndToEndEncrypted => Err(MailboxSecurityError::MissingEncryption),
            MailboxStorageClass::ExplicitlyPublic
                if self
                    .public_policy_id
                    .as_deref()
                    .is_some_and(|policy_id| !policy_id.trim().is_empty()) =>
            {
                Ok(())
            }
            MailboxStorageClass::ExplicitlyPublic => Err(MailboxSecurityError::MissingPublicPolicy),
        }
    }

    /// Redact peer metadata according to this policy.
    #[must_use]
    pub fn redact_peer(&self, peer: &str) -> String {
        redact_token_to(peer, self.metadata_peer_visible_chars)
    }
}

/// Tamper-evidence attached to one mailbox storage record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailboxTamperEvidence {
    /// Manifest root expected by the receiver.
    pub manifest_root: ObjectDigest,
    /// Digest of encrypted relay bytes or explicitly public payload bytes.
    pub stored_object_digest: ObjectDigest,
    /// Manifest generation expected for this mailbox entry.
    pub manifest_epoch: u64,
    /// Monotonic mailbox sequence number for replay detection.
    pub sequence: u64,
    /// Expected stored byte count.
    pub content_length: u64,
    /// Entry expiry time in seconds since Unix epoch.
    pub expires_at_epoch_secs: u64,
    /// Optional previous record digest for append-only mailbox chains.
    pub previous_record_digest: Option<ObjectDigest>,
}

impl MailboxTamperEvidence {
    /// Validate retrieval evidence before a receiver trusts mailbox data.
    pub fn validate_retrieval(
        &self,
        receipt: &MailboxRetrievalReceipt,
        last_seen_sequence: Option<u64>,
    ) -> Result<(), MailboxSecurityError> {
        if receipt.retrieved_at_epoch_secs > self.expires_at_epoch_secs {
            return Err(MailboxSecurityError::StaleEntry {
                expired_at_epoch_secs: self.expires_at_epoch_secs,
                observed_epoch_secs: receipt.retrieved_at_epoch_secs,
            });
        }
        if last_seen_sequence.is_some_and(|last_seen| receipt.sequence <= last_seen) {
            return Err(MailboxSecurityError::Replay {
                last_seen_sequence,
                observed_sequence: receipt.sequence,
            });
        }
        if receipt.sequence != self.sequence {
            return Err(MailboxSecurityError::SequenceMismatch {
                expected: self.sequence,
                observed: receipt.sequence,
            });
        }
        if !object_digest_eq(&receipt.manifest_root, &self.manifest_root) {
            return Err(MailboxSecurityError::DigestMismatch {
                field: "manifest_root",
            });
        }
        if !object_digest_eq(&receipt.stored_object_digest, &self.stored_object_digest) {
            return Err(MailboxSecurityError::DigestMismatch {
                field: "stored_object_digest",
            });
        }
        if receipt.manifest_epoch != self.manifest_epoch {
            return Err(MailboxSecurityError::ManifestEpochMismatch {
                expected: self.manifest_epoch,
                observed: receipt.manifest_epoch,
            });
        }
        if receipt.bytes_returned != self.content_length {
            return Err(MailboxSecurityError::Truncated {
                expected_bytes: self.content_length,
                observed_bytes: receipt.bytes_returned,
            });
        }
        Ok(())
    }
}

/// Retrieval receipt supplied by an offline mailbox receiver.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailboxRetrievalReceipt {
    /// Manifest root observed by the receiver.
    pub manifest_root: ObjectDigest,
    /// Digest of bytes returned by the relay.
    pub stored_object_digest: ObjectDigest,
    /// Manifest generation observed by the receiver.
    pub manifest_epoch: u64,
    /// Mailbox sequence number observed by the receiver.
    pub sequence: u64,
    /// Bytes returned by the relay.
    pub bytes_returned: u64,
    /// Retrieval time in seconds since Unix epoch.
    pub retrieved_at_epoch_secs: u64,
}

/// Request to place an inbox offer into encrypted offline mailbox custody.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailboxStoreRequest {
    /// Stable mailbox record identifier used for quota accounting and replay logs.
    pub mailbox_id: String,
    /// Privacy policy applied before relay custody.
    pub privacy_policy: MailboxPrivacyPolicy,
    /// Tamper-evidence committed by the sender before upload.
    pub evidence: MailboxTamperEvidence,
    /// Bytes charged to relay mailbox storage.
    pub stored_bytes: u64,
}

impl MailboxStoreRequest {
    fn validate_for_item(
        &self,
        item: &InboxItem,
        now_epoch_secs: u64,
    ) -> Result<(), MailboxSecurityError> {
        self.privacy_policy.validate()?;
        if now_epoch_secs > self.evidence.expires_at_epoch_secs {
            return Err(MailboxSecurityError::StaleEntry {
                expired_at_epoch_secs: self.evidence.expires_at_epoch_secs,
                observed_epoch_secs: now_epoch_secs,
            });
        }
        if !object_digest_eq(&self.evidence.manifest_root, &item.object_root) {
            return Err(MailboxSecurityError::DigestMismatch {
                field: "manifest_root",
            });
        }
        if self.evidence.manifest_epoch != item.manifest_epoch {
            return Err(MailboxSecurityError::ManifestEpochMismatch {
                expected: item.manifest_epoch,
                observed: self.evidence.manifest_epoch,
            });
        }
        if self.evidence.content_length != self.stored_bytes {
            return Err(MailboxSecurityError::Truncated {
                expected_bytes: self.evidence.content_length,
                observed_bytes: self.stored_bytes,
            });
        }
        Ok(())
    }

    fn quota_allocation(&self) -> QuotaAllocation {
        QuotaAllocation::one_record(QuotaBucket::Mailbox, self.stored_bytes)
    }
}

/// Durable offline mailbox custody record for a pending transfer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailboxStorageRecord {
    /// Stable mailbox record identifier.
    pub mailbox_id: String,
    /// Inbox item represented by this mailbox record.
    pub item_id: String,
    /// Object graph root committed by the manifest.
    pub object_root: ObjectDigest,
    /// Source peer token redacted for relay-visible diagnostics.
    pub redacted_source_peer: String,
    /// Grant used to authorize mailbox custody.
    pub grant_id: String,
    /// Privacy policy applied before relay custody.
    pub privacy_policy: MailboxPrivacyPolicy,
    /// Tamper-evidence needed before receiver trust.
    pub evidence: MailboxTamperEvidence,
    /// Quota allocation record id.
    pub allocation_record_id: String,
    /// Time this record entered mailbox custody.
    pub stored_at_epoch_secs: u64,
}

impl MailboxStorageRecord {
    /// Validate a receiver retrieval receipt before exposing mailbox bytes.
    pub fn validate_retrieval(
        &self,
        receipt: &MailboxRetrievalReceipt,
        last_seen_sequence: Option<u64>,
    ) -> Result<(), MailboxSecurityError> {
        self.evidence
            .validate_retrieval(receipt, last_seen_sequence)
    }
}

/// Verified object graph indexed for local cache/seeding decisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheIndexRecord {
    /// Inbox item represented by this cache row.
    pub item_id: String,
    /// Object graph root committed by the manifest.
    pub object_root: ObjectDigest,
    /// Manifest generation verified before cache exposure.
    pub manifest_epoch: u64,
    /// Stable object type used by cache grants.
    pub object_type: String,
    /// Verified bytes indexed in the cache.
    pub bytes: u64,
    /// Grant used to authorize local cache custody.
    pub cache_grant_id: String,
    /// Grant used to authorize seeding, if seeding has started.
    pub seed_grant_id: Option<String>,
    /// Time this record entered local cache custody.
    pub cached_at_epoch_secs: u64,
    /// Time this record started seeding to authorized peers.
    pub seeded_at_epoch_secs: Option<u64>,
}

/// Offline mailbox security validation failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MailboxSecurityError {
    /// Private mailbox storage was not encrypted before relay custody.
    MissingEncryption,
    /// Public mailbox storage lacked an explicit public-data policy id.
    MissingPublicPolicy,
    /// A digest-bearing field differed from the expected value.
    DigestMismatch {
        /// Field that failed the digest check.
        field: &'static str,
    },
    /// The retrieved manifest generation differed from the expected generation.
    ManifestEpochMismatch {
        /// Expected manifest generation.
        expected: u64,
        /// Observed manifest generation.
        observed: u64,
    },
    /// The retrieved mailbox sequence differed from the expected sequence.
    SequenceMismatch {
        /// Expected sequence.
        expected: u64,
        /// Observed sequence.
        observed: u64,
    },
    /// Retrieval repeated or rewound a previously seen sequence number.
    Replay {
        /// Highest sequence observed before this retrieval.
        last_seen_sequence: Option<u64>,
        /// Sequence observed in this retrieval.
        observed_sequence: u64,
    },
    /// Relay returned fewer or more bytes than the manifest committed.
    Truncated {
        /// Expected byte count.
        expected_bytes: u64,
        /// Observed byte count.
        observed_bytes: u64,
    },
    /// Mailbox entry was retrieved after its expiry.
    StaleEntry {
        /// Entry expiry time.
        expired_at_epoch_secs: u64,
        /// Observed retrieval time.
        observed_epoch_secs: u64,
    },
}

impl fmt::Display for MailboxSecurityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingEncryption => f.write_str("private mailbox object is not encrypted"),
            Self::MissingPublicPolicy => {
                f.write_str("public mailbox object lacks an explicit policy id")
            }
            Self::DigestMismatch { field } => write!(f, "mailbox digest mismatch in {field}"),
            Self::ManifestEpochMismatch { expected, observed } => write!(
                f,
                "mailbox manifest epoch mismatch: expected {expected}, observed {observed}"
            ),
            Self::SequenceMismatch { expected, observed } => write!(
                f,
                "mailbox sequence mismatch: expected {expected}, observed {observed}"
            ),
            Self::Replay {
                last_seen_sequence,
                observed_sequence,
            } => write!(
                f,
                "mailbox replay detected: last seen {last_seen_sequence:?}, observed {observed_sequence}"
            ),
            Self::Truncated {
                expected_bytes,
                observed_bytes,
            } => write!(
                f,
                "mailbox truncation detected: expected {expected_bytes} bytes, observed {observed_bytes}"
            ),
            Self::StaleEntry {
                expired_at_epoch_secs,
                observed_epoch_secs,
            } => write!(
                f,
                "stale mailbox entry: expired at {expired_at_epoch_secs}, observed at {observed_epoch_secs}"
            ),
        }
    }
}

impl std::error::Error for MailboxSecurityError {}

/// Inbox item stored by the daemon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboxItem {
    /// Stable inbox item identifier.
    pub item_id: String,
    /// Root digest of the object graph.
    pub object_root: ObjectDigest,
    /// Peer that offered the graph.
    pub source_peer: String,
    /// Local destination path.
    pub destination_path: PathBuf,
    /// Total bytes expected by the manifest.
    pub bytes_total: u64,
    /// Bytes received so far.
    pub bytes_received: u64,
    /// Current manifest generation.
    pub manifest_epoch: u64,
    /// Current lifecycle state.
    pub state: InboxState,
    /// Grant used to authorize receive work.
    pub grant_id: Option<String>,
    /// Last state update time in seconds since Unix epoch.
    pub updated_epoch_secs: u64,
    /// Redacted failure reason suitable for stable diagnostics.
    pub failure_reason: Option<String>,
}

impl InboxItem {
    /// Return a redacted source peer token for human diagnostics.
    #[must_use]
    pub fn redacted_source_peer(&self) -> String {
        redact_token(&self.source_peer)
    }
}

/// Stable JSON row emitted for `atpd inbox --json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboxJsonRow {
    /// Stable inbox item identifier.
    pub item_id: String,
    /// Stable lowercase state.
    pub state: String,
    /// Redacted object graph root.
    pub object_root: String,
    /// Redacted source peer.
    pub source_peer: String,
    /// Local destination path.
    pub destination_path: String,
    /// Total bytes expected by the manifest.
    pub bytes_total: u64,
    /// Bytes received so far.
    pub bytes_received: u64,
    /// Current manifest generation.
    pub manifest_epoch: u64,
    /// Grant used to authorize receive work.
    pub grant_id: Option<String>,
    /// Redacted failure reason.
    pub failure_reason: Option<String>,
}

/// Aggregated inbox diagnostics for daemon status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboxDiagnostics {
    /// Total inbox items.
    pub item_count: usize,
    /// Active receive count.
    pub active_count: usize,
    /// Stored offline mailbox item count.
    pub mailbox_stored_count: usize,
    /// Locally cached item count.
    pub cached_count: usize,
    /// Locally seeded item count.
    pub seeded_count: usize,
    /// Completed item count.
    pub completed_count: usize,
    /// Failed item count.
    pub failed_count: usize,
    /// Cancelled item count.
    pub cancelled_count: usize,
    /// Grant count known to the inbox.
    pub grant_count: usize,
}

/// Whole-daemon ATP diagnostics snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonDiagnostics {
    /// Number of active transfers.
    pub active_transfers: usize,
    /// Number of path candidates currently tracked.
    pub path_count: usize,
    /// Number of repair sessions currently tracked.
    pub repair_sessions: usize,
    /// Available disk bytes when known.
    pub disk_available_bytes: Option<u64>,
    /// Journal record count.
    pub journal_entries: usize,
    /// Grant count.
    pub grant_count: usize,
    /// Cache entry count.
    pub cache_entries: usize,
    /// Inbox item count.
    pub inbox_items: usize,
    /// Platform name or class.
    pub platform: String,
    /// Service lifecycle state.
    pub service_lifecycle: String,
}

impl DaemonDiagnostics {
    /// Emit stable redacted human rows.
    #[must_use]
    pub fn stable_human_lines(&self) -> Vec<String> {
        vec![
            format!("lifecycle {}", self.service_lifecycle),
            format!("platform {}", redact_token(&self.platform)),
            format!("active_transfers {}", self.active_transfers),
            format!("paths {}", self.path_count),
            format!("repair_sessions {}", self.repair_sessions),
            format!("journal_entries {}", self.journal_entries),
            format!("grants {}", self.grant_count),
            format!("cache_entries {}", self.cache_entries),
            format!("inbox_items {}", self.inbox_items),
            format!(
                "disk_available_bytes {}",
                self.disk_available_bytes
                    .map_or_else(|| "unknown".to_string(), |bytes| bytes.to_string())
            ),
        ]
    }
}

/// Local inbox and receive-grant index.
#[derive(Debug, Clone, Default)]
pub struct LocalInbox {
    grants: BTreeMap<String, ReceiveGrant>,
    items: BTreeMap<String, InboxItem>,
    cache_records: BTreeMap<String, CacheIndexRecord>,
    mailbox_records: BTreeMap<String, MailboxStorageRecord>,
    mailbox_last_seen_sequences: BTreeMap<String, u64>,
}

impl LocalInbox {
    /// Create an empty local inbox.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            grants: BTreeMap::new(),
            items: BTreeMap::new(),
            cache_records: BTreeMap::new(),
            mailbox_records: BTreeMap::new(),
            mailbox_last_seen_sequences: BTreeMap::new(),
        }
    }

    /// Store or replace a receive grant.
    pub fn allow(&mut self, grant: ReceiveGrant) {
        self.grants.insert(grant.id.clone(), grant);
    }

    /// Revoke a grant by id.
    pub fn revoke(&mut self, grant_id: &str) -> Result<(), InboxError> {
        let grant = self
            .grants
            .get_mut(grant_id)
            .ok_or_else(|| InboxError::UnknownGrant(grant_id.to_string()))?;
        grant.revoke();
        Ok(())
    }

    /// Return a grant by id.
    #[must_use]
    pub fn grant(&self, grant_id: &str) -> Option<&ReceiveGrant> {
        self.grants.get(grant_id)
    }

    /// Accept an incoming offer into the inbox.
    pub fn offer(&mut self, offer: InboxOffer) -> Result<(), InboxError> {
        if self.items.contains_key(&offer.item_id) {
            return Err(InboxError::DuplicateItem(offer.item_id));
        }

        let item = InboxItem {
            item_id: offer.item_id.clone(),
            object_root: offer.object_root,
            source_peer: offer.source_peer,
            destination_path: offer.destination_path,
            bytes_total: offer.bytes_total,
            bytes_received: 0,
            manifest_epoch: offer.manifest_epoch,
            state: InboxState::Offered,
            grant_id: None,
            updated_epoch_secs: offer.offered_at_epoch_secs,
            failure_reason: None,
        };
        self.items.insert(offer.item_id, item);
        Ok(())
    }

    /// Start receiving an offered item after checking receive permissions.
    pub fn start_receive(
        &mut self,
        item_id: &str,
        grant_id: &str,
        now_epoch_secs: u64,
    ) -> Result<(), InboxError> {
        let item = self
            .items
            .get(item_id)
            .ok_or_else(|| InboxError::UnknownItem(item_id.to_string()))?;
        let grant = self
            .grants
            .get(grant_id)
            .ok_or_else(|| InboxError::UnknownGrant(grant_id.to_string()))?;

        if !grant.allows_path(
            AllowAction::Receive,
            &item.destination_path,
            item.bytes_total,
            now_epoch_secs,
        ) {
            return Err(InboxError::Unauthorized {
                grant_id: grant_id.to_string(),
                action: AllowAction::Receive,
            });
        }

        let item = self
            .items
            .get_mut(item_id)
            .ok_or_else(|| InboxError::UnknownItem(item_id.to_string()))?;
        ensure_transition(item.state, InboxState::Active)?;
        item.state = InboxState::Active;
        item.grant_id = Some(grant_id.to_string());
        item.updated_epoch_secs = now_epoch_secs;
        Ok(())
    }

    /// Record deterministic receive progress.
    pub fn record_progress(
        &mut self,
        item_id: &str,
        bytes_received: u64,
        now_epoch_secs: u64,
    ) -> Result<(), InboxError> {
        let item = self
            .items
            .get_mut(item_id)
            .ok_or_else(|| InboxError::UnknownItem(item_id.to_string()))?;
        if item.state.is_terminal() {
            return Err(InboxError::InvalidTransition {
                from: item.state,
                to: item.state,
            });
        }
        item.bytes_received = bytes_received.min(item.bytes_total);
        item.updated_epoch_secs = now_epoch_secs;
        if item.bytes_received == item.bytes_total {
            ensure_transition(item.state, InboxState::Completed)?;
            item.state = InboxState::Completed;
        }
        Ok(())
    }

    /// Store an offered transfer in encrypted offline mailbox custody.
    pub fn store_mailbox(
        &mut self,
        item_id: &str,
        grant_id: &str,
        request: MailboxStoreRequest,
        quota: &mut QuotaLedger,
        now_epoch_secs: u64,
    ) -> Result<(), InboxError> {
        if self.mailbox_records.contains_key(&request.mailbox_id) {
            return Err(InboxError::DuplicateMailboxRecord(request.mailbox_id));
        }

        let item = self
            .items
            .get(item_id)
            .ok_or_else(|| InboxError::UnknownItem(item_id.to_string()))?;
        ensure_transition(item.state, InboxState::MailboxStored)?;
        request
            .validate_for_item(item, now_epoch_secs)
            .map_err(InboxError::MailboxSecurity)?;

        let grant = self
            .grants
            .get(grant_id)
            .ok_or_else(|| InboxError::UnknownGrant(grant_id.to_string()))?;
        if !grant.allows_path(
            AllowAction::Receive,
            &item.destination_path,
            request.stored_bytes,
            now_epoch_secs,
        ) {
            return Err(InboxError::Unauthorized {
                grant_id: grant_id.to_string(),
                action: AllowAction::Receive,
            });
        }

        quota
            .reserve(request.mailbox_id.clone(), request.quota_allocation())
            .map_err(InboxError::Quota)?;

        let redacted_source_peer = request.privacy_policy.redact_peer(&item.source_peer);
        let record = MailboxStorageRecord {
            mailbox_id: request.mailbox_id.clone(),
            item_id: item.item_id.clone(),
            object_root: item.object_root.clone(),
            redacted_source_peer,
            grant_id: grant_id.to_string(),
            privacy_policy: request.privacy_policy,
            evidence: request.evidence,
            allocation_record_id: request.mailbox_id.clone(),
            stored_at_epoch_secs: now_epoch_secs,
        };

        let item = self
            .items
            .get_mut(item_id)
            .ok_or_else(|| InboxError::UnknownItem(item_id.to_string()))?;
        item.state = InboxState::MailboxStored;
        item.grant_id = Some(grant_id.to_string());
        item.updated_epoch_secs = now_epoch_secs;
        self.mailbox_records
            .insert(record.mailbox_id.clone(), record);
        Ok(())
    }

    /// Begin a later `get --pending` receive from a stored mailbox record.
    pub fn start_mailbox_retrieval(
        &mut self,
        mailbox_id: &str,
        receipt: &MailboxRetrievalReceipt,
        last_seen_sequence: Option<u64>,
        now_epoch_secs: u64,
    ) -> Result<(), InboxError> {
        let record = self
            .mailbox_records
            .get(mailbox_id)
            .ok_or_else(|| InboxError::UnknownMailboxRecord(mailbox_id.to_string()))?;
        let recorded_last_seen = self.mailbox_last_seen_sequences.get(mailbox_id).copied();
        let effective_last_seen = match (last_seen_sequence, recorded_last_seen) {
            (Some(caller_sequence), Some(recorded_sequence)) => {
                Some(caller_sequence.max(recorded_sequence))
            }
            (Some(caller_sequence), None) => Some(caller_sequence),
            (None, Some(recorded_sequence)) => Some(recorded_sequence),
            (None, None) => None,
        };
        record
            .validate_retrieval(receipt, effective_last_seen)
            .map_err(InboxError::MailboxSecurity)?;

        let item = self
            .items
            .get_mut(&record.item_id)
            .ok_or_else(|| InboxError::UnknownItem(record.item_id.clone()))?;
        ensure_transition(item.state, InboxState::Active)?;
        item.state = InboxState::Active;
        item.bytes_received = receipt.bytes_returned.min(item.bytes_total);
        item.updated_epoch_secs = now_epoch_secs;
        self.mailbox_last_seen_sequences
            .insert(mailbox_id.to_string(), receipt.sequence);
        Ok(())
    }

    /// Index a verified object graph in the local cache after grant enforcement.
    pub fn cache_verified(
        &mut self,
        item_id: &str,
        grant_id: &str,
        object_type: impl Into<String>,
        bytes: u64,
        now_epoch_secs: u64,
    ) -> Result<(), InboxError> {
        if self.cache_records.contains_key(item_id) {
            return Err(InboxError::DuplicateCacheRecord(item_id.to_string()));
        }

        let object_type = object_type.into();
        let item = self
            .items
            .get(item_id)
            .ok_or_else(|| InboxError::UnknownItem(item_id.to_string()))?;
        ensure_transition(item.state, InboxState::Cached)?;

        let grant = self
            .grants
            .get(grant_id)
            .ok_or_else(|| InboxError::UnknownGrant(grant_id.to_string()))?;
        if !grant.allows_cache_entry(
            AllowAction::Cache,
            &item.object_root,
            &object_type,
            bytes,
            1,
            now_epoch_secs,
        ) {
            return Err(InboxError::Unauthorized {
                grant_id: grant_id.to_string(),
                action: AllowAction::Cache,
            });
        }

        let record = CacheIndexRecord {
            item_id: item.item_id.clone(),
            object_root: item.object_root.clone(),
            manifest_epoch: item.manifest_epoch,
            object_type,
            bytes,
            cache_grant_id: grant_id.to_string(),
            seed_grant_id: None,
            cached_at_epoch_secs: now_epoch_secs,
            seeded_at_epoch_secs: None,
        };

        let item = self
            .items
            .get_mut(item_id)
            .ok_or_else(|| InboxError::UnknownItem(item_id.to_string()))?;
        item.state = InboxState::Cached;
        item.grant_id = Some(grant_id.to_string());
        item.updated_epoch_secs = now_epoch_secs;
        self.cache_records.insert(item_id.to_string(), record);
        Ok(())
    }

    /// Start seeding a cached object graph after grant enforcement.
    pub fn seed_cached(
        &mut self,
        item_id: &str,
        grant_id: &str,
        now_epoch_secs: u64,
    ) -> Result<(), InboxError> {
        let item = self
            .items
            .get(item_id)
            .ok_or_else(|| InboxError::UnknownItem(item_id.to_string()))?;
        ensure_transition(item.state, InboxState::Seeded)?;

        let record = self
            .cache_records
            .get(item_id)
            .ok_or_else(|| InboxError::UnknownCacheRecord(item_id.to_string()))?;
        let grant = self
            .grants
            .get(grant_id)
            .ok_or_else(|| InboxError::UnknownGrant(grant_id.to_string()))?;
        if !grant.allows_cache_entry(
            AllowAction::Seed,
            &record.object_root,
            &record.object_type,
            record.bytes,
            1,
            now_epoch_secs,
        ) {
            return Err(InboxError::Unauthorized {
                grant_id: grant_id.to_string(),
                action: AllowAction::Seed,
            });
        }

        let item = self
            .items
            .get_mut(item_id)
            .ok_or_else(|| InboxError::UnknownItem(item_id.to_string()))?;
        item.state = InboxState::Seeded;
        item.grant_id = Some(grant_id.to_string());
        item.updated_epoch_secs = now_epoch_secs;

        let record = self
            .cache_records
            .get_mut(item_id)
            .ok_or_else(|| InboxError::UnknownCacheRecord(item_id.to_string()))?;
        record.seed_grant_id = Some(grant_id.to_string());
        record.seeded_at_epoch_secs = Some(now_epoch_secs);
        Ok(())
    }

    /// Move an item through its lifecycle.
    pub fn transition(
        &mut self,
        item_id: &str,
        next: InboxState,
        now_epoch_secs: u64,
    ) -> Result<(), InboxError> {
        let item = self
            .items
            .get_mut(item_id)
            .ok_or_else(|| InboxError::UnknownItem(item_id.to_string()))?;
        ensure_transition(item.state, next)?;
        item.state = next;
        item.updated_epoch_secs = now_epoch_secs;
        Ok(())
    }

    /// Mark an item as failed with a stable redacted reason.
    pub fn mark_failed(
        &mut self,
        item_id: &str,
        reason: impl Into<String>,
        now_epoch_secs: u64,
    ) -> Result<(), InboxError> {
        let item = self
            .items
            .get_mut(item_id)
            .ok_or_else(|| InboxError::UnknownItem(item_id.to_string()))?;
        ensure_transition(item.state, InboxState::Failed)?;
        item.state = InboxState::Failed;
        item.updated_epoch_secs = now_epoch_secs;
        item.failure_reason = Some(redact_token(&reason.into()));
        Ok(())
    }

    /// Return all items in stable id order.
    #[must_use]
    pub fn list(&self) -> Vec<&InboxItem> {
        self.items.values().collect()
    }

    /// Return items in one state in stable id order.
    #[must_use]
    pub fn list_by_state(&self, state: InboxState) -> Vec<&InboxItem> {
        self.items
            .values()
            .filter(|item| item.state == state)
            .collect()
    }

    /// Return stored mailbox records in stable mailbox id order.
    #[must_use]
    pub fn mailbox_records(&self) -> Vec<&MailboxStorageRecord> {
        self.mailbox_records.values().collect()
    }

    /// Return cached object records in stable item id order.
    #[must_use]
    pub fn cache_records(&self) -> Vec<&CacheIndexRecord> {
        self.cache_records.values().collect()
    }

    /// Return stable JSON-compatible rows.
    #[must_use]
    pub fn json_rows(&self) -> Vec<InboxJsonRow> {
        self.items.values().map(InboxJsonRow::from).collect()
    }

    /// Return stable JSON lines.
    pub fn json_lines(&self) -> Result<Vec<String>, serde_json::Error> {
        self.json_rows().iter().map(serde_json::to_string).collect()
    }

    /// Return stable redacted human rows.
    #[must_use]
    pub fn human_rows(&self) -> Vec<String> {
        let mut rows = vec!["id state bytes source destination".to_string()];
        rows.extend(self.items.values().map(|item| {
            format!(
                "{} {} {}/{} {} {}",
                item.item_id,
                item.state,
                item.bytes_received,
                item.bytes_total,
                item.redacted_source_peer(),
                item.destination_path.display()
            )
        }));
        rows
    }

    /// Return aggregate inbox diagnostics.
    #[must_use]
    pub fn diagnostics(&self) -> InboxDiagnostics {
        let mut counts = BTreeMap::new();
        for item in self.items.values() {
            *counts.entry(item.state).or_insert(0) += 1;
        }
        InboxDiagnostics {
            item_count: self.items.len(),
            active_count: count_state(&counts, InboxState::Active),
            mailbox_stored_count: count_state(&counts, InboxState::MailboxStored),
            cached_count: count_state(&counts, InboxState::Cached),
            seeded_count: count_state(&counts, InboxState::Seeded),
            completed_count: count_state(&counts, InboxState::Completed),
            failed_count: count_state(&counts, InboxState::Failed),
            cancelled_count: count_state(&counts, InboxState::Cancelled),
            grant_count: self.grants.len(),
        }
    }
}

impl From<&InboxItem> for InboxJsonRow {
    fn from(item: &InboxItem) -> Self {
        Self {
            item_id: item.item_id.clone(), // ubs:ignore - diagnostic serialization
            state: item.state.as_str().to_string(), // ubs:ignore - diagnostic serialization
            object_root: item.object_root.redacted(),
            source_peer: item.redacted_source_peer(),
            destination_path: item.destination_path.display().to_string(), // ubs:ignore - diagnostic serialization
            bytes_total: item.bytes_total,
            bytes_received: item.bytes_received,
            manifest_epoch: item.manifest_epoch,
            grant_id: item.grant_id.clone(), // ubs:ignore - diagnostic serialization
            failure_reason: item.failure_reason.clone(), // ubs:ignore - diagnostic serialization
        }
    }
}

/// Inbox authorization and lifecycle error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboxError {
    /// The item id is unknown.
    UnknownItem(String),
    /// The grant id is unknown.
    UnknownGrant(String),
    /// The mailbox record id is unknown.
    UnknownMailboxRecord(String),
    /// The cache record id is unknown.
    UnknownCacheRecord(String),
    /// The item id already exists.
    DuplicateItem(String),
    /// The mailbox record id already exists.
    DuplicateMailboxRecord(String),
    /// The cache record id already exists.
    DuplicateCacheRecord(String),
    /// The grant does not authorize the operation.
    Unauthorized {
        /// Grant that failed authorization.
        grant_id: String,
        /// Action that was requested.
        action: AllowAction,
    },
    /// The lifecycle transition is invalid.
    InvalidTransition {
        /// Current state.
        from: InboxState,
        /// Requested state.
        to: InboxState,
    },
    /// Mailbox privacy or tamper evidence failed validation.
    MailboxSecurity(MailboxSecurityError),
    /// Mailbox quota accounting failed before state transition.
    Quota(QuotaError),
}

impl fmt::Display for InboxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownItem(item_id) => write!(f, "unknown inbox item `{item_id}`"),
            Self::UnknownGrant(grant_id) => write!(f, "unknown grant `{grant_id}`"),
            Self::UnknownMailboxRecord(mailbox_id) => {
                write!(f, "unknown mailbox record `{mailbox_id}`")
            }
            Self::UnknownCacheRecord(item_id) => write!(f, "unknown cache record `{item_id}`"),
            Self::DuplicateItem(item_id) => write!(f, "duplicate inbox item `{item_id}`"),
            Self::DuplicateMailboxRecord(mailbox_id) => {
                write!(f, "duplicate mailbox record `{mailbox_id}`")
            }
            Self::DuplicateCacheRecord(item_id) => {
                write!(f, "duplicate cache record `{item_id}`")
            }
            Self::Unauthorized { grant_id, action } => {
                write!(
                    f,
                    "grant `{grant_id}` does not authorize {}",
                    action.as_str()
                )
            }
            Self::InvalidTransition { from, to } => {
                write!(f, "invalid inbox transition from {from} to {to}")
            }
            Self::MailboxSecurity(err) => write!(f, "{err}"),
            Self::Quota(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for InboxError {}

fn ensure_transition(from: InboxState, to: InboxState) -> Result<(), InboxError> {
    if from == to || valid_transition(from, to) {
        return Ok(());
    }
    Err(InboxError::InvalidTransition { from, to })
}

const fn valid_transition(from: InboxState, to: InboxState) -> bool {
    match from {
        InboxState::Pending => matches!(to, InboxState::Offered | InboxState::Cancelled),
        InboxState::Offered => matches!(
            to,
            InboxState::Active
                | InboxState::Paused
                | InboxState::Cancelled
                | InboxState::MailboxStored
        ),
        InboxState::Active => matches!(
            to,
            InboxState::Paused
                | InboxState::Failed
                | InboxState::Cancelled
                | InboxState::MailboxStored
                | InboxState::Cached
                | InboxState::Seeded
                | InboxState::Completed
        ),
        InboxState::Paused => {
            matches!(
                to,
                InboxState::Active | InboxState::Cancelled | InboxState::Failed
            )
        }
        InboxState::MailboxStored => {
            matches!(
                to,
                InboxState::Active | InboxState::Cached | InboxState::Cancelled
            )
        }
        InboxState::Cached => {
            matches!(
                to,
                InboxState::Seeded | InboxState::Completed | InboxState::Cancelled
            )
        }
        InboxState::Seeded => matches!(to, InboxState::Completed | InboxState::Cancelled),
        InboxState::Failed | InboxState::Cancelled | InboxState::Completed => false,
    }
}

fn count_state(counts: &BTreeMap<InboxState, usize>, state: InboxState) -> usize {
    counts.get(&state).copied().unwrap_or(0)
}

fn object_digest_eq(left: &ObjectDigest, right: &ObjectDigest) -> bool {
    subtle::ConstantTimeEq::ct_eq(left.as_bytes().as_ref(), right.as_bytes().as_ref()).into()
}

fn redact_token(token: &str) -> String {
    redact_token_to(token, 8)
}

fn redact_token_to(token: &str, visible_chars: usize) -> String {
    let visible: String = token.chars().take(visible_chars).collect();
    if token.chars().count() <= visible_chars {
        visible
    } else {
        format!("{visible}...")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atp::quota::{QuotaLimit, QuotaUsage};

    fn digest(byte: u8) -> ObjectDigest {
        ObjectDigest::new([byte; 32])
    }

    fn receive_actions() -> BTreeSet<AllowAction> {
        std::iter::once(AllowAction::Receive).collect()
    }

    fn cache_actions() -> BTreeSet<AllowAction> {
        std::iter::once(AllowAction::Cache).collect()
    }

    fn seed_actions() -> BTreeSet<AllowAction> {
        std::iter::once(AllowAction::Seed).collect()
    }

    fn offer(item_id: &str, path: &str, bytes_total: u64) -> InboxOffer {
        InboxOffer {
            item_id: item_id.to_string(),
            object_root: digest(7),
            source_peer: "peer-abcdefghijklmnopqrstuvwxyz".to_string(),
            destination_path: PathBuf::from(path),
            bytes_total,
            manifest_epoch: 3,
            offered_at_epoch_secs: 10,
        }
    }

    fn mailbox_evidence() -> MailboxTamperEvidence {
        MailboxTamperEvidence {
            manifest_root: digest(1),
            stored_object_digest: digest(2),
            manifest_epoch: 7,
            sequence: 42,
            content_length: 4096,
            expires_at_epoch_secs: 100,
            previous_record_digest: Some(digest(3)),
        }
    }

    fn mailbox_receipt() -> MailboxRetrievalReceipt {
        MailboxRetrievalReceipt {
            manifest_root: digest(1),
            stored_object_digest: digest(2),
            manifest_epoch: 7,
            sequence: 42,
            bytes_returned: 4096,
            retrieved_at_epoch_secs: 99,
        }
    }

    fn mailbox_store_request(mailbox_id: &str, stored_bytes: u64) -> MailboxStoreRequest {
        MailboxStoreRequest {
            mailbox_id: mailbox_id.to_string(),
            privacy_policy: MailboxPrivacyPolicy::encrypted(),
            evidence: MailboxTamperEvidence {
                manifest_root: digest(7),
                stored_object_digest: digest(8),
                manifest_epoch: 3,
                sequence: 1,
                content_length: stored_bytes,
                expires_at_epoch_secs: 100,
                previous_record_digest: None,
            },
            stored_bytes,
        }
    }

    fn stored_mailbox_receipt(bytes_returned: u64) -> MailboxRetrievalReceipt {
        MailboxRetrievalReceipt {
            manifest_root: digest(7),
            stored_object_digest: digest(8),
            manifest_epoch: 3,
            sequence: 1,
            bytes_returned,
            retrieved_at_epoch_secs: 12,
        }
    }

    #[test]
    fn mailbox_privacy_policy_requires_encryption_or_public_policy() {
        let encrypted = MailboxPrivacyPolicy::encrypted();
        assert_eq!(
            encrypted.storage_class,
            MailboxStorageClass::EndToEndEncrypted
        );
        encrypted.validate().unwrap(); // ubs:ignore - test oracle

        let mut broken_private = MailboxPrivacyPolicy::encrypted();
        broken_private.encrypted_at_rest = false;
        assert_eq!(
            broken_private.validate().unwrap_err(), // ubs:ignore - test oracle
            MailboxSecurityError::MissingEncryption
        );

        let public = MailboxPrivacyPolicy::explicitly_public("policy:public-fixture");
        public.validate().unwrap(); // ubs:ignore - test oracle
        assert_eq!(
            MailboxPrivacyPolicy::explicitly_public("  ")
                .validate()
                .unwrap_err(), // ubs:ignore - test oracle
            MailboxSecurityError::MissingPublicPolicy
        );

        let redacted = MailboxPrivacyPolicy {
            metadata_peer_visible_chars: 4,
            ..MailboxPrivacyPolicy::encrypted()
        }
        .redact_peer("peer-abcdefghijklmnopqrstuvwxyz");
        assert_eq!(redacted, "peer...");
    }

    #[test]
    fn mailbox_tamper_evidence_rejects_bad_retrievals() {
        let evidence = mailbox_evidence();
        let receipt = mailbox_receipt();
        evidence.validate_retrieval(&receipt, Some(41)).unwrap(); // ubs:ignore - test oracle

        let mut tampered = mailbox_receipt();
        tampered.stored_object_digest = digest(9);
        assert_eq!(
            evidence.validate_retrieval(&tampered, Some(41)),
            Err(MailboxSecurityError::DigestMismatch {
                field: "stored_object_digest"
            })
        );

        let mut replayed = mailbox_receipt();
        replayed.sequence = 41;
        assert_eq!(
            evidence.validate_retrieval(&replayed, Some(41)),
            Err(MailboxSecurityError::Replay {
                last_seen_sequence: Some(41),
                observed_sequence: 41,
            })
        );

        let mut truncated = mailbox_receipt();
        truncated.bytes_returned = 1024;
        assert_eq!(
            evidence.validate_retrieval(&truncated, Some(41)),
            Err(MailboxSecurityError::Truncated {
                expected_bytes: 4096,
                observed_bytes: 1024,
            })
        );

        let mut stale = mailbox_receipt();
        stale.retrieved_at_epoch_secs = 101;
        assert_eq!(
            evidence.validate_retrieval(&stale, Some(41)),
            Err(MailboxSecurityError::StaleEntry {
                expired_at_epoch_secs: 100,
                observed_epoch_secs: 101,
            })
        );
    }

    #[test]
    fn encrypted_mailbox_store_charges_quota_and_records_tamper_evidence() {
        let mut inbox = LocalInbox::new();
        let mut quota = QuotaLedger::new();
        quota.set_limit(QuotaBucket::Mailbox, QuotaLimit::new(1024, 4));
        inbox
            .offer(offer("in-1", "/data/inbox/project", 128))
            .unwrap(); // ubs:ignore - test oracle
        inbox.allow(ReceiveGrant::new(
            "grant-1",
            "peer-a",
            receive_actions(),
            GrantScope::PathPrefix(PathBuf::from("/data/inbox")),
        ));

        inbox
            .store_mailbox(
                "in-1",
                "grant-1",
                mailbox_store_request("mailbox-1", 128),
                &mut quota,
                11,
            )
            .unwrap(); // ubs:ignore - test oracle

        let item = inbox.list()[0]; // ubs:ignore - test oracle
        assert_eq!(item.state, InboxState::MailboxStored);
        assert_eq!(item.grant_id.as_deref(), Some("grant-1"));
        assert_eq!(
            quota.usage(QuotaBucket::Mailbox),
            QuotaUsage {
                bytes: 128,
                records: 1
            }
        );

        let record = inbox.mailbox_records()[0]; // ubs:ignore - test oracle
        assert_eq!(record.mailbox_id, "mailbox-1");
        assert_eq!(record.allocation_record_id, "mailbox-1");
        assert_eq!(record.redacted_source_peer, "peer-abc...");
        assert_eq!(record.evidence.stored_object_digest, digest(8));

        let receipt = stored_mailbox_receipt(128);
        record.validate_retrieval(&receipt, None).unwrap(); // ubs:ignore - test oracle
    }

    #[test]
    fn mailbox_get_pending_validates_receipt_before_active_receive() {
        let mut inbox = LocalInbox::new();
        let mut quota = QuotaLedger::new();
        quota.set_limit(QuotaBucket::Mailbox, QuotaLimit::new(1024, 4));
        inbox
            .offer(offer("in-1", "/data/inbox/project", 128))
            .unwrap(); // ubs:ignore - test oracle
        inbox.allow(ReceiveGrant::new(
            "grant-1",
            "peer-a",
            receive_actions(),
            GrantScope::PathPrefix(PathBuf::from("/data/inbox")),
        ));
        inbox
            .store_mailbox(
                "in-1",
                "grant-1",
                mailbox_store_request("mailbox-1", 128),
                &mut quota,
                11,
            )
            .unwrap(); // ubs:ignore - test oracle

        inbox
            .start_mailbox_retrieval("mailbox-1", &stored_mailbox_receipt(128), None, 13)
            .unwrap(); // ubs:ignore - test oracle

        let item = inbox.list()[0]; // ubs:ignore - test oracle
        assert_eq!(item.state, InboxState::Active);
        assert_eq!(item.bytes_received, 128);
        assert_eq!(item.updated_epoch_secs, 13);
    }

    #[test]
    fn mailbox_get_pending_rejects_replay_even_without_caller_sequence() {
        let mut inbox = LocalInbox::new();
        let mut quota = QuotaLedger::new();
        quota.set_limit(QuotaBucket::Mailbox, QuotaLimit::new(1024, 4));
        inbox
            .offer(offer("in-1", "/data/inbox/project", 128))
            .unwrap(); // ubs:ignore - test oracle
        inbox.allow(ReceiveGrant::new(
            "grant-1",
            "peer-a",
            receive_actions(),
            GrantScope::PathPrefix(PathBuf::from("/data/inbox")),
        ));
        inbox
            .store_mailbox(
                "in-1",
                "grant-1",
                mailbox_store_request("mailbox-1", 128),
                &mut quota,
                11,
            )
            .unwrap(); // ubs:ignore - test oracle
        let receipt = stored_mailbox_receipt(128);
        inbox
            .start_mailbox_retrieval("mailbox-1", &receipt, None, 13)
            .unwrap(); // ubs:ignore - test oracle

        let err = inbox
            .start_mailbox_retrieval("mailbox-1", &receipt, None, 14)
            .unwrap_err(); // ubs:ignore - test oracle

        assert_eq!(
            err,
            InboxError::MailboxSecurity(MailboxSecurityError::Replay {
                last_seen_sequence: Some(1),
                observed_sequence: 1
            })
        );
        let item = inbox.list()[0]; // ubs:ignore - test oracle
        assert_eq!(item.state, InboxState::Active);
        assert_eq!(item.bytes_received, 128);
        assert_eq!(item.updated_epoch_secs, 13);
    }

    #[test]
    fn mailbox_get_pending_rejects_tampered_receipt_without_state_change() {
        let mut inbox = LocalInbox::new();
        let mut quota = QuotaLedger::new();
        quota.set_limit(QuotaBucket::Mailbox, QuotaLimit::new(1024, 4));
        inbox
            .offer(offer("in-1", "/data/inbox/project", 128))
            .unwrap(); // ubs:ignore - test oracle
        inbox.allow(ReceiveGrant::new(
            "grant-1",
            "peer-a",
            receive_actions(),
            GrantScope::PathPrefix(PathBuf::from("/data/inbox")),
        ));
        inbox
            .store_mailbox(
                "in-1",
                "grant-1",
                mailbox_store_request("mailbox-1", 128),
                &mut quota,
                11,
            )
            .unwrap(); // ubs:ignore - test oracle
        let mut receipt = stored_mailbox_receipt(128);
        receipt.stored_object_digest = digest(9);

        let err = inbox
            .start_mailbox_retrieval("mailbox-1", &receipt, None, 13)
            .unwrap_err(); // ubs:ignore - test oracle

        assert_eq!(
            err,
            InboxError::MailboxSecurity(MailboxSecurityError::DigestMismatch {
                field: "stored_object_digest"
            })
        );
        let item = inbox.list()[0]; // ubs:ignore - test oracle
        assert_eq!(item.state, InboxState::MailboxStored);
        assert_eq!(item.bytes_received, 0);
        assert_eq!(item.updated_epoch_secs, 11);
    }

    #[test]
    fn mailbox_store_rejects_plain_private_storage_before_quota_mutation() {
        let mut inbox = LocalInbox::new();
        let mut quota = QuotaLedger::new();
        quota.set_limit(QuotaBucket::Mailbox, QuotaLimit::new(1024, 4));
        inbox
            .offer(offer("in-1", "/data/inbox/project", 128))
            .unwrap(); // ubs:ignore - test oracle
        inbox.allow(ReceiveGrant::new(
            "grant-1",
            "peer-a",
            receive_actions(),
            GrantScope::PathPrefix(PathBuf::from("/data/inbox")),
        ));
        let mut request = mailbox_store_request("mailbox-1", 128);
        request.privacy_policy.encrypted_at_rest = false;

        let err = inbox
            .store_mailbox("in-1", "grant-1", request, &mut quota, 11)
            .unwrap_err(); // ubs:ignore - test oracle

        assert_eq!(
            err,
            InboxError::MailboxSecurity(MailboxSecurityError::MissingEncryption)
        );
        assert_eq!(inbox.list()[0].state, InboxState::Offered); // ubs:ignore - test oracle
        assert_eq!(quota.usage(QuotaBucket::Mailbox), QuotaUsage::default());
        assert!(inbox.mailbox_records().is_empty());
    }

    #[test]
    fn mailbox_store_rejects_quota_exhaustion_before_state_transition() {
        let mut inbox = LocalInbox::new();
        let mut quota = QuotaLedger::new();
        quota.set_limit(QuotaBucket::Mailbox, QuotaLimit::new(64, 1));
        inbox
            .offer(offer("in-1", "/data/inbox/project", 128))
            .unwrap(); // ubs:ignore - test oracle
        inbox.allow(ReceiveGrant::new(
            "grant-1",
            "peer-a",
            receive_actions(),
            GrantScope::PathPrefix(PathBuf::from("/data/inbox")),
        ));

        let err = inbox
            .store_mailbox(
                "in-1",
                "grant-1",
                mailbox_store_request("mailbox-1", 128),
                &mut quota,
                11,
            )
            .unwrap_err(); // ubs:ignore - test oracle

        assert!(matches!(
            err,
            InboxError::Quota(QuotaError::Exhausted {
                bucket: QuotaBucket::Mailbox,
                ..
            })
        ));
        assert_eq!(inbox.list()[0].state, InboxState::Offered); // ubs:ignore - test oracle
        assert_eq!(quota.usage(QuotaBucket::Mailbox), QuotaUsage::default());
    }

    #[test]
    fn unattended_receive_requires_matching_grant() {
        let mut inbox = LocalInbox::new();
        inbox
            .offer(offer("in-1", "/data/inbox/project", 128))
            .unwrap(); // ubs:ignore - test oracle
        inbox.allow(
            ReceiveGrant::new(
                "grant-1",
                "peer-a",
                receive_actions(),
                GrantScope::PathPrefix(PathBuf::from("/data/inbox")),
            )
            .with_quota(GrantQuota {
                max_bytes: Some(512),
                max_items: Some(1),
            }),
        );

        inbox.start_receive("in-1", "grant-1", 11).unwrap(); // ubs:ignore - test oracle
        inbox.record_progress("in-1", 128, 12).unwrap(); // ubs:ignore - test oracle

        let item = inbox.list()[0]; // ubs:ignore - test oracle
        assert_eq!(item.state, InboxState::Completed);
        assert_eq!(item.grant_id.as_deref(), Some("grant-1"));
    }

    #[test]
    fn policy_enforcement_rejects_unauthorized_path() {
        let mut inbox = LocalInbox::new();
        inbox.offer(offer("in-1", "/tmp/outside", 64)).unwrap(); // ubs:ignore - test oracle
        inbox.allow(ReceiveGrant::new(
            "grant-1",
            "peer-a",
            receive_actions(),
            GrantScope::PathPrefix(PathBuf::from("/data/inbox")),
        ));

        let err = inbox.start_receive("in-1", "grant-1", 11).unwrap_err();
        assert_eq!(
            err,
            InboxError::Unauthorized {
                grant_id: "grant-1".to_string(),
                action: AllowAction::Receive,
            }
        );
    }

    #[test]
    fn cache_verified_records_manifest_root_and_authorizing_grant() {
        let mut inbox = LocalInbox::new();
        inbox
            .offer(offer("in-1", "/data/inbox/project", 128))
            .unwrap(); // ubs:ignore - test oracle
        inbox.allow(ReceiveGrant::new(
            "receive-grant",
            "peer-a",
            receive_actions(),
            GrantScope::PathPrefix(PathBuf::from("/data/inbox")),
        ));
        inbox.allow(ReceiveGrant::new(
            "cache-grant",
            "peer-a",
            cache_actions(),
            GrantScope::ObjectGraph(digest(7)),
        ));
        inbox.start_receive("in-1", "receive-grant", 11).unwrap(); // ubs:ignore - test oracle

        inbox
            .cache_verified("in-1", "cache-grant", "artifact", 128, 12)
            .unwrap(); // ubs:ignore - test oracle

        let item = inbox.list()[0]; // ubs:ignore - test oracle
        assert_eq!(item.state, InboxState::Cached);
        assert_eq!(item.grant_id.as_deref(), Some("cache-grant"));

        let record = inbox.cache_records()[0]; // ubs:ignore - test oracle
        assert_eq!(record.item_id, "in-1");
        assert_eq!(record.object_root, digest(7));
        assert_eq!(record.manifest_epoch, 3);
        assert_eq!(record.object_type, "artifact");
        assert_eq!(record.bytes, 128);
        assert_eq!(record.cache_grant_id, "cache-grant");
        assert_eq!(record.seed_grant_id, None);
        assert_eq!(record.cached_at_epoch_secs, 12);
    }

    #[test]
    fn cache_verified_rejects_expired_or_mismatched_grants_without_state_change() {
        let mut inbox = LocalInbox::new();
        inbox
            .offer(offer("in-1", "/data/inbox/project", 128))
            .unwrap(); // ubs:ignore - test oracle
        inbox.allow(ReceiveGrant::new(
            "receive-grant",
            "peer-a",
            receive_actions(),
            GrantScope::PathPrefix(PathBuf::from("/data/inbox")),
        ));
        inbox.allow(
            ReceiveGrant::new(
                "expired-cache-grant",
                "peer-a",
                cache_actions(),
                GrantScope::Cache {
                    object_types: std::iter::once("artifact".to_string()).collect(),
                    max_bytes: Some(512),
                },
            )
            .with_expiry(11),
        );
        inbox.start_receive("in-1", "receive-grant", 10).unwrap(); // ubs:ignore - test oracle

        let err = inbox
            .cache_verified("in-1", "expired-cache-grant", "artifact", 128, 12)
            .unwrap_err(); // ubs:ignore - test oracle

        assert_eq!(
            err,
            InboxError::Unauthorized {
                grant_id: "expired-cache-grant".to_string(),
                action: AllowAction::Cache,
            }
        );
        let item = inbox.list()[0]; // ubs:ignore - test oracle
        assert_eq!(item.state, InboxState::Active);
        assert_eq!(item.grant_id.as_deref(), Some("receive-grant"));
        assert!(inbox.cache_records().is_empty());
    }

    #[test]
    fn seed_cached_requires_active_seed_grant() {
        let mut inbox = LocalInbox::new();
        inbox
            .offer(offer("in-1", "/data/inbox/project", 128))
            .unwrap(); // ubs:ignore - test oracle
        inbox.allow(ReceiveGrant::new(
            "receive-grant",
            "peer-a",
            receive_actions(),
            GrantScope::PathPrefix(PathBuf::from("/data/inbox")),
        ));
        inbox.allow(ReceiveGrant::new(
            "cache-grant",
            "peer-a",
            cache_actions(),
            GrantScope::ObjectGraph(digest(7)),
        ));
        inbox.allow(
            ReceiveGrant::new(
                "expired-seed-grant",
                "peer-a",
                seed_actions(),
                GrantScope::ObjectGraph(digest(7)),
            )
            .with_expiry(12),
        );
        inbox.allow(ReceiveGrant::new(
            "seed-grant",
            "peer-a",
            seed_actions(),
            GrantScope::ObjectGraph(digest(7)),
        ));
        inbox.start_receive("in-1", "receive-grant", 10).unwrap(); // ubs:ignore - test oracle
        inbox
            .cache_verified("in-1", "cache-grant", "artifact", 128, 11)
            .unwrap(); // ubs:ignore - test oracle

        let err = inbox.seed_cached("in-1", "cache-grant", 13).unwrap_err(); // ubs:ignore - test oracle
        assert_eq!(
            err,
            InboxError::Unauthorized {
                grant_id: "cache-grant".to_string(),
                action: AllowAction::Seed,
            }
        );
        let err = inbox
            .seed_cached("in-1", "expired-seed-grant", 13)
            .unwrap_err(); // ubs:ignore - test oracle
        assert_eq!(
            err,
            InboxError::Unauthorized {
                grant_id: "expired-seed-grant".to_string(),
                action: AllowAction::Seed,
            }
        );

        inbox.seed_cached("in-1", "seed-grant", 14).unwrap(); // ubs:ignore - test oracle

        let item = inbox.list()[0]; // ubs:ignore - test oracle
        assert_eq!(item.state, InboxState::Seeded);
        assert_eq!(item.grant_id.as_deref(), Some("seed-grant"));
        let record = inbox.cache_records()[0]; // ubs:ignore - test oracle
        assert_eq!(record.cache_grant_id, "cache-grant");
        assert_eq!(record.seed_grant_id.as_deref(), Some("seed-grant"));
        assert_eq!(record.seeded_at_epoch_secs, Some(14));
    }

    #[test]
    fn state_transitions_cover_mailbox_cache_seed_and_cancel() {
        let mut inbox = LocalInbox::new();
        inbox
            .offer(offer("in-1", "/data/inbox/project", 64))
            .unwrap(); // ubs:ignore - test oracle

        inbox
            .transition("in-1", InboxState::MailboxStored, 11)
            .unwrap(); // ubs:ignore - test oracle
        inbox.transition("in-1", InboxState::Cached, 12).unwrap(); // ubs:ignore - test oracle
        inbox.transition("in-1", InboxState::Seeded, 13).unwrap(); // ubs:ignore - test oracle
        inbox.transition("in-1", InboxState::Completed, 14).unwrap(); // ubs:ignore - test oracle

        let diagnostics = inbox.diagnostics();
        assert_eq!(diagnostics.completed_count, 1);
        assert_eq!(diagnostics.mailbox_stored_count, 0);
    }

    #[test]
    fn json_and_human_output_are_stable_and_redacted() {
        let mut inbox = LocalInbox::new();
        inbox.offer(offer("b", "/data/inbox/b", 2)).unwrap(); // ubs:ignore - test oracle
        inbox.offer(offer("a", "/data/inbox/a", 1)).unwrap(); // ubs:ignore - test oracle

        let human = inbox.human_rows();
        assert_eq!(human[0], "id state bytes source destination");
        assert!(human[1].starts_with("a offered 0/1 peer-abc..."));
        assert!(human[2].starts_with("b offered 0/2 peer-abc..."));

        let json = inbox.json_lines().unwrap(); // ubs:ignore - test oracle
        assert!(json[0].contains("\"item_id\":\"a\""));
        assert!(!json[0].contains("abcdefghijklmnopqrstuvwxyz"));
    }

    #[test]
    fn daemon_diagnostics_have_stable_rows() {
        let diagnostics = DaemonDiagnostics {
            active_transfers: 1,
            path_count: 2,
            repair_sessions: 3,
            disk_available_bytes: Some(4096),
            journal_entries: 4,
            grant_count: 5,
            cache_entries: 6,
            inbox_items: 7,
            platform: "linux-x86_64-secret".to_string(),
            service_lifecycle: "running".to_string(),
        };

        let rows = diagnostics.stable_human_lines();
        assert_eq!(rows[0], "lifecycle running");
        assert_eq!(rows[1], "platform linux-x8...");
        assert!(rows.contains(&"disk_available_bytes 4096".to_string()));
    }
}
