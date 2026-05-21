//! Local ATP inbox state, receive grants, and daemon diagnostics.

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
                let size_ok = max_bytes.map_or(true, |limit| bytes <= limit);
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
        let bytes_ok = self.max_bytes.map_or(true, |limit| bytes <= limit);
        let items_ok = self.max_items.map_or(true, |limit| items <= limit);
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
                .map_or(true, |expires_at| now_epoch_secs <= expires_at)
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
}

impl LocalInbox {
    /// Create an empty local inbox.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            grants: BTreeMap::new(),
            items: BTreeMap::new(),
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
    /// The item id already exists.
    DuplicateItem(String),
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
}

impl fmt::Display for InboxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownItem(item_id) => write!(f, "unknown inbox item `{item_id}`"),
            Self::UnknownGrant(grant_id) => write!(f, "unknown grant `{grant_id}`"),
            Self::DuplicateItem(item_id) => write!(f, "duplicate inbox item `{item_id}`"),
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

fn redact_token(token: &str) -> String {
    let visible: String = token.chars().take(8).collect();
    if token.chars().count() <= 8 {
        visible
    } else {
        format!("{visible}...")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: u8) -> ObjectDigest {
        ObjectDigest::new([byte; 32])
    }

    fn receive_actions() -> BTreeSet<AllowAction> {
        [AllowAction::Receive].into_iter().collect()
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
