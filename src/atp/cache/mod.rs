//! ATP local cache authorization, seeding, quota, and diagnostics.

use crate::atp::inbox::{AllowAction, GrantQuota, ObjectDigest};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Privacy class carried by a cached object graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyClass {
    /// Public content may be seeded by any matching seed grant.
    Public,
    /// Team-scoped content requires a grant that covers team content.
    Team,
    /// Private content requires an explicit private-seeding grant.
    Private,
}

impl PrivacyClass {
    /// Stable lowercase privacy name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Team => "team",
            Self::Private => "private",
        }
    }
}

/// Cache entry lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheEntryState {
    /// Entry is verified and resident.
    Verified,
    /// Entry has been seeded at least once and remains resident.
    Seeded,
    /// Entry was evicted to satisfy quota.
    Evicted,
    /// Entry failed verification and must not be served.
    Quarantined,
}

impl CacheEntryState {
    /// Stable lowercase state name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Seeded => "seeded",
            Self::Evicted => "evicted",
            Self::Quarantined => "quarantined",
        }
    }

    /// Return true when bytes should count against resident cache quota.
    #[must_use]
    pub const fn is_resident(self) -> bool {
        matches!(self, Self::Verified | Self::Seeded)
    }
}

impl fmt::Display for CacheEntryState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Verified object graph entry in the local cache.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheEntry {
    /// Root digest of the cached graph.
    pub object_root: ObjectDigest,
    /// Application object type used by policy scopes.
    pub object_type: String,
    /// Manifest generation verified for this graph.
    pub manifest_epoch: u64,
    /// Resident bytes used by the graph.
    pub bytes: u64,
    /// Number of objects represented by the graph.
    pub object_count: u64,
    /// Privacy class enforced before seeding.
    pub privacy: PrivacyClass,
    /// Cache lifecycle state.
    pub state: CacheEntryState,
    /// Caller-supplied verification timestamp.
    pub last_verified_epoch_secs: u64,
    /// Number of successful seed operations.
    pub seed_count: u64,
}

impl CacheEntry {
    /// Create a verified resident cache entry.
    #[must_use]
    pub fn verified(
        object_root: ObjectDigest,
        object_type: impl Into<String>,
        manifest_epoch: u64,
        bytes: u64,
        object_count: u64,
        privacy: PrivacyClass,
        last_verified_epoch_secs: u64,
    ) -> Self {
        Self {
            object_root,
            object_type: object_type.into(),
            manifest_epoch,
            bytes,
            object_count,
            privacy,
            state: CacheEntryState::Verified,
            last_verified_epoch_secs,
            seed_count: 0,
        }
    }

    /// Return true when the entry is resident and seedable.
    #[must_use]
    pub const fn is_resident(&self) -> bool {
        self.state.is_resident()
    }
}

/// ATP cache or seed grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheGrant {
    /// Stable grant identifier.
    pub id: String,
    /// Peer, actor, or daemon principal that owns the grant.
    pub subject: String,
    /// Cache actions authorized by this grant.
    pub actions: BTreeSet<AllowAction>,
    /// Empty means every graph root is accepted.
    pub object_roots: BTreeSet<ObjectDigest>,
    /// Empty means every object type is accepted.
    pub object_types: BTreeSet<String>,
    /// Quota limits enforced before cache or seed work starts.
    pub quota: GrantQuota,
    /// Expiry as seconds since Unix epoch; callers supply the clock.
    pub expires_at_epoch_secs: Option<u64>,
    /// Revoked grants fail closed even if they are not expired.
    pub revoked: bool,
    /// Whether private graphs may be seeded.
    pub allow_private: bool,
}

impl CacheGrant {
    /// Create a non-expiring cache grant with no quota.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        subject: impl Into<String>,
        actions: BTreeSet<AllowAction>,
    ) -> Self {
        Self {
            id: id.into(),
            subject: subject.into(),
            actions,
            object_roots: BTreeSet::new(),
            object_types: BTreeSet::new(),
            quota: GrantQuota::default(),
            expires_at_epoch_secs: None,
            revoked: false,
            allow_private: false,
        }
    }

    /// Restrict this grant to one graph root.
    #[must_use]
    pub fn with_object_root(mut self, object_root: ObjectDigest) -> Self {
        self.object_roots.insert(object_root);
        self
    }

    /// Restrict this grant to one object type.
    #[must_use]
    pub fn with_object_type(mut self, object_type: impl Into<String>) -> Self {
        self.object_types.insert(object_type.into());
        self
    }

    /// Attach a quota to the grant.
    #[must_use]
    pub const fn with_quota(mut self, quota: GrantQuota) -> Self {
        self.quota = quota;
        self
    }

    /// Allow seeding private graphs.
    #[must_use]
    pub const fn allow_private(mut self) -> Self {
        self.allow_private = true;
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

    fn allows_entry(
        &self,
        action: AllowAction,
        entry: &CacheEntry,
        now_epoch_secs: u64,
    ) -> Result<(), CacheError> {
        if !self.is_active(now_epoch_secs)
            || !self.actions.contains(&action)
            || !(self.object_roots.is_empty() || self.object_roots.contains(&entry.object_root))
            || !(self.object_types.is_empty() || self.object_types.contains(&entry.object_type))
        {
            return Err(CacheError::Unauthorized {
                grant_id: self.id.clone(),
                action,
            });
        }

        if !self.quota.permits(entry.bytes, entry.object_count) {
            return Err(CacheError::OverQuota {
                requested_bytes: entry.bytes,
                max_bytes: self.quota.max_bytes,
            });
        }

        if entry.privacy == PrivacyClass::Private && !self.allow_private {
            return Err(CacheError::PrivacyViolation {
                object_root: entry.object_root.redacted(),
            });
        }

        Ok(())
    }
}

/// Cache seed request from the daemon or SDK.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheSeedRequest {
    /// Grant used to authorize seeding.
    pub grant_id: String,
    /// Graph root requested by the peer.
    pub object_root: ObjectDigest,
    /// Manifest epoch expected by the requester.
    pub manifest_epoch: u64,
    /// Caller-supplied timestamp in seconds since Unix epoch.
    pub now_epoch_secs: u64,
}

/// Receipt for a successful seed operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeedReceipt {
    /// Redacted graph root.
    pub object_root: String,
    /// Manifest epoch served.
    pub manifest_epoch: u64,
    /// Resident bytes served.
    pub bytes: u64,
    /// Object type served.
    pub object_type: String,
    /// Grant that authorized the seed.
    pub grant_id: String,
}

/// Cache mutation summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheMutation {
    /// Redacted graph root inserted or updated.
    pub object_root: String,
    /// Resident bytes after the mutation.
    pub used_bytes: u64,
    /// Redacted roots evicted to satisfy quota.
    pub evicted_roots: Vec<String>,
}

/// Aggregated local cache diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheDiagnostics {
    /// Resident cache bytes.
    pub used_bytes: u64,
    /// Maximum resident cache bytes.
    pub max_bytes: u64,
    /// Number of known entries, including evicted history.
    pub entry_count: usize,
    /// Resident verified entries.
    pub verified_count: usize,
    /// Resident seeded entries.
    pub seeded_count: usize,
    /// Evicted entry count.
    pub evicted_count: usize,
    /// Quarantined entry count.
    pub quarantined_count: usize,
    /// Grant count known to the cache.
    pub grant_count: usize,
}

/// Local ATP object graph cache.
#[derive(Debug, Clone)]
pub struct ObjectCache {
    max_bytes: u64,
    used_bytes: u64,
    grants: BTreeMap<String, CacheGrant>,
    entries: BTreeMap<ObjectDigest, CacheEntry>,
}

impl ObjectCache {
    /// Create an empty cache with a hard resident byte quota.
    #[must_use]
    pub const fn new(max_bytes: u64) -> Self {
        Self {
            max_bytes,
            used_bytes: 0,
            grants: BTreeMap::new(),
            entries: BTreeMap::new(),
        }
    }

    /// Store or replace a cache grant.
    pub fn allow(&mut self, grant: CacheGrant) {
        self.grants.insert(grant.id.clone(), grant);
    }

    /// Revoke a cache grant by id.
    pub fn revoke(&mut self, grant_id: &str) -> Result<(), CacheError> {
        let grant = self
            .grants
            .get_mut(grant_id)
            .ok_or_else(|| CacheError::UnknownGrant(grant_id.to_string()))?;
        grant.revoke();
        Ok(())
    }

    /// Insert a verified graph after checking a cache grant.
    pub fn cache_authorized(
        &mut self,
        grant_id: &str,
        entry: CacheEntry,
        now_epoch_secs: u64,
    ) -> Result<CacheMutation, CacheError> {
        let grant = self
            .grants
            .get(grant_id)
            .ok_or_else(|| CacheError::UnknownGrant(grant_id.to_string()))?;
        grant.allows_entry(AllowAction::Cache, &entry, now_epoch_secs)?;
        self.insert_verified(entry)
    }

    /// Insert a verified graph, evicting older resident entries if needed.
    pub fn insert_verified(&mut self, entry: CacheEntry) -> Result<CacheMutation, CacheError> {
        if entry.bytes > self.max_bytes {
            return Err(CacheError::OverQuota {
                requested_bytes: entry.bytes,
                max_bytes: Some(self.max_bytes),
            });
        }

        let old_bytes = self
            .entries
            .get(&entry.object_root)
            .filter(|old| old.is_resident())
            .map_or(0, |old| old.bytes);
        let used_without_old = self.used_bytes.saturating_sub(old_bytes);

        let mut evicted_roots = Vec::new();
        self.used_bytes = used_without_old;
        while self
            .used_bytes
            .checked_add(entry.bytes)
            .ok_or(CacheError::OverQuota {
                requested_bytes: entry.bytes,
                max_bytes: Some(self.max_bytes),
            })?
            > self.max_bytes
        {
            let Some(root) = self.eviction_candidate(&entry.object_root) else {
                return Err(CacheError::OverQuota {
                    requested_bytes: entry.bytes,
                    max_bytes: Some(self.max_bytes),
                });
            };
            let redacted = root.redacted();
            self.evict_resident(&root)?;
            evicted_roots.push(redacted);
        }

        self.used_bytes =
            self.used_bytes
                .checked_add(entry.bytes)
                .ok_or(CacheError::OverQuota {
                    requested_bytes: entry.bytes,
                    max_bytes: Some(self.max_bytes),
                })?;
        let redacted_root = entry.object_root.redacted();
        self.entries.insert(entry.object_root.clone(), entry);
        Ok(CacheMutation {
            object_root: redacted_root,
            used_bytes: self.used_bytes,
            evicted_roots,
        })
    }

    /// Seed a resident graph after grant, manifest, quota, and privacy checks.
    pub fn seed(&mut self, request: CacheSeedRequest) -> Result<SeedReceipt, CacheError> {
        let entry = self
            .entries
            .get(&request.object_root)
            .ok_or_else(|| CacheError::MissingObject(request.object_root.redacted()))?;
        if !entry.is_resident() {
            return Err(CacheError::MissingObject(request.object_root.redacted()));
        }
        if entry.manifest_epoch != request.manifest_epoch {
            return Err(CacheError::StaleManifest {
                object_root: request.object_root.redacted(),
                requested_epoch: request.manifest_epoch,
                cached_epoch: entry.manifest_epoch,
            });
        }

        let grant = self
            .grants
            .get(&request.grant_id)
            .ok_or_else(|| CacheError::UnknownGrant(request.grant_id.clone()))?;
        grant.allows_entry(AllowAction::Seed, entry, request.now_epoch_secs)?;

        let entry = self
            .entries
            .get_mut(&request.object_root)
            .ok_or_else(|| CacheError::MissingObject(request.object_root.redacted()))?;
        entry.state = CacheEntryState::Seeded;
        entry.seed_count = entry.seed_count.saturating_add(1);
        Ok(SeedReceipt {
            object_root: entry.object_root.redacted(),
            manifest_epoch: entry.manifest_epoch,
            bytes: entry.bytes,
            object_type: entry.object_type.clone(),
            grant_id: request.grant_id,
        })
    }

    /// Return an entry by graph root.
    #[must_use]
    pub fn entry(&self, object_root: &ObjectDigest) -> Option<&CacheEntry> {
        self.entries.get(object_root)
    }

    /// Return resident cache bytes.
    #[must_use]
    pub const fn used_bytes(&self) -> u64 {
        self.used_bytes
    }

    /// Return aggregate cache diagnostics.
    #[must_use]
    pub fn diagnostics(&self) -> CacheDiagnostics {
        let mut verified_count = 0;
        let mut seeded_count = 0;
        let mut evicted_count = 0;
        let mut quarantined_count = 0;
        for entry in self.entries.values() {
            match entry.state {
                CacheEntryState::Verified => verified_count += 1,
                CacheEntryState::Seeded => seeded_count += 1,
                CacheEntryState::Evicted => evicted_count += 1,
                CacheEntryState::Quarantined => quarantined_count += 1,
            }
        }
        CacheDiagnostics {
            used_bytes: self.used_bytes,
            max_bytes: self.max_bytes,
            entry_count: self.entries.len(),
            verified_count,
            seeded_count,
            evicted_count,
            quarantined_count,
            grant_count: self.grants.len(),
        }
    }

    fn eviction_candidate(&self, protected_root: &ObjectDigest) -> Option<ObjectDigest> {
        self.entries
            .iter()
            .filter(|(root, entry)| *root != protected_root && entry.is_resident())
            .min_by(|(left_root, left), (right_root, right)| {
                left.last_verified_epoch_secs
                    .cmp(&right.last_verified_epoch_secs)
                    .then_with(|| left_root.cmp(right_root))
            })
            .map(|(root, _)| root.clone())
    }

    fn evict_resident(&mut self, object_root: &ObjectDigest) -> Result<(), CacheError> {
        let entry = self
            .entries
            .get_mut(object_root)
            .ok_or_else(|| CacheError::MissingObject(object_root.redacted()))?;
        if entry.is_resident() {
            self.used_bytes = self.used_bytes.saturating_sub(entry.bytes);
            entry.bytes = 0;
            entry.state = CacheEntryState::Evicted;
        }
        Ok(())
    }
}

/// Cache authorization, integrity, quota, and privacy error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheError {
    /// The grant id is unknown.
    UnknownGrant(String),
    /// The object graph is not resident in cache.
    MissingObject(String),
    /// The grant does not authorize the operation.
    Unauthorized {
        /// Grant that failed authorization.
        grant_id: String,
        /// Action that was requested.
        action: AllowAction,
    },
    /// Requested manifest does not match the verified cache entry.
    StaleManifest {
        /// Redacted graph root.
        object_root: String,
        /// Requested manifest epoch.
        requested_epoch: u64,
        /// Cached manifest epoch.
        cached_epoch: u64,
    },
    /// Cache or grant quota would be exceeded.
    OverQuota {
        /// Bytes requested by this operation.
        requested_bytes: u64,
        /// Maximum bytes allowed when known.
        max_bytes: Option<u64>,
    },
    /// Private graph seeding was requested without explicit permission.
    PrivacyViolation {
        /// Redacted graph root.
        object_root: String,
    },
}

impl fmt::Display for CacheError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownGrant(grant_id) => write!(f, "unknown cache grant `{grant_id}`"),
            Self::MissingObject(root) => write!(f, "cache object `{root}` is not resident"),
            Self::Unauthorized { grant_id, action } => {
                write!(
                    f,
                    "grant `{grant_id}` does not authorize {}",
                    action.as_str()
                )
            }
            Self::StaleManifest {
                object_root,
                requested_epoch,
                cached_epoch,
            } => write!(
                f,
                "stale manifest for `{object_root}`: requested {requested_epoch}, cached {cached_epoch}"
            ),
            Self::OverQuota {
                requested_bytes,
                max_bytes,
            } => write!(
                f,
                "cache quota exceeded for {requested_bytes} bytes with max {max_bytes:?}"
            ),
            Self::PrivacyViolation { object_root } => {
                write!(f, "privacy policy forbids seeding `{object_root}`")
            }
        }
    }
}

impl std::error::Error for CacheError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: u8) -> ObjectDigest {
        ObjectDigest::new([byte; 32])
    }

    fn cache_seed_actions() -> BTreeSet<AllowAction> {
        [AllowAction::Cache, AllowAction::Seed]
            .into_iter()
            .collect()
    }

    fn entry(byte: u8, bytes: u64, verified_at: u64) -> CacheEntry {
        CacheEntry::verified(
            digest(byte),
            "artifact",
            7,
            bytes,
            1,
            PrivacyClass::Public,
            verified_at,
        )
    }

    #[test]
    fn authorized_cache_and_seed_graph() {
        let root = digest(1);
        let mut cache = ObjectCache::new(1024);
        cache.allow(
            CacheGrant::new("grant-1", "peer-a", cache_seed_actions())
                .with_object_root(root.clone())
                .with_object_type("artifact")
                .with_quota(GrantQuota {
                    max_bytes: Some(1024),
                    max_items: Some(2),
                }),
        );

        cache
            .cache_authorized(
                "grant-1",
                CacheEntry::verified(
                    root.clone(),
                    "artifact",
                    7,
                    256,
                    2,
                    PrivacyClass::Public,
                    10,
                ),
                11,
            )
            .unwrap();
        let receipt = cache
            .seed(CacheSeedRequest {
                grant_id: "grant-1".to_string(),
                object_root: root,
                manifest_epoch: 7,
                now_epoch_secs: 12,
            })
            .unwrap();

        assert_eq!(receipt.bytes, 256);
        assert_eq!(cache.diagnostics().seeded_count, 1);
    }

    #[test]
    fn refuses_unauthorized_and_stale_seed_requests() {
        let root = digest(2);
        let mut cache = ObjectCache::new(1024);
        cache.insert_verified(entry(2, 128, 10)).unwrap();
        cache.allow(CacheGrant::new(
            "grant-1",
            "peer-a",
            [AllowAction::Seed].into_iter().collect(),
        ));

        let stale = cache
            .seed(CacheSeedRequest {
                grant_id: "grant-1".to_string(),
                object_root: root.clone(),
                manifest_epoch: 6,
                now_epoch_secs: 11,
            })
            .unwrap_err();
        assert!(matches!(stale, CacheError::StaleManifest { .. }));

        let missing_grant = cache
            .seed(CacheSeedRequest {
                grant_id: "missing".to_string(),
                object_root: root,
                manifest_epoch: 7,
                now_epoch_secs: 11,
            })
            .unwrap_err();
        assert_eq!(
            missing_grant,
            CacheError::UnknownGrant("missing".to_string())
        );
    }

    #[test]
    fn quota_eviction_is_deterministic() {
        let mut cache = ObjectCache::new(10);
        cache.insert_verified(entry(1, 6, 1)).unwrap();
        cache.insert_verified(entry(2, 6, 2)).unwrap();

        assert_eq!(cache.used_bytes(), 6);
        assert_eq!(
            cache.entry(&digest(1)).map(|entry| entry.state),
            Some(CacheEntryState::Evicted)
        );
        assert_eq!(
            cache.entry(&digest(2)).map(|entry| entry.state),
            Some(CacheEntryState::Verified)
        );
    }

    #[test]
    fn over_quota_and_private_seed_fail_closed() {
        let root = digest(3);
        let mut cache = ObjectCache::new(512);
        let too_large = CacheEntry::verified(
            root.clone(),
            "artifact",
            1,
            1024,
            1,
            PrivacyClass::Public,
            10,
        );
        assert!(matches!(
            cache.insert_verified(too_large).unwrap_err(),
            CacheError::OverQuota { .. }
        ));

        cache.allow(CacheGrant::new(
            "grant-1",
            "peer-a",
            [AllowAction::Seed].into_iter().collect(),
        ));
        cache
            .insert_verified(CacheEntry::verified(
                root.clone(),
                "artifact",
                1,
                128,
                1,
                PrivacyClass::Private,
                10,
            ))
            .unwrap();
        let err = cache
            .seed(CacheSeedRequest {
                grant_id: "grant-1".to_string(),
                object_root: root,
                manifest_epoch: 1,
                now_epoch_secs: 11,
            })
            .unwrap_err();
        assert!(matches!(err, CacheError::PrivacyViolation { .. }));
    }

    #[test]
    fn diagnostics_count_cache_states_and_grants() {
        let mut cache = ObjectCache::new(20);
        cache.allow(CacheGrant::new(
            "grant-1",
            "peer-a",
            [AllowAction::Cache].into_iter().collect(),
        ));
        cache.insert_verified(entry(1, 8, 1)).unwrap();
        cache.insert_verified(entry(2, 8, 2)).unwrap();
        cache.insert_verified(entry(3, 8, 3)).unwrap();

        let diagnostics = cache.diagnostics();
        assert_eq!(diagnostics.used_bytes, 16);
        assert_eq!(diagnostics.evicted_count, 1);
        assert_eq!(diagnostics.verified_count, 2);
        assert_eq!(diagnostics.grant_count, 1);
    }
}
