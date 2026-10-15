//! ATP daemon quota accounting and retention planning.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Resource bucket governed by the daemon quota ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuotaBucket {
    /// Verified cache entries and seeded object graph metadata.
    Cache,
    /// Offline mailbox offers and pending mailbox payload metadata.
    Mailbox,
    /// Structured trace records.
    Traces,
    /// Proof bundles and replay artifacts.
    ProofArtifacts,
    /// Local inbox entries and receive plans.
    Inbox,
    /// Quarantined receive data and failed validation payload metadata.
    Quarantine,
    /// Partial journals needed for resume after shutdown.
    PartialJournals,
    /// Diagnostic bundles and daemon status snapshots.
    Diagnostics,
    /// Durable daemon settings.
    Settings,
    /// Peer identities and key handles.
    Identities,
    /// Capability grants and consent records.
    Grants,
    /// Active and completed transfer state.
    Transfers,
}

impl QuotaBucket {
    /// Stable lowercase bucket name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cache => "cache",
            Self::Mailbox => "mailbox",
            Self::Traces => "traces",
            Self::ProofArtifacts => "proof_artifacts",
            Self::Inbox => "inbox",
            Self::Quarantine => "quarantine",
            Self::PartialJournals => "partial_journals",
            Self::Diagnostics => "diagnostics",
            Self::Settings => "settings",
            Self::Identities => "identities",
            Self::Grants => "grants",
            Self::Transfers => "transfers",
        }
    }
}

impl fmt::Display for QuotaBucket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Hard quota for one bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuotaLimit {
    /// Maximum resident bytes.
    pub max_bytes: u64,
    /// Maximum resident records.
    pub max_records: u64,
}

impl QuotaLimit {
    /// Build a hard quota.
    #[must_use]
    pub const fn new(max_bytes: u64, max_records: u64) -> Self {
        Self {
            max_bytes,
            max_records,
        }
    }
}

/// Current quota usage for one bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct QuotaUsage {
    /// Resident bytes.
    pub bytes: u64,
    /// Resident record count.
    pub records: u64,
}

impl QuotaUsage {
    /// Add usage with overflow checking.
    pub fn checked_add(self, allocation: QuotaAllocation) -> Result<Self, QuotaError> {
        let bytes =
            self.bytes
                .checked_add(allocation.bytes)
                .ok_or(QuotaError::CounterOverflow {
                    bucket: allocation.bucket,
                })?;
        let records =
            self.records
                .checked_add(allocation.records)
                .ok_or(QuotaError::CounterOverflow {
                    bucket: allocation.bucket,
                })?;
        Ok(Self { bytes, records })
    }

    /// Remove usage, saturating to zero so cleanup is idempotent.
    #[must_use]
    pub fn saturating_sub(self, allocation: QuotaAllocation) -> Self {
        Self {
            bytes: self.bytes.saturating_sub(allocation.bytes),
            records: self.records.saturating_sub(allocation.records),
        }
    }
}

/// Allocation charged to a quota bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuotaAllocation {
    /// Bucket to charge.
    pub bucket: QuotaBucket,
    /// Bytes charged.
    pub bytes: u64,
    /// Records charged.
    pub records: u64,
}

impl QuotaAllocation {
    /// Build a one-record allocation.
    #[must_use]
    pub const fn one_record(bucket: QuotaBucket, bytes: u64) -> Self {
        Self {
            bucket,
            bytes,
            records: 1,
        }
    }
}

/// Per-record retention clock data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionClock {
    /// Record creation time in seconds since Unix epoch.
    pub created_epoch_secs: u64,
    /// Last mutation time in seconds since Unix epoch.
    pub updated_epoch_secs: u64,
    /// Explicit expiry time in seconds since Unix epoch.
    pub expires_epoch_secs: Option<u64>,
}

impl RetentionClock {
    /// Build a clock with no explicit expiry.
    #[must_use]
    pub const fn new(created_epoch_secs: u64, updated_epoch_secs: u64) -> Self {
        Self {
            created_epoch_secs,
            updated_epoch_secs,
            expires_epoch_secs: None,
        }
    }

    /// Attach an explicit expiry.
    #[must_use]
    pub const fn with_expiry(mut self, expires_epoch_secs: u64) -> Self {
        self.expires_epoch_secs = Some(expires_epoch_secs);
        self
    }
}

/// Retention rule for one bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionRule {
    /// Keep records for at most this many seconds after last update.
    pub max_age_secs: Option<u64>,
    /// Keep at most this many newest records.
    pub max_records: Option<u64>,
    /// Expire explicit `expires_epoch_secs` values when reached.
    pub honor_explicit_expiry: bool,
}

impl RetentionRule {
    /// Keep records indefinitely unless explicit expiry is set.
    #[must_use]
    pub const fn indefinite() -> Self {
        Self {
            max_age_secs: None,
            max_records: None,
            honor_explicit_expiry: true,
        }
    }

    /// Keep records for a bounded age.
    #[must_use]
    pub const fn max_age(max_age_secs: u64) -> Self {
        Self {
            max_age_secs: Some(max_age_secs),
            max_records: None,
            honor_explicit_expiry: true,
        }
    }

    /// Return true when this rule expires a record at `now_epoch_secs`.
    #[must_use]
    pub fn expires(self, clock: RetentionClock, now_epoch_secs: u64) -> bool {
        if self.honor_explicit_expiry
            && clock
                .expires_epoch_secs
                .is_some_and(|expires| now_epoch_secs >= expires)
        {
            return true;
        }
        self.max_age_secs.is_some_and(|max_age| {
            now_epoch_secs.saturating_sub(clock.updated_epoch_secs) > max_age
        })
    }
}

/// Retention policy keyed by bucket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionPolicy {
    rules: BTreeMap<QuotaBucket, RetentionRule>,
}

impl RetentionPolicy {
    /// Build the daemon default retention policy.
    #[must_use]
    pub fn daemon_defaults() -> Self {
        let mut rules = BTreeMap::new();
        rules.insert(QuotaBucket::Cache, RetentionRule::indefinite());
        rules.insert(
            QuotaBucket::Mailbox,
            RetentionRule::max_age(30 * 24 * 60 * 60),
        );
        rules.insert(
            QuotaBucket::Traces,
            RetentionRule::max_age(7 * 24 * 60 * 60),
        );
        rules.insert(
            QuotaBucket::ProofArtifacts,
            RetentionRule::max_age(30 * 24 * 60 * 60),
        );
        rules.insert(
            QuotaBucket::Inbox,
            RetentionRule::max_age(30 * 24 * 60 * 60),
        );
        rules.insert(
            QuotaBucket::Quarantine,
            RetentionRule::max_age(24 * 60 * 60),
        );
        rules.insert(
            QuotaBucket::PartialJournals,
            RetentionRule::max_age(7 * 24 * 60 * 60),
        );
        rules.insert(
            QuotaBucket::Diagnostics,
            RetentionRule::max_age(24 * 60 * 60),
        );
        rules.insert(QuotaBucket::Settings, RetentionRule::indefinite());
        rules.insert(QuotaBucket::Identities, RetentionRule::indefinite());
        rules.insert(QuotaBucket::Grants, RetentionRule::indefinite());
        rules.insert(
            QuotaBucket::Transfers,
            RetentionRule::max_age(30 * 24 * 60 * 60),
        );
        Self { rules }
    }

    /// Override one bucket rule.
    pub fn set_rule(&mut self, bucket: QuotaBucket, rule: RetentionRule) {
        self.rules.insert(bucket, rule);
    }

    /// Return the rule for a bucket.
    #[must_use]
    pub fn rule(&self, bucket: QuotaBucket) -> RetentionRule {
        self.rules
            .get(&bucket)
            .copied()
            .unwrap_or_else(RetentionRule::indefinite)
    }

    /// Select expired records in deterministic record-id order.
    #[must_use]
    pub fn expired_records(&self, records: &[RetentionRecord], now_epoch_secs: u64) -> Vec<String> {
        let mut expired = BTreeSet::new();
        for record in records {
            if self
                .rule(record.bucket)
                .expires(record.clock, now_epoch_secs)
            {
                expired.insert(record.record_id.clone());
            }
        }

        for (bucket, rule) in &self.rules {
            let Some(max_records) = rule.max_records else {
                continue;
            };
            let keep = usize::try_from(max_records).unwrap_or(usize::MAX);
            let mut bucket_records: Vec<_> = records
                .iter()
                .filter(|record| {
                    record.bucket == *bucket && !expired.contains(record.record_id.as_str())
                })
                .collect();
            bucket_records.sort_by(|left, right| {
                right
                    .clock
                    .updated_epoch_secs
                    .cmp(&left.clock.updated_epoch_secs)
                    .then_with(|| left.record_id.cmp(&right.record_id))
            });
            for record in bucket_records.into_iter().skip(keep) {
                expired.insert(record.record_id.clone());
            }
        }

        expired.into_iter().collect()
    }
}

/// Retention metadata for one persistent state record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionRecord {
    /// Stable record id.
    pub record_id: String,
    /// Bucket that owns the record.
    pub bucket: QuotaBucket,
    /// Record clock metadata.
    pub clock: RetentionClock,
}

/// In-memory quota ledger for deterministic daemon state accounting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuotaLedger {
    limits: BTreeMap<QuotaBucket, QuotaLimit>,
    usage: BTreeMap<QuotaBucket, QuotaUsage>,
    allocations: BTreeMap<String, QuotaAllocation>,
}

impl QuotaLedger {
    /// Build a ledger with daemon defaults.
    #[must_use]
    pub fn daemon_defaults() -> Self {
        let mut ledger = Self::new();
        ledger.set_limit(
            QuotaBucket::Cache,
            QuotaLimit::new(4 * 1024 * 1024 * 1024, 500_000),
        );
        ledger.set_limit(
            QuotaBucket::Mailbox,
            QuotaLimit::new(512 * 1024 * 1024, 100_000),
        );
        ledger.set_limit(
            QuotaBucket::Traces,
            QuotaLimit::new(256 * 1024 * 1024, 250_000),
        );
        ledger.set_limit(
            QuotaBucket::ProofArtifacts,
            QuotaLimit::new(512 * 1024 * 1024, 100_000),
        );
        ledger.set_limit(
            QuotaBucket::Inbox,
            QuotaLimit::new(256 * 1024 * 1024, 100_000),
        );
        ledger.set_limit(
            QuotaBucket::Quarantine,
            QuotaLimit::new(512 * 1024 * 1024, 50_000),
        );
        ledger.set_limit(
            QuotaBucket::PartialJournals,
            QuotaLimit::new(1024 * 1024 * 1024, 250_000),
        );
        ledger.set_limit(
            QuotaBucket::Diagnostics,
            QuotaLimit::new(128 * 1024 * 1024, 50_000),
        );
        ledger.set_limit(
            QuotaBucket::Settings,
            QuotaLimit::new(16 * 1024 * 1024, 10_000),
        );
        ledger.set_limit(
            QuotaBucket::Identities,
            QuotaLimit::new(64 * 1024 * 1024, 100_000),
        );
        ledger.set_limit(
            QuotaBucket::Grants,
            QuotaLimit::new(64 * 1024 * 1024, 250_000),
        );
        ledger.set_limit(
            QuotaBucket::Transfers,
            QuotaLimit::new(512 * 1024 * 1024, 250_000),
        );
        ledger
    }

    /// Build an empty ledger with no configured limits.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            limits: BTreeMap::new(),
            usage: BTreeMap::new(),
            allocations: BTreeMap::new(),
        }
    }

    /// Set or replace one bucket limit.
    pub fn set_limit(&mut self, bucket: QuotaBucket, limit: QuotaLimit) {
        self.limits.insert(bucket, limit);
    }

    /// Return a bucket limit.
    #[must_use]
    pub fn limit(&self, bucket: QuotaBucket) -> Option<QuotaLimit> {
        self.limits.get(&bucket).copied()
    }

    /// Return current usage for a bucket.
    #[must_use]
    pub fn usage(&self, bucket: QuotaBucket) -> QuotaUsage {
        self.usage.get(&bucket).copied().unwrap_or_default()
    }

    /// Reserve an allocation for a stable record id.
    pub fn reserve(
        &mut self,
        record_id: impl Into<String>,
        allocation: QuotaAllocation,
    ) -> Result<(), QuotaError> {
        let record_id = record_id.into();
        if self.allocations.contains_key(&record_id) {
            return Err(QuotaError::DuplicateAllocation(record_id));
        }

        let next = self.usage(allocation.bucket).checked_add(allocation)?;
        if let Some(limit) = self.limit(allocation.bucket) {
            if next.bytes > limit.max_bytes || next.records > limit.max_records {
                return Err(QuotaError::Exhausted {
                    bucket: allocation.bucket,
                    requested: allocation,
                    current: self.usage(allocation.bucket),
                    limit,
                });
            }
        }

        self.usage.insert(allocation.bucket, next);
        self.allocations.insert(record_id, allocation);
        Ok(())
    }

    /// Release an allocation by record id.
    pub fn release(&mut self, record_id: &str) -> Result<QuotaAllocation, QuotaError> {
        let allocation = self
            .allocations
            .remove(record_id)
            .ok_or_else(|| QuotaError::UnknownAllocation(record_id.to_string()))?;
        let current = self.usage(allocation.bucket);
        self.usage
            .insert(allocation.bucket, current.saturating_sub(allocation));
        Ok(allocation)
    }

    /// Return deterministic ledger rows.
    #[must_use]
    pub fn rows(&self) -> Vec<QuotaRow> {
        self.limits
            .iter()
            .map(|(bucket, limit)| QuotaRow {
                bucket: *bucket,
                limit: *limit,
                usage: self.usage(*bucket),
            })
            .collect()
    }

    /// Return configured limits in deterministic bucket order.
    #[must_use]
    pub fn limits(&self) -> Vec<(QuotaBucket, QuotaLimit)> {
        self.limits
            .iter()
            .map(|(bucket, limit)| (*bucket, *limit))
            .collect()
    }

    /// Return the number of tracked record allocations.
    #[must_use]
    pub fn allocation_count(&self) -> usize {
        self.allocations.len()
    }
}

impl Default for QuotaLedger {
    fn default() -> Self {
        Self::new()
    }
}

/// Stable quota diagnostic row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuotaRow {
    /// Bucket name.
    pub bucket: QuotaBucket,
    /// Configured limit.
    pub limit: QuotaLimit,
    /// Current usage.
    pub usage: QuotaUsage,
}

/// Quota accounting error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuotaError {
    /// The record id already has an allocation.
    DuplicateAllocation(String),
    /// The record id has no allocation.
    UnknownAllocation(String),
    /// An accounting counter overflowed.
    CounterOverflow {
        /// Bucket whose counter overflowed.
        bucket: QuotaBucket,
    },
    /// Bucket quota would be exceeded.
    Exhausted {
        /// Bucket that refused the allocation.
        bucket: QuotaBucket,
        /// Requested allocation.
        requested: QuotaAllocation,
        /// Current usage before the allocation.
        current: QuotaUsage,
        /// Configured limit.
        limit: QuotaLimit,
    },
}

impl fmt::Display for QuotaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateAllocation(record_id) => {
                write!(f, "quota allocation already exists for `{record_id}`")
            }
            Self::UnknownAllocation(record_id) => {
                write!(f, "quota allocation `{record_id}` is unknown")
            }
            Self::CounterOverflow { bucket } => {
                write!(f, "quota counter overflow in bucket `{bucket}`")
            }
            Self::Exhausted {
                bucket,
                requested,
                current,
                limit,
            } => write!(
                f,
                "quota exhausted for `{bucket}`: requested {} bytes/{} records, current {} bytes/{} records, limit {} bytes/{} records",
                requested.bytes,
                requested.records,
                current.bytes,
                current.records,
                limit.max_bytes,
                limit.max_records
            ),
        }
    }
}

impl std::error::Error for QuotaError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quota_reserve_and_release_are_accounted() {
        let mut ledger = QuotaLedger::new();
        ledger.set_limit(QuotaBucket::Cache, QuotaLimit::new(100, 2));

        ledger
            .reserve(
                "cache-a",
                QuotaAllocation::one_record(QuotaBucket::Cache, 40),
            )
            .unwrap(); // ubs:ignore - test oracle
        ledger
            .reserve(
                "cache-b",
                QuotaAllocation::one_record(QuotaBucket::Cache, 50),
            )
            .unwrap(); // ubs:ignore - test oracle

        assert_eq!(
            ledger.usage(QuotaBucket::Cache),
            QuotaUsage {
                bytes: 90,
                records: 2
            }
        );
        assert_eq!(
            ledger.release("cache-a").unwrap(),
            QuotaAllocation::one_record(QuotaBucket::Cache, 40)
        );
        assert_eq!(
            ledger.usage(QuotaBucket::Cache),
            QuotaUsage {
                bytes: 50,
                records: 1
            }
        );
    }

    #[test]
    fn quota_exhaustion_fails_before_mutating_usage() {
        let mut ledger = QuotaLedger::new();
        ledger.set_limit(QuotaBucket::Mailbox, QuotaLimit::new(10, 1));
        ledger
            .reserve(
                "mail-a",
                QuotaAllocation::one_record(QuotaBucket::Mailbox, 8),
            )
            .unwrap(); // ubs:ignore - test oracle

        let err = ledger
            .reserve(
                "mail-b",
                QuotaAllocation::one_record(QuotaBucket::Mailbox, 1),
            )
            .unwrap_err(); // ubs:ignore - test oracle

        assert!(matches!(
            err,
            QuotaError::Exhausted {
                bucket: QuotaBucket::Mailbox,
                ..
            }
        ));
        assert_eq!(
            ledger.usage(QuotaBucket::Mailbox),
            QuotaUsage {
                bytes: 8,
                records: 1
            }
        );
        assert_eq!(ledger.allocation_count(), 1);
    }

    #[test]
    fn retention_uses_explicit_expiry_and_max_age() {
        let mut policy = RetentionPolicy::daemon_defaults();
        policy.set_rule(QuotaBucket::Traces, RetentionRule::max_age(10));
        let records = vec![
            RetentionRecord {
                record_id: "new".to_string(),
                bucket: QuotaBucket::Traces,
                clock: RetentionClock::new(0, 95),
            },
            RetentionRecord {
                record_id: "old".to_string(),
                bucket: QuotaBucket::Traces,
                clock: RetentionClock::new(0, 80),
            },
            RetentionRecord {
                record_id: "explicit".to_string(),
                bucket: QuotaBucket::Mailbox,
                clock: RetentionClock::new(0, 99).with_expiry(100),
            },
        ];

        assert_eq!(
            policy.expired_records(&records, 100),
            vec!["explicit".to_string(), "old".to_string()]
        );
    }

    #[test]
    fn retention_enforces_max_records_by_oldest_update() {
        let mut policy = RetentionPolicy::daemon_defaults();
        policy.set_rule(
            QuotaBucket::Diagnostics,
            RetentionRule {
                max_age_secs: None,
                max_records: Some(2),
                honor_explicit_expiry: true,
            },
        );
        let records = vec![
            RetentionRecord {
                record_id: "middle".to_string(),
                bucket: QuotaBucket::Diagnostics,
                clock: RetentionClock::new(0, 20),
            },
            RetentionRecord {
                record_id: "oldest".to_string(),
                bucket: QuotaBucket::Diagnostics,
                clock: RetentionClock::new(0, 10),
            },
            RetentionRecord {
                record_id: "newest".to_string(),
                bucket: QuotaBucket::Diagnostics,
                clock: RetentionClock::new(0, 30),
            },
        ];

        assert_eq!(
            policy.expired_records(&records, 100),
            vec!["oldest".to_string()]
        );
    }

    #[test]
    fn retention_max_records_ignores_already_expired_records() {
        let mut policy = RetentionPolicy::daemon_defaults();
        policy.set_rule(
            QuotaBucket::Mailbox,
            RetentionRule {
                max_age_secs: None,
                max_records: Some(1),
                honor_explicit_expiry: true,
            },
        );
        let records = vec![
            RetentionRecord {
                record_id: "live-older".to_string(),
                bucket: QuotaBucket::Mailbox,
                clock: RetentionClock::new(0, 10),
            },
            RetentionRecord {
                record_id: "expired-newer".to_string(),
                bucket: QuotaBucket::Mailbox,
                clock: RetentionClock::new(0, 30).with_expiry(100),
            },
        ];

        assert_eq!(
            policy.expired_records(&records, 100),
            vec!["expired-newer".to_string()]
        );
    }

    #[test]
    fn quota_rows_are_deterministic() {
        let mut ledger = QuotaLedger::new();
        ledger.set_limit(QuotaBucket::Traces, QuotaLimit::new(10, 10));
        ledger.set_limit(QuotaBucket::Cache, QuotaLimit::new(20, 20));

        let rows = ledger.rows();
        assert_eq!(rows[0].bucket, QuotaBucket::Cache);
        assert_eq!(rows[1].bucket, QuotaBucket::Traces);
    }
}
