//! Persistent atpd state schema and redacted export model.

#[cfg(test)]
use crate::asupersync::atp::inbox::ObjectDigest;
#[cfg(test)]
use crate::asupersync::atp::quota::{
    QuotaAllocation, QuotaBucket, QuotaError, QuotaLedger, QuotaRow, QuotaUsage, RetentionClock,
    RetentionPolicy, RetentionRecord,
};
#[cfg(not(test))]
use crate::atp::inbox::ObjectDigest;
#[cfg(not(test))]
use crate::atp::quota::{
    QuotaAllocation, QuotaBucket, QuotaError, QuotaLedger, QuotaRow, QuotaUsage, RetentionClock,
    RetentionPolicy, RetentionRecord,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Current persistent atpd schema version.
pub const ATPD_STATE_SCHEMA_VERSION: u32 = 1;

/// Persistent state schema version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AtpdSchemaVersion(pub u32);

impl AtpdSchemaVersion {
    /// Current schema version.
    pub const CURRENT: Self = Self(ATPD_STATE_SCHEMA_VERSION);

    /// Return true when this schema can be read by the current code.
    #[must_use]
    pub const fn is_supported(self) -> bool {
        self.0 <= Self::CURRENT.0
    }
}

/// Persistent collection owned by atpd.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AtpdStateCollection {
    /// Durable peer identities and key handles.
    Identities,
    /// Capability grants and revocation records.
    Grants,
    /// Active, paused, failed, and completed transfer state.
    Transfers,
    /// Resume journals and append-only journal checkpoints.
    Journals,
    /// Verified cache records and seed metadata.
    Cache,
    /// Local inbox entries.
    Inbox,
    /// Offline mailbox metadata.
    Mailbox,
    /// Receive plans and consent prompts.
    ReceivePlans,
    /// Consent record replay log.
    ConsentRecords,
    /// Proof bundles and replay artifacts.
    ProofBundles,
    /// Structured traces.
    Traces,
    /// Diagnostic bundles.
    Diagnostics,
    /// Durable daemon settings.
    Settings,
    /// Quarantined receive data and validation failures.
    Quarantine,
}

impl AtpdStateCollection {
    /// Stable lowercase collection name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Identities => "identities",
            Self::Grants => "grants",
            Self::Transfers => "transfers",
            Self::Journals => "journals",
            Self::Cache => "cache",
            Self::Inbox => "inbox",
            Self::Mailbox => "mailbox",
            Self::ReceivePlans => "receive_plans",
            Self::ConsentRecords => "consent_records",
            Self::ProofBundles => "proof_bundles",
            Self::Traces => "traces",
            Self::Diagnostics => "diagnostics",
            Self::Settings => "settings",
            Self::Quarantine => "quarantine",
        }
    }

    /// Quota bucket charged by this collection.
    #[must_use]
    pub const fn quota_bucket(self) -> QuotaBucket {
        match self {
            Self::Identities => QuotaBucket::Identities,
            Self::Grants | Self::ConsentRecords | Self::ReceivePlans => QuotaBucket::Grants,
            Self::Transfers => QuotaBucket::Transfers,
            Self::Journals => QuotaBucket::PartialJournals,
            Self::Cache => QuotaBucket::Cache,
            Self::Inbox => QuotaBucket::Inbox,
            Self::Mailbox => QuotaBucket::Mailbox,
            Self::ProofBundles => QuotaBucket::ProofArtifacts,
            Self::Traces => QuotaBucket::Traces,
            Self::Diagnostics => QuotaBucket::Diagnostics,
            Self::Settings => QuotaBucket::Settings,
            Self::Quarantine => QuotaBucket::Quarantine,
        }
    }
}

impl fmt::Display for AtpdStateCollection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Privacy sensitivity of a stored record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StateSensitivity {
    /// Safe to show in diagnostics.
    Public,
    /// Internal daemon state, redacted by default.
    Internal,
    /// Peer identity metadata, redacted unless explicitly exported.
    PeerIdentity,
    /// Capability or grant material.
    GrantSecret,
    /// Key material or handles to key material.
    KeyMaterial,
    /// Private object metadata or local paths.
    PrivateContent,
    /// Quarantined adversarial or failed-validation data.
    Quarantine,
}

impl StateSensitivity {
    /// Return true when default listings must redact the record payload.
    #[allow(dead_code)]
    #[must_use]
    pub const fn redact_by_default(self) -> bool {
        !matches!(self, Self::Public)
    }
}

/// Export policy for one state record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StateExportPolicy {
    /// Never export this record through generic export.
    Deny,
    /// Export only redacted metadata by default.
    Redacted,
    /// Export full payload only when capability policy authorizes it.
    ExplicitPolicyRequired,
}

/// Caller-selected export mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtpdExportMode {
    /// Redacted export for diagnostics and support bundles.
    Redacted,
    /// Full export; requires explicit policy authorization.
    Full,
}

/// One persisted daemon state record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtpdStateRecord {
    /// Stable record id inside its collection.
    pub record_id: String,
    /// Collection that owns the record.
    pub collection: AtpdStateCollection,
    /// Canonical payload digest.
    pub payload_digest: ObjectDigest,
    /// Redacted summary suitable for diagnostics.
    pub redacted_summary: String,
    /// Size charged to quota.
    pub bytes: u64,
    /// Retention clock metadata.
    pub retention: RetentionClock,
    /// Privacy sensitivity.
    pub sensitivity: StateSensitivity,
    /// Export policy.
    pub export_policy: StateExportPolicy,
    /// True when this record represents quarantined state.
    pub quarantined: bool,
    /// Schema-specific field names present in the payload.
    pub fields: BTreeSet<String>,
}

impl AtpdStateRecord {
    /// Build a persisted state record.
    #[must_use]
    pub fn new(
        record_id: impl Into<String>,
        collection: AtpdStateCollection,
        payload_digest: ObjectDigest,
        redacted_summary: impl Into<String>,
        bytes: u64,
        retention: RetentionClock,
        sensitivity: StateSensitivity,
    ) -> Self {
        Self {
            record_id: record_id.into(),
            collection,
            payload_digest,
            redacted_summary: redacted_summary.into(),
            bytes,
            retention,
            sensitivity,
            export_policy: StateExportPolicy::Redacted,
            quarantined: collection == AtpdStateCollection::Quarantine,
            fields: BTreeSet::new(),
        }
    }

    /// Attach export policy.
    #[must_use]
    pub const fn with_export_policy(mut self, export_policy: StateExportPolicy) -> Self {
        self.export_policy = export_policy;
        self
    }

    /// Attach a payload field name to the schema descriptor.
    #[must_use]
    pub fn with_field(mut self, field: impl Into<String>) -> Self {
        self.fields.insert(field.into());
        self
    }

    fn quota_allocation(&self) -> QuotaAllocation {
        QuotaAllocation::one_record(self.collection.quota_bucket(), self.bytes)
    }

    fn retention_record(&self) -> RetentionRecord {
        RetentionRecord {
            record_id: scoped_record_id(self.collection, &self.record_id),
            bucket: self.collection.quota_bucket(),
            clock: self.retention,
        }
    }
}

/// Redacted or full record in an export bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtpdExportRecord {
    /// Stable scoped record id.
    pub scoped_id: String,
    /// Collection that owns the record.
    pub collection: AtpdStateCollection,
    /// Redacted summary.
    pub summary: String,
    /// Redacted payload digest.
    pub payload_digest: String,
    /// Size charged to quota.
    pub bytes: u64,
    /// Privacy sensitivity.
    pub sensitivity: StateSensitivity,
    /// Whether the payload is redacted.
    pub redacted: bool,
    /// Schema-specific field names present in the payload.
    pub fields: Vec<String>,
}

/// Exportable daemon state bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtpdStateExport {
    /// Schema version exported.
    pub schema_version: AtpdSchemaVersion,
    /// Export mode used.
    pub mode: String,
    /// Export records in deterministic order.
    pub records: Vec<AtpdExportRecord>,
    /// Quota rows at export time.
    pub quota_rows: Vec<QuotaRow>,
    /// Store settings summary.
    pub settings: AtpdStateSettings,
}

/// Persistent store integrity report for corrupted-store recovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtpdIntegrityReport {
    /// Required collections absent from the state map.
    pub missing_collections: Vec<AtpdStateCollection>,
    /// Buckets whose recorded usage does not match stored records.
    pub quota_mismatches: Vec<AtpdQuotaMismatch>,
}

impl AtpdIntegrityReport {
    /// Return true when the schema and quota ledger are internally consistent.
    #[allow(dead_code)]
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.missing_collections.is_empty() && self.quota_mismatches.is_empty()
    }
}

/// Quota mismatch found during integrity validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtpdQuotaMismatch {
    /// Bucket with inconsistent accounting.
    pub bucket: QuotaBucket,
    /// Usage recomputed from records.
    pub expected: QuotaUsage,
    /// Usage currently recorded in the ledger.
    pub actual: QuotaUsage,
}

/// Durable store settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtpdStateSettings {
    /// Root directory policy label, not an ambient database path.
    pub storage_root_label: String,
    /// Whether full exports require capability-policy authorization.
    pub require_policy_for_full_export: bool,
    /// Whether key material is stored as handles instead of raw keys.
    pub key_material_is_handle_only: bool,
    /// Whether diagnostic exports are redacted by default.
    pub diagnostics_redacted_by_default: bool,
}

impl Default for AtpdStateSettings {
    fn default() -> Self {
        Self {
            storage_root_label: "cx_scoped_atpd_state".to_string(),
            require_policy_for_full_export: true,
            key_material_is_handle_only: true,
            diagnostics_redacted_by_default: true,
        }
    }
}

/// Persistent atpd state schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtpdPersistentState {
    /// Schema version.
    pub schema_version: AtpdSchemaVersion,
    /// Store settings.
    pub settings: AtpdStateSettings,
    /// Quota ledger.
    pub quota_ledger: QuotaLedger,
    /// Retention policy.
    pub retention_policy: RetentionPolicy,
    /// Records grouped by collection then record id.
    pub records: BTreeMap<AtpdStateCollection, BTreeMap<String, AtpdStateRecord>>,
}

impl AtpdPersistentState {
    /// Build an empty daemon state store model.
    #[must_use]
    pub fn new() -> Self {
        Self {
            schema_version: AtpdSchemaVersion::CURRENT,
            settings: AtpdStateSettings::default(),
            quota_ledger: QuotaLedger::daemon_defaults(),
            retention_policy: RetentionPolicy::daemon_defaults(),
            records: BTreeMap::new(),
        }
    }

    /// Validate that every required collection exists in the schema surface.
    #[must_use]
    pub fn covers_required_collections(&self) -> bool {
        required_collections()
            .iter()
            .all(|collection| self.records.contains_key(collection))
    }

    /// Ensure all required collections are present, even if empty.
    pub fn ensure_required_collections(&mut self) {
        for collection in required_collections() {
            self.records.entry(collection).or_default();
        }
    }

    /// Insert a record after charging quota.
    pub fn insert_record(&mut self, record: AtpdStateRecord) -> Result<(), AtpdStateError> {
        if !self.schema_version.is_supported() {
            return Err(AtpdStateError::UnsupportedSchema(self.schema_version));
        }

        let scoped_id = scoped_record_id(record.collection, &record.record_id);
        if self
            .records
            .get(&record.collection)
            .and_then(|records| records.get(&record.record_id))
            .is_some()
        {
            return Err(AtpdStateError::DuplicateRecord(scoped_id));
        }

        self.quota_ledger
            .reserve(scoped_id, record.quota_allocation())?;
        self.records
            .entry(record.collection)
            .or_default()
            .insert(record.record_id.clone(), record);
        Ok(())
    }

    /// Remove a record due to retention or quarantine cleanup.
    pub fn expire_record(
        &mut self,
        collection: AtpdStateCollection,
        record_id: &str,
    ) -> Result<AtpdStateRecord, AtpdStateError> {
        let records = self
            .records
            .get_mut(&collection)
            .ok_or(AtpdStateError::UnknownCollection(collection))?;
        let record = records.remove(record_id).ok_or_else(|| {
            AtpdStateError::UnknownRecord(scoped_record_id(collection, record_id))
        })?;
        self.quota_ledger
            .release(&scoped_record_id(collection, record_id))?;
        Ok(record)
    }

    /// Apply retention policy and return expired scoped ids.
    pub fn apply_retention(&mut self, now_epoch_secs: u64) -> Result<Vec<String>, AtpdStateError> {
        let expired = self.expired_record_ids(now_epoch_secs);
        for scoped_id in &expired {
            let (collection, record_id) = parse_scoped_record_id(scoped_id)?;
            self.expire_record(collection, record_id)?;
        }
        Ok(expired)
    }

    /// Return retention-expired scoped ids without mutating state.
    #[must_use]
    pub fn expired_record_ids(&self, now_epoch_secs: u64) -> Vec<String> {
        let records: Vec<_> = self
            .records
            .values()
            .flat_map(|records| records.values().map(AtpdStateRecord::retention_record))
            .collect();
        self.retention_policy
            .expired_records(&records, now_epoch_secs)
    }

    /// Validate schema coverage and quota accounting without mutating state.
    #[must_use]
    pub fn integrity_report(&self) -> AtpdIntegrityReport {
        let missing_collections = required_collections()
            .into_iter()
            .filter(|collection| !self.records.contains_key(collection))
            .collect();

        let mut expected_usage: BTreeMap<QuotaBucket, QuotaUsage> = BTreeMap::new();
        for record in self.records.values().flat_map(BTreeMap::values) {
            let usage = expected_usage
                .entry(record.collection.quota_bucket())
                .or_default();
            usage.bytes = usage.bytes.saturating_add(record.bytes);
            usage.records = usage.records.saturating_add(1);
        }

        let mut buckets: BTreeSet<_> = expected_usage.keys().copied().collect();
        buckets.extend(self.quota_ledger.rows().iter().map(|row| row.bucket));

        let quota_mismatches = buckets
            .into_iter()
            .filter_map(|bucket| {
                let expected = expected_usage.get(&bucket).copied().unwrap_or_default();
                let actual = self.quota_ledger.usage(bucket);
                (expected != actual).then_some(AtpdQuotaMismatch {
                    bucket,
                    expected,
                    actual,
                })
            })
            .collect();

        AtpdIntegrityReport {
            missing_collections,
            quota_mismatches,
        }
    }

    /// Export a redacted or full state bundle.
    pub fn export(
        &self,
        mode: AtpdExportMode,
        policy_authorized: bool,
    ) -> Result<AtpdStateExport, AtpdStateError> {
        if mode == AtpdExportMode::Full
            && self.settings.require_policy_for_full_export
            && !policy_authorized
        {
            return Err(AtpdStateError::PolicyRequiredForFullExport);
        }

        let mut records = Vec::new();
        for (collection, collection_records) in &self.records {
            for record in collection_records.values() {
                if record.export_policy == StateExportPolicy::Deny {
                    continue;
                }
                let redacted = match mode {
                    AtpdExportMode::Redacted => true,
                    AtpdExportMode::Full => {
                        record.export_policy == StateExportPolicy::Redacted
                            || (record.sensitivity == StateSensitivity::KeyMaterial
                                && self.settings.key_material_is_handle_only)
                    }
                };
                let payload_digest = if redacted {
                    record.payload_digest.redacted()
                } else {
                    record.payload_digest.to_hex()
                };
                records.push(AtpdExportRecord {
                    scoped_id: scoped_record_id(*collection, &record.record_id),
                    collection: *collection,
                    summary: record.redacted_summary.clone(),
                    payload_digest,
                    bytes: record.bytes,
                    sensitivity: record.sensitivity,
                    redacted,
                    fields: record.fields.iter().cloned().collect(),
                });
            }
        }

        Ok(AtpdStateExport {
            schema_version: self.schema_version,
            mode: match mode {
                AtpdExportMode::Redacted => "redacted",
                AtpdExportMode::Full => "full",
            }
            .to_string(),
            records,
            quota_rows: self.quota_ledger.rows(),
            settings: self.settings.clone(),
        })
    }

    /// Export a privacy-safe diagnostics bundle with redaction forced on.
    pub fn privacy_safe_diagnostics_export(&self) -> Result<AtpdStateExport, AtpdStateError> {
        self.export(AtpdExportMode::Redacted, false)
    }

    /// Restore a state schema from a trusted snapshot.
    pub fn restore(snapshot: Self) -> Result<Self, AtpdStateError> {
        if !snapshot.schema_version.is_supported() {
            return Err(AtpdStateError::UnsupportedSchema(snapshot.schema_version));
        }
        let mut restored = Self {
            schema_version: snapshot.schema_version,
            settings: snapshot.settings,
            quota_ledger: quota_limits_only(&snapshot.quota_ledger),
            retention_policy: snapshot.retention_policy,
            records: BTreeMap::new(),
        };
        restored.ensure_required_collections();
        for records in snapshot.records.into_values() {
            for record in records.into_values() {
                restored.insert_record(record)?;
            }
        }
        Ok(restored)
    }

    /// Return a deterministic JSON snapshot for tests and proof artifacts.
    pub fn deterministic_snapshot_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

impl Default for AtpdPersistentState {
    fn default() -> Self {
        Self::new()
    }
}

/// Persistent state error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AtpdStateError {
    /// Schema version cannot be read by this code.
    UnsupportedSchema(AtpdSchemaVersion),
    /// Collection is unknown in this state store.
    UnknownCollection(AtpdStateCollection),
    /// Record id does not exist.
    UnknownRecord(String),
    /// Record id already exists.
    DuplicateRecord(String),
    /// Quota ledger rejected the operation.
    Quota(QuotaError),
    /// Full export requires explicit policy authorization.
    PolicyRequiredForFullExport,
    /// Scoped record id is malformed.
    MalformedScopedRecordId(String),
}

impl fmt::Display for AtpdStateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedSchema(version) => {
                write!(f, "unsupported atpd state schema version {}", version.0)
            }
            Self::UnknownCollection(collection) => {
                write!(f, "unknown atpd state collection `{collection}`")
            }
            Self::UnknownRecord(record_id) => write!(f, "unknown atpd state record `{record_id}`"),
            Self::DuplicateRecord(record_id) => {
                write!(f, "duplicate atpd state record `{record_id}`")
            }
            Self::Quota(err) => write!(f, "{err}"),
            Self::PolicyRequiredForFullExport => {
                write!(f, "full atpd state export requires explicit policy")
            }
            Self::MalformedScopedRecordId(record_id) => {
                write!(f, "malformed scoped record id `{record_id}`")
            }
        }
    }
}

impl std::error::Error for AtpdStateError {}

impl From<QuotaError> for AtpdStateError {
    fn from(value: QuotaError) -> Self {
        Self::Quota(value)
    }
}

/// Build the required collection set.
#[must_use]
pub fn required_collections() -> Vec<AtpdStateCollection> {
    vec![
        AtpdStateCollection::Identities,
        AtpdStateCollection::Grants,
        AtpdStateCollection::Transfers,
        AtpdStateCollection::Journals,
        AtpdStateCollection::Cache,
        AtpdStateCollection::Inbox,
        AtpdStateCollection::Mailbox,
        AtpdStateCollection::ReceivePlans,
        AtpdStateCollection::ConsentRecords,
        AtpdStateCollection::ProofBundles,
        AtpdStateCollection::Traces,
        AtpdStateCollection::Diagnostics,
        AtpdStateCollection::Settings,
        AtpdStateCollection::Quarantine,
    ]
}

fn scoped_record_id(collection: AtpdStateCollection, record_id: &str) -> String {
    format!("{collection}:{record_id}")
}

fn quota_limits_only(source: &QuotaLedger) -> QuotaLedger {
    let mut ledger = QuotaLedger::new();
    for (bucket, limit) in source.limits() {
        ledger.set_limit(bucket, limit);
    }
    ledger
}

fn parse_scoped_record_id(scoped_id: &str) -> Result<(AtpdStateCollection, &str), AtpdStateError> {
    let Some((collection_name, record_id)) = scoped_id.split_once(':') else {
        return Err(AtpdStateError::MalformedScopedRecordId(
            scoped_id.to_string(),
        ));
    };
    let collection = required_collections()
        .into_iter()
        .find(|collection| collection.as_str() == collection_name)
        .ok_or_else(|| AtpdStateError::MalformedScopedRecordId(scoped_id.to_string()))?;
    if record_id.is_empty() {
        return Err(AtpdStateError::MalformedScopedRecordId(
            scoped_id.to_string(),
        ));
    }
    Ok((collection, record_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asupersync::atp::quota::{QuotaLimit, RetentionRule};

    fn digest(byte: u8) -> ObjectDigest {
        ObjectDigest::new([byte; 32])
    }

    fn record(
        record_id: &str,
        collection: AtpdStateCollection,
        bytes: u64,
        updated_epoch_secs: u64,
        sensitivity: StateSensitivity,
    ) -> AtpdStateRecord {
        AtpdStateRecord::new(
            record_id,
            collection,
            digest(bytes as u8),
            format!("{collection}:{record_id}"),
            bytes,
            RetentionClock::new(0, updated_epoch_secs),
            sensitivity,
        )
        .with_field("payload_digest")
    }

    #[test]
    fn schema_covers_every_required_collection() {
        let mut state = AtpdPersistentState::new();
        state.ensure_required_collections();

        assert!(state.covers_required_collections());
        assert_eq!(required_collections().len(), 14);
    }

    #[test]
    fn migration_rejects_future_schema() {
        let mut snapshot = AtpdPersistentState::new();
        snapshot.schema_version = AtpdSchemaVersion(ATPD_STATE_SCHEMA_VERSION + 1);

        assert_eq!(
            AtpdPersistentState::restore(snapshot).unwrap_err(), // ubs:ignore - test oracle
            AtpdStateError::UnsupportedSchema(AtpdSchemaVersion(ATPD_STATE_SCHEMA_VERSION + 1))
        );
    }

    #[test]
    fn quota_exhaustion_blocks_insert_without_mutating_state() {
        let mut state = AtpdPersistentState::new();
        state
            .quota_ledger
            .set_limit(QuotaBucket::Cache, QuotaLimit::new(10, 1));
        state
            .insert_record(record(
                "cache-a",
                AtpdStateCollection::Cache,
                8,
                10,
                StateSensitivity::PrivateContent,
            ))
            .unwrap(); // ubs:ignore - test oracle

        let err = state
            .insert_record(record(
                "cache-b",
                AtpdStateCollection::Cache,
                1,
                11,
                StateSensitivity::PrivateContent,
            ))
            .unwrap_err();

        assert!(matches!(
            err,
            AtpdStateError::Quota(QuotaError::Exhausted { .. })
        ));
        assert_eq!(
            state
                .records
                .get(&AtpdStateCollection::Cache)
                .map(BTreeMap::len),
            Some(1)
        );
    }

    #[test]
    fn integrity_report_detects_corrupt_quota_accounting() {
        let mut state = AtpdPersistentState::new();
        state.ensure_required_collections();
        state
            .records
            .entry(AtpdStateCollection::Cache)
            .or_default()
            .insert(
                "unaccounted".to_string(),
                record(
                    "unaccounted",
                    AtpdStateCollection::Cache,
                    9,
                    10,
                    StateSensitivity::PrivateContent,
                ),
            );

        let report = state.integrity_report();
        assert!(report.missing_collections.is_empty());
        assert_eq!(
            report.quota_mismatches,
            vec![AtpdQuotaMismatch {
                bucket: QuotaBucket::Cache,
                expected: QuotaUsage {
                    bytes: 9,
                    records: 1
                },
                actual: QuotaUsage::default(),
            }]
        );
    }

    #[test]
    fn retention_expires_old_records_and_releases_quota() {
        let mut state = AtpdPersistentState::new();
        state
            .retention_policy
            .set_rule(QuotaBucket::Traces, RetentionRule::max_age(10));
        state
            .insert_record(record(
                "trace-old",
                AtpdStateCollection::Traces,
                5,
                80,
                StateSensitivity::Internal,
            ))
            .unwrap(); // ubs:ignore - test oracle
        state
            .insert_record(record(
                "trace-new",
                AtpdStateCollection::Traces,
                7,
                95,
                StateSensitivity::Internal,
            ))
            .unwrap(); // ubs:ignore - test oracle

        assert_eq!(
            state.apply_retention(100).unwrap(),
            vec!["traces:trace-old".to_string()]
        );
        assert_eq!(state.quota_ledger.usage(QuotaBucket::Traces).bytes, 7);
    }

    #[test]
    fn redacted_export_hides_sensitive_payloads() {
        let mut state = AtpdPersistentState::new();
        state
            .insert_record(
                record(
                    "identity-a",
                    AtpdStateCollection::Identities,
                    32,
                    10,
                    StateSensitivity::KeyMaterial,
                )
                .with_export_policy(StateExportPolicy::ExplicitPolicyRequired),
            )
            .unwrap(); // ubs:ignore - test oracle

        let export = state.export(AtpdExportMode::Redacted, false).unwrap(); // ubs:ignore - test oracle
        assert_eq!(export.records.len(), 1);
        assert!(export.records[0].redacted);
        assert!(export.records[0].payload_digest.ends_with("..."));
    }

    #[test]
    fn diagnostics_export_is_always_redacted_without_policy() {
        let mut state = AtpdPersistentState::new();
        state
            .insert_record(
                record(
                    "diagnostic-a",
                    AtpdStateCollection::Diagnostics,
                    16,
                    10,
                    StateSensitivity::Internal,
                )
                .with_export_policy(StateExportPolicy::ExplicitPolicyRequired),
            )
            .unwrap(); // ubs:ignore - test oracle

        let export = state.privacy_safe_diagnostics_export().unwrap(); // ubs:ignore - test oracle
        assert_eq!(export.mode, "redacted");
        assert!(export.records[0].redacted);
    }

    #[test]
    fn full_export_requires_policy_and_still_respects_record_policy() {
        let mut state = AtpdPersistentState::new();
        state
            .insert_record(
                record(
                    "public-setting",
                    AtpdStateCollection::Settings,
                    1,
                    10,
                    StateSensitivity::Public,
                )
                .with_export_policy(StateExportPolicy::ExplicitPolicyRequired),
            )
            .unwrap(); // ubs:ignore - test oracle

        assert_eq!(
            state.export(AtpdExportMode::Full, false).unwrap_err(), // ubs:ignore - test oracle
            AtpdStateError::PolicyRequiredForFullExport
        );
        let export = state.export(AtpdExportMode::Full, true).unwrap(); // ubs:ignore - test oracle
        assert!(!export.records[0].redacted);
        assert!(!export.records[0].payload_digest.ends_with("..."));
    }

    #[test]
    fn full_export_with_policy_can_include_private_metadata_digest() {
        let mut state = AtpdPersistentState::new();
        state
            .insert_record(
                record(
                    "cache-private",
                    AtpdStateCollection::Cache,
                    2,
                    10,
                    StateSensitivity::PrivateContent,
                )
                .with_export_policy(StateExportPolicy::ExplicitPolicyRequired),
            )
            .unwrap(); // ubs:ignore - test oracle

        let export = state.export(AtpdExportMode::Full, true).unwrap(); // ubs:ignore - test oracle
        assert!(!export.records[0].redacted);
    }

    #[test]
    fn consent_records_restore_and_snapshot_deterministically() {
        let mut state = AtpdPersistentState::new();
        state.ensure_required_collections();
        state
            .insert_record(record(
                "consent-a",
                AtpdStateCollection::ConsentRecords,
                9,
                10,
                StateSensitivity::GrantSecret,
            ))
            .unwrap(); // ubs:ignore - test oracle

        let restored = AtpdPersistentState::restore(state.clone()).unwrap(); // ubs:ignore - test oracle
        assert_eq!(
            state.deterministic_snapshot_json().unwrap(),
            restored.deterministic_snapshot_json().unwrap()
        );
    }

    #[test]
    fn quarantine_cleanup_uses_retention_policy() {
        let mut state = AtpdPersistentState::new();
        state
            .retention_policy
            .set_rule(QuotaBucket::Quarantine, RetentionRule::max_age(1));
        state
            .insert_record(record(
                "quarantine-a",
                AtpdStateCollection::Quarantine,
                64,
                10,
                StateSensitivity::Quarantine,
            ))
            .unwrap(); // ubs:ignore - test oracle

        assert_eq!(
            state.expired_record_ids(12),
            vec!["quarantine:quarantine-a".to_string()]
        );
    }
}
