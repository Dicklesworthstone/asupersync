//! Grant storage implementation for persistent capability management.

use super::{GrantAuditRecord, GrantError, GrantInfo, GrantQuery, GrantResult, GrantStats};
use crate::types::outcome::Outcome;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Persistent storage record for grants.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantRecord {
    /// Grant information
    pub grant_info: GrantInfo,
    /// Audit trail
    pub audit_records: Vec<GrantAuditRecord>,
    /// Storage metadata
    pub storage_metadata: StorageMetadata,
}

/// Storage metadata for grants.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageMetadata {
    /// Version of storage format
    pub version: u32,
    /// When record was created
    pub created_at: SystemTime,
    /// When record was last updated
    pub updated_at: SystemTime,
    /// Storage location
    pub file_path: Option<String>,
}

impl Default for StorageMetadata {
    fn default() -> Self {
        let now = SystemTime::now();
        Self {
            version: 1,
            created_at: now,
            updated_at: now,
            file_path: None,
        }
    }
}

/// File-based grant storage implementation.
pub struct GrantStorage {
    /// Base directory for storage
    base_dir: PathBuf,
    /// In-memory cache of grants
    grants_cache: HashMap<String, GrantRecord>,
    /// Audit records cache
    audit_cache: Vec<GrantAuditRecord>,
    /// Whether cache is dirty
    cache_dirty: bool,
}

impl GrantStorage {
    /// Create a new grant storage.
    pub fn new<P: AsRef<Path>>(base_dir: P) -> GrantResult<Self> {
        let base_dir = base_dir.as_ref().to_path_buf();

        // Ensure directory exists
        if let Err(e) = fs::create_dir_all(&base_dir) {
            return Outcome::Err(GrantError::Storage(format!(
                "failed to create storage directory: {e}"
            )));
        }

        let mut storage = Self {
            base_dir,
            grants_cache: HashMap::new(),
            audit_cache: Vec::new(),
            cache_dirty: false,
        };

        // Load existing data. Capability state is security-sensitive; silently
        // dropping unreadable or malformed records would start the enforcer
        // from an incomplete view.
        match storage.load_from_disk() {
            Outcome::Ok(()) => {}
            Outcome::Err(error) => return Outcome::Err(error),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        }

        Outcome::ok(storage)
    }

    /// Store a grant.
    pub fn store_grant(&mut self, grant_info: GrantInfo) -> GrantResult<()> {
        let grant_id = grant_info.capability.grant_id.clone();

        // Check if grant already exists
        if self.grants_cache.contains_key(&grant_id) {
            return Outcome::Err(GrantError::AlreadyExists { grant_id });
        }

        // Create storage record
        let mut metadata = StorageMetadata::default();
        metadata.file_path = Some(
            self.grant_file_path(&grant_id)
                .to_string_lossy()
                .to_string(),
        );

        let record = GrantRecord {
            grant_info,
            audit_records: Vec::new(),
            storage_metadata: metadata,
        };

        match self.persist_record(&grant_id, &record) {
            Outcome::Ok(()) => {}
            Outcome::Err(error) => return Outcome::Err(error),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        }

        self.grants_cache.insert(grant_id, record);
        Outcome::ok(())
    }

    /// Retrieve a grant by ID.
    pub fn get_grant(&self, grant_id: &str) -> GrantResult<GrantInfo> {
        match self.grants_cache.get(grant_id) {
            Some(record) => Outcome::ok(record.grant_info.clone()),
            None => Outcome::Err(GrantError::NotFound {
                grant_id: grant_id.to_string(),
            }),
        }
    }

    /// Update an existing grant.
    pub fn update_grant(&mut self, grant_id: &str, grant_info: GrantInfo) -> GrantResult<()> {
        if grant_info.capability.grant_id != grant_id {
            return Outcome::Err(GrantError::ValidationFailed {
                issues: vec![format!(
                    "grant id mismatch: key {grant_id:?} does not match capability id {:?}",
                    grant_info.capability.grant_id
                )],
            });
        }

        let mut updated_record = match self.grants_cache.get(grant_id) {
            Some(record) => record,
            None => {
                return Outcome::Err(GrantError::NotFound {
                    grant_id: grant_id.to_string(),
                });
            }
        }
        .clone();

        updated_record.grant_info = grant_info;
        updated_record.storage_metadata.updated_at = SystemTime::now();
        updated_record.storage_metadata.file_path =
            Some(self.grant_file_path(grant_id).to_string_lossy().to_string());

        match self.persist_record(grant_id, &updated_record) {
            Outcome::Ok(()) => {}
            Outcome::Err(error) => return Outcome::Err(error),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        }

        self.grants_cache
            .insert(grant_id.to_string(), updated_record);
        self.cache_dirty = false;
        Outcome::ok(())
    }

    /// Delete a grant.
    pub fn delete_grant(&mut self, grant_id: &str) -> GrantResult<()> {
        if !self.grants_cache.contains_key(grant_id) {
            return Outcome::Err(GrantError::NotFound {
                grant_id: grant_id.to_string(),
            });
        }

        let file_path = self.grant_file_path(grant_id);
        match fs::remove_file(&file_path) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => {
                return Outcome::Err(GrantError::Storage(format!(
                    "failed to remove grant file {}: {error}",
                    file_path.display()
                )));
            }
        }

        self.grants_cache.remove(grant_id);
        self.cache_dirty = false;
        Outcome::ok(())
    }

    /// List grants matching query.
    pub fn list_grants(&self, query: &GrantQuery) -> GrantResult<Vec<GrantInfo>> {
        let mut results = Vec::new();

        for record in self.grants_cache.values() {
            let grant_info = &record.grant_info;

            // Apply filters
            if let Some(subject) = query.subject {
                if grant_info.capability.subject != subject {
                    continue;
                }
            }

            if let Some(issuer) = query.issuer {
                if grant_info.capability.issuer != issuer {
                    continue;
                }
            }

            if let Some(state) = query.state {
                if grant_info.state != state {
                    continue;
                }
            }

            if let Some(action) = query.action {
                if !grant_info.capability.grants_action(&action) {
                    continue;
                }
            }

            if query.usable_only && !grant_info.is_usable() {
                continue;
            }

            results.push(grant_info.clone());
        }

        // Apply limit
        if let Some(limit) = query.limit {
            results.truncate(limit);
        }

        Outcome::ok(results)
    }

    /// Add an audit record for a grant.
    pub fn add_audit_record(&mut self, record: GrantAuditRecord) -> GrantResult<()> {
        let grant_id = record.grant_id.clone();
        let mut updated_record = match self.grants_cache.get(&grant_id) {
            Some(grant_record) => grant_record.clone(),
            None => {
                return Outcome::Err(GrantError::NotFound {
                    grant_id: record.grant_id,
                });
            }
        };
        updated_record.audit_records.push(record.clone());
        updated_record.storage_metadata.updated_at = SystemTime::now();

        let mut updated_audit_cache = self.audit_cache.clone();
        updated_audit_cache.push(record);

        match self.persist_record(&grant_id, &updated_record) {
            Outcome::Ok(()) => {}
            Outcome::Err(error) => return Outcome::Err(error),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        }

        match self.persist_audit_records(&updated_audit_cache) {
            Outcome::Ok(()) => {}
            Outcome::Err(error) => return Outcome::Err(error),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        }

        self.grants_cache.insert(grant_id, updated_record);
        self.audit_cache = updated_audit_cache;
        self.cache_dirty = false;
        Outcome::ok(())
    }

    /// Get audit records for a grant.
    pub fn get_audit_records(&self, grant_id: &str) -> GrantResult<Vec<GrantAuditRecord>> {
        match self.grants_cache.get(grant_id) {
            Some(record) => Outcome::ok(record.audit_records.clone()),
            None => Outcome::Err(GrantError::NotFound {
                grant_id: grant_id.to_string(),
            }),
        }
    }

    /// Get global audit records.
    #[must_use]
    pub fn get_global_audit_records(&self) -> Vec<GrantAuditRecord> {
        self.audit_cache.clone()
    }

    /// Get storage statistics.
    #[must_use]
    pub fn get_stats(&self) -> GrantStats {
        let mut grants_by_state = HashMap::new();
        let mut unique_subjects = HashSet::new();
        let mut unique_issuers = HashSet::new();
        let mut total_usage = 0_u64;

        for record in self.grants_cache.values() {
            let grant_info = &record.grant_info;

            // Count by state
            *grants_by_state.entry(grant_info.state).or_insert(0) += 1;

            // Track unique peers
            unique_subjects.insert(grant_info.capability.subject);
            unique_issuers.insert(grant_info.capability.issuer);

            // Sum usage
            total_usage = total_usage.saturating_add(grant_info.usage_count);
        }

        GrantStats {
            total_grants: self.grants_cache.len() as u64,
            grants_by_state,
            total_usage,
            unique_subjects: unique_subjects.len() as u64,
            unique_issuers: unique_issuers.len() as u64,
        }
    }

    /// Flush all cached data to disk.
    pub fn flush(&mut self) -> GrantResult<()> {
        if !self.cache_dirty {
            return Outcome::ok(());
        }

        // Persist all grants
        for grant_id in self.grants_cache.keys() {
            match self.persist_grant(grant_id) {
                Outcome::Ok(()) => {}
                Outcome::Err(error) => return Outcome::Err(error),
                Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
                Outcome::Panicked(payload) => return Outcome::Panicked(payload),
            }
        }

        // Persist audit log
        match self.persist_audit_log() {
            Outcome::Ok(()) => {}
            Outcome::Err(error) => return Outcome::Err(error),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        }

        self.cache_dirty = false;
        Outcome::ok(())
    }

    /// Load data from disk.
    fn load_from_disk(&mut self) -> GrantResult<()> {
        // Load grants
        let grants_dir = self.base_dir.join("grants");
        if grants_dir.exists() {
            let entries = match fs::read_dir(&grants_dir) {
                Ok(entries) => entries,
                Err(error) => {
                    return Outcome::Err(GrantError::Storage(format!(
                        "failed to read grants directory {}: {error}",
                        grants_dir.display()
                    )));
                }
            };

            for entry in entries {
                let entry = match entry {
                    Ok(entry) => entry,
                    Err(error) => {
                        return Outcome::Err(GrantError::Storage(format!(
                            "failed to read grants directory entry: {error}"
                        )));
                    }
                };

                if entry
                    .path()
                    .extension()
                    .is_some_and(|extension| extension == "json")
                {
                    match self.load_grant_file(&entry.path()) {
                        Outcome::Ok(()) => {}
                        Outcome::Err(error) => return Outcome::Err(error),
                        Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
                        Outcome::Panicked(payload) => return Outcome::Panicked(payload),
                    }
                }
            }
        }

        // Load audit log
        let audit_file = self.base_dir.join("audit.jsonl");
        if audit_file.exists() {
            match self.load_audit_file(&audit_file) {
                Outcome::Ok(()) => {}
                Outcome::Err(error) => return Outcome::Err(error),
                Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
                Outcome::Panicked(payload) => return Outcome::Panicked(payload),
            }
        }

        Outcome::ok(())
    }

    /// Load a single grant file.
    fn load_grant_file(&mut self, path: &Path) -> GrantResult<()> {
        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                return Outcome::err(GrantError::Storage(format!(
                    "failed to read grant file: {e}"
                )));
            }
        };

        let mut record: GrantRecord = match serde_json::from_str(&content) {
            Ok(r) => r,
            Err(e) => {
                return Outcome::err(GrantError::Storage(format!(
                    "failed to parse grant file: {e}"
                )));
            }
        };

        let grant_id = record.grant_info.capability.grant_id.clone();
        if self.grants_cache.contains_key(&grant_id) {
            return Outcome::Err(GrantError::Storage(format!(
                "duplicate grant id {grant_id:?} while loading {}",
                path.display()
            )));
        }

        record.storage_metadata.file_path = Some(path.to_string_lossy().to_string());
        self.grants_cache.insert(grant_id, record);

        Outcome::ok(())
    }

    /// Load audit log file.
    fn load_audit_file(&mut self, path: &Path) -> GrantResult<()> {
        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                return Outcome::err(GrantError::Storage(format!(
                    "failed to read audit file: {e}"
                )));
            }
        };

        for (line_index, line) in content.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }

            match serde_json::from_str::<GrantAuditRecord>(line) {
                Ok(record) => self.audit_cache.push(record),
                Err(error) => {
                    return Outcome::Err(GrantError::Storage(format!(
                        "failed to parse audit record at line {}: {error}",
                        line_index + 1
                    )));
                }
            }
        }

        Outcome::ok(())
    }

    /// Persist a single grant to disk.
    fn persist_grant(&self, grant_id: &str) -> GrantResult<()> {
        let record = match self.grants_cache.get(grant_id) {
            Some(record) => record,
            None => {
                return Outcome::Err(GrantError::NotFound {
                    grant_id: grant_id.to_string(),
                });
            }
        };

        self.persist_record(grant_id, record)
    }

    /// Persist an already-built grant record to disk.
    fn persist_record(&self, grant_id: &str, record: &GrantRecord) -> GrantResult<()> {
        // Ensure grants directory exists
        let grants_dir = self.base_dir.join("grants");
        if let Err(e) = fs::create_dir_all(&grants_dir) {
            return Outcome::Err(GrantError::Storage(format!(
                "failed to create grants directory: {e}"
            )));
        }

        // Write grant file
        let file_path = self.grant_file_path(grant_id);
        let content = match serde_json::to_string_pretty(record) {
            Ok(c) => c,
            Err(e) => {
                return Outcome::err(GrantError::Storage(format!(
                    "failed to serialize grant: {e}"
                )));
            }
        };

        match fs::write(&file_path, content) {
            Ok(_) => {}
            Err(e) => {
                return Outcome::err(GrantError::Storage(format!(
                    "failed to write grant file: {e}"
                )));
            }
        }

        Outcome::ok(())
    }

    /// Persist audit log to disk.
    fn persist_audit_log(&self) -> GrantResult<()> {
        self.persist_audit_records(&self.audit_cache)
    }

    /// Persist the provided audit records to disk.
    fn persist_audit_records(&self, records: &[GrantAuditRecord]) -> GrantResult<()> {
        let audit_file = self.base_dir.join("audit.jsonl");
        let mut content = String::new();

        for record in records {
            let line = match serde_json::to_string(record) {
                Ok(line) => line,
                Err(error) => {
                    return Outcome::Err(GrantError::Storage(format!(
                        "failed to serialize audit record: {error}"
                    )));
                }
            };
            content.push_str(&line);
            content.push('\n');
        }

        match fs::write(&audit_file, content) {
            Ok(_) => {}
            Err(e) => {
                return Outcome::err(GrantError::Storage(format!(
                    "failed to write audit log: {e}"
                )));
            }
        }

        Outcome::ok(())
    }

    /// Get file path for a grant.
    fn grant_file_path(&self, grant_id: &str) -> PathBuf {
        use sha2::{Digest, Sha256};

        let digest = Sha256::digest(grant_id.as_bytes());
        self.base_dir
            .join("grants")
            .join(format!("{}.json", hex::encode(digest)))
    }
}

impl Drop for GrantStorage {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atp::grant::GrantOperation;
    use crate::atp::policy::{
        Capability, CapabilityAction, ResourceScope, ScopeConstraints, TemporalScope,
    };
    use crate::net::atp::protocol::PeerId;
    use std::collections::HashSet;
    use std::time::Duration;
    use tempfile::tempdir;

    fn create_test_grant_info_with_id(grant_id: &str) -> GrantInfo {
        let mut actions = HashSet::new();
        actions.insert(CapabilityAction::Read);

        let capability = Capability::new(
            grant_id.to_string(),
            PeerId::test(1),
            PeerId::test(2),
            ResourceScope::Any,
            actions,
            TemporalScope::expires_in(Duration::from_secs(3600)),
            ScopeConstraints::default(),
        );

        GrantInfo::new(capability)
    }

    fn create_test_grant_info() -> GrantInfo {
        create_test_grant_info_with_id("test-grant-123")
    }

    #[test]
    fn storage_stores_and_retrieves_grants() {
        let temp_dir = tempdir().expect("tempdir"); // ubs:ignore - test oracle
        let mut storage = GrantStorage::new(temp_dir.path()).expect("create storage"); // ubs:ignore - test oracle

        let grant_info = create_test_grant_info();
        let grant_id = grant_info.capability.grant_id.clone();

        // Store grant
        storage
            .store_grant(grant_info.clone())
            .expect("store grant"); // ubs:ignore - test oracle

        // Retrieve grant
        let retrieved = storage.get_grant(&grant_id).expect("get grant"); // ubs:ignore - test oracle
        assert_eq!(
            retrieved.capability.grant_id,
            grant_info.capability.grant_id
        );
        assert_eq!(retrieved.capability.subject, grant_info.capability.subject);
    }

    #[test]
    fn storage_prevents_duplicate_grants() {
        let temp_dir = tempdir().expect("tempdir"); // ubs:ignore - test oracle
        let mut storage = GrantStorage::new(temp_dir.path()).expect("create storage"); // ubs:ignore - test oracle

        let grant_info = create_test_grant_info();

        // Store grant
        storage
            .store_grant(grant_info.clone())
            .expect("store grant"); // ubs:ignore - test oracle

        // Try to store again - should fail
        let result = storage.store_grant(grant_info);
        assert!(matches!(
            result,
            Outcome::Err(GrantError::AlreadyExists { .. })
        ));
    }

    #[test]
    fn storage_uses_collision_resistant_file_paths() {
        let temp_dir = tempdir().expect("tempdir"); // ubs:ignore - test oracle
        let mut storage = GrantStorage::new(temp_dir.path()).expect("create storage"); // ubs:ignore - test oracle

        let first = create_test_grant_info_with_id("grant/a");
        let second = create_test_grant_info_with_id("grant_a");
        let first_path = storage.grant_file_path(&first.capability.grant_id);
        let second_path = storage.grant_file_path(&second.capability.grant_id);

        assert_ne!(first_path, second_path);

        storage.store_grant(first.clone()).expect("store first"); // ubs:ignore - test oracle
        storage.store_grant(second.clone()).expect("store second"); // ubs:ignore - test oracle

        assert!(first_path.exists());
        assert!(second_path.exists());

        let reloaded = GrantStorage::new(temp_dir.path()).expect("reload storage"); // ubs:ignore - test oracle
        assert!(reloaded.get_grant(&first.capability.grant_id).is_ok());
        assert!(reloaded.get_grant(&second.capability.grant_id).is_ok());
    }

    #[test]
    fn storage_rejects_update_with_mismatched_grant_id() {
        let temp_dir = tempdir().expect("tempdir"); // ubs:ignore - test oracle
        let mut storage = GrantStorage::new(temp_dir.path()).expect("create storage"); // ubs:ignore - test oracle
        let grant_info = create_test_grant_info();
        let grant_id = grant_info.capability.grant_id.clone();

        storage.store_grant(grant_info).expect("store grant"); // ubs:ignore - test oracle

        let mismatched = create_test_grant_info_with_id("different-grant-id");
        let result = storage.update_grant(&grant_id, mismatched);

        assert!(matches!(
            result,
            Outcome::Err(GrantError::ValidationFailed { .. })
        ));
        assert!(storage.get_grant(&grant_id).is_ok());
        assert!(matches!(
            storage.get_grant("different-grant-id"),
            Outcome::Err(GrantError::NotFound { .. })
        ));
    }

    #[test]
    fn storage_lists_grants_with_filters() {
        let temp_dir = tempdir().expect("tempdir"); // ubs:ignore - test oracle
        let mut storage = GrantStorage::new(temp_dir.path()).expect("create storage"); // ubs:ignore - test oracle

        let grant_info = create_test_grant_info();
        storage
            .store_grant(grant_info.clone())
            .expect("store grant"); // ubs:ignore - test oracle

        // Query by subject
        let query = GrantQuery {
            subject: Some(grant_info.capability.subject),
            ..Default::default()
        };

        let results = storage.list_grants(&query).expect("list grants"); // ubs:ignore - test oracle
        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0].capability.grant_id,
            grant_info.capability.grant_id
        );

        // Query by different subject
        let query = GrantQuery {
            subject: Some(PeerId::test(99)),
            ..Default::default()
        };

        let results = storage.list_grants(&query).expect("list grants"); // ubs:ignore - test oracle
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn storage_tracks_audit_records() {
        let temp_dir = tempdir().expect("tempdir"); // ubs:ignore - test oracle
        let mut storage = GrantStorage::new(temp_dir.path()).expect("create storage"); // ubs:ignore - test oracle

        let grant_info = create_test_grant_info();
        let grant_id = grant_info.capability.grant_id.clone();
        storage.store_grant(grant_info).expect("store grant"); // ubs:ignore - test oracle

        // Add audit record
        let audit_record = GrantAuditRecord {
            grant_id: grant_id.clone(),
            operation: GrantOperation::Used,
            actor: PeerId::test(1),
            target: None,
            timestamp: SystemTime::now(),
            context: HashMap::new(),
            capability_summary: "test summary".to_string(),
        };

        storage
            .add_audit_record(audit_record.clone())
            .expect("add audit record"); // ubs:ignore - test oracle

        // Retrieve audit records
        let records = storage
            .get_audit_records(&grant_id)
            .expect("get audit records"); // ubs:ignore - test oracle
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].operation, GrantOperation::Used);

        // Check global audit records
        let global_records = storage.get_global_audit_records();
        assert_eq!(global_records.len(), 1);
    }

    #[test]
    fn storage_rejects_audit_records_for_missing_grants() {
        let temp_dir = tempdir().expect("tempdir"); // ubs:ignore - test oracle
        let mut storage = GrantStorage::new(temp_dir.path()).expect("create storage"); // ubs:ignore - test oracle

        let result = storage.add_audit_record(GrantAuditRecord {
            grant_id: "missing-grant".to_string(),
            operation: GrantOperation::Used,
            actor: PeerId::test(1),
            target: None,
            timestamp: SystemTime::now(),
            context: HashMap::new(),
            capability_summary: "missing".to_string(),
        });

        assert!(matches!(result, Outcome::Err(GrantError::NotFound { .. })));
        assert!(storage.get_global_audit_records().is_empty());
    }

    #[test]
    fn storage_persists_across_instances() {
        let temp_dir = tempdir().expect("tempdir"); // ubs:ignore - test oracle
        let grant_info = create_test_grant_info();
        let grant_id = grant_info.capability.grant_id.clone();

        // Create storage and store grant
        {
            let mut storage = GrantStorage::new(temp_dir.path()).expect("create storage"); // ubs:ignore - test oracle
            storage
                .store_grant(grant_info.clone())
                .expect("store grant"); // ubs:ignore - test oracle
        }

        // Create new storage instance and verify grant is still there
        {
            let storage = GrantStorage::new(temp_dir.path()).expect("create storage"); // ubs:ignore - test oracle
            let retrieved = storage.get_grant(&grant_id).expect("get grant"); // ubs:ignore - test oracle
            assert_eq!(
                retrieved.capability.grant_id,
                grant_info.capability.grant_id
            );
        }
    }

    #[test]
    fn storage_persists_grant_specific_audit_records_across_instances() {
        let temp_dir = tempdir().expect("tempdir"); // ubs:ignore - test oracle
        let grant_info = create_test_grant_info();
        let grant_id = grant_info.capability.grant_id.clone();

        {
            let mut storage = GrantStorage::new(temp_dir.path()).expect("create storage"); // ubs:ignore - test oracle
            storage.store_grant(grant_info).expect("store grant"); // ubs:ignore - test oracle
            storage
                .add_audit_record(GrantAuditRecord {
                    grant_id: grant_id.clone(),
                    operation: GrantOperation::Used,
                    actor: PeerId::test(1),
                    target: None,
                    timestamp: SystemTime::now(),
                    context: HashMap::new(),
                    capability_summary: "used".to_string(),
                })
                .expect("add audit record"); // ubs:ignore - test oracle
        }

        let storage = GrantStorage::new(temp_dir.path()).expect("reload storage"); // ubs:ignore - test oracle
        let records = storage
            .get_audit_records(&grant_id)
            .expect("get persisted audit records"); // ubs:ignore - test oracle
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].operation, GrantOperation::Used);
        assert_eq!(storage.get_global_audit_records().len(), 1);
    }

    #[test]
    fn storage_rejects_malformed_grant_file_on_startup() {
        let temp_dir = tempdir().expect("tempdir"); // ubs:ignore - test oracle
        let grants_dir = temp_dir.path().join("grants");
        std::fs::create_dir_all(&grants_dir).expect("create grants dir"); // ubs:ignore - test oracle
        std::fs::write(grants_dir.join("bad.json"), "{not valid json")
            .expect("write malformed grant"); // ubs:ignore - test oracle

        let result = GrantStorage::new(temp_dir.path());

        assert!(matches!(result, Outcome::Err(GrantError::Storage(_))));
    }

    #[test]
    fn storage_rejects_duplicate_grant_ids_on_startup() {
        let temp_dir = tempdir().expect("tempdir"); // ubs:ignore - test oracle
        let grants_dir = temp_dir.path().join("grants");
        std::fs::create_dir_all(&grants_dir).expect("create grants dir"); // ubs:ignore - test oracle

        let record = GrantRecord {
            grant_info: create_test_grant_info_with_id("duplicate-grant"),
            audit_records: Vec::new(),
            storage_metadata: StorageMetadata::default(),
        };
        let serialized = serde_json::to_string_pretty(&record).expect("serialize record"); // ubs:ignore - test oracle

        std::fs::write(grants_dir.join("first.json"), &serialized).expect("write first grant"); // ubs:ignore - test oracle
        std::fs::write(grants_dir.join("second.json"), serialized).expect("write second grant"); // ubs:ignore - test oracle

        let result = GrantStorage::new(temp_dir.path());

        assert!(matches!(
            result,
            Outcome::Err(GrantError::Storage(message)) if message.contains("duplicate grant id")
        ));
    }

    #[test]
    fn storage_rejects_malformed_audit_log_on_startup() {
        let temp_dir = tempdir().expect("tempdir"); // ubs:ignore - test oracle
        std::fs::write(temp_dir.path().join("audit.jsonl"), "not json\n")
            .expect("write malformed audit log"); // ubs:ignore - test oracle

        let result = GrantStorage::new(temp_dir.path());

        assert!(matches!(result, Outcome::Err(GrantError::Storage(_))));
    }

    #[test]
    fn storage_calculates_stats() {
        let temp_dir = tempdir().expect("tempdir"); // ubs:ignore - test oracle
        let mut storage = GrantStorage::new(temp_dir.path()).expect("create storage"); // ubs:ignore - test oracle

        let grant_info = create_test_grant_info();
        storage.store_grant(grant_info).expect("store grant"); // ubs:ignore - test oracle

        let stats = storage.get_stats();
        assert_eq!(stats.total_grants, 1);
        assert_eq!(stats.unique_subjects, 1);
        assert_eq!(stats.unique_issuers, 1);
        assert_eq!(stats.total_usage, 0);
    }

    #[test]
    fn storage_stats_saturate_total_usage() {
        let temp_dir = tempdir().expect("tempdir"); // ubs:ignore - test oracle
        let mut storage = GrantStorage::new(temp_dir.path()).expect("create storage"); // ubs:ignore - test oracle

        let mut first = create_test_grant_info_with_id("first-grant");
        first.usage_count = u64::MAX;
        storage.store_grant(first).expect("store first grant"); // ubs:ignore - test oracle

        let mut second = create_test_grant_info_with_id("second-grant");
        second.usage_count = 1;
        storage.store_grant(second).expect("store second grant"); // ubs:ignore - test oracle

        let stats = storage.get_stats();
        assert_eq!(stats.total_usage, u64::MAX);
    }
}
