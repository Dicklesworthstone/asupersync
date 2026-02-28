//! Browser storage adapter with explicit authority and deterministic test seam.
//!
//! This module provides a policy-enforced in-memory bridge for browser storage
//! semantics (IndexedDB/localStorage style APIs). It is intentionally
//! deterministic: storage is backed by `BTreeMap` and all key enumeration order
//! is stable.

use crate::io::cap::{
    BrowserStorageIoCap, StorageBackend, StorageIoCap, StorageOperation, StoragePolicyError,
    StorageRequest,
};
use std::collections::BTreeMap;

/// Error returned by browser storage operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserStorageError {
    /// Policy validation failed.
    Policy(StoragePolicyError),
}

impl std::fmt::Display for BrowserStorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Policy(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for BrowserStorageError {}

impl From<StoragePolicyError> for BrowserStorageError {
    fn from(error: StoragePolicyError) -> Self {
        Self::Policy(error)
    }
}

/// Structured storage telemetry event with redaction-aware fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageEvent {
    /// Operation that was attempted.
    pub operation: StorageOperation,
    /// Backend targeted by the operation.
    pub backend: StorageBackend,
    /// Namespace label (possibly redacted).
    pub namespace_label: String,
    /// Key label (possibly redacted).
    pub key_label: Option<String>,
    /// Value length metadata (possibly redacted).
    pub value_len: Option<usize>,
    /// Event outcome.
    pub outcome: StorageEventOutcome,
}

/// Deterministic outcome classification for storage telemetry events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageEventOutcome {
    /// Request passed policy checks and was applied.
    Allowed,
    /// Request was denied by policy.
    Denied,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct StorageKey {
    backend: StorageBackend,
    namespace: String,
    key: String,
}

/// Deterministic browser storage adapter used for policy enforcement and tests.
#[derive(Debug, Clone)]
pub struct BrowserStorageAdapter {
    cap: BrowserStorageIoCap,
    entries: BTreeMap<StorageKey, Vec<u8>>,
    used_bytes: usize,
    events: Vec<StorageEvent>,
}

impl BrowserStorageAdapter {
    /// Creates a new deterministic storage adapter.
    #[must_use]
    pub fn new(cap: BrowserStorageIoCap) -> Self {
        Self {
            cap,
            entries: BTreeMap::new(),
            used_bytes: 0,
            events: Vec::new(),
        }
    }

    /// Returns the configured capability adapter.
    #[must_use]
    pub fn cap(&self) -> &BrowserStorageIoCap {
        &self.cap
    }

    /// Returns currently tracked aggregate storage bytes.
    #[must_use]
    pub fn used_bytes(&self) -> usize {
        self.used_bytes
    }

    /// Returns the current deterministic entry count.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Returns collected storage telemetry events.
    #[must_use]
    pub fn events(&self) -> &[StorageEvent] {
        &self.events
    }

    /// Stores a value under `(backend, namespace, key)`.
    pub fn set(
        &mut self,
        backend: StorageBackend,
        namespace: impl Into<String>,
        key: impl Into<String>,
        value: Vec<u8>,
    ) -> Result<(), BrowserStorageError> {
        let namespace = namespace.into();
        let key = key.into();
        let request = StorageRequest::set(backend, namespace.clone(), key.clone(), value.len());
        self.authorize_and_record(&request)?;

        let quota = self.cap.quota_policy();
        let storage_key = StorageKey {
            backend,
            namespace: namespace.clone(),
            key: key.clone(),
        };
        let new_entry_size = entry_size(&namespace, &key, value.len());
        let old_entry_size = self
            .entries
            .get(&storage_key)
            .map_or(0, |old| entry_size(&namespace, &key, old.len()));

        let projected_entries = if self.entries.contains_key(&storage_key) {
            self.entries.len()
        } else {
            self.entries.len() + 1
        };
        if projected_entries > quota.max_entries {
            return self.policy_error(
                &request,
                StoragePolicyError::EntryCountExceeded {
                    projected: projected_entries,
                    limit: quota.max_entries,
                },
            );
        }

        let projected_bytes = self.used_bytes - old_entry_size + new_entry_size;
        if projected_bytes > quota.max_total_bytes {
            return self.policy_error(
                &request,
                StoragePolicyError::QuotaExceeded {
                    projected_bytes,
                    limit_bytes: quota.max_total_bytes,
                },
            );
        }

        self.used_bytes = projected_bytes;
        self.entries.insert(storage_key, value);
        Ok(())
    }

    /// Reads a value by `(backend, namespace, key)`.
    pub fn get(
        &mut self,
        backend: StorageBackend,
        namespace: impl Into<String>,
        key: impl Into<String>,
    ) -> Result<Option<Vec<u8>>, BrowserStorageError> {
        let namespace = namespace.into();
        let key = key.into();
        let request = StorageRequest::get(backend, namespace.clone(), key.clone());
        self.authorize_and_record(&request)?;

        let storage_key = StorageKey {
            backend,
            namespace,
            key,
        };
        Ok(self.entries.get(&storage_key).cloned())
    }

    /// Deletes a single key.
    pub fn delete(
        &mut self,
        backend: StorageBackend,
        namespace: impl Into<String>,
        key: impl Into<String>,
    ) -> Result<bool, BrowserStorageError> {
        let namespace = namespace.into();
        let key = key.into();
        let request = StorageRequest::delete(backend, namespace.clone(), key.clone());
        self.authorize_and_record(&request)?;

        let storage_key = StorageKey {
            backend,
            namespace: namespace.clone(),
            key: key.clone(),
        };

        let removed = self.entries.remove(&storage_key);
        if let Some(old) = removed {
            self.used_bytes =
                self.used_bytes
                    .saturating_sub(entry_size(&namespace, &key, old.len()));
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Lists keys in deterministic sorted order for a namespace.
    pub fn list_keys(
        &mut self,
        backend: StorageBackend,
        namespace: impl Into<String>,
    ) -> Result<Vec<String>, BrowserStorageError> {
        let namespace = namespace.into();
        let request = StorageRequest::list_keys(backend, namespace.clone());
        self.authorize_and_record(&request)?;

        Ok(self
            .entries
            .keys()
            .filter(|candidate| candidate.backend == backend && candidate.namespace == namespace)
            .map(|candidate| candidate.key.clone())
            .collect())
    }

    /// Clears all keys in a namespace and returns number of removed entries.
    pub fn clear_namespace(
        &mut self,
        backend: StorageBackend,
        namespace: impl Into<String>,
    ) -> Result<usize, BrowserStorageError> {
        let namespace = namespace.into();
        let request = StorageRequest::clear_namespace(backend, namespace.clone());
        self.authorize_and_record(&request)?;

        let keys_to_remove: Vec<StorageKey> = self
            .entries
            .keys()
            .filter(|candidate| candidate.backend == backend && candidate.namespace == namespace)
            .cloned()
            .collect();
        let removed_count = keys_to_remove.len();

        for key in keys_to_remove {
            if let Some(value) = self.entries.remove(&key) {
                self.used_bytes = self.used_bytes.saturating_sub(entry_size(
                    &key.namespace,
                    &key.key,
                    value.len(),
                ));
            }
        }

        Ok(removed_count)
    }

    fn authorize_and_record(
        &mut self,
        request: &StorageRequest,
    ) -> Result<(), BrowserStorageError> {
        match self.cap.authorize(request) {
            Ok(()) => {
                self.record_event(request, StorageEventOutcome::Allowed);
                Ok(())
            }
            Err(error) => self.policy_error(request, error),
        }
    }

    fn policy_error<T>(
        &mut self,
        request: &StorageRequest,
        error: StoragePolicyError,
    ) -> Result<T, BrowserStorageError> {
        self.record_event(request, StorageEventOutcome::Denied);
        Err(BrowserStorageError::Policy(error))
    }

    fn record_event(&mut self, request: &StorageRequest, outcome: StorageEventOutcome) {
        let redaction = self.cap.redaction_policy();
        let namespace_label = if redaction.redact_namespaces {
            format!("namespace[len:{}]", request.namespace.len())
        } else {
            request.namespace.clone()
        };
        let key_label = request.key.as_ref().map(|key| {
            if redaction.redact_keys {
                format!("key[len:{}]", key.len())
            } else {
                key.clone()
            }
        });
        let value_len = if redaction.redact_value_lengths {
            None
        } else {
            Some(request.value_len)
        };

        self.events.push(StorageEvent {
            operation: request.operation,
            backend: request.backend,
            namespace_label,
            key_label,
            value_len,
            outcome,
        });
    }
}

fn entry_size(namespace: &str, key: &str, value_len: usize) -> usize {
    namespace.len() + key.len() + value_len
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::cap::{
        StorageAuthority, StorageConsistencyPolicy, StorageOperation, StorageQuotaPolicy,
        StorageRedactionPolicy,
    };

    fn storage_cap_with_defaults() -> BrowserStorageIoCap {
        BrowserStorageIoCap::new(
            StorageAuthority::deny_all()
                .grant_backend(StorageBackend::IndexedDb)
                .grant_backend(StorageBackend::LocalStorage)
                .grant_namespace("cache:*")
                .grant_namespace("prefs:*")
                .grant_operation(StorageOperation::Get)
                .grant_operation(StorageOperation::Set)
                .grant_operation(StorageOperation::Delete)
                .grant_operation(StorageOperation::ListKeys)
                .grant_operation(StorageOperation::ClearNamespace),
            StorageQuotaPolicy {
                max_total_bytes: 256,
                max_key_bytes: 64,
                max_value_bytes: 128,
                max_namespace_bytes: 32,
                max_entries: 16,
            },
            StorageConsistencyPolicy::ImmediateReadAfterWrite,
            StorageRedactionPolicy::default(),
        )
    }

    #[test]
    fn adapter_round_trip_set_get_delete_is_deterministic() {
        let mut adapter = BrowserStorageAdapter::new(storage_cap_with_defaults());
        adapter
            .set(
                StorageBackend::IndexedDb,
                "cache:user:42",
                "profile",
                b"v1".to_vec(),
            )
            .expect("set should succeed");
        adapter
            .set(
                StorageBackend::IndexedDb,
                "cache:user:42",
                "access_token",
                b"t-1".to_vec(),
            )
            .expect("set should succeed");

        let keys = adapter
            .list_keys(StorageBackend::IndexedDb, "cache:user:42")
            .expect("list should succeed");
        assert_eq!(keys, vec!["access_token".to_owned(), "profile".to_owned()]);

        let value = adapter
            .get(StorageBackend::IndexedDb, "cache:user:42", "profile")
            .expect("get should succeed");
        assert_eq!(value, Some(b"v1".to_vec()));

        let removed = adapter
            .delete(StorageBackend::IndexedDb, "cache:user:42", "profile")
            .expect("delete should succeed");
        assert!(removed);
        assert_eq!(
            adapter
                .get(StorageBackend::IndexedDb, "cache:user:42", "profile")
                .expect("get should succeed"),
            None
        );
    }

    #[test]
    fn adapter_enforces_total_quota() {
        let cap = BrowserStorageIoCap::new(
            StorageAuthority::deny_all()
                .grant_backend(StorageBackend::LocalStorage)
                .grant_namespace("prefs:*")
                .grant_operation(StorageOperation::Set),
            StorageQuotaPolicy {
                max_total_bytes: 16,
                max_key_bytes: 16,
                max_value_bytes: 16,
                max_namespace_bytes: 16,
                max_entries: 8,
            },
            StorageConsistencyPolicy::ImmediateReadAfterWrite,
            StorageRedactionPolicy::default(),
        );
        let mut adapter = BrowserStorageAdapter::new(cap);

        adapter
            .set(
                StorageBackend::LocalStorage,
                "prefs:v1",
                "a",
                b"12".to_vec(),
            )
            .expect("first set should fit quota");

        let result = adapter.set(
            StorageBackend::LocalStorage,
            "prefs:v1",
            "abc",
            b"123456789".to_vec(),
        );
        assert!(matches!(
            result,
            Err(BrowserStorageError::Policy(
                StoragePolicyError::QuotaExceeded { .. }
            ))
        ));
    }

    #[test]
    fn adapter_denies_ungranted_namespace() {
        let mut adapter = BrowserStorageAdapter::new(storage_cap_with_defaults());
        let result = adapter.set(
            StorageBackend::IndexedDb,
            "session:v1",
            "token",
            b"x".to_vec(),
        );
        assert_eq!(
            result,
            Err(BrowserStorageError::Policy(
                StoragePolicyError::NamespaceDenied("session:v1".to_owned())
            ))
        );
    }

    #[test]
    fn adapter_records_redacted_events_when_configured() {
        let cap = BrowserStorageIoCap::new(
            StorageAuthority::deny_all()
                .grant_backend(StorageBackend::IndexedDb)
                .grant_namespace("cache:*")
                .grant_operation(StorageOperation::Set),
            StorageQuotaPolicy::default(),
            StorageConsistencyPolicy::ImmediateReadAfterWrite,
            StorageRedactionPolicy {
                redact_keys: true,
                redact_namespaces: true,
                redact_value_lengths: true,
            },
        );
        let mut adapter = BrowserStorageAdapter::new(cap);

        let result = adapter.set(
            StorageBackend::IndexedDb,
            "cache:user:9001",
            "secret-key",
            b"payload".to_vec(),
        );
        assert!(result.is_ok());

        let event = adapter.events().last().expect("event should exist");
        assert_eq!(event.outcome, StorageEventOutcome::Allowed);
        assert_eq!(event.namespace_label, "namespace[len:15]");
        assert_eq!(event.key_label.as_deref(), Some("key[len:10]"));
        assert_eq!(event.value_len, None);
    }
}
