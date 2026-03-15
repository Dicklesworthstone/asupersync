//! Browser storage adapter with explicit authority and deterministic test seam.
//!
//! This module provides a policy-enforced in-memory bridge for browser storage
//! semantics (IndexedDB/localStorage style APIs). It is intentionally
//! deterministic: storage is backed by `BTreeMap` and all key enumeration order
//! is stable.

use crate::io::cap::{
    BrowserStorageIoCap, StorageBackend, StorageConsistencyPolicy, StorageIoCap, StorageOperation,
    StoragePolicyError, StorageRequest,
};
#[cfg(target_arch = "wasm32")]
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
#[cfg(target_arch = "wasm32")]
use js_sys::{Array, Promise, Uint8Array};
use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::{JsCast, JsValue, closure::Closure};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen_futures::JsFuture;
#[cfg(target_arch = "wasm32")]
use web_sys::{
    Event, IdbDatabase, IdbFactory, IdbObjectStore, IdbOpenDbRequest, IdbRequest, IdbTransaction,
    IdbTransactionMode, Storage, WorkerGlobalScope,
};

/// Error returned by browser storage operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserStorageError {
    /// Policy validation failed.
    Policy(StoragePolicyError),
    /// Backend is temporarily unavailable in current execution context.
    BackendUnavailable(StorageBackend),
    /// Host-backed backend returned an operation error.
    HostBackend {
        /// Backend that produced the error.
        backend: StorageBackend,
        /// Storage operation that failed.
        operation: StorageOperation,
        /// Backend-provided diagnostic message.
        message: String,
    },
}

impl std::fmt::Display for BrowserStorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Policy(error) => write!(f, "{error}"),
            Self::BackendUnavailable(backend) => {
                write!(f, "storage backend unavailable: {backend:?}")
            }
            Self::HostBackend {
                backend,
                operation,
                message,
            } => write!(
                f,
                "storage host backend error ({backend:?}, {operation:?}): {message}"
            ),
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
    /// Deterministic reason code for policy and availability diagnostics.
    pub reason_code: StorageEventReasonCode,
}

/// Deterministic outcome classification for storage telemetry events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageEventOutcome {
    /// Request passed policy checks and was applied.
    Allowed,
    /// Request was denied by policy.
    Denied,
}

/// Stable reason code attached to storage telemetry events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageEventReasonCode {
    /// Request passed policy checks and was applied.
    Allowed,
    /// Namespace was empty/invalid.
    InvalidNamespace,
    /// Backend was outside allowed policy.
    BackendDenied,
    /// Namespace was outside allowed policy.
    NamespaceDenied,
    /// Operation was outside allowed policy.
    OperationDenied,
    /// Required key was missing.
    MissingKey,
    /// Key exceeded configured length limits.
    KeyTooLarge,
    /// Value exceeded configured length limits.
    ValueTooLarge,
    /// Namespace exceeded configured length limits.
    NamespaceTooLarge,
    /// Entry count would exceed configured limits.
    EntryCountExceeded,
    /// Aggregate bytes would exceed configured limits.
    QuotaExceeded,
    /// Backend is unavailable in this execution context.
    BackendUnavailable,
    /// Host backend returned an operation error.
    HostBackendError,
}

/// Host-backed browser storage implementation contract.
///
/// This allows the storage adapter to route specific backends (for example
/// `localStorage` in wasm browsers) to concrete host facilities while keeping
/// policy checks, telemetry, and deterministic behavior in one place.
pub trait StorageHostBackend: std::fmt::Debug + Send + Sync {
    /// Writes a value for the given namespace/key.
    fn set(&self, namespace: &str, key: &str, value: &[u8]) -> Result<(), String>;
    /// Reads a value for the given namespace/key.
    fn get(&self, namespace: &str, key: &str) -> Result<Option<Vec<u8>>, String>;
    /// Deletes a key and returns whether a value existed.
    fn delete(&self, namespace: &str, key: &str) -> Result<bool, String>;
    /// Lists keys in a namespace.
    fn list_keys(&self, namespace: &str) -> Result<Vec<String>, String>;
    /// Clears a namespace and returns removed entry count.
    fn clear_namespace(&self, namespace: &str) -> Result<usize, String>;
}

/// Boxed future type for async browser host backends on wasm targets.
#[cfg(target_arch = "wasm32")]
pub type StorageHostFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, String>> + 'a>>;

/// Boxed future type for async browser host backends on native targets.
///
/// Native clippy lanes require these adapter futures to remain `Send` so the
/// storage seam stays compatible with multithreaded executors used by tests and
/// host-only validation.
#[cfg(not(target_arch = "wasm32"))]
pub type StorageHostFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, String>> + Send + 'a>>;

/// Async host-backed browser storage implementation contract.
///
/// This is required for browser-native backends such as IndexedDB whose host
/// APIs are inherently asynchronous.
pub trait AsyncStorageHostBackend: std::fmt::Debug + Send + Sync {
    /// Writes a value for the given namespace/key.
    fn set<'a>(
        &'a self,
        namespace: &'a str,
        key: &'a str,
        value: &'a [u8],
    ) -> StorageHostFuture<'a, ()>;
    /// Reads a value for the given namespace/key.
    fn get<'a>(
        &'a self,
        namespace: &'a str,
        key: &'a str,
    ) -> StorageHostFuture<'a, Option<Vec<u8>>>;
    /// Deletes a key and returns whether a value existed.
    fn delete<'a>(&'a self, namespace: &'a str, key: &'a str) -> StorageHostFuture<'a, bool>;
    /// Lists keys in a namespace.
    fn list_keys<'a>(&'a self, namespace: &'a str) -> StorageHostFuture<'a, Vec<String>>;
    /// Clears a namespace and returns removed entry count.
    fn clear_namespace<'a>(&'a self, namespace: &'a str) -> StorageHostFuture<'a, usize>;
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct StorageKey {
    backend: StorageBackend,
    namespace: String,
    key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct StorageNamespaceKey {
    backend: StorageBackend,
    namespace: String,
}

/// Deterministic browser storage adapter used for policy enforcement and tests.
#[derive(Debug, Clone)]
pub struct BrowserStorageAdapter {
    cap: BrowserStorageIoCap,
    entries: BTreeMap<StorageKey, Vec<u8>>,
    list_snapshot: BTreeMap<StorageNamespaceKey, Vec<String>>,
    host_backends: BTreeMap<StorageBackend, Arc<dyn StorageHostBackend>>,
    async_host_backends: BTreeMap<StorageBackend, Arc<dyn AsyncStorageHostBackend>>,
    unavailable_backends: BTreeMap<StorageBackend, bool>,
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
            list_snapshot: BTreeMap::new(),
            host_backends: BTreeMap::new(),
            async_host_backends: BTreeMap::new(),
            unavailable_backends: BTreeMap::new(),
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

    /// Registers a host-backed implementation for a specific storage backend.
    ///
    /// When present, storage operations for `backend` are routed through this
    /// implementation after policy authorization.
    pub fn register_host_backend(
        &mut self,
        backend: StorageBackend,
        host_backend: Arc<dyn StorageHostBackend>,
    ) {
        self.host_backends.insert(backend, host_backend);
    }

    /// Registers an async host-backed implementation for a specific storage backend.
    pub fn register_async_host_backend(
        &mut self,
        backend: StorageBackend,
        host_backend: Arc<dyn AsyncStorageHostBackend>,
    ) {
        self.async_host_backends.insert(backend, host_backend);
    }

    /// Registers the default wasm `localStorage` host backend.
    #[cfg(target_arch = "wasm32")]
    pub fn register_wasm_local_storage_backend(&mut self) {
        self.register_host_backend(
            StorageBackend::LocalStorage,
            Arc::new(LocalStorageHostBackend),
        );
    }

    /// Registers the default wasm `IndexedDB` host backend.
    #[cfg(target_arch = "wasm32")]
    pub fn register_wasm_indexed_db_backend(&mut self) {
        self.register_async_host_backend(StorageBackend::IndexedDb, Arc::new(IndexedDbHostBackend));
    }

    /// Removes any registered host-backed implementation for `backend`.
    pub fn unregister_host_backend(
        &mut self,
        backend: StorageBackend,
    ) -> Option<Arc<dyn StorageHostBackend>> {
        self.host_backends.remove(&backend)
    }

    /// Removes any registered async host-backed implementation for `backend`.
    pub fn unregister_async_host_backend(
        &mut self,
        backend: StorageBackend,
    ) -> Option<Arc<dyn AsyncStorageHostBackend>> {
        self.async_host_backends.remove(&backend)
    }

    /// Returns whether a host-backed implementation is registered for `backend`.
    #[must_use]
    pub fn has_host_backend(&self, backend: StorageBackend) -> bool {
        self.host_backends.contains_key(&backend)
    }

    /// Returns whether an async host-backed implementation is registered for `backend`.
    #[must_use]
    pub fn has_async_host_backend(&self, backend: StorageBackend) -> bool {
        self.async_host_backends.contains_key(&backend)
    }

    /// Configures deterministic availability for a backend.
    ///
    /// When set to unavailable, all operations targeting the backend fail with
    /// [`BrowserStorageError::BackendUnavailable`] after authority validation.
    pub fn set_backend_available(&mut self, backend: StorageBackend, available: bool) {
        if available {
            self.unavailable_backends.remove(&backend);
        } else {
            self.unavailable_backends.insert(backend, false);
        }
    }

    /// Returns whether a backend is currently marked available.
    #[must_use]
    pub fn backend_available(&self, backend: StorageBackend) -> bool {
        self.unavailable_backends
            .get(&backend)
            .copied()
            .unwrap_or(true)
    }

    /// Deterministically forces list-view convergence for a namespace.
    pub fn flush_namespace_list_view(
        &mut self,
        backend: StorageBackend,
        namespace: impl Into<String>,
    ) {
        let namespace = namespace.into();
        self.recompute_list_snapshot(backend, &namespace);
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
        if self.async_host_backend(backend).is_some() {
            return self.sync_backend_requires_async(&request);
        }

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

        if let Some(host_backend) = self.host_backend(backend) {
            if let Err(message) = host_backend.set(&namespace, &key, &value) {
                return self.host_backend_error(&request, message);
            }
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
        if self.async_host_backend(backend).is_some() {
            return self.sync_backend_requires_async(&request);
        }

        let storage_key = StorageKey {
            backend,
            namespace,
            key,
        };
        if let Some(host_backend) = self.host_backend(backend) {
            let value = match host_backend.get(&storage_key.namespace, &storage_key.key) {
                Ok(value) => value,
                Err(message) => return self.host_backend_error(&request, message),
            };
            self.sync_entry_cache(&storage_key, value.as_ref());
            return Ok(value);
        }

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
        if self.async_host_backend(backend).is_some() {
            return self.sync_backend_requires_async(&request);
        }

        let storage_key = StorageKey {
            backend,
            namespace: namespace.clone(),
            key: key.clone(),
        };

        if let Some(host_backend) = self.host_backend(backend) {
            let deleted = match host_backend.delete(&namespace, &key) {
                Ok(deleted) => deleted,
                Err(message) => return self.host_backend_error(&request, message),
            };
            self.remove_cached_entry(&storage_key);
            return Ok(deleted);
        }

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
        if self.async_host_backend(backend).is_some() {
            return self.sync_backend_requires_async(&request);
        }

        if let Some(host_backend) = self.host_backend(backend) {
            if self.cap.consistency_policy() == StorageConsistencyPolicy::ImmediateReadAfterWrite {
                return self.host_backend_list_keys(&request, &*host_backend, &namespace);
            }

            let namespace_key = StorageNamespaceKey {
                backend,
                namespace: namespace.clone(),
            };
            let visible = self
                .list_snapshot
                .get(&namespace_key)
                .cloned()
                .unwrap_or_default();

            let next = self.host_backend_list_keys(&request, &*host_backend, &namespace)?;
            self.list_snapshot.insert(namespace_key, next);
            return Ok(visible);
        }

        if self.cap.consistency_policy() == StorageConsistencyPolicy::ImmediateReadAfterWrite {
            return Ok(self.collect_namespace_keys(backend, &namespace));
        }

        let namespace_key = StorageNamespaceKey {
            backend,
            namespace: namespace.clone(),
        };
        let visible = self
            .list_snapshot
            .get(&namespace_key)
            .cloned()
            .unwrap_or_default();

        // Deterministic eventual-consistency seam: this call may return a
        // stale list, but advances the snapshot so the next list converges.
        self.recompute_list_snapshot(backend, &namespace);
        Ok(visible)
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
        if self.async_host_backend(backend).is_some() {
            return self.sync_backend_requires_async(&request);
        }

        if let Some(host_backend) = self.host_backend(backend) {
            let removed_count = match host_backend.clear_namespace(&namespace) {
                Ok(removed_count) => removed_count,
                Err(message) => return self.host_backend_error(&request, message),
            };
            self.remove_cached_namespace(backend, &namespace);
            return Ok(removed_count);
        }

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

    /// Stores a value under `(backend, namespace, key)` using async host backends when needed.
    #[allow(clippy::future_not_send)]
    pub async fn set_async(
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

        let Some(host_backend) = self.async_host_backend(backend) else {
            return self.set(backend, namespace, key, value);
        };

        let storage_key = StorageKey {
            backend,
            namespace: namespace.clone(),
            key: key.clone(),
        };
        let projected_bytes = self.project_set_quota(&request, &storage_key, value.len())?;
        if let Err(message) = host_backend.set(&namespace, &key, &value).await {
            return self.host_backend_error(&request, message);
        }
        self.used_bytes = projected_bytes;
        self.entries.insert(storage_key, value);
        Ok(())
    }

    /// Reads a value by `(backend, namespace, key)` using async host backends when needed.
    #[allow(clippy::future_not_send)]
    pub async fn get_async(
        &mut self,
        backend: StorageBackend,
        namespace: impl Into<String>,
        key: impl Into<String>,
    ) -> Result<Option<Vec<u8>>, BrowserStorageError> {
        let namespace = namespace.into();
        let key = key.into();
        let request = StorageRequest::get(backend, namespace.clone(), key.clone());
        self.authorize_and_record(&request)?;

        let Some(host_backend) = self.async_host_backend(backend) else {
            return self.get(backend, namespace, key);
        };

        let storage_key = StorageKey {
            backend,
            namespace,
            key,
        };
        let value = match host_backend
            .get(&storage_key.namespace, &storage_key.key)
            .await
        {
            Ok(value) => value,
            Err(message) => return self.host_backend_error(&request, message),
        };
        self.sync_entry_cache(&storage_key, value.as_ref());
        Ok(value)
    }

    /// Deletes a single key using async host backends when needed.
    #[allow(clippy::future_not_send)]
    pub async fn delete_async(
        &mut self,
        backend: StorageBackend,
        namespace: impl Into<String>,
        key: impl Into<String>,
    ) -> Result<bool, BrowserStorageError> {
        let namespace = namespace.into();
        let key = key.into();
        let request = StorageRequest::delete(backend, namespace.clone(), key.clone());
        self.authorize_and_record(&request)?;

        let Some(host_backend) = self.async_host_backend(backend) else {
            return self.delete(backend, namespace, key);
        };

        let storage_key = StorageKey {
            backend,
            namespace: namespace.clone(),
            key: key.clone(),
        };
        let deleted = match host_backend.delete(&namespace, &key).await {
            Ok(deleted) => deleted,
            Err(message) => return self.host_backend_error(&request, message),
        };
        self.remove_cached_entry(&storage_key);
        Ok(deleted)
    }

    /// Lists keys in deterministic sorted order for a namespace using async host backends when needed.
    #[allow(clippy::future_not_send)]
    pub async fn list_keys_async(
        &mut self,
        backend: StorageBackend,
        namespace: impl Into<String>,
    ) -> Result<Vec<String>, BrowserStorageError> {
        let namespace = namespace.into();
        let request = StorageRequest::list_keys(backend, namespace.clone());
        self.authorize_and_record(&request)?;

        let Some(host_backend) = self.async_host_backend(backend) else {
            return self.list_keys(backend, namespace);
        };

        if self.cap.consistency_policy() == StorageConsistencyPolicy::ImmediateReadAfterWrite {
            return self
                .async_host_backend_list_keys(&request, &*host_backend, &namespace)
                .await;
        }

        let namespace_key = StorageNamespaceKey {
            backend,
            namespace: namespace.clone(),
        };
        let visible = self
            .list_snapshot
            .get(&namespace_key)
            .cloned()
            .unwrap_or_default();

        let next = self
            .async_host_backend_list_keys(&request, &*host_backend, &namespace)
            .await?;
        self.list_snapshot.insert(namespace_key, next);
        Ok(visible)
    }

    /// Clears all keys in a namespace using async host backends when needed.
    #[allow(clippy::future_not_send)]
    pub async fn clear_namespace_async(
        &mut self,
        backend: StorageBackend,
        namespace: impl Into<String>,
    ) -> Result<usize, BrowserStorageError> {
        let namespace = namespace.into();
        let request = StorageRequest::clear_namespace(backend, namespace.clone());
        self.authorize_and_record(&request)?;

        let Some(host_backend) = self.async_host_backend(backend) else {
            return self.clear_namespace(backend, namespace);
        };

        let removed_count = match host_backend.clear_namespace(&namespace).await {
            Ok(removed_count) => removed_count,
            Err(message) => return self.host_backend_error(&request, message),
        };
        self.remove_cached_namespace(backend, &namespace);
        Ok(removed_count)
    }

    fn authorize_and_record(
        &mut self,
        request: &StorageRequest,
    ) -> Result<(), BrowserStorageError> {
        match self.cap.authorize(request) {
            Ok(()) => {
                if !self.backend_available(request.backend) {
                    return self.backend_unavailable(request);
                }
                self.record_event(
                    request,
                    StorageEventOutcome::Allowed,
                    StorageEventReasonCode::Allowed,
                );
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
        self.record_event(
            request,
            StorageEventOutcome::Denied,
            reason_code_for_policy_error(&error),
        );
        Err(BrowserStorageError::Policy(error))
    }

    fn backend_unavailable<T>(
        &mut self,
        request: &StorageRequest,
    ) -> Result<T, BrowserStorageError> {
        self.record_event(
            request,
            StorageEventOutcome::Denied,
            StorageEventReasonCode::BackendUnavailable,
        );
        Err(BrowserStorageError::BackendUnavailable(request.backend))
    }

    fn host_backend_error<T>(
        &mut self,
        request: &StorageRequest,
        message: String,
    ) -> Result<T, BrowserStorageError> {
        self.record_event(
            request,
            StorageEventOutcome::Denied,
            StorageEventReasonCode::HostBackendError,
        );
        Err(BrowserStorageError::HostBackend {
            backend: request.backend,
            operation: request.operation,
            message,
        })
    }

    fn host_backend(&self, backend: StorageBackend) -> Option<Arc<dyn StorageHostBackend>> {
        self.host_backends.get(&backend).cloned()
    }

    fn async_host_backend(
        &self,
        backend: StorageBackend,
    ) -> Option<Arc<dyn AsyncStorageHostBackend>> {
        self.async_host_backends.get(&backend).cloned()
    }

    fn sync_backend_requires_async<T>(
        &mut self,
        request: &StorageRequest,
    ) -> Result<T, BrowserStorageError> {
        self.host_backend_error(
            request,
            "backend requires async browser storage adapter methods".to_owned(),
        )
    }

    fn host_backend_list_keys(
        &mut self,
        request: &StorageRequest,
        backend: &dyn StorageHostBackend,
        namespace: &str,
    ) -> Result<Vec<String>, BrowserStorageError> {
        let mut keys = match backend.list_keys(namespace) {
            Ok(keys) => keys,
            Err(message) => return self.host_backend_error(request, message),
        };
        keys.sort();
        keys.dedup();
        Ok(keys)
    }

    #[allow(clippy::future_not_send)]
    async fn async_host_backend_list_keys(
        &mut self,
        request: &StorageRequest,
        backend: &dyn AsyncStorageHostBackend,
        namespace: &str,
    ) -> Result<Vec<String>, BrowserStorageError> {
        let mut keys = match backend.list_keys(namespace).await {
            Ok(keys) => keys,
            Err(message) => return self.host_backend_error(request, message),
        };
        keys.sort();
        keys.dedup();
        Ok(keys)
    }

    fn project_set_quota(
        &mut self,
        request: &StorageRequest,
        storage_key: &StorageKey,
        value_len: usize,
    ) -> Result<usize, BrowserStorageError> {
        let quota = self.cap.quota_policy();
        let new_entry_size = entry_size(&storage_key.namespace, &storage_key.key, value_len);
        let old_entry_size = self.entries.get(storage_key).map_or(0, |old| {
            entry_size(&storage_key.namespace, &storage_key.key, old.len())
        });

        let projected_entries = if self.entries.contains_key(storage_key) {
            self.entries.len()
        } else {
            self.entries.len() + 1
        };
        if projected_entries > quota.max_entries {
            return self.policy_error(
                request,
                StoragePolicyError::EntryCountExceeded {
                    projected: projected_entries,
                    limit: quota.max_entries,
                },
            );
        }

        let projected_bytes = self.used_bytes - old_entry_size + new_entry_size;
        if projected_bytes > quota.max_total_bytes {
            return self.policy_error(
                request,
                StoragePolicyError::QuotaExceeded {
                    projected_bytes,
                    limit_bytes: quota.max_total_bytes,
                },
            );
        }

        Ok(projected_bytes)
    }

    fn sync_entry_cache(&mut self, storage_key: &StorageKey, value: Option<&Vec<u8>>) {
        self.remove_cached_entry(storage_key);
        if let Some(value) = value {
            self.used_bytes = self.used_bytes.saturating_add(entry_size(
                &storage_key.namespace,
                &storage_key.key,
                value.len(),
            ));
            self.entries.insert(storage_key.clone(), value.clone());
        }
    }

    fn remove_cached_entry(&mut self, storage_key: &StorageKey) {
        if let Some(previous) = self.entries.remove(storage_key) {
            self.used_bytes = self.used_bytes.saturating_sub(entry_size(
                &storage_key.namespace,
                &storage_key.key,
                previous.len(),
            ));
        }
    }

    fn remove_cached_namespace(&mut self, backend: StorageBackend, namespace: &str) {
        let keys_to_remove: Vec<StorageKey> = self
            .entries
            .keys()
            .filter(|candidate| candidate.backend == backend && candidate.namespace == namespace)
            .cloned()
            .collect();
        for key in keys_to_remove {
            self.remove_cached_entry(&key);
        }
    }

    fn collect_namespace_keys(&self, backend: StorageBackend, namespace: &str) -> Vec<String> {
        self.entries
            .keys()
            .filter(|candidate| candidate.backend == backend && candidate.namespace == namespace)
            .map(|candidate| candidate.key.clone())
            .collect()
    }

    fn recompute_list_snapshot(&mut self, backend: StorageBackend, namespace: &str) {
        let key = StorageNamespaceKey {
            backend,
            namespace: namespace.to_owned(),
        };
        self.list_snapshot
            .insert(key, self.collect_namespace_keys(backend, namespace));
    }

    fn record_event(
        &mut self,
        request: &StorageRequest,
        outcome: StorageEventOutcome,
        reason_code: StorageEventReasonCode,
    ) {
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
            reason_code,
        });
    }
}

fn reason_code_for_policy_error(error: &StoragePolicyError) -> StorageEventReasonCode {
    match error {
        StoragePolicyError::InvalidNamespace(_) => StorageEventReasonCode::InvalidNamespace,
        StoragePolicyError::BackendDenied(_) => StorageEventReasonCode::BackendDenied,
        StoragePolicyError::NamespaceDenied(_) => StorageEventReasonCode::NamespaceDenied,
        StoragePolicyError::OperationDenied(_) => StorageEventReasonCode::OperationDenied,
        StoragePolicyError::MissingKey(_) => StorageEventReasonCode::MissingKey,
        StoragePolicyError::KeyTooLarge { .. } => StorageEventReasonCode::KeyTooLarge,
        StoragePolicyError::ValueTooLarge { .. } => StorageEventReasonCode::ValueTooLarge,
        StoragePolicyError::NamespaceTooLarge { .. } => StorageEventReasonCode::NamespaceTooLarge,
        StoragePolicyError::EntryCountExceeded { .. } => StorageEventReasonCode::EntryCountExceeded,
        StoragePolicyError::QuotaExceeded { .. } => StorageEventReasonCode::QuotaExceeded,
    }
}

fn entry_size(namespace: &str, key: &str, value_len: usize) -> usize {
    namespace.len() + key.len() + value_len
}

/// WASM host backend that persists values in browser `localStorage`.
#[cfg(target_arch = "wasm32")]
#[derive(Debug, Default)]
pub struct LocalStorageHostBackend;

#[cfg(target_arch = "wasm32")]
impl LocalStorageHostBackend {
    const KEY_PREFIX: &'static str = "asupersync:storage:v1:";

    fn with_storage<T>(f: impl FnOnce(Storage) -> Result<T, String>) -> Result<T, String> {
        let window = web_sys::window().ok_or_else(|| "window is unavailable".to_owned())?;
        let storage = window
            .local_storage()
            .map_err(|error| format!("failed to access localStorage: {error:?}"))?
            .ok_or_else(|| "localStorage is unavailable".to_owned())?;
        f(storage)
    }

    fn key_prefix(namespace: &str) -> String {
        let encoded_namespace = URL_SAFE_NO_PAD.encode(namespace.as_bytes());
        format!("{}{encoded_namespace}:", Self::KEY_PREFIX)
    }

    fn encode_storage_key(namespace: &str, key: &str) -> String {
        let mut prefixed = Self::key_prefix(namespace);
        prefixed.push_str(&URL_SAFE_NO_PAD.encode(key.as_bytes()));
        prefixed
    }

    fn decode_key_segment(encoded: &str) -> Option<String> {
        URL_SAFE_NO_PAD
            .decode(encoded)
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
    }

    fn decode_storage_key(full_key: &str, namespace: &str) -> Option<String> {
        let prefix = Self::key_prefix(namespace);
        full_key
            .strip_prefix(&prefix)
            .and_then(Self::decode_key_segment)
    }
}

#[cfg(target_arch = "wasm32")]
impl StorageHostBackend for LocalStorageHostBackend {
    fn set(&self, namespace: &str, key: &str, value: &[u8]) -> Result<(), String> {
        let storage_key = Self::encode_storage_key(namespace, key);
        let encoded_value = URL_SAFE_NO_PAD.encode(value);
        Self::with_storage(|storage| {
            storage
                .set_item(&storage_key, &encoded_value)
                .map_err(|error| format!("localStorage set_item failed: {error:?}"))
        })
    }

    fn get(&self, namespace: &str, key: &str) -> Result<Option<Vec<u8>>, String> {
        let storage_key = Self::encode_storage_key(namespace, key);
        Self::with_storage(|storage| {
            let encoded = storage
                .get_item(&storage_key)
                .map_err(|error| format!("localStorage get_item failed: {error:?}"))?;
            encoded
                .map(|payload| {
                    URL_SAFE_NO_PAD
                        .decode(payload.as_bytes())
                        .map_err(|error| format!("failed to decode localStorage payload: {error}"))
                })
                .transpose()
        })
    }

    fn delete(&self, namespace: &str, key: &str) -> Result<bool, String> {
        let storage_key = Self::encode_storage_key(namespace, key);
        Self::with_storage(|storage| {
            let existed = storage
                .get_item(&storage_key)
                .map_err(|error| format!("localStorage get_item failed: {error:?}"))?
                .is_some();
            storage
                .remove_item(&storage_key)
                .map_err(|error| format!("localStorage remove_item failed: {error:?}"))?;
            Ok(existed)
        })
    }

    fn list_keys(&self, namespace: &str) -> Result<Vec<String>, String> {
        Self::with_storage(|storage| {
            let mut keys = Vec::new();
            let len = storage
                .length()
                .map_err(|error| format!("localStorage length failed: {error:?}"))?;
            for index in 0..len {
                let maybe_key = storage
                    .key(index)
                    .map_err(|error| format!("localStorage key({index}) failed: {error:?}"))?;
                if let Some(full_key) = maybe_key {
                    if let Some(decoded) = Self::decode_storage_key(&full_key, namespace) {
                        keys.push(decoded);
                    }
                }
            }
            Ok(keys)
        })
    }

    fn clear_namespace(&self, namespace: &str) -> Result<usize, String> {
        let keys = self.list_keys(namespace)?;
        for key in &keys {
            let storage_key = Self::encode_storage_key(namespace, key);
            Self::with_storage(|storage| {
                storage
                    .remove_item(&storage_key)
                    .map_err(|error| format!("localStorage remove_item failed: {error:?}"))
            })?;
        }
        Ok(keys.len())
    }
}

/// WASM host backend that persists values in browser `IndexedDB`.
#[cfg(target_arch = "wasm32")]
#[derive(Debug, Default)]
pub struct IndexedDbHostBackend;

#[cfg(target_arch = "wasm32")]
impl IndexedDbHostBackend {
    const DB_NAME: &'static str = "asupersync_storage_v1";
    const STORE_NAME: &'static str = "entries";
    const KEY_PREFIX: &'static str = "asupersync:indexeddb:v1:";
    const DB_VERSION: u32 = 1;

    fn key_prefix(namespace: &str) -> String {
        let encoded_namespace = URL_SAFE_NO_PAD.encode(namespace.as_bytes());
        format!("{}{encoded_namespace}:", Self::KEY_PREFIX)
    }

    fn encode_storage_key(namespace: &str, key: &str) -> String {
        let mut prefixed = Self::key_prefix(namespace);
        prefixed.push_str(&URL_SAFE_NO_PAD.encode(key.as_bytes()));
        prefixed
    }

    fn decode_storage_key(full_key: &str, namespace: &str) -> Option<String> {
        let prefix = Self::key_prefix(namespace);
        full_key.strip_prefix(&prefix).and_then(|encoded| {
            URL_SAFE_NO_PAD
                .decode(encoded)
                .ok()
                .and_then(|bytes| String::from_utf8(bytes).ok())
        })
    }

    fn factory() -> Result<IdbFactory, String> {
        if let Some(window) = web_sys::window() {
            return window
                .indexed_db()
                .map_err(|error| format!("failed to access IndexedDB from Window: {error:?}"))?
                .ok_or_else(|| "IndexedDB is unavailable on Window".to_owned());
        }

        if let Ok(worker) = js_sys::global().dyn_into::<WorkerGlobalScope>() {
            return worker
                .indexed_db()
                .map_err(|error| {
                    format!("failed to access IndexedDB from WorkerGlobalScope: {error:?}")
                })?
                .ok_or_else(|| "IndexedDB is unavailable in WorkerGlobalScope".to_owned());
        }

        Err("window or WorkerGlobalScope IndexedDB host is unavailable".to_owned())
    }

    async fn database(&self) -> Result<IdbDatabase, String> {
        let request = Self::factory()?
            .open_with_u32(Self::DB_NAME, Self::DB_VERSION)
            .map_err(|error| format!("failed to open IndexedDB database: {error:?}"))?;

        let upgrade_request = request.clone();
        let on_upgrade = Closure::once_into_js(move |_event: Event| {
            if let Ok(result) = upgrade_request.result() {
                if let Ok(db) = result.dyn_into::<IdbDatabase>() {
                    let _ = db.create_object_store(IndexedDbHostBackend::STORE_NAME);
                }
            }
        });
        request.set_onupgradeneeded(Some(on_upgrade.unchecked_ref()));

        let value = await_open_request(&request).await?;
        value
            .dyn_into::<IdbDatabase>()
            .map_err(|value| format!("IndexedDB open did not return a database: {value:?}"))
    }

    async fn store(
        &self,
        mode: IdbTransactionMode,
    ) -> Result<(IdbDatabase, IdbTransaction, IdbObjectStore), String> {
        let database = self.database().await?;
        let transaction = database
            .transaction_with_str_and_mode(Self::STORE_NAME, mode)
            .map_err(|error| format!("failed to open IndexedDB transaction: {error:?}"))?;
        let store = transaction
            .object_store(Self::STORE_NAME)
            .map_err(|error| format!("failed to open IndexedDB object store: {error:?}"))?;
        Ok((database, transaction, store))
    }

    fn decode_binary_value(value: JsValue) -> Result<Option<Vec<u8>>, String> {
        if value.is_undefined() || value.is_null() {
            return Ok(None);
        }
        if value.is_instance_of::<Uint8Array>() || value.is_instance_of::<js_sys::ArrayBuffer>() {
            return Ok(Some(Uint8Array::new(&value).to_vec()));
        }
        Err(format!(
            "IndexedDB returned a non-binary payload for browser storage: {value:?}"
        ))
    }
}

#[cfg(target_arch = "wasm32")]
impl AsyncStorageHostBackend for IndexedDbHostBackend {
    fn set<'a>(
        &'a self,
        namespace: &'a str,
        key: &'a str,
        value: &'a [u8],
    ) -> StorageHostFuture<'a, ()> {
        Box::pin(async move {
            let (_database, transaction, store) = self.store(IdbTransactionMode::Readwrite).await?;
            let storage_key = Self::encode_storage_key(namespace, key);
            let payload = Uint8Array::from(value);
            let request = store
                .put_with_key(&payload.into(), &JsValue::from_str(&storage_key))
                .map_err(|error| format!("IndexedDB put failed to start: {error:?}"))?;
            let _ = await_request(&request).await?;
            await_transaction(&transaction).await
        })
    }

    fn get<'a>(
        &'a self,
        namespace: &'a str,
        key: &'a str,
    ) -> StorageHostFuture<'a, Option<Vec<u8>>> {
        Box::pin(async move {
            let (_database, _transaction, store) = self.store(IdbTransactionMode::Readonly).await?;
            let storage_key = Self::encode_storage_key(namespace, key);
            let request = store
                .get(&JsValue::from_str(&storage_key))
                .map_err(|error| format!("IndexedDB get failed to start: {error:?}"))?;
            let value = await_request(&request).await?;
            Self::decode_binary_value(value)
        })
    }

    fn delete<'a>(&'a self, namespace: &'a str, key: &'a str) -> StorageHostFuture<'a, bool> {
        Box::pin(async move {
            let (_database, transaction, store) = self.store(IdbTransactionMode::Readwrite).await?;
            let storage_key = Self::encode_storage_key(namespace, key);
            let existing_request = store
                .get(&JsValue::from_str(&storage_key))
                .map_err(|error| format!("IndexedDB existence check failed to start: {error:?}"))?;
            let existed = !await_request(&existing_request).await?.is_undefined();
            let delete_request = store
                .delete(&JsValue::from_str(&storage_key))
                .map_err(|error| format!("IndexedDB delete failed to start: {error:?}"))?;
            let _ = await_request(&delete_request).await?;
            await_transaction(&transaction).await?;
            Ok(existed)
        })
    }

    fn list_keys<'a>(&'a self, namespace: &'a str) -> StorageHostFuture<'a, Vec<String>> {
        Box::pin(async move {
            let (_database, _transaction, store) = self.store(IdbTransactionMode::Readonly).await?;
            let request = store
                .get_all_keys()
                .map_err(|error| format!("IndexedDB get_all_keys failed to start: {error:?}"))?;
            let result = await_request(&request).await?;
            let mut keys = Vec::new();
            for value in Array::from(&result).iter() {
                if let Some(full_key) = value.as_string() {
                    if let Some(decoded) = Self::decode_storage_key(&full_key, namespace) {
                        keys.push(decoded);
                    }
                }
            }
            keys.sort();
            keys.dedup();
            Ok(keys)
        })
    }

    fn clear_namespace<'a>(&'a self, namespace: &'a str) -> StorageHostFuture<'a, usize> {
        Box::pin(async move {
            let keys = self.list_keys(namespace).await?;
            if keys.is_empty() {
                return Ok(0);
            }
            let (_database, transaction, store) = self.store(IdbTransactionMode::Readwrite).await?;
            for key in &keys {
                let storage_key = Self::encode_storage_key(namespace, key);
                let request = store
                    .delete(&JsValue::from_str(&storage_key))
                    .map_err(|error| {
                        format!(
                            "IndexedDB delete failed to start during clear_namespace: {error:?}"
                        )
                    })?;
                let _ = await_request(&request).await?;
            }
            await_transaction(&transaction).await?;
            Ok(keys.len())
        })
    }
}

#[cfg(target_arch = "wasm32")]
fn clear_idb_request_handlers(request: &IdbRequest) {
    request.set_onsuccess(None);
    request.set_onerror(None);
}

#[cfg(target_arch = "wasm32")]
fn clear_idb_open_request_handlers(request: &IdbOpenDbRequest) {
    request.set_onsuccess(None);
    request.set_onerror(None);
    request.set_onblocked(None);
    request.set_onupgradeneeded(None);
}

#[cfg(target_arch = "wasm32")]
fn clear_idb_transaction_handlers(transaction: &IdbTransaction) {
    transaction.set_oncomplete(None);
    transaction.set_onerror(None);
    transaction.set_onabort(None);
}

#[cfg(target_arch = "wasm32")]
fn indexed_db_error_message(value: &JsValue) -> String {
    value.as_string().unwrap_or_else(|| format!("{value:?}"))
}

#[cfg(target_arch = "wasm32")]
async fn await_request(request: &IdbRequest) -> Result<JsValue, String> {
    let request = request.clone();
    let promise = Promise::new(&mut move |resolve, reject| {
        let success_request = request.clone();
        let success_cleanup = request.clone();
        let resolve_success = resolve.clone();
        let reject_success = reject.clone();
        let on_success = Closure::once_into_js(move |_event: Event| {
            clear_idb_request_handlers(&success_cleanup);
            match success_request.result() {
                Ok(value) => {
                    let _ = resolve_success.call1(&JsValue::UNDEFINED, &value);
                }
                Err(error) => {
                    let _ = reject_success.call1(&JsValue::UNDEFINED, &error);
                }
            }
        });
        request.set_onsuccess(Some(on_success.unchecked_ref()));

        let error_request = request.clone();
        let error_cleanup = request.clone();
        let reject_error = reject.clone();
        let on_error = Closure::once_into_js(move |_event: Event| {
            clear_idb_request_handlers(&error_cleanup);
            let error = error_request
                .error()
                .map(JsValue::from)
                .unwrap_or_else(|_| JsValue::from_str("IndexedDB request failed"));
            let _ = reject_error.call1(&JsValue::UNDEFINED, &error);
        });
        request.set_onerror(Some(on_error.unchecked_ref()));
    });

    JsFuture::from(promise)
        .await
        .map_err(|error| indexed_db_error_message(&error))
}

#[cfg(target_arch = "wasm32")]
async fn await_open_request(request: &IdbOpenDbRequest) -> Result<JsValue, String> {
    let request = request.clone();
    let promise = Promise::new(&mut move |resolve, reject| {
        let success_request = request.clone();
        let success_cleanup = request.clone();
        let resolve_success = resolve.clone();
        let reject_success = reject.clone();
        let on_success = Closure::once_into_js(move |_event: Event| {
            clear_idb_open_request_handlers(&success_cleanup);
            match success_request.result() {
                Ok(value) => {
                    let _ = resolve_success.call1(&JsValue::UNDEFINED, &value);
                }
                Err(error) => {
                    let _ = reject_success.call1(&JsValue::UNDEFINED, &error);
                }
            }
        });
        request.set_onsuccess(Some(on_success.unchecked_ref()));

        let error_request = request.clone();
        let error_cleanup = request.clone();
        let reject_error = reject.clone();
        let on_error = Closure::once_into_js(move |_event: Event| {
            clear_idb_open_request_handlers(&error_cleanup);
            let error = error_request
                .error()
                .map(JsValue::from)
                .unwrap_or_else(|_| JsValue::from_str("IndexedDB open failed"));
            let _ = reject_error.call1(&JsValue::UNDEFINED, &error);
        });
        request.set_onerror(Some(on_error.unchecked_ref()));

        let blocked_cleanup = request.clone();
        let reject_blocked = reject.clone();
        let on_blocked = Closure::once_into_js(move |_event: Event| {
            clear_idb_open_request_handlers(&blocked_cleanup);
            let _ = reject_blocked.call1(
                &JsValue::UNDEFINED,
                &JsValue::from_str("IndexedDB open blocked by another connection"),
            );
        });
        request.set_onblocked(Some(on_blocked.unchecked_ref()));
    });

    JsFuture::from(promise)
        .await
        .map_err(|error| indexed_db_error_message(&error))
}

#[cfg(target_arch = "wasm32")]
async fn await_transaction(transaction: &IdbTransaction) -> Result<(), String> {
    let transaction = transaction.clone();
    let promise = Promise::new(&mut move |resolve, reject| {
        let complete_cleanup = transaction.clone();
        let resolve_complete = resolve.clone();
        let on_complete = Closure::once_into_js(move |_event: Event| {
            clear_idb_transaction_handlers(&complete_cleanup);
            let _ = resolve_complete.call0(&JsValue::UNDEFINED);
        });
        transaction.set_oncomplete(Some(on_complete.unchecked_ref()));

        let error_cleanup = transaction.clone();
        let reject_error = reject.clone();
        let on_error = Closure::once_into_js(move |_event: Event| {
            clear_idb_transaction_handlers(&error_cleanup);
            let _ = reject_error.call1(
                &JsValue::UNDEFINED,
                &JsValue::from_str("IndexedDB transaction failed"),
            );
        });
        transaction.set_onerror(Some(on_error.unchecked_ref()));

        let abort_cleanup = transaction.clone();
        let reject_abort = reject.clone();
        let on_abort = Closure::once_into_js(move |_event: Event| {
            clear_idb_transaction_handlers(&abort_cleanup);
            let _ = reject_abort.call1(
                &JsValue::UNDEFINED,
                &JsValue::from_str("IndexedDB transaction aborted"),
            );
        });
        transaction.set_onabort(Some(on_abort.unchecked_ref()));
    });

    JsFuture::from(promise)
        .await
        .map(|_| ())
        .map_err(|error| indexed_db_error_message(&error))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::cap::{
        StorageAuthority, StorageConsistencyPolicy, StorageOperation, StorageQuotaPolicy,
        StorageRedactionPolicy,
    };
    use std::sync::Mutex;

    #[derive(Debug, Default)]
    struct MockHostBackend {
        entries: Mutex<BTreeMap<(String, String), Vec<u8>>>,
    }

    impl StorageHostBackend for MockHostBackend {
        fn set(&self, namespace: &str, key: &str, value: &[u8]) -> Result<(), String> {
            self.entries
                .lock()
                .expect("host backend lock poisoned")
                .insert((namespace.to_owned(), key.to_owned()), value.to_vec());
            Ok(())
        }

        fn get(&self, namespace: &str, key: &str) -> Result<Option<Vec<u8>>, String> {
            Ok(self
                .entries
                .lock()
                .expect("host backend lock poisoned")
                .get(&(namespace.to_owned(), key.to_owned()))
                .cloned())
        }

        fn delete(&self, namespace: &str, key: &str) -> Result<bool, String> {
            Ok(self
                .entries
                .lock()
                .expect("host backend lock poisoned")
                .remove(&(namespace.to_owned(), key.to_owned()))
                .is_some())
        }

        fn list_keys(&self, namespace: &str) -> Result<Vec<String>, String> {
            let mut keys: Vec<String> = self
                .entries
                .lock()
                .expect("host backend lock poisoned")
                .keys()
                .filter(|(candidate_namespace, _)| candidate_namespace == namespace)
                .map(|(_, key)| key.clone())
                .collect();
            keys.sort();
            Ok(keys)
        }

        fn clear_namespace(&self, namespace: &str) -> Result<usize, String> {
            let mut entries = self.entries.lock().expect("host backend lock poisoned");
            let initial_len = entries.len();
            entries.retain(|(candidate_namespace, _), _| candidate_namespace != namespace);
            Ok(initial_len.saturating_sub(entries.len()))
        }
    }

    #[derive(Debug)]
    struct FailingHostBackend;

    impl StorageHostBackend for FailingHostBackend {
        fn set(&self, _namespace: &str, _key: &str, _value: &[u8]) -> Result<(), String> {
            Err("simulated host backend set failure".to_owned())
        }

        fn get(&self, _namespace: &str, _key: &str) -> Result<Option<Vec<u8>>, String> {
            Err("simulated host backend get failure".to_owned())
        }

        fn delete(&self, _namespace: &str, _key: &str) -> Result<bool, String> {
            Err("simulated host backend delete failure".to_owned())
        }

        fn list_keys(&self, _namespace: &str) -> Result<Vec<String>, String> {
            Err("simulated host backend list failure".to_owned())
        }

        fn clear_namespace(&self, _namespace: &str) -> Result<usize, String> {
            Err("simulated host backend clear failure".to_owned())
        }
    }

    #[derive(Debug, Default)]
    struct MockAsyncHostBackend {
        entries: Mutex<BTreeMap<(String, String), Vec<u8>>>,
    }

    impl AsyncStorageHostBackend for MockAsyncHostBackend {
        fn set<'a>(
            &'a self,
            namespace: &'a str,
            key: &'a str,
            value: &'a [u8],
        ) -> StorageHostFuture<'a, ()> {
            Box::pin(async move {
                self.entries
                    .lock()
                    .expect("async host backend lock poisoned")
                    .insert((namespace.to_owned(), key.to_owned()), value.to_vec());
                Ok(())
            })
        }

        fn get<'a>(
            &'a self,
            namespace: &'a str,
            key: &'a str,
        ) -> StorageHostFuture<'a, Option<Vec<u8>>> {
            Box::pin(async move {
                Ok(self
                    .entries
                    .lock()
                    .expect("async host backend lock poisoned")
                    .get(&(namespace.to_owned(), key.to_owned()))
                    .cloned())
            })
        }

        fn delete<'a>(&'a self, namespace: &'a str, key: &'a str) -> StorageHostFuture<'a, bool> {
            Box::pin(async move {
                Ok(self
                    .entries
                    .lock()
                    .expect("async host backend lock poisoned")
                    .remove(&(namespace.to_owned(), key.to_owned()))
                    .is_some())
            })
        }

        fn list_keys<'a>(&'a self, namespace: &'a str) -> StorageHostFuture<'a, Vec<String>> {
            Box::pin(async move {
                let mut keys: Vec<String> = self
                    .entries
                    .lock()
                    .expect("async host backend lock poisoned")
                    .keys()
                    .filter(|(candidate_namespace, _)| candidate_namespace == namespace)
                    .map(|(_, key)| key.clone())
                    .collect();
                keys.sort();
                Ok(keys)
            })
        }

        fn clear_namespace<'a>(&'a self, namespace: &'a str) -> StorageHostFuture<'a, usize> {
            Box::pin(async move {
                let mut entries = self
                    .entries
                    .lock()
                    .expect("async host backend lock poisoned");
                let initial_len = entries.len();
                entries.retain(|(candidate_namespace, _), _| candidate_namespace != namespace);
                Ok(initial_len.saturating_sub(entries.len()))
            })
        }
    }

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
        assert_eq!(event.reason_code, StorageEventReasonCode::Allowed);
        assert_eq!(event.namespace_label, "namespace[len:15]");
        assert_eq!(event.key_label.as_deref(), Some("key[len:10]"));
        assert_eq!(event.value_len, None);
    }

    #[test]
    fn adapter_records_denied_reason_code_for_policy_error() {
        let mut adapter = BrowserStorageAdapter::new(storage_cap_with_defaults());
        let result = adapter.clear_namespace(StorageBackend::IndexedDb, "session:v1");
        assert_eq!(
            result,
            Err(BrowserStorageError::Policy(
                StoragePolicyError::NamespaceDenied("session:v1".to_owned())
            ))
        );

        let event = adapter.events().last().expect("event should exist");
        assert_eq!(event.outcome, StorageEventOutcome::Denied);
        assert_eq!(event.reason_code, StorageEventReasonCode::NamespaceDenied);
    }

    #[test]
    fn adapter_backend_unavailable_is_deterministic_and_traced() {
        let mut adapter = BrowserStorageAdapter::new(storage_cap_with_defaults());
        adapter.set_backend_available(StorageBackend::IndexedDb, false);

        let result = adapter.set(
            StorageBackend::IndexedDb,
            "cache:user:1",
            "token",
            b"abc".to_vec(),
        );
        assert_eq!(
            result,
            Err(BrowserStorageError::BackendUnavailable(
                StorageBackend::IndexedDb
            ))
        );

        let event = adapter.events().last().expect("event should exist");
        assert_eq!(event.outcome, StorageEventOutcome::Denied);
        assert_eq!(
            event.reason_code,
            StorageEventReasonCode::BackendUnavailable
        );
    }

    #[test]
    fn adapter_eventual_list_is_stale_then_converges() {
        let cap = BrowserStorageIoCap::new(
            StorageAuthority::deny_all()
                .grant_backend(StorageBackend::IndexedDb)
                .grant_namespace("cache:*")
                .grant_operation(StorageOperation::Get)
                .grant_operation(StorageOperation::Set)
                .grant_operation(StorageOperation::Delete)
                .grant_operation(StorageOperation::ListKeys),
            StorageQuotaPolicy::default(),
            StorageConsistencyPolicy::ReadAfterWriteEventualList,
            StorageRedactionPolicy::default(),
        );
        let mut adapter = BrowserStorageAdapter::new(cap);

        adapter
            .set(
                StorageBackend::IndexedDb,
                "cache:user:7",
                "profile",
                b"v1".to_vec(),
            )
            .expect("set should succeed");
        assert_eq!(
            adapter
                .get(StorageBackend::IndexedDb, "cache:user:7", "profile")
                .expect("get should succeed"),
            Some(b"v1".to_vec())
        );

        assert_eq!(
            adapter
                .list_keys(StorageBackend::IndexedDb, "cache:user:7")
                .expect("first list should succeed"),
            Vec::<String>::new()
        );
        assert_eq!(
            adapter
                .list_keys(StorageBackend::IndexedDb, "cache:user:7")
                .expect("second list should converge"),
            vec!["profile".to_owned()]
        );

        adapter
            .delete(StorageBackend::IndexedDb, "cache:user:7", "profile")
            .expect("delete should succeed");
        assert_eq!(
            adapter
                .get(StorageBackend::IndexedDb, "cache:user:7", "profile")
                .expect("get should succeed"),
            None
        );
        assert_eq!(
            adapter
                .list_keys(StorageBackend::IndexedDb, "cache:user:7")
                .expect("first post-delete list should be stale"),
            vec!["profile".to_owned()]
        );
        assert_eq!(
            adapter
                .list_keys(StorageBackend::IndexedDb, "cache:user:7")
                .expect("second post-delete list should converge"),
            Vec::<String>::new()
        );
    }

    #[test]
    fn adapter_flush_namespace_list_view_forces_convergence() {
        let cap = BrowserStorageIoCap::new(
            StorageAuthority::deny_all()
                .grant_backend(StorageBackend::IndexedDb)
                .grant_namespace("cache:*")
                .grant_operation(StorageOperation::ListKeys)
                .grant_operation(StorageOperation::Set),
            StorageQuotaPolicy::default(),
            StorageConsistencyPolicy::ReadAfterWriteEventualList,
            StorageRedactionPolicy::default(),
        );
        let mut adapter = BrowserStorageAdapter::new(cap);
        adapter
            .set(
                StorageBackend::IndexedDb,
                "cache:user:9",
                "profile",
                b"v2".to_vec(),
            )
            .expect("set should succeed");

        adapter.flush_namespace_list_view(StorageBackend::IndexedDb, "cache:user:9");
        assert_eq!(
            adapter
                .list_keys(StorageBackend::IndexedDb, "cache:user:9")
                .expect("list should succeed"),
            vec!["profile".to_owned()]
        );
    }

    #[test]
    fn adapter_clear_namespace_updates_used_bytes() {
        let mut adapter = BrowserStorageAdapter::new(storage_cap_with_defaults());
        adapter
            .set(
                StorageBackend::IndexedDb,
                "cache:user:42",
                "a",
                b"12".to_vec(),
            )
            .expect("set should succeed");
        adapter
            .set(
                StorageBackend::IndexedDb,
                "cache:user:42",
                "b",
                b"123".to_vec(),
            )
            .expect("set should succeed");
        assert!(adapter.used_bytes() > 0);

        let removed = adapter
            .clear_namespace(StorageBackend::IndexedDb, "cache:user:42")
            .expect("clear should succeed");
        assert_eq!(removed, 2);
        assert_eq!(adapter.entry_count(), 0);
        assert_eq!(adapter.used_bytes(), 0);
    }

    #[test]
    fn adapter_routes_local_storage_operations_through_registered_host_backend() {
        let host_backend = Arc::new(MockHostBackend::default());
        let mut adapter = BrowserStorageAdapter::new(storage_cap_with_defaults());
        adapter.register_host_backend(StorageBackend::LocalStorage, host_backend.clone());

        adapter
            .set(
                StorageBackend::LocalStorage,
                "prefs:v1",
                "theme",
                b"dark".to_vec(),
            )
            .expect("host-backed set should succeed");
        assert_eq!(
            host_backend
                .get("prefs:v1", "theme")
                .expect("host-backed get should succeed"),
            Some(b"dark".to_vec())
        );

        let listed = adapter
            .list_keys(StorageBackend::LocalStorage, "prefs:v1")
            .expect("host-backed list should succeed");
        assert_eq!(listed, vec!["theme".to_owned()]);

        let removed = adapter
            .delete(StorageBackend::LocalStorage, "prefs:v1", "theme")
            .expect("host-backed delete should succeed");
        assert!(removed);
        assert_eq!(
            host_backend
                .get("prefs:v1", "theme")
                .expect("host-backed get should succeed"),
            None
        );
    }

    #[test]
    fn adapter_records_host_backend_failures_with_deterministic_reason_code() {
        let mut adapter = BrowserStorageAdapter::new(storage_cap_with_defaults());
        adapter.register_host_backend(StorageBackend::LocalStorage, Arc::new(FailingHostBackend));

        let result = adapter.set(
            StorageBackend::LocalStorage,
            "prefs:v1",
            "theme",
            b"light".to_vec(),
        );
        assert!(matches!(
            result,
            Err(BrowserStorageError::HostBackend {
                backend: StorageBackend::LocalStorage,
                operation: StorageOperation::Set,
                ..
            })
        ));

        let event = adapter.events().last().expect("event should exist");
        assert_eq!(event.outcome, StorageEventOutcome::Denied);
        assert_eq!(event.reason_code, StorageEventReasonCode::HostBackendError);
    }

    #[test]
    fn sync_methods_fail_closed_for_async_only_backends() {
        let mut adapter = BrowserStorageAdapter::new(storage_cap_with_defaults());
        adapter.register_async_host_backend(
            StorageBackend::IndexedDb,
            Arc::new(MockAsyncHostBackend::default()),
        );

        let result = adapter.set(
            StorageBackend::IndexedDb,
            "cache:user:42",
            "profile",
            b"v1".to_vec(),
        );
        assert!(matches!(
            result,
            Err(BrowserStorageError::HostBackend {
                backend: StorageBackend::IndexedDb,
                operation: StorageOperation::Set,
                message,
            }) if message.contains("requires async browser storage adapter methods")
        ));
        assert_eq!(adapter.entry_count(), 0);
    }

    #[test]
    fn async_host_backend_round_trip_is_deterministic() {
        let async_backend = Arc::new(MockAsyncHostBackend::default());
        let mut adapter = BrowserStorageAdapter::new(storage_cap_with_defaults());
        adapter.register_async_host_backend(StorageBackend::IndexedDb, async_backend.clone());

        futures_lite::future::block_on(async {
            adapter
                .set_async(
                    StorageBackend::IndexedDb,
                    "cache:user:11",
                    "profile",
                    b"v1".to_vec(),
                )
                .await
                .expect("async set should succeed");

            assert_eq!(
                async_backend
                    .get("cache:user:11", "profile")
                    .await
                    .expect("async host get should succeed"),
                Some(b"v1".to_vec())
            );
            assert_eq!(
                adapter
                    .get_async(StorageBackend::IndexedDb, "cache:user:11", "profile")
                    .await
                    .expect("async get should succeed"),
                Some(b"v1".to_vec())
            );
            assert_eq!(
                adapter
                    .list_keys_async(StorageBackend::IndexedDb, "cache:user:11")
                    .await
                    .expect("async list should succeed"),
                vec!["profile".to_owned()]
            );
            assert!(
                adapter
                    .delete_async(StorageBackend::IndexedDb, "cache:user:11", "profile")
                    .await
                    .expect("async delete should succeed")
            );
            assert_eq!(
                adapter
                    .get_async(StorageBackend::IndexedDb, "cache:user:11", "profile")
                    .await
                    .expect("async get should succeed"),
                None
            );
        });
    }

    #[test]
    fn async_host_backend_eventual_list_is_stale_then_converges() {
        let cap = BrowserStorageIoCap::new(
            StorageAuthority::deny_all()
                .grant_backend(StorageBackend::IndexedDb)
                .grant_namespace("cache:*")
                .grant_operation(StorageOperation::Get)
                .grant_operation(StorageOperation::Set)
                .grant_operation(StorageOperation::Delete)
                .grant_operation(StorageOperation::ListKeys),
            StorageQuotaPolicy::default(),
            StorageConsistencyPolicy::ReadAfterWriteEventualList,
            StorageRedactionPolicy::default(),
        );
        let mut adapter = BrowserStorageAdapter::new(cap);
        adapter.register_async_host_backend(
            StorageBackend::IndexedDb,
            Arc::new(MockAsyncHostBackend::default()),
        );

        futures_lite::future::block_on(async {
            adapter
                .set_async(
                    StorageBackend::IndexedDb,
                    "cache:user:13",
                    "profile",
                    b"v2".to_vec(),
                )
                .await
                .expect("async set should succeed");

            assert_eq!(
                adapter
                    .list_keys_async(StorageBackend::IndexedDb, "cache:user:13")
                    .await
                    .expect("first async list should succeed"),
                Vec::<String>::new()
            );
            assert_eq!(
                adapter
                    .list_keys_async(StorageBackend::IndexedDb, "cache:user:13")
                    .await
                    .expect("second async list should converge"),
                vec!["profile".to_owned()]
            );

            adapter
                .delete_async(StorageBackend::IndexedDb, "cache:user:13", "profile")
                .await
                .expect("async delete should succeed");

            assert_eq!(
                adapter
                    .list_keys_async(StorageBackend::IndexedDb, "cache:user:13")
                    .await
                    .expect("first post-delete async list should be stale"),
                vec!["profile".to_owned()]
            );
            assert_eq!(
                adapter
                    .list_keys_async(StorageBackend::IndexedDb, "cache:user:13")
                    .await
                    .expect("second post-delete async list should converge"),
                Vec::<String>::new()
            );
        });
    }
}
