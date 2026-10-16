    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::io::cap::{
        StorageAuthority, StorageConsistencyPolicy, StorageOperation, StorageQuotaPolicy,
        StorageRedactionPolicy,
    };
    use std::sync::Mutex;
    use std::task::{Context, Poll};

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

    #[derive(Debug)]
    struct PendingAsyncHostBackend;

    impl AsyncStorageHostBackend for PendingAsyncHostBackend {
        fn set<'a>(
            &'a self,
            _namespace: &'a str,
            _key: &'a str,
            _value: &'a [u8],
        ) -> StorageHostFuture<'a, ()> {
            Box::pin(std::future::pending())
        }

        fn get<'a>(
            &'a self,
            _namespace: &'a str,
            _key: &'a str,
        ) -> StorageHostFuture<'a, Option<Vec<u8>>> {
            Box::pin(std::future::pending())
        }

        fn delete<'a>(&'a self, _namespace: &'a str, _key: &'a str) -> StorageHostFuture<'a, bool> {
            Box::pin(std::future::pending())
        }

        fn list_keys<'a>(&'a self, _namespace: &'a str) -> StorageHostFuture<'a, Vec<String>> {
            Box::pin(std::future::pending())
        }

        fn clear_namespace<'a>(&'a self, _namespace: &'a str) -> StorageHostFuture<'a, usize> {
            Box::pin(std::future::pending())
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

    fn storage_cap_with_quota(quota: StorageQuotaPolicy) -> BrowserStorageIoCap {
        BrowserStorageIoCap::new(
            StorageAuthority::deny_all()
                .grant_backend(StorageBackend::IndexedDb)
                .grant_backend(StorageBackend::LocalStorage)
                .grant_namespace("cache:*")
                .grant_operation(StorageOperation::Get)
                .grant_operation(StorageOperation::Set),
            quota,
            StorageConsistencyPolicy::ImmediateReadAfterWrite,
            StorageRedactionPolicy::default(),
        )
    }

    fn quota(
        max_total_bytes: usize,
        max_value_bytes: usize,
        max_entries: usize,
    ) -> StorageQuotaPolicy {
        StorageQuotaPolicy {
            max_total_bytes,
            max_key_bytes: 16,
            max_value_bytes,
            max_namespace_bytes: 16,
            max_entries,
        }
    }

    fn cached_value<'a>(
        adapter: &'a BrowserStorageAdapter,
        backend: StorageBackend,
        namespace: &str,
        key: &str,
    ) -> Option<&'a [u8]> {
        adapter
            .entries
            .get(&StorageKey {
                backend,
                namespace: namespace.to_owned(),
                key: key.to_owned(),
            })
            .map(Vec::as_slice)
    }

    fn assert_one_terminal_event_since(
        adapter: &BrowserStorageAdapter,
        before: usize,
        outcome: StorageEventOutcome,
        reason_code: StorageEventReasonCode,
    ) {
        assert_eq!(adapter.events().len(), before + 1);
        let event = &adapter.events()[before];
        assert_eq!(event.outcome, outcome);
        assert_eq!(event.reason_code, reason_code);
    }

    #[test]
    fn sync_operations_emit_one_terminal_success_event_each() {
        let mut adapter = BrowserStorageAdapter::new(storage_cap_with_defaults());
        const BACKEND: StorageBackend = StorageBackend::LocalStorage;
        const NAMESPACE: &str = "prefs:v1";

        adapter
            .set(BACKEND, NAMESPACE, "theme", b"dark".to_vec())
            .expect("set succeeds");
        adapter
            .get(BACKEND, NAMESPACE, "theme")
            .expect("get succeeds");
        adapter
            .list_keys(BACKEND, NAMESPACE)
            .expect("list succeeds");
        adapter
            .delete(BACKEND, NAMESPACE, "theme")
            .expect("delete succeeds");
        adapter
            .clear_namespace(BACKEND, NAMESPACE)
            .expect("clear succeeds");

        assert_eq!(adapter.events().len(), 5);
        assert!(adapter.events().iter().all(|event| {
            event.outcome == StorageEventOutcome::Allowed
                && event.reason_code == StorageEventReasonCode::Allowed
        }));
    }

    #[test]
    fn async_fallback_emits_one_terminal_event_per_result() {
        futures_lite::future::block_on(async {
            let mut adapter = BrowserStorageAdapter::new(storage_cap_with_defaults());
            let before = adapter.events().len();
            adapter
                .set_async(
                    StorageBackend::LocalStorage,
                    "prefs:v1",
                    "theme",
                    b"dark".to_vec(),
                )
                .await
                .expect("sync fallback succeeds");
            assert_one_terminal_event_since(
                &adapter,
                before,
                StorageEventOutcome::Allowed,
                StorageEventReasonCode::Allowed,
            );

            let before = adapter.events().len();
            let result = adapter
                .set_async(
                    StorageBackend::LocalStorage,
                    "prefs:v1",
                    "oversized",
                    vec![0; 129],
                )
                .await;
            assert!(matches!(
                result,
                Err(BrowserStorageError::Policy(
                    StoragePolicyError::ValueTooLarge { .. }
                ))
            ));
            assert_one_terminal_event_since(
                &adapter,
                before,
                StorageEventOutcome::Denied,
                StorageEventReasonCode::ValueTooLarge,
            );
        });
    }

    #[test]
    fn dropped_async_operations_emit_no_terminal_event() {
        let mut never_polled = BrowserStorageAdapter::new(storage_cap_with_defaults());
        let future = never_polled.set_async(
            StorageBackend::LocalStorage,
            "prefs:v1",
            "theme",
            b"dark".to_vec(),
        );
        drop(future);
        assert!(never_polled.events().is_empty());

        let mut pending = BrowserStorageAdapter::new(storage_cap_with_defaults());
        pending.register_async_host_backend(
            StorageBackend::IndexedDb,
            Arc::new(PendingAsyncHostBackend),
        );
        let mut future = Box::pin(pending.set_async(
            StorageBackend::IndexedDb,
            "cache:user:1",
            "profile",
            b"v1".to_vec(),
        ));
        let mut task_cx = Context::from_waker(std::task::Waker::noop());
        assert!(matches!(future.as_mut().poll(&mut task_cx), Poll::Pending));
        drop(future);
        assert!(pending.events().is_empty());
    }

    #[test]
    fn host_get_quota_contract_sync() {
        const BACKEND: StorageBackend = StorageBackend::LocalStorage;
        const NAMESPACE: &str = "cache:n";

        let oversized_host = Arc::new(MockHostBackend::default());
        oversized_host
            .set(NAMESPACE, "a", b"12345")
            .expect("seed oversized host value");
        let mut oversized = BrowserStorageAdapter::new(storage_cap_with_quota(quota(64, 4, 1)));
        oversized
            .set(BACKEND, NAMESPACE, "a", b"ok".to_vec())
            .expect("seed prior cached value");
        let prior_bytes = oversized.used_bytes();
        oversized.register_host_backend(BACKEND, oversized_host);

        assert_eq!(
            oversized.get(BACKEND, NAMESPACE, "a"),
            Err(BrowserStorageError::Policy(
                StoragePolicyError::ValueTooLarge { len: 5, limit: 4 }
            ))
        );
        assert_eq!(
            cached_value(&oversized, BACKEND, NAMESPACE, "a"),
            Some(&b"ok"[..])
        );
        assert_eq!(oversized.used_bytes(), prior_bytes);
        assert_eq!(oversized.entry_count(), 1);
        let event = oversized.events().last().expect("oversized denial event");
        assert_eq!(event.outcome, StorageEventOutcome::Denied);
        assert_eq!(event.reason_code, StorageEventReasonCode::ValueTooLarge);
        assert_eq!(event.value_len, Some(5));

        let entry_host = Arc::new(MockHostBackend::default());
        entry_host
            .set(NAMESPACE, "b", b"yy")
            .expect("seed second host entry");
        let mut entries = BrowserStorageAdapter::new(storage_cap_with_quota(quota(64, 8, 1)));
        entries
            .set(BACKEND, NAMESPACE, "a", b"x".to_vec())
            .expect("seed first cached entry");
        let prior_bytes = entries.used_bytes();
        entries.register_host_backend(BACKEND, entry_host);

        assert_eq!(
            entries.get(BACKEND, NAMESPACE, "b"),
            Err(BrowserStorageError::Policy(
                StoragePolicyError::EntryCountExceeded {
                    projected: 2,
                    limit: 1,
                }
            ))
        );
        assert_eq!(
            cached_value(&entries, BACKEND, NAMESPACE, "a"),
            Some(&b"x"[..])
        );
        assert_eq!(cached_value(&entries, BACKEND, NAMESPACE, "b"), None);
        assert_eq!(entries.used_bytes(), prior_bytes);
        let event = entries.events().last().expect("entry denial event");
        assert_eq!(
            event.reason_code,
            StorageEventReasonCode::EntryCountExceeded
        );
        assert_eq!(event.value_len, Some(2));

        let total_host = Arc::new(MockHostBackend::default());
        total_host
            .set(NAMESPACE, "b", b"y")
            .expect("seed quota host entry");
        let mut total = BrowserStorageAdapter::new(storage_cap_with_quota(quota(17, 8, 2)));
        total
            .set(BACKEND, NAMESPACE, "a", b"x".to_vec())
            .expect("seed cached quota entry");
        let prior_bytes = total.used_bytes();
        total.register_host_backend(BACKEND, total_host);

        assert_eq!(
            total.get(BACKEND, NAMESPACE, "b"),
            Err(BrowserStorageError::Policy(
                StoragePolicyError::QuotaExceeded {
                    projected_bytes: 18,
                    limit_bytes: 17,
                }
            ))
        );
        assert_eq!(
            cached_value(&total, BACKEND, NAMESPACE, "a"),
            Some(&b"x"[..])
        );
        assert_eq!(cached_value(&total, BACKEND, NAMESPACE, "b"), None);
        assert_eq!(total.used_bytes(), prior_bytes);
        let event = total.events().last().expect("total quota denial event");
        assert_eq!(event.reason_code, StorageEventReasonCode::QuotaExceeded);
        assert_eq!(event.value_len, Some(1));

        let boundary_host = Arc::new(MockHostBackend::default());
        boundary_host
            .set(NAMESPACE, "a", b"1234")
            .expect("seed boundary host value");
        let mut boundary = BrowserStorageAdapter::new(storage_cap_with_quota(quota(12, 4, 1)));
        boundary
            .set(BACKEND, NAMESPACE, "a", b"12".to_vec())
            .expect("seed replacement cache value");
        boundary.register_host_backend(
            BACKEND,
            Arc::clone(&boundary_host) as Arc<dyn StorageHostBackend>,
        );

        assert_eq!(
            boundary
                .get(BACKEND, NAMESPACE, "a")
                .expect("exact-boundary host read"),
            Some(b"1234".to_vec())
        );
        assert_eq!(boundary.entry_count(), 1);
        assert_eq!(boundary.used_bytes(), 12);
        assert_eq!(
            cached_value(&boundary, BACKEND, NAMESPACE, "a"),
            Some(&b"1234"[..])
        );

        boundary_host
            .delete(NAMESPACE, "a")
            .expect("delete host value");
        assert_eq!(
            boundary
                .get(BACKEND, NAMESPACE, "a")
                .expect("host absence must be observed"),
            None
        );
        assert_eq!(boundary.entry_count(), 0);
        assert_eq!(boundary.used_bytes(), 0);

        boundary_host
            .set(NAMESPACE, "a", b"")
            .expect("seed empty host value");
        assert_eq!(
            boundary
                .get(BACKEND, NAMESPACE, "a")
                .expect("empty host value must be observed"),
            Some(Vec::new())
        );
        assert_eq!(boundary.entry_count(), 1);
        assert_eq!(boundary.used_bytes(), entry_size(NAMESPACE, "a", 0));
        assert_eq!(
            cached_value(&boundary, BACKEND, NAMESPACE, "a"),
            Some(&b""[..])
        );
    }

    #[test]
    fn host_get_quota_contract_async() {
        const BACKEND: StorageBackend = StorageBackend::IndexedDb;
        const NAMESPACE: &str = "cache:n";

        futures_lite::future::block_on(async {
            let oversized_host = Arc::new(MockAsyncHostBackend::default());
            oversized_host
                .set(NAMESPACE, "a", b"12345")
                .await
                .expect("seed oversized async host value");
            let mut oversized = BrowserStorageAdapter::new(storage_cap_with_quota(quota(64, 4, 1)));
            oversized
                .set(BACKEND, NAMESPACE, "a", b"ok".to_vec())
                .expect("seed prior cached value");
            let prior_bytes = oversized.used_bytes();
            oversized.register_async_host_backend(BACKEND, oversized_host);

            assert_eq!(
                oversized.get_async(BACKEND, NAMESPACE, "a").await,
                Err(BrowserStorageError::Policy(
                    StoragePolicyError::ValueTooLarge { len: 5, limit: 4 }
                ))
            );
            assert_eq!(
                cached_value(&oversized, BACKEND, NAMESPACE, "a"),
                Some(&b"ok"[..])
            );
            assert_eq!(oversized.used_bytes(), prior_bytes);
            assert_eq!(oversized.entry_count(), 1);
            let event = oversized.events().last().expect("oversized denial event");
            assert_eq!(event.outcome, StorageEventOutcome::Denied);
            assert_eq!(event.reason_code, StorageEventReasonCode::ValueTooLarge);
            assert_eq!(event.value_len, Some(5));

            let entry_host = Arc::new(MockAsyncHostBackend::default());
            entry_host
                .set(NAMESPACE, "b", b"yy")
                .await
                .expect("seed second async host entry");
            let mut entries = BrowserStorageAdapter::new(storage_cap_with_quota(quota(64, 8, 1)));
            entries
                .set(BACKEND, NAMESPACE, "a", b"x".to_vec())
                .expect("seed first cached entry");
            let prior_bytes = entries.used_bytes();
            entries.register_async_host_backend(BACKEND, entry_host);

            assert_eq!(
                entries.get_async(BACKEND, NAMESPACE, "b").await,
                Err(BrowserStorageError::Policy(
                    StoragePolicyError::EntryCountExceeded {
                        projected: 2,
                        limit: 1,
                    }
                ))
            );
            assert_eq!(
                cached_value(&entries, BACKEND, NAMESPACE, "a"),
                Some(&b"x"[..])
            );
            assert_eq!(cached_value(&entries, BACKEND, NAMESPACE, "b"), None);
            assert_eq!(entries.used_bytes(), prior_bytes);
            let event = entries.events().last().expect("entry denial event");
            assert_eq!(
                event.reason_code,
                StorageEventReasonCode::EntryCountExceeded
            );
            assert_eq!(event.value_len, Some(2));

            let total_host = Arc::new(MockAsyncHostBackend::default());
            total_host
                .set(NAMESPACE, "b", b"y")
                .await
                .expect("seed async quota host entry");
            let mut total = BrowserStorageAdapter::new(storage_cap_with_quota(quota(17, 8, 2)));
            total
                .set(BACKEND, NAMESPACE, "a", b"x".to_vec())
                .expect("seed cached quota entry");
            let prior_bytes = total.used_bytes();
            total.register_async_host_backend(BACKEND, total_host);

            assert_eq!(
                total.get_async(BACKEND, NAMESPACE, "b").await,
                Err(BrowserStorageError::Policy(
                    StoragePolicyError::QuotaExceeded {
                        projected_bytes: 18,
                        limit_bytes: 17,
                    }
                ))
            );
            assert_eq!(
                cached_value(&total, BACKEND, NAMESPACE, "a"),
                Some(&b"x"[..])
            );
            assert_eq!(cached_value(&total, BACKEND, NAMESPACE, "b"), None);
            assert_eq!(total.used_bytes(), prior_bytes);
            let event = total.events().last().expect("total quota denial event");
            assert_eq!(event.reason_code, StorageEventReasonCode::QuotaExceeded);
            assert_eq!(event.value_len, Some(1));

            let boundary_host = Arc::new(MockAsyncHostBackend::default());
            boundary_host
                .set(NAMESPACE, "a", b"1234")
                .await
                .expect("seed boundary async host value");
            let mut boundary = BrowserStorageAdapter::new(storage_cap_with_quota(quota(12, 4, 1)));
            boundary
                .set(BACKEND, NAMESPACE, "a", b"12".to_vec())
                .expect("seed replacement cache value");
            boundary.register_async_host_backend(
                BACKEND,
                Arc::clone(&boundary_host) as Arc<dyn AsyncStorageHostBackend>,
            );

            assert_eq!(
                boundary
                    .get_async(BACKEND, NAMESPACE, "a")
                    .await
                    .expect("exact-boundary async host read"),
                Some(b"1234".to_vec())
            );
            assert_eq!(boundary.entry_count(), 1);
            assert_eq!(boundary.used_bytes(), 12);
            assert_eq!(
                cached_value(&boundary, BACKEND, NAMESPACE, "a"),
                Some(&b"1234"[..])
            );

            boundary_host
                .delete(NAMESPACE, "a")
                .await
                .expect("delete async host value");
            assert_eq!(
                boundary
                    .get_async(BACKEND, NAMESPACE, "a")
                    .await
                    .expect("async host absence must be observed"),
                None
            );
            assert_eq!(boundary.entry_count(), 0);
            assert_eq!(boundary.used_bytes(), 0);

            boundary_host
                .set(NAMESPACE, "a", b"")
                .await
                .expect("seed empty async host value");
            assert_eq!(
                boundary
                    .get_async(BACKEND, NAMESPACE, "a")
                    .await
                    .expect("empty async host value must be observed"),
                Some(Vec::new())
            );
            assert_eq!(boundary.entry_count(), 1);
            assert_eq!(boundary.used_bytes(), entry_size(NAMESPACE, "a", 0));
            assert_eq!(
                cached_value(&boundary, BACKEND, NAMESPACE, "a"),
                Some(&b""[..])
            );
        });
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
        assert_eq!(
            adapter.events().len(),
            1,
            "host failure is one terminal event"
        );
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
        assert_eq!(
            adapter.events().len(),
            1,
            "sync/async mismatch is one terminal event"
        );
        assert_eq!(adapter.events()[0].outcome, StorageEventOutcome::Denied);
        assert_eq!(
            adapter.events()[0].reason_code,
            StorageEventReasonCode::HostBackendError
        );
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
            assert_eq!(
                adapter
                    .clear_namespace_async(StorageBackend::IndexedDb, "cache:user:11")
                    .await
                    .expect("async clear should succeed"),
                0
            );
            assert_eq!(adapter.events().len(), 6);
            assert!(adapter.events().iter().all(|event| {
                event.outcome == StorageEventOutcome::Allowed
                    && event.reason_code == StorageEventReasonCode::Allowed
            }));
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
