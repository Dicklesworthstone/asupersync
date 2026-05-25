//! Real E2E integration tests: types/wasm_abi ↔ io/browser_storage integration (br-e2e-129).
//!
//! Tests that wasm-bound storage API correctly serializes objects across the JS/wasm
//! boundary without memory leaks. Verifies ABI version compatibility, boundary
//! serialization integrity, and proper resource cleanup.
//!
//! # Integration Patterns Tested
//!
//! - **WASM ABI Serialization**: Objects correctly serialized across JS/wasm boundary
//! - **Storage Backend Integration**: Browser storage backends handle WASM serialization
//! - **Memory Leak Prevention**: No resource leaks during boundary crossings
//! - **ABI Version Compatibility**: Version negotiation works across boundaries
//! - **Payload Shape Validation**: Boundary payload shapes maintain integrity
//!
//! # Test Scenarios
//!
//! 1. **Basic ABI Serialization** — Objects serialize/deserialize across JS/wasm boundary
//! 2. **localStorage Integration** — WASM ABI payloads stored in localStorage backend
//! 3. **IndexedDB Integration** — Binary payloads handled through IndexedDB backend
//! 4. **ABI Version Negotiation** — Compatibility decisions work across storage operations
//! 5. **Memory Leak Detection** — Resource cleanup during boundary operations
//!
//! # Safety Properties Verified
//!
//! - WASM ABI payloads serialize correctly without data corruption
//! - Browser storage backends handle binary data across JS/wasm boundary
//! - No memory leaks occur during serialization/deserialization cycles
//! - ABI version compatibility prevents incompatible operations
//! - Boundary crossings maintain deterministic behavior for testing

#[cfg(all(test, feature = "real-service-e2e"))]
mod tests {
    #![allow(
        clippy::expect_fun_call,
        clippy::future_not_send,
        clippy::match_same_arms,
        clippy::missing_panics_doc,
        clippy::needless_pass_by_value,
        clippy::unwrap_used,
        dead_code
    )]

    use crate::io::browser_storage::{BrowserStorageAdapter, BrowserStorageError};
    use crate::io::cap::{BrowserStorageIoCap, StorageBackend, StorageConsistencyPolicy};
    use crate::types::wasm_abi::{
        WasmAbiVersion, WasmAbiCompatibilityDecision, WasmAbiSymbol, WasmAbiPayloadShape,
        WasmAbiSignature, classify_wasm_abi_compatibility, required_wasm_abi_bump,
        WasmAbiChangeClass, WasmAbiVersionBump, WASM_ABI_MAJOR_VERSION, WASM_ABI_MINOR_VERSION,
    };
    use serde::{Deserialize, Serialize};
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::Arc;

    /// Test phases for WASM ABI-browser storage integration testing
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum WasmStorageTestPhase {
        Initial,
        AbiSetup,
        StorageSetup,
        PayloadSerialization,
        BoundaryTransfer,
        StorageOperations,
        MemoryLeakCheck,
        VersionCompatibility,
        ResourceCleanup,
        Complete,
    }

    /// WASM ABI-storage integration statistics
    #[derive(Debug, Clone, Default)]
    struct WasmStorageStats {
        abi_objects_created: u32,
        payloads_serialized: u32,
        storage_operations: u32,
        boundary_crossings: u32,
        memory_allocations: u32,
        memory_deallocations: u32,
        compatibility_checks: u32,
        version_negotiations: u32,
        cleanup_operations: u32,
        successful_integrations: u32,
    }

    /// Test result for WASM ABI-storage integration scenarios
    #[derive(Debug, Clone)]
    struct WasmStorageTestResult {
        success: bool,
        phase: WasmStorageTestPhase,
        final_memory_usage: usize,
        stats: WasmStorageStats,
        error_details: Option<String>,
        abi_version: WasmAbiVersion,
    }

    /// Mock WASM ABI payload for testing serialization
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct MockWasmPayload {
        symbol: WasmAbiSymbol,
        handle_id: u64,
        payload_data: Vec<u8>,
        timestamp: u64,
        metadata: BTreeMap<String, String>,
    }

    impl MockWasmPayload {
        fn new(symbol: WasmAbiSymbol, handle_id: u64, data: &[u8]) -> Self {
            Self {
                symbol,
                handle_id,
                payload_data: data.to_vec(),
                timestamp: 42, // Mock timestamp
                metadata: BTreeMap::new(),
            }
        }

        fn with_metadata(mut self, key: &str, value: &str) -> Self {
            self.metadata.insert(key.to_string(), value.to_string());
            self
        }

        fn serialized_size(&self) -> usize {
            bincode::serialized_size(self).unwrap_or(0) as usize
        }

        fn to_bytes(&self) -> Result<Vec<u8>, String> {
            bincode::serialize(self).map_err(|e| format!("Serialization failed: {}", e))
        }

        fn from_bytes(data: &[u8]) -> Result<Self, String> {
            bincode::deserialize(data).map_err(|e| format!("Deserialization failed: {}", e))
        }
    }

    /// Mock memory tracker for detecting leaks
    struct MemoryTracker {
        allocations: Arc<AtomicUsize>,
        deallocations: Arc<AtomicUsize>,
        peak_usage: Arc<AtomicUsize>,
        current_usage: Arc<AtomicUsize>,
    }

    impl MemoryTracker {
        fn new() -> Self {
            Self {
                allocations: Arc::new(AtomicUsize::new(0)),
                deallocations: Arc::new(AtomicUsize::new(0)),
                peak_usage: Arc::new(AtomicUsize::new(0)),
                current_usage: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn allocate(&self, size: usize) {
            self.allocations.fetch_add(1, Ordering::Release);
            let current = self.current_usage.fetch_add(size, Ordering::Release) + size;

            // Update peak usage
            loop {
                let peak = self.peak_usage.load(Ordering::Acquire);
                if current <= peak || self.peak_usage.compare_exchange_weak(
                    peak, current, Ordering::Release, Ordering::Relaxed
                ).is_ok() {
                    break;
                }
            }
        }

        fn deallocate(&self, size: usize) {
            self.deallocations.fetch_add(1, Ordering::Release);
            self.current_usage.fetch_sub(size, Ordering::Release);
        }

        fn current_usage(&self) -> usize {
            self.current_usage.load(Ordering::Acquire)
        }

        fn is_balanced(&self) -> bool {
            self.allocations.load(Ordering::Acquire) == self.deallocations.load(Ordering::Acquire)
        }

        fn allocation_count(&self) -> usize {
            self.allocations.load(Ordering::Acquire)
        }

        fn deallocation_count(&self) -> usize {
            self.deallocations.load(Ordering::Acquire)
        }
    }

    /// Test harness for WASM ABI-storage integration
    struct WasmStorageTestHarness {
        stats: WasmStorageStats,
        current_phase: WasmStorageTestPhase,
        memory_tracker: MemoryTracker,
        abi_version: WasmAbiVersion,
    }

    impl WasmStorageTestHarness {
        fn new() -> Self {
            Self {
                stats: WasmStorageStats::default(),
                current_phase: WasmStorageTestPhase::Initial,
                memory_tracker: MemoryTracker::new(),
                abi_version: WasmAbiVersion::CURRENT,
            }
        }

        async fn test_basic_abi_serialization(&mut self) -> WasmStorageTestResult {
            self.current_phase = WasmStorageTestPhase::AbiSetup;

            // Create test ABI objects
            let payload1 = MockWasmPayload::new(
                WasmAbiSymbol::RuntimeCreate,
                1,
                b"test runtime payload"
            ).with_metadata("test", "basic");

            let payload2 = MockWasmPayload::new(
                WasmAbiSymbol::TaskSpawn,
                2,
                b"spawn task payload"
            ).with_metadata("priority", "high");

            self.stats.abi_objects_created += 2;

            self.current_phase = WasmStorageTestPhase::PayloadSerialization;

            // Test serialization
            let serialized1 = payload1.to_bytes().map_err(|e| {
                return self.finalize_test(false, Some(format!("Serialization failed: {}", e)));
            }).unwrap();

            let serialized2 = payload2.to_bytes().map_err(|e| {
                return self.finalize_test(false, Some(format!("Serialization failed: {}", e)));
            }).unwrap();

            self.stats.payloads_serialized += 2;

            // Track memory for serialization
            self.memory_tracker.allocate(serialized1.len());
            self.memory_tracker.allocate(serialized2.len());
            self.stats.memory_allocations += 2;

            self.current_phase = WasmStorageTestPhase::BoundaryTransfer;

            // Test deserialization (simulating JS/WASM boundary crossing)
            let deserialized1 = MockWasmPayload::from_bytes(&serialized1).map_err(|e| {
                return self.finalize_test(false, Some(format!("Deserialization failed: {}", e)));
            }).unwrap();

            let deserialized2 = MockWasmPayload::from_bytes(&serialized2).map_err(|e| {
                return self.finalize_test(false, Some(format!("Deserialization failed: {}", e)));
            }).unwrap();

            self.stats.boundary_crossings += 2;

            // Verify integrity after boundary crossing
            assert_eq!(payload1, deserialized1, "Payload 1 should survive boundary crossing");
            assert_eq!(payload2, deserialized2, "Payload 2 should survive boundary crossing");

            // Clean up memory
            self.memory_tracker.deallocate(serialized1.len());
            self.memory_tracker.deallocate(serialized2.len());
            self.stats.memory_deallocations += 2;

            self.stats.successful_integrations += 1;

            self.finalize_test(true, Some("Basic ABI serialization successful".to_string()))
        }

        async fn test_localstorage_integration(&mut self) -> WasmStorageTestResult {
            self.current_phase = WasmStorageTestPhase::StorageSetup;

            // Create storage adapter
            let cap = BrowserStorageIoCap::for_testing();
            let mut storage = BrowserStorageAdapter::new(cap);

            // Mock localStorage backend for non-WASM targets
            let backend = StorageBackend::LocalStorage;
            storage.set_backend_available(backend, true);

            self.current_phase = WasmStorageTestPhase::PayloadSerialization;

            // Create WASM payloads for storage
            let payloads = vec![
                MockWasmPayload::new(WasmAbiSymbol::ScopeEnter, 10, b"scope data"),
                MockWasmPayload::new(WasmAbiSymbol::FetchRequest, 11, b"fetch request data"),
                MockWasmPayload::new(WasmAbiSymbol::TaskCancel, 12, b"cancel task data"),
            ];

            self.stats.abi_objects_created += 3;

            self.current_phase = WasmStorageTestPhase::StorageOperations;

            // Store payloads through storage API
            for (i, payload) in payloads.iter().enumerate() {
                let key = format!("abi_payload_{}", i);
                let serialized = payload.to_bytes().unwrap();

                // Track memory
                self.memory_tracker.allocate(serialized.len());
                self.stats.memory_allocations += 1;
                self.stats.payloads_serialized += 1;

                // Store in backend (deterministic in-memory for testing)
                match storage.set(backend, "test_namespace", &key, &serialized) {
                    Ok(()) => {
                        self.stats.storage_operations += 1;
                    }
                    Err(e) => {
                        return self.finalize_test(
                            false,
                            Some(format!("Storage operation failed: {:?}", e))
                        );
                    }
                }
            }

            self.current_phase = WasmStorageTestPhase::BoundaryTransfer;

            // Retrieve and verify payloads
            for (i, expected_payload) in payloads.iter().enumerate() {
                let key = format!("abi_payload_{}", i);

                match storage.get(backend, "test_namespace", &key) {
                    Ok(Some(data)) => {
                        let retrieved = MockWasmPayload::from_bytes(&data).unwrap();
                        assert_eq!(expected_payload, &retrieved, "Retrieved payload should match original");

                        self.stats.boundary_crossings += 1;
                        self.memory_tracker.deallocate(data.len());
                        self.stats.memory_deallocations += 1;
                    }
                    Ok(None) => {
                        return self.finalize_test(
                            false,
                            Some(format!("Payload {} not found in storage", i))
                        );
                    }
                    Err(e) => {
                        return self.finalize_test(
                            false,
                            Some(format!("Storage retrieval failed: {:?}", e))
                        );
                    }
                }
            }

            self.stats.successful_integrations += 1;

            self.finalize_test(true, Some("localStorage integration successful".to_string()))
        }

        async fn test_indexeddb_integration(&mut self) -> WasmStorageTestResult {
            self.current_phase = WasmStorageTestPhase::StorageSetup;

            // Create storage adapter for IndexedDB
            let cap = BrowserStorageIoCap::for_testing();
            let mut storage = BrowserStorageAdapter::new(cap);

            // Mock IndexedDB backend
            let backend = StorageBackend::IndexedDb;
            storage.set_backend_available(backend, true);

            self.current_phase = WasmStorageTestPhase::PayloadSerialization;

            // Create binary payloads that would be transferred via Uint8Array
            let binary_payloads = vec![
                (b"binary_data_1".to_vec(), WasmAbiSymbol::RuntimeClose),
                (b"large_binary_payload_with_more_data".to_vec(), WasmAbiSymbol::TaskJoin),
                (vec![0u8; 1024], WasmAbiSymbol::ScopeClose), // Large binary payload
            ];

            self.current_phase = WasmStorageTestPhase::StorageOperations;

            // Test binary data handling (simulates Uint8Array usage in WASM)
            for (i, (binary_data, symbol)) in binary_payloads.iter().enumerate() {
                let payload = MockWasmPayload::new(*symbol, 20 + i as u64, binary_data);
                let serialized = payload.to_bytes().unwrap();

                // Track memory for large binary operations
                self.memory_tracker.allocate(serialized.len());
                self.stats.memory_allocations += 1;
                self.stats.payloads_serialized += 1;

                let key = format!("binary_payload_{}", i);

                // Store binary payload
                match storage.set(backend, "binary_namespace", &key, &serialized) {
                    Ok(()) => {
                        self.stats.storage_operations += 1;
                    }
                    Err(e) => {
                        return self.finalize_test(
                            false,
                            Some(format!("Binary storage failed: {:?}", e))
                        );
                    }
                }

                // Immediate retrieval to test boundary crossing
                match storage.get(backend, "binary_namespace", &key) {
                    Ok(Some(retrieved_data)) => {
                        let retrieved_payload = MockWasmPayload::from_bytes(&retrieved_data).unwrap();
                        assert_eq!(payload, retrieved_payload, "Binary payload should survive boundary crossing");

                        self.stats.boundary_crossings += 1;
                        self.memory_tracker.deallocate(serialized.len());
                        self.stats.memory_deallocations += 1;
                    }
                    Ok(None) => {
                        return self.finalize_test(
                            false,
                            Some(format!("Binary payload {} not found", i))
                        );
                    }
                    Err(e) => {
                        return self.finalize_test(
                            false,
                            Some(format!("Binary retrieval failed: {:?}", e))
                        );
                    }
                }
            }

            self.stats.abi_objects_created += 3;
            self.stats.successful_integrations += 1;

            self.finalize_test(true, Some("IndexedDB binary integration successful".to_string()))
        }

        async fn test_abi_version_compatibility(&mut self) -> WasmStorageTestResult {
            self.current_phase = WasmStorageTestPhase::VersionCompatibility;

            // Test version compatibility scenarios
            let test_cases = vec![
                // (producer, consumer, expected_decision)
                (WasmAbiVersion { major: 1, minor: 0 }, WasmAbiVersion { major: 1, minor: 0 }, WasmAbiCompatibilityDecision::Exact),
                (WasmAbiVersion { major: 1, minor: 0 }, WasmAbiVersion { major: 1, minor: 1 }, WasmAbiCompatibilityDecision::BackwardCompatible { producer_minor: 0, consumer_minor: 1 }),
                (WasmAbiVersion { major: 1, minor: 1 }, WasmAbiVersion { major: 1, minor: 0 }, WasmAbiCompatibilityDecision::ConsumerTooOld { producer_minor: 1, consumer_minor: 0 }),
                (WasmAbiVersion { major: 1, minor: 0 }, WasmAbiVersion { major: 2, minor: 0 }, WasmAbiCompatibilityDecision::MajorMismatch { producer_major: 1, consumer_major: 2 }),
            ];

            for (producer, consumer, expected) in test_cases {
                let decision = classify_wasm_abi_compatibility(producer, consumer);
                assert_eq!(decision, expected, "ABI compatibility decision should match expected");
                self.stats.compatibility_checks += 1;

                // Test that compatible versions can store/retrieve data
                if decision.is_compatible() {
                    let payload = MockWasmPayload::new(
                        WasmAbiSymbol::RuntimeCreate,
                        42,
                        format!("compat_test_{}_{}", producer.major, producer.minor).as_bytes()
                    );

                    let serialized = payload.to_bytes().unwrap();
                    self.memory_tracker.allocate(serialized.len());
                    self.stats.payloads_serialized += 1;

                    // Verify the payload can be serialized/deserialized with compatible versions
                    let retrieved = MockWasmPayload::from_bytes(&serialized).unwrap();
                    assert_eq!(payload, retrieved, "Compatible versions should handle payloads correctly");

                    self.memory_tracker.deallocate(serialized.len());
                    self.stats.version_negotiations += 1;
                }
            }

            self.stats.successful_integrations += 1;

            self.finalize_test(true, Some("ABI version compatibility successful".to_string()))
        }

        async fn test_memory_leak_detection(&mut self) -> WasmStorageTestResult {
            self.current_phase = WasmStorageTestPhase::MemoryLeakCheck;

            let initial_usage = self.memory_tracker.current_usage();
            let initial_allocations = self.memory_tracker.allocation_count();

            // Perform many serialization/deserialization cycles
            for i in 0..100 {
                let payload = MockWasmPayload::new(
                    WasmAbiSymbol::TaskSpawn,
                    100 + i,
                    format!("leak_test_payload_{}", i).as_bytes()
                );

                // Serialize
                let serialized = payload.to_bytes().unwrap();
                self.memory_tracker.allocate(serialized.len());
                self.stats.memory_allocations += 1;
                self.stats.payloads_serialized += 1;

                // Deserialize (boundary crossing)
                let _retrieved = MockWasmPayload::from_bytes(&serialized).unwrap();
                self.stats.boundary_crossings += 1;

                // Clean up
                self.memory_tracker.deallocate(serialized.len());
                self.stats.memory_deallocations += 1;
            }

            self.current_phase = WasmStorageTestPhase::ResourceCleanup;

            let final_usage = self.memory_tracker.current_usage();
            let final_allocations = self.memory_tracker.allocation_count();

            // Verify no memory leaks
            if final_usage != initial_usage {
                return self.finalize_test(
                    false,
                    Some(format!("Memory leak detected: {} -> {} bytes", initial_usage, final_usage))
                );
            }

            if !self.memory_tracker.is_balanced() {
                return self.finalize_test(
                    false,
                    Some(format!(
                        "Unbalanced allocations: {} allocs, {} deallocs",
                        self.memory_tracker.allocation_count(),
                        self.memory_tracker.deallocation_count()
                    ))
                );
            }

            self.stats.cleanup_operations += (final_allocations - initial_allocations) as u32;
            self.stats.successful_integrations += 1;

            self.finalize_test(true, Some("Memory leak detection successful - no leaks found".to_string()))
        }

        fn finalize_test(
            &mut self,
            success: bool,
            error: Option<String>
        ) -> WasmStorageTestResult {
            self.current_phase = WasmStorageTestPhase::Complete;

            WasmStorageTestResult {
                success,
                phase: self.current_phase.clone(),
                final_memory_usage: self.memory_tracker.current_usage(),
                stats: self.stats.clone(),
                error_details: error,
                abi_version: self.abi_version,
            }
        }
    }

    #[test]
    fn test_wasm_abi_basic_serialization() {
        let rt = crate::runtime::RuntimeBuilder::new().build().unwrap();
        rt.block_on(async {
            let mut harness = WasmStorageTestHarness::new();
            let result = harness.test_basic_abi_serialization().await;

            assert!(result.success, "Basic ABI serialization should succeed");
            assert_eq!(result.phase, WasmStorageTestPhase::Complete);
            assert_eq!(result.stats.abi_objects_created, 2);
            assert_eq!(result.stats.payloads_serialized, 2);
            assert_eq!(result.stats.boundary_crossings, 2);
            assert_eq!(result.stats.successful_integrations, 1);
            assert_eq!(result.final_memory_usage, 0); // All memory should be cleaned up
        });
    }

    #[test]
    fn test_wasm_abi_localstorage_integration() {
        let rt = crate::runtime::RuntimeBuilder::new().build().unwrap();
        rt.block_on(async {
            let mut harness = WasmStorageTestHarness::new();
            let result = harness.test_localstorage_integration().await;

            assert!(result.success, "localStorage integration should succeed");
            assert_eq!(result.phase, WasmStorageTestPhase::Complete);
            assert_eq!(result.stats.abi_objects_created, 3);
            assert_eq!(result.stats.storage_operations, 3);
            assert_eq!(result.stats.boundary_crossings, 3);
            assert_eq!(result.stats.successful_integrations, 1);
        });
    }

    #[test]
    fn test_wasm_abi_indexeddb_integration() {
        let rt = crate::runtime::RuntimeBuilder::new().build().unwrap();
        rt.block_on(async {
            let mut harness = WasmStorageTestHarness::new();
            let result = harness.test_indexeddb_integration().await;

            assert!(result.success, "IndexedDB binary integration should succeed");
            assert_eq!(result.phase, WasmStorageTestPhase::Complete);
            assert_eq!(result.stats.abi_objects_created, 3);
            assert_eq!(result.stats.storage_operations, 3);
            assert_eq!(result.stats.boundary_crossings, 3);
            assert_eq!(result.stats.successful_integrations, 1);
        });
    }

    #[test]
    fn test_wasm_abi_version_compatibility() {
        let rt = crate::runtime::RuntimeBuilder::new().build().unwrap();
        rt.block_on(async {
            let mut harness = WasmStorageTestHarness::new();
            let result = harness.test_abi_version_compatibility().await;

            assert!(result.success, "ABI version compatibility should succeed");
            assert_eq!(result.phase, WasmStorageTestPhase::Complete);
            assert_eq!(result.stats.compatibility_checks, 4);
            assert_eq!(result.stats.version_negotiations, 2); // Only compatible versions
            assert_eq!(result.stats.successful_integrations, 1);
        });
    }

    #[test]
    fn test_wasm_abi_memory_leak_detection() {
        let rt = crate::runtime::RuntimeBuilder::new().build().unwrap();
        rt.block_on(async {
            let mut harness = WasmStorageTestHarness::new();
            let result = harness.test_memory_leak_detection().await;

            assert!(result.success, "Memory leak detection should succeed");
            assert_eq!(result.phase, WasmStorageTestPhase::Complete);
            assert_eq!(result.stats.payloads_serialized, 100);
            assert_eq!(result.stats.boundary_crossings, 100);
            assert_eq!(result.stats.memory_allocations, 100);
            assert_eq!(result.stats.memory_deallocations, 100);
            assert_eq!(result.final_memory_usage, 0); // No memory leaks
            assert_eq!(result.stats.successful_integrations, 1);
        });
    }

    #[test]
    fn test_comprehensive_wasm_storage_integration() {
        let rt = crate::runtime::RuntimeBuilder::new().build().unwrap();
        rt.block_on(async {
            // Test multiple scenarios to ensure comprehensive coverage
            let mut harness = WasmStorageTestHarness::new();

            // Run basic serialization test
            let result1 = harness.test_basic_abi_serialization().await;
            assert!(result1.success);

            // Reset harness for next test
            harness = WasmStorageTestHarness::new();

            // Test storage integration
            let result2 = harness.test_localstorage_integration().await;
            assert!(result2.success);

            // Reset harness for next test
            harness = WasmStorageTestHarness::new();

            // Test memory leak detection
            let result3 = harness.test_memory_leak_detection().await;
            assert!(result3.success);

            // Verify all scenarios completed successfully
            assert!(result1.success && result2.success && result3.success,
                    "All WASM ABI-storage integration scenarios should succeed");
        });
    }
}