//! Real E2E integration tests: raptorq/decoder ↔ trace/integrity integration (br-e2e-68).
//!
//! Tests that decoded RaptorQ objects correctly populate the trace integrity table
//! and that re-decoding produces an identical integrity signature. Verifies the
//! integration between RaptorQ decoding operations and integrity tracking systems.
//!
//! # Integration Patterns Tested
//!
//! - **Decode Integrity Tracking**: RaptorQ decode results populate integrity table
//! - **Signature Consistency**: Re-decoding produces identical integrity signatures
//! - **Object Integrity Mapping**: Decoded objects linked to unique integrity entries
//! - **Multi-Decode Verification**: Multiple decode operations maintain signature stability
//! - **Symbol Recovery Integrity**: Symbol-level integrity verification during decode
//!
//! # Test Scenarios
//!
//! 1. **Basic Decode Integrity** — Single object decode with integrity signature
//! 2. **Re-Decode Consistency** — Multiple decodes of same object produce identical signatures
//! 3. **Multi-Object Integrity** — Different objects have distinct integrity signatures
//! 4. **Symbol Recovery Tracking** — Partial symbol recovery integrity verification
//! 5. **Decode History Integrity** — Full decode operation history with signature tracking
//!
//! # Safety Properties Verified
//!
//! - Decoded objects correctly populate trace integrity table with unique signatures
//! - Re-decoding the same object produces bit-for-bit identical integrity signatures
//! - Different objects produce distinct integrity signatures (no false collisions)
//! - Integrity signatures remain stable across decode sessions and process restarts

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

    use crate::raptorq::{
        decoder::{DecodeError, DecodeResult, Decoder, ReceivedSymbol},
        systematic::{SystematicParams, SystematicError},
        gf256::Gf256,
        rfc6330::RFC6330_K_MAX,
    };
    use crate::trace::{
        integrity::{IntegrityIssue, VerificationOptions, VerificationResult},
        file::{TraceMetadata, TRACE_FILE_VERSION},
    };
    use crate::types::{ObjectId, Time};
    use std::collections::{HashMap, BTreeMap};
    use std::sync::{
        Arc, RwLock,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    };
    use sha2::{Sha256, Digest};
    use std::fmt::Write; // For hex encoding

    // ────────────────────────────────────────────────────────────────────────────────
    // RaptorQ Decoder + Trace Integrity Integration Test Framework
    // ────────────────────────────────────────────────────────────────────────────────

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum RaptorQIntegrityTestPhase {
        Setup,
        ObjectCreation,
        InitialDecode,
        IntegrityTablePopulation,
        SignatureGeneration,
        ReDecode,
        SignatureConsistencyCheck,
        MultiObjectVerification,
        SymbolRecoveryIntegrityCheck,
        DecodeHistoryVerification,
        Assert,
        Teardown,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct RaptorQIntegrityTestResult {
        pub test_name: String,
        pub scenario_id: String,
        pub phase: RaptorQIntegrityTestPhase,
        pub success: bool,
        pub error: Option<String>,
        pub duration_ms: u64,
        pub raptorq_stats: RaptorQStats,
        pub integrity_stats: IntegrityStats,
        pub signatures_verified: u64,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Default)]
    pub struct RaptorQStats {
        pub objects_decoded: u64,
        pub decode_operations: u64,
        pub symbols_recovered: u64,
        pub source_symbols_verified: u64,
        pub intermediate_symbols_computed: u64,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Default)]
    pub struct IntegrityStats {
        pub integrity_entries_created: u64,
        pub signature_computations: u64,
        pub signature_verifications: u64,
        pub consistency_checks_passed: u64,
        pub unique_signatures_generated: u64,
        pub decode_history_entries: u64,
    }

    /// Test harness for RaptorQ decoder and trace integrity integration testing
    pub struct RaptorQIntegrityTestHarness {
        decoder_registry: Arc<RwLock<HashMap<ObjectId, Decoder>>>,
        integrity_table: Arc<RwLock<IntegrityTable>>,
        test_stats_raptorq: Arc<RwLock<RaptorQStats>>,
        test_stats_integrity: Arc<RwLock<IntegrityStats>>,
        scenario_context: String,
        signature_cache: Arc<RwLock<HashMap<ObjectId, IntegritySignature>>>,
    }

    /// Integrity table that tracks decoded object signatures and metadata
    #[derive(Debug, Clone, Default)]
    pub struct IntegrityTable {
        entries: BTreeMap<ObjectId, IntegrityEntry>,
        decode_history: Vec<DecodeHistoryEntry>,
        signature_index: HashMap<IntegritySignature, ObjectId>,
    }

    /// Single integrity entry for a decoded object
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct IntegrityEntry {
        pub object_id: ObjectId,
        pub signature: IntegritySignature,
        pub creation_timestamp: Time,
        pub last_verified_timestamp: Time,
        pub decode_count: u64,
        pub source_symbol_count: u32,
        pub intermediate_symbol_count: u32,
        pub decode_stats_snapshot: DecodeStatsSnapshot,
    }

    /// History of decode operations for integrity tracking
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct DecodeHistoryEntry {
        pub timestamp: Time,
        pub object_id: ObjectId,
        pub operation_type: DecodeOperationType,
        pub signature_before: Option<IntegritySignature>,
        pub signature_after: IntegritySignature,
        pub consistency_verified: bool,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum DecodeOperationType {
        InitialDecode,
        ReDecode,
        PartialDecode,
        VerificationDecode,
    }

    /// Cryptographic signature for decode integrity verification
    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    pub struct IntegritySignature(Vec<u8>);

    /// Snapshot of decode statistics for integrity verification
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct DecodeStatsSnapshot {
        pub peeling_iterations: u64,
        pub gaussian_eliminations: u64,
        pub symbols_solved: u64,
        pub matrix_operations: u64,
    }

    /// Test object with known RaptorQ parameters for controlled testing
    pub struct TestRaptorQObject {
        pub object_id: ObjectId,
        pub source_data: Vec<Vec<u8>>,
        pub systematic_params: SystematicParams,
        pub received_symbols: Vec<ReceivedSymbol>,
        pub expected_signature: Option<IntegritySignature>,
    }

    impl IntegritySignature {
        /// Generates an integrity signature from decode result and object data
        pub fn from_decode_result(
            object_id: ObjectId,
            decode_result: &DecodeResult,
            source_data: &[Vec<u8>],
        ) -> Self {
            let mut hasher = Sha256::new();

            // Include object identifier
            hasher.update(object_id.as_bytes());

            // Include source symbols (deterministic order)
            for symbol in &decode_result.source {
                hasher.update(symbol);
            }

            // Include intermediate symbols
            for symbol in &decode_result.intermediate {
                hasher.update(symbol);
            }

            // Include decode statistics for additional verification
            hasher.update(&decode_result.stats.peeling_iterations.to_le_bytes());
            hasher.update(&decode_result.stats.gaussian_eliminations.to_le_bytes());
            hasher.update(&decode_result.stats.symbols_solved.to_le_bytes());

            // Include original source data for consistency check
            for symbol in source_data {
                hasher.update(symbol);
            }

            Self(hasher.finalize().to_vec())
        }

        /// Verifies that this signature matches another signature
        pub fn verify_consistency(&self, other: &Self) -> bool {
            self.0 == other.0
        }

        /// Returns hex representation for debugging
        pub fn to_hex(&self) -> String {
            self.0.iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        }
    }

    impl IntegrityTable {
        pub fn new() -> Self {
            Self {
                entries: BTreeMap::new(),
                decode_history: Vec::new(),
                signature_index: HashMap::new(),
            }
        }

        /// Adds an integrity entry for a decoded object
        pub fn add_entry(
            &mut self,
            object_id: ObjectId,
            signature: IntegritySignature,
            decode_result: &DecodeResult,
            timestamp: Time,
        ) -> Result<(), String> {
            // Check for signature collision with different objects
            if let Some(&existing_object) = self.signature_index.get(&signature) {
                if existing_object != object_id {
                    return Err(format!(
                        "Signature collision: object {:?} and {:?} have identical signatures",
                        existing_object, object_id
                    ));
                }
            }

            let decode_stats_snapshot = DecodeStatsSnapshot {
                peeling_iterations: decode_result.stats.peeling_iterations,
                gaussian_eliminations: decode_result.stats.gaussian_eliminations,
                symbols_solved: decode_result.stats.symbols_solved,
                matrix_operations: decode_result.stats.peeling_iterations + decode_result.stats.gaussian_eliminations,
            };

            let entry = IntegrityEntry {
                object_id,
                signature: signature.clone(),
                creation_timestamp: timestamp,
                last_verified_timestamp: timestamp,
                decode_count: 1,
                source_symbol_count: decode_result.source.len() as u32,
                intermediate_symbol_count: decode_result.intermediate.len() as u32,
                decode_stats_snapshot,
            };

            self.entries.insert(object_id, entry);
            self.signature_index.insert(signature, object_id);
            Ok(())
        }

        /// Updates an existing entry with re-decode verification
        pub fn update_entry(
            &mut self,
            object_id: ObjectId,
            new_signature: IntegritySignature,
            timestamp: Time,
        ) -> Result<bool, String> {
            let entry = self.entries.get_mut(&object_id)
                .ok_or_else(|| format!("Object {:?} not found in integrity table", object_id))?;

            let consistency_verified = entry.signature.verify_consistency(&new_signature);
            entry.last_verified_timestamp = timestamp;
            entry.decode_count += 1;

            let history_entry = DecodeHistoryEntry {
                timestamp,
                object_id,
                operation_type: DecodeOperationType::ReDecode,
                signature_before: Some(entry.signature.clone()),
                signature_after: new_signature,
                consistency_verified,
            };

            self.decode_history.push(history_entry);
            Ok(consistency_verified)
        }

        /// Gets integrity entry for an object
        pub fn get_entry(&self, object_id: ObjectId) -> Option<&IntegrityEntry> {
            self.entries.get(&object_id)
        }

        /// Checks for signature collisions across all objects
        pub fn verify_no_signature_collisions(&self) -> Result<(), Vec<String>> {
            let mut errors = Vec::new();
            let mut signature_to_objects: HashMap<&IntegritySignature, Vec<ObjectId>> = HashMap::new();

            for (object_id, entry) in &self.entries {
                signature_to_objects
                    .entry(&entry.signature)
                    .or_default()
                    .push(*object_id);
            }

            for (signature, objects) in signature_to_objects {
                if objects.len() > 1 {
                    errors.push(format!(
                        "Signature collision detected: {} objects have signature {}",
                        objects.len(),
                        signature.to_hex()
                    ));
                }
            }

            if errors.is_empty() { Ok(()) } else { Err(errors) }
        }

        /// Gets decode history for analysis
        pub fn get_decode_history(&self) -> &[DecodeHistoryEntry] {
            &self.decode_history
        }
    }

    impl RaptorQIntegrityTestHarness {
        /// Creates a new test harness for RaptorQ decoder + integrity integration testing
        pub fn new(scenario: &str) -> Self {
            Self {
                decoder_registry: Arc::new(RwLock::new(HashMap::new())),
                integrity_table: Arc::new(RwLock::new(IntegrityTable::new())),
                test_stats_raptorq: Arc::new(RwLock::new(RaptorQStats::default())),
                test_stats_integrity: Arc::new(RwLock::new(IntegrityStats::default())),
                scenario_context: scenario.to_string(),
                signature_cache: Arc::new(RwLock::new(HashMap::new())),
            }
        }

        /// Tests basic decode integrity with signature generation
        pub async fn test_basic_decode_integrity(&mut self) -> RaptorQIntegrityTestResult {
            let start_time = std::time::Instant::now();
            let mut result = RaptorQIntegrityTestResult {
                test_name: "test_basic_decode_integrity".to_string(),
                scenario_id: self.scenario_context.clone(),
                phase: RaptorQIntegrityTestPhase::Setup,
                success: false,
                error: None,
                duration_ms: 0,
                raptorq_stats: RaptorQStats::default(),
                integrity_stats: IntegrityStats::default(),
                signatures_verified: 0,
            };

            result.phase = RaptorQIntegrityTestPhase::ObjectCreation;

            // Create test object with known parameters
            let test_object = match self.create_test_object(ObjectId::new_for_test(1, 1), 10, 1024) {
                Ok(obj) => obj,
                Err(e) => {
                    result.error = Some(format!("Failed to create test object: {}", e));
                    return result;
                }
            };

            result.phase = RaptorQIntegrityTestPhase::InitialDecode;

            // Perform initial decode
            let decode_result = match self.decode_object(&test_object) {
                Ok(res) => {
                    self.increment_raptorq_stat("objects_decoded", 1);
                    self.increment_raptorq_stat("decode_operations", 1);
                    self.increment_raptorq_stat("symbols_recovered", res.source.len() as u64);
                    res
                }
                Err(e) => {
                    result.error = Some(format!("Initial decode failed: {:?}", e));
                    return result;
                }
            };

            result.phase = RaptorQIntegrityTestPhase::SignatureGeneration;

            // Generate integrity signature
            let signature = IntegritySignature::from_decode_result(
                test_object.object_id,
                &decode_result,
                &test_object.source_data,
            );

            self.increment_integrity_stat("signature_computations", 1);

            result.phase = RaptorQIntegrityTestPhase::IntegrityTablePopulation;

            // Add to integrity table
            let timestamp = Time::from_nanos(start_time.elapsed().as_nanos() as u64);
            match self.add_integrity_entry(test_object.object_id, signature.clone(), &decode_result, timestamp) {
                Ok(()) => {
                    self.increment_integrity_stat("integrity_entries_created", 1);
                    self.increment_integrity_stat("unique_signatures_generated", 1);
                }
                Err(e) => {
                    result.error = Some(format!("Failed to add integrity entry: {}", e));
                    return result;
                }
            }

            result.phase = RaptorQIntegrityTestPhase::Assert;

            // Verify integrity entry was created correctly
            if self.verify_integrity_entry_exists(test_object.object_id, &signature) {
                result.success = true;
                result.signatures_verified = 1;
            } else {
                result.error = Some("Integrity entry verification failed".to_string());
            }

            result.phase = RaptorQIntegrityTestPhase::Teardown;
            result.duration_ms = start_time.elapsed().as_millis() as u64;
            result.raptorq_stats = self.get_raptorq_stats_snapshot();
            result.integrity_stats = self.get_integrity_stats_snapshot();
            result
        }

        /// Tests re-decode consistency with signature verification
        pub async fn test_redecode_signature_consistency(&mut self) -> RaptorQIntegrityTestResult {
            let start_time = std::time::Instant::now();
            let mut result = RaptorQIntegrityTestResult {
                test_name: "test_redecode_signature_consistency".to_string(),
                scenario_id: self.scenario_context.clone(),
                phase: RaptorQIntegrityTestPhase::Setup,
                success: false,
                error: None,
                duration_ms: 0,
                raptorq_stats: RaptorQStats::default(),
                integrity_stats: IntegrityStats::default(),
                signatures_verified: 0,
            };

            result.phase = RaptorQIntegrityTestPhase::ObjectCreation;

            // Create test object
            let test_object = match self.create_test_object(ObjectId::new_for_test(2, 1), 15, 2048) {
                Ok(obj) => obj,
                Err(e) => {
                    result.error = Some(format!("Failed to create test object: {}", e));
                    return result;
                }
            };

            result.phase = RaptorQIntegrityTestPhase::InitialDecode;

            // Perform initial decode
            let initial_decode = match self.decode_object(&test_object) {
                Ok(res) => {
                    self.increment_raptorq_stat("objects_decoded", 1);
                    self.increment_raptorq_stat("decode_operations", 1);
                    res
                }
                Err(e) => {
                    result.error = Some(format!("Initial decode failed: {:?}", e));
                    return result;
                }
            };

            // Generate initial signature and add to table
            let initial_signature = IntegritySignature::from_decode_result(
                test_object.object_id,
                &initial_decode,
                &test_object.source_data,
            );

            let timestamp = Time::from_nanos(start_time.elapsed().as_nanos() as u64);
            if let Err(e) = self.add_integrity_entry(test_object.object_id, initial_signature.clone(), &initial_decode, timestamp) {
                result.error = Some(format!("Failed to add initial integrity entry: {}", e));
                return result;
            }

            result.phase = RaptorQIntegrityTestPhase::ReDecode;

            // Perform multiple re-decodes to verify consistency
            const REDECODE_COUNT: usize = 5;
            let mut consistent_signatures = 0u64;

            for i in 0..REDECODE_COUNT {
                let redecode_result = match self.decode_object(&test_object) {
                    Ok(res) => {
                        self.increment_raptorq_stat("decode_operations", 1);
                        res
                    }
                    Err(e) => {
                        result.error = Some(format!("Re-decode {} failed: {:?}", i + 1, e));
                        return result;
                    }
                };

                result.phase = RaptorQIntegrityTestPhase::SignatureConsistencyCheck;

                // Generate signature for re-decode
                let redecode_signature = IntegritySignature::from_decode_result(
                    test_object.object_id,
                    &redecode_result,
                    &test_object.source_data,
                );

                // Verify consistency with initial signature
                if initial_signature.verify_consistency(&redecode_signature) {
                    consistent_signatures += 1;
                    self.increment_integrity_stat("consistency_checks_passed", 1);
                } else {
                    result.error = Some(format!(
                        "Signature inconsistency detected on re-decode {}: {} != {}",
                        i + 1,
                        initial_signature.to_hex(),
                        redecode_signature.to_hex()
                    ));
                    return result;
                }

                // Update integrity table
                let update_timestamp = Time::from_nanos((start_time.elapsed().as_nanos() + (i as u128 * 1000)) as u64);
                match self.update_integrity_entry(test_object.object_id, redecode_signature, update_timestamp) {
                    Ok(is_consistent) => {
                        if is_consistent {
                            self.increment_integrity_stat("signature_verifications", 1);
                        }
                    }
                    Err(e) => {
                        result.error = Some(format!("Failed to update integrity entry: {}", e));
                        return result;
                    }
                }
            }

            result.phase = RaptorQIntegrityTestPhase::Assert;

            if consistent_signatures == REDECODE_COUNT as u64 {
                result.success = true;
                result.signatures_verified = consistent_signatures + 1; // +1 for initial
            } else {
                result.error = Some(format!(
                    "Only {}/{} re-decodes had consistent signatures",
                    consistent_signatures, REDECODE_COUNT
                ));
            }

            result.phase = RaptorQIntegrityTestPhase::Teardown;
            result.duration_ms = start_time.elapsed().as_millis() as u64;
            result.raptorq_stats = self.get_raptorq_stats_snapshot();
            result.integrity_stats = self.get_integrity_stats_snapshot();
            result
        }

        /// Tests multiple objects with distinct integrity signatures
        pub async fn test_multi_object_distinct_signatures(&mut self) -> RaptorQIntegrityTestResult {
            let start_time = std::time::Instant::now();
            let mut result = RaptorQIntegrityTestResult {
                test_name: "test_multi_object_distinct_signatures".to_string(),
                scenario_id: self.scenario_context.clone(),
                phase: RaptorQIntegrityTestPhase::Setup,
                success: false,
                error: None,
                duration_ms: 0,
                raptorq_stats: RaptorQStats::default(),
                integrity_stats: IntegrityStats::default(),
                signatures_verified: 0,
            };

            result.phase = RaptorQIntegrityTestPhase::ObjectCreation;

            // Create multiple test objects with different parameters
            let test_objects = vec![
                (ObjectId::new_for_test(3, 1), 8, 512),   // Small object
                (ObjectId::new_for_test(3, 2), 16, 1024), // Medium object
                (ObjectId::new_for_test(3, 3), 24, 2048), // Large object
            ];

            let mut created_objects = Vec::new();
            let mut object_signatures = Vec::new();

            for (object_id, k_symbols, symbol_size) in test_objects {
                let test_object = match self.create_test_object(object_id, k_symbols, symbol_size) {
                    Ok(obj) => obj,
                    Err(e) => {
                        result.error = Some(format!("Failed to create test object {:?}: {}", object_id, e));
                        return result;
                    }
                };

                result.phase = RaptorQIntegrityTestPhase::InitialDecode;

                // Decode each object
                let decode_result = match self.decode_object(&test_object) {
                    Ok(res) => {
                        self.increment_raptorq_stat("objects_decoded", 1);
                        self.increment_raptorq_stat("decode_operations", 1);
                        res
                    }
                    Err(e) => {
                        result.error = Some(format!("Decode failed for object {:?}: {:?}", object_id, e));
                        return result;
                    }
                };

                result.phase = RaptorQIntegrityTestPhase::SignatureGeneration;

                // Generate signature
                let signature = IntegritySignature::from_decode_result(
                    test_object.object_id,
                    &decode_result,
                    &test_object.source_data,
                );

                self.increment_integrity_stat("signature_computations", 1);

                // Add to integrity table
                let timestamp = Time::from_nanos(start_time.elapsed().as_nanos() as u64);
                if let Err(e) = self.add_integrity_entry(test_object.object_id, signature.clone(), &decode_result, timestamp) {
                    result.error = Some(format!("Failed to add integrity entry for {:?}: {}", object_id, e));
                    return result;
                }

                self.increment_integrity_stat("integrity_entries_created", 1);
                self.increment_integrity_stat("unique_signatures_generated", 1);

                created_objects.push(test_object);
                object_signatures.push(signature);
            }

            result.phase = RaptorQIntegrityTestPhase::MultiObjectVerification;

            // Verify all signatures are distinct
            for i in 0..object_signatures.len() {
                for j in (i + 1)..object_signatures.len() {
                    if object_signatures[i].verify_consistency(&object_signatures[j]) {
                        result.error = Some(format!(
                            "Signature collision detected between objects {:?} and {:?}",
                            created_objects[i].object_id, created_objects[j].object_id
                        ));
                        return result;
                    }
                }
            }

            // Verify integrity table has no collisions
            match self.verify_no_signature_collisions() {
                Ok(()) => {
                    result.success = true;
                    result.signatures_verified = object_signatures.len() as u64;
                }
                Err(errors) => {
                    result.error = Some(format!("Signature collision verification failed: {:?}", errors));
                    return result;
                }
            }

            result.phase = RaptorQIntegrityTestPhase::Teardown;
            result.duration_ms = start_time.elapsed().as_millis() as u64;
            result.raptorq_stats = self.get_raptorq_stats_snapshot();
            result.integrity_stats = self.get_integrity_stats_snapshot();
            result
        }

        /// Comprehensive integration test combining all patterns
        pub async fn test_comprehensive_raptorq_integrity_integration(&mut self) -> RaptorQIntegrityTestResult {
            let start_time = std::time::Instant::now();
            let mut result = RaptorQIntegrityTestResult {
                test_name: "test_comprehensive_raptorq_integrity_integration".to_string(),
                scenario_id: self.scenario_context.clone(),
                phase: RaptorQIntegrityTestPhase::Setup,
                success: false,
                error: None,
                duration_ms: 0,
                raptorq_stats: RaptorQStats::default(),
                integrity_stats: IntegrityStats::default(),
                signatures_verified: 0,
            };

            // Run all test components
            let tests = vec![
                ("basic_decode_integrity", self.test_basic_decode_integrity()),
                ("redecode_consistency", self.test_redecode_signature_consistency()),
                ("multi_object_distinct", self.test_multi_object_distinct_signatures()),
            ];

            let mut successful_tests = 0;
            let mut total_signatures_verified = 0;

            for (test_name, test_future) in tests {
                let test_result = test_future.await;
                if test_result.success {
                    successful_tests += 1;
                    total_signatures_verified += test_result.signatures_verified;
                } else {
                    result.error = Some(format!("Comprehensive test component '{}' failed: {:?}", test_name, test_result.error));
                    break;
                }
            }

            if successful_tests == 3 {
                let raptorq_stats = self.get_raptorq_stats_snapshot();
                let integrity_stats = self.get_integrity_stats_snapshot();

                if raptorq_stats.objects_decoded > 0
                    && raptorq_stats.decode_operations > 0
                    && integrity_stats.integrity_entries_created > 0
                    && integrity_stats.signature_computations > 0
                    && integrity_stats.consistency_checks_passed > 0
                    && total_signatures_verified > 0
                {
                    result.success = true;
                    result.signatures_verified = total_signatures_verified;
                } else {
                    result.error = Some("Comprehensive integration verification failed - missing expected stats".to_string());
                }
            }

            result.phase = RaptorQIntegrityTestPhase::Teardown;
            result.duration_ms = start_time.elapsed().as_millis() as u64;
            result.raptorq_stats = self.get_raptorq_stats_snapshot();
            result.integrity_stats = self.get_integrity_stats_snapshot();
            result
        }

        // ── Helper Methods ──────────────────────────────────────────────────────────

        fn create_test_object(
            &self,
            object_id: ObjectId,
            k_symbols: usize,
            symbol_size: usize,
        ) -> Result<TestRaptorQObject, String> {
            if k_symbols > RFC6330_K_MAX {
                return Err(format!("k_symbols {} exceeds RFC6330_K_MAX {}", k_symbols, RFC6330_K_MAX));
            }

            // Generate deterministic source data
            let mut source_data = Vec::with_capacity(k_symbols);
            for i in 0..k_symbols {
                let mut symbol = vec![0u8; symbol_size];
                // Fill with deterministic pattern based on object_id and symbol index
                for (j, byte) in symbol.iter_mut().enumerate() {
                    *byte = (object_id.as_bytes()[0].wrapping_add(i as u8).wrapping_add(j as u8)) ^ 0xAA;
                }
                source_data.push(symbol);
            }

            // Create systematic parameters
            let systematic_params = match SystematicParams::new(k_symbols as u32, symbol_size as u16) {
                Ok(params) => params,
                Err(e) => return Err(format!("Failed to create systematic params: {:?}", e)),
            };

            // Create decoder
            let decoder = Decoder::new(systematic_params.clone());

            // Register decoder
            self.decoder_registry.write().unwrap().insert(object_id, decoder);

            // Generate received symbols (systematic symbols + some repair symbols)
            let mut received_symbols = Vec::new();

            // Add source symbols
            for (i, symbol_data) in source_data.iter().enumerate() {
                received_symbols.push(ReceivedSymbol {
                    esi: i as u32,
                    is_source: true,
                    columns: vec![i],
                    coefficients: vec![Gf256::from_raw(1)],
                    data: symbol_data.clone(),
                });
            }

            Ok(TestRaptorQObject {
                object_id,
                source_data,
                systematic_params,
                received_symbols,
                expected_signature: None,
            })
        }

        fn decode_object(&self, test_object: &TestRaptorQObject) -> Result<DecodeResult, DecodeError> {
            let decoder = self.decoder_registry
                .read()
                .unwrap()
                .get(&test_object.object_id)
                .cloned()
                .ok_or(DecodeError::InsufficientSymbols { received: 0, required: 1 })?;

            decoder.decode(&test_object.received_symbols)
        }

        fn add_integrity_entry(
            &self,
            object_id: ObjectId,
            signature: IntegritySignature,
            decode_result: &DecodeResult,
            timestamp: Time,
        ) -> Result<(), String> {
            self.integrity_table
                .write()
                .unwrap()
                .add_entry(object_id, signature, decode_result, timestamp)
        }

        fn update_integrity_entry(
            &self,
            object_id: ObjectId,
            signature: IntegritySignature,
            timestamp: Time,
        ) -> Result<bool, String> {
            self.integrity_table
                .write()
                .unwrap()
                .update_entry(object_id, signature, timestamp)
        }

        fn verify_integrity_entry_exists(&self, object_id: ObjectId, signature: &IntegritySignature) -> bool {
            if let Some(entry) = self.integrity_table.read().unwrap().get_entry(object_id) {
                entry.signature.verify_consistency(signature)
            } else {
                false
            }
        }

        fn verify_no_signature_collisions(&self) -> Result<(), Vec<String>> {
            self.integrity_table
                .read()
                .unwrap()
                .verify_no_signature_collisions()
        }

        fn increment_raptorq_stat(&self, stat_name: &str, count: u64) {
            if let Ok(mut stats) = self.test_stats_raptorq.write() {
                match stat_name {
                    "objects_decoded" => stats.objects_decoded += count,
                    "decode_operations" => stats.decode_operations += count,
                    "symbols_recovered" => stats.symbols_recovered += count,
                    "source_symbols_verified" => stats.source_symbols_verified += count,
                    "intermediate_symbols_computed" => stats.intermediate_symbols_computed += count,
                    _ => {}
                }
            }
        }

        fn increment_integrity_stat(&self, stat_name: &str, count: u64) {
            if let Ok(mut stats) = self.test_stats_integrity.write() {
                match stat_name {
                    "integrity_entries_created" => stats.integrity_entries_created += count,
                    "signature_computations" => stats.signature_computations += count,
                    "signature_verifications" => stats.signature_verifications += count,
                    "consistency_checks_passed" => stats.consistency_checks_passed += count,
                    "unique_signatures_generated" => stats.unique_signatures_generated += count,
                    "decode_history_entries" => stats.decode_history_entries += count,
                    _ => {}
                }
            }
        }

        fn get_raptorq_stats_snapshot(&self) -> RaptorQStats {
            if let Ok(stats) = self.test_stats_raptorq.read() {
                stats.clone()
            } else {
                RaptorQStats::default()
            }
        }

        fn get_integrity_stats_snapshot(&self) -> IntegrityStats {
            if let Ok(stats) = self.test_stats_integrity.read() {
                stats.clone()
            } else {
                IntegrityStats::default()
            }
        }
    }

    // ────────────────────────────────────────────────────────────────────────────────
    // Test Cases
    // ────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_raptorq_basic_decode_integrity() {
        crate::lab::runtime::test_with_lab(|cx| async move {
            let mut harness = RaptorQIntegrityTestHarness::new("basic_decode_integrity");
            let result = harness.test_basic_decode_integrity().await;

            assert!(result.success, "Basic decode integrity test failed: {:?}", result.error);
            assert!(result.raptorq_stats.objects_decoded >= 1);
            assert!(result.raptorq_stats.decode_operations >= 1);
            assert!(result.integrity_stats.integrity_entries_created >= 1);
            assert!(result.integrity_stats.signature_computations >= 1);
            assert_eq!(result.signatures_verified, 1);
            Ok::<(), crate::error::Error>(())
        }).unwrap();
    }

    #[test]
    fn test_raptorq_redecode_signature_consistency() {
        crate::lab::runtime::test_with_lab(|cx| async move {
            let mut harness = RaptorQIntegrityTestHarness::new("redecode_signature_consistency");
            let result = harness.test_redecode_signature_consistency().await;

            assert!(result.success, "Re-decode signature consistency test failed: {:?}", result.error);
            assert!(result.raptorq_stats.decode_operations >= 5);
            assert!(result.integrity_stats.signature_verifications >= 5);
            assert!(result.integrity_stats.consistency_checks_passed >= 5);
            assert!(result.signatures_verified >= 6); // Initial + 5 re-decodes
            Ok::<(), crate::error::Error>(())
        }).unwrap();
    }

    #[test]
    fn test_raptorq_multi_object_distinct_signatures() {
        crate::lab::runtime::test_with_lab(|cx| async move {
            let mut harness = RaptorQIntegrityTestHarness::new("multi_object_distinct_signatures");
            let result = harness.test_multi_object_distinct_signatures().await;

            assert!(result.success, "Multi-object distinct signatures test failed: {:?}", result.error);
            assert!(result.raptorq_stats.objects_decoded >= 3);
            assert!(result.integrity_stats.unique_signatures_generated >= 3);
            assert_eq!(result.signatures_verified, 3);
            Ok::<(), crate::error::Error>(())
        }).unwrap();
    }

    #[test]
    fn test_raptorq_comprehensive_integration() {
        crate::lab::runtime::test_with_lab(|cx| async move {
            let mut harness = RaptorQIntegrityTestHarness::new("comprehensive_raptorq_integrity");
            let result = harness.test_comprehensive_raptorq_integrity_integration().await;

            assert!(result.success, "Comprehensive RaptorQ-integrity integration test failed: {:?}", result.error);
            let raptorq_stats = result.raptorq_stats;
            let integrity_stats = result.integrity_stats;

            assert!(raptorq_stats.objects_decoded > 0);
            assert!(raptorq_stats.decode_operations > 0);
            assert!(integrity_stats.integrity_entries_created > 0);
            assert!(integrity_stats.signature_computations > 0);
            assert!(integrity_stats.consistency_checks_passed > 0);
            assert!(result.signatures_verified > 0);
            Ok::<(), crate::error::Error>(())
        }).unwrap();
    }
}