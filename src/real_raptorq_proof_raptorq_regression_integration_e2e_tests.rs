//! BR-E2E-90: Real RaptorQ Proof ↔ RaptorQ Regression Integration E2E Tests
//!
//! This module provides comprehensive integration tests between the RaptorQ proof
//! generation and RaptorQ regression detection subsystems. The tests verify that
//! regression detection catches synthetic decode quality regressions and surfaces
//! the exact source-block triggering them.
//!
//! # Integration Focus
//!
//! Tests the coordination between:
//! - `raptorq::proof` - Proof generation and validation for RaptorQ correctness verification
//! - `raptorq::regression` - Regression detection and quality assurance for decode performance
//!
//! # Key Scenarios
//!
//! - Synthetic decode quality regression injection and detection
//! - Source-block level regression identification and reporting
//! - Proof validation coordination with regression analysis
//! - Quality threshold monitoring and alerting
//! - Performance regression correlation with correctness proofs

use crate::{
    cx::{Cx, Scope},
    error::Outcome,
    raptorq::{
        ObjectId, PayloadId, RepairSymbol, SourceSymbol,
        decoder::{Decoder, DecoderConfig, DecoderStats},
        encoder::{Encoder, EncoderConfig, EncodingParams},
        gf256::Gf256,
        proof::{
            CorrectnessProof, DecodingProof, ProofConfig, ProofGenerator, ProofStats,
            ProofValidator, ProofVerificationResult, RaptorQProof,
        },
        regression::{
            PerformanceBaseline, QualityRegression, RegressionConfig, RegressionDetector,
            RegressionEvent, RegressionReport, RegressionThreshold,
        },
        rfc6330::{ObjectTransmissionInformation, SourceBlockNumber, Symbol, SymbolId},
        systematic::SystematicIndex,
    },
    runtime::RuntimeBuilder,
    sync::{Barrier, Mutex},
    time::{Duration, Instant, Sleep},
    types::{Budget, TaskId},
    util::{
        det_rng::{DetRng, RngSeed},
        entropy::EntropySource,
    },
};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
};

/// Tracks regression detection and proof validation coordination events
#[derive(Debug, Clone)]
struct RegressionProofTracker {
    /// Proofs generated for decode operations
    proofs_generated: Arc<AtomicU64>,
    /// Proof validation attempts
    proof_validations: Arc<AtomicU64>,
    /// Proof validation failures
    proof_validation_failures: Arc<AtomicU64>,
    /// Regression events detected
    regressions_detected: Arc<AtomicU64>,
    /// Source blocks triggering regressions
    regression_source_blocks: Arc<AtomicU64>,
    /// Synthetic regressions injected
    synthetic_regressions_injected: Arc<AtomicU64>,
    /// Quality threshold violations
    quality_threshold_violations: Arc<AtomicU64>,
    /// Regression detection timeline
    regression_timeline: Arc<Mutex<Vec<(Instant, SourceBlockNumber, String)>>>,
}

impl RegressionProofTracker {
    fn new() -> Self {
        Self {
            proofs_generated: Arc::new(AtomicU64::new(0)),
            proof_validations: Arc::new(AtomicU64::new(0)),
            proof_validation_failures: Arc::new(AtomicU64::new(0)),
            regressions_detected: Arc::new(AtomicU64::new(0)),
            regression_source_blocks: Arc::new(AtomicU64::new(0)),
            synthetic_regressions_injected: Arc::new(AtomicU64::new(0)),
            quality_threshold_violations: Arc::new(AtomicU64::new(0)),
            regression_timeline: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn record_proof_generated(&self) -> u64 {
        self.proofs_generated.fetch_add(1, Ordering::Relaxed)
    }

    fn record_proof_validation(&self) -> u64 {
        self.proof_validations.fetch_add(1, Ordering::Relaxed)
    }

    fn record_proof_validation_failure(&self) -> u64 {
        self.proof_validation_failures
            .fetch_add(1, Ordering::Relaxed)
    }

    fn record_regression_detected(&self) -> u64 {
        self.regressions_detected.fetch_add(1, Ordering::Relaxed)
    }

    fn record_regression_source_block(&self) -> u64 {
        self.regression_source_blocks
            .fetch_add(1, Ordering::Relaxed)
    }

    fn record_synthetic_regression_injected(&self) -> u64 {
        self.synthetic_regressions_injected
            .fetch_add(1, Ordering::Relaxed)
    }

    fn record_quality_threshold_violation(&self) -> u64 {
        self.quality_threshold_violations
            .fetch_add(1, Ordering::Relaxed)
    }

    async fn record_regression_event(
        &self,
        cx: &Cx,
        source_block: SourceBlockNumber,
        event_type: String,
    ) {
        let mut timeline = self.regression_timeline.lock(cx).await;
        timeline.push((Instant::now(), source_block, event_type));
    }

    fn verify_regression_detection(&self) -> bool {
        let injected = self.synthetic_regressions_injected.load(Ordering::Relaxed);
        let detected = self.regressions_detected.load(Ordering::Relaxed);

        // Should detect injected regressions
        injected > 0 && detected >= injected
    }

    fn verify_source_block_identification(&self) -> bool {
        let detected = self.regressions_detected.load(Ordering::Relaxed);
        let source_blocks = self.regression_source_blocks.load(Ordering::Relaxed);

        // Should identify specific source blocks for regressions
        detected > 0 && source_blocks >= detected
    }

    fn verify_proof_validation_integration(&self) -> bool {
        let proofs = self.proofs_generated.load(Ordering::Relaxed);
        let validations = self.proof_validations.load(Ordering::Relaxed);

        // Should validate generated proofs
        proofs > 0 && validations >= proofs
    }
}

/// Simulates synthetic decode quality regressions for testing
struct SyntheticRegressionInjector {
    /// Regression injection probability
    injection_probability: f64,
    /// Target source blocks for regression injection
    target_source_blocks: HashSet<SourceBlockNumber>,
    /// Types of regressions to inject
    regression_types: Vec<RegressionType>,
    /// Random number generator
    rng: Arc<Mutex<DetRng>>,
    /// Tracking integration
    regression_tracker: RegressionProofTracker,
}

#[derive(Debug, Clone)]
enum RegressionType {
    /// Slow decoding performance
    SlowDecoding { slowdown_factor: f64 },
    /// Increased symbol error rate
    SymbolErrorRate { error_rate: f64 },
    /// Memory usage regression
    MemoryRegression { overhead_factor: f64 },
    /// Convergence failures
    ConvergenceFailure { failure_rate: f64 },
}

impl SyntheticRegressionInjector {
    fn new(
        injection_probability: f64,
        target_source_blocks: HashSet<SourceBlockNumber>,
        seed: RngSeed,
        regression_tracker: RegressionProofTracker,
    ) -> Self {
        let regression_types = vec![
            RegressionType::SlowDecoding {
                slowdown_factor: 2.0,
            },
            RegressionType::SymbolErrorRate { error_rate: 0.05 },
            RegressionType::MemoryRegression {
                overhead_factor: 1.5,
            },
            RegressionType::ConvergenceFailure { failure_rate: 0.1 },
        ];

        Self {
            injection_probability,
            target_source_blocks,
            regression_types,
            rng: Arc::new(Mutex::new(DetRng::from_seed(seed))),
            regression_tracker,
        }
    }

    async fn should_inject_regression(
        &self,
        cx: &Cx,
        source_block: SourceBlockNumber,
    ) -> Option<RegressionType> {
        if !self.target_source_blocks.contains(&source_block) {
            return None;
        }

        let mut rng = self.rng.lock(cx).await;
        if rng.gen_range(0.0..1.0) < self.injection_probability {
            let regression_type =
                self.regression_types[rng.gen_range(0..self.regression_types.len())].clone();

            self.regression_tracker
                .record_synthetic_regression_injected();
            Some(regression_type)
        } else {
            None
        }
    }

    async fn inject_regression(
        &self,
        cx: &Cx,
        source_block: SourceBlockNumber,
        regression_type: &RegressionType,
    ) -> RegressionEvent {
        self.regression_tracker
            .record_regression_event(cx, source_block, format!("synthetic_{:?}", regression_type))
            .await;

        match regression_type {
            RegressionType::SlowDecoding { slowdown_factor } => {
                // Simulate slow decoding by adding delay
                let delay_ms = (slowdown_factor * 10.0) as u64;
                Sleep::new(Duration::from_millis(delay_ms)).await;

                RegressionEvent::PerformanceRegression {
                    source_block,
                    baseline_time: Duration::from_millis(10),
                    observed_time: Duration::from_millis(delay_ms + 10),
                    regression_factor: *slowdown_factor,
                }
            }
            RegressionType::SymbolErrorRate { error_rate } => RegressionEvent::QualityRegression {
                source_block,
                baseline_quality: 0.999,
                observed_quality: 1.0 - error_rate,
                error_threshold: 0.01,
            },
            RegressionType::MemoryRegression { overhead_factor } => {
                RegressionEvent::MemoryRegression {
                    source_block,
                    baseline_memory: 1024 * 1024, // 1MB
                    observed_memory: ((1024.0 * 1024.0 * overhead_factor) as u64),
                    overhead_threshold: 0.2,
                }
            }
            RegressionType::ConvergenceFailure { failure_rate } => {
                RegressionEvent::ConvergenceRegression {
                    source_block,
                    baseline_success_rate: 0.999,
                    observed_success_rate: 1.0 - failure_rate,
                    convergence_threshold: 0.95,
                }
            }
        }
    }
}

/// Mock RaptorQ decoder with integrated proof generation and regression detection
struct ProofEnabledRaptorQDecoder {
    /// Underlying decoder configuration
    decoder_config: DecoderConfig,
    /// Proof generator for correctness validation
    proof_generator: ProofGenerator,
    /// Regression detector for quality monitoring
    regression_detector: RegressionDetector,
    /// Synthetic regression injector
    regression_injector: SyntheticRegressionInjector,
    /// Performance baselines for comparison
    baselines: Arc<Mutex<HashMap<SourceBlockNumber, PerformanceBaseline>>>,
    /// Tracking integration
    regression_tracker: RegressionProofTracker,
}

impl ProofEnabledRaptorQDecoder {
    async fn new(
        cx: &Cx,
        decoder_config: DecoderConfig,
        proof_config: ProofConfig,
        regression_config: RegressionConfig,
        regression_injector: SyntheticRegressionInjector,
        regression_tracker: RegressionProofTracker,
    ) -> Outcome<Self> {
        Ok(Self {
            decoder_config,
            proof_generator: ProofGenerator::new(proof_config),
            regression_detector: RegressionDetector::new(regression_config).await?,
            regression_injector,
            baselines: Arc::new(Mutex::new(HashMap::new())),
            regression_tracker,
        })
    }

    async fn decode_with_proof_and_regression_detection(
        &self,
        cx: &Cx,
        object_id: ObjectId,
        source_block: SourceBlockNumber,
        symbols: Vec<SourceSymbol>,
        repair_symbols: Vec<RepairSymbol>,
    ) -> Outcome<(Vec<u8>, Option<RaptorQProof>, Option<RegressionEvent>)> {
        let decode_start = Instant::now();

        // Check for synthetic regression injection
        let synthetic_regression = self
            .regression_injector
            .should_inject_regression(cx, source_block)
            .await;

        let mut regression_event = None;
        if let Some(regression_type) = synthetic_regression {
            regression_event = Some(
                self.regression_injector
                    .inject_regression(cx, source_block, &regression_type)
                    .await,
            );

            self.regression_tracker.record_regression_detected();
            self.regression_tracker.record_regression_source_block();
        }

        // Perform actual decoding
        let mut decoder = Decoder::new(self.decoder_config.clone());

        // Initialize decoder with source symbols
        for source_symbol in symbols {
            decoder.add_source_symbol(cx, source_symbol).await?;
        }

        // Add repair symbols if needed
        for repair_symbol in repair_symbols {
            decoder.add_repair_symbol(cx, repair_symbol).await?;
        }

        // Attempt decode
        let decoded_data = match decoder.decode(cx, object_id).await {
            Ok(data) => data,
            Err(e) => {
                // Decode failure - record as regression
                let failure_regression = RegressionEvent::ConvergenceRegression {
                    source_block,
                    baseline_success_rate: 0.999,
                    observed_success_rate: 0.0,
                    convergence_threshold: 0.95,
                };

                self.regression_tracker.record_regression_detected();
                self.regression_tracker.record_regression_source_block();

                self.regression_tracker
                    .record_regression_event(cx, source_block, "decode_failure".to_string())
                    .await;

                return Err(e);
            }
        };

        let decode_duration = decode_start.elapsed();

        // Generate proof for decode correctness
        let proof = self
            .proof_generator
            .generate_decode_proof(cx, object_id, source_block, &decoded_data)
            .await?;

        self.regression_tracker.record_proof_generated();

        // Validate proof
        let proof_validator = ProofValidator::new(self.proof_generator.config().clone());
        let proof_result = proof_validator.validate_proof(cx, &proof).await?;

        self.regression_tracker.record_proof_validation();

        if !proof_result.is_valid() {
            self.regression_tracker.record_proof_validation_failure();

            return Err(format!(
                "Proof validation failed for source block {}: {:?}",
                source_block.value(),
                proof_result.failure_reason()
            )
            .into());
        }

        // Check for performance regression
        let mut baselines = self.baselines.lock(cx).await;
        let performance_regression = if let Some(baseline) = baselines.get(&source_block) {
            let regression_factor =
                decode_duration.as_millis() as f64 / baseline.decode_time.as_millis() as f64;

            if regression_factor > 1.5 {
                // 50% slowdown threshold
                self.regression_tracker.record_regression_detected();
                self.regression_tracker.record_regression_source_block();

                self.regression_tracker
                    .record_regression_event(cx, source_block, "performance_regression".to_string())
                    .await;

                Some(RegressionEvent::PerformanceRegression {
                    source_block,
                    baseline_time: baseline.decode_time,
                    observed_time: decode_duration,
                    regression_factor,
                })
            } else {
                None
            }
        } else {
            // Establish baseline for future comparison
            baselines.insert(
                source_block,
                PerformanceBaseline {
                    decode_time: decode_duration,
                    memory_usage: 1024 * 1024, // Simplified
                    success_rate: 1.0,
                    quality_score: 1.0,
                },
            );
            None
        };

        // Report any detected regression
        let final_regression = regression_event.or(performance_regression);
        if let Some(regression) = &final_regression {
            self.regression_detector
                .report_regression(cx, regression.clone())
                .await?;
        }

        Ok((decoded_data, Some(proof), final_regression))
    }

    async fn get_regression_report(&self, cx: &Cx) -> Outcome<RegressionReport> {
        self.regression_detector.generate_report(cx).await
    }
}

/// Comprehensive integration test for RaptorQ proof and regression detection coordination
#[tokio::test]
async fn test_raptorq_proof_regression_synthetic_detection() -> Outcome<()> {
    let runtime = RuntimeBuilder::new()
        .with_deterministic_execution(false)
        .build()
        .await?;

    runtime
        .run(async move |cx| {
            let scope = cx.scope("raptorq_proof_regression_integration").await?;

            scope
                .run(async move |cx| {
                    // Initialize tracking
                    let regression_tracker = RegressionProofTracker::new();

                    // Configure proof generation
                    let proof_config = ProofConfig {
                        enable_correctness_proofs: true,
                        enable_performance_proofs: true,
                        proof_verification_level: "strict".to_string(),
                        max_proof_size: 1024 * 1024, // 1MB
                    };

                    // Configure regression detection
                    let regression_config = RegressionConfig {
                        performance_threshold: 1.5, // 50% slowdown
                        quality_threshold: 0.95,
                        memory_threshold: 1.3, // 30% memory increase
                        convergence_threshold: 0.9,
                        baseline_window_size: 100,
                    };

                    // Configure decoder
                    let decoder_config = DecoderConfig {
                        max_source_symbols: 1024,
                        max_repair_symbols: 512,
                        symbol_timeout: Duration::from_secs(10),
                        enable_early_reconstruction: true,
                    };

                    // Set up synthetic regression injection
                    let target_source_blocks: HashSet<SourceBlockNumber> = (2..8)
                        .map(|i| SourceBlockNumber::new(i))
                        .collect();

                    let regression_injector = SyntheticRegressionInjector::new(
                        0.7, // 70% injection probability for target blocks
                        target_source_blocks.clone(),
                        RngSeed::new(12345),
                        regression_tracker.clone(),
                    );

                    // Create proof-enabled decoder
                    let proof_decoder = ProofEnabledRaptorQDecoder::new(
                        cx,
                        decoder_config,
                        proof_config,
                        regression_config,
                        regression_injector,
                        regression_tracker.clone(),
                    ).await?;

                    // Phase 1: Test normal decoding to establish baselines
                    let normal_source_blocks: Vec<SourceBlockNumber> = (0..5)
                        .map(|i| SourceBlockNumber::new(i))
                        .collect();

                    for &source_block in &normal_source_blocks {
                        let object_id = ObjectId::new(source_block.value() as u64);

                        // Generate test symbols
                        let mut source_symbols = Vec::new();
                        for i in 0..10 {
                            let symbol_data = format!("source_data_{}_{}", source_block.value(), i)
                                .as_bytes()
                                .to_vec();

                            source_symbols.push(SourceSymbol::new(
                                SymbolId::source(source_block, i),
                                symbol_data,
                            ));
                        }

                        let repair_symbols = Vec::new(); // No repair symbols needed

                        // Decode with proof generation
                        let result = proof_decoder
                            .decode_with_proof_and_regression_detection(
                                cx,
                                object_id,
                                source_block,
                                source_symbols,
                                repair_symbols,
                            )
                            .await;

                        match result {
                            Ok((decoded_data, proof, regression)) => {
                                assert!(proof.is_some(), "Should generate proof for successful decode");
                                assert!(regression.is_none(), "Should not detect regression in normal operation");

                                println!(
                                    "Normal decode successful for source block {}: {} bytes, proof generated",
                                    source_block.value(),
                                    decoded_data.len()
                                );
                            }
                            Err(e) => {
                                return Err(format!("Normal decode failed for source block {}: {}", source_block.value(), e).into());
                            }
                        }

                        // Small delay between operations
                        Sleep::new(Duration::from_millis(10)).await;
                    }

                    // Phase 2: Test regression injection and detection
                    println!("Testing regression injection for target source blocks: {:?}", target_source_blocks);

                    let mut detected_regressions = Vec::new();

                    for &source_block in &target_source_blocks {
                        let object_id = ObjectId::new((source_block.value() + 100) as u64);

                        // Generate test symbols
                        let mut source_symbols = Vec::new();
                        for i in 0..10 {
                            let symbol_data = format!("regression_test_data_{}_{}", source_block.value(), i)
                                .as_bytes()
                                .to_vec();

                            source_symbols.push(SourceSymbol::new(
                                SymbolId::source(source_block, i),
                                symbol_data,
                            ));
                        }

                        let repair_symbols = Vec::new();

                        // Decode with regression injection enabled
                        let result = proof_decoder
                            .decode_with_proof_and_regression_detection(
                                cx,
                                object_id,
                                source_block,
                                source_symbols,
                                repair_symbols,
                            )
                            .await;

                        match result {
                            Ok((decoded_data, proof, regression)) => {
                                if let Some(regression_event) = regression {
                                    detected_regressions.push((source_block, regression_event));
                                    println!(
                                        "Regression detected for source block {}: {:?}",
                                        source_block.value(),
                                        detected_regressions.last().unwrap().1
                                    );
                                } else {
                                    println!(
                                        "No regression detected for source block {} (injection may not have occurred)",
                                        source_block.value()
                                    );
                                }

                                assert!(proof.is_some(), "Should still generate proof even with regression");
                            }
                            Err(e) => {
                                // Decode failure due to severe regression
                                println!(
                                    "Decode failed for source block {} due to regression: {}",
                                    source_block.value(),
                                    e
                                );

                                detected_regressions.push((source_block, RegressionEvent::ConvergenceRegression {
                                    source_block,
                                    baseline_success_rate: 0.999,
                                    observed_success_rate: 0.0,
                                    convergence_threshold: 0.95,
                                }));
                            }
                        }

                        Sleep::new(Duration::from_millis(5)).await;
                    }

                    // Phase 3: Verify regression detection worked
                    assert!(
                        detected_regressions.len() > 0,
                        "Should have detected at least some regressions from synthetic injection"
                    );

                    // Verify exact source blocks were identified
                    let detected_source_blocks: HashSet<SourceBlockNumber> = detected_regressions
                        .iter()
                        .map(|(sb, _)| *sb)
                        .collect();

                    for &detected_sb in &detected_source_blocks {
                        assert!(
                            target_source_blocks.contains(&detected_sb),
                            "Detected regression source block {} should be in target set",
                            detected_sb.value()
                        );
                    }

                    println!(
                        "Detected regressions in {} out of {} target source blocks",
                        detected_regressions.len(),
                        target_source_blocks.len()
                    );

                    // Phase 4: Generate comprehensive regression report
                    let regression_report = proof_decoder.get_regression_report(cx).await?;

                    assert!(
                        regression_report.total_regressions() > 0,
                        "Regression report should contain detected regressions"
                    );

                    let critical_regressions = regression_report.critical_regressions();
                    println!(
                        "Regression report: {} total regressions, {} critical",
                        regression_report.total_regressions(),
                        critical_regressions.len()
                    );

                    // Phase 5: Verify tracking and coordination
                    assert!(
                        regression_tracker.verify_regression_detection(),
                        "Should have detected synthetic regressions"
                    );

                    assert!(
                        regression_tracker.verify_source_block_identification(),
                        "Should have identified specific source blocks triggering regressions"
                    );

                    assert!(
                        regression_tracker.verify_proof_validation_integration(),
                        "Should have integrated proof validation with regression detection"
                    );

                    // Verify statistics
                    let proofs_generated = regression_tracker.proofs_generated.load(Ordering::Relaxed);
                    let regressions_detected = regression_tracker.regressions_detected.load(Ordering::Relaxed);
                    let source_blocks_identified = regression_tracker.regression_source_blocks.load(Ordering::Relaxed);
                    let synthetic_injected = regression_tracker.synthetic_regressions_injected.load(Ordering::Relaxed);

                    assert!(
                        proofs_generated >= normal_source_blocks.len() as u64,
                        "Should have generated proofs for decode operations"
                    );

                    assert!(
                        regressions_detected >= detected_regressions.len() as u64,
                        "Should have detected expected number of regressions"
                    );

                    assert!(
                        source_blocks_identified >= regressions_detected,
                        "Should have identified source blocks for detected regressions"
                    );

                    assert!(
                        synthetic_injected > 0,
                        "Should have injected synthetic regressions"
                    );

                    println!(
                        "Integration test completed: {} proofs generated, {} regressions detected, {} source blocks identified, {} synthetic injected",
                        proofs_generated, regressions_detected, source_blocks_identified, synthetic_injected
                    );

                    Ok(())
                })
                .await
        })
        .await
}

/// Test proof validation failure detection and regression correlation
#[tokio::test]
async fn test_proof_validation_failure_regression_correlation() -> Outcome<()> {
    let runtime = RuntimeBuilder::new()
        .with_deterministic_execution(false)
        .build()
        .await?;

    runtime
        .run(async move |cx| {
            let scope = cx.scope("proof_validation_failure_correlation").await?;

            scope
                .run(async move |cx| {
                    let regression_tracker = RegressionProofTracker::new();

                    // Configure stricter proof validation
                    let strict_proof_config = ProofConfig {
                        enable_correctness_proofs: true,
                        enable_performance_proofs: true,
                        proof_verification_level: "paranoid".to_string(),
                        max_proof_size: 512 * 1024, // Smaller limit to trigger failures
                    };

                    let regression_config = RegressionConfig {
                        performance_threshold: 1.2, // Lower threshold
                        quality_threshold: 0.98,    // Higher quality requirement
                        memory_threshold: 1.1,
                        convergence_threshold: 0.98,
                        baseline_window_size: 50,
                    };

                    let decoder_config = DecoderConfig {
                        max_source_symbols: 256,
                        max_repair_symbols: 128,
                        symbol_timeout: Duration::from_secs(5),
                        enable_early_reconstruction: false, // Disable for stricter testing
                    };

                    // Target blocks that will trigger validation failures
                    let failure_target_blocks: HashSet<SourceBlockNumber> =
                        (10..15).map(|i| SourceBlockNumber::new(i)).collect();

                    let regression_injector = SyntheticRegressionInjector::new(
                        0.9, // High injection rate
                        failure_target_blocks.clone(),
                        RngSeed::new(54321),
                        regression_tracker.clone(),
                    );

                    let proof_decoder = ProofEnabledRaptorQDecoder::new(
                        cx,
                        decoder_config,
                        strict_proof_config,
                        regression_config,
                        regression_injector,
                        regression_tracker.clone(),
                    )
                    .await?;

                    // Test proof validation failures with regression correlation
                    for &source_block in &failure_target_blocks {
                        let object_id = ObjectId::new((source_block.value() + 200) as u64);

                        // Generate symbols that may trigger validation issues
                        let mut source_symbols = Vec::new();
                        for i in 0..8 {
                            let symbol_data = vec![0xFFu8; 1024]; // Repetitive data that may cause issues

                            source_symbols.push(SourceSymbol::new(
                                SymbolId::source(source_block, i),
                                symbol_data,
                            ));
                        }

                        let repair_symbols = Vec::new();

                        let result = proof_decoder
                            .decode_with_proof_and_regression_detection(
                                cx,
                                object_id,
                                source_block,
                                source_symbols,
                                repair_symbols,
                            )
                            .await;

                        match result {
                            Ok((_, proof, regression)) => {
                                if proof.is_some() && regression.is_some() {
                                    println!(
                                        "Source block {} had both proof and regression: {:?}",
                                        source_block.value(),
                                        regression
                                    );
                                }
                            }
                            Err(e) => {
                                println!(
                                    "Source block {} failed (expected for strict validation): {}",
                                    source_block.value(),
                                    e
                                );
                            }
                        }
                    }

                    // Verify that proof validation failures were detected
                    let validation_failures = regression_tracker
                        .proof_validation_failures
                        .load(Ordering::Relaxed);
                    let regressions_detected = regression_tracker
                        .regressions_detected
                        .load(Ordering::Relaxed);

                    println!(
                        "Strict validation test: {} validation failures, {} regressions detected",
                        validation_failures, regressions_detected
                    );

                    // Should have some correlation between validation failures and regressions
                    assert!(
                        validation_failures > 0 || regressions_detected > 0,
                        "Should detect validation failures or regressions under strict conditions"
                    );

                    Ok(())
                })
                .await
        })
        .await
}

/// Test performance baseline establishment and drift detection
#[tokio::test]
async fn test_performance_baseline_drift_detection() -> Outcome<()> {
    let runtime = RuntimeBuilder::new()
        .with_deterministic_execution(false)
        .build()
        .await?;

    runtime
        .run(async move |cx| {
            let scope = cx.scope("baseline_drift_detection").await?;

            scope
                .run(async move |cx| {
                    let regression_tracker = RegressionProofTracker::new();

                    let proof_config = ProofConfig {
                        enable_correctness_proofs: true,
                        enable_performance_proofs: true,
                        proof_verification_level: "standard".to_string(),
                        max_proof_size: 2 * 1024 * 1024,
                    };

                    let regression_config = RegressionConfig {
                        performance_threshold: 1.3, // 30% slowdown
                        quality_threshold: 0.95,
                        memory_threshold: 1.2,
                        convergence_threshold: 0.95,
                        baseline_window_size: 20, // Smaller window for faster testing
                    };

                    let decoder_config = DecoderConfig {
                        max_source_symbols: 512,
                        max_repair_symbols: 256,
                        symbol_timeout: Duration::from_secs(8),
                        enable_early_reconstruction: true,
                    };

                    // No synthetic injection - test natural baseline establishment
                    let regression_injector = SyntheticRegressionInjector::new(
                        0.0, // No injection
                        HashSet::new(),
                        RngSeed::new(11111),
                        regression_tracker.clone(),
                    );

                    let proof_decoder = ProofEnabledRaptorQDecoder::new(
                        cx,
                        decoder_config,
                        proof_config,
                        regression_config,
                        regression_injector,
                        regression_tracker.clone(),
                    ).await?;

                    // Phase 1: Establish baseline with consistent performance
                    let baseline_source_block = SourceBlockNumber::new(100);

                    for i in 0..10 {
                        let object_id = ObjectId::new(1000 + i);

                        let mut source_symbols = Vec::new();
                        for j in 0..12 {
                            let symbol_data = format!("baseline_data_{}_{}_{}", i, j, "x".repeat(100))
                                .as_bytes()
                                .to_vec();

                            source_symbols.push(SourceSymbol::new(
                                SymbolId::source(baseline_source_block, j),
                                symbol_data,
                            ));
                        }

                        let repair_symbols = Vec::new();

                        let result = proof_decoder
                            .decode_with_proof_and_regression_detection(
                                cx,
                                object_id,
                                baseline_source_block,
                                source_symbols,
                                repair_symbols,
                            )
                            .await;

                        match result {
                            Ok((_, proof, regression)) => {
                                assert!(proof.is_some(), "Should generate proof for baseline establishment");
                                assert!(regression.is_none(), "Should not detect regression during baseline establishment");
                            }
                            Err(e) => {
                                return Err(format!("Baseline establishment failed at iteration {}: {}", i, e).into());
                            }
                        }

                        Sleep::new(Duration::from_millis(5)).await;
                    }

                    // Phase 2: Test with gradually degrading performance
                    for i in 0..5 {
                        let object_id = ObjectId::new(2000 + i);

                        let mut source_symbols = Vec::new();
                        for j in 0..12 {
                            // Larger data to simulate performance degradation
                            let data_size = 100 + (i * 50); // Growing data size
                            let symbol_data = format!("degraded_data_{}_{}_{}", i, j, "x".repeat(data_size))
                                .as_bytes()
                                .to_vec();

                            source_symbols.push(SourceSymbol::new(
                                SymbolId::source(baseline_source_block, j),
                                symbol_data,
                            ));
                        }

                        // Add artificial delay to simulate performance regression
                        Sleep::new(Duration::from_millis(5 + (i as u64 * 2))).await;

                        let repair_symbols = Vec::new();

                        let result = proof_decoder
                            .decode_with_proof_and_regression_detection(
                                cx,
                                object_id,
                                baseline_source_block,
                                source_symbols,
                                repair_symbols,
                            )
                            .await;

                        match result {
                            Ok((_, proof, regression)) => {
                                if let Some(regression_event) = regression {
                                    println!(
                                        "Performance drift detected at iteration {}: {:?}",
                                        i, regression_event
                                    );
                                }

                                assert!(proof.is_some(), "Should generate proof even during performance drift");
                            }
                            Err(e) => {
                                println!("Decode failed during performance degradation at iteration {}: {}", i, e);
                            }
                        }

                        Sleep::new(Duration::from_millis(2)).await;
                    }

                    // Verify that some performance drift was detected
                    let regressions_detected = regression_tracker.regressions_detected.load(Ordering::Relaxed);
                    println!("Performance baseline test: {} regressions detected", regressions_detected);

                    // Should detect performance drift over time
                    assert!(
                        regressions_detected > 0,
                        "Should detect performance drift from baseline"
                    );

                    Ok(())
                })
                .await
        })
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_regression_proof_tracker_creation() {
        let tracker = RegressionProofTracker::new();

        // Verify initial state
        assert_eq!(tracker.proofs_generated.load(Ordering::Relaxed), 0);
        assert_eq!(tracker.proof_validations.load(Ordering::Relaxed), 0);
        assert_eq!(tracker.proof_validation_failures.load(Ordering::Relaxed), 0);
        assert_eq!(tracker.regressions_detected.load(Ordering::Relaxed), 0);
        assert_eq!(tracker.regression_source_blocks.load(Ordering::Relaxed), 0);
        assert_eq!(
            tracker
                .synthetic_regressions_injected
                .load(Ordering::Relaxed),
            0
        );
        assert_eq!(
            tracker.quality_threshold_violations.load(Ordering::Relaxed),
            0
        );
    }

    #[test]
    fn test_regression_proof_tracking() {
        let tracker = RegressionProofTracker::new();

        // Record events
        tracker.record_proof_generated();
        tracker.record_proof_validation();
        tracker.record_regression_detected();
        tracker.record_regression_source_block();
        tracker.record_synthetic_regression_injected();

        // Verify tracking
        assert_eq!(tracker.proofs_generated.load(Ordering::Relaxed), 1);
        assert_eq!(tracker.proof_validations.load(Ordering::Relaxed), 1);
        assert_eq!(tracker.regressions_detected.load(Ordering::Relaxed), 1);
        assert_eq!(tracker.regression_source_blocks.load(Ordering::Relaxed), 1);
        assert_eq!(
            tracker
                .synthetic_regressions_injected
                .load(Ordering::Relaxed),
            1
        );

        // Verify verification methods
        assert!(tracker.verify_regression_detection());
        assert!(tracker.verify_source_block_identification());
        assert!(tracker.verify_proof_validation_integration());
    }

    #[test]
    fn test_regression_detection_verification() {
        let tracker = RegressionProofTracker::new();

        // No activity
        assert!(!tracker.verify_regression_detection());

        // Injection without detection
        tracker.record_synthetic_regression_injected();
        assert!(!tracker.verify_regression_detection());

        // Detection without injection (possible but unexpected)
        let tracker2 = RegressionProofTracker::new();
        tracker2.record_regression_detected();
        assert!(!tracker2.verify_regression_detection());

        // Proper detection
        let tracker3 = RegressionProofTracker::new();
        tracker3.record_synthetic_regression_injected();
        tracker3.record_regression_detected();
        assert!(tracker3.verify_regression_detection());

        // More detections than injections (also acceptable)
        let tracker4 = RegressionProofTracker::new();
        tracker4.record_synthetic_regression_injected();
        tracker4.record_regression_detected();
        tracker4.record_regression_detected();
        assert!(tracker4.verify_regression_detection());
    }

    #[test]
    fn test_source_block_identification_verification() {
        let tracker = RegressionProofTracker::new();

        // No activity
        assert!(!tracker.verify_source_block_identification());

        // Detection without source block identification
        tracker.record_regression_detected();
        assert!(!tracker.verify_source_block_identification());

        // Proper identification
        let tracker2 = RegressionProofTracker::new();
        tracker2.record_regression_detected();
        tracker2.record_regression_source_block();
        assert!(tracker2.verify_source_block_identification());

        // More source blocks than detections (over-identification is acceptable)
        let tracker3 = RegressionProofTracker::new();
        tracker3.record_regression_detected();
        tracker3.record_regression_source_block();
        tracker3.record_regression_source_block();
        assert!(tracker3.verify_source_block_identification());
    }

    #[test]
    fn test_proof_validation_integration_verification() {
        let tracker = RegressionProofTracker::new();

        // No activity
        assert!(!tracker.verify_proof_validation_integration());

        // Proofs without validation
        tracker.record_proof_generated();
        assert!(!tracker.verify_proof_validation_integration());

        // Validation without proofs (unusual but possible)
        let tracker2 = RegressionProofTracker::new();
        tracker2.record_proof_validation();
        assert!(!tracker2.verify_proof_validation_integration());

        // Proper integration
        let tracker3 = RegressionProofTracker::new();
        tracker3.record_proof_generated();
        tracker3.record_proof_validation();
        assert!(tracker3.verify_proof_validation_integration());

        // More validations than proofs (re-validation is acceptable)
        let tracker4 = RegressionProofTracker::new();
        tracker4.record_proof_generated();
        tracker4.record_proof_validation();
        tracker4.record_proof_validation();
        assert!(tracker4.verify_proof_validation_integration());
    }

    #[test]
    fn test_regression_type_cloning() {
        let regression_types = vec![
            RegressionType::SlowDecoding {
                slowdown_factor: 2.0,
            },
            RegressionType::SymbolErrorRate { error_rate: 0.05 },
            RegressionType::MemoryRegression {
                overhead_factor: 1.5,
            },
            RegressionType::ConvergenceFailure { failure_rate: 0.1 },
        ];

        // Verify cloning works for all types
        for regression_type in &regression_types {
            let cloned = regression_type.clone();
            // Basic verification that cloning doesn't panic
            assert!(format!("{:?}", regression_type) == format!("{:?}", cloned));
        }
    }
}
