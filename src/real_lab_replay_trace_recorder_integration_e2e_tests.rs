//! BR-E2E-86: Real Lab Replay ↔ Trace Recorder Integration E2E Tests
//!
//! This module provides comprehensive integration tests between the lab replay
//! system and trace recorder subsystems. The tests verify that recorded executions
//! replayed under chaos injection produce divergence reports with exact
//! non-deterministic decision points.
//!
//! # Integration Focus
//!
//! Tests the coordination between:
//! - `lab::replay` - Deterministic execution replay with chaos injection
//! - `trace::recorder` - Execution trace recording and divergence detection
//!
//! # Key Scenarios
//!
//! - Record deterministic execution trace with decision points
//! - Replay execution with injected chaos/non-determinism
//! - Detect exact divergence points between original and replayed execution
//! - Report non-deterministic decisions with precise context
//! - Validate trace integrity and replay fidelity

use crate::{
    cx::{Cx, Scope},
    error::Outcome,
    lab::{
        chaos::{ChaosConfig, ChaosEvent, ChaosInjector, ChaosType},
        replay::{ReplayConfig, ReplayEngine, ReplayEvent, ReplaySession, ReplayStats},
        runtime::{LabRuntime, LabRuntimeConfig, VirtualTime},
    },
    runtime::{RuntimeBuilder, TaskHandle},
    sync::{Barrier, Mutex, Semaphore},
    time::{Duration, Sleep},
    trace::{
        event::{EventId, TraceEvent, TraceId},
        minimizer::TraceMinimizer,
        recorder::{
            DecisionPoint, DivergenceReport, ExecutionTrace, RecorderConfig, RecorderEvent,
            TraceRecorder, TraceReplayComparator,
        },
    },
    types::{Budget, RegionId, TaskId},
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

/// Tracks divergence detection events during replay with chaos injection
#[derive(Debug, Clone)]
struct DivergenceTracker {
    /// Original execution decision points recorded
    original_decisions_recorded: Arc<AtomicU64>,
    /// Replay decisions that diverged from original
    divergent_decisions: Arc<AtomicU64>,
    /// Exact divergence points detected
    divergence_points_detected: Arc<AtomicU64>,
    /// Chaos injection events that caused divergence
    chaos_induced_divergences: Arc<AtomicU64>,
    /// Successful replay sessions completed
    replay_sessions_completed: Arc<AtomicU64>,
    /// Failed replay sessions
    replay_sessions_failed: Arc<AtomicU64>,
    /// Divergence timeline for analysis
    divergence_timeline: Arc<Mutex<Vec<(EventId, TraceEvent, std::time::Instant)>>>,
}

impl DivergenceTracker {
    fn new() -> Self {
        Self {
            original_decisions_recorded: Arc::new(AtomicU64::new(0)),
            divergent_decisions: Arc::new(AtomicU64::new(0)),
            divergence_points_detected: Arc::new(AtomicU64::new(0)),
            chaos_induced_divergences: Arc::new(AtomicU64::new(0)),
            replay_sessions_completed: Arc::new(AtomicU64::new(0)),
            replay_sessions_failed: Arc::new(AtomicU64::new(0)),
            divergence_timeline: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn record_original_decision(&self) {
        self.original_decisions_recorded
            .fetch_add(1, Ordering::Relaxed);
    }

    fn record_divergent_decision(&self) {
        self.divergent_decisions.fetch_add(1, Ordering::Relaxed);
    }

    fn record_divergence_point(&self) {
        self.divergence_points_detected
            .fetch_add(1, Ordering::Relaxed);
    }

    fn record_chaos_induced_divergence(&self) {
        self.chaos_induced_divergences
            .fetch_add(1, Ordering::Relaxed);
    }

    fn record_replay_completed(&self) {
        self.replay_sessions_completed
            .fetch_add(1, Ordering::Relaxed);
    }

    fn record_replay_failed(&self) {
        self.replay_sessions_failed.fetch_add(1, Ordering::Relaxed);
    }

    async fn record_divergence_event(&self, cx: &Cx, event_id: EventId, trace_event: TraceEvent) {
        let mut timeline = self.divergence_timeline.lock(cx).await;
        timeline.push((event_id, trace_event, std::time::Instant::now()));
    }

    fn verify_divergence_detection(&self) -> bool {
        let divergences = self.divergence_points_detected.load(Ordering::Relaxed);
        let chaos_divergences = self.chaos_induced_divergences.load(Ordering::Relaxed);
        let completed = self.replay_sessions_completed.load(Ordering::Relaxed);

        // Should have detected divergences from chaos injection
        divergences > 0 && chaos_divergences > 0 && completed > 0
    }

    fn verify_replay_success(&self) -> bool {
        let completed = self.replay_sessions_completed.load(Ordering::Relaxed);
        let failed = self.replay_sessions_failed.load(Ordering::Relaxed);

        // Should have more successful replays than failures
        completed > 0 && completed > failed
    }
}

/// Simulates a non-deterministic computation that creates decision points
struct NonDeterministicComputation {
    /// Computation identifier
    id: u64,
    /// Number of decision points in computation
    decision_count: usize,
    /// Random seed for original execution
    original_seed: RngSeed,
    /// Decision outcomes from original execution
    original_decisions: Arc<Mutex<Vec<u64>>>,
    /// Divergence tracking
    divergence_tracker: DivergenceTracker,
}

impl NonDeterministicComputation {
    fn new(
        id: u64,
        decision_count: usize,
        original_seed: RngSeed,
        divergence_tracker: DivergenceTracker,
    ) -> Self {
        Self {
            id,
            decision_count,
            original_seed,
            original_decisions: Arc::new(Mutex::new(Vec::new())),
            divergence_tracker,
        }
    }

    async fn execute_original(&self, cx: &Cx, recorder: &TraceRecorder) -> Outcome<Vec<u64>> {
        let mut rng = DetRng::from_seed(self.original_seed);
        let mut decisions = Vec::new();

        for i in 0..self.decision_count {
            // Create a decision point
            let decision_point = DecisionPoint {
                id: EventId::new(self.id * 1000 + i as u64),
                context: format!("computation_{}_decision_{}", self.id, i),
                alternatives: vec!["path_a".to_string(), "path_b".to_string()],
                timestamp: VirtualTime::now(),
            };

            // Record the decision point
            recorder
                .record_decision_point(cx, decision_point.clone())
                .await?;
            self.divergence_tracker.record_original_decision();

            // Make a random decision
            let decision = rng.gen_range(0..=1000);
            decisions.push(decision);

            // Record the decision outcome
            let trace_event = TraceEvent::DecisionMade {
                decision_id: decision_point.id,
                chosen_alternative: if decision % 2 == 0 {
                    "path_a"
                } else {
                    "path_b"
                }
                .to_string(),
                outcome_value: decision,
            };

            recorder.record_event(cx, trace_event).await?;

            // Simulate computation based on decision
            if decision % 2 == 0 {
                // Path A: Fast computation
                Sleep::new(Duration::from_millis(1)).await;
            } else {
                // Path B: Slower computation
                Sleep::new(Duration::from_millis(3)).await;
            }

            // Yield to allow other tasks to run
            if i % 5 == 0 {
                cx.yield_now().await;
            }
        }

        let mut original_decisions = self.original_decisions.lock(cx).await;
        *original_decisions = decisions.clone();

        Ok(decisions)
    }

    async fn execute_replay(
        &self,
        cx: &Cx,
        recorder: &TraceRecorder,
        chaos_injector: &ChaosInjector,
    ) -> Outcome<(Vec<u64>, Vec<DecisionPoint>)> {
        let mut rng = DetRng::from_seed(self.original_seed);
        let mut replay_decisions = Vec::new();
        let mut divergence_points = Vec::new();

        let original_decisions = self.original_decisions.lock(cx).await;
        let original_decisions = original_decisions.clone();

        for i in 0..self.decision_count {
            // Create the same decision point as original
            let decision_point = DecisionPoint {
                id: EventId::new(self.id * 1000 + i as u64),
                context: format!("computation_{}_decision_{}", self.id, i),
                alternatives: vec!["path_a".to_string(), "path_b".to_string()],
                timestamp: VirtualTime::now(),
            };

            // Check for chaos injection at this decision point
            if let Some(chaos_event) = chaos_injector
                .maybe_inject_chaos(cx, &decision_point)
                .await?
            {
                match chaos_event.chaos_type {
                    ChaosType::SchedulingDelay => {
                        // Inject scheduling delay
                        Sleep::new(Duration::from_millis(5)).await;
                    }
                    ChaosType::TaskPreemption => {
                        // Force a yield
                        cx.yield_now().await;
                        Sleep::new(Duration::from_micros(100)).await;
                    }
                    ChaosType::ResourceContention => {
                        // Simulate contention delay
                        Sleep::new(Duration::from_millis(2)).await;
                    }
                    _ => {
                        // Other chaos types
                    }
                }

                self.divergence_tracker.record_chaos_induced_divergence();
            }

            // Make decision (potentially affected by chaos)
            let decision = if chaos_injector.is_chaos_active() {
                // Chaos may affect the decision
                let base_decision = rng.gen_range(0..=1000);
                let chaos_offset = rng.gen_range(0..=50);
                base_decision.wrapping_add(chaos_offset)
            } else {
                // Original decision path
                rng.gen_range(0..=1000)
            };

            replay_decisions.push(decision);

            // Check for divergence from original
            if i < original_decisions.len() {
                let original_decision = original_decisions[i];
                if decision != original_decision {
                    self.divergence_tracker.record_divergent_decision();
                    self.divergence_tracker.record_divergence_point();

                    divergence_points.push(decision_point.clone());

                    // Record divergence event
                    let trace_event = TraceEvent::DivergenceDetected {
                        original_decision: original_decision,
                        replay_decision: decision,
                        divergence_context: decision_point.context.clone(),
                    };

                    self.divergence_tracker
                        .record_divergence_event(cx, decision_point.id, trace_event.clone())
                        .await;

                    recorder.record_event(cx, trace_event).await?;
                }
            }

            // Record the replay decision
            let trace_event = TraceEvent::DecisionMade {
                decision_id: decision_point.id,
                chosen_alternative: if decision % 2 == 0 {
                    "path_a"
                } else {
                    "path_b"
                }
                .to_string(),
                outcome_value: decision,
            };

            recorder.record_event(cx, trace_event).await?;

            // Execute the same computation paths
            if decision % 2 == 0 {
                Sleep::new(Duration::from_millis(1)).await;
            } else {
                Sleep::new(Duration::from_millis(3)).await;
            }

            if i % 5 == 0 {
                cx.yield_now().await;
            }
        }

        Ok((replay_decisions, divergence_points))
    }
}

/// Comprehensive integration test for lab replay and trace recorder coordination
#[tokio::test]
async fn test_lab_replay_trace_recorder_divergence_detection() -> Outcome<()> {
    let runtime = RuntimeBuilder::new()
        .with_deterministic_execution(false)
        .build()
        .await?;

    runtime
        .run(async move |cx| {
            let scope = cx.scope("lab_replay_trace_recorder_integration").await?;

            scope
                .run(async move |cx| {
                    // Initialize tracking
                    let divergence_tracker = DivergenceTracker::new();

                    // Configure lab runtime for deterministic replay
                    let lab_config = LabRuntimeConfig {
                        enable_deterministic_scheduling: true,
                        enable_virtual_time: true,
                        seed: RngSeed::new(12345),
                        chaos_probability: 0.0, // Start without chaos
                    };

                    let mut lab_runtime = LabRuntime::new(lab_config);

                    // Configure trace recorder
                    let recorder_config = RecorderConfig {
                        max_events: 10000,
                        max_decision_points: 1000,
                        enable_compression: false,
                        buffer_size: 4096,
                    };

                    let recorder = TraceRecorder::new(recorder_config);

                    // Configure replay engine
                    let replay_config = ReplayConfig {
                        max_replay_attempts: 3,
                        divergence_detection_threshold: 0.1,
                        enable_chaos_injection: true,
                        replay_timeout: Duration::from_secs(30),
                    };

                    let mut replay_engine = ReplayEngine::new(replay_config);

                    // Phase 1: Record original deterministic execution
                    let computation = NonDeterministicComputation::new(
                        1,
                        20, // 20 decision points
                        RngSeed::new(67890),
                        divergence_tracker.clone(),
                    );

                    recorder.start_recording(cx).await?;

                    let original_trace = lab_runtime.run_deterministic(cx, async {
                        computation.execute_original(cx, &recorder).await
                    }).await?;

                    let execution_trace = recorder.stop_recording(cx).await?;

                    match original_trace {
                        Ok(original_decisions) => {
                            assert_eq!(
                                original_decisions.len(),
                                20,
                                "Should have recorded 20 decisions"
                            );

                            let trace_stats = execution_trace.stats();
                            assert!(
                                trace_stats.decision_points > 0,
                                "Should have recorded decision points"
                            );

                            println!(
                                "Original execution: {} decisions, {} trace events",
                                original_decisions.len(),
                                trace_stats.total_events
                            );
                        }
                        Err(e) => return Err(format!("Original execution failed: {}", e).into()),
                    }

                    // Phase 2: Configure chaos injection
                    let chaos_config = ChaosConfig {
                        injection_probability: 0.3, // 30% chance of chaos at each decision point
                        chaos_types: vec![
                            ChaosType::SchedulingDelay,
                            ChaosType::TaskPreemption,
                            ChaosType::ResourceContention,
                        ],
                        intensity: 0.5,
                        seed: RngSeed::new(99999),
                    };

                    let chaos_injector = ChaosInjector::new(chaos_config);

                    // Phase 3: Replay with chaos injection
                    let replay_session = ReplaySession::new(
                        execution_trace.clone(),
                        chaos_injector.clone(),
                    );

                    recorder.start_recording(cx).await?;

                    let replay_result = replay_engine
                        .replay_with_chaos(cx, replay_session, async {
                            computation
                                .execute_replay(cx, &recorder, &chaos_injector)
                                .await
                        })
                        .await?;

                    let replay_trace = recorder.stop_recording(cx).await?;

                    match replay_result {
                        Ok((replay_decisions, divergence_points)) => {
                            divergence_tracker.record_replay_completed();

                            println!(
                                "Replay execution: {} decisions, {} divergence points",
                                replay_decisions.len(),
                                divergence_points.len()
                            );

                            assert!(
                                divergence_points.len() > 0,
                                "Should have detected divergence points from chaos injection"
                            );

                            // Phase 4: Generate divergence report
                            let comparator = TraceReplayComparator::new();
                            let divergence_report = comparator
                                .compare_traces(cx, &execution_trace, &replay_trace)
                                .await?;

                            assert!(
                                divergence_report.has_divergences(),
                                "Divergence report should detect differences"
                            );

                            let divergent_decisions = divergence_report.divergent_decision_points();
                            assert!(
                                divergent_decisions.len() > 0,
                                "Should identify specific divergent decision points"
                            );

                            // Verify exact decision point context
                            for divergent_point in &divergent_decisions {
                                assert!(
                                    divergent_point.context.contains("computation_1_decision_"),
                                    "Divergence point should have exact context: {}",
                                    divergent_point.context
                                );

                                println!(
                                    "Divergence detected at: {} ({})",
                                    divergent_point.id.value(),
                                    divergent_point.context
                                );
                            }

                            // Phase 5: Minimize divergence trace
                            let minimizer = TraceMinimizer::new();
                            let minimal_divergence = minimizer
                                .minimize_to_first_divergence(cx, divergence_report)
                                .await?;

                            assert!(
                                minimal_divergence.minimal_trace_length() > 0,
                                "Should produce minimal divergent trace"
                            );

                            assert!(
                                minimal_divergence.first_divergence_point().is_some(),
                                "Should identify first divergence point"
                            );

                            if let Some(first_divergence) = minimal_divergence.first_divergence_point() {
                                println!(
                                    "First divergence at decision {}: {}",
                                    first_divergence.id.value(),
                                    first_divergence.context
                                );
                            }
                        }
                        Err(e) => {
                            divergence_tracker.record_replay_failed();
                            return Err(format!("Replay execution failed: {}", e).into());
                        }
                    }

                    // Phase 6: Verification
                    assert!(
                        divergence_tracker.verify_divergence_detection(),
                        "Should have successfully detected divergences from chaos injection"
                    );

                    assert!(
                        divergence_tracker.verify_replay_success(),
                        "Should have successfully completed replay"
                    );

                    // Verify statistics
                    let original_decisions = divergence_tracker.original_decisions_recorded.load(Ordering::Relaxed);
                    let divergent_decisions = divergence_tracker.divergent_decisions.load(Ordering::Relaxed);
                    let divergence_points = divergence_tracker.divergence_points_detected.load(Ordering::Relaxed);

                    assert!(
                        original_decisions >= 20,
                        "Should have recorded original decisions"
                    );

                    assert!(
                        divergent_decisions > 0,
                        "Should have detected divergent decisions from chaos"
                    );

                    assert!(
                        divergence_points > 0,
                        "Should have identified exact divergence points"
                    );

                    println!(
                        "Integration test completed: {} original decisions, {} divergent decisions, {} divergence points",
                        original_decisions, divergent_decisions, divergence_points
                    );

                    Ok(())
                })
                .await
        })
        .await
}

/// Test replay with different chaos injection strategies
#[tokio::test]
async fn test_replay_recorder_multiple_chaos_strategies() -> Outcome<()> {
    let runtime = RuntimeBuilder::new()
        .with_deterministic_execution(false)
        .build()
        .await?;

    runtime
        .run(async move |cx| {
            let scope = cx.scope("multiple_chaos_strategies").await?;

            scope
                .run(async move |cx| {
                    let divergence_tracker = DivergenceTracker::new();

                    let lab_config = LabRuntimeConfig {
                        enable_deterministic_scheduling: true,
                        enable_virtual_time: true,
                        seed: RngSeed::new(11111),
                        chaos_probability: 0.0,
                    };

                    let mut lab_runtime = LabRuntime::new(lab_config);

                    let recorder_config = RecorderConfig {
                        max_events: 5000,
                        max_decision_points: 500,
                        enable_compression: false,
                        buffer_size: 2048,
                    };

                    let recorder = TraceRecorder::new(recorder_config);

                    // Record baseline execution
                    let computation = NonDeterministicComputation::new(
                        2,
                        10,
                        RngSeed::new(22222),
                        divergence_tracker.clone(),
                    );

                    recorder.start_recording(cx).await?;

                    let baseline_result = lab_runtime
                        .run_deterministic(cx, async {
                            computation.execute_original(cx, &recorder).await
                        })
                        .await?;

                    let baseline_trace = recorder.stop_recording(cx).await?;

                    baseline_result?;

                    // Test different chaos strategies
                    let chaos_strategies = vec![
                        (
                            "low_intensity",
                            ChaosConfig {
                                injection_probability: 0.1,
                                chaos_types: vec![ChaosType::SchedulingDelay],
                                intensity: 0.2,
                                seed: RngSeed::new(33333),
                            },
                        ),
                        (
                            "medium_intensity",
                            ChaosConfig {
                                injection_probability: 0.3,
                                chaos_types: vec![
                                    ChaosType::SchedulingDelay,
                                    ChaosType::TaskPreemption,
                                ],
                                intensity: 0.5,
                                seed: RngSeed::new(44444),
                            },
                        ),
                        (
                            "high_intensity",
                            ChaosConfig {
                                injection_probability: 0.5,
                                chaos_types: vec![
                                    ChaosType::SchedulingDelay,
                                    ChaosType::TaskPreemption,
                                    ChaosType::ResourceContention,
                                ],
                                intensity: 0.8,
                                seed: RngSeed::new(55555),
                            },
                        ),
                    ];

                    let replay_config = ReplayConfig {
                        max_replay_attempts: 2,
                        divergence_detection_threshold: 0.05,
                        enable_chaos_injection: true,
                        replay_timeout: Duration::from_secs(15),
                    };

                    let mut replay_engine = ReplayEngine::new(replay_config);

                    for (strategy_name, chaos_config) in chaos_strategies {
                        println!("Testing chaos strategy: {}", strategy_name);

                        let chaos_injector = ChaosInjector::new(chaos_config);
                        let replay_session =
                            ReplaySession::new(baseline_trace.clone(), chaos_injector.clone());

                        recorder.start_recording(cx).await?;

                        let replay_result = replay_engine
                            .replay_with_chaos(cx, replay_session, async {
                                computation
                                    .execute_replay(cx, &recorder, &chaos_injector)
                                    .await
                            })
                            .await;

                        let strategy_trace = recorder.stop_recording(cx).await?;

                        match replay_result {
                            Ok((replay_decisions, divergence_points)) => {
                                divergence_tracker.record_replay_completed();

                                let comparator = TraceReplayComparator::new();
                                let divergence_report = comparator
                                    .compare_traces(cx, &baseline_trace, &strategy_trace)
                                    .await?;

                                println!(
                                    "Strategy {}: {} divergence points, {} trace differences",
                                    strategy_name,
                                    divergence_points.len(),
                                    divergence_report.total_divergences()
                                );

                                // Higher intensity chaos should generally produce more divergences
                                if strategy_name == "high_intensity" {
                                    assert!(
                                        divergence_points.len() > 0,
                                        "High intensity chaos should produce divergences"
                                    );
                                }
                            }
                            Err(e) => {
                                divergence_tracker.record_replay_failed();
                                println!("Strategy {} failed: {}", strategy_name, e);
                                // Some failures are acceptable under high chaos
                            }
                        }
                    }

                    // Should have at least some successful replays
                    assert!(
                        divergence_tracker
                            .replay_sessions_completed
                            .load(Ordering::Relaxed)
                            > 0,
                        "Should have completed at least some replay sessions"
                    );

                    Ok(())
                })
                .await
        })
        .await
}

/// Test trace recorder precision in capturing decision point context
#[tokio::test]
async fn test_trace_recorder_decision_point_precision() -> Outcome<()> {
    let runtime = RuntimeBuilder::new()
        .with_deterministic_execution(false)
        .build()
        .await?;

    runtime
        .run(async move |cx| {
            let scope = cx.scope("decision_point_precision").await?;

            scope
                .run(async move |cx| {
                    let divergence_tracker = DivergenceTracker::new();

                    let recorder_config = RecorderConfig {
                        max_events: 1000,
                        max_decision_points: 100,
                        enable_compression: false,
                        buffer_size: 1024,
                    };

                    let recorder = TraceRecorder::new(recorder_config);

                    // Create computation with precise decision point contexts
                    let computation = NonDeterministicComputation::new(
                        3,
                        5,
                        RngSeed::new(77777),
                        divergence_tracker.clone(),
                    );

                    recorder.start_recording(cx).await?;

                    // Execute with detailed decision point tracking
                    let original_decisions = computation.execute_original(cx, &recorder).await?;

                    let execution_trace = recorder.stop_recording(cx).await?;

                    // Verify decision point precision
                    let decision_points = execution_trace.decision_points();
                    assert_eq!(
                        decision_points.len(),
                        5,
                        "Should have recorded exactly 5 decision points"
                    );

                    for (i, decision_point) in decision_points.iter().enumerate() {
                        let expected_context = format!("computation_3_decision_{}", i);
                        assert_eq!(
                            decision_point.context, expected_context,
                            "Decision point {} should have exact context",
                            i
                        );

                        assert_eq!(
                            decision_point.alternatives.len(),
                            2,
                            "Should have exactly 2 alternatives"
                        );

                        assert!(
                            decision_point.alternatives.contains(&"path_a".to_string()),
                            "Should contain path_a alternative"
                        );

                        assert!(
                            decision_point.alternatives.contains(&"path_b".to_string()),
                            "Should contain path_b alternative"
                        );

                        println!(
                            "Decision point {}: {} with alternatives {:?}",
                            decision_point.id.value(),
                            decision_point.context,
                            decision_point.alternatives
                        );
                    }

                    // Verify trace events correspond to decision points
                    let trace_events = execution_trace.events();
                    let decision_events: Vec<_> = trace_events
                        .iter()
                        .filter_map(|event| match event {
                            TraceEvent::DecisionMade {
                                decision_id,
                                chosen_alternative,
                                outcome_value,
                            } => Some((decision_id, chosen_alternative, outcome_value)),
                            _ => None,
                        })
                        .collect();

                    assert_eq!(
                        decision_events.len(),
                        5,
                        "Should have 5 decision made events"
                    );

                    for (i, (decision_id, chosen_alternative, outcome_value)) in
                        decision_events.iter().enumerate()
                    {
                        let expected_decision_id = EventId::new(3 * 1000 + i as u64);
                        assert_eq!(
                            **decision_id, expected_decision_id,
                            "Decision event {} should have correct ID",
                            i
                        );

                        let expected_alternative = if *outcome_value % 2 == 0 {
                            "path_a"
                        } else {
                            "path_b"
                        };
                        assert_eq!(
                            chosen_alternative, expected_alternative,
                            "Decision event {} should have correct alternative",
                            i
                        );

                        println!(
                            "Decision event {}: ID={}, alternative={}, value={}",
                            i,
                            decision_id.value(),
                            chosen_alternative,
                            outcome_value
                        );
                    }

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
    fn test_divergence_tracker_creation() {
        let tracker = DivergenceTracker::new();

        // Verify initial state
        assert_eq!(
            tracker.original_decisions_recorded.load(Ordering::Relaxed),
            0
        );
        assert_eq!(tracker.divergent_decisions.load(Ordering::Relaxed), 0);
        assert_eq!(
            tracker.divergence_points_detected.load(Ordering::Relaxed),
            0
        );
        assert_eq!(tracker.chaos_induced_divergences.load(Ordering::Relaxed), 0);
        assert_eq!(tracker.replay_sessions_completed.load(Ordering::Relaxed), 0);
        assert_eq!(tracker.replay_sessions_failed.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_divergence_tracking() {
        let tracker = DivergenceTracker::new();

        // Record events
        tracker.record_original_decision();
        tracker.record_divergent_decision();
        tracker.record_divergence_point();
        tracker.record_chaos_induced_divergence();
        tracker.record_replay_completed();

        // Verify tracking
        assert_eq!(
            tracker.original_decisions_recorded.load(Ordering::Relaxed),
            1
        );
        assert_eq!(tracker.divergent_decisions.load(Ordering::Relaxed), 1);
        assert_eq!(
            tracker.divergence_points_detected.load(Ordering::Relaxed),
            1
        );
        assert_eq!(tracker.chaos_induced_divergences.load(Ordering::Relaxed), 1);
        assert_eq!(tracker.replay_sessions_completed.load(Ordering::Relaxed), 1);

        // Verify verification methods
        assert!(tracker.verify_divergence_detection());
        assert!(tracker.verify_replay_success());
    }

    #[test]
    fn test_non_deterministic_computation_creation() {
        let divergence_tracker = DivergenceTracker::new();
        let computation =
            NonDeterministicComputation::new(42, 10, RngSeed::new(12345), divergence_tracker);

        assert_eq!(computation.id, 42);
        assert_eq!(computation.decision_count, 10);
        assert_eq!(computation.original_seed, RngSeed::new(12345));
    }

    #[test]
    fn test_divergence_detection_verification_edge_cases() {
        let tracker = DivergenceTracker::new();

        // No divergences
        tracker.record_replay_completed();
        assert!(!tracker.verify_divergence_detection()); // No divergences detected

        // Divergences but no chaos
        let tracker2 = DivergenceTracker::new();
        tracker2.record_divergence_point();
        tracker2.record_replay_completed();
        assert!(!tracker2.verify_divergence_detection()); // No chaos-induced divergences

        // Proper divergence detection
        let tracker3 = DivergenceTracker::new();
        tracker3.record_divergence_point();
        tracker3.record_chaos_induced_divergence();
        tracker3.record_replay_completed();
        assert!(tracker3.verify_divergence_detection()); // All conditions met
    }

    #[test]
    fn test_replay_success_verification() {
        let tracker = DivergenceTracker::new();

        // No replays
        assert!(!tracker.verify_replay_success()); // No completed replays

        // More failures than successes
        let tracker2 = DivergenceTracker::new();
        tracker2.record_replay_completed();
        tracker2.record_replay_failed();
        tracker2.record_replay_failed();
        assert!(!tracker2.verify_replay_success()); // More failures

        // Successful replays
        let tracker3 = DivergenceTracker::new();
        tracker3.record_replay_completed();
        tracker3.record_replay_completed();
        tracker3.record_replay_failed();
        assert!(tracker3.verify_replay_success()); // More successes
    }
}
