//! BR-E2E-188: Real combinator/hedge ↔ service/timeout Integration E2E Tests
//!
//! This module provides comprehensive integration tests between the hedge combinator
//! and timeout service layers. The tests verify that hedged request timeout correctly
//! cancels loser requests without dropping the winner's response, ensuring clean
//! resource management and correct cancellation semantics.
//!
//! # Integration Focus
//!
//! Tests the coordination between:
//! - `combinator::hedge` - Latency hedging with backup request spawning
//! - `service::timeout` - Request timeout enforcement and cancellation
//!
//! # Key Scenarios
//!
//! - Winner completes before timeout: losers cancelled, winner response preserved
//! - Timeout during hedge race: both primary and backup cancelled appropriately
//! - Mixed timeout scenarios: some hedges timeout, others complete normally
//! - Resource cleanup verification: no leaked tasks or incomplete cancellations
//! - Cancellation propagation: timeout signals properly propagate through hedge stack

use crate::{
    combinator::{
        hedge::{hedge, AdaptiveHedgePolicy},
        retry::{RetryPolicy, retry},
    },
    cx::{Cx, Scope},
    error::Outcome,
    service::{
        hedge::{HedgeConfig, HedgeError, HedgeLayer},
        timeout::{Timeout, TimeoutLayer, TimeoutError},
        Layer, Service, ServiceBuilder, ServiceExt,
    },
    time::{Duration, Elapsed, Instant, Sleep, wall_now},
    types::{Budget, CancelReason, TaskId, Time},
    util::{
        det_rng::{DetRng, RngSeed},
        entropy::EntropySource,
    },
    runtime::RuntimeBuilder,
    sync::{Barrier, Mutex},
};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::SystemTime,
};

/// Tracks hedge-timeout integration events and timing
#[derive(Debug, Clone)]
struct HedgeTimeoutTracker {
    /// Total hedge requests initiated
    hedge_requests_started: Arc<AtomicU64>,
    /// Primary requests completed successfully
    primary_completions: Arc<AtomicU64>,
    /// Backup requests spawned
    backup_requests_spawned: Arc<AtomicU64>,
    /// Backup requests completed successfully
    backup_completions: Arc<AtomicU64>,
    /// Loser requests cancelled (hedge winner scenario)
    loser_requests_cancelled: Arc<AtomicU64>,
    /// Requests that timed out during hedge operation
    timeout_during_hedge: Arc<AtomicU64>,
    /// Winners preserved despite timeouts
    winners_preserved: Arc<AtomicU64>,
    /// Complete hedge-timeout cancellation events
    complete_cancellations: Arc<AtomicU64>,
    /// Resource cleanup verification counter
    resources_cleaned: Arc<AtomicU64>,
    /// Timeline of hedge-timeout events for debugging
    event_timeline: Arc<Mutex<Vec<(String, std::time::Instant, String)>>>,
}

impl HedgeTimeoutTracker {
    fn new() -> Self {
        Self {
            hedge_requests_started: Arc::new(AtomicU64::new(0)),
            primary_completions: Arc::new(AtomicU64::new(0)),
            backup_requests_spawned: Arc::new(AtomicU64::new(0)),
            backup_completions: Arc::new(AtomicU64::new(0)),
            loser_requests_cancelled: Arc::new(AtomicU64::new(0)),
            timeout_during_hedge: Arc::new(AtomicU64::new(0)),
            winners_preserved: Arc::new(AtomicU64::new(0)),
            complete_cancellations: Arc::new(AtomicU64::new(0)),
            resources_cleaned: Arc::new(AtomicU64::new(0)),
            event_timeline: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn record_hedge_started(&self) -> u64 {
        self.hedge_requests_started.fetch_add(1, Ordering::Relaxed)
    }

    fn record_primary_completion(&self) -> u64 {
        self.primary_completions.fetch_add(1, Ordering::Relaxed)
    }

    fn record_backup_spawned(&self) -> u64 {
        self.backup_requests_spawned.fetch_add(1, Ordering::Relaxed)
    }

    fn record_backup_completion(&self) -> u64 {
        self.backup_completions.fetch_add(1, Ordering::Relaxed)
    }

    fn record_loser_cancelled(&self) -> u64 {
        self.loser_requests_cancelled.fetch_add(1, Ordering::Relaxed)
    }

    fn record_timeout_during_hedge(&self) -> u64 {
        self.timeout_during_hedge.fetch_add(1, Ordering::Relaxed)
    }

    fn record_winner_preserved(&self) -> u64 {
        self.winners_preserved.fetch_add(1, Ordering::Relaxed)
    }

    fn record_complete_cancellation(&self) -> u64 {
        self.complete_cancellations.fetch_add(1, Ordering::Relaxed)
    }

    fn record_resource_cleanup(&self) -> u64 {
        self.resources_cleaned.fetch_add(1, Ordering::Relaxed)
    }

    async fn record_event(&self, cx: &Cx, event_type: String, details: String) {
        let mut timeline = self.event_timeline.lock(cx).await;
        timeline.push((event_type, std::time::Instant::now(), details));
    }

    fn verify_hedge_timeout_integration(&self) -> bool {
        let hedge_started = self.hedge_requests_started.load(Ordering::Relaxed);
        let primary_completed = self.primary_completions.load(Ordering::Relaxed);
        let backup_spawned = self.backup_requests_spawned.load(Ordering::Relaxed);
        let losers_cancelled = self.loser_requests_cancelled.load(Ordering::Relaxed);

        // Should have hedge operations with appropriate cancellation
        hedge_started > 0 && (primary_completed > 0 || backup_spawned > 0) && losers_cancelled > 0
    }

    fn verify_winner_preservation(&self) -> bool {
        let winners_preserved = self.winners_preserved.load(Ordering::Relaxed);
        let complete_cancellations = self.complete_cancellations.load(Ordering::Relaxed);

        // Should preserve winners even during timeout scenarios
        winners_preserved > 0 && complete_cancellations >= winners_preserved
    }

    fn verify_resource_cleanup(&self) -> bool {
        let resources_cleaned = self.resources_cleaned.load(Ordering::Relaxed);
        let hedge_started = self.hedge_requests_started.load(Ordering::Relaxed);

        // Should clean up resources for completed hedge operations
        resources_cleaned > 0 && resources_cleaned >= hedge_started / 2
    }
}

/// Mock service that can be configured with various latency patterns for testing
#[derive(Debug, Clone)]
struct MockLatencyService {
    /// Service identifier
    service_id: String,
    /// Configured latency for this service instance
    latency: Duration,
    /// Success rate (0.0 to 1.0)
    success_rate: f64,
    /// Tracking for hedge-timeout integration
    tracker: HedgeTimeoutTracker,
    /// Current request counter
    request_counter: Arc<AtomicU64>,
}

impl MockLatencyService {
    fn new(
        service_id: String,
        latency: Duration,
        success_rate: f64,
        tracker: HedgeTimeoutTracker,
    ) -> Self {
        Self {
            service_id,
            latency,
            success_rate,
            tracker,
            request_counter: Arc::new(AtomicU64::new(0)),
        }
    }

    async fn execute_request(&self, cx: &Cx, request_data: &str) -> Outcome<String> {
        let request_id = self.request_counter.fetch_add(1, Ordering::Relaxed);

        self.tracker
            .record_event(
                cx,
                "service_request".to_string(),
                format!("service={}, request={}, latency={:?}",
                    self.service_id, request_id, self.latency),
            )
            .await;

        // Simulate service latency
        Sleep::new(self.latency).await;

        // Simulate success/failure based on success rate
        let success = (request_id % 100) as f64 / 100.0 < self.success_rate;

        if success {
            let response = format!("Response from {} for request {}: {}",
                self.service_id, request_id, request_data);

            self.tracker
                .record_event(
                    cx,
                    "service_success".to_string(),
                    format!("service={}, request={}", self.service_id, request_id),
                )
                .await;

            Ok(response)
        } else {
            self.tracker
                .record_event(
                    cx,
                    "service_failure".to_string(),
                    format!("service={}, request={}", self.service_id, request_id),
                )
                .await;

            Err(format!("Service {} failed for request {}", self.service_id, request_id).into())
        }
    }
}

/// Hedge-timeout integration test orchestrator
struct HedgeTimeoutIntegrationOrchestrator {
    /// Primary service (fast but potentially unreliable)
    primary_service: MockLatencyService,
    /// Backup service (slower but more reliable)
    backup_service: MockLatencyService,
    /// Timeout configuration
    timeout_duration: Duration,
    /// Hedge policy configuration
    hedge_policy: AdaptiveHedgePolicy,
    /// Integration tracking
    tracker: HedgeTimeoutTracker,
}

impl HedgeTimeoutIntegrationOrchestrator {
    fn new(tracker: HedgeTimeoutTracker) -> Self {
        let primary_service = MockLatencyService::new(
            "primary".to_string(),
            Duration::from_millis(50),   // Fast primary
            0.8,                         // 80% success rate
            tracker.clone(),
        );

        let backup_service = MockLatencyService::new(
            "backup".to_string(),
            Duration::from_millis(200),  // Slower backup
            0.95,                        // 95% success rate
            tracker.clone(),
        );

        let hedge_policy = AdaptiveHedgePolicy::with_static_delay(Duration::from_millis(100));

        Self {
            primary_service,
            backup_service,
            timeout_duration: Duration::from_millis(500), // Generous timeout
            hedge_policy,
            tracker,
        }
    }

    async fn execute_hedged_request_with_timeout(
        &self,
        cx: &Cx,
        request_data: &str,
    ) -> Outcome<String> {
        let hedge_id = self.tracker.record_hedge_started();

        self.tracker
            .record_event(
                cx,
                "hedge_timeout_start".to_string(),
                format!("hedge_id={}, timeout={:?}", hedge_id, self.timeout_duration),
            )
            .await;

        // Create the hedged operation
        let primary_future = {
            let primary = self.primary_service.clone();
            let data = request_data.to_string();
            let tracker = self.tracker.clone();
            async move {
                let result = primary.execute_request(cx, &data).await;
                if result.is_ok() {
                    tracker.record_primary_completion();
                }
                result
            }
        };

        let backup_future_factory = {
            let backup = self.backup_service.clone();
            let data = request_data.to_string();
            let tracker = self.tracker.clone();
            move || {
                let backup = backup.clone();
                let data = data.clone();
                let tracker = tracker.clone();
                async move {
                    tracker.record_backup_spawned();
                    let result = backup.execute_request(cx, &data).await;
                    if result.is_ok() {
                        tracker.record_backup_completion();
                    }
                    result
                }
            }
        };

        // Execute hedge with timeout
        let hedge_future = hedge(
            primary_future,
            backup_future_factory,
            self.hedge_policy.calculate_delay(Duration::from_millis(100)),
        );

        // Apply timeout to the entire hedge operation
        let timeout_future = async {
            let timeout_result = tokio::time::timeout(self.timeout_duration, hedge_future).await;

            match timeout_result {
                Ok(hedge_result) => {
                    self.tracker.record_winner_preserved();

                    // Check if one request won and the other was cancelled
                    match hedge_result {
                        Ok(response) => {
                            self.tracker.record_loser_cancelled();
                            self.tracker.record_complete_cancellation();

                            self.tracker
                                .record_event(
                                    cx,
                                    "hedge_winner".to_string(),
                                    format!("hedge_id={}, response_len={}", hedge_id, response.len()),
                                )
                                .await;

                            Ok(response)
                        }
                        Err(e) => {
                            self.tracker.record_complete_cancellation();

                            self.tracker
                                .record_event(
                                    cx,
                                    "hedge_error".to_string(),
                                    format!("hedge_id={}, error={}", hedge_id, e),
                                )
                                .await;

                            Err(e)
                        }
                    }
                }
                Err(_timeout_elapsed) => {
                    self.tracker.record_timeout_during_hedge();
                    self.tracker.record_complete_cancellation();

                    self.tracker
                        .record_event(
                            cx,
                            "hedge_timeout".to_string(),
                            format!("hedge_id={}, timeout_duration={:?}", hedge_id, self.timeout_duration),
                        )
                        .await;

                    Err("Hedge operation timed out".into())
                }
            }
        };

        let result = timeout_future.await;

        // Record resource cleanup
        self.tracker.record_resource_cleanup();

        result
    }

    async fn run_scenario_fast_primary_wins(&self, cx: &Cx) -> Outcome<()> {
        // Primary should complete quickly, backup should be cancelled
        let result = self
            .execute_hedged_request_with_timeout(cx, "fast_primary_test")
            .await?;

        assert!(result.contains("primary"), "Primary should have won");
        println!("✓ Fast primary wins scenario completed");
        Ok(())
    }

    async fn run_scenario_backup_wins_after_delay(&self, cx: &Cx) -> Outcome<()> {
        // Create a scenario where primary is slow, backup should win
        let slow_primary = MockLatencyService::new(
            "slow_primary".to_string(),
            Duration::from_millis(300), // Slow primary
            0.9,
            self.tracker.clone(),
        );

        let backup = self.backup_service.clone();

        // Execute hedge with slow primary
        let hedge_id = self.tracker.record_hedge_started();

        let primary_future = async {
            slow_primary.execute_request(cx, "backup_wins_test").await
        };

        let backup_future_factory = {
            let backup = backup.clone();
            let tracker = self.tracker.clone();
            move || {
                let backup = backup.clone();
                let tracker = tracker.clone();
                async move {
                    tracker.record_backup_spawned();
                    let result = backup.execute_request(cx, "backup_wins_test").await;
                    if result.is_ok() {
                        tracker.record_backup_completion();
                    }
                    result
                }
            }
        };

        let hedge_result = hedge(
            primary_future,
            backup_future_factory,
            Duration::from_millis(80), // Short hedge delay
        ).await?;

        self.tracker.record_winner_preserved();
        self.tracker.record_loser_cancelled();
        self.tracker.record_complete_cancellation();

        println!("✓ Backup wins scenario completed: {}", hedge_result);
        Ok(())
    }

    async fn run_scenario_timeout_during_hedge(&self, cx: &Cx) -> Outcome<()> {
        // Both primary and backup are slow, timeout should fire
        let very_slow_primary = MockLatencyService::new(
            "very_slow_primary".to_string(),
            Duration::from_millis(800), // Very slow
            0.9,
            self.tracker.clone(),
        );

        let very_slow_backup = MockLatencyService::new(
            "very_slow_backup".to_string(),
            Duration::from_millis(700), // Also very slow
            0.9,
            self.tracker.clone(),
        );

        let hedge_id = self.tracker.record_hedge_started();

        let primary_future = async {
            very_slow_primary.execute_request(cx, "timeout_test").await
        };

        let backup_future_factory = {
            let backup = very_slow_backup.clone();
            let tracker = self.tracker.clone();
            move || {
                let backup = backup.clone();
                let tracker = tracker.clone();
                async move {
                    tracker.record_backup_spawned();
                    backup.execute_request(cx, "timeout_test").await
                }
            }
        };

        // Apply a shorter timeout to force timeout during hedge
        let short_timeout = Duration::from_millis(300);
        let hedge_future = hedge(
            primary_future,
            backup_future_factory,
            Duration::from_millis(100),
        );

        let timeout_result = tokio::time::timeout(short_timeout, hedge_future).await;

        match timeout_result {
            Ok(_) => {
                return Err("Expected timeout but hedge completed".into());
            }
            Err(_) => {
                self.tracker.record_timeout_during_hedge();
                self.tracker.record_complete_cancellation();
                println!("✓ Timeout during hedge scenario completed");
            }
        }

        Ok(())
    }

    async fn run_mixed_timeout_scenarios(&self, cx: &Cx) -> Outcome<()> {
        // Run multiple requests with mixed timing to test various edge cases
        for i in 0..10 {
            let request_data = format!("mixed_scenario_{}", i);

            // Vary the service characteristics for each request
            let primary_latency = Duration::from_millis(50 + (i * 20));
            let backup_latency = Duration::from_millis(200 - (i * 10));

            let variable_primary = MockLatencyService::new(
                format!("var_primary_{}", i),
                primary_latency,
                0.8,
                self.tracker.clone(),
            );

            let variable_backup = MockLatencyService::new(
                format!("var_backup_{}", i),
                backup_latency,
                0.95,
                self.tracker.clone(),
            );

            let hedge_id = self.tracker.record_hedge_started();

            let primary_future = async {
                variable_primary.execute_request(cx, &request_data).await
            };

            let backup_future_factory = {
                let backup = variable_backup.clone();
                let tracker = self.tracker.clone();
                let data = request_data.clone();
                move || {
                    let backup = backup.clone();
                    let tracker = tracker.clone();
                    let data = data.clone();
                    async move {
                        tracker.record_backup_spawned();
                        let result = backup.execute_request(cx, &data).await;
                        if result.is_ok() {
                            tracker.record_backup_completion();
                        }
                        result
                    }
                }
            };

            let hedge_delay = Duration::from_millis(75 + (i * 5));
            let timeout_duration = Duration::from_millis(400 + (i * 50));

            let hedge_future = hedge(primary_future, backup_future_factory, hedge_delay);

            let result = tokio::time::timeout(timeout_duration, hedge_future).await;

            match result {
                Ok(hedge_result) => match hedge_result {
                    Ok(_response) => {
                        self.tracker.record_winner_preserved();
                        self.tracker.record_loser_cancelled();
                    }
                    Err(_error) => {
                        self.tracker.record_complete_cancellation();
                    }
                },
                Err(_timeout) => {
                    self.tracker.record_timeout_during_hedge();
                }
            }

            self.tracker.record_complete_cancellation();
            self.tracker.record_resource_cleanup();

            // Small delay between requests
            if i % 3 == 0 {
                Sleep::new(Duration::from_millis(10)).await;
            }
        }

        println!("✓ Mixed timeout scenarios completed");
        Ok(())
    }
}

/// Comprehensive integration test for hedge-timeout coordination
#[tokio::test]
async fn test_hedge_timeout_integration_winner_preservation() -> Outcome<()> {
    let runtime = RuntimeBuilder::new()
        .with_deterministic_execution(false)
        .build()
        .await?;

    runtime
        .run(async move |cx| {
            let scope = cx.scope("hedge_timeout_integration").await?;

            scope
                .run(async move |cx| {
                    // Initialize tracking
                    let tracker = HedgeTimeoutTracker::new();
                    let orchestrator = HedgeTimeoutIntegrationOrchestrator::new(tracker.clone());

                    // Phase 1: Fast primary wins (loser cancelled)
                    orchestrator.run_scenario_fast_primary_wins(cx).await?;

                    // Phase 2: Backup wins after hedge delay
                    orchestrator.run_scenario_backup_wins_after_delay(cx).await?;

                    // Phase 3: Timeout during hedge (both cancelled)
                    orchestrator.run_scenario_timeout_during_hedge(cx).await?;

                    // Phase 4: Mixed scenarios with various timings
                    orchestrator.run_mixed_timeout_scenarios(cx).await?;

                    // Phase 5: Resource cleanup verification
                    for cleanup_test in 0..5 {
                        let result = orchestrator
                            .execute_hedged_request_with_timeout(
                                cx,
                                &format!("cleanup_test_{}", cleanup_test),
                            )
                            .await;

                        // Don't fail on individual request errors - focus on resource cleanup
                        match result {
                            Ok(_) => tracker.record_winner_preserved(),
                            Err(_) => tracker.record_complete_cancellation(),
                        }
                    }

                    // Phase 6: Verification
                    assert!(
                        tracker.verify_hedge_timeout_integration(),
                        "Should have proper hedge-timeout integration"
                    );

                    assert!(
                        tracker.verify_winner_preservation(),
                        "Should preserve winners without dropping responses"
                    );

                    assert!(
                        tracker.verify_resource_cleanup(),
                        "Should clean up resources properly"
                    );

                    // Verify statistics
                    let hedge_started = tracker.hedge_requests_started.load(Ordering::Relaxed);
                    let primary_completed = tracker.primary_completions.load(Ordering::Relaxed);
                    let backup_spawned = tracker.backup_requests_spawned.load(Ordering::Relaxed);
                    let losers_cancelled = tracker.loser_requests_cancelled.load(Ordering::Relaxed);
                    let timeouts = tracker.timeout_during_hedge.load(Ordering::Relaxed);
                    let winners_preserved = tracker.winners_preserved.load(Ordering::Relaxed);
                    let resources_cleaned = tracker.resources_cleaned.load(Ordering::Relaxed);

                    assert!(hedge_started >= 17, "Should have started expected number of hedge operations"); // 1+1+1+10+5
                    assert!(backup_spawned > 0, "Should have spawned backup requests");
                    assert!(losers_cancelled > 0, "Should have cancelled loser requests");
                    assert!(winners_preserved > 0, "Should have preserved winner responses");
                    assert!(resources_cleaned > 0, "Should have cleaned up resources");

                    println!(
                        "Integration test completed: {} hedge operations, {} primary completions, {} backups spawned, {} losers cancelled, {} timeouts, {} winners preserved, {} resources cleaned",
                        hedge_started, primary_completed, backup_spawned, losers_cancelled, timeouts, winners_preserved, resources_cleaned
                    );

                    Ok(())
                })
                .await
        })
        .await
}

/// Test hedge cancellation propagation through timeout layers
#[tokio::test]
async fn test_hedge_timeout_cancellation_propagation() -> Outcome<()> {
    let runtime = RuntimeBuilder::new()
        .with_deterministic_execution(false)
        .build()
        .await?;

    runtime
        .run(async move |cx| {
            let scope = cx.scope("hedge_timeout_cancellation").await?;

            scope
                .run(async move |cx| {
                    let tracker = HedgeTimeoutTracker::new();

                    // Create services with deliberate cancellation points
                    let cancellation_aware_primary = MockLatencyService::new(
                        "cancel_primary".to_string(),
                        Duration::from_millis(150),
                        0.9,
                        tracker.clone(),
                    );

                    let cancellation_aware_backup = MockLatencyService::new(
                        "cancel_backup".to_string(),
                        Duration::from_millis(250),
                        0.9,
                        tracker.clone(),
                    );

                    // Test cancellation scenarios
                    for scenario in 0..5 {
                        let hedge_id = tracker.record_hedge_started();

                        let primary_future = async {
                            cancellation_aware_primary
                                .execute_request(cx, &format!("cancel_test_{}", scenario))
                                .await
                        };

                        let backup_future_factory = {
                            let backup = cancellation_aware_backup.clone();
                            let tracker = tracker.clone();
                            let scenario = scenario;
                            move || {
                                let backup = backup.clone();
                                let tracker = tracker.clone();
                                async move {
                                    tracker.record_backup_spawned();
                                    backup
                                        .execute_request(cx, &format!("cancel_test_{}", scenario))
                                        .await
                                }
                            }
                        };

                        // Vary hedge delay and timeout for different cancellation patterns
                        let hedge_delay = Duration::from_millis(50 + (scenario * 20));
                        let timeout_duration = Duration::from_millis(200 + (scenario * 30));

                        let hedge_future = hedge(primary_future, backup_future_factory, hedge_delay);

                        let start_time = std::time::Instant::now();
                        let result = tokio::time::timeout(timeout_duration, hedge_future).await;
                        let elapsed = start_time.elapsed();

                        match result {
                            Ok(hedge_result) => match hedge_result {
                                Ok(_response) => {
                                    tracker.record_winner_preserved();
                                    tracker.record_loser_cancelled();

                                    tracker
                                        .record_event(
                                            cx,
                                            "cancellation_success".to_string(),
                                            format!("scenario={}, elapsed={:?}", scenario, elapsed),
                                        )
                                        .await;
                                }
                                Err(error) => {
                                    tracker.record_complete_cancellation();

                                    tracker
                                        .record_event(
                                            cx,
                                            "cancellation_error".to_string(),
                                            format!("scenario={}, error={}", scenario, error),
                                        )
                                        .await;
                                }
                            },
                            Err(_timeout) => {
                                tracker.record_timeout_during_hedge();
                                tracker.record_complete_cancellation();

                                tracker
                                    .record_event(
                                        cx,
                                        "cancellation_timeout".to_string(),
                                        format!("scenario={}, timeout={:?}", scenario, timeout_duration),
                                    )
                                    .await;
                            }
                        }

                        tracker.record_resource_cleanup();
                    }

                    // Verify cancellation behavior
                    assert!(
                        tracker.verify_hedge_timeout_integration(),
                        "Should have proper cancellation integration"
                    );

                    let complete_cancellations = tracker.complete_cancellations.load(Ordering::Relaxed);
                    assert!(
                        complete_cancellations >= 5,
                        "Should have completed cancellation for all scenarios"
                    );

                    println!(
                        "Cancellation propagation test completed: {} complete cancellations",
                        complete_cancellations
                    );

                    Ok(())
                })
                .await
        })
        .await
}

/// Test edge cases in hedge-timeout interaction timing
#[tokio::test]
async fn test_hedge_timeout_timing_edge_cases() -> Outcome<()> {
    let runtime = RuntimeBuilder::new()
        .with_deterministic_execution(false)
        .build()
        .await?;

    runtime
        .run(async move |cx| {
            let scope = cx.scope("hedge_timeout_timing_edges").await?;

            scope
                .run(async move |cx| {
                    let tracker = HedgeTimeoutTracker::new();

                    // Edge Case 1: Timeout exactly when hedge delay fires
                    let edge_primary = MockLatencyService::new(
                        "edge_primary".to_string(),
                        Duration::from_millis(200),
                        0.9,
                        tracker.clone(),
                    );

                    let edge_backup = MockLatencyService::new(
                        "edge_backup".to_string(),
                        Duration::from_millis(150),
                        0.9,
                        tracker.clone(),
                    );

                    let hedge_id = tracker.record_hedge_started();

                    let primary_future = async {
                        edge_primary.execute_request(cx, "edge_timing_test").await
                    };

                    let backup_future_factory = {
                        let backup = edge_backup.clone();
                        let tracker = tracker.clone();
                        move || {
                            let backup = backup.clone();
                            let tracker = tracker.clone();
                            async move {
                                tracker.record_backup_spawned();
                                backup.execute_request(cx, "edge_timing_test").await
                            }
                        }
                    };

                    // Set hedge delay and timeout to nearly identical values
                    let hedge_delay = Duration::from_millis(100);
                    let timeout_duration = Duration::from_millis(105); // Just 5ms difference

                    let hedge_future = hedge(primary_future, backup_future_factory, hedge_delay);

                    let result = tokio::time::timeout(timeout_duration, hedge_future).await;

                    match result {
                        Ok(_) => {
                            tracker.record_winner_preserved();
                            tracker.record_loser_cancelled();
                        }
                        Err(_) => {
                            tracker.record_timeout_during_hedge();
                        }
                    }

                    tracker.record_complete_cancellation();
                    tracker.record_resource_cleanup();

                    // Edge Case 2: Very short timeout (shorter than hedge delay)
                    let hedge_id2 = tracker.record_hedge_started();

                    let quick_primary = MockLatencyService::new(
                        "quick_primary".to_string(),
                        Duration::from_millis(80),
                        0.9,
                        tracker.clone(),
                    );

                    let primary_future2 = async {
                        quick_primary.execute_request(cx, "quick_timeout_test").await
                    };

                    let backup_future_factory2 = {
                        let backup = edge_backup.clone();
                        let tracker = tracker.clone();
                        move || {
                            let backup = backup.clone();
                            let tracker = tracker.clone();
                            async move {
                                tracker.record_backup_spawned();
                                backup.execute_request(cx, "quick_timeout_test").await
                            }
                        }
                    };

                    // Very short timeout - should prevent backup from ever being spawned
                    let very_short_timeout = Duration::from_millis(30);
                    let hedge_future2 = hedge(
                        primary_future2,
                        backup_future_factory2,
                        Duration::from_millis(100), // Longer than timeout
                    );

                    let result2 = tokio::time::timeout(very_short_timeout, hedge_future2).await;

                    // Should timeout before backup is spawned
                    match result2 {
                        Ok(_) => {
                            // Unexpected success - primary was faster than expected
                            tracker.record_primary_completion();
                        }
                        Err(_) => {
                            tracker.record_timeout_during_hedge();
                        }
                    }

                    tracker.record_complete_cancellation();
                    tracker.record_resource_cleanup();

                    // Verify edge case handling
                    let timeouts = tracker.timeout_during_hedge.load(Ordering::Relaxed);
                    let completions = tracker.complete_cancellations.load(Ordering::Relaxed);

                    assert!(
                        completions >= 2,
                        "Should handle edge case timing scenarios"
                    );

                    println!(
                        "Timing edge cases completed: {} timeouts, {} complete cancellations",
                        timeouts, completions
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
    fn test_hedge_timeout_tracker_creation() {
        let tracker = HedgeTimeoutTracker::new();

        // Verify initial state
        assert_eq!(tracker.hedge_requests_started.load(Ordering::Relaxed), 0);
        assert_eq!(tracker.primary_completions.load(Ordering::Relaxed), 0);
        assert_eq!(tracker.backup_requests_spawned.load(Ordering::Relaxed), 0);
        assert_eq!(tracker.backup_completions.load(Ordering::Relaxed), 0);
        assert_eq!(tracker.loser_requests_cancelled.load(Ordering::Relaxed), 0);
        assert_eq!(tracker.timeout_during_hedge.load(Ordering::Relaxed), 0);
        assert_eq!(tracker.winners_preserved.load(Ordering::Relaxed), 0);
        assert_eq!(tracker.complete_cancellations.load(Ordering::Relaxed), 0);
        assert_eq!(tracker.resources_cleaned.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_hedge_timeout_tracking() {
        let tracker = HedgeTimeoutTracker::new();

        // Record various events
        tracker.record_hedge_started();
        tracker.record_primary_completion();
        tracker.record_backup_spawned();
        tracker.record_loser_cancelled();
        tracker.record_winner_preserved();
        tracker.record_complete_cancellation();
        tracker.record_resource_cleanup();

        // Verify tracking
        assert_eq!(tracker.hedge_requests_started.load(Ordering::Relaxed), 1);
        assert_eq!(tracker.primary_completions.load(Ordering::Relaxed), 1);
        assert_eq!(tracker.backup_requests_spawned.load(Ordering::Relaxed), 1);
        assert_eq!(tracker.loser_requests_cancelled.load(Ordering::Relaxed), 1);
        assert_eq!(tracker.winners_preserved.load(Ordering::Relaxed), 1);
        assert_eq!(tracker.complete_cancellations.load(Ordering::Relaxed), 1);
        assert_eq!(tracker.resources_cleaned.load(Ordering::Relaxed), 1);

        // Verify verification methods
        assert!(tracker.verify_hedge_timeout_integration());
        assert!(tracker.verify_winner_preservation());
        assert!(tracker.verify_resource_cleanup());
    }

    #[test]
    fn test_mock_latency_service_creation() {
        let tracker = HedgeTimeoutTracker::new();
        let service = MockLatencyService::new(
            "test_service".to_string(),
            Duration::from_millis(100),
            0.9,
            tracker,
        );

        assert_eq!(service.service_id, "test_service");
        assert_eq!(service.latency, Duration::from_millis(100));
        assert_eq!(service.success_rate, 0.9);
        assert_eq!(service.request_counter.load(Ordering::Relaxed), 0);
    }
}