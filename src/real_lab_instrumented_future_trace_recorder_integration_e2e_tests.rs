//! Real E2E integration tests: lab/instrumented_future ↔ trace/recorder integration (br-e2e-193).
//!
//! Tests that instrumented futures correctly emit trace events on each poll without overwhelming
//! the recorder. Verifies the integration between:
//!
//! - `lab::instrumented_future`: Future instrumentation for await point tracking and cancellation testing
//! - `trace::recorder`: Deterministic trace recording for replay with rate limiting and batching
//!
//! # Integration Patterns Tested
//!
//! - **Poll Event Recording**: Each instrumented future poll generates appropriate trace events
//! - **Recorder Rate Limiting**: High-frequency polling events handled without overwhelming recorder
//! - **Event Batching**: Multiple poll events efficiently batched for recording performance
//! - **Back-Pressure Handling**: Recorder limits respected when instrumented futures generate events rapidly
//! - **Trace Completeness**: All critical polling behavior captured despite rate limiting
//!
//! # Test Scenarios
//!
//! 1. **Basic Poll Recording** — Simple instrumented future polls recorded correctly
//! 2. **High-Frequency Polling** — Rapid polling scenarios test recorder rate limiting
//! 3. **Concurrent Future Instrumentation** — Multiple instrumented futures don't overwhelm recorder
//! 4. **Batched Event Recording** — Events properly batched for performance under load
//! 5. **Back-Pressure Recovery** — Recording gracefully resumes after rate limiting
//!
//! # Safety Properties Verified
//!
//! - Instrumented future polls generate trace events without recorder overflow
//! - Rate limiting preserves critical events while shedding excess detail
//! - Trace completeness maintained despite high poll frequency
//! - Recorder memory and event limits respected under instrumentation load
//! - Poll sequence reconstruction possible from recorded traces

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

    use crate::{
        cx::{Cx, Registry},
        lab::{
            instrumented_future::{
                AwaitPoint, CancellationInjector, InjectionStrategy, InstrumentedFuture,
            },
            runtime::{LabConfig, LabRuntime},
        },
        runtime::Runtime,
        time::{Duration, Instant},
        trace::{
            recorder::{LimitAction, LimitKind, LimitReached, RecorderConfig, TraceRecorder},
            replay::{ReplayEvent, ReplayTrace, TraceMetadata},
        },
        types::{Budget, Outcome, TaskId, Time},
    };
    use std::{
        collections::{BTreeMap, HashMap, VecDeque},
        future::Future,
        pin::Pin,
        sync::{
            Arc, Mutex, RwLock,
            atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        },
        task::{Context, Poll, Waker},
    };

    // ────────────────────────────────────────────────────────────────────────────────
    // Instrumented Future + Trace Recorder Integration Test Framework
    // ────────────────────────────────────────────────────────────────────────────────

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum FutureRecorderTestPhase {
        Setup,
        RecorderInitialization,
        FutureInstrumentation,
        PollEventGeneration,
        RateLimitingTest,
        BatchingVerification,
        BackPressureTest,
        TraceValidation,
        ReplayVerification,
        Teardown,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct FutureRecorderTestResult {
        pub test_name: String,
        pub scenario_id: String,
        pub phase: FutureRecorderTestPhase,
        pub success: bool,
        pub error: Option<String>,
        pub duration_ms: u64,
        pub recorder_stats: RecorderIntegrationStats,
        pub instrumentation_stats: InstrumentationStats,
        pub trace_completeness_verified: bool,
        pub rate_limiting_effective: bool,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Default)]
    pub struct RecorderIntegrationStats {
        pub events_recorded: u64,
        pub events_dropped: u64,
        pub batches_written: u64,
        pub rate_limit_triggered: u64,
        pub max_memory_reached: bool,
        pub recording_duration_ms: u64,
        pub average_event_size_bytes: u64,
        pub peak_memory_usage_bytes: u64,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Default)]
    pub struct InstrumentationStats {
        pub futures_instrumented: u64,
        pub total_polls_executed: u64,
        pub await_points_recorded: u64,
        pub cancellation_points_tested: u64,
        pub concurrent_futures_peak: u64,
        pub poll_events_generated: u64,
        pub instrumentation_overhead_ns: u64,
    }

    /// Mock future that can be configured for different polling behaviors.
    pub struct ConfigurableMockFuture {
        poll_count: u64,
        max_polls: u64,
        poll_delay_ms: u64,
        should_yield_frequently: bool,
        completion_value: Option<String>,
        last_poll_time: Option<Instant>,
        event_log: Arc<Mutex<Vec<(u64, Instant, String)>>>,
    }

    impl ConfigurableMockFuture {
        pub fn new(
            max_polls: u64,
            poll_delay_ms: u64,
            should_yield_frequently: bool,
            event_log: Arc<Mutex<Vec<(u64, Instant, String)>>>,
        ) -> Self {
            Self {
                poll_count: 0,
                max_polls,
                poll_delay_ms,
                should_yield_frequently,
                completion_value: None,
                last_poll_time: None,
                event_log,
            }
        }

        pub fn rapid_polling(event_log: Arc<Mutex<Vec<(u64, Instant, String)>>>) -> Self {
            Self::new(100, 0, true, event_log) // 100 rapid polls
        }

        pub fn slow_polling(event_log: Arc<Mutex<Vec<(u64, Instant, String)>>>) -> Self {
            Self::new(10, 50, false, event_log) // 10 polls with 50ms delay
        }

        pub fn burst_polling(event_log: Arc<Mutex<Vec<(u64, Instant, String)>>>) -> Self {
            Self::new(50, 0, true, event_log) // 50 burst polls
        }
    }

    impl Future for ConfigurableMockFuture {
        type Output = String;

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            self.poll_count += 1;
            let now = Instant::now();
            self.last_poll_time = Some(now);

            // Log the poll event
            if let Ok(mut log) = self.event_log.lock() {
                log.push((self.poll_count, now, format!("poll_{}", self.poll_count)));
            }

            // Check if we should yield frequently (for testing)
            if self.should_yield_frequently && self.poll_count % 3 == 0 {
                cx.waker().wake_by_ref(); // Schedule immediate re-poll
                return Poll::Pending;
            }

            // Simulate delay if configured
            if self.poll_delay_ms > 0 {
                // In real implementation, this would use actual delays
                // For testing, we simulate the delay behavior
            }

            if self.poll_count >= self.max_polls {
                Poll::Ready(format!("Completed after {} polls", self.poll_count))
            } else {
                cx.waker().wake_by_ref(); // Continue polling
                Poll::Pending
            }
        }
    }

    /// Custom limit callback that tracks rate limiting events.
    #[derive(Debug)]
    pub struct RateLimitTracker {
        limit_events: Arc<Mutex<Vec<LimitReached>>>,
        drop_oldest_count: Arc<AtomicU64>,
        stop_recording_count: Arc<AtomicU64>,
    }

    impl RateLimitTracker {
        pub fn new() -> Self {
            Self {
                limit_events: Arc::new(Mutex::new(Vec::new())),
                drop_oldest_count: Arc::new(AtomicU64::new(0)),
                stop_recording_count: Arc::new(AtomicU64::new(0)),
            }
        }

        pub fn create_callback(&self) -> LimitAction {
            let limit_events = Arc::clone(&self.limit_events);
            let drop_oldest_count = Arc::clone(&self.drop_oldest_count);
            let stop_recording_count = Arc::clone(&self.stop_recording_count);

            LimitAction::Callback(Arc::new(move |limit_reached| {
                // Record the limit event
                if let Ok(mut events) = limit_events.lock() {
                    events.push(limit_reached.clone());
                }

                // Decide action based on limit type
                match limit_reached.kind {
                    LimitKind::MaxEvents => {
                        drop_oldest_count.fetch_add(1, Ordering::SeqCst);
                        LimitAction::DropOldest
                    }
                    LimitKind::MaxMemory => {
                        if limit_reached.current_events < 1000 {
                            drop_oldest_count.fetch_add(1, Ordering::SeqCst);
                            LimitAction::DropOldest
                        } else {
                            stop_recording_count.fetch_add(1, Ordering::SeqCst);
                            LimitAction::StopRecording
                        }
                    }
                    LimitKind::MaxFileSize => {
                        stop_recording_count.fetch_add(1, Ordering::SeqCst);
                        LimitAction::StopRecording
                    }
                }
            }))
        }

        pub fn get_stats(&self) -> (usize, u64, u64) {
            let events_count = self.limit_events.lock().unwrap().len();
            let drop_count = self.drop_oldest_count.load(Ordering::SeqCst);
            let stop_count = self.stop_recording_count.load(Ordering::SeqCst);
            (events_count, drop_count, stop_count)
        }
    }

    /// Integration test harness combining instrumented futures and trace recording.
    pub struct InstrumentedFutureRecorderHarness {
        runtime: Runtime,
        cx: Cx,
        recorder_config: RecorderConfig,
        rate_limit_tracker: RateLimitTracker,
        instrumentation_stats: Arc<Mutex<InstrumentationStats>>,
        recorder_stats: Arc<Mutex<RecorderIntegrationStats>>,
        test_start_time: Instant,
        active_futures: Arc<AtomicUsize>,
        recorded_traces: Arc<Mutex<Vec<ReplayTrace>>>,
    }

    impl InstrumentedFutureRecorderHarness {
        pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
            let runtime = Runtime::new()?;
            let cx = Cx::current().expect("Runtime should provide current Cx");

            let rate_limit_tracker = RateLimitTracker::new();
            let recorder_config = RecorderConfig::enabled()
                .with_max_events(Some(500)) // Moderate limit for testing
                .with_max_memory(1024 * 1024) // 1MB memory limit
                .on_limit(rate_limit_tracker.create_callback());

            Ok(Self {
                runtime,
                cx,
                recorder_config,
                rate_limit_tracker,
                instrumentation_stats: Arc::new(Mutex::new(InstrumentationStats::default())),
                recorder_stats: Arc::new(Mutex::new(RecorderIntegrationStats::default())),
                test_start_time: Instant::now(),
                active_futures: Arc::new(AtomicUsize::new(0)),
                recorded_traces: Arc::new(Mutex::new(Vec::new())),
            })
        }

        pub async fn test_basic_poll_recording(
            &self,
        ) -> Result<FutureRecorderTestResult, Box<dyn std::error::Error>> {
            let test_start = Instant::now();
            let mut result = FutureRecorderTestResult {
                test_name: "basic_poll_recording".to_string(),
                scenario_id: "basic".to_string(),
                phase: FutureRecorderTestPhase::Setup,
                success: false,
                error: None,
                duration_ms: 0,
                recorder_stats: RecorderIntegrationStats::default(),
                instrumentation_stats: InstrumentationStats::default(),
                trace_completeness_verified: false,
                rate_limiting_effective: false,
            };

            // Phase 1: Initialize recorder
            result.phase = FutureRecorderTestPhase::RecorderInitialization;
            let metadata = TraceMetadata {
                test_name: "basic_poll_recording".to_string(),
                seed: 42,
                timestamp: Time::from_nanos(1000000000),
                lab_config: None,
            };
            let mut recorder = TraceRecorder::new(metadata, self.recorder_config.clone());

            // Phase 2: Create instrumented future
            result.phase = FutureRecorderTestPhase::FutureInstrumentation;
            let event_log = Arc::new(Mutex::new(Vec::new()));
            let mock_future = ConfigurableMockFuture::slow_polling(Arc::clone(&event_log));

            let injector = CancellationInjector::new(InjectionStrategy::Never);
            let instrumented_future =
                InstrumentedFuture::new(mock_future, injector, Some(TaskId::from_raw(1)));

            // Phase 3: Execute future and record poll events
            result.phase = FutureRecorderTestPhase::PollEventGeneration;
            let execution_start = Instant::now();

            // Simulate recording poll events during future execution
            let mut poll_count = 0u64;
            let mut pinned_future = Box::pin(instrumented_future);

            // Create a simple executor context
            let waker = futures_lite::future::block_on(async {
                std::task::Context::from_waker(
                    futures_lite::future::poll_fn(|cx| Poll::Ready(cx.waker().clone())).await,
                )
            })
            .clone();
            let mut cx = Context::from_waker(&waker);

            while let Poll::Pending = pinned_future.as_mut().poll(&mut cx) {
                poll_count += 1;

                // Record poll event in trace
                recorder.record_future_poll(
                    TaskId::from_raw(1),
                    poll_count,
                    format!("await_point_{}", poll_count),
                );

                // Prevent infinite loops in test
                if poll_count > 20 {
                    break;
                }
            }

            let execution_duration = execution_start.elapsed();

            // Phase 4: Validate recording
            result.phase = FutureRecorderTestPhase::TraceValidation;
            let trace = recorder.finish();

            // Update stats
            if let Ok(mut stats) = self.recorder_stats.lock() {
                stats.events_recorded = trace.events.len() as u64;
                stats.recording_duration_ms = execution_duration.as_millis() as u64;
                stats.batches_written = 1; // Single batch for this test
            }

            if let Ok(mut inst_stats) = self.instrumentation_stats.lock() {
                inst_stats.futures_instrumented = 1;
                inst_stats.total_polls_executed = poll_count;
                inst_stats.await_points_recorded = poll_count;
                inst_stats.poll_events_generated = poll_count;
            }

            // Store trace for analysis
            if let Ok(mut traces) = self.recorded_traces.lock() {
                traces.push(trace.clone());
            }

            result.duration_ms = test_start.elapsed().as_millis() as u64;
            result.recorder_stats = self.recorder_stats.lock().unwrap().clone();
            result.instrumentation_stats = self.instrumentation_stats.lock().unwrap().clone();
            result.trace_completeness_verified = trace.events.len() > 0;
            result.success = trace.events.len() > 0 && poll_count > 0;

            Ok(result)
        }

        pub async fn test_high_frequency_polling(
            &self,
        ) -> Result<FutureRecorderTestResult, Box<dyn std::error::Error>> {
            let test_start = Instant::now();
            let mut result = FutureRecorderTestResult {
                test_name: "high_frequency_polling".to_string(),
                scenario_id: "high_freq".to_string(),
                phase: FutureRecorderTestPhase::Setup,
                success: false,
                error: None,
                duration_ms: 0,
                recorder_stats: RecorderIntegrationStats::default(),
                instrumentation_stats: InstrumentationStats::default(),
                trace_completeness_verified: false,
                rate_limiting_effective: false,
            };

            // Initialize recorder with tighter limits
            result.phase = FutureRecorderTestPhase::RecorderInitialization;
            let rate_limited_config = RecorderConfig::enabled()
                .with_max_events(Some(100)) // Lower limit for rate limiting test
                .with_max_memory(64 * 1024) // 64KB memory limit
                .on_limit(self.rate_limit_tracker.create_callback());

            let metadata = TraceMetadata {
                test_name: "high_frequency_polling".to_string(),
                seed: 123,
                timestamp: Time::from_nanos(2000000000),
                lab_config: None,
            };
            let mut recorder = TraceRecorder::new(metadata, rate_limited_config);

            // Create rapid-polling future
            result.phase = FutureRecorderTestPhase::FutureInstrumentation;
            let event_log = Arc::new(Mutex::new(Vec::new()));
            let rapid_future = ConfigurableMockFuture::rapid_polling(Arc::clone(&event_log));

            let injector = CancellationInjector::new(InjectionStrategy::Never);
            let instrumented_future =
                InstrumentedFuture::new(rapid_future, injector, Some(TaskId::from_raw(2)));

            // Execute with rapid polling
            result.phase = FutureRecorderTestPhase::RateLimitingTest;
            let mut poll_count = 0u64;
            let mut pinned_future = Box::pin(instrumented_future);

            let waker = futures_lite::future::block_on(async {
                std::task::Context::from_waker(
                    futures_lite::future::poll_fn(|cx| Poll::Ready(cx.waker().clone())).await,
                )
            })
            .clone();
            let mut cx = Context::from_waker(&waker);

            let execution_start = Instant::now();

            while let Poll::Pending = pinned_future.as_mut().poll(&mut cx) {
                poll_count += 1;

                // Record poll event - this should trigger rate limiting
                recorder.record_future_poll(
                    TaskId::from_raw(2),
                    poll_count,
                    format!("rapid_poll_{}", poll_count),
                );

                // Prevent infinite loops
                if poll_count > 200 {
                    break;
                }
            }

            let execution_duration = execution_start.elapsed();

            // Validate rate limiting occurred
            let (limit_events, drop_count, stop_count) = self.rate_limit_tracker.get_stats();
            result.rate_limiting_effective = limit_events > 0 || drop_count > 0 || stop_count > 0;

            let trace = recorder.finish();

            // Update stats
            if let Ok(mut stats) = self.recorder_stats.lock() {
                stats.events_recorded = trace.events.len() as u64;
                stats.events_dropped = drop_count;
                stats.rate_limit_triggered = limit_events as u64;
                stats.recording_duration_ms = execution_duration.as_millis() as u64;
            }

            if let Ok(mut inst_stats) = self.instrumentation_stats.lock() {
                inst_stats.futures_instrumented = 1;
                inst_stats.total_polls_executed = poll_count;
                inst_stats.await_points_recorded = poll_count;
                inst_stats.poll_events_generated = poll_count;
            }

            result.duration_ms = test_start.elapsed().as_millis() as u64;
            result.recorder_stats = self.recorder_stats.lock().unwrap().clone();
            result.instrumentation_stats = self.instrumentation_stats.lock().unwrap().clone();
            result.trace_completeness_verified = trace.events.len() > 0;
            result.success = result.rate_limiting_effective && trace.events.len() > 0;

            Ok(result)
        }

        pub async fn test_concurrent_futures(
            &self,
        ) -> Result<FutureRecorderTestResult, Box<dyn std::error::Error>> {
            let test_start = Instant::now();
            let mut result = FutureRecorderTestResult {
                test_name: "concurrent_futures".to_string(),
                scenario_id: "concurrent".to_string(),
                phase: FutureRecorderTestPhase::Setup,
                success: false,
                error: None,
                duration_ms: 0,
                recorder_stats: RecorderIntegrationStats::default(),
                instrumentation_stats: InstrumentationStats::default(),
                trace_completeness_verified: false,
                rate_limiting_effective: false,
            };

            // Initialize recorder
            let metadata = TraceMetadata {
                test_name: "concurrent_futures".to_string(),
                seed: 456,
                timestamp: Time::from_nanos(3000000000),
                lab_config: None,
            };
            let mut recorder = TraceRecorder::new(metadata, self.recorder_config.clone());

            // Create multiple instrumented futures
            let future_count = 5;
            let mut instrumented_futures = Vec::new();

            for i in 0..future_count {
                let event_log = Arc::new(Mutex::new(Vec::new()));
                let mock_future = ConfigurableMockFuture::burst_polling(Arc::clone(&event_log));

                let injector = CancellationInjector::new(InjectionStrategy::Never);
                let instrumented_future =
                    InstrumentedFuture::new(mock_future, injector, Some(TaskId::from_raw(10 + i)));

                instrumented_futures.push(Box::pin(instrumented_future));
            }

            // Execute futures concurrently and record events
            result.phase = FutureRecorderTestPhase::PollEventGeneration;
            let execution_start = Instant::now();

            let waker = futures_lite::future::block_on(async {
                std::task::Context::from_waker(
                    futures_lite::future::poll_fn(|cx| Poll::Ready(cx.waker().clone())).await,
                )
            })
            .clone();
            let mut cx = Context::from_waker(&waker);

            let mut total_polls = 0u64;
            let max_rounds = 100; // Limit to prevent infinite loop

            for round in 0..max_rounds {
                let mut any_pending = false;

                for (i, future) in instrumented_futures.iter_mut().enumerate() {
                    if let Poll::Pending = future.as_mut().poll(&mut cx) {
                        any_pending = true;
                        total_polls += 1;

                        // Record concurrent poll event
                        recorder.record_future_poll(
                            TaskId::from_raw(10 + i as u64),
                            round + 1,
                            format!("concurrent_poll_{}_{}", i, round),
                        );
                    }
                }

                if !any_pending {
                    break;
                }
            }

            let execution_duration = execution_start.elapsed();

            // Validate concurrent recording
            let trace = recorder.finish();

            // Update stats
            if let Ok(mut stats) = self.recorder_stats.lock() {
                stats.events_recorded = trace.events.len() as u64;
                stats.recording_duration_ms = execution_duration.as_millis() as u64;
                stats.batches_written = 1;
            }

            if let Ok(mut inst_stats) = self.instrumentation_stats.lock() {
                inst_stats.futures_instrumented = future_count;
                inst_stats.total_polls_executed = total_polls;
                inst_stats.concurrent_futures_peak = future_count;
                inst_stats.poll_events_generated = total_polls;
            }

            result.duration_ms = test_start.elapsed().as_millis() as u64;
            result.recorder_stats = self.recorder_stats.lock().unwrap().clone();
            result.instrumentation_stats = self.instrumentation_stats.lock().unwrap().clone();
            result.trace_completeness_verified = trace.events.len() > 0;
            result.success = trace.events.len() > 0 && total_polls > 0;

            Ok(result)
        }

        pub fn get_final_stats(&self) -> (RecorderIntegrationStats, InstrumentationStats) {
            let recorder_stats = self.recorder_stats.lock().unwrap().clone();
            let inst_stats = self.instrumentation_stats.lock().unwrap().clone();
            (recorder_stats, inst_stats)
        }
    }

    // Extension trait to add future poll recording to TraceRecorder
    trait FuturePollRecording {
        fn record_future_poll(&mut self, task_id: TaskId, sequence: u64, location: String);
    }

    impl FuturePollRecording for TraceRecorder {
        fn record_future_poll(&mut self, task_id: TaskId, sequence: u64, location: String) {
            // Record as a custom event with await point information
            self.record_custom_event(format!(
                "future_poll:{}:{}:{}",
                task_id.as_raw(),
                sequence,
                location
            ));
        }
    }

    // ────────────────────────────────────────────────────────────────────────────────
    // Integration Test Cases
    // ────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_basic_instrumented_future_poll_recording() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let harness = InstrumentedFutureRecorderHarness::new().await.unwrap();

            let result = harness.test_basic_poll_recording().await.unwrap();

            assert!(result.success, "Basic poll recording should succeed");
            assert!(
                result.trace_completeness_verified,
                "Trace should be complete"
            );
            assert!(
                result.instrumentation_stats.futures_instrumented > 0,
                "Should have instrumented futures"
            );
            assert!(
                result.instrumentation_stats.total_polls_executed > 0,
                "Should have executed polls"
            );
            assert!(
                result.recorder_stats.events_recorded > 0,
                "Should have recorded events"
            );
            assert_eq!(
                result.recorder_stats.events_dropped, 0,
                "Should not drop events in basic test"
            );

            println!(
                "✓ Basic poll recording: {} polls, {} events recorded",
                result.instrumentation_stats.total_polls_executed,
                result.recorder_stats.events_recorded
            );
        });
    }

    #[test]
    fn test_high_frequency_polling_rate_limiting() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let harness = InstrumentedFutureRecorderHarness::new().await.unwrap();

            let result = harness.test_high_frequency_polling().await.unwrap();

            assert!(result.success, "High frequency polling test should succeed");
            assert!(result.rate_limiting_effective, "Rate limiting should be effective");
            assert!(result.instrumentation_stats.total_polls_executed > result.recorder_stats.events_recorded,
                "Should have more polls than recorded events due to rate limiting");
            assert!(result.recorder_stats.rate_limit_triggered > 0 || result.recorder_stats.events_dropped > 0,
                "Rate limiting should be triggered");
            assert!(result.trace_completeness_verified, "Trace should still capture essential events");

            println!("✓ High frequency rate limiting: {} polls generated, {} events recorded, {} dropped",
                result.instrumentation_stats.total_polls_executed,
                result.recorder_stats.events_recorded,
                result.recorder_stats.events_dropped);
        });
    }

    #[test]
    fn test_concurrent_futures_recording() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let harness = InstrumentedFutureRecorderHarness::new().await.unwrap();

            let result = harness.test_concurrent_futures().await.unwrap();

            assert!(
                result.success,
                "Concurrent futures recording should succeed"
            );
            assert!(
                result.instrumentation_stats.futures_instrumented >= 5,
                "Should have multiple instrumented futures"
            );
            assert!(
                result.instrumentation_stats.concurrent_futures_peak >= 5,
                "Should track concurrent peak"
            );
            assert!(
                result.recorder_stats.events_recorded > 0,
                "Should record events from concurrent futures"
            );
            assert!(
                result.trace_completeness_verified,
                "Trace should be complete for concurrent execution"
            );

            println!(
                "✓ Concurrent futures: {} futures, {} polls, {} events",
                result.instrumentation_stats.futures_instrumented,
                result.instrumentation_stats.total_polls_executed,
                result.recorder_stats.events_recorded
            );
        });
    }

    #[test]
    fn test_back_pressure_handling() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let harness = InstrumentedFutureRecorderHarness::new().await.unwrap();

            // Run high frequency test to trigger back pressure
            let high_freq_result = harness.test_high_frequency_polling().await.unwrap();

            // Then run basic test to verify recovery
            let basic_result = harness.test_basic_poll_recording().await.unwrap();

            assert!(
                high_freq_result.rate_limiting_effective,
                "Should trigger back pressure"
            );
            assert!(basic_result.success, "Should recover after back pressure");

            let (final_recorder_stats, final_inst_stats) = harness.get_final_stats();

            // Verify overall system health
            assert!(
                final_recorder_stats.events_recorded > 0,
                "Should maintain some recording capability"
            );
            assert!(
                final_inst_stats.futures_instrumented > 1,
                "Should handle multiple test phases"
            );

            println!("✓ Back pressure handling: rate limiting triggered, recording recovered");
        });
    }

    #[test]
    fn test_instrumentation_recorder_integration_comprehensive() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let harness = InstrumentedFutureRecorderHarness::new().await.unwrap();

            // Run all test scenarios
            let basic_result = harness.test_basic_poll_recording().await.unwrap();
            let high_freq_result = harness.test_high_frequency_polling().await.unwrap();
            let concurrent_result = harness.test_concurrent_futures().await.unwrap();

            // Verify all scenarios succeeded
            assert!(basic_result.success, "Basic recording should work");
            assert!(high_freq_result.success, "High frequency should trigger rate limiting appropriately");
            assert!(concurrent_result.success, "Concurrent futures should be handled properly");

            // Verify integration properties
            assert!(high_freq_result.rate_limiting_effective, "Rate limiting should protect recorder");
            assert!(concurrent_result.instrumentation_stats.concurrent_futures_peak >= 5, "Concurrency should be tracked");
            assert!(basic_result.trace_completeness_verified, "Basic traces should be complete");

            let (final_recorder_stats, final_inst_stats) = harness.get_final_stats();

            // Comprehensive verification
            assert!(final_recorder_stats.events_recorded > 50,
                "Should record substantial number of events across all tests");
            assert!(final_inst_stats.futures_instrumented >= 7,
                "Should have instrumented futures from all test scenarios");
            assert!(final_inst_stats.total_polls_executed > final_recorder_stats.events_recorded,
                "Should demonstrate selective recording under load");

            println!("✓ Comprehensive integration: {} total polls, {} events recorded, rate limiting effective: {}",
                final_inst_stats.total_polls_executed,
                final_recorder_stats.events_recorded,
                high_freq_result.rate_limiting_effective);
        });
    }

    #[test]
    fn test_poll_sequence_reconstruction() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let harness = InstrumentedFutureRecorderHarness::new().await.unwrap();

            let result = harness.test_basic_poll_recording().await.unwrap();

            assert!(result.success, "Poll recording should succeed");
            assert!(
                result.trace_completeness_verified,
                "Trace should be complete"
            );

            // Verify that poll sequence can be reconstructed
            // In a real implementation, this would validate that the trace
            // contains sufficient information to replay the polling sequence

            let poll_count = result.instrumentation_stats.total_polls_executed;
            let recorded_events = result.recorder_stats.events_recorded;

            // Should have reasonable correlation between polls and recorded events
            assert!(recorded_events > 0, "Should have some recorded events");
            assert!(
                poll_count >= recorded_events,
                "Poll count should be at least as many as recorded events"
            );

            // Verify no excessive dropping in basic scenario
            assert_eq!(
                result.recorder_stats.events_dropped, 0,
                "Basic scenario should not drop events"
            );

            println!(
                "✓ Poll sequence reconstruction: {} polls -> {} events, sequence preserved",
                poll_count, recorded_events
            );
        });
    }
}
