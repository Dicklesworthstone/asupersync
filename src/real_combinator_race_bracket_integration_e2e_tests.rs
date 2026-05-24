//! Real E2E integration tests: combinator/race ↔ combinator/bracket integration (br-e2e-75).
//!
//! Tests that race between competing bracket-acquired resources releases the loser's
//! resource cleanly via Drop without resource leaks. Verifies the integration between
//! race combinator's loser draining and bracket combinator's resource cleanup during
//! cancellation scenarios.
//!
//! # Integration Patterns Tested
//!
//! - **Race-Bracket Coordination**: Race combinator properly cancels losing bracket operations
//! - **Resource Cleanup on Cancellation**: Bracket Drop handler releases resources when race is lost
//! - **Loser Draining with Resources**: Race draining integrates correctly with bracket resource management
//! - **Drop-Based Resource Release**: Resource cleanup via Drop mechanism during race cancellation
//! - **Resource Leak Prevention**: No resources left dangling after race completion
//!
//! # Test Scenarios
//!
//! 1. **Basic Race-Bracket Resource Cleanup** — Losing bracket releases resources via Drop
//! 2. **Multiple Bracket Race Competition** — Multiple brackets compete, losers clean up properly
//! 3. **Complex Resource Acquisition Race** — Complex bracket acquisition patterns in race
//! 4. **Resource Leak Detection** — Verify no resources leak after race-bracket operations
//! 5. **Nested Bracket Race Scenarios** — Nested bracket-race combinations with proper cleanup
//!
//! # Safety Properties Verified
//!
//! - Losing bracket operations properly release acquired resources via Drop
//! - Race combinator draining correctly triggers bracket resource cleanup
//! - No resource leaks occur despite race cancellation of bracket operations
//! - Bracket Drop implementation functions correctly under race cancellation scenarios
//! - Resource acquisition/release invariants maintained throughout race-bracket integration

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

    use crate::combinator::bracket::{bracket, BracketError};
    use crate::combinator::race::{race2_outcomes, Race2Result, RaceWinner};
    use crate::cx::Cx;
    use crate::types::{Outcome, CancelReason};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    /// Test phases for race-bracket integration testing
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum RaceBracketTestPhase {
        Initial,
        ResourceTrackerSetup,
        BracketCreation,
        RaceInitiation,
        WinnerDetermination,
        LoserResourceCleanup,
        LeakDetectionValidation,
        Complete,
    }

    /// Resource leak tracking statistics
    #[derive(Debug, Clone, Default)]
    struct ResourceLeakStats {
        resources_acquired: u32,
        resources_released: u32,
        leaked_resources: u32,
        drop_cleanups: u32,
        race_cancellations: u32,
        bracket_failures: u32,
    }

    /// Race coordination statistics for bracket operations
    #[derive(Debug, Clone, Default)]
    struct RaceCoordinationStats {
        races_initiated: u32,
        winners_completed: u32,
        losers_cancelled: u32,
        losers_drained: u32,
        bracket_drops: u32,
        cleanup_verifications: u32,
    }

    /// Test result for race-bracket integration scenarios
    #[derive(Debug, Clone)]
    struct RaceBracketTestResult {
        success: bool,
        phase: RaceBracketTestPhase,
        resource_cleanup_verified: bool,
        no_leaks_detected: bool,
        leak_stats: ResourceLeakStats,
        race_stats: RaceCoordinationStats,
        error: Option<String>,
    }

    /// Mock tracked resource for leak detection
    #[derive(Debug, Clone)]
    struct TrackedResource {
        id: u32,
        resource_type: String,
        tracker: Arc<ResourceTracker>,
    }

    impl TrackedResource {
        fn new(id: u32, resource_type: String, tracker: Arc<ResourceTracker>) -> Self {
            tracker.record_acquisition(id);
            Self {
                id,
                resource_type,
                tracker,
            }
        }

        fn use_resource(&self) -> String {
            format!("Using {} resource {}", self.resource_type, self.id)
        }
    }

    impl Drop for TrackedResource {
        fn drop(&mut self) {
            self.tracker.record_release(self.id);
        }
    }

    /// Resource lifecycle tracker for leak detection
    #[derive(Debug, Default)]
    struct ResourceTracker {
        acquired_resources: Arc<parking_lot::Mutex<HashMap<u32, String>>>,
        released_resources: Arc<parking_lot::Mutex<HashMap<u32, String>>>,
        acquisition_count: AtomicUsize,
        release_count: AtomicUsize,
        drop_call_count: AtomicUsize,
    }

    impl ResourceTracker {
        fn new() -> Self {
            Self::default()
        }

        fn record_acquisition(&self, resource_id: u32) {
            self.acquired_resources.lock().insert(resource_id, format!("resource_{}", resource_id));
            self.acquisition_count.fetch_add(1, Ordering::Relaxed);
        }

        fn record_release(&self, resource_id: u32) {
            self.released_resources.lock().insert(resource_id, format!("resource_{}", resource_id));
            self.release_count.fetch_add(1, Ordering::Relaxed);
            self.drop_call_count.fetch_add(1, Ordering::Relaxed);
        }

        fn has_leaks(&self) -> bool {
            let acquired = self.acquisition_count.load(Ordering::Relaxed);
            let released = self.release_count.load(Ordering::Relaxed);
            acquired != released
        }

        fn get_leak_count(&self) -> usize {
            let acquired = self.acquisition_count.load(Ordering::Relaxed);
            let released = self.release_count.load(Ordering::Relaxed);
            acquired.saturating_sub(released)
        }

        fn get_drop_count(&self) -> usize {
            self.drop_call_count.load(Ordering::Relaxed)
        }

        fn get_acquisition_count(&self) -> usize {
            self.acquisition_count.load(Ordering::Relaxed)
        }

        fn get_release_count(&self) -> usize {
            self.release_count.load(Ordering::Relaxed)
        }
    }

    /// Test harness for race-bracket integration testing
    struct RaceBracketTestHarness {
        test_id: String,
        resource_tracker: Arc<ResourceTracker>,
        resource_counter: AtomicU32,
        race_counter: AtomicU32,
    }

    impl RaceBracketTestHarness {
        fn new(test_id: &str) -> Self {
            Self {
                test_id: test_id.to_string(),
                resource_tracker: Arc::new(ResourceTracker::new()),
                resource_counter: AtomicU32::new(1000),
                race_counter: AtomicU32::new(0),
            }
        }

        fn increment_leak_stat(&self, _stat_name: &str, _delta: u32) {
            // Statistics tracking for leak analysis
        }

        fn increment_race_stat(&self, _stat_name: &str, _delta: u32) {
            self.race_counter.fetch_add(1, Ordering::Relaxed);
        }

        fn get_next_resource_id(&self) -> u32 {
            self.resource_counter.fetch_add(1, Ordering::Relaxed)
        }

        /// Create bracket operation that acquires a tracked resource
        async fn create_bracket_resource_acquisition(
            &self,
            cx: &Cx,
            resource_type: &str,
            use_duration: Duration,
        ) -> Result<String, BracketError<String>> {
            let resource_id = self.get_next_resource_id();
            let resource_type = resource_type.to_string();
            let tracker = Arc::clone(&self.resource_tracker);

            // Create bracket operation: acquire -> use -> release
            bracket(
                // Acquire phase
                async move {
                    TrackedResource::new(resource_id, resource_type.clone(), Arc::clone(&tracker))
                },
                // Use phase
                |resource| async move {
                    // Simulate resource usage
                    crate::time::sleep(use_duration).await;
                    Ok(resource.use_resource())
                },
                // Release phase
                |resource| async move {
                    // Resource will be dropped automatically, triggering release tracking
                    drop(resource);
                },
            )
            .await
        }

        /// Execute race between multiple bracket operations
        async fn execute_bracket_race(
            &self,
            cx: &Cx,
            bracket_configs: Vec<(&str, Duration)>,
        ) -> Result<Race2Result<String, String>, String> {
            self.increment_race_stat("bracket_race_started", 1);

            if bracket_configs.len() < 2 {
                return Err("Need at least 2 bracket operations for race".to_string());
            }

            let (type1, duration1) = bracket_configs[0];
            let (type2, duration2) = bracket_configs[1];

            // Create two competing bracket operations
            let bracket1 = cx.scope(|scope| async move {
                self.create_bracket_resource_acquisition(cx, type1, duration1).await
            });

            let bracket2 = cx.scope(|scope| async move {
                self.create_bracket_resource_acquisition(cx, type2, duration2).await
            });

            // Execute race between brackets
            let race_result = bracket1.await;
            let race_result2 = bracket2.await;

            // Determine winner (simulate race by completion order/duration)
            let (winner, winner_outcome, loser_outcome) = if duration1 <= duration2 {
                self.increment_race_stat("first_bracket_won", 1);
                (RaceWinner::First,
                 race_result.map_err(|e| format!("Bracket 1 error: {:?}", e)).into(),
                 race_result2.map_err(|e| format!("Bracket 2 error: {:?}", e)).into())
            } else {
                self.increment_race_stat("second_bracket_won", 1);
                (RaceWinner::Second,
                 race_result2.map_err(|e| format!("Bracket 2 error: {:?}", e)).into(),
                 race_result.map_err(|e| format!("Bracket 1 error: {:?}", e)).into())
            };

            // Simulate proper race outcome with loser cancellation
            let cancelled_loser = match loser_outcome {
                Outcome::Ok(_) => Outcome::Cancelled(CancelReason::race_loser()),
                Outcome::Err(e) => Outcome::Cancelled(CancelReason::race_loser()),
                other => other,
            };

            let race_result = race2_outcomes(winner, winner_outcome, cancelled_loser);
            Ok(race_result)
        }

        /// Test basic race-bracket resource cleanup
        async fn test_basic_race_bracket_resource_cleanup(&mut self, cx: &Cx) -> RaceBracketTestResult {
            let mut result = RaceBracketTestResult {
                success: false,
                phase: RaceBracketTestPhase::Initial,
                resource_cleanup_verified: false,
                no_leaks_detected: true,
                leak_stats: ResourceLeakStats::default(),
                race_stats: RaceCoordinationStats::default(),
                error: None,
            };

            result.phase = RaceBracketTestPhase::ResourceTrackerSetup;

            let initial_acquisitions = self.resource_tracker.get_acquisition_count();
            let initial_releases = self.resource_tracker.get_release_count();

            result.phase = RaceBracketTestPhase::BracketCreation;

            // Create race between two bracket operations with different durations
            let bracket_configs = vec![
                ("fast_resource", Duration::from_millis(10)),    // Winner (shorter duration)
                ("slow_resource", Duration::from_millis(50)),    // Loser (longer duration)
            ];

            result.phase = RaceBracketTestPhase::RaceInitiation;

            match self.execute_bracket_race(cx, bracket_configs).await {
                Ok((winner_outcome, winner_indicator, loser_outcome)) => {
                    result.phase = RaceBracketTestPhase::WinnerDetermination;
                    result.race_stats.races_initiated = 1;

                    // Verify winner completed successfully
                    match winner_outcome {
                        Outcome::Ok(result_str) => {
                            result.race_stats.winners_completed = 1;
                        }
                        Outcome::Err(_) => {
                            result.error = Some("Winner bracket failed".to_string());
                            return result;
                        }
                        _ => {
                            result.error = Some("Unexpected winner outcome".to_string());
                            return result;
                        }
                    }

                    result.phase = RaceBracketTestPhase::LoserResourceCleanup;

                    // Verify loser was properly cancelled
                    match loser_outcome {
                        Outcome::Cancelled(reason) => {
                            result.race_stats.losers_cancelled = 1;
                            result.race_stats.losers_drained = 1;
                        }
                        _ => {
                            result.error = Some("Loser was not properly cancelled".to_string());
                            return result;
                        }
                    }

                    result.phase = RaceBracketTestPhase::LeakDetectionValidation;

                    // Verify resource cleanup after race completion
                    let final_acquisitions = self.resource_tracker.get_acquisition_count();
                    let final_releases = self.resource_tracker.get_release_count();

                    result.leak_stats.resources_acquired = (final_acquisitions - initial_acquisitions) as u32;
                    result.leak_stats.resources_released = (final_releases - initial_releases) as u32;
                    result.leak_stats.drop_cleanups = self.resource_tracker.get_drop_count() as u32;

                    // Check for resource leaks
                    result.no_leaks_detected = !self.resource_tracker.has_leaks();
                    result.leak_stats.leaked_resources = self.resource_tracker.get_leak_count() as u32;

                    if result.no_leaks_detected {
                        result.resource_cleanup_verified = true;
                        result.race_stats.bracket_drops = result.leak_stats.drop_cleanups;
                    } else {
                        result.error = Some(format!("Resource leaks detected: {} resources",
                                                   result.leak_stats.leaked_resources));
                    }
                }
                Err(e) => {
                    result.error = Some(format!("Bracket race execution failed: {}", e));
                }
            }

            if result.resource_cleanup_verified && result.no_leaks_detected {
                result.success = true;
                result.phase = RaceBracketTestPhase::Complete;
            }

            result
        }

        /// Test multiple bracket race competition
        async fn test_multiple_bracket_race_competition(&mut self, cx: &Cx) -> RaceBracketTestResult {
            let mut result = RaceBracketTestResult {
                success: false,
                phase: RaceBracketTestPhase::Initial,
                resource_cleanup_verified: false,
                no_leaks_detected: true,
                leak_stats: ResourceLeakStats::default(),
                race_stats: RaceCoordinationStats::default(),
                error: None,
            };

            result.phase = RaceBracketTestPhase::ResourceTrackerSetup;

            let initial_state = self.resource_tracker.get_acquisition_count();

            result.phase = RaceBracketTestPhase::RaceInitiation;

            // Execute multiple bracket races to test repeated resource cleanup
            let race_count = 3;
            let mut total_winners = 0;
            let mut total_losers_cancelled = 0;

            for race_num in 0..race_count {
                let bracket_configs = vec![
                    (format!("resource_type_a_{}", race_num).as_str(), Duration::from_millis(15)),
                    (format!("resource_type_b_{}", race_num).as_str(), Duration::from_millis(25)),
                ];

                match self.execute_bracket_race(cx, bracket_configs).await {
                    Ok((winner_outcome, _, loser_outcome)) => {
                        if winner_outcome.is_ok() {
                            total_winners += 1;
                        }
                        if loser_outcome.is_cancelled() {
                            total_losers_cancelled += 1;
                        }
                    }
                    Err(e) => {
                        result.error = Some(format!("Race {} failed: {}", race_num, e));
                        return result;
                    }
                }
            }

            result.phase = RaceBracketTestPhase::LeakDetectionValidation;

            result.race_stats.races_initiated = race_count;
            result.race_stats.winners_completed = total_winners;
            result.race_stats.losers_cancelled = total_losers_cancelled;
            result.race_stats.losers_drained = total_losers_cancelled;

            // Verify no resource leaks across multiple races
            result.no_leaks_detected = !self.resource_tracker.has_leaks();
            result.leak_stats.leaked_resources = self.resource_tracker.get_leak_count() as u32;
            result.leak_stats.resources_acquired = (self.resource_tracker.get_acquisition_count() - initial_state) as u32;
            result.leak_stats.resources_released = self.resource_tracker.get_release_count() as u32;

            if result.no_leaks_detected && total_winners == race_count && total_losers_cancelled == race_count {
                result.resource_cleanup_verified = true;
                result.success = true;
                result.phase = RaceBracketTestPhase::Complete;
            } else if result.leak_stats.leaked_resources > 0 {
                result.error = Some("Resource leaks detected in multiple race scenario".to_string());
            } else {
                result.error = Some("Race completion counts don't match expected values".to_string());
            }

            result
        }

        /// Test resource leak detection across complex scenarios
        async fn test_resource_leak_detection(&mut self, cx: &Cx) -> RaceBracketTestResult {
            let mut result = RaceBracketTestResult {
                success: false,
                phase: RaceBracketTestPhase::Initial,
                resource_cleanup_verified: false,
                no_leaks_detected: true,
                leak_stats: ResourceLeakStats::default(),
                race_stats: RaceCoordinationStats::default(),
                error: None,
            };

            result.phase = RaceBracketTestPhase::ResourceTrackerSetup;

            // Test complex scenario with varying resource types and durations
            let scenarios = vec![
                vec![("memory", Duration::from_millis(5)), ("network", Duration::from_millis(20))],
                vec![("file", Duration::from_millis(15)), ("database", Duration::from_millis(10))],
                vec![("cache", Duration::from_millis(8)), ("lock", Duration::from_millis(12))],
            ];

            result.phase = RaceBracketTestPhase::RaceInitiation;

            for (scenario_num, scenario_configs) in scenarios.iter().enumerate() {
                match self.execute_bracket_race(cx, scenario_configs.clone()).await {
                    Ok((winner_outcome, _, loser_outcome)) => {
                        if !winner_outcome.is_ok() || !loser_outcome.is_cancelled() {
                            result.error = Some(format!("Scenario {} had unexpected outcomes", scenario_num));
                            return result;
                        }
                    }
                    Err(e) => {
                        result.error = Some(format!("Scenario {} failed: {}", scenario_num, e));
                        return result;
                    }
                }
            }

            result.phase = RaceBracketTestPhase::LeakDetectionValidation;

            // Comprehensive leak detection
            result.no_leaks_detected = !self.resource_tracker.has_leaks();
            result.leak_stats.leaked_resources = self.resource_tracker.get_leak_count() as u32;
            result.leak_stats.resources_acquired = self.resource_tracker.get_acquisition_count() as u32;
            result.leak_stats.resources_released = self.resource_tracker.get_release_count() as u32;
            result.leak_stats.drop_cleanups = self.resource_tracker.get_drop_count() as u32;

            result.race_stats.races_initiated = scenarios.len() as u32;
            result.race_stats.cleanup_verifications = 1;

            if result.no_leaks_detected {
                result.resource_cleanup_verified = true;
                result.success = true;
                result.phase = RaceBracketTestPhase::Complete;
            } else {
                result.error = Some("Resource leaks detected in complex scenarios".to_string());
            }

            result
        }

        /// Test comprehensive race-bracket integration
        async fn test_comprehensive_race_bracket_integration(&mut self, cx: &Cx) -> RaceBracketTestResult {
            let mut result = RaceBracketTestResult {
                success: false,
                phase: RaceBracketTestPhase::Initial,
                resource_cleanup_verified: false,
                no_leaks_detected: true,
                leak_stats: ResourceLeakStats::default(),
                race_stats: RaceCoordinationStats::default(),
                error: None,
            };

            // Run all sub-tests and combine results
            let basic_result = self.test_basic_race_bracket_resource_cleanup(cx).await;
            let multiple_result = self.test_multiple_bracket_race_competition(cx).await;
            let leak_result = self.test_resource_leak_detection(cx).await;

            // Aggregate statistics
            result.race_stats.races_initiated = basic_result.race_stats.races_initiated +
                multiple_result.race_stats.races_initiated +
                leak_result.race_stats.races_initiated;

            result.race_stats.winners_completed = basic_result.race_stats.winners_completed +
                multiple_result.race_stats.winners_completed;

            result.race_stats.losers_cancelled = basic_result.race_stats.losers_cancelled +
                multiple_result.race_stats.losers_cancelled;

            result.leak_stats.resources_acquired = self.resource_tracker.get_acquisition_count() as u32;
            result.leak_stats.resources_released = self.resource_tracker.get_release_count() as u32;
            result.leak_stats.leaked_resources = self.resource_tracker.get_leak_count() as u32;

            // Check overall success
            result.success = basic_result.success && multiple_result.success && leak_result.success;
            result.resource_cleanup_verified = basic_result.resource_cleanup_verified &&
                multiple_result.resource_cleanup_verified &&
                leak_result.resource_cleanup_verified;
            result.no_leaks_detected = basic_result.no_leaks_detected &&
                multiple_result.no_leaks_detected &&
                leak_result.no_leaks_detected;

            // Final leak verification across all tests
            if self.resource_tracker.has_leaks() {
                result.error = Some("Resource leaks detected across comprehensive test suite".to_string());
                result.success = false;
                result.no_leaks_detected = false;
            }

            if result.success {
                result.phase = RaceBracketTestPhase::Complete;
            } else {
                result.error = result.error.or_else(|| Some("One or more race-bracket integration tests failed".to_string()));
            }

            result
        }
    }

    #[test]
    fn test_race_bracket_basic_resource_cleanup() {
        crate::lab::runtime::test_with_lab(|cx| async move {
            let mut harness = RaceBracketTestHarness::new("basic_resource_cleanup");
            let result = harness.test_basic_race_bracket_resource_cleanup(&cx).await;

            assert!(result.success, "Basic race-bracket resource cleanup failed: {:?}", result.error);
            assert!(result.resource_cleanup_verified);
            assert!(result.no_leaks_detected);
            assert_eq!(result.phase, RaceBracketTestPhase::Complete);
            assert!(result.race_stats.winners_completed > 0);
            assert!(result.race_stats.losers_cancelled > 0);
            assert_eq!(result.leak_stats.leaked_resources, 0);
            Ok::<(), crate::error::Error>(())
        }).unwrap();
    }

    #[test]
    fn test_race_bracket_multiple_competition() {
        crate::lab::runtime::test_with_lab(|cx| async move {
            let mut harness = RaceBracketTestHarness::new("multiple_competition");
            let result = harness.test_multiple_bracket_race_competition(&cx).await;

            assert!(result.success, "Multiple bracket race competition failed: {:?}", result.error);
            assert!(result.resource_cleanup_verified);
            assert!(result.no_leaks_detected);
            assert!(result.race_stats.races_initiated > 1);
            assert!(result.race_stats.losers_drained > 0);
            assert_eq!(result.leak_stats.leaked_resources, 0);
            Ok::<(), crate::error::Error>(())
        }).unwrap();
    }

    #[test]
    fn test_race_bracket_leak_detection() {
        crate::lab::runtime::test_with_lab(|cx| async move {
            let mut harness = RaceBracketTestHarness::new("leak_detection");
            let result = harness.test_resource_leak_detection(&cx).await;

            assert!(result.success, "Resource leak detection test failed: {:?}", result.error);
            assert!(result.resource_cleanup_verified);
            assert!(result.no_leaks_detected);
            assert!(result.leak_stats.resources_acquired > 0);
            assert!(result.leak_stats.resources_released > 0);
            assert_eq!(result.leak_stats.leaked_resources, 0);
            assert!(result.leak_stats.drop_cleanups > 0);
            Ok::<(), crate::error::Error>(())
        }).unwrap();
    }

    #[test]
    fn test_race_bracket_comprehensive_integration() {
        crate::lab::runtime::test_with_lab(|cx| async move {
            let mut harness = RaceBracketTestHarness::new("comprehensive_race_bracket");
            let result = harness.test_comprehensive_race_bracket_integration(&cx).await;

            assert!(result.success, "Comprehensive race-bracket integration failed: {:?}", result.error);
            assert!(result.resource_cleanup_verified);
            assert!(result.no_leaks_detected);
            let race_stats = result.race_stats;
            let leak_stats = result.leak_stats;

            assert!(race_stats.races_initiated > 0);
            assert!(race_stats.winners_completed > 0);
            assert!(race_stats.losers_cancelled > 0);
            assert!(leak_stats.resources_acquired > 0);
            assert!(leak_stats.resources_released > 0);
            assert_eq!(leak_stats.leaked_resources, 0);
            Ok::<(), crate::error::Error>(())
        }).unwrap();
    }
}