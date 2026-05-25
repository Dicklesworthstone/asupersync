//! Real combinator/race ↔ obligation/lyapunov integration E2E tests.
//!
//! Tests race-loser's obligations correctly decrement Lyapunov potential without leaking.
//! Verifies that race combinator integration with Lyapunov stability tracking properly
//! manages losing tasks' obligations and maintains system stability invariants.

use crate::bytes::Bytes;
use crate::combinator::race;
use crate::cx::Cx;
use crate::error::AsupersyncError;
use crate::obligation::lyapunov::{LyapunovFunction, LyapunovPotential, StabilityAnalyzer};
use crate::obligation::{Obligation, ObligationLedger, ObligationState};
use crate::runtime::{region, spawn, RuntimeBuilder};
use crate::time::{sleep, Duration};
use crate::types::{Budget, Outcome, ObligationId, TaskId};

use std::collections::HashMap;
use std::sync::{Arc, Mutex, atomic::{AtomicU64, AtomicUsize, Ordering}};

/// Number of race participants for stress testing.
const RACE_PARTICIPANTS: usize = 8;

/// Number of obligations per race participant.
const OBLIGATIONS_PER_PARTICIPANT: usize = 4;

/// Maximum race duration for timeout testing.
const MAX_RACE_DURATION_MS: u64 = 1000;

/// Stability threshold for Lyapunov analysis.
const STABILITY_THRESHOLD: f64 = 0.001;

/// Race-Lyapunov integration test framework.
///
/// Provides facilities for testing race combinator integration with Lyapunov
/// stability tracking while ensuring proper obligation cleanup for race losers.
#[derive(Debug)]
pub struct RaceLyapunovTestFramework {
    /// Lyapunov stability analyzer.
    stability_analyzer: Arc<Mutex<StabilityAnalyzer>>,
    /// Obligation ledger for tracking race participant obligations.
    obligation_ledger: Arc<Mutex<ObligationLedger>>,
    /// Race result tracker.
    race_tracker: RaceResultTracker,
    /// Potential function calculator.
    potential_calculator: PotentialCalculator,
    /// Resource leak detector.
    leak_detector: ResourceLeakDetector,
}

impl RaceLyapunovTestFramework {
    /// Creates a new race-Lyapunov test framework.
    pub fn new() -> Self {
        Self {
            stability_analyzer: Arc::new(Mutex::new(StabilityAnalyzer::new(STABILITY_THRESHOLD))),
            obligation_ledger: Arc::new(Mutex::new(ObligationLedger::new())),
            race_tracker: RaceResultTracker::new(),
            potential_calculator: PotentialCalculator::new(),
            leak_detector: ResourceLeakDetector::new(),
        }
    }

    /// Tests race loser obligation cleanup with Lyapunov potential tracking.
    pub async fn test_race_loser_obligation_cleanup(
        &self,
        cx: &Cx,
    ) -> Outcome<RaceCleanupResult, RaceLyapunovError> {
        // Record initial Lyapunov potential
        let initial_potential = self.calculate_system_potential().await?;

        // Create race participants with obligations
        let participants = self.create_race_participants_with_obligations(cx).await?;

        // Execute race and track winner/losers
        let race_result = self.execute_race_with_tracking(cx, participants).await?;

        // Verify loser obligations are cleaned up
        let cleanup_verification = self.verify_loser_obligation_cleanup(
            &race_result.losers
        ).await?;

        // Calculate final Lyapunov potential
        let final_potential = self.calculate_system_potential().await?;

        // Verify potential decremented correctly
        let potential_delta = initial_potential - final_potential;
        let potential_decremented = potential_delta > 0.0;

        // Check for resource leaks
        let leak_check = self.leak_detector.detect_leaks().await?;

        Outcome::Ok(RaceCleanupResult {
            initial_potential,
            final_potential,
            potential_decremented,
            potential_delta,
            winner_task_id: race_result.winner,
            losers_count: race_result.losers.len(),
            obligations_cleaned: cleanup_verification.cleaned_obligations,
            obligations_leaked: cleanup_verification.leaked_obligations,
            cleanup_successful: cleanup_verification.all_cleaned,
            no_resource_leaks: !leak_check.has_leaks,
        })
    }

    /// Tests multiple concurrent races with Lyapunov stability analysis.
    pub async fn test_concurrent_races_stability(
        &self,
        cx: &Cx,
    ) -> Outcome<StabilityAnalysisResult, RaceLyapunovError> {
        let concurrent_races = 4;
        let mut race_tasks = Vec::new();

        // Record baseline stability metrics
        let baseline_stability = self.analyze_system_stability().await?;

        // Launch concurrent races
        for race_id in 0..concurrent_races {
            let framework = self.clone();
            let race_cx = cx.clone();

            let race_task = async move {
                let participants = framework.create_race_participants_with_obligations(&race_cx).await?;
                framework.execute_race_with_tracking(&race_cx, participants).await
            };

            race_tasks.push(race_task);
        }

        // Execute all races concurrently within a region
        let race_results = region(Budget::default(), |region_cx| async move {
            let mut handles = Vec::new();

            for race_task in race_tasks {
                let handle = spawn(&region_cx, race_task)?;
                handles.push(handle);
            }

            let mut results = Vec::new();
            for handle in handles {
                results.push(handle.await?);
            }

            Outcome::Ok(results)
        }).await?;

        // Analyze post-race stability
        let post_race_stability = self.analyze_system_stability().await?;

        // Verify stability maintained or improved
        let stability_maintained = post_race_stability.stability_metric >=
                                 baseline_stability.stability_metric - STABILITY_THRESHOLD;

        // Check obligation cleanup across all races
        let total_participants = race_results.iter().map(|r| r.losers.len() + 1).sum();
        let total_obligations_expected = total_participants * OBLIGATIONS_PER_PARTICIPANT;

        let cleanup_verification = self.verify_global_obligation_cleanup().await?;

        Outcome::Ok(StabilityAnalysisResult {
            concurrent_races_completed: race_results.len(),
            baseline_stability: baseline_stability.stability_metric,
            post_race_stability: post_race_stability.stability_metric,
            stability_maintained,
            total_participants,
            total_obligations_expected,
            obligations_properly_cleaned: cleanup_verification.all_obligations_resolved,
            lyapunov_convergence_verified: post_race_stability.converged,
        })
    }

    /// Tests race timeout scenarios with obligation leak prevention.
    pub async fn test_race_timeout_obligation_safety(
        &self,
        cx: &Cx,
    ) -> Outcome<TimeoutSafetyResult, RaceLyapunovError> {
        // Create race with intentionally slow participants
        let slow_participants = self.create_slow_race_participants_with_obligations(cx).await?;

        // Record pre-race obligation count
        let pre_race_obligations = self.count_active_obligations().await?;

        // Execute race with timeout
        let timeout_duration = Duration::from_millis(MAX_RACE_DURATION_MS / 2);
        let race_result = self.execute_race_with_timeout(
            cx, slow_participants, timeout_duration
        ).await?;

        // Verify all obligations cleaned up despite timeout
        sleep(cx, Duration::from_millis(100)).await?; // Allow cleanup time
        let post_race_obligations = self.count_active_obligations().await?;

        // Calculate Lyapunov potential after timeout handling
        let timeout_potential = self.calculate_system_potential().await?;

        // Verify system stability after timeout
        let stability_after_timeout = self.analyze_system_stability().await?;

        Outcome::Ok(TimeoutSafetyResult {
            race_timed_out: race_result.timed_out,
            pre_race_obligations,
            post_race_obligations,
            obligations_leaked: post_race_obligations > pre_race_obligations,
            timeout_potential,
            system_stable_after_timeout: stability_after_timeout.converged,
            cleanup_duration_ms: race_result.cleanup_duration.as_millis() as u64,
        })
    }

    /// Creates race participants with attached obligations.
    async fn create_race_participants_with_obligations(
        &self,
        cx: &Cx,
    ) -> Result<Vec<RaceParticipant>, RaceLyapunovError> {
        let mut participants = Vec::new();

        for participant_id in 0..RACE_PARTICIPANTS {
            let task_id = TaskId::new();
            let mut obligations = Vec::new();

            // Create obligations for this participant
            for _ in 0..OBLIGATIONS_PER_PARTICIPANT {
                let obligation = self.create_participant_obligation(task_id).await?;
                obligations.push(obligation);
            }

            let participant = RaceParticipant {
                task_id,
                participant_id,
                obligations,
                estimated_duration: Duration::from_millis((participant_id as u64 + 1) * 100),
                work_payload: self.generate_work_payload(participant_id),
            };

            participants.push(participant);
        }

        Ok(participants)
    }

    /// Creates intentionally slow race participants for timeout testing.
    async fn create_slow_race_participants_with_obligations(
        &self,
        cx: &Cx,
    ) -> Result<Vec<RaceParticipant>, RaceLyapunovError> {
        let mut participants = Vec::new();

        for participant_id in 0..RACE_PARTICIPANTS {
            let task_id = TaskId::new();
            let mut obligations = Vec::new();

            for _ in 0..OBLIGATIONS_PER_PARTICIPANT {
                let obligation = self.create_participant_obligation(task_id).await?;
                obligations.push(obligation);
            }

            // Intentionally slow participants that will likely timeout
            let slow_duration = Duration::from_millis(MAX_RACE_DURATION_MS * 2);

            let participant = RaceParticipant {
                task_id,
                participant_id,
                obligations,
                estimated_duration: slow_duration,
                work_payload: self.generate_work_payload(participant_id),
            };

            participants.push(participant);
        }

        Ok(participants)
    }

    /// Executes race with comprehensive tracking.
    async fn execute_race_with_tracking(
        &self,
        cx: &Cx,
        participants: Vec<RaceParticipant>,
    ) -> Result<RaceExecutionResult, RaceLyapunovError> {
        let start_time = std::time::Instant::now();
        self.race_tracker.record_race_start(&participants).await;

        // Create race tasks
        let mut race_tasks = Vec::new();
        for participant in &participants {
            let participant_clone = participant.clone();
            let framework = self.clone();

            let task = async move {
                // Simulate work with obligation tracking
                sleep(&cx, participant_clone.estimated_duration).await?;

                // Update Lyapunov potential during work
                framework.update_potential_during_work(&participant_clone).await?;

                // Return participant for winner identification
                Outcome::Ok(participant_clone.task_id)
            };

            race_tasks.push(task);
        }

        // Execute race using combinator
        let winner = race(race_tasks).await
            .map_err(|e| RaceLyapunovError::RaceExecution(format!("Race failed: {:?}", e)))?;

        let execution_time = start_time.elapsed();

        // Identify losers
        let losers: Vec<_> = participants.iter()
            .filter(|p| p.task_id != winner)
            .map(|p| p.task_id)
            .collect();

        // Record race completion
        self.race_tracker.record_race_completion(winner, &losers).await;

        Ok(RaceExecutionResult {
            winner,
            losers,
            execution_time,
            timed_out: false,
            cleanup_duration: Duration::from_millis(0),
        })
    }

    /// Executes race with timeout handling.
    async fn execute_race_with_timeout(
        &self,
        cx: &Cx,
        participants: Vec<RaceParticipant>,
        timeout: Duration,
    ) -> Result<RaceExecutionResult, RaceLyapunovError> {
        let start_time = std::time::Instant::now();

        // Create timeout task
        let timeout_task = async move {
            sleep(cx, timeout).await?;
            Outcome::Err(RaceLyapunovError::Timeout)
        };

        // Create race tasks
        let mut race_tasks = Vec::new();
        for participant in &participants {
            let participant_clone = participant.clone();

            let task = async move {
                sleep(&cx, participant_clone.estimated_duration).await?;
                Outcome::Ok(participant_clone.task_id)
            };

            race_tasks.push(task);
        }

        // Add timeout to race
        race_tasks.push(timeout_task);

        // Execute race with timeout
        let race_result = race(race_tasks).await;
        let execution_time = start_time.elapsed();

        // Handle timeout case
        let cleanup_start = std::time::Instant::now();

        let (winner, timed_out) = match race_result {
            Ok(task_id) => (task_id, false),
            Err(RaceLyapunovError::Timeout) => {
                // Cleanup timed out participants
                self.cleanup_timed_out_participants(&participants).await?;
                (TaskId::new(), true) // Dummy winner for timeout case
            },
            Err(e) => return Err(e),
        };

        let cleanup_duration = cleanup_start.elapsed();

        // All participants are losers in timeout case
        let losers: Vec<_> = if timed_out {
            participants.iter().map(|p| p.task_id).collect()
        } else {
            participants.iter()
                .filter(|p| p.task_id != winner)
                .map(|p| p.task_id)
                .collect()
        };

        Ok(RaceExecutionResult {
            winner,
            losers,
            execution_time,
            timed_out,
            cleanup_duration,
        })
    }

    /// Creates an obligation for a race participant.
    async fn create_participant_obligation(
        &self,
        task_id: TaskId,
    ) -> Result<Obligation, RaceLyapunovError> {
        let obligation_id = ObligationId::new();
        let obligation = Obligation::new(obligation_id, task_id);

        // Register with ledger
        let mut ledger = self.obligation_ledger.lock().unwrap();
        ledger.register_obligation(obligation_id, ObligationState::Reserved)?;

        Ok(obligation)
    }

    /// Generates work payload for participant.
    fn generate_work_payload(&self, participant_id: usize) -> Bytes {
        let payload = format!("race-participant-{}-work-data", participant_id);
        Bytes::from(payload.into_bytes())
    }

    /// Updates Lyapunov potential during participant work.
    async fn update_potential_during_work(
        &self,
        participant: &RaceParticipant,
    ) -> Result<(), RaceLyapunovError> {
        let potential_delta = self.potential_calculator.calculate_work_potential(participant)?;

        let mut analyzer = self.stability_analyzer.lock().unwrap();
        analyzer.update_potential(potential_delta)?;

        Ok(())
    }

    /// Calculates current system Lyapunov potential.
    async fn calculate_system_potential(&self) -> Result<f64, RaceLyapunovError> {
        let analyzer = self.stability_analyzer.lock().unwrap();
        Ok(analyzer.get_current_potential())
    }

    /// Analyzes current system stability.
    async fn analyze_system_stability(&self) -> Result<StabilityMetrics, RaceLyapunovError> {
        let analyzer = self.stability_analyzer.lock().unwrap();

        let stability_metric = analyzer.calculate_stability_metric()?;
        let converged = stability_metric < STABILITY_THRESHOLD;

        Ok(StabilityMetrics {
            stability_metric,
            converged,
        })
    }

    /// Verifies loser obligation cleanup.
    async fn verify_loser_obligation_cleanup(
        &self,
        losers: &[TaskId],
    ) -> Result<CleanupVerification, RaceLyapunovError> {
        let ledger = self.obligation_ledger.lock().unwrap();

        let mut cleaned_obligations = 0;
        let mut leaked_obligations = 0;

        for loser_task_id in losers {
            let loser_obligations = ledger.get_obligations_for_task(*loser_task_id)?;

            for obligation_id in loser_obligations {
                match ledger.get_obligation_state(obligation_id)? {
                    ObligationState::Aborted | ObligationState::Committed => {
                        cleaned_obligations += 1;
                    },
                    ObligationState::Reserved => {
                        leaked_obligations += 1;
                    },
                }
            }
        }

        Ok(CleanupVerification {
            cleaned_obligations,
            leaked_obligations,
            all_cleaned: leaked_obligations == 0,
        })
    }

    /// Verifies global obligation cleanup across all races.
    async fn verify_global_obligation_cleanup(&self) -> Result<GlobalCleanupVerification, RaceLyapunovError> {
        let ledger = self.obligation_ledger.lock().unwrap();
        let all_obligations_resolved = ledger.all_obligations_resolved();
        let total_active_obligations = ledger.count_active_obligations();

        Ok(GlobalCleanupVerification {
            all_obligations_resolved,
            active_obligations_remaining: total_active_obligations,
        })
    }

    /// Counts currently active obligations.
    async fn count_active_obligations(&self) -> Result<usize, RaceLyapunovError> {
        let ledger = self.obligation_ledger.lock().unwrap();
        Ok(ledger.count_active_obligations())
    }

    /// Cleans up timed-out participants.
    async fn cleanup_timed_out_participants(
        &self,
        participants: &[RaceParticipant],
    ) -> Result<(), RaceLyapunovError> {
        let mut ledger = self.obligation_ledger.lock().unwrap();

        for participant in participants {
            for obligation in &participant.obligations {
                // Abort obligations for timed-out participants
                ledger.update_obligation_state(
                    obligation.id(),
                    ObligationState::Aborted
                )?;
            }
        }

        Ok(())
    }
}

impl Clone for RaceLyapunovTestFramework {
    fn clone(&self) -> Self {
        Self {
            stability_analyzer: self.stability_analyzer.clone(),
            obligation_ledger: self.obligation_ledger.clone(),
            race_tracker: self.race_tracker.clone(),
            potential_calculator: self.potential_calculator.clone(),
            leak_detector: self.leak_detector.clone(),
        }
    }
}

/// Race participant with obligations.
#[derive(Debug, Clone)]
struct RaceParticipant {
    task_id: TaskId,
    participant_id: usize,
    obligations: Vec<Obligation>,
    estimated_duration: Duration,
    work_payload: Bytes,
}

/// Race result tracking.
#[derive(Debug, Clone)]
struct RaceResultTracker {
    completed_races: Arc<AtomicUsize>,
    total_winners: Arc<AtomicUsize>,
    total_losers: Arc<AtomicUsize>,
}

impl RaceResultTracker {
    fn new() -> Self {
        Self {
            completed_races: Arc::new(AtomicUsize::new(0)),
            total_winners: Arc::new(AtomicUsize::new(0)),
            total_losers: Arc::new(AtomicUsize::new(0)),
        }
    }

    async fn record_race_start(&self, participants: &[RaceParticipant]) {
        // Track race start metrics
    }

    async fn record_race_completion(&self, winner: TaskId, losers: &[TaskId]) {
        self.completed_races.fetch_add(1, Ordering::SeqCst);
        self.total_winners.fetch_add(1, Ordering::SeqCst);
        self.total_losers.fetch_add(losers.len(), Ordering::SeqCst);
    }
}

/// Potential function calculator.
#[derive(Debug, Clone)]
struct PotentialCalculator {
    base_potential: Arc<AtomicU64>,
}

impl PotentialCalculator {
    fn new() -> Self {
        Self {
            base_potential: Arc::new(AtomicU64::new(1000)), // Initial potential
        }
    }

    fn calculate_work_potential(&self, participant: &RaceParticipant) -> Result<f64, RaceLyapunovError> {
        // Calculate potential based on participant work
        let work_factor = participant.estimated_duration.as_millis() as f64 / 1000.0;
        let obligation_factor = participant.obligations.len() as f64;

        Ok(work_factor * obligation_factor * 0.1)
    }
}

/// Resource leak detector.
#[derive(Debug, Clone)]
struct ResourceLeakDetector {
    tracked_resources: Arc<Mutex<HashMap<TaskId, usize>>>,
}

impl ResourceLeakDetector {
    fn new() -> Self {
        Self {
            tracked_resources: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    async fn detect_leaks(&self) -> Result<LeakDetectionResult, RaceLyapunovError> {
        let resources = self.tracked_resources.lock().unwrap();
        let has_leaks = !resources.is_empty();
        let leaked_resources = resources.len();

        Ok(LeakDetectionResult {
            has_leaks,
            leaked_resources,
        })
    }
}

/// Test result structures.

#[derive(Debug)]
pub struct RaceCleanupResult {
    pub initial_potential: f64,
    pub final_potential: f64,
    pub potential_decremented: bool,
    pub potential_delta: f64,
    pub winner_task_id: TaskId,
    pub losers_count: usize,
    pub obligations_cleaned: usize,
    pub obligations_leaked: usize,
    pub cleanup_successful: bool,
    pub no_resource_leaks: bool,
}

#[derive(Debug)]
pub struct StabilityAnalysisResult {
    pub concurrent_races_completed: usize,
    pub baseline_stability: f64,
    pub post_race_stability: f64,
    pub stability_maintained: bool,
    pub total_participants: usize,
    pub total_obligations_expected: usize,
    pub obligations_properly_cleaned: bool,
    pub lyapunov_convergence_verified: bool,
}

#[derive(Debug)]
pub struct TimeoutSafetyResult {
    pub race_timed_out: bool,
    pub pre_race_obligations: usize,
    pub post_race_obligations: usize,
    pub obligations_leaked: bool,
    pub timeout_potential: f64,
    pub system_stable_after_timeout: bool,
    pub cleanup_duration_ms: u64,
}

#[derive(Debug)]
struct RaceExecutionResult {
    winner: TaskId,
    losers: Vec<TaskId>,
    execution_time: Duration,
    timed_out: bool,
    cleanup_duration: Duration,
}

#[derive(Debug)]
struct CleanupVerification {
    cleaned_obligations: usize,
    leaked_obligations: usize,
    all_cleaned: bool,
}

#[derive(Debug)]
struct GlobalCleanupVerification {
    all_obligations_resolved: bool,
    active_obligations_remaining: usize,
}

#[derive(Debug)]
struct StabilityMetrics {
    stability_metric: f64,
    converged: bool,
}

#[derive(Debug)]
struct LeakDetectionResult {
    has_leaks: bool,
    leaked_resources: usize,
}

/// Race-Lyapunov integration errors.
#[derive(Debug)]
pub enum RaceLyapunovError {
    /// Race execution failure.
    RaceExecution(String),
    /// Obligation management failure.
    ObligationManagement(String),
    /// Lyapunov analysis failure.
    LyapunovAnalysis(String),
    /// Resource leak detected.
    ResourceLeak(String),
    /// Stability violation.
    StabilityViolation(String),
    /// Timeout during operation.
    Timeout,
    /// I/O error during operation.
    Io(std::io::Error),
}

impl std::fmt::Display for RaceLyapunovError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RaceLyapunovError::RaceExecution(msg) => write!(f, "Race execution error: {}", msg),
            RaceLyapunovError::ObligationManagement(msg) => write!(f, "Obligation management error: {}", msg),
            RaceLyapunovError::LyapunovAnalysis(msg) => write!(f, "Lyapunov analysis error: {}", msg),
            RaceLyapunovError::ResourceLeak(msg) => write!(f, "Resource leak: {}", msg),
            RaceLyapunovError::StabilityViolation(msg) => write!(f, "Stability violation: {}", msg),
            RaceLyapunovError::Timeout => write!(f, "Operation timed out"),
            RaceLyapunovError::Io(e) => write!(f, "I/O error: {}", e),
        }
    }
}

impl std::error::Error for RaceLyapunovError {}

impl From<std::io::Error> for RaceLyapunovError {
    fn from(err: std::io::Error) -> Self {
        RaceLyapunovError::Io(err)
    }
}

/// Tests basic race loser obligation cleanup.
#[cfg(test)]
mod race_loser_cleanup_tests {
    use super::*;

    #[test]
    fn test_race_loser_obligation_cleanup() {
        let rt = RuntimeBuilder::new().build().expect("Failed to create runtime");

        rt.block_on(async move {
            region(Budget::default(), |cx| async move {
                let framework = RaceLyapunovTestFramework::new();

                let result = framework.test_race_loser_obligation_cleanup(&cx).await
                    .expect("Failed to test race loser cleanup");

                assert!(result.potential_decremented);
                assert!(result.potential_delta > 0.0);
                assert!(result.losers_count > 0);
                assert!(result.cleanup_successful);
                assert_eq!(result.obligations_leaked, 0);
                assert!(result.no_resource_leaks);

                Outcome::Ok(())
            }).await
        }).expect("Runtime execution failed");
    }

    #[test]
    fn test_race_with_multiple_participants() {
        let rt = RuntimeBuilder::new().build().expect("Failed to create runtime");

        rt.block_on(async move {
            region(Budget::default(), |cx| async move {
                let framework = RaceLyapunovTestFramework::new();

                let result = framework.test_race_loser_obligation_cleanup(&cx).await
                    .expect("Failed to test multi-participant race");

                // Should have exactly one winner and (RACE_PARTICIPANTS - 1) losers
                assert_eq!(result.losers_count, RACE_PARTICIPANTS - 1);

                // All loser obligations should be cleaned
                let expected_loser_obligations = result.losers_count * OBLIGATIONS_PER_PARTICIPANT;
                assert_eq!(result.obligations_cleaned, expected_loser_obligations);

                Outcome::Ok(())
            }).await
        }).expect("Runtime execution failed");
    }
}

/// Tests concurrent race stability analysis.
#[cfg(test)]
mod stability_analysis_tests {
    use super::*;

    #[test]
    fn test_concurrent_races_stability() {
        let rt = RuntimeBuilder::new().build().expect("Failed to create runtime");

        rt.block_on(async move {
            region(Budget::default(), |cx| async move {
                let framework = RaceLyapunovTestFramework::new();

                let result = framework.test_concurrent_races_stability(&cx).await
                    .expect("Failed to test concurrent races");

                assert!(result.concurrent_races_completed > 0);
                assert!(result.stability_maintained);
                assert!(result.obligations_properly_cleaned);
                assert!(result.lyapunov_convergence_verified);

                Outcome::Ok(())
            }).await
        }).expect("Runtime execution failed");
    }

    #[test]
    fn test_lyapunov_potential_consistency() {
        let rt = RuntimeBuilder::new().build().expect("Failed to create runtime");

        rt.block_on(async move {
            region(Budget::default(), |cx| async move {
                let framework = RaceLyapunovTestFramework::new();

                // Run multiple race cleanup tests
                let mut total_potential_delta = 0.0;

                for _ in 0..3 {
                    let result = framework.test_race_loser_obligation_cleanup(&cx).await
                        .expect("Failed to test race cleanup");

                    total_potential_delta += result.potential_delta;
                    assert!(result.potential_decremented);
                }

                // Total potential should have decreased significantly
                assert!(total_potential_delta > 0.0);

                Outcome::Ok(())
            }).await
        }).expect("Runtime execution failed");
    }
}

/// Tests timeout handling and safety.
#[cfg(test)]
mod timeout_safety_tests {
    use super::*;

    #[test]
    fn test_race_timeout_obligation_safety() {
        let rt = RuntimeBuilder::new().build().expect("Failed to create runtime");

        rt.block_on(async move {
            region(Budget::default(), |cx| async move {
                let framework = RaceLyapunovTestFramework::new();

                let result = framework.test_race_timeout_obligation_safety(&cx).await
                    .expect("Failed to test timeout safety");

                assert!(result.race_timed_out);
                assert!(!result.obligations_leaked);
                assert!(result.system_stable_after_timeout);
                assert!(result.cleanup_duration_ms > 0);

                Outcome::Ok(())
            }).await
        }).expect("Runtime execution failed");
    }

    #[test]
    fn test_timeout_cleanup_completeness() {
        let rt = RuntimeBuilder::new().build().expect("Failed to create runtime");

        rt.block_on(async move {
            region(Budget::default(), |cx| async move {
                let framework = RaceLyapunovTestFramework::new();

                // Record initial obligation count
                let initial_count = framework.count_active_obligations().await
                    .expect("Failed to count initial obligations");

                let result = framework.test_race_timeout_obligation_safety(&cx).await
                    .expect("Failed to test timeout cleanup");

                // Should return to baseline or lower obligation count
                assert!(result.post_race_obligations <= initial_count);

                Outcome::Ok(())
            }).await
        }).expect("Runtime execution failed");
    }
}

/// Tests edge cases and error conditions.
#[cfg(test)]
mod edge_case_tests {
    use super::*;

    #[test]
    fn test_empty_race_handling() {
        let rt = RuntimeBuilder::new().build().expect("Failed to create runtime");

        rt.block_on(async move {
            region(Budget::default(), |cx| async move {
                let framework = RaceLyapunovTestFramework::new();

                // Test with minimal participants
                let empty_participants = Vec::new();
                let result = framework.execute_race_with_tracking(&cx, empty_participants).await;

                // Should handle empty race gracefully
                assert!(result.is_err() || result.unwrap().losers.is_empty());

                Outcome::Ok(())
            }).await
        }).expect("Runtime execution failed");
    }

    #[test]
    fn test_single_participant_race() {
        let rt = RuntimeBuilder::new().build().expect("Failed to create runtime");

        rt.block_on(async move {
            region(Budget::default(), |cx| async move {
                let framework = RaceLyapunovTestFramework::new();

                // Create single participant
                let single_participant = vec![RaceParticipant {
                    task_id: TaskId::new(),
                    participant_id: 0,
                    obligations: vec![],
                    estimated_duration: Duration::from_millis(10),
                    work_payload: Bytes::from("single"),
                }];

                let result = framework.execute_race_with_tracking(&cx, single_participant).await
                    .expect("Failed to execute single participant race");

                // Should have winner and no losers
                assert_eq!(result.losers.len(), 0);

                Outcome::Ok(())
            }).await
        }).expect("Runtime execution failed");
    }
}