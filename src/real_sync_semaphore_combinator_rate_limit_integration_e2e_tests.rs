//! Real sync/semaphore ↔ combinator/rate_limit integration e2e tests
//!
//! Tests the integration between semaphore-based resource limiting and rate limiting
//! combinators, verifying that semaphore permits properly coordinate with rate limit
//! enforcement for effective backpressure control, resource protection, and throughput
//! regulation in high-concurrency scenarios.
//!
//! Test scenarios:
//! - Semaphore permit acquisition with rate limit enforcement
//! - Backpressure coordination between semaphores and rate limiters
//! - Resource exhaustion handling with combined limiting strategies
//! - Throughput regulation with multi-layer resource protection

use crate::{
    combinator::rate_limit::{
        BackpressureStrategy, RateLimit, RateLimitConfig, RateLimitError, RateLimitResult,
        RateLimitStrategy, SlidingWindow, ThrottleConfig, TokenBucket,
    },
    cx::{Cx, Scope},
    error::Error,
    sync::{
        PermitAcquisition, ResourcePool, Semaphore, SemaphoreConfig, SemaphorePermit,
        SemaphoreStats, WaitingStrategy,
    },
    time::{Duration, Instant, Sleep},
    types::{Budget, Outcome, TaskId},
};
use std::{
    collections::{HashMap, VecDeque},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
};

/// Controllable semaphore system integrated with rate limiting combinators
/// for testing resource management and backpressure coordination
struct RateLimitedSemaphoreSystem {
    resource_semaphore: Semaphore,
    rate_limiter: RateLimit,
    coordination_config: Arc<RwLock<CoordinationConfig>>,
    permit_rate_correlation: Arc<Mutex<HashMap<String, PermitRateCorrelation>>>,
    backpressure_tracker: Arc<Mutex<BackpressureTracker>>,
    integration_stats: Arc<Mutex<SemaphoreRateLimitStats>>,
}

#[derive(Clone)]
struct CoordinationConfig {
    enforce_rate_before_semaphore: bool,
    enforce_semaphore_before_rate: bool,
    combined_backpressure_enabled: bool,
    permit_timeout_ms: u64,
    rate_limit_timeout_ms: u64,
    max_waiting_tasks: usize,
    adaptive_strategy_enabled: bool,
}

#[derive(Debug)]
struct PermitRateCorrelation {
    correlation_id: String,
    semaphore_permit: Option<SemaphorePermit>,
    rate_limit_token: Option<RateLimitToken>,
    acquisition_strategy: AcquisitionStrategy,
    started_at: Instant,
    semaphore_acquired_at: Option<Instant>,
    rate_limit_acquired_at: Option<Instant>,
    completed_at: Option<Instant>,
    final_status: CorrelationStatus,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum AcquisitionStrategy {
    SemaphoreFirst,
    RateLimitFirst,
    Concurrent,
    Adaptive,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum CorrelationStatus {
    Pending,
    SemaphoreAcquired,
    RateLimitAcquired,
    BothAcquired,
    Failed,
    TimedOut,
    Cancelled,
}

#[derive(Debug, Clone)]
struct RateLimitToken {
    token_id: String,
    bucket_id: String,
    tokens_consumed: u32,
    acquired_at: Instant,
    valid_until: Instant,
}

#[derive(Debug)]
struct BackpressureTracker {
    semaphore_denials: AtomicU64,
    rate_limit_denials: AtomicU64,
    combined_denials: AtomicU64,
    backpressure_events: AtomicU64,
    adaptive_strategy_changes: AtomicU64,
    waiting_task_count: AtomicUsize,
    max_waiting_tasks_reached: AtomicU64,
    successful_coordinations: AtomicU64,
}

#[derive(Debug)]
struct SemaphoreRateLimitStats {
    total_acquisition_attempts: AtomicU64,
    successful_acquisitions: AtomicU64,
    failed_acquisitions: AtomicU64,
    timeout_acquisitions: AtomicU64,
    semaphore_contention_time_ms: AtomicU64,
    rate_limit_wait_time_ms: AtomicU64,
    average_coordination_time_ms: AtomicU64,
    peak_concurrent_requests: AtomicUsize,
    throughput_requests_per_second: AtomicU64,
}

impl RateLimitedSemaphoreSystem {
    pub async fn new(
        semaphore_config: SemaphoreConfig,
        rate_limit_config: RateLimitConfig,
        coordination_config: CoordinationConfig,
    ) -> Result<Self, Error> {
        let resource_semaphore = Semaphore::new(semaphore_config).await?;
        let rate_limiter = RateLimit::new(rate_limit_config).await?;

        Ok(Self {
            resource_semaphore,
            rate_limiter,
            coordination_config: Arc::new(RwLock::new(coordination_config)),
            permit_rate_correlation: Arc::new(Mutex::new(HashMap::new())),
            backpressure_tracker: Arc::new(Mutex::new(BackpressureTracker {
                semaphore_denials: AtomicU64::new(0),
                rate_limit_denials: AtomicU64::new(0),
                combined_denials: AtomicU64::new(0),
                backpressure_events: AtomicU64::new(0),
                adaptive_strategy_changes: AtomicU64::new(0),
                waiting_task_count: AtomicUsize::new(0),
                max_waiting_tasks_reached: AtomicU64::new(0),
                successful_coordinations: AtomicU64::new(0),
            })),
            integration_stats: Arc::new(Mutex::new(SemaphoreRateLimitStats {
                total_acquisition_attempts: AtomicU64::new(0),
                successful_acquisitions: AtomicU64::new(0),
                failed_acquisitions: AtomicU64::new(0),
                timeout_acquisitions: AtomicU64::new(0),
                semaphore_contention_time_ms: AtomicU64::new(0),
                rate_limit_wait_time_ms: AtomicU64::new(0),
                average_coordination_time_ms: AtomicU64::new(0),
                peak_concurrent_requests: AtomicUsize::new(0),
                throughput_requests_per_second: AtomicU64::new(0),
            })),
        })
    }

    /// Acquire both semaphore permit and rate limit token with coordination
    pub async fn acquire_coordinated_access(
        &self,
        cx: &Cx,
        request_id: String,
        tokens_required: u32,
        timeout: Duration,
    ) -> Outcome<CoordinatedAccess, Error> {
        let correlation_id = format!("coord_{}", request_id);
        let start_time = Instant::now();

        let config = self.coordination_config.read().unwrap().clone();
        let strategy = self.determine_acquisition_strategy(&config).await;

        let correlation = PermitRateCorrelation {
            correlation_id: correlation_id.clone(),
            semaphore_permit: None,
            rate_limit_token: None,
            acquisition_strategy: strategy,
            started_at: start_time,
            semaphore_acquired_at: None,
            rate_limit_acquired_at: None,
            completed_at: None,
            final_status: CorrelationStatus::Pending,
        };

        // Track correlation
        {
            let mut correlations = self.permit_rate_correlation.lock().unwrap();
            correlations.insert(correlation_id.clone(), correlation);
        }

        self.increment_stat("total_acquisition_attempts", 1);

        // Track waiting task count for backpressure monitoring
        {
            let tracker = self.backpressure_tracker.lock().unwrap();
            let current_waiting = tracker.waiting_task_count.fetch_add(1, Ordering::SeqCst);

            if current_waiting >= config.max_waiting_tasks {
                tracker
                    .max_waiting_tasks_reached
                    .fetch_add(1, Ordering::SeqCst);
                self.decrement_waiting_count();
                return Outcome::Err(Error::internal("Maximum waiting tasks limit reached"));
            }
        }

        let result = match strategy {
            AcquisitionStrategy::SemaphoreFirst => {
                self.acquire_semaphore_then_rate_limit(
                    cx,
                    &correlation_id,
                    tokens_required,
                    timeout,
                )
                .await
            }
            AcquisitionStrategy::RateLimitFirst => {
                self.acquire_rate_limit_then_semaphore(
                    cx,
                    &correlation_id,
                    tokens_required,
                    timeout,
                )
                .await
            }
            AcquisitionStrategy::Concurrent => {
                self.acquire_concurrent(cx, &correlation_id, tokens_required, timeout)
                    .await
            }
            AcquisitionStrategy::Adaptive => {
                self.acquire_adaptive(cx, &correlation_id, tokens_required, timeout)
                    .await
            }
        };

        self.decrement_waiting_count();

        let execution_time_ms = start_time.elapsed().as_millis() as u64;

        // Update correlation with final result
        {
            let mut correlations = self.permit_rate_correlation.lock().unwrap();
            if let Some(correlation) = correlations.get_mut(&correlation_id) {
                correlation.completed_at = Some(Instant::now());
                correlation.final_status = match &result {
                    Ok(_) => {
                        self.increment_stat("successful_acquisitions", 1);
                        let tracker = self.backpressure_tracker.lock().unwrap();
                        tracker
                            .successful_coordinations
                            .fetch_add(1, Ordering::SeqCst);
                        CorrelationStatus::BothAcquired
                    }
                    Err(_) => {
                        self.increment_stat("failed_acquisitions", 1);
                        CorrelationStatus::Failed
                    }
                };
            }
        }

        self.update_average_coordination_time(execution_time_ms);

        result
    }

    async fn acquire_semaphore_then_rate_limit(
        &self,
        cx: &Cx,
        correlation_id: &str,
        tokens_required: u32,
        timeout: Duration,
    ) -> Result<CoordinatedAccess, Error> {
        let start_time = Instant::now();

        // Phase 1: Acquire semaphore permit
        let semaphore_permit = match self
            .resource_semaphore
            .acquire_timeout(cx, timeout / 2)
            .await
        {
            Outcome::Ok(permit) => {
                self.update_correlation_semaphore_acquired(correlation_id, permit.clone());
                permit
            }
            Outcome::Err(e) => {
                let tracker = self.backpressure_tracker.lock().unwrap();
                tracker.semaphore_denials.fetch_add(1, Ordering::SeqCst);
                return Err(Error::internal(format!("Semaphore acquisition failed: {}", e)));
            }
            Outcome::Cancelled => {
                return Err(Error::internal("Semaphore acquisition cancelled"));
            }
        };

        let semaphore_time = start_time.elapsed();
        self.add_semaphore_contention_time(semaphore_time.as_millis() as u64);

        // Phase 2: Acquire rate limit token
        let remaining_timeout = timeout.saturating_sub(semaphore_time);
        let rate_limit_token = match self
            .rate_limiter
            .acquire_tokens(cx, tokens_required, remaining_timeout)
            .await
        {
            Ok(token) => {
                self.update_correlation_rate_limit_acquired(correlation_id, token.clone());
                token
            }
            Err(e) => {
                // Release semaphore permit on rate limit failure
                drop(semaphore_permit);
                let tracker = self.backpressure_tracker.lock().unwrap();
                tracker.rate_limit_denials.fetch_add(1, Ordering::SeqCst);
                tracker.combined_denials.fetch_add(1, Ordering::SeqCst);
                return Err(Error::internal(format!("Rate limit acquisition failed: {}", e)));
            }
        };

        let rate_limit_time = start_time.elapsed() - semaphore_time;
        self.add_rate_limit_wait_time(rate_limit_time.as_millis() as u64);

        Ok(CoordinatedAccess {
            correlation_id: correlation_id.to_string(),
            semaphore_permit,
            rate_limit_token,
            acquisition_strategy: AcquisitionStrategy::SemaphoreFirst,
            total_acquisition_time: start_time.elapsed(),
        })
    }

    async fn acquire_rate_limit_then_semaphore(
        &self,
        cx: &Cx,
        correlation_id: &str,
        tokens_required: u32,
        timeout: Duration,
    ) -> Result<CoordinatedAccess, Error> {
        let start_time = Instant::now();

        // Phase 1: Acquire rate limit token
        let rate_limit_token = match self
            .rate_limiter
            .acquire_tokens(cx, tokens_required, timeout / 2)
            .await
        {
            Ok(token) => {
                self.update_correlation_rate_limit_acquired(correlation_id, token.clone());
                token
            }
            Err(e) => {
                let tracker = self.backpressure_tracker.lock().unwrap();
                tracker.rate_limit_denials.fetch_add(1, Ordering::SeqCst);
                return Err(Error::internal(format!("Rate limit acquisition failed: {}", e)));
            }
        };

        let rate_limit_time = start_time.elapsed();
        self.add_rate_limit_wait_time(rate_limit_time.as_millis() as u64);

        // Phase 2: Acquire semaphore permit
        let remaining_timeout = timeout.saturating_sub(rate_limit_time);
        let semaphore_permit = match self
            .resource_semaphore
            .acquire_timeout(cx, remaining_timeout)
            .await
        {
            Outcome::Ok(permit) => {
                self.update_correlation_semaphore_acquired(correlation_id, permit.clone());
                permit
            }
            Outcome::Err(e) => {
                // Release rate limit token on semaphore failure
                drop(rate_limit_token);
                let tracker = self.backpressure_tracker.lock().unwrap();
                tracker.semaphore_denials.fetch_add(1, Ordering::SeqCst);
                tracker.combined_denials.fetch_add(1, Ordering::SeqCst);
                return Err(Error::internal(format!("Semaphore acquisition failed: {}", e)));
            }
            Outcome::Cancelled => {
                drop(rate_limit_token);
                return Err(Error::internal("Semaphore acquisition cancelled"));
            }
        };

        let semaphore_time = start_time.elapsed() - rate_limit_time;
        self.add_semaphore_contention_time(semaphore_time.as_millis() as u64);

        Ok(CoordinatedAccess {
            correlation_id: correlation_id.to_string(),
            semaphore_permit,
            rate_limit_token,
            acquisition_strategy: AcquisitionStrategy::RateLimitFirst,
            total_acquisition_time: start_time.elapsed(),
        })
    }

    async fn acquire_concurrent(
        &self,
        cx: &Cx,
        correlation_id: &str,
        tokens_required: u32,
        timeout: Duration,
    ) -> Result<CoordinatedAccess, Error> {
        let start_time = Instant::now();

        // Launch both acquisitions concurrently
        let semaphore_future = self.resource_semaphore.acquire_timeout(cx, timeout);
        let rate_limit_future = self
            .rate_limiter
            .acquire_tokens(cx, tokens_required, timeout);

        // Wait for both to complete
        let (semaphore_result, rate_limit_result) =
            tokio::join!(semaphore_future, rate_limit_future);

        let semaphore_permit = match semaphore_result {
            Outcome::Ok(permit) => {
                self.update_correlation_semaphore_acquired(correlation_id, permit.clone());
                permit
            }
            Outcome::Err(e) => {
                let tracker = self.backpressure_tracker.lock().unwrap();
                tracker.semaphore_denials.fetch_add(1, Ordering::SeqCst);
                return Err(Error::internal(format!(
                    "Concurrent semaphore acquisition failed: {}",
                    e
                )));
            }
            Outcome::Cancelled => {
                return Err(Error::internal("Concurrent semaphore acquisition cancelled"));
            }
        };

        let rate_limit_token = match rate_limit_result {
            Ok(token) => {
                self.update_correlation_rate_limit_acquired(correlation_id, token.clone());
                token
            }
            Err(e) => {
                // Release semaphore permit on rate limit failure
                drop(semaphore_permit);
                let tracker = self.backpressure_tracker.lock().unwrap();
                tracker.rate_limit_denials.fetch_add(1, Ordering::SeqCst);
                tracker.combined_denials.fetch_add(1, Ordering::SeqCst);
                return Err(Error::internal(format!(
                    "Concurrent rate limit acquisition failed: {}",
                    e
                )));
            }
        };

        let total_time = start_time.elapsed();
        self.add_semaphore_contention_time(total_time.as_millis() as u64 / 2);
        self.add_rate_limit_wait_time(total_time.as_millis() as u64 / 2);

        Ok(CoordinatedAccess {
            correlation_id: correlation_id.to_string(),
            semaphore_permit,
            rate_limit_token,
            acquisition_strategy: AcquisitionStrategy::Concurrent,
            total_acquisition_time: total_time,
        })
    }

    async fn acquire_adaptive(
        &self,
        cx: &Cx,
        correlation_id: &str,
        tokens_required: u32,
        timeout: Duration,
    ) -> Result<CoordinatedAccess, Error> {
        // Adaptive strategy: choose based on current system state
        let strategy = self.choose_adaptive_strategy().await;

        let tracker = self.backpressure_tracker.lock().unwrap();
        tracker
            .adaptive_strategy_changes
            .fetch_add(1, Ordering::SeqCst);

        match strategy {
            AcquisitionStrategy::SemaphoreFirst => {
                self.acquire_semaphore_then_rate_limit(cx, correlation_id, tokens_required, timeout)
                    .await
            }
            AcquisitionStrategy::RateLimitFirst => {
                self.acquire_rate_limit_then_semaphore(cx, correlation_id, tokens_required, timeout)
                    .await
            }
            AcquisitionStrategy::Concurrent => {
                self.acquire_concurrent(cx, correlation_id, tokens_required, timeout)
                    .await
            }
            AcquisitionStrategy::Adaptive => {
                // Fallback to concurrent if adaptive recursion
                self.acquire_concurrent(cx, correlation_id, tokens_required, timeout)
                    .await
            }
        }
    }

    async fn determine_acquisition_strategy(
        &self,
        config: &CoordinationConfig,
    ) -> AcquisitionStrategy {
        if config.adaptive_strategy_enabled {
            AcquisitionStrategy::Adaptive
        } else if config.enforce_semaphore_before_rate {
            AcquisitionStrategy::SemaphoreFirst
        } else if config.enforce_rate_before_semaphore {
            AcquisitionStrategy::RateLimitFirst
        } else {
            AcquisitionStrategy::Concurrent
        }
    }

    async fn choose_adaptive_strategy(&self) -> AcquisitionStrategy {
        // Simple adaptive logic based on current backpressure conditions
        let tracker = self.backpressure_tracker.lock().unwrap();
        let semaphore_denials = tracker.semaphore_denials.load(Ordering::SeqCst);
        let rate_limit_denials = tracker.rate_limit_denials.load(Ordering::SeqCst);
        let waiting_tasks = tracker.waiting_task_count.load(Ordering::SeqCst);

        // Choose strategy based on historical denial patterns
        if semaphore_denials > rate_limit_denials * 2 {
            // Semaphore is more contentious, try rate limit first
            AcquisitionStrategy::RateLimitFirst
        } else if rate_limit_denials > semaphore_denials * 2 {
            // Rate limit is more restrictive, try semaphore first
            AcquisitionStrategy::SemaphoreFirst
        } else if waiting_tasks > 10 {
            // High contention, use concurrent acquisition for speed
            AcquisitionStrategy::Concurrent
        } else {
            // Balanced contention, use concurrent by default
            AcquisitionStrategy::Concurrent
        }
    }

    fn update_correlation_semaphore_acquired(&self, correlation_id: &str, permit: SemaphorePermit) {
        let mut correlations = self.permit_rate_correlation.lock().unwrap();
        if let Some(correlation) = correlations.get_mut(correlation_id) {
            correlation.semaphore_permit = Some(permit);
            correlation.semaphore_acquired_at = Some(Instant::now());
            correlation.final_status = CorrelationStatus::SemaphoreAcquired;
        }
    }

    fn update_correlation_rate_limit_acquired(&self, correlation_id: &str, token: RateLimitToken) {
        let mut correlations = self.permit_rate_correlation.lock().unwrap();
        if let Some(correlation) = correlations.get_mut(correlation_id) {
            correlation.rate_limit_token = Some(token);
            correlation.rate_limit_acquired_at = Some(Instant::now());

            if correlation.semaphore_permit.is_some() {
                correlation.final_status = CorrelationStatus::BothAcquired;
            } else {
                correlation.final_status = CorrelationStatus::RateLimitAcquired;
            }
        }
    }

    fn decrement_waiting_count(&self) {
        let tracker = self.backpressure_tracker.lock().unwrap();
        tracker.waiting_task_count.fetch_sub(1, Ordering::SeqCst);
    }

    fn increment_stat(&self, stat_name: &str, count: u64) {
        let stats = self.integration_stats.lock().unwrap();
        match stat_name {
            "total_acquisition_attempts" => stats
                .total_acquisition_attempts
                .fetch_add(count, Ordering::SeqCst),
            "successful_acquisitions" => stats
                .successful_acquisitions
                .fetch_add(count, Ordering::SeqCst),
            "failed_acquisitions" => stats.failed_acquisitions.fetch_add(count, Ordering::SeqCst),
            "timeout_acquisitions" => stats
                .timeout_acquisitions
                .fetch_add(count, Ordering::SeqCst),
            _ => 0,
        };
    }

    fn add_semaphore_contention_time(&self, time_ms: u64) {
        let stats = self.integration_stats.lock().unwrap();
        stats
            .semaphore_contention_time_ms
            .fetch_add(time_ms, Ordering::SeqCst);
    }

    fn add_rate_limit_wait_time(&self, time_ms: u64) {
        let stats = self.integration_stats.lock().unwrap();
        stats
            .rate_limit_wait_time_ms
            .fetch_add(time_ms, Ordering::SeqCst);
    }

    fn update_average_coordination_time(&self, time_ms: u64) {
        let stats = self.integration_stats.lock().unwrap();
        stats
            .average_coordination_time_ms
            .store(time_ms, Ordering::SeqCst);
    }

    /// Get comprehensive coordination statistics
    pub fn get_coordination_stats(&self) -> SemaphoreRateLimitCoordinationStats {
        let integration = self.integration_stats.lock().unwrap();
        let tracker = self.backpressure_tracker.lock().unwrap();

        SemaphoreRateLimitCoordinationStats {
            total_acquisition_attempts: integration
                .total_acquisition_attempts
                .load(Ordering::SeqCst),
            successful_acquisitions: integration.successful_acquisitions.load(Ordering::SeqCst),
            failed_acquisitions: integration.failed_acquisitions.load(Ordering::SeqCst),
            timeout_acquisitions: integration.timeout_acquisitions.load(Ordering::SeqCst),
            semaphore_contention_time_ms: integration
                .semaphore_contention_time_ms
                .load(Ordering::SeqCst),
            rate_limit_wait_time_ms: integration.rate_limit_wait_time_ms.load(Ordering::SeqCst),
            average_coordination_time_ms: integration
                .average_coordination_time_ms
                .load(Ordering::SeqCst),
            semaphore_denials: tracker.semaphore_denials.load(Ordering::SeqCst),
            rate_limit_denials: tracker.rate_limit_denials.load(Ordering::SeqCst),
            combined_denials: tracker.combined_denials.load(Ordering::SeqCst),
            backpressure_events: tracker.backpressure_events.load(Ordering::SeqCst),
            successful_coordinations: tracker.successful_coordinations.load(Ordering::SeqCst),
            adaptive_strategy_changes: tracker.adaptive_strategy_changes.load(Ordering::SeqCst),
            max_waiting_tasks_reached: tracker.max_waiting_tasks_reached.load(Ordering::SeqCst),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CoordinatedAccess {
    pub correlation_id: String,
    pub semaphore_permit: SemaphorePermit,
    pub rate_limit_token: RateLimitToken,
    pub acquisition_strategy: AcquisitionStrategy,
    pub total_acquisition_time: Duration,
}

impl Drop for CoordinatedAccess {
    fn drop(&mut self) {
        // Both permit and token will be automatically released when dropped
    }
}

#[derive(Debug, Clone)]
pub struct SemaphoreRateLimitCoordinationStats {
    pub total_acquisition_attempts: u64,
    pub successful_acquisitions: u64,
    pub failed_acquisitions: u64,
    pub timeout_acquisitions: u64,
    pub semaphore_contention_time_ms: u64,
    pub rate_limit_wait_time_ms: u64,
    pub average_coordination_time_ms: u64,
    pub semaphore_denials: u64,
    pub rate_limit_denials: u64,
    pub combined_denials: u64,
    pub backpressure_events: u64,
    pub successful_coordinations: u64,
    pub adaptive_strategy_changes: u64,
    pub max_waiting_tasks_reached: u64,
}

#[cfg(all(test, feature = "real-service-e2e"))]
mod tests {
    use super::*;
    use crate::cx::region;

    #[tokio::test]
    async fn test_basic_semaphore_rate_limit_coordination() {
        let budget = Budget::new(Duration::from_secs(30), Duration::from_secs(5));

        region(budget, |cx, scope| async move {
            // Set up semaphore and rate limiter integration
            let semaphore_config = SemaphoreConfig {
                max_permits: 5,
                initial_permits: 5,
                fair_scheduling: true,
                ..Default::default()
            };

            let rate_limit_config = RateLimitConfig {
                strategy: RateLimitStrategy::TokenBucket {
                    capacity: 10,
                    refill_rate: 2.0, // 2 tokens per second
                    initial_tokens: 10,
                },
                burst_allowance: 5,
                backpressure_strategy: BackpressureStrategy::Block,
                ..Default::default()
            };

            let coordination_config = CoordinationConfig {
                enforce_rate_before_semaphore: false,
                enforce_semaphore_before_rate: true, // Semaphore first
                combined_backpressure_enabled: true,
                permit_timeout_ms: 5000,
                rate_limit_timeout_ms: 5000,
                max_waiting_tasks: 20,
                adaptive_strategy_enabled: false,
            };

            let coordination_system = RateLimitedSemaphoreSystem::new(
                semaphore_config,
                rate_limit_config,
                coordination_config,
            )
            .await
            .expect("Failed to create coordination system");

            // Test basic coordinated acquisition
            let request_id = "basic_test_001".to_string();
            let tokens_required = 3;
            let timeout = Duration::from_secs(10);

            let coordinated_access = coordination_system
                .acquire_coordinated_access(cx, request_id, tokens_required, timeout)
                .await
                .expect("Coordinated acquisition should succeed");

            assert_eq!(
                coordinated_access.acquisition_strategy,
                AcquisitionStrategy::SemaphoreFirst
            );
            assert!(coordinated_access.total_acquisition_time < Duration::from_secs(1));

            // Access should work with both permit and token
            assert!(!coordinated_access.correlation_id.is_empty());

            // Release access (automatic on drop)
            drop(coordinated_access);

            // Verify statistics
            let stats = coordination_system.get_coordination_stats();
            assert_eq!(stats.total_acquisition_attempts, 1);
            assert_eq!(stats.successful_acquisitions, 1);
            assert_eq!(stats.failed_acquisitions, 0);

            Outcome::Ok(())
        })
        .await
        .expect("Region should complete successfully");
    }

    #[tokio::test]
    async fn test_concurrent_acquisition_backpressure() {
        let budget = Budget::new(Duration::from_secs(45), Duration::from_secs(10));

        region(budget, |cx, scope| async move {
            // Set up system with limited resources to test backpressure
            let semaphore_config = SemaphoreConfig {
                max_permits: 3, // Very limited permits
                initial_permits: 3,
                fair_scheduling: true,
                ..Default::default()
            };

            let rate_limit_config = RateLimitConfig {
                strategy: RateLimitStrategy::SlidingWindow {
                    window_size: Duration::from_secs(2),
                    max_requests: 5, // Limited rate
                },
                burst_allowance: 2,
                backpressure_strategy: BackpressureStrategy::Block,
                ..Default::default()
            };

            let coordination_config = CoordinationConfig {
                enforce_rate_before_semaphore: false,
                enforce_semaphore_before_rate: false,
                combined_backpressure_enabled: true,
                permit_timeout_ms: 3000,
                rate_limit_timeout_ms: 3000,
                max_waiting_tasks: 10,
                adaptive_strategy_enabled: false,
            };

            let coordination_system = RateLimitedSemaphoreSystem::new(
                semaphore_config,
                rate_limit_config,
                coordination_config,
            )
            .await
            .expect("Failed to create coordination system");

            // Launch multiple concurrent acquisition attempts
            let mut acquisition_tasks = Vec::new();
            let attempt_count = 8; // More than semaphore permits and rate limit

            for i in 0..attempt_count {
                let system_ref = &coordination_system;
                let request_id = format!("concurrent_test_{}", i);

                let task = scope.spawn(&format!("acquire_{}", i), async move {
                    system_ref
                        .acquire_coordinated_access(
                            cx,
                            request_id,
                            1, // Single token per request
                            Duration::from_secs(5),
                        )
                        .await
                })?;

                acquisition_tasks.push(task);

                // Small stagger to create realistic timing
                if i % 2 == 0 {
                    Sleep::new(Duration::from_millis(10)).await;
                }
            }

            // Collect results
            let mut successful_acquisitions = 0;
            let mut failed_acquisitions = 0;
            let mut coordinated_accesses = Vec::new();

            for (i, task) in acquisition_tasks.into_iter().enumerate() {
                match task.join(cx).await {
                    Ok(Ok(access)) => {
                        successful_acquisitions += 1;
                        coordinated_accesses.push(access);
                    }
                    Ok(Err(_)) => {
                        failed_acquisitions += 1;
                        println!("Acquisition {} failed due to backpressure", i);
                    }
                    Err(_) => {
                        failed_acquisitions += 1;
                        println!("Acquisition {} was cancelled", i);
                    }
                }
            }

            // Should have some successful acquisitions and some backpressure failures
            assert!(
                successful_acquisitions > 0,
                "Should have some successful acquisitions"
            );
            assert!(
                failed_acquisitions > 0,
                "Should have some backpressure failures"
            );

            // Release acquired accesses
            for access in coordinated_accesses {
                drop(access);
            }

            // Verify backpressure coordination statistics
            let stats = coordination_system.get_coordination_stats();
            assert_eq!(stats.total_acquisition_attempts, attempt_count as u64);
            assert_eq!(
                stats.successful_acquisitions,
                successful_acquisitions as u64
            );
            assert_eq!(stats.failed_acquisitions, failed_acquisitions as u64);

            // Should have experienced some form of denial due to limited resources
            assert!(stats.semaphore_denials > 0 || stats.rate_limit_denials > 0);

            println!("Concurrent backpressure test results:");
            println!("- Successful acquisitions: {}", successful_acquisitions);
            println!("- Failed acquisitions: {}", failed_acquisitions);
            println!("- Semaphore denials: {}", stats.semaphore_denials);
            println!("- Rate limit denials: {}", stats.rate_limit_denials);
            println!("- Combined denials: {}", stats.combined_denials);

            Outcome::Ok(())
        })
        .await
        .expect("Region should complete successfully");
    }

    #[tokio::test]
    async fn test_adaptive_strategy_coordination() {
        let budget = Budget::new(Duration::from_secs(45), Duration::from_secs(10));

        region(budget, |cx, scope| async move {
            // Set up system with adaptive strategy enabled
            let semaphore_config = SemaphoreConfig {
                max_permits: 4,
                initial_permits: 4,
                fair_scheduling: true,
                ..Default::default()
            };

            let rate_limit_config = RateLimitConfig {
                strategy: RateLimitStrategy::TokenBucket {
                    capacity: 6,
                    refill_rate: 1.5, // Moderate refill rate
                    initial_tokens: 6,
                },
                burst_allowance: 3,
                backpressure_strategy: BackpressureStrategy::Block,
                ..Default::default()
            };

            let coordination_config = CoordinationConfig {
                enforce_rate_before_semaphore: false,
                enforce_semaphore_before_rate: false,
                combined_backpressure_enabled: true,
                permit_timeout_ms: 4000,
                rate_limit_timeout_ms: 4000,
                max_waiting_tasks: 15,
                adaptive_strategy_enabled: true, // Enable adaptive strategy
            };

            let coordination_system = RateLimitedSemaphoreSystem::new(
                semaphore_config,
                rate_limit_config,
                coordination_config,
            )
            .await
            .expect("Failed to create coordination system");

            // Create initial contention patterns to trigger adaptive behavior
            let warmup_tasks = 6;
            let mut warmup_handles = Vec::new();

            for i in 0..warmup_tasks {
                let system_ref = &coordination_system;
                let request_id = format!("warmup_{}", i);

                let handle = scope.spawn(&format!("warmup_{}", i), async move {
                    let result = system_ref
                        .acquire_coordinated_access(
                            cx,
                            request_id,
                            2, // Higher token requirement to create rate limit pressure
                            Duration::from_secs(3),
                        )
                        .await;

                    // Hold access briefly to create contention
                    if result.is_ok() {
                        Sleep::new(Duration::from_millis(100)).await;
                    }

                    result
                })?;

                warmup_handles.push(handle);
                Sleep::new(Duration::from_millis(20)).await;
            }

            // Wait for warmup to complete
            for handle in warmup_handles {
                let _ = handle.join(cx).await;
            }

            // Now test adaptive strategy with more requests
            let adaptive_test_count = 12;
            let mut adaptive_tasks = Vec::new();

            for i in 0..adaptive_test_count {
                let system_ref = &coordination_system;
                let request_id = format!("adaptive_test_{}", i);

                let task = scope.spawn(&format!("adaptive_{}", i), async move {
                    system_ref
                        .acquire_coordinated_access(
                            cx,
                            request_id,
                            1, // Lower token requirement
                            Duration::from_secs(4),
                        )
                        .await
                })?;

                adaptive_tasks.push(task);
                Sleep::new(Duration::from_millis(15)).await;
            }

            // Collect adaptive test results
            let mut adaptive_successful = 0;
            let mut adaptive_failed = 0;

            for task in adaptive_tasks {
                match task.join(cx).await {
                    Ok(Ok(_)) => adaptive_successful += 1,
                    Ok(Err(_)) => adaptive_failed += 1,
                    Err(_) => adaptive_failed += 1,
                }
            }

            // Verify adaptive strategy behavior
            let stats = coordination_system.get_coordination_stats();
            assert!(
                stats.adaptive_strategy_changes > 0,
                "Should have triggered adaptive strategy changes"
            );
            assert!(
                adaptive_successful > 0,
                "Should have some successful adaptive acquisitions"
            );

            println!("Adaptive strategy test results:");
            println!("- Adaptive successful: {}", adaptive_successful);
            println!("- Adaptive failed: {}", adaptive_failed);
            println!("- Strategy changes: {}", stats.adaptive_strategy_changes);
            println!("- Total attempts: {}", stats.total_acquisition_attempts);
            println!(
                "- Successful coordinations: {}",
                stats.successful_coordinations
            );

            Outcome::Ok(())
        })
        .await
        .expect("Region should complete successfully");
    }
}
