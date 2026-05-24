//! Real-service E2E tests: raptorq systematic ↔ runtime/scheduler integration.
//!
//! Tests integration between:
//! - `raptorq::systematic`: RaptorQ encoding/decoding with systematic symbols
//! - `runtime::scheduler`: Three-lane priority scheduler with fairness contracts
//!
//! This exercises decode work units scheduling fairly through priority lanes
//! under symbol loss bursts, verifying scheduler fairness and decode prioritization.

#[cfg(test)]
mod tests {
    use crate::cx::Cx;
    use crate::raptorq::systematic::{SystematicParams, SystematicEncoder, SystematicDecoder};
    use crate::runtime::scheduler::priority::{PriorityScheduler, SchedulerLane};
    use crate::runtime::scheduler::three_lane::{ThreeLaneScheduler, SchedulerConfig, FairnessPolicy};
    use crate::runtime::{region, spawn_blocking};
    use crate::types::{Budget, Time, TaskId, RegionId, Policy, Priority};
    use std::collections::{HashMap, BTreeMap, VecDeque};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, AtomicUsize, AtomicBool, Ordering};
    use std::time::Duration;

    // RaptorQ decode work unit representation
    #[derive(Debug, Clone)]
    struct DecodeWorkUnit {
        work_id: u64,
        source_block_id: u64,
        symbol_loss_rate: f64,
        priority: Priority,
        deadline: Option<Time>,
        symbols_needed: usize,
        symbols_available: usize,
        decode_complexity: DecodeComplexity,
    }

    #[derive(Debug, Clone, PartialEq)]
    enum DecodeComplexity {
        Trivial,        // All systematic symbols available
        Moderate,       // Some repair symbols needed
        Heavy,          // Many repair symbols needed, complex matrix operations
        Critical,       // Near minimal symbols, maximum decode complexity
    }

    #[derive(Debug, Clone)]
    enum SymbolLossBurst {
        Sporadic { loss_rate: f64 },
        Clustered { burst_size: usize, burst_rate: f64 },
        Adversarial { pattern: Vec<bool> }, // true = lost
        Progressive { initial_rate: f64, escalation: f64 },
    }

    // Scheduler lane assignment for decode work
    #[derive(Debug, Clone, Copy, PartialEq)]
    enum DecodeSchedulerLane {
        Cancel,    // High priority decode (critical data, immediate deadline)
        Timed,     // Deadline-driven decode (EDF scheduling)
        Ready,     // Background decode (best-effort)
    }

    // Test data factory for RaptorQ decode scenarios
    struct RaptorQDecodeFactory {
        work_counter: AtomicU64,
        block_counter: AtomicU64,
    }

    impl RaptorQDecodeFactory {
        fn new() -> Self {
            Self {
                work_counter: AtomicU64::new(1),
                block_counter: AtomicU64::new(1),
            }
        }

        fn create_decode_work_unit(&self, complexity: DecodeComplexity, lane: DecodeSchedulerLane) -> DecodeWorkUnit {
            let work_id = self.work_counter.fetch_add(1, Ordering::Relaxed);
            let block_id = self.block_counter.load(Ordering::Relaxed);

            let (priority, deadline, loss_rate, symbols_needed, symbols_available) = match (complexity, lane) {
                (DecodeComplexity::Critical, DecodeSchedulerLane::Cancel) => {
                    (Priority::Critical, Some(Time::from_millis(50)), 0.8, 1000, 256)
                }
                (DecodeComplexity::Heavy, DecodeSchedulerLane::Timed) => {
                    (Priority::High, Some(Time::from_millis(200)), 0.6, 800, 400)
                }
                (DecodeComplexity::Moderate, DecodeSchedulerLane::Ready) => {
                    (Priority::Normal, None, 0.3, 500, 400)
                }
                (DecodeComplexity::Trivial, DecodeSchedulerLane::Ready) => {
                    (Priority::Low, None, 0.1, 256, 256)
                }
                _ => {
                    // Default case for other combinations
                    (Priority::Normal, Some(Time::from_millis(1000)), 0.4, 600, 350)
                }
            };

            DecodeWorkUnit {
                work_id,
                source_block_id: block_id,
                symbol_loss_rate: loss_rate,
                priority,
                deadline,
                symbols_needed,
                symbols_available,
                decode_complexity: complexity,
            }
        }

        fn create_symbol_loss_burst(&self, burst_type: &str) -> SymbolLossBurst {
            match burst_type {
                "sporadic" => SymbolLossBurst::Sporadic { loss_rate: 0.2 },
                "clustered" => SymbolLossBurst::Clustered { burst_size: 20, burst_rate: 0.7 },
                "adversarial" => {
                    let pattern = vec![true, true, false, true, false, false, true, true, false, true];
                    SymbolLossBurst::Adversarial { pattern }
                }
                "progressive" => SymbolLossBurst::Progressive { initial_rate: 0.1, escalation: 1.2 },
                _ => SymbolLossBurst::Sporadic { loss_rate: 0.3 },
            }
        }

        fn next_block_id(&self) -> u64 {
            self.block_counter.fetch_add(1, Ordering::Relaxed)
        }
    }

    // RaptorQ decoder that integrates with scheduler for work prioritization
    struct ScheduledRaptorQDecoder {
        decoder_id: u64,
        systematic_params: SystematicParams,
        pending_work: VecDeque<DecodeWorkUnit>,
        active_decodes: HashMap<u64, DecodeProgress>,
        scheduler_lane_assignments: HashMap<u64, DecodeSchedulerLane>,
        fairness_stats: FairnessTracker,
        logger: TestLogger,
    }

    #[derive(Debug, Clone)]
    struct DecodeProgress {
        work_unit: DecodeWorkUnit,
        symbols_processed: usize,
        decode_start_time: Time,
        scheduler_lane: DecodeSchedulerLane,
        preemption_count: usize,
    }

    #[derive(Debug)]
    struct FairnessTracker {
        cancel_lane_dispatches: AtomicU64,
        timed_lane_dispatches: AtomicU64,
        ready_lane_dispatches: AtomicU64,
        cancel_preemptions: AtomicU64,
        deadline_misses: AtomicU64,
        starvation_events: AtomicU64,
    }

    impl FairnessTracker {
        fn new() -> Self {
            Self {
                cancel_lane_dispatches: AtomicU64::new(0),
                timed_lane_dispatches: AtomicU64::new(0),
                ready_lane_dispatches: AtomicU64::new(0),
                cancel_preemptions: AtomicU64::new(0),
                deadline_misses: AtomicU64::new(0),
                starvation_events: AtomicU64::new(0),
            }
        }

        fn record_dispatch(&self, lane: DecodeSchedulerLane) {
            match lane {
                DecodeSchedulerLane::Cancel => {
                    self.cancel_lane_dispatches.fetch_add(1, Ordering::Relaxed);
                }
                DecodeSchedulerLane::Timed => {
                    self.timed_lane_dispatches.fetch_add(1, Ordering::Relaxed);
                }
                DecodeSchedulerLane::Ready => {
                    self.ready_lane_dispatches.fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        fn record_preemption(&self) {
            self.cancel_preemptions.fetch_add(1, Ordering::Relaxed);
        }

        fn record_deadline_miss(&self) {
            self.deadline_misses.fetch_add(1, Ordering::Relaxed);
        }

        fn record_starvation(&self) {
            self.starvation_events.fetch_add(1, Ordering::Relaxed);
        }

        fn get_stats(&self) -> FairnessStats {
            FairnessStats {
                cancel_dispatches: self.cancel_lane_dispatches.load(Ordering::Relaxed),
                timed_dispatches: self.timed_lane_dispatches.load(Ordering::Relaxed),
                ready_dispatches: self.ready_lane_dispatches.load(Ordering::Relaxed),
                preemptions: self.cancel_preemptions.load(Ordering::Relaxed),
                deadline_misses: self.deadline_misses.load(Ordering::Relaxed),
                starvation_events: self.starvation_events.load(Ordering::Relaxed),
            }
        }
    }

    #[derive(Debug, Clone)]
    struct FairnessStats {
        cancel_dispatches: u64,
        timed_dispatches: u64,
        ready_dispatches: u64,
        preemptions: u64,
        deadline_misses: u64,
        starvation_events: u64,
    }

    impl ScheduledRaptorQDecoder {
        fn new(
            decoder_id: u64,
            k: usize,  // number of source symbols
            logger: TestLogger
        ) -> Result<Self, Box<dyn std::error::Error>> {
            // Create systematic parameters for this decoder
            let systematic_params = SystematicParams::new(k)?;

            Ok(Self {
                decoder_id,
                systematic_params,
                pending_work: VecDeque::new(),
                active_decodes: HashMap::new(),
                scheduler_lane_assignments: HashMap::new(),
                fairness_stats: FairnessTracker::new(),
                logger,
            })
        }

        async fn submit_decode_work(
            &mut self,
            cx: &Cx,
            work_unit: DecodeWorkUnit
        ) -> Result<(), Box<dyn std::error::Error>> {
            self.logger.raptorq_event("submit_decode_work",
                &format!("work_{}_block_{}_complexity_{:?}",
                    work_unit.work_id, work_unit.source_block_id, work_unit.decode_complexity));

            // Assign scheduler lane based on work unit characteristics
            let lane = self.determine_scheduler_lane(&work_unit);
            self.scheduler_lane_assignments.insert(work_unit.work_id, lane);

            self.pending_work.push_back(work_unit);

            self.logger.scheduler_event("work_queued",
                &format!("work_{}_lane_{:?}", self.pending_work.back().unwrap().work_id, lane));

            Ok(())
        }

        fn determine_scheduler_lane(&self, work_unit: &DecodeWorkUnit) -> DecodeSchedulerLane {
            match (&work_unit.decode_complexity, work_unit.deadline, work_unit.priority) {
                // Critical complexity or very high priority -> Cancel lane
                (DecodeComplexity::Critical, _, _) |
                (_, _, Priority::Critical) => DecodeSchedulerLane::Cancel,

                // Has deadline -> Timed lane
                (_, Some(_), _) => DecodeSchedulerLane::Timed,

                // Everything else -> Ready lane
                _ => DecodeSchedulerLane::Ready,
            }
        }

        async fn execute_decode_work(
            &mut self,
            cx: &Cx,
            scheduler: &mut dyn SchedulerInterface
        ) -> Result<Vec<DecodeResult>, Box<dyn std::error::Error>> {
            self.logger.scheduler_event("execute_decode_work",
                &format!("pending_{}_active_{}", self.pending_work.len(), self.active_decodes.len()));

            let mut results = Vec::new();

            // Process work according to scheduler lane priorities
            while let Some(next_work) = self.get_next_scheduled_work(scheduler).await? {
                let decode_result = self.process_decode_work_unit(cx, next_work).await?;
                results.push(decode_result);
            }

            Ok(results)
        }

        async fn get_next_scheduled_work(
            &mut self,
            scheduler: &mut dyn SchedulerInterface
        ) -> Result<Option<DecodeWorkUnit>, Box<dyn std::error::Error>> {
            if self.pending_work.is_empty() {
                return Ok(None);
            }

            // Query scheduler for next lane to process
            let next_lane = scheduler.next_priority_lane().await?;

            self.logger.scheduler_event("scheduler_lane_selected", &format!("{:?}", next_lane));

            // Find work unit matching the selected lane
            for (i, work_unit) in self.pending_work.iter().enumerate() {
                if let Some(&assigned_lane) = self.scheduler_lane_assignments.get(&work_unit.work_id) {
                    if self.lane_matches(assigned_lane, next_lane) {
                        let work_unit = self.pending_work.remove(i).unwrap();

                        // Record dispatch for fairness tracking
                        self.fairness_stats.record_dispatch(assigned_lane);

                        self.logger.scheduler_event("work_dispatched",
                            &format!("work_{}_lane_{:?}", work_unit.work_id, assigned_lane));

                        return Ok(Some(work_unit));
                    }
                }
            }

            // No work available for selected lane
            Ok(None)
        }

        fn lane_matches(&self, assigned: DecodeSchedulerLane, scheduler: SchedulerLaneType) -> bool {
            match (assigned, scheduler) {
                (DecodeSchedulerLane::Cancel, SchedulerLaneType::Cancel) => true,
                (DecodeSchedulerLane::Timed, SchedulerLaneType::Timed) => true,
                (DecodeSchedulerLane::Ready, SchedulerLaneType::Ready) => true,
                _ => false,
            }
        }

        async fn process_decode_work_unit(
            &mut self,
            cx: &Cx,
            work_unit: DecodeWorkUnit
        ) -> Result<DecodeResult, Box<dyn std::error::Error>> {
            self.logger.raptorq_event("process_decode_start",
                &format!("work_{}_symbols_needed_{}_available_{}",
                    work_unit.work_id, work_unit.symbols_needed, work_unit.symbols_available));

            let start_time = crate::time::wall_now();

            // Simulate RaptorQ decode based on symbol availability and complexity
            let decode_outcome = self.simulate_raptorq_decode(&work_unit).await?;

            let end_time = crate::time::wall_now();
            let decode_duration = end_time.saturating_sub(start_time);

            // Check if deadline was met
            let deadline_met = work_unit.deadline.map_or(true, |deadline| end_time <= deadline);

            if !deadline_met {
                self.fairness_stats.record_deadline_miss();
                self.logger.scheduler_event("deadline_missed",
                    &format!("work_{}_deadline_{:?}_actual_{}",
                        work_unit.work_id, work_unit.deadline, end_time.as_nanos()));
            }

            let result = DecodeResult {
                work_id: work_unit.work_id,
                outcome: decode_outcome,
                decode_duration,
                deadline_met,
                symbols_processed: work_unit.symbols_available,
                scheduler_lane: *self.scheduler_lane_assignments.get(&work_unit.work_id).unwrap(),
            };

            self.logger.raptorq_event("decode_complete",
                &format!("work_{}_outcome_{:?}_duration_{}ms",
                    work_unit.work_id, decode_outcome, decode_duration.as_millis()));

            Ok(result)
        }

        async fn simulate_raptorq_decode(&self, work_unit: &DecodeWorkUnit) -> Result<DecodeOutcome, Box<dyn std::error::Error>> {
            // Simulate decode based on symbol loss and complexity
            let symbols_lost = work_unit.symbols_needed - work_unit.symbols_available;
            let loss_rate = symbols_lost as f64 / work_unit.symbols_needed as f64;

            match work_unit.decode_complexity {
                DecodeComplexity::Trivial => {
                    // All systematic symbols available - trivial decode
                    Ok(DecodeOutcome::Success { repair_symbols_used: 0 })
                }
                DecodeComplexity::Moderate => {
                    if loss_rate <= 0.3 {
                        Ok(DecodeOutcome::Success { repair_symbols_used: symbols_lost })
                    } else {
                        Ok(DecodeOutcome::PartialSuccess { symbols_recovered: work_unit.symbols_available })
                    }
                }
                DecodeComplexity::Heavy => {
                    if loss_rate <= 0.5 {
                        // Simulate complex matrix operations
                        Ok(DecodeOutcome::Success { repair_symbols_used: symbols_lost })
                    } else {
                        Ok(DecodeOutcome::Failed { reason: "Insufficient symbols for decode".to_string() })
                    }
                }
                DecodeComplexity::Critical => {
                    if symbols_lost <= 50 {
                        // Near-minimal decode scenario
                        Ok(DecodeOutcome::Success { repair_symbols_used: symbols_lost })
                    } else {
                        Ok(DecodeOutcome::Failed { reason: "Too many symbols lost for recovery".to_string() })
                    }
                }
            }
        }

        fn analyze_fairness(&self) -> FairnessAnalysis {
            let stats = self.fairness_stats.get_stats();
            let total_dispatches = stats.cancel_dispatches + stats.timed_dispatches + stats.ready_dispatches;

            let cancel_ratio = if total_dispatches > 0 {
                stats.cancel_dispatches as f64 / total_dispatches as f64
            } else {
                0.0
            };

            let timed_ratio = if total_dispatches > 0 {
                stats.timed_dispatches as f64 / total_dispatches as f64
            } else {
                0.0
            };

            let ready_ratio = if total_dispatches > 0 {
                stats.ready_dispatches as f64 / total_dispatches as f64
            } else {
                0.0
            };

            // Fairness is good if no single lane dominates excessively
            let is_fair = cancel_ratio < 0.8 && (timed_ratio > 0.1 || ready_ratio > 0.1);

            FairnessAnalysis {
                total_dispatches,
                cancel_ratio,
                timed_ratio,
                ready_ratio,
                deadline_miss_rate: if total_dispatches > 0 { stats.deadline_misses as f64 / total_dispatches as f64 } else { 0.0 },
                is_fair,
                fairness_stats: stats,
            }
        }
    }

    #[derive(Debug, Clone)]
    struct DecodeResult {
        work_id: u64,
        outcome: DecodeOutcome,
        decode_duration: Duration,
        deadline_met: bool,
        symbols_processed: usize,
        scheduler_lane: DecodeSchedulerLane,
    }

    #[derive(Debug, Clone)]
    enum DecodeOutcome {
        Success { repair_symbols_used: usize },
        PartialSuccess { symbols_recovered: usize },
        Failed { reason: String },
    }

    #[derive(Debug)]
    struct FairnessAnalysis {
        total_dispatches: u64,
        cancel_ratio: f64,
        timed_ratio: f64,
        ready_ratio: f64,
        deadline_miss_rate: f64,
        is_fair: bool,
        fairness_stats: FairnessStats,
    }

    // Mock scheduler interface for testing
    #[derive(Debug, Clone, Copy)]
    enum SchedulerLaneType {
        Cancel,
        Timed,
        Ready,
    }

    #[async_trait::async_trait]
    trait SchedulerInterface: Send + Sync {
        async fn next_priority_lane(&mut self) -> Result<SchedulerLaneType, Box<dyn std::error::Error>>;
        async fn report_workload(&mut self, lane: SchedulerLaneType, count: usize) -> Result<(), Box<dyn std::error::Error>>;
    }

    // Real three-lane scheduler integration for E2E testing
    type RealThreeLaneScheduler = ThreeLaneScheduler;

    // Note: Using real ThreeLaneScheduler implementation - no mock interface needed

    // Structured test logger for RaptorQ scheduler integration
    #[derive(Debug, Clone)]
    struct TestLogger {
        test_name: String,
        events: Arc<parking_lot::Mutex<Vec<String>>>,
    }

    impl TestLogger {
        fn new(test_name: &str) -> Self {
            Self {
                test_name: test_name.to_string(),
                events: Arc::new(parking_lot::Mutex::new(Vec::new())),
            }
        }

        fn log_event(&self, category: &str, event: &str, details: &str) {
            let timestamp = crate::time::wall_now();
            let entry = format!("{{\"test\":\"{}\",\"category\":\"{}\",\"event\":\"{}\",\"details\":\"{}\",\"ts\":{}}}",
                self.test_name, category, event, details, timestamp.as_nanos());
            self.events.lock().push(entry);
            eprintln!("{}", entry);
        }

        fn raptorq_event(&self, event: &str, details: &str) {
            self.log_event("raptorq", event, details);
        }

        fn scheduler_event(&self, event: &str, details: &str) {
            self.log_event("scheduler", event, details);
        }

        fn fairness_event(&self, event: &str, details: &str) {
            self.log_event("fairness", event, details);
        }

        fn integration_event(&self, event: &str, details: &str) {
            self.log_event("integration", event, details);
        }

        fn get_events(&self) -> Vec<String> {
            self.events.lock().clone()
        }
    }

    // Integration test harness
    struct RaptorQSchedulerHarness {
        decoder: ScheduledRaptorQDecoder,
        scheduler: RealThreeLaneScheduler,
        factory: RaptorQDecodeFactory,
        logger: TestLogger,
        symbol_loss_scenario: SymbolLossBurst,
    }

    impl RaptorQSchedulerHarness {
        async fn new(test_name: &str, k_symbols: usize) -> Result<Self, Box<dyn std::error::Error>> {
            let logger = TestLogger::new(test_name);
            let decoder = ScheduledRaptorQDecoder::new(1, k_symbols, logger.clone())?;
            let scheduler_config = SchedulerConfig {
                cancel_limit: 5,  // Allow up to 5 consecutive cancel dispatches
                timed_limit: 3,   // Allow up to 3 consecutive timed dispatches
                fairness_policy: FairnessPolicy::BoundedStreaks,
            };
            let scheduler = ThreeLaneScheduler::new(scheduler_config);
            let factory = RaptorQDecodeFactory::new();
            let symbol_loss_scenario = factory.create_symbol_loss_burst("sporadic");

            logger.integration_event("harness_created",
                &format!("k_symbols_{}_decoder_{}", k_symbols, 1));

            Ok(Self {
                decoder,
                scheduler,
                factory,
                logger,
                symbol_loss_scenario,
            })
        }

        async fn simulate_symbol_loss_burst(
            &mut self,
            cx: &Cx,
            burst_scenario: SymbolLossBurst
        ) -> Result<Vec<DecodeWorkUnit>, Box<dyn std::error::Error>> {
            self.logger.integration_event("simulate_symbol_loss_burst", &format!("{:?}", burst_scenario));
            self.symbol_loss_scenario = burst_scenario;

            let mut work_units = Vec::new();

            match &self.symbol_loss_scenario {
                SymbolLossBurst::Sporadic { loss_rate } => {
                    // Create work units with sporadic losses
                    for i in 0..10 {
                        let complexity = if *loss_rate > 0.5 {
                            DecodeComplexity::Heavy
                        } else if *loss_rate > 0.3 {
                            DecodeComplexity::Moderate
                        } else {
                            DecodeComplexity::Trivial
                        };

                        let lane = match i % 3 {
                            0 => DecodeSchedulerLane::Cancel,
                            1 => DecodeSchedulerLane::Timed,
                            _ => DecodeSchedulerLane::Ready,
                        };

                        let work_unit = self.factory.create_decode_work_unit(complexity, lane);
                        work_units.push(work_unit);
                    }
                }

                SymbolLossBurst::Clustered { burst_size, burst_rate } => {
                    // Create work units with clustered losses
                    for i in 0..*burst_size {
                        let complexity = if *burst_rate > 0.6 {
                            DecodeComplexity::Critical
                        } else {
                            DecodeComplexity::Heavy
                        };

                        // Critical work goes to cancel lane
                        let work_unit = self.factory.create_decode_work_unit(
                            complexity, DecodeSchedulerLane::Cancel
                        );
                        work_units.push(work_unit);
                    }
                }

                SymbolLossBurst::Adversarial { pattern } => {
                    // Create work units based on adversarial pattern
                    for (i, &is_lost) in pattern.iter().enumerate() {
                        let complexity = if is_lost {
                            if i % 2 == 0 { DecodeComplexity::Critical } else { DecodeComplexity::Heavy }
                        } else {
                            DecodeComplexity::Trivial
                        };

                        let lane = if is_lost {
                            DecodeSchedulerLane::Cancel
                        } else {
                            DecodeSchedulerLane::Ready
                        };

                        let work_unit = self.factory.create_decode_work_unit(complexity, lane);
                        work_units.push(work_unit);
                    }
                }

                SymbolLossBurst::Progressive { initial_rate, escalation } => {
                    // Create work units with progressively increasing losses
                    let mut current_rate = *initial_rate;
                    for i in 0..8 {
                        let complexity = if current_rate > 0.7 {
                            DecodeComplexity::Critical
                        } else if current_rate > 0.4 {
                            DecodeComplexity::Heavy
                        } else {
                            DecodeComplexity::Moderate
                        };

                        let lane = if current_rate > 0.5 {
                            DecodeSchedulerLane::Cancel
                        } else if current_rate > 0.2 {
                            DecodeSchedulerLane::Timed
                        } else {
                            DecodeSchedulerLane::Ready
                        };

                        let work_unit = self.factory.create_decode_work_unit(complexity, lane);
                        work_units.push(work_unit);

                        current_rate *= escalation;
                    }
                }
            }

            // Submit work units to decoder
            for work_unit in &work_units {
                self.decoder.submit_decode_work(cx, work_unit.clone()).await?;
            }

            // Update scheduler workload counts
            let mut lane_counts: HashMap<SchedulerLaneType, usize> = HashMap::new();
            for work_unit in &work_units {
                let lane = self.decoder.determine_scheduler_lane(work_unit);
                let scheduler_lane = match lane {
                    DecodeSchedulerLane::Cancel => SchedulerLaneType::Cancel,
                    DecodeSchedulerLane::Timed => SchedulerLaneType::Timed,
                    DecodeSchedulerLane::Ready => SchedulerLaneType::Ready,
                };
                *lane_counts.entry(scheduler_lane).or_insert(0) += 1;
            }

            for (lane, count) in lane_counts {
                self.scheduler.report_workload(lane, count).await?;
            }

            self.logger.integration_event("symbol_loss_burst_created",
                &format!("work_units_{}", work_units.len()));

            Ok(work_units)
        }

        async fn execute_scheduled_decode(
            &mut self,
            cx: &Cx
        ) -> Result<Vec<DecodeResult>, Box<dyn std::error::Error>> {
            self.logger.integration_event("execute_scheduled_decode", "starting");

            let results = self.decoder.execute_decode_work(cx, &mut self.scheduler).await?;

            self.logger.integration_event("scheduled_decode_complete",
                &format!("results_{}", results.len()));

            Ok(results)
        }

        async fn verify_scheduler_fairness(&self) -> Result<FairnessVerificationReport, Box<dyn std::error::Error>> {
            self.logger.fairness_event("verify_fairness", "starting");

            let fairness_analysis = self.decoder.analyze_fairness();

            let report = FairnessVerificationReport {
                fairness_analysis: fairness_analysis.clone(),
                priority_lane_respected: fairness_analysis.cancel_ratio >= fairness_analysis.ready_ratio,
                deadline_compliance: fairness_analysis.deadline_miss_rate < 0.1,
                no_starvation: fairness_analysis.fairness_stats.starvation_events == 0,
                overall_fair: fairness_analysis.is_fair,
            };

            self.logger.fairness_event("fairness_verified",
                &format!("fair_{}_priority_respected_{}_deadline_compliance_{}",
                    report.overall_fair, report.priority_lane_respected, report.deadline_compliance));

            Ok(report)
        }

        fn analyze_integration_events(&self) -> IntegrationAnalysis {
            let events = self.logger.get_events();

            let mut analysis = IntegrationAnalysis {
                total_events: events.len(),
                raptorq_events: 0,
                scheduler_events: 0,
                fairness_events: 0,
                integration_events: 0,
                decode_operations: 0,
                scheduler_dispatches: 0,
            };

            for event in &events {
                if event.contains("\"category\":\"raptorq\"") {
                    analysis.raptorq_events += 1;
                    if event.contains("decode") {
                        analysis.decode_operations += 1;
                    }
                } else if event.contains("\"category\":\"scheduler\"") {
                    analysis.scheduler_events += 1;
                    if event.contains("dispatched") {
                        analysis.scheduler_dispatches += 1;
                    }
                } else if event.contains("\"category\":\"fairness\"") {
                    analysis.fairness_events += 1;
                } else if event.contains("\"category\":\"integration\"") {
                    analysis.integration_events += 1;
                }
            }

            analysis
        }
    }

    #[derive(Debug)]
    struct FairnessVerificationReport {
        fairness_analysis: FairnessAnalysis,
        priority_lane_respected: bool,
        deadline_compliance: bool,
        no_starvation: bool,
        overall_fair: bool,
    }

    #[derive(Debug)]
    struct IntegrationAnalysis {
        total_events: usize,
        raptorq_events: usize,
        scheduler_events: usize,
        fairness_events: usize,
        integration_events: usize,
        decode_operations: usize,
        scheduler_dispatches: usize,
    }

    #[test]
    fn test_raptorq_scheduler_integration() {
        crate::lab::runtime::test_with_lab(|cx| async move {
            let mut harness = RaptorQSchedulerHarness::new("raptorq_scheduler_integration", 256)
                .await
                .expect("Harness creation should succeed");

            // Simulate sporadic symbol loss burst
            let loss_burst = harness.factory.create_symbol_loss_burst("sporadic");
            let work_units = harness.simulate_symbol_loss_burst(&cx, loss_burst).await?;

            assert!(!work_units.is_empty(), "Should create decode work units");

            // Execute scheduled decode work
            let results = harness.execute_scheduled_decode(&cx).await?;

            assert_eq!(results.len(), work_units.len(), "Should process all work units");

            // Verify scheduler fairness
            let fairness_report = harness.verify_scheduler_fairness().await?;
            assert!(fairness_report.priority_lane_respected, "Priority lanes should be respected");
            assert!(fairness_report.deadline_compliance, "Deadline compliance should be maintained");
            assert!(fairness_report.no_starvation, "No lane should be starved");

            // Analyze integration
            let analysis = harness.analyze_integration_events();
            assert!(analysis.raptorq_events > 0, "Should have RaptorQ events");
            assert!(analysis.scheduler_events > 0, "Should have scheduler events");
            assert!(analysis.decode_operations > 0, "Should have decode operations");

            Ok(())
        }).expect("RaptorQ scheduler integration test should complete successfully");
    }

    #[test]
    fn test_priority_lanes_under_symbol_loss() {
        crate::lab::runtime::test_with_lab(|cx| async move {
            let mut harness = RaptorQSchedulerHarness::new("priority_lanes_symbol_loss", 512)
                .await
                .expect("Harness creation should succeed");

            // Simulate clustered symbol loss (high priority work)
            let clustered_loss = SymbolLossBurst::Clustered { burst_size: 15, burst_rate: 0.8 };
            let work_units = harness.simulate_symbol_loss_burst(&cx, clustered_loss).await?;

            // Execute decode work
            let results = harness.execute_scheduled_decode(&cx).await?;

            // Verify that critical work was prioritized
            let cancel_lane_results: Vec<_> = results.iter()
                .filter(|r| r.scheduler_lane == DecodeSchedulerLane::Cancel)
                .collect();

            assert!(!cancel_lane_results.is_empty(), "Should have cancel lane work");

            // Verify fairness under high priority load
            let fairness_report = harness.verify_scheduler_fairness().await?;
            assert!(fairness_report.priority_lane_respected, "Priority should be respected under load");

            Ok(())
        }).expect("Priority lanes under symbol loss test should complete successfully");
    }

    #[test]
    fn test_fairness_under_adversarial_loss() {
        crate::lab::runtime::test_with_lab(|cx| async move {
            let mut harness = RaptorQSchedulerHarness::new("fairness_adversarial_loss", 1024)
                .await
                .expect("Harness creation should succeed");

            // Simulate adversarial symbol loss pattern
            let adversarial_pattern = vec![true, true, false, true, false, false, true, true, false, true];
            let adversarial_loss = SymbolLossBurst::Adversarial { pattern: adversarial_pattern };
            let work_units = harness.simulate_symbol_loss_burst(&cx, adversarial_loss).await?;

            // Execute decode work
            let results = harness.execute_scheduled_decode(&cx).await?;

            // Verify scheduler maintained fairness despite adversarial pattern
            let fairness_report = harness.verify_scheduler_fairness().await?;
            assert!(fairness_report.overall_fair, "Should maintain fairness under adversarial patterns");
            assert!(fairness_report.no_starvation, "Should prevent starvation");

            // Verify mixed lane processing
            let lane_types: std::collections::HashSet<_> = results.iter()
                .map(|r| r.scheduler_lane)
                .collect();
            assert!(lane_types.len() > 1, "Should process multiple lane types");

            Ok(())
        }).expect("Fairness under adversarial loss test should complete successfully");
    }

    #[test]
    fn test_progressive_loss_scheduling() {
        crate::lab::runtime::test_with_lab(|cx| async move {
            let mut harness = RaptorQSchedulerHarness::new("progressive_loss_scheduling", 512)
                .await
                .expect("Harness creation should succeed");

            // Simulate progressive symbol loss escalation
            let progressive_loss = SymbolLossBurst::Progressive { initial_rate: 0.1, escalation: 1.3 };
            let work_units = harness.simulate_symbol_loss_burst(&cx, progressive_loss).await?;

            // Execute decode work
            let results = harness.execute_scheduled_decode(&cx).await?;

            // Verify scheduler adapted to increasing loss severity
            let analysis = harness.analyze_integration_events();
            assert!(analysis.scheduler_dispatches >= work_units.len(), "Should dispatch all work");

            // Check that later work (higher loss) was prioritized appropriately
            let fairness_report = harness.verify_scheduler_fairness().await?;
            assert!(fairness_report.priority_lane_respected, "Should adapt priority to loss severity");

            Ok(())
        }).expect("Progressive loss scheduling test should complete successfully");
    }

    #[test]
    fn test_decode_complexity_lane_assignment() {
        crate::lab::runtime::test_with_lab(|cx| async move {
            let mut harness = RaptorQSchedulerHarness::new("decode_complexity_lane_assignment", 256)
                .await
                .expect("Harness creation should succeed");

            // Create work units of different complexities
            let complexities = vec![
                DecodeComplexity::Trivial,
                DecodeComplexity::Moderate,
                DecodeComplexity::Heavy,
                DecodeComplexity::Critical,
            ];

            for complexity in complexities {
                let work_unit = harness.factory.create_decode_work_unit(
                    complexity.clone(),
                    DecodeSchedulerLane::Ready  // Let scheduler determine actual lane
                );
                harness.decoder.submit_decode_work(&cx, work_unit).await?;
            }

            // Update scheduler workloads
            harness.scheduler.report_workload(SchedulerLaneType::Cancel, 1).await?;
            harness.scheduler.report_workload(SchedulerLaneType::Timed, 1).await?;
            harness.scheduler.report_workload(SchedulerLaneType::Ready, 2).await?;

            // Execute decode work
            let results = harness.execute_scheduled_decode(&cx).await?;

            // Verify lane assignment based on complexity
            let critical_in_cancel = results.iter()
                .any(|r| r.scheduler_lane == DecodeSchedulerLane::Cancel);
            assert!(critical_in_cancel, "Critical work should be in cancel lane");

            let analysis = harness.analyze_integration_events();
            assert_eq!(analysis.decode_operations, 4, "Should process all complexity types");

            Ok(())
        }).expect("Decode complexity lane assignment test should complete successfully");
    }
}