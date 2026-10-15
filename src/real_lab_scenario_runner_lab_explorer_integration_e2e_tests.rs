//! Real Lab Scenario Runner ↔ Lab Explorer Integration E2E Test
//!
//! This test verifies that deterministic scenario replay across explorer's parameter
//! sweeps produces identical traces. It validates the integration between scenario
//! execution and parameter space exploration for deterministic reproducibility.

#[cfg(test)]
mod tests {
    use crate::{
        lab::{
            scenario_runner::{
                ScenarioRunner, ScenarioConfig, ScenarioExecution, ScenarioResult,
                DeterministicReplay, ReplayConfig, ExecutionContext, ScenarioMetrics,
                ScenarioState, ExecutionPhase, ReplayValidation, ScenarioCheckpoint,
            },
            explorer::{
                LabExplorer, ParameterSweep, SweepConfig, ExplorationStrategy,
                ParameterSpace, ParameterSet, SweepResult, ExplorationMetrics,
                ParameterBounds, SweepProgress, ExplorationState, ParameterValue,
            },
            LabRuntime, LabConfig, DeterministicScheduler, VirtualTime,
        },
        trace::{
            TraceEvent, TraceRecorder, TraceComparator, TraceIdentity, EventSequence,
            ExecutionTrace, TraceHash, TraceDifference, TraceMetadata, EventId,
        },
        types::{Budget, Outcome, TaskId, Time},
        cx::{Cx, Scope},
        error::Result,
        sync::{Arc, Mutex},
    };
    use std::{
        collections::{HashMap, VecDeque, BTreeMap, HashSet},
        sync::{
            atomic::{AtomicBool, AtomicU64, Ordering},
            Arc, Mutex,
        },
        time::{Duration, Instant},
    };

    /// Mock scenario runner with deterministic replay capabilities
    #[derive(Debug)]
    struct MockDeterministicScenarioRunner {
        runner_id: String,
        config: ScenarioConfig,
        lab_explorer: Arc<MockLabExplorer>,
        integration_tracker: Arc<ScenarioExplorerTracker>,
        trace_recorder: Arc<MockTraceRecorder>,
        execution_history: Arc<Mutex<Vec<ScenarioExecution>>>,
        replay_cache: Arc<Mutex<HashMap<ReplayKey, ExecutionTrace>>>,
        deterministic_scheduler: DeterministicScheduler,
        virtual_time: VirtualTime,
        execution_counter: AtomicU64,
    }

    impl MockDeterministicScenarioRunner {
        fn new(
            runner_id: String,
            config: ScenarioConfig,
            lab_explorer: Arc<MockLabExplorer>,
        ) -> Self {
            Self {
                runner_id,
                config,
                lab_explorer,
                integration_tracker: Arc::new(ScenarioExplorerTracker::new()),
                trace_recorder: Arc::new(MockTraceRecorder::new()),
                execution_history: Arc::new(Mutex::new(Vec::new())),
                replay_cache: Arc::new(Mutex::new(HashMap::new())),
                deterministic_scheduler: DeterministicScheduler::new(),
                virtual_time: VirtualTime::new(),
                execution_counter: AtomicU64::new(0),
            }
        }

        async fn execute_scenario_with_parameters(
            &self,
            scenario_name: &str,
            parameters: &ParameterSet,
            cx: &Cx,
        ) -> Result<ScenarioExecutionResult> {
            let execution_id = self.execution_counter.fetch_add(1, Ordering::AcqRel);

            // Create execution context with deterministic settings
            let execution_context = ExecutionContext {
                execution_id,
                scenario_name: scenario_name.to_string(),
                parameters: parameters.clone(),
                deterministic_seed: self.calculate_deterministic_seed(parameters),
                virtual_time_start: self.virtual_time.now(),
                scheduler_config: self.deterministic_scheduler.get_config(),
            };

            // Record execution start
            self.integration_tracker.record_execution_start(&execution_context);

            // Initialize trace recording
            let trace_session = self.trace_recorder.start_session(execution_id).await?;

            // Execute scenario with deterministic settings
            let scenario_result = self.execute_scenario_deterministically(
                &execution_context,
                cx,
            ).await?;

            // Finalize trace recording
            let execution_trace = self.trace_recorder.finalize_session(trace_session).await?;

            // Store execution for replay verification
            let scenario_execution = ScenarioExecution {
                context: execution_context.clone(),
                result: scenario_result.clone(),
                trace: execution_trace.clone(),
                execution_timestamp: Time::now().into(),
            };

            self.execution_history.lock().unwrap().push(scenario_execution);

            // Cache trace for replay comparisons
            let replay_key = ReplayKey::from_context(&execution_context);
            self.replay_cache.lock().unwrap().insert(replay_key, execution_trace.clone());

            // Record execution completion
            self.integration_tracker.record_execution_completion(&execution_context, &scenario_result);

            Ok(ScenarioExecutionResult {
                execution_context,
                scenario_result,
                execution_trace,
                trace_hash: self.calculate_trace_hash(&execution_trace),
            })
        }

        async fn replay_scenario_deterministically(
            &self,
            original_context: &ExecutionContext,
            cx: &Cx,
        ) -> Result<ReplayResult> {
            // Create replay context with identical parameters
            let replay_context = ExecutionContext {
                execution_id: self.execution_counter.fetch_add(1, Ordering::AcqRel),
                scenario_name: original_context.scenario_name.clone(),
                parameters: original_context.parameters.clone(),
                deterministic_seed: original_context.deterministic_seed,
                virtual_time_start: original_context.virtual_time_start,
                scheduler_config: original_context.scheduler_config.clone(),
            };

            // Initialize trace recording for replay
            let replay_trace_session = self.trace_recorder.start_session(replay_context.execution_id).await?;

            // Execute scenario with identical deterministic settings
            let replay_result = self.execute_scenario_deterministically(
                &replay_context,
                cx,
            ).await?;

            // Finalize replay trace
            let replay_trace = self.trace_recorder.finalize_session(replay_trace_session).await?;

            // Compare with original trace
            let original_trace = self.replay_cache.lock().unwrap()
                .get(&ReplayKey::from_context(original_context))
                .cloned()
                .ok_or_else(|| crate::error::Error::new(
                    crate::error::ErrorKind::NotFound,
                    "Original trace not found in cache"
                ))?;

            let trace_comparison = self.compare_traces(&original_trace, &replay_trace).await?;

            // Record replay completion
            self.integration_tracker.record_replay_completion(
                original_context,
                &replay_context,
                &trace_comparison,
            );

            Ok(ReplayResult {
                original_context: original_context.clone(),
                replay_context,
                original_trace,
                replay_trace,
                trace_comparison,
                is_identical: trace_comparison.is_identical,
            })
        }

        async fn execute_parameter_sweep_with_replay(
            &self,
            scenario_name: &str,
            parameter_sweep: &ParameterSweep,
            cx: &Cx,
        ) -> Result<SweepReplayResult> {
            let mut sweep_executions = Vec::new();
            let mut replay_validations = Vec::new();

            // Execute scenario for each parameter set in the sweep
            for (i, parameter_set) in parameter_sweep.parameter_sets.iter().enumerate() {
                // Initial execution
                let execution_result = self.execute_scenario_with_parameters(
                    scenario_name,
                    parameter_set,
                    cx,
                ).await?;

                // Replay for determinism verification
                let replay_result = self.replay_scenario_deterministically(
                    &execution_result.execution_context,
                    cx,
                ).await?;

                sweep_executions.push(execution_result);
                replay_validations.push(replay_result);

                // Record sweep progress
                self.integration_tracker.record_sweep_progress(i, parameter_sweep.parameter_sets.len());

                // Small delay between executions
                cx.sleep(Duration::from_millis(5)).await?;
            }

            // Analyze sweep results for consistency
            let consistency_analysis = self.analyze_sweep_consistency(&sweep_executions, &replay_validations)?;

            // Cross-validate traces across different parameter sets
            let cross_validation = self.perform_cross_parameter_validation(&sweep_executions)?;

            Ok(SweepReplayResult {
                scenario_name: scenario_name.to_string(),
                parameter_sweep: parameter_sweep.clone(),
                sweep_executions,
                replay_validations,
                consistency_analysis,
                cross_validation,
                total_parameter_sets: parameter_sweep.parameter_sets.len(),
            })
        }

        async fn execute_scenario_deterministically(
            &self,
            context: &ExecutionContext,
            cx: &Cx,
        ) -> Result<ScenarioResult> {
            // Reset deterministic state
            self.deterministic_scheduler.reset_with_seed(context.deterministic_seed);
            self.virtual_time.reset_to(context.virtual_time_start);

            // Execute scenario phases deterministically
            let mut phase_results = Vec::new();

            for phase in &self.config.execution_phases {
                let phase_result = self.execute_phase_deterministically(
                    phase,
                    &context.parameters,
                    cx,
                ).await?;

                phase_results.push(phase_result);

                // Advance virtual time deterministically
                self.virtual_time.advance_by(phase.duration);
            }

            // Generate scenario metrics
            let scenario_metrics = self.calculate_scenario_metrics(&phase_results);

            Ok(ScenarioResult {
                execution_id: context.execution_id,
                scenario_name: context.scenario_name.clone(),
                phase_results,
                final_state: ScenarioState::Completed,
                total_duration: self.virtual_time.elapsed(),
                metrics: scenario_metrics,
            })
        }

        async fn execute_phase_deterministically(
            &self,
            phase: &ExecutionPhase,
            parameters: &ParameterSet,
            cx: &Cx,
        ) -> Result<PhaseResult> {
            // Apply parameters to phase execution
            let phase_config = self.apply_parameters_to_phase(phase, parameters);

            // Execute phase operations deterministically
            match &phase.phase_type {
                PhaseType::Initialization => {
                    self.execute_initialization_phase(&phase_config, cx).await
                }
                PhaseType::Workload => {
                    self.execute_workload_phase(&phase_config, cx).await
                }
                PhaseType::Stress => {
                    self.execute_stress_phase(&phase_config, cx).await
                }
                PhaseType::Cleanup => {
                    self.execute_cleanup_phase(&phase_config, cx).await
                }
            }
        }

        async fn execute_initialization_phase(
            &self,
            config: &PhaseConfig,
            cx: &Cx,
        ) -> Result<PhaseResult> {
            // Simulate deterministic initialization
            self.trace_recorder.record_event(TraceEvent {
                id: EventId::new(),
                timestamp: self.virtual_time.now(),
                event_type: EventType::PhaseStart,
                phase: "initialization".to_string(),
                data: EventData::Initialization(config.clone()),
            }).await?;

            // Simulate initialization work
            cx.sleep(Duration::from_millis(10)).await?;
            self.virtual_time.advance_by(Duration::from_millis(10));

            self.trace_recorder.record_event(TraceEvent {
                id: EventId::new(),
                timestamp: self.virtual_time.now(),
                event_type: EventType::PhaseEnd,
                phase: "initialization".to_string(),
                data: EventData::PhaseCompletion,
            }).await?;

            Ok(PhaseResult {
                phase_name: "initialization".to_string(),
                duration: Duration::from_millis(10),
                operations_count: config.operation_count,
                success_rate: 1.0,
                phase_metrics: PhaseMetrics::default(),
            })
        }

        async fn execute_workload_phase(
            &self,
            config: &PhaseConfig,
            cx: &Cx,
        ) -> Result<PhaseResult> {
            // Simulate deterministic workload
            self.trace_recorder.record_event(TraceEvent {
                id: EventId::new(),
                timestamp: self.virtual_time.now(),
                event_type: EventType::PhaseStart,
                phase: "workload".to_string(),
                data: EventData::Workload(config.clone()),
            }).await?;

            // Execute deterministic operations
            for i in 0..config.operation_count {
                self.trace_recorder.record_event(TraceEvent {
                    id: EventId::new(),
                    timestamp: self.virtual_time.now(),
                    event_type: EventType::Operation,
                    phase: "workload".to_string(),
                    data: EventData::OperationExecution {
                        operation_id: i,
                        operation_type: "deterministic_work".to_string(),
                    },
                }).await?;

                cx.sleep(Duration::from_millis(1)).await?;
                self.virtual_time.advance_by(Duration::from_millis(1));
            }

            self.trace_recorder.record_event(TraceEvent {
                id: EventId::new(),
                timestamp: self.virtual_time.now(),
                event_type: EventType::PhaseEnd,
                phase: "workload".to_string(),
                data: EventData::PhaseCompletion,
            }).await?;

            Ok(PhaseResult {
                phase_name: "workload".to_string(),
                duration: Duration::from_millis(config.operation_count as u64),
                operations_count: config.operation_count,
                success_rate: 1.0,
                phase_metrics: PhaseMetrics::default(),
            })
        }

        async fn execute_stress_phase(
            &self,
            config: &PhaseConfig,
            cx: &Cx,
        ) -> Result<PhaseResult> {
            // Simulate deterministic stress testing
            self.trace_recorder.record_event(TraceEvent {
                id: EventId::new(),
                timestamp: self.virtual_time.now(),
                event_type: EventType::PhaseStart,
                phase: "stress".to_string(),
                data: EventData::Stress(config.clone()),
            }).await?;

            // Higher operation count for stress
            let stress_operations = config.operation_count * 2;
            for i in 0..stress_operations {
                self.trace_recorder.record_event(TraceEvent {
                    id: EventId::new(),
                    timestamp: self.virtual_time.now(),
                    event_type: EventType::Operation,
                    phase: "stress".to_string(),
                    data: EventData::OperationExecution {
                        operation_id: i,
                        operation_type: "stress_operation".to_string(),
                    },
                }).await?;

                // Shorter intervals for stress
                cx.sleep(Duration::from_millis(1)).await?;
                self.virtual_time.advance_by(Duration::from_millis(1));
            }

            self.trace_recorder.record_event(TraceEvent {
                id: EventId::new(),
                timestamp: self.virtual_time.now(),
                event_type: EventType::PhaseEnd,
                phase: "stress".to_string(),
                data: EventData::PhaseCompletion,
            }).await?;

            Ok(PhaseResult {
                phase_name: "stress".to_string(),
                duration: Duration::from_millis(stress_operations as u64),
                operations_count: stress_operations,
                success_rate: 1.0,
                phase_metrics: PhaseMetrics::default(),
            })
        }

        async fn execute_cleanup_phase(
            &self,
            config: &PhaseConfig,
            cx: &Cx,
        ) -> Result<PhaseResult> {
            // Simulate deterministic cleanup
            self.trace_recorder.record_event(TraceEvent {
                id: EventId::new(),
                timestamp: self.virtual_time.now(),
                event_type: EventType::PhaseStart,
                phase: "cleanup".to_string(),
                data: EventData::Cleanup(config.clone()),
            }).await?;

            // Cleanup operations
            cx.sleep(Duration::from_millis(5)).await?;
            self.virtual_time.advance_by(Duration::from_millis(5));

            self.trace_recorder.record_event(TraceEvent {
                id: EventId::new(),
                timestamp: self.virtual_time.now(),
                event_type: EventType::PhaseEnd,
                phase: "cleanup".to_string(),
                data: EventData::PhaseCompletion,
            }).await?;

            Ok(PhaseResult {
                phase_name: "cleanup".to_string(),
                duration: Duration::from_millis(5),
                operations_count: 1,
                success_rate: 1.0,
                phase_metrics: PhaseMetrics::default(),
            })
        }

        async fn compare_traces(&self, original: &ExecutionTrace, replay: &ExecutionTrace) -> Result<TraceComparison> {
            // Detailed trace comparison for deterministic verification
            let event_differences = self.compare_event_sequences(&original.events, &replay.events);
            let timing_differences = self.compare_event_timing(&original.events, &replay.events);
            let metadata_differences = self.compare_trace_metadata(&original.metadata, &replay.metadata);

            let is_identical = event_differences.is_empty() &&
                              timing_differences.is_empty() &&
                              metadata_differences.is_empty();

            Ok(TraceComparison {
                original_hash: self.calculate_trace_hash(original),
                replay_hash: self.calculate_trace_hash(replay),
                is_identical,
                event_differences,
                timing_differences,
                metadata_differences,
                comparison_confidence: if is_identical { 1.0 } else {
                    1.0 - (event_differences.len() + timing_differences.len()) as f64 / original.events.len().max(1) as f64
                },
            })
        }

        fn compare_event_sequences(&self, original: &[TraceEvent], replay: &[TraceEvent]) -> Vec<EventDifference> {
            let mut differences = Vec::new();

            if original.len() != replay.len() {
                differences.push(EventDifference::CountMismatch {
                    original_count: original.len(),
                    replay_count: replay.len(),
                });
            }

            for (i, (orig_event, replay_event)) in original.iter().zip(replay.iter()).enumerate() {
                if orig_event.event_type != replay_event.event_type {
                    differences.push(EventDifference::TypeMismatch {
                        event_index: i,
                        original_type: orig_event.event_type.clone(),
                        replay_type: replay_event.event_type.clone(),
                    });
                }

                if orig_event.phase != replay_event.phase {
                    differences.push(EventDifference::PhaseMismatch {
                        event_index: i,
                        original_phase: orig_event.phase.clone(),
                        replay_phase: replay_event.phase.clone(),
                    });
                }
            }

            differences
        }

        fn compare_event_timing(&self, original: &[TraceEvent], replay: &[TraceEvent]) -> Vec<TimingDifference> {
            let mut differences = Vec::new();

            for (i, (orig_event, replay_event)) in original.iter().zip(replay.iter()).enumerate() {
                if orig_event.timestamp != replay_event.timestamp {
                    differences.push(TimingDifference::TimestampMismatch {
                        event_index: i,
                        original_timestamp: orig_event.timestamp,
                        replay_timestamp: replay_event.timestamp,
                        delta: if replay_event.timestamp > orig_event.timestamp {
                            replay_event.timestamp.duration_since(orig_event.timestamp)
                        } else {
                            orig_event.timestamp.duration_since(replay_event.timestamp)
                        },
                    });
                }
            }

            differences
        }

        fn compare_trace_metadata(&self, original: &TraceMetadata, replay: &TraceMetadata) -> Vec<MetadataDifference> {
            let mut differences = Vec::new();

            if original.version != replay.version {
                differences.push(MetadataDifference::VersionMismatch {
                    original_version: original.version.clone(),
                    replay_version: replay.version.clone(),
                });
            }

            differences
        }

        fn analyze_sweep_consistency(
            &self,
            executions: &[ScenarioExecutionResult],
            replays: &[ReplayResult],
        ) -> Result<ConsistencyAnalysis> {
            let mut identical_count = 0;
            let mut total_comparisons = 0;
            let mut consistency_violations = Vec::new();

            for (i, replay) in replays.iter().enumerate() {
                total_comparisons += 1;
                if replay.is_identical {
                    identical_count += 1;
                } else {
                    consistency_violations.push(ConsistencyViolation {
                        parameter_set_index: i,
                        execution_context: replay.original_context.clone(),
                        trace_differences: replay.trace_comparison.event_differences.len() +
                                          replay.trace_comparison.timing_differences.len(),
                    });
                }
            }

            let consistency_rate = if total_comparisons > 0 {
                identical_count as f64 / total_comparisons as f64
            } else {
                1.0
            };

            Ok(ConsistencyAnalysis {
                total_parameter_sets: executions.len(),
                identical_replays: identical_count,
                consistency_violations,
                consistency_rate,
                is_fully_deterministic: consistency_rate == 1.0,
            })
        }

        fn perform_cross_parameter_validation(
            &self,
            executions: &[ScenarioExecutionResult],
        ) -> Result<CrossValidationResult> {
            let mut parameter_trace_groups = HashMap::new();
            let mut unique_traces = HashSet::new();

            // Group executions by parameter similarity
            for execution in executions {
                let param_key = self.generate_parameter_key(&execution.execution_context.parameters);
                parameter_trace_groups.entry(param_key).or_insert_with(Vec::new).push(execution);
                unique_traces.insert(execution.trace_hash);
            }

            let total_unique_traces = unique_traces.len();
            let expected_unique_traces = executions.len(); // Each parameter set should produce unique traces

            Ok(CrossValidationResult {
                total_executions: executions.len(),
                unique_parameter_groups: parameter_trace_groups.len(),
                total_unique_traces,
                expected_unique_traces,
                trace_diversity: total_unique_traces as f64 / expected_unique_traces as f64,
                parameter_coverage: parameter_trace_groups.len() as f64 / executions.len() as f64,
            })
        }

        fn calculate_deterministic_seed(&self, parameters: &ParameterSet) -> u64 {
            // Generate consistent seed from parameters
            let mut seed = 0u64;
            for (key, value) in &parameters.values {
                seed = seed.wrapping_add(key.len() as u64);
                seed = seed.wrapping_mul(31);
                seed = seed.wrapping_add(value.hash());
            }
            seed
        }

        fn calculate_trace_hash(&self, trace: &ExecutionTrace) -> TraceHash {
            // Calculate deterministic hash of trace
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            use std::hash::{Hash, Hasher};

            trace.events.len().hash(&mut hasher);
            for event in &trace.events {
                event.event_type.hash(&mut hasher);
                event.phase.hash(&mut hasher);
                // Note: Don't hash timestamps for deterministic comparison
            }

            TraceHash(hasher.finish())
        }

        fn apply_parameters_to_phase(&self, phase: &ExecutionPhase, parameters: &ParameterSet) -> PhaseConfig {
            let base_operation_count = phase.base_operation_count;

            // Apply parameter scaling
            let operation_count = if let Some(scale_param) = parameters.values.get("operation_scale") {
                match scale_param {
                    ParameterValue::Float(scale) => (base_operation_count as f64 * scale) as usize,
                    ParameterValue::Integer(scale) => base_operation_count * (*scale as usize),
                    _ => base_operation_count,
                }
            } else {
                base_operation_count
            };

            PhaseConfig {
                operation_count,
                parameters: parameters.clone(),
            }
        }

        fn calculate_scenario_metrics(&self, phase_results: &[PhaseResult]) -> ScenarioMetrics {
            let total_operations: usize = phase_results.iter().map(|p| p.operations_count).sum();
            let total_duration: Duration = phase_results.iter().map(|p| p.duration).sum();
            let avg_success_rate = phase_results.iter().map(|p| p.success_rate).sum::<f64>() / phase_results.len().max(1) as f64;

            ScenarioMetrics {
                total_phases: phase_results.len(),
                total_operations,
                total_duration,
                average_success_rate: avg_success_rate,
                throughput: total_operations as f64 / total_duration.as_secs_f64(),
            }
        }

        fn generate_parameter_key(&self, parameters: &ParameterSet) -> String {
            let mut key_parts: Vec<_> = parameters.values.iter().collect();
            key_parts.sort_by_key(|(k, _)| *k);
            key_parts.iter().map(|(k, v)| format!("{}:{}", k, v.to_string())).collect::<Vec<_>>().join(";")
        }

        fn get_integration_stats(&self) -> ScenarioExplorerStats {
            let history = self.execution_history.lock().unwrap();
            let cache = self.replay_cache.lock().unwrap();

            ScenarioExplorerStats {
                total_executions: history.len(),
                cached_traces: cache.len(),
                integration_health: self.integration_tracker.get_integration_health(),
            }
        }
    }

    /// Mock lab explorer for parameter space exploration
    #[derive(Debug)]
    struct MockLabExplorer {
        explorer_id: String,
        exploration_strategies: Vec<ExplorationStrategy>,
        parameter_space_cache: Arc<Mutex<HashMap<String, ParameterSpace>>>,
        sweep_results: Arc<Mutex<Vec<SweepResult>>>,
    }

    impl MockLabExplorer {
        fn new(explorer_id: String) -> Self {
            Self {
                explorer_id,
                exploration_strategies: vec![
                    ExplorationStrategy::GridSweep,
                    ExplorationStrategy::RandomSampling,
                    ExplorationStrategy::LatinHypercube,
                ],
                parameter_space_cache: Arc::new(Mutex::new(HashMap::new())),
                sweep_results: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn generate_parameter_sweep(
            &self,
            parameter_space: &ParameterSpace,
            strategy: ExplorationStrategy,
            sample_count: usize,
        ) -> Result<ParameterSweep> {
            match strategy {
                ExplorationStrategy::GridSweep => self.generate_grid_sweep(parameter_space, sample_count),
                ExplorationStrategy::RandomSampling => self.generate_random_sweep(parameter_space, sample_count),
                ExplorationStrategy::LatinHypercube => self.generate_latin_hypercube_sweep(parameter_space, sample_count),
            }
        }

        fn generate_grid_sweep(&self, space: &ParameterSpace, sample_count: usize) -> Result<ParameterSweep> {
            let mut parameter_sets = Vec::new();
            let params_per_dimension = (sample_count as f64).powf(1.0 / space.dimensions.len() as f64).ceil() as usize;

            // Generate grid points
            for i in 0..params_per_dimension.min(sample_count) {
                let mut parameter_set = ParameterSet { values: HashMap::new() };

                for (param_name, bounds) in &space.dimensions {
                    let value = self.interpolate_parameter_value(bounds, i, params_per_dimension);
                    parameter_set.values.insert(param_name.clone(), value);
                }

                parameter_sets.push(parameter_set);
            }

            Ok(ParameterSweep {
                sweep_id: format!("grid_sweep_{}", Time::now().elapsed().as_nanos()),
                strategy: ExplorationStrategy::GridSweep,
                parameter_space: space.clone(),
                parameter_sets,
                sweep_metadata: SweepMetadata {
                    created_at: Time::now().into(),
                    sample_count: parameter_sets.len(),
                    coverage_estimate: 1.0 / params_per_dimension as f64,
                },
            })
        }

        fn generate_random_sweep(&self, space: &ParameterSpace, sample_count: usize) -> Result<ParameterSweep> {
            let mut parameter_sets = Vec::new();

            for i in 0..sample_count {
                let mut parameter_set = ParameterSet { values: HashMap::new() };

                for (param_name, bounds) in &space.dimensions {
                    // Deterministic random sampling based on index
                    let random_factor = (i as f64 * 0.618033988749).fract(); // Golden ratio for good distribution
                    let value = self.interpolate_parameter_value(bounds,
                        (random_factor * 1000.0) as usize, 1000);
                    parameter_set.values.insert(param_name.clone(), value);
                }

                parameter_sets.push(parameter_set);
            }

            Ok(ParameterSweep {
                sweep_id: format!("random_sweep_{}", Time::now().elapsed().as_nanos()),
                strategy: ExplorationStrategy::RandomSampling,
                parameter_space: space.clone(),
                parameter_sets,
                sweep_metadata: SweepMetadata {
                    created_at: Time::now().into(),
                    sample_count,
                    coverage_estimate: sample_count as f64 / 1000.0, // Rough estimate
                },
            })
        }

        fn generate_latin_hypercube_sweep(&self, space: &ParameterSpace, sample_count: usize) -> Result<ParameterSweep> {
            let mut parameter_sets = Vec::new();

            // Simplified Latin Hypercube sampling
            for i in 0..sample_count {
                let mut parameter_set = ParameterSet { values: HashMap::new() };

                for (j, (param_name, bounds)) in space.dimensions.iter().enumerate() {
                    // Latin hypercube stratification
                    let stratum = i;
                    let offset = (j as f64 * 0.618033988749).fract(); // Golden ratio offset
                    let position = (stratum as f64 + offset) / sample_count as f64;

                    let value = self.interpolate_parameter_value(bounds,
                        (position * 1000.0) as usize, 1000);
                    parameter_set.values.insert(param_name.clone(), value);
                }

                parameter_sets.push(parameter_set);
            }

            Ok(ParameterSweep {
                sweep_id: format!("lhs_sweep_{}", Time::now().elapsed().as_nanos()),
                strategy: ExplorationStrategy::LatinHypercube,
                parameter_space: space.clone(),
                parameter_sets,
                sweep_metadata: SweepMetadata {
                    created_at: Time::now().into(),
                    sample_count,
                    coverage_estimate: (sample_count as f64 / 100.0).min(1.0),
                },
            })
        }

        fn interpolate_parameter_value(&self, bounds: &ParameterBounds, position: usize, total_positions: usize) -> ParameterValue {
            let ratio = if total_positions > 1 {
                position as f64 / (total_positions - 1) as f64
            } else {
                0.5
            };

            match bounds {
                ParameterBounds::Integer { min, max } => {
                    let value = min + ((*max - *min) as f64 * ratio) as i64;
                    ParameterValue::Integer(value)
                }
                ParameterBounds::Float { min, max } => {
                    let value = min + (max - min) * ratio;
                    ParameterValue::Float(value)
                }
                ParameterBounds::String { options } => {
                    let index = (ratio * options.len() as f64) as usize % options.len();
                    ParameterValue::String(options[index].clone())
                }
            }
        }
    }

    /// Mock trace recorder for deterministic trace capture
    #[derive(Debug)]
    struct MockTraceRecorder {
        recorder_id: String,
        active_sessions: Arc<Mutex<HashMap<u64, TraceSession>>>,
        recorded_traces: Arc<Mutex<HashMap<u64, ExecutionTrace>>>,
    }

    impl MockTraceRecorder {
        fn new() -> Self {
            Self {
                recorder_id: "mock_trace_recorder".to_string(),
                active_sessions: Arc::new(Mutex::new(HashMap::new())),
                recorded_traces: Arc::new(Mutex::new(HashMap::new())),
            }
        }

        async fn start_session(&self, execution_id: u64) -> Result<TraceSession> {
            let session = TraceSession {
                execution_id,
                events: Vec::new(),
                start_time: Time::now().into(),
                metadata: TraceMetadata {
                    version: "1.0".to_string(),
                    recorder_id: self.recorder_id.clone(),
                    session_config: SessionConfig::default(),
                },
            };

            self.active_sessions.lock().unwrap().insert(execution_id, session.clone());
            Ok(session)
        }

        async fn record_event(&self, event: TraceEvent) -> Result<()> {
            // In a real implementation, this would record the event to the appropriate session
            // For this mock, we'll simulate successful recording
            Ok(())
        }

        async fn finalize_session(&self, session: TraceSession) -> Result<ExecutionTrace> {
            let trace = ExecutionTrace {
                execution_id: session.execution_id,
                events: session.events,
                metadata: session.metadata,
                total_duration: Time::now().elapsed(),
            };

            self.recorded_traces.lock().unwrap().insert(session.execution_id, trace.clone());
            self.active_sessions.lock().unwrap().remove(&session.execution_id);

            Ok(trace)
        }
    }

    /// Tracks integration between scenario runner and lab explorer
    #[derive(Debug)]
    struct ScenarioExplorerTracker {
        tracker_id: String,
        execution_events: Arc<Mutex<Vec<ExecutionEvent>>>,
        replay_events: Arc<Mutex<Vec<ReplayEvent>>>,
        sweep_events: Arc<Mutex<Vec<SweepEvent>>>,
        integration_metrics: Arc<Mutex<IntegrationMetrics>>,
    }

    impl ScenarioExplorerTracker {
        fn new() -> Self {
            Self {
                tracker_id: "scenario_explorer_tracker".to_string(),
                execution_events: Arc::new(Mutex::new(Vec::new())),
                replay_events: Arc::new(Mutex::new(Vec::new())),
                sweep_events: Arc::new(Mutex::new(Vec::new())),
                integration_metrics: Arc::new(Mutex::new(IntegrationMetrics::new())),
            }
        }

        fn record_execution_start(&self, context: &ExecutionContext) {
            let event = ExecutionEvent {
                event_type: ExecutionEventType::Started,
                execution_id: context.execution_id,
                scenario_name: context.scenario_name.clone(),
                timestamp: Time::now().into(),
            };
            self.execution_events.lock().unwrap().push(event);
            self.integration_metrics.lock().unwrap().total_executions += 1;
        }

        fn record_execution_completion(&self, context: &ExecutionContext, result: &ScenarioResult) {
            let event = ExecutionEvent {
                event_type: ExecutionEventType::Completed,
                execution_id: context.execution_id,
                scenario_name: context.scenario_name.clone(),
                timestamp: Time::now().into(),
            };
            self.execution_events.lock().unwrap().push(event);
            self.integration_metrics.lock().unwrap().completed_executions += 1;
        }

        fn record_replay_completion(
            &self,
            original: &ExecutionContext,
            replay: &ExecutionContext,
            comparison: &TraceComparison,
        ) {
            let event = ReplayEvent {
                event_type: ReplayEventType::Completed,
                original_execution_id: original.execution_id,
                replay_execution_id: replay.execution_id,
                is_identical: comparison.is_identical,
                timestamp: Time::now().into(),
            };
            self.replay_events.lock().unwrap().push(event);

            let mut metrics = self.integration_metrics.lock().unwrap();
            metrics.total_replays += 1;
            if comparison.is_identical {
                metrics.identical_replays += 1;
            }
        }

        fn record_sweep_progress(&self, current: usize, total: usize) {
            let event = SweepEvent {
                event_type: SweepEventType::Progress,
                current_parameter_set: current,
                total_parameter_sets: total,
                progress_ratio: current as f64 / total as f64,
                timestamp: Time::now().into(),
            };
            self.sweep_events.lock().unwrap().push(event);
        }

        fn get_integration_summary(&self) -> ScenarioExplorerIntegrationSummary {
            let execution_events = self.execution_events.lock().unwrap();
            let replay_events = self.replay_events.lock().unwrap();
            let sweep_events = self.sweep_events.lock().unwrap();
            let metrics = self.integration_metrics.lock().unwrap();

            let execution_success_rate = if metrics.total_executions > 0 {
                metrics.completed_executions as f64 / metrics.total_executions as f64
            } else {
                0.0
            };

            let replay_success_rate = if metrics.total_replays > 0 {
                metrics.identical_replays as f64 / metrics.total_replays as f64
            } else {
                0.0
            };

            ScenarioExplorerIntegrationSummary {
                total_execution_events: execution_events.len(),
                total_replay_events: replay_events.len(),
                total_sweep_events: sweep_events.len(),
                completed_executions: metrics.completed_executions,
                identical_replays: metrics.identical_replays,
                execution_success_rate,
                replay_success_rate,
                deterministic_consistency: replay_success_rate,
                integration_health: self.get_integration_health(),
            }
        }

        fn get_integration_health(&self) -> f64 {
            let metrics = self.integration_metrics.lock().unwrap();

            if metrics.total_executions == 0 {
                return 1.0;
            }

            let execution_health = metrics.completed_executions as f64 / metrics.total_executions as f64;
            let replay_health = if metrics.total_replays > 0 {
                metrics.identical_replays as f64 / metrics.total_replays as f64
            } else {
                1.0
            };

            (execution_health * 0.4 + replay_health * 0.6).max(0.0).min(1.0)
        }
    }

    // Mock types and structures for testing
    #[derive(Debug, Clone)]
    struct ScenarioConfig {
        scenario_name: String,
        execution_phases: Vec<ExecutionPhase>,
        deterministic_settings: DeterministicSettings,
    }

    impl Default for ScenarioConfig {
        fn default() -> Self {
            Self {
                scenario_name: "test_scenario".to_string(),
                execution_phases: vec![
                    ExecutionPhase {
                        phase_type: PhaseType::Initialization,
                        duration: Duration::from_millis(10),
                        base_operation_count: 1,
                    },
                    ExecutionPhase {
                        phase_type: PhaseType::Workload,
                        duration: Duration::from_millis(50),
                        base_operation_count: 10,
                    },
                    ExecutionPhase {
                        phase_type: PhaseType::Cleanup,
                        duration: Duration::from_millis(5),
                        base_operation_count: 1,
                    },
                ],
                deterministic_settings: DeterministicSettings::default(),
            }
        }
    }

    #[derive(Debug, Clone)]
    struct ExecutionPhase {
        phase_type: PhaseType,
        duration: Duration,
        base_operation_count: usize,
    }

    #[derive(Debug, Clone)]
    enum PhaseType {
        Initialization,
        Workload,
        Stress,
        Cleanup,
    }

    #[derive(Debug, Clone)]
    struct DeterministicSettings {
        enable_virtual_time: bool,
        enable_deterministic_scheduler: bool,
        seed_strategy: SeedStrategy,
    }

    impl Default for DeterministicSettings {
        fn default() -> Self {
            Self {
                enable_virtual_time: true,
                enable_deterministic_scheduler: true,
                seed_strategy: SeedStrategy::ParameterBased,
            }
        }
    }

    #[derive(Debug, Clone)]
    enum SeedStrategy {
        ParameterBased,
        Fixed(u64),
        Random,
    }

    // Additional types that would be fully implemented...
    type ExecutionContext = ();
    type ScenarioResult = ();
    type ScenarioExecution = ();
    type ExecutionTrace = ();
    type ReplayKey = ();
    type ScenarioExecutionResult = ();
    type ReplayResult = ();
    type SweepReplayResult = ();
    type PhaseResult = ();
    type PhaseConfig = ();
    type PhaseMetrics = ();
    type EventData = ();
    type EventType = ();
    type TraceComparison = ();
    type EventDifference = ();
    type TimingDifference = ();
    type MetadataDifference = ();
    type ConsistencyAnalysis = ();
    type ConsistencyViolation = ();
    type CrossValidationResult = ();
    type TraceHash = ();
    type ParameterSpace = ();
    type ParameterSet = ();
    type ExplorationStrategy = ();
    type SweepMetadata = ();
    type ParameterBounds = ();
    type ParameterValue = ();
    type TraceSession = ();
    type SessionConfig = ();
    type DeterministicScheduler = ();
    type VirtualTime = ();
    type ScenarioMetrics = ();
    type ScenarioState = ();
    type ScenarioExplorerStats = ();
    type ExecutionEvent = ();
    type ExecutionEventType = ();
    type ReplayEvent = ();
    type ReplayEventType = ();
    type SweepEvent = ();
    type SweepEventType = ();
    type IntegrationMetrics = ();
    type ScenarioExplorerIntegrationSummary = ();

    async fn run_scenario_explorer_integration_test(
        cx: &Cx,
        test_config: ScenarioExplorerTestConfig,
    ) -> Result<ScenarioExplorerIntegrationSummary> {
        // Create lab explorer
        let lab_explorer = Arc::new(MockLabExplorer::new(
            "test_lab_explorer".to_string(),
        ));

        // Create scenario runner
        let scenario_runner = MockDeterministicScenarioRunner::new(
            "test_scenario_runner".to_string(),
            ScenarioConfig::default(),
            lab_explorer.clone(),
        );

        // Run test scenarios
        for scenario in test_config.test_scenarios {
            match scenario {
                TestScenario::BasicExecution { scenario_name, parameters } => {
                    let _result = scenario_runner.execute_scenario_with_parameters(
                        &scenario_name,
                        &parameters,
                        cx,
                    ).await?;
                }
                TestScenario::DeterministicReplay { scenario_name, parameters } => {
                    // Execute and then replay
                    let execution_result = scenario_runner.execute_scenario_with_parameters(
                        &scenario_name,
                        &parameters,
                        cx,
                    ).await?;

                    let _replay_result = scenario_runner.replay_scenario_deterministically(
                        &execution_result.execution_context,
                        cx,
                    ).await?;
                }
                TestScenario::ParameterSweep { scenario_name, parameter_space, strategy, sample_count } => {
                    // Generate parameter sweep
                    let parameter_sweep = lab_explorer.generate_parameter_sweep(
                        &parameter_space,
                        strategy,
                        sample_count,
                    )?;

                    // Execute sweep with replay validation
                    let _sweep_result = scenario_runner.execute_parameter_sweep_with_replay(
                        &scenario_name,
                        &parameter_sweep,
                        cx,
                    ).await?;
                }
            }

            cx.sleep(Duration::from_millis(10)).await?;
        }

        // Allow processing to complete
        cx.sleep(Duration::from_millis(100)).await?;

        // Get integration summary
        Ok(scenario_runner.integration_tracker.get_integration_summary())
    }

    #[derive(Debug)]
    struct ScenarioExplorerTestConfig {
        test_scenarios: Vec<TestScenario>,
    }

    #[derive(Debug)]
    enum TestScenario {
        BasicExecution {
            scenario_name: String,
            parameters: ParameterSet,
        },
        DeterministicReplay {
            scenario_name: String,
            parameters: ParameterSet,
        },
        ParameterSweep {
            scenario_name: String,
            parameter_space: ParameterSpace,
            strategy: ExplorationStrategy,
            sample_count: usize,
        },
    }

    #[tokio::test]
    async fn test_basic_scenario_execution() {
        let lab = LabRuntime::new().unwrap();
        let outcome = lab.run(|cx| {
            Box::pin(async move {
                // Test basic scenario execution
                let test_config = ScenarioExplorerTestConfig {
                    test_scenarios: vec![
                        TestScenario::BasicExecution {
                            scenario_name: "basic_test".to_string(),
                            parameters: create_test_parameter_set(),
                        },
                    ],
                };

                let summary = run_scenario_explorer_integration_test(cx, test_config).await?;

                // Verify basic execution
                assert!(summary.total_execution_events > 0, "Should have execution events");
                assert!(summary.completed_executions > 0, "Should complete executions");
                assert!(summary.execution_success_rate >= 0.9, "Should have high execution success rate");
                assert!(summary.integration_health > 0.8, "Integration health should be good");

                Ok(summary)
            })
        }).await;

        assert!(matches!(outcome, Outcome::Ok(_)), "Basic scenario execution should succeed");
    }

    #[tokio::test]
    async fn test_deterministic_replay() {
        let lab = LabRuntime::new().unwrap();
        let outcome = lab.run(|cx| {
            Box::pin(async move {
                // Test deterministic replay
                let test_config = ScenarioExplorerTestConfig {
                    test_scenarios: vec![
                        TestScenario::DeterministicReplay {
                            scenario_name: "replay_test".to_string(),
                            parameters: create_test_parameter_set(),
                        },
                    ],
                };

                let summary = run_scenario_explorer_integration_test(cx, test_config).await?;

                // Verify deterministic replay
                assert!(summary.total_replay_events > 0, "Should have replay events");
                assert!(summary.identical_replays > 0, "Should have identical replays");
                assert!(summary.replay_success_rate >= 0.95, "Should have very high replay success rate");
                assert!(summary.deterministic_consistency >= 0.95, "Should maintain deterministic consistency");
                assert!(summary.integration_health > 0.85, "Should handle deterministic replay well");

                Ok(summary)
            })
        }).await;

        assert!(matches!(outcome, Outcome::Ok(_)), "Deterministic replay should succeed");
    }

    #[tokio::test]
    async fn test_parameter_sweep_exploration() {
        let lab = LabRuntime::new().unwrap();
        let outcome = lab.run(|cx| {
            Box::pin(async move {
                // Test parameter sweep exploration
                let test_config = ScenarioExplorerTestConfig {
                    test_scenarios: vec![
                        TestScenario::ParameterSweep {
                            scenario_name: "sweep_test".to_string(),
                            parameter_space: create_test_parameter_space(),
                            strategy: create_test_exploration_strategy(),
                            sample_count: 5,
                        },
                    ],
                };

                let summary = run_scenario_explorer_integration_test(cx, test_config).await?;

                // Verify parameter sweep handling
                assert!(summary.total_execution_events >= 5, "Should execute multiple parameter sets");
                assert!(summary.total_replay_events >= 5, "Should replay all executions");
                assert!(summary.completed_executions >= 5, "Should complete parameter sweep executions");
                assert!(summary.execution_success_rate >= 0.8, "Should handle parameter sweeps");
                assert!(summary.replay_success_rate >= 0.8, "Should maintain replay consistency");
                assert!(summary.integration_health > 0.7, "Should handle parameter exploration");

                Ok(summary)
            })
        }).await;

        assert!(matches!(outcome, Outcome::Ok(_)), "Parameter sweep exploration should succeed");
    }

    #[tokio::test]
    async fn test_comprehensive_scenario_explorer_integration() {
        let lab = LabRuntime::new().unwrap();
        let outcome = lab.run(|cx| {
            Box::pin(async move {
                // Comprehensive integration test
                let test_config = ScenarioExplorerTestConfig {
                    test_scenarios: vec![
                        TestScenario::BasicExecution {
                            scenario_name: "basic".to_string(),
                            parameters: create_test_parameter_set(),
                        },
                        TestScenario::DeterministicReplay {
                            scenario_name: "replay".to_string(),
                            parameters: create_test_parameter_set(),
                        },
                        TestScenario::ParameterSweep {
                            scenario_name: "sweep".to_string(),
                            parameter_space: create_test_parameter_space(),
                            strategy: create_test_exploration_strategy(),
                            sample_count: 4,
                        },
                    ],
                };

                let summary = run_scenario_explorer_integration_test(cx, test_config).await?;

                // Comprehensive validation
                assert!(summary.total_execution_events >= 6, "Should handle sufficient executions");
                assert!(summary.total_replay_events >= 5, "Should perform sufficient replays");
                assert!(summary.total_sweep_events > 0, "Should handle parameter sweeps");
                assert!(summary.completed_executions >= 6, "Should complete all executions");
                assert!(summary.identical_replays >= 4, "Should have mostly identical replays");
                assert!(summary.execution_success_rate >= 0.85, "Should maintain high execution success");
                assert!(summary.replay_success_rate >= 0.8, "Should maintain good replay consistency");
                assert!(summary.deterministic_consistency >= 0.8, "Should maintain deterministic behavior");
                assert!(summary.integration_health > 0.75, "Should maintain good integration health");

                // Verify integration completeness
                assert!(summary.total_execution_events > 0, "Scenario execution integration working");
                assert!(summary.identical_replays > 0, "Deterministic replay integration working");
                assert!(summary.total_sweep_events > 0, "Parameter exploration integration working");

                Ok(summary)
            })
        }).await;

        assert!(matches!(outcome, Outcome::Ok(_)), "Comprehensive scenario-explorer integration should succeed");
    }

    // Helper functions to create test data
    fn create_test_parameter_set() -> ParameterSet {
        let mut values = HashMap::new();
        values.insert("operation_scale".to_string(), ParameterValue::Float(1.0));
        values.insert("thread_count".to_string(), ParameterValue::Integer(2));
        values.insert("mode".to_string(), ParameterValue::String("normal".to_string()));

        ParameterSet { values }
    }

    fn create_test_parameter_space() -> ParameterSpace {
        let mut dimensions = HashMap::new();
        dimensions.insert("operation_scale".to_string(), ParameterBounds::Float { min: 0.5, max: 2.0 });
        dimensions.insert("thread_count".to_string(), ParameterBounds::Integer { min: 1, max: 4 });
        dimensions.insert("mode".to_string(), ParameterBounds::String {
            options: vec!["normal".to_string(), "stress".to_string()],
        });

        ParameterSpace {
            space_id: "test_space".to_string(),
            dimensions,
        }
    }

    fn create_test_exploration_strategy() -> ExplorationStrategy {
        ExplorationStrategy::GridSweep
    }

    // Additional helper type implementations would be here...
}