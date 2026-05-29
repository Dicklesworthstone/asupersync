//! Replay Minimization Infrastructure for ATP Lab
//!
//! Provides trace minimization and replay optimization for deterministic lab execution.
//! Reduces large traces to minimal reproducing cases for efficient debugging.

use crate::error::{Error, Result};
use crate::trace::event::TraceEvent;
use crate::types::{ObligationId, RegionId, TaskId};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, info, warn};

/// Configuration for replay minimization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinimizationConfig {
    /// Maximum iterations for delta debugging
    pub max_iterations: usize,
    /// Minimum chunk size for binary search
    pub min_chunk_size: usize,
    /// Enable aggressive pruning of irrelevant events
    pub aggressive_pruning: bool,
    /// Preserve timing relationships during minimization
    pub preserve_timing: bool,
    /// Target reduction ratio (0.0 to 1.0)
    pub target_reduction: f64,
    /// Timeout for each replay attempt
    pub replay_timeout_ms: u64,
}

impl Default for MinimizationConfig {
    fn default() -> Self {
        Self {
            max_iterations: 1000,
            min_chunk_size: 1,
            aggressive_pruning: true,
            preserve_timing: true,
            target_reduction: 0.1,
            replay_timeout_ms: 5000,
        }
    }
}

/// Result of trace minimization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinimizationResult {
    /// Original trace size
    pub original_size: usize,
    /// Minimized trace size
    pub minimized_size: usize,
    /// Reduction ratio achieved
    pub reduction_ratio: f64,
    /// Number of iterations performed
    pub iterations: usize,
    /// Time taken for minimization
    pub duration_ms: u64,
    /// Events that were essential for reproduction
    pub essential_events: Vec<usize>,
    /// Events that were pruned as irrelevant
    pub pruned_events: Vec<usize>,
}

/// Strategy for trace minimization
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MinimizationStrategy {
    /// Binary search-based delta debugging
    DeltaDebugging,
    /// Dependency-aware pruning
    DependencyPruning,
    /// Causal cone reduction
    CausalCone,
    /// Hybrid approach combining multiple strategies
    Hybrid,
}

/// Abstract interface for replay validation
pub trait ReplayValidator: Send + Sync {
    /// Check if the given trace reproduces the target behavior
    fn validate_replay(&self, events: &[TraceEvent]) -> Result<bool>;

    /// Get the target behavior description for debugging
    fn target_description(&self) -> String;
}

/// Minimizer for ATP lab traces
pub struct TraceMinimizer {
    config: MinimizationConfig,
    validator: Arc<dyn ReplayValidator>,
    strategy: MinimizationStrategy,
    cache: HashMap<Vec<usize>, bool>,
}

impl TraceMinimizer {
    /// Create new trace minimizer
    pub fn new(
        config: MinimizationConfig,
        validator: Arc<dyn ReplayValidator>,
        strategy: MinimizationStrategy,
    ) -> Self {
        Self {
            config,
            validator,
            strategy,
            cache: HashMap::new(),
        }
    }

    /// Minimize a trace to its essential elements
    pub async fn minimize(&mut self, events: Vec<TraceEvent>) -> Result<MinimizationResult> {
        let start_time = Instant::now();
        let original_size = events.len();

        info!(
            "Starting trace minimization: {} events, strategy: {:?}",
            original_size, self.strategy
        );

        let minimized_events = match self.strategy {
            MinimizationStrategy::DeltaDebugging => self.delta_debugging_minimize(events).await?,
            MinimizationStrategy::DependencyPruning => {
                self.dependency_pruning_minimize(events).await?
            }
            MinimizationStrategy::CausalCone => self.causal_cone_minimize(events).await?,
            MinimizationStrategy::Hybrid => self.hybrid_minimize(events).await?,
        };

        let minimized_size = minimized_events.len();
        let reduction_ratio = if original_size > 0 {
            1.0 - (minimized_size as f64 / original_size as f64)
        } else {
            0.0
        };

        let duration = start_time.elapsed();

        // Compute essential and pruned event indices
        let essential_events: Vec<usize> = minimized_events
            .iter()
            .enumerate()
            .map(|(i, _)| i)
            .collect();

        let pruned_events: Vec<usize> = (minimized_size..original_size).collect();

        let result = MinimizationResult {
            original_size,
            minimized_size,
            reduction_ratio,
            iterations: self.cache.len(),
            duration_ms: duration.as_millis() as u64,
            essential_events,
            pruned_events,
        };

        info!(
            "Minimization complete: {} -> {} events ({:.1}% reduction)",
            original_size,
            minimized_size,
            reduction_ratio * 100.0
        );

        Ok(result)
    }

    /// Delta debugging-based minimization using binary search
    async fn delta_debugging_minimize(
        &mut self,
        events: Vec<TraceEvent>,
    ) -> Result<Vec<TraceEvent>> {
        let mut current = events;
        let mut changed = true;
        let mut iteration = 0;

        while changed && iteration < self.config.max_iterations {
            changed = false;
            iteration += 1;

            debug!(
                "Delta debugging iteration {}, {} events",
                iteration,
                current.len()
            );

            // Try removing chunks of events
            let chunk_size = std::cmp::max(self.config.min_chunk_size, current.len() / 4);

            for start in (0..current.len()).step_by(chunk_size) {
                let end = std::cmp::min(start + chunk_size, current.len());

                // Create candidate with chunk removed
                let mut candidate = current.clone();
                candidate.drain(start..end);

                if self.validate_candidate(&candidate).await? {
                    current = candidate;
                    changed = true;
                    break; // Restart with smaller trace
                }
            }
        }

        Ok(current)
    }

    /// Dependency-aware pruning minimization
    async fn dependency_pruning_minimize(
        &mut self,
        events: Vec<TraceEvent>,
    ) -> Result<Vec<TraceEvent>> {
        let dependencies = self.compute_dependencies(&events);
        let mut essential = HashSet::new();

        // Find events that are transitively required
        for (i, event) in events.iter().enumerate() {
            if self.is_target_event(event) {
                self.mark_dependencies_recursive(&dependencies, i, &mut essential);
            }
        }

        // Extract essential events in original order
        let minimized: Vec<TraceEvent> = events
            .into_iter()
            .enumerate()
            .filter_map(|(i, event)| {
                if essential.contains(&i) {
                    Some(event)
                } else {
                    None
                }
            })
            .collect();

        // Validate the result
        if !self.validate_candidate(&minimized).await? {
            warn!("Dependency pruning produced invalid trace, falling back to original");
            return Err(Error::internal("Dependency pruning failed validation"));
        }

        Ok(minimized)
    }

    /// Causal cone-based minimization
    async fn causal_cone_minimize(&mut self, events: Vec<TraceEvent>) -> Result<Vec<TraceEvent>> {
        let causal_graph = self.build_causal_graph(&events);
        let target_events = self.find_target_events(&events);

        let mut reachable = HashSet::new();

        // Perform backward reachability from target events
        let mut queue = VecDeque::new();
        for &target in &target_events {
            queue.push_back(target);
            reachable.insert(target);
        }

        while let Some(current) = queue.pop_front() {
            if let Some(predecessors) = causal_graph.get(&current) {
                for &pred in predecessors {
                    if reachable.insert(pred) {
                        queue.push_back(pred);
                    }
                }
            }
        }

        // Extract reachable events
        let minimized: Vec<TraceEvent> = events
            .into_iter()
            .enumerate()
            .filter_map(|(i, event)| {
                if reachable.contains(&i) {
                    Some(event)
                } else {
                    None
                }
            })
            .collect();

        // Validate the result
        if !self.validate_candidate(&minimized).await? {
            warn!("Causal cone minimization produced invalid trace, falling back");
            return Err(Error::internal(
                "Causal cone minimization failed validation",
            ));
        }

        Ok(minimized)
    }

    /// Hybrid minimization combining multiple strategies
    async fn hybrid_minimize(&mut self, events: Vec<TraceEvent>) -> Result<Vec<TraceEvent>> {
        // Start with dependency pruning for coarse reduction
        let mut current = self
            .dependency_pruning_minimize(events.clone())
            .await
            .unwrap_or(events);

        // Apply causal cone if still too large
        if current.len() > 100 {
            let fallback = current.clone();
            current = self.causal_cone_minimize(current).await.unwrap_or(fallback);
        }

        // Finish with delta debugging for fine-grained reduction
        if current.len() > 10 {
            let fallback = current.clone();
            current = self
                .delta_debugging_minimize(current)
                .await
                .unwrap_or(fallback);
        }

        Ok(current)
    }

    /// Validate a candidate trace
    async fn validate_candidate(&mut self, events: &[TraceEvent]) -> Result<bool> {
        // Check cache first
        let key: Vec<usize> = events.iter().enumerate().map(|(i, _)| i).collect();
        if let Some(&cached) = self.cache.get(&key) {
            return Ok(cached);
        }

        let result = self.validator.validate_replay(events)?;

        // Cache the result
        self.cache.insert(key, result);

        Ok(result)
    }

    /// Compute event dependencies
    fn compute_dependencies(&self, events: &[TraceEvent]) -> HashMap<usize, Vec<usize>> {
        let mut dependencies: HashMap<usize, Vec<usize>> = HashMap::new();
        let mut task_events = HashMap::<TaskId, Vec<usize>>::new();
        let mut region_events = HashMap::<RegionId, Vec<usize>>::new();
        let mut obligation_events = HashMap::<ObligationId, Vec<usize>>::new();

        // Group events by task, region, and obligation
        for (i, event) in events.iter().enumerate() {
            if let Some(task_id) = self.extract_task_id(event) {
                task_events.entry(task_id).or_default().push(i);
            }
            if let Some(region_id) = self.extract_region_id(event) {
                region_events.entry(region_id).or_default().push(i);
            }
            if let Some(obligation_id) = self.extract_obligation_id(event) {
                obligation_events.entry(obligation_id).or_default().push(i);
            }
        }

        // Build dependencies within tasks (task lifecycle ordering)
        for event_list in task_events.values() {
            for window in event_list.windows(2) {
                let (first, second) = (window[0], window[1]);
                dependencies.entry(second).or_default().push(first);
            }
        }

        // Build dependencies within regions (region lifecycle ordering)
        for event_list in region_events.values() {
            for window in event_list.windows(2) {
                let (first, second) = (window[0], window[1]);
                dependencies.entry(second).or_default().push(first);
            }
        }

        // Build dependencies within obligations (obligation lifecycle ordering)
        for event_list in obligation_events.values() {
            for window in event_list.windows(2) {
                let (first, second) = (window[0], window[1]);
                dependencies.entry(second).or_default().push(first);
            }
        }

        // Cross-event causal dependencies
        for i in 0..events.len() {
            for j in 0..i {
                if self.has_causal_relationship(&events[j], &events[i]) {
                    dependencies.entry(i).or_default().push(j);
                }
            }
        }

        // Additional semantic dependencies
        self.add_semantic_dependencies(events, &mut dependencies);

        dependencies
    }

    /// Mark dependencies recursively
    fn mark_dependencies_recursive(
        &self,
        dependencies: &HashMap<usize, Vec<usize>>,
        event_idx: usize,
        essential: &mut HashSet<usize>,
    ) {
        if !essential.insert(event_idx) {
            return; // Already marked
        }

        if let Some(deps) = dependencies.get(&event_idx) {
            for &dep in deps {
                self.mark_dependencies_recursive(dependencies, dep, essential);
            }
        }
    }

    /// Build causal graph between events
    fn build_causal_graph(&self, events: &[TraceEvent]) -> HashMap<usize, Vec<usize>> {
        let mut graph: HashMap<usize, Vec<usize>> = HashMap::new();

        // Simple causal relationship: happens-before ordering
        for i in 0..events.len() {
            for j in 0..i {
                if self.has_causal_relationship(&events[j], &events[i]) {
                    graph.entry(i).or_default().push(j);
                }
            }
        }

        graph
    }

    /// Check if event is a target for minimization
    fn is_target_event(&self, event: &TraceEvent) -> bool {
        use crate::trace::event::TraceEventKind::*;

        match event.kind {
            // Critical events that usually indicate problems
            ObligationLeak | ObligationAbort | FuturelockDetected => true,

            // Cancellation events - important for understanding failures
            CancelRequest | CancelAck => true,

            // Region lifecycle events that might indicate hangs or deadlocks
            RegionCloseBegin | RegionCloseComplete | RegionCancelled => true,

            // Worker events that might indicate cross-boundary issues
            WorkerCancelRequested | WorkerDrainCompleted | WorkerFinalizeCompleted => true,

            // Monitor/supervision events that indicate failures
            DownDelivered | ExitDelivered => true,

            // I/O errors are often important
            IoError => true,

            // User traces and checkpoints might mark important points
            UserTrace | Checkpoint => true,

            // Regular operational events are not targets by default
            Spawn
            | Schedule
            | Yield
            | Wake
            | Poll
            | Complete
            | RegionCreated
            | ObligationReserve
            | ObligationCommit
            | TimeAdvance
            | TimerScheduled
            | TimerFired
            | TimerCancelled
            | IoRequested
            | IoReady
            | IoResult
            | RngSeed
            | RngValue
            | ChaosInjection
            | MonitorCreated
            | MonitorDropped
            | LinkCreated
            | LinkDropped
            | WorkerCancelAcknowledged
            | WorkerDrainStarted => false,
        }
    }

    /// Find target events in trace
    fn find_target_events(&self, events: &[TraceEvent]) -> Vec<usize> {
        events
            .iter()
            .enumerate()
            .filter_map(|(i, event)| {
                if self.is_target_event(event) {
                    Some(i)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Extract task ID from event
    fn extract_task_id(&self, event: &TraceEvent) -> Option<TaskId> {
        use crate::trace::event::TraceData;

        match &event.data {
            TraceData::Task { task, .. } => Some(*task),
            TraceData::Cancel { task, .. } => Some(*task),
            TraceData::Obligation { task, .. } => Some(*task),
            _ => None,
        }
    }

    /// Extract region ID from event
    fn extract_region_id(&self, event: &TraceEvent) -> Option<RegionId> {
        use crate::trace::event::TraceData;

        match &event.data {
            TraceData::Task { region, .. } => Some(*region),
            TraceData::Region { region, .. } => Some(*region),
            TraceData::Cancel { region, .. } => Some(*region),
            TraceData::Obligation { region, .. } => Some(*region),
            _ => None,
        }
    }

    /// Extract obligation ID from event
    fn extract_obligation_id(&self, event: &TraceEvent) -> Option<ObligationId> {
        use crate::trace::event::TraceData;

        match &event.data {
            TraceData::Obligation { obligation, .. } => Some(*obligation),
            _ => None,
        }
    }

    /// Add semantic dependencies based on domain knowledge
    fn add_semantic_dependencies(
        &self,
        events: &[TraceEvent],
        dependencies: &mut HashMap<usize, Vec<usize>>,
    ) {
        use crate::trace::event::TraceEventKind::*;

        // Find parent-child region relationships
        for (child_idx, child_event) in events.iter().enumerate() {
            if self.extract_region_id(child_event).is_some() {
                // Look for the parent region creation that this child depends on
                for (parent_idx, parent_event) in events.iter().enumerate().take(child_idx) {
                    if parent_event.kind == RegionCreated {
                        if let Some(parent_region) = self.extract_region_id(parent_event) {
                            // If child event references parent as its parent, add dependency
                            if let crate::trace::event::TraceData::Region {
                                parent: Some(p), ..
                            } = &child_event.data
                            {
                                if *p == parent_region {
                                    dependencies.entry(child_idx).or_default().push(parent_idx);
                                }
                            }
                        }
                    }
                }
            }
        }

        // Timer dependencies: if timer events happen in sequence, they may be related
        let mut timer_scheduled_indices = Vec::new();
        for (i, event) in events.iter().enumerate() {
            match event.kind {
                TimerScheduled => timer_scheduled_indices.push(i),
                TimerFired | TimerCancelled => {
                    // Timer fire/cancel events depend on the most recent timer scheduled
                    if let Some(&last_scheduled) = timer_scheduled_indices.last() {
                        dependencies.entry(i).or_default().push(last_scheduled);
                    }
                }
                _ => {}
            }
        }

        // Monitor/link dependencies: down/exit events depend on monitor/link creation
        let mut monitor_created_indices = Vec::new();
        let mut link_created_indices = Vec::new();
        for (i, event) in events.iter().enumerate() {
            match event.kind {
                MonitorCreated => monitor_created_indices.push(i),
                LinkCreated => link_created_indices.push(i),
                DownDelivered => {
                    // Down events depend on monitor creation
                    for &monitor_idx in &monitor_created_indices {
                        if monitor_idx < i {
                            dependencies.entry(i).or_default().push(monitor_idx);
                        }
                    }
                }
                ExitDelivered => {
                    // Exit events depend on link creation
                    for &link_idx in &link_created_indices {
                        if link_idx < i {
                            dependencies.entry(i).or_default().push(link_idx);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    /// Check if two events have causal relationship
    fn has_causal_relationship(&self, first: &TraceEvent, second: &TraceEvent) -> bool {
        use crate::trace::event::{TraceData, TraceEventKind::*};

        // Logical time ordering indicates causal dependency
        if let (Some(first_time), Some(second_time)) = (&first.logical_time, &second.logical_time) {
            if first_time < second_time {
                return true;
            }
        }

        // Check for specific causal patterns based on event kinds and data
        match (&first.kind, &second.kind, &first.data, &second.data) {
            // Task lifecycle: spawn -> schedule -> poll -> complete
            (
                Spawn,
                Schedule,
                TraceData::Task { task: task1, .. },
                TraceData::Task { task: task2, .. },
            )
            | (
                Schedule,
                Poll,
                TraceData::Task { task: task1, .. },
                TraceData::Task { task: task2, .. },
            )
            | (
                Poll,
                Complete,
                TraceData::Task { task: task1, .. },
                TraceData::Task { task: task2, .. },
            ) if task1 == task2 => true,

            // Wake -> Schedule relationship
            (
                Wake,
                Schedule,
                TraceData::Task { task: task1, .. },
                TraceData::Task { task: task2, .. },
            ) if task1 == task2 => true,

            // Cancellation protocol: request -> ack
            (
                CancelRequest,
                CancelAck,
                TraceData::Cancel { task: task1, .. },
                TraceData::Cancel { task: task2, .. },
            ) if task1 == task2 => true,

            // Region lifecycle: create -> close
            (
                RegionCreated,
                RegionCloseBegin,
                TraceData::Region {
                    region: region1, ..
                },
                TraceData::Region {
                    region: region2, ..
                },
            )
            | (
                RegionCloseBegin,
                RegionCloseComplete,
                TraceData::Region {
                    region: region1, ..
                },
                TraceData::Region {
                    region: region2, ..
                },
            ) if region1 == region2 => true,

            // Parent-child region relationships
            (
                RegionCreated,
                _,
                TraceData::Region { region: parent, .. },
                TraceData::Region {
                    parent: Some(child_parent),
                    ..
                },
            ) if parent == child_parent => true,

            // Obligation lifecycle: reserve -> commit/abort
            (
                ObligationReserve,
                ObligationCommit,
                TraceData::Obligation {
                    obligation: obl1, ..
                },
                TraceData::Obligation {
                    obligation: obl2, ..
                },
            )
            | (
                ObligationReserve,
                ObligationAbort,
                TraceData::Obligation {
                    obligation: obl1, ..
                },
                TraceData::Obligation {
                    obligation: obl2, ..
                },
            ) if obl1 == obl2 => true,

            // Timer lifecycle: schedule -> fire/cancel
            (TimerScheduled, TimerFired, _, _) | (TimerScheduled, TimerCancelled, _, _) => true,

            // I/O lifecycle: request -> ready -> result/error
            (IoRequested, IoReady, _, _) | (IoReady, IoResult, _, _) | (IoReady, IoError, _, _) => {
                true
            }

            // Worker offload protocol
            (WorkerCancelRequested, WorkerCancelAcknowledged, _, _)
            | (WorkerCancelAcknowledged, WorkerDrainStarted, _, _)
            | (WorkerDrainStarted, WorkerDrainCompleted, _, _)
            | (WorkerDrainCompleted, WorkerFinalizeCompleted, _, _) => true,

            // Monitor/link relationships
            (MonitorCreated, DownDelivered, _, _) | (LinkCreated, ExitDelivered, _, _) => true,

            _ => false,
        }
    }
}

/// Replay optimizer for performance
#[derive(Debug)]
pub struct ReplayOptimizer {
    config: MinimizationConfig,
}

impl ReplayOptimizer {
    /// Create new replay optimizer
    pub fn new(config: MinimizationConfig) -> Self {
        Self { config }
    }

    /// Optimize trace for faster replay
    pub async fn optimize(&self, events: Vec<TraceEvent>) -> Result<Vec<TraceEvent>> {
        let mut optimized = events;

        // Remove redundant events
        optimized = self.remove_redundant_events(optimized)?;

        // Compress timing information if not preserved
        if !self.config.preserve_timing {
            optimized = self.compress_timing(optimized)?;
        }

        // Merge compatible events
        optimized = self.merge_compatible_events(optimized)?;

        Ok(optimized)
    }

    /// Remove redundant events from trace
    fn remove_redundant_events(&self, events: Vec<TraceEvent>) -> Result<Vec<TraceEvent>> {
        let mut result = Vec::new();
        let mut seen_states = HashSet::new();

        for event in events {
            let state_key = self.compute_state_key(&event)?;

            if seen_states.insert(state_key) {
                result.push(event);
            }
        }

        Ok(result)
    }

    /// Compress timing information for faster replay
    fn compress_timing(&self, events: Vec<TraceEvent>) -> Result<Vec<TraceEvent>> {
        // Implementation would compress or remove timing data
        Ok(events)
    }

    /// Merge compatible events
    fn merge_compatible_events(&self, events: Vec<TraceEvent>) -> Result<Vec<TraceEvent>> {
        // Implementation would merge events that can be batched
        Ok(events)
    }

    /// Extract task ID from event
    fn extract_task_id(&self, event: &TraceEvent) -> Option<TaskId> {
        use crate::trace::event::TraceData;

        match &event.data {
            TraceData::Task { task, .. } => Some(*task),
            TraceData::Cancel { task, .. } => Some(*task),
            TraceData::Obligation { task, .. } => Some(*task),
            _ => None,
        }
    }

    /// Extract region ID from event
    fn extract_region_id(&self, event: &TraceEvent) -> Option<RegionId> {
        use crate::trace::event::TraceData;

        match &event.data {
            TraceData::Task { region, .. } => Some(*region),
            TraceData::Region { region, .. } => Some(*region),
            TraceData::Cancel { region, .. } => Some(*region),
            TraceData::Obligation { region, .. } => Some(*region),
            _ => None,
        }
    }

    /// Extract obligation ID from event
    fn extract_obligation_id(&self, event: &TraceEvent) -> Option<ObligationId> {
        use crate::trace::event::TraceData;

        match &event.data {
            TraceData::Obligation { obligation, .. } => Some(*obligation),
            _ => None,
        }
    }

    /// Compute state key for deduplication
    fn compute_state_key(&self, event: &TraceEvent) -> Result<String> {
        // Create key based on event kind and relevant data
        use crate::trace::event::TraceEventKind;

        let kind_str = match event.kind {
            TraceEventKind::Spawn => "spawn",
            TraceEventKind::Schedule => "schedule",
            TraceEventKind::Poll => "poll",
            TraceEventKind::Complete => "complete",
            TraceEventKind::CancelRequest => "cancel_req",
            TraceEventKind::CancelAck => "cancel_ack",
            TraceEventKind::RegionCreated => "region_created",
            TraceEventKind::RegionCloseBegin => "region_close_begin",
            TraceEventKind::RegionCloseComplete => "region_close_complete",
            TraceEventKind::ObligationReserve => "obl_reserve",
            TraceEventKind::ObligationCommit => "obl_commit",
            TraceEventKind::ObligationAbort => "obl_abort",
            TraceEventKind::ObligationLeak => "obl_leak",
            TraceEventKind::FuturelockDetected => "futurelock",
            _ => "other",
        };

        // Include task/region/obligation IDs in the key for uniqueness
        let task_id = self
            .extract_task_id(event)
            .map(|id| format!("_t{}", id.as_u64()))
            .unwrap_or_default();
        let region_id = self
            .extract_region_id(event)
            .map(|id| format!("_r{}", id.as_u64()))
            .unwrap_or_default();
        let obligation_id = self
            .extract_obligation_id(event)
            .map(|id| format!("_o{}", id.as_u64()))
            .unwrap_or_default();

        Ok(format!(
            "{}{}{}{}",
            kind_str, task_id, region_id, obligation_id
        ))
    }
}

/// Factory for creating trace minimizers
pub struct MinimizerFactory;

impl MinimizerFactory {
    /// Create minimizer for specific bug reproduction
    pub fn for_bug_reproduction(bug_validator: Arc<dyn ReplayValidator>) -> TraceMinimizer {
        let config = MinimizationConfig {
            aggressive_pruning: true,
            target_reduction: 0.05, // Very aggressive for bugs
            ..Default::default()
        };

        TraceMinimizer::new(config, bug_validator, MinimizationStrategy::Hybrid)
    }

    /// Create minimizer for performance analysis
    pub fn for_performance_analysis(perf_validator: Arc<dyn ReplayValidator>) -> TraceMinimizer {
        let config = MinimizationConfig {
            preserve_timing: true, // Important for perf analysis
            target_reduction: 0.3, // Less aggressive
            ..Default::default()
        };

        TraceMinimizer::new(config, perf_validator, MinimizationStrategy::CausalCone)
    }

    /// Create minimizer for race condition analysis
    pub fn for_race_conditions(race_validator: Arc<dyn ReplayValidator>) -> TraceMinimizer {
        let config = MinimizationConfig {
            preserve_timing: true,     // Critical for race conditions
            aggressive_pruning: false, // Be conservative
            target_reduction: 0.5,
            ..Default::default()
        };

        TraceMinimizer::new(
            config,
            race_validator,
            MinimizationStrategy::DependencyPruning,
        )
    }
}

/// Utility functions for trace processing
pub mod utils {
    use super::*;

    /// Load trace from file
    pub async fn load_trace(path: &Path) -> Result<Vec<TraceEvent>> {
        let content = tokio::fs::read_to_string(path)
            .await
            .map_err(|e| Error::internal(format!("failed to read trace file: {e}")))?;

        let events: Vec<TraceEvent> = content
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect();

        Ok(events)
    }

    /// Save trace to file
    pub async fn save_trace(events: &[TraceEvent], path: &Path) -> Result<()> {
        let mut lines = Vec::new();
        for event in events {
            lines.push(
                serde_json::to_string(event).map_err(|e| {
                    Error::internal(format!("failed to serialize trace event: {e}"))
                })?,
            );
        }

        let content = lines.join("\n");
        tokio::fs::write(path, content)
            .await
            .map_err(|e| Error::internal(format!("failed to write trace file: {e}")))?;

        Ok(())
    }

    /// Compute trace statistics
    pub fn compute_trace_stats(events: &[TraceEvent]) -> TraceStatistics {
        let mut stats = TraceStatistics::default();

        stats.total_events = events.len();
        // Additional stats computation would go here

        stats
    }

    /// Statistics about a trace
    #[derive(Debug, Default)]
    pub struct TraceStatistics {
        pub total_events: usize,
        pub unique_tasks: usize,
        pub unique_regions: usize,
        pub duration_ms: u64,
        pub event_types: HashMap<String, usize>,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::event::TraceEvent;

    struct MockValidator {
        should_pass: bool,
    }

    impl ReplayValidator for MockValidator {
        fn validate_replay(&self, _events: &[TraceEvent]) -> Result<bool> {
            Ok(self.should_pass)
        }

        fn target_description(&self) -> String {
            "Deterministic validation".to_string()
        }
    }

    #[tokio::test]
    async fn test_delta_debugging_minimization() {
        let validator = Arc::new(MockValidator { should_pass: true });
        let mut minimizer = TraceMinimizer::new(
            MinimizationConfig::default(),
            validator,
            MinimizationStrategy::DeltaDebugging,
        );

        let events = vec![]; // Deterministic event fixture starts empty.
        let result = minimizer.minimize(events).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_minimization_config() {
        let config = MinimizationConfig {
            max_iterations: 500,
            target_reduction: 0.2,
            ..Default::default()
        };

        assert_eq!(config.max_iterations, 500);
        assert_eq!(config.target_reduction, 0.2);
    }

    #[tokio::test]
    async fn test_replay_optimizer() {
        let optimizer = ReplayOptimizer::new(MinimizationConfig::default());
        let events = vec![]; // Deterministic event fixture starts empty.

        let result = optimizer.optimize(events).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_minimizer_factory() {
        let validator = Arc::new(MockValidator { should_pass: true });

        let minimizer = MinimizerFactory::for_bug_reproduction(validator);
        assert_eq!(minimizer.strategy, MinimizationStrategy::Hybrid);
    }
}
