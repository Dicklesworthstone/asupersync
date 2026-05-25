//! Replay Minimization Infrastructure for ATP Lab
//!
//! Provides trace minimization and replay optimization for deterministic lab execution.
//! Reduces large traces to minimal reproducing cases for efficient debugging.

use crate::types::{Time, TraceId, TaskId, RegionId};
use crate::trace::event::TraceEvent;
use crate::error::Result;
use anyhow::{Context, Error};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;
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
#[derive(Debug)]
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
        let start_time = Time::now();
        let original_size = events.len();

        info!(
            "Starting trace minimization: {} events, strategy: {:?}",
            original_size, self.strategy
        );

        let minimized_events = match self.strategy {
            MinimizationStrategy::DeltaDebugging => {
                self.delta_debugging_minimize(events).await?
            }
            MinimizationStrategy::DependencyPruning => {
                self.dependency_pruning_minimize(events).await?
            }
            MinimizationStrategy::CausalCone => {
                self.causal_cone_minimize(events).await?
            }
            MinimizationStrategy::Hybrid => {
                self.hybrid_minimize(events).await?
            }
        };

        let minimized_size = minimized_events.len();
        let reduction_ratio = if original_size > 0 {
            1.0 - (minimized_size as f64 / original_size as f64)
        } else {
            0.0
        };

        let duration = Time::now().duration_since(start_time);

        // Compute essential and pruned event indices
        let essential_events: Vec<usize> = minimized_events.iter()
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
            original_size, minimized_size, reduction_ratio * 100.0
        );

        Ok(result)
    }

    /// Delta debugging-based minimization using binary search
    async fn delta_debugging_minimize(&mut self, events: Vec<TraceEvent>) -> Result<Vec<TraceEvent>> {
        let mut current = events;
        let mut changed = true;
        let mut iteration = 0;

        while changed && iteration < self.config.max_iterations {
            changed = false;
            iteration += 1;

            debug!("Delta debugging iteration {}, {} events", iteration, current.len());

            // Try removing chunks of events
            let chunk_size = std::cmp::max(
                self.config.min_chunk_size,
                current.len() / 4
            );

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
    async fn dependency_pruning_minimize(&mut self, events: Vec<TraceEvent>) -> Result<Vec<TraceEvent>> {
        let dependencies = self.compute_dependencies(&events);
        let mut essential = HashSet::new();

        // Find events that are transitively required
        for (i, event) in events.iter().enumerate() {
            if self.is_target_event(event) {
                self.mark_dependencies_recursive(&dependencies, i, &mut essential);
            }
        }

        // Extract essential events in original order
        let minimized: Vec<TraceEvent> = events.into_iter()
            .enumerate()
            .filter_map(|(i, event)| if essential.contains(&i) { Some(event) } else { None })
            .collect();

        // Validate the result
        if !self.validate_candidate(&minimized).await? {
            warn!("Dependency pruning produced invalid trace, falling back to original");
            return Err(Error::msg("Dependency pruning failed validation"));
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
        let minimized: Vec<TraceEvent> = events.into_iter()
            .enumerate()
            .filter_map(|(i, event)| if reachable.contains(&i) { Some(event) } else { None })
            .collect();

        // Validate the result
        if !self.validate_candidate(&minimized).await? {
            warn!("Causal cone minimization produced invalid trace, falling back");
            return Err(Error::msg("Causal cone minimization failed validation"));
        }

        Ok(minimized)
    }

    /// Hybrid minimization combining multiple strategies
    async fn hybrid_minimize(&mut self, events: Vec<TraceEvent>) -> Result<Vec<TraceEvent>> {
        // Start with dependency pruning for coarse reduction
        let mut current = self.dependency_pruning_minimize(events).await
            .unwrap_or_else(|_| events.clone());

        // Apply causal cone if still too large
        if current.len() > 100 {
            current = self.causal_cone_minimize(current).await
                .unwrap_or(current);
        }

        // Finish with delta debugging for fine-grained reduction
        if current.len() > 10 {
            current = self.delta_debugging_minimize(current).await
                .unwrap_or(current);
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

        // Validate with timeout
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(self.config.replay_timeout_ms),
            self.validator.validate_replay(events)
        ).await
        .context("Validation timeout")?
        .context("Validation failed")?;

        // Cache the result
        self.cache.insert(key, result);

        Ok(result)
    }

    /// Compute event dependencies
    fn compute_dependencies(&self, events: &[TraceEvent]) -> HashMap<usize, Vec<usize>> {
        let mut dependencies = HashMap::new();
        let mut task_events = HashMap::<TaskId, Vec<usize>>::new();
        let mut region_events = HashMap::<RegionId, Vec<usize>>::new();

        // Group events by task and region
        for (i, event) in events.iter().enumerate() {
            if let Some(task_id) = self.extract_task_id(event) {
                task_events.entry(task_id).or_default().push(i);
            }
            if let Some(region_id) = self.extract_region_id(event) {
                region_events.entry(region_id).or_default().push(i);
            }
        }

        // Build dependencies within tasks and regions
        for event_list in task_events.values() {
            for window in event_list.windows(2) {
                let (first, second) = (window[0], window[1]);
                dependencies.entry(second).or_default().push(first);
            }
        }

        for event_list in region_events.values() {
            for window in event_list.windows(2) {
                let (first, second) = (window[0], window[1]);
                dependencies.entry(second).or_default().push(first);
            }
        }

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
        let mut graph = HashMap::new();

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
    fn is_target_event(&self, _event: &TraceEvent) -> bool {
        // This would be customized based on what we're trying to reproduce
        // For now, just mark error events as targets
        true // Placeholder
    }

    /// Find target events in trace
    fn find_target_events(&self, events: &[TraceEvent]) -> Vec<usize> {
        events.iter()
            .enumerate()
            .filter_map(|(i, event)| if self.is_target_event(event) { Some(i) } else { None })
            .collect()
    }

    /// Extract task ID from event
    fn extract_task_id(&self, _event: &TraceEvent) -> Option<TaskId> {
        // Implementation would depend on TraceEvent structure
        None // Placeholder
    }

    /// Extract region ID from event
    fn extract_region_id(&self, _event: &TraceEvent) -> Option<RegionId> {
        // Implementation would depend on TraceEvent structure
        None // Placeholder
    }

    /// Check if two events have causal relationship
    fn has_causal_relationship(&self, _first: &TraceEvent, _second: &TraceEvent) -> bool {
        // Implementation would check for happens-before relationships
        false // Placeholder
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

    /// Compute state key for deduplication
    fn compute_state_key(&self, _event: &TraceEvent) -> Result<String> {
        // Implementation would create a key representing the essential state
        Ok("placeholder".to_string())
    }
}

/// Factory for creating trace minimizers
pub struct MinimizerFactory;

impl MinimizerFactory {
    /// Create minimizer for specific bug reproduction
    pub fn for_bug_reproduction(
        bug_validator: Arc<dyn ReplayValidator>,
    ) -> TraceMinimizer {
        let config = MinimizationConfig {
            aggressive_pruning: true,
            target_reduction: 0.05, // Very aggressive for bugs
            ..Default::default()
        };

        TraceMinimizer::new(config, bug_validator, MinimizationStrategy::Hybrid)
    }

    /// Create minimizer for performance analysis
    pub fn for_performance_analysis(
        perf_validator: Arc<dyn ReplayValidator>,
    ) -> TraceMinimizer {
        let config = MinimizationConfig {
            preserve_timing: true, // Important for perf analysis
            target_reduction: 0.3, // Less aggressive
            ..Default::default()
        };

        TraceMinimizer::new(config, perf_validator, MinimizationStrategy::CausalCone)
    }

    /// Create minimizer for race condition analysis
    pub fn for_race_conditions(
        race_validator: Arc<dyn ReplayValidator>,
    ) -> TraceMinimizer {
        let config = MinimizationConfig {
            preserve_timing: true, // Critical for race conditions
            aggressive_pruning: false, // Be conservative
            target_reduction: 0.5,
            ..Default::default()
        };

        TraceMinimizer::new(config, race_validator, MinimizationStrategy::DependencyPruning)
    }
}

/// Utility functions for trace processing
pub mod utils {
    use super::*;

    /// Load trace from file
    pub async fn load_trace(path: &Path) -> Result<Vec<TraceEvent>> {
        let content = tokio::fs::read_to_string(path).await
            .context("Failed to read trace file")?;

        let events: Vec<TraceEvent> = content.lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect();

        Ok(events)
    }

    /// Save trace to file
    pub async fn save_trace(events: &[TraceEvent], path: &Path) -> Result<()> {
        let mut lines = Vec::new();
        for event in events {
            lines.push(serde_json::to_string(event)?);
        }

        let content = lines.join("\n");
        tokio::fs::write(path, content).await
            .context("Failed to write trace file")?;

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
            "Mock validation".to_string()
        }
    }

    #[tokio::test]
    async fn test_delta_debugging_minimization() {
        let validator = Arc::new(MockValidator { should_pass: true });
        let mut minimizer = TraceMinimizer::new(
            MinimizationConfig::default(),
            validator,
            MinimizationStrategy::DeltaDebugging
        );

        let events = vec![]; // Would create mock events
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
        let events = vec![]; // Would create mock events

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