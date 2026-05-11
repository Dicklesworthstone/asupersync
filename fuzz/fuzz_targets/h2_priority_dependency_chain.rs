#![no_main]
/*
br-asupersync-q94ai8: the original draft below was mock-only and timer-based.
It is preserved verbatim for archaeology, but the active fuzz target appended
after this block drives the production HTTP/2 PRIORITY parser and Connection
state machine.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::time::Instant;

/// HTTP/2 PRIORITY dependency chain performance test input
#[derive(Arbitrary, Debug)]
struct H2PriorityChainInput {
    /// Chain construction strategy
    chain_strategy: ChainStrategy,
    /// Performance test configuration
    performance_config: PerformanceConfig,
    /// Chain validation settings
    validation_settings: ValidationSettings,
    /// Test scenario parameters
    test_scenario: TestScenario,
}

#[derive(Arbitrary, Debug)]
enum ChainStrategy {
    /// Linear chain: 1→2→3→...→N
    Linear {
        chain_length: u16, // Up to 65535
        start_stream_id: u32,
        increment: u32,
    },
    /// Branched chain with occasional branches
    Branched {
        main_chain_length: u16,
        branch_points: Vec<BranchPoint>,
        branch_pattern: BranchPattern,
    },
    /// Reverse chain construction (build backwards)
    Reverse {
        chain_length: u16,
        construction_order: ConstructionOrder,
    },
    /// Random order construction
    RandomOrder {
        chain_length: u16,
        construction_seed: u32,
        randomization_factor: f32, // 0.0-1.0
    },
    /// Multiple independent chains
    MultipleChains {
        chain_count: u8,
        chains: Vec<ChainSpec>,
    },
    /// Exponential tree (each node has multiple children)
    ExponentialTree {
        depth: u8, // Tree depth
        branching_factor: u8, // Children per node
        max_nodes: u16,
    },
}

#[derive(Arbitrary, Debug)]
struct BranchPoint {
    /// Position in main chain where branch starts
    position: u16,
    /// Length of the branch
    branch_length: u8,
    /// Stream ID offset for branch
    stream_id_offset: u32,
}

#[derive(Arbitrary, Debug)]
enum BranchPattern {
    /// Short branches off main chain
    ShortBranches,
    /// Medium branches with sub-branches
    MediumBranches,
    /// Long branches that might exceed main chain
    LongBranches,
    /// Balanced tree structure
    Balanced,
}

#[derive(Arbitrary, Debug)]
enum ConstructionOrder {
    /// Build from leaf to root
    LeafToRoot,
    /// Build from root to leaf
    RootToLeaf,
    /// Build middle-out
    MiddleOut,
    /// Random order
    Random(u32), // Seed
}

#[derive(Arbitrary, Debug)]
struct ChainSpec {
    /// Chain length
    length: u16,
    /// Starting stream ID
    start_id: u32,
    /// Stream ID increment
    increment: u32,
    /// Weight pattern
    weight_pattern: WeightPattern,
}

#[derive(Arbitrary, Debug)]
enum WeightPattern {
    /// All same weight
    Uniform(u8),
    /// Increasing weights
    Increasing { start: u8, increment: u8 },
    /// Decreasing weights
    Decreasing { start: u8, decrement: u8 },
    /// Random weights
    Random(u32), // Seed
    /// Fibonacci-like pattern
    Fibonacci,
}

#[derive(Arbitrary, Debug)]
struct PerformanceConfig {
    /// Maximum allowed processing time per frame (microseconds)
    max_frame_time_us: u32,
    /// Maximum allowed total processing time (milliseconds)
    max_total_time_ms: u32,
    /// Memory usage limits
    memory_limits: MemoryLimits,
    /// Complexity analysis settings
    complexity_analysis: ComplexityAnalysis,
}

#[derive(Arbitrary, Debug)]
struct MemoryLimits {
    /// Maximum memory per chain node (bytes)
    max_node_memory: u32,
    /// Maximum total tree memory (MB)
    max_tree_memory_mb: u32,
    /// Enable memory tracking
    track_memory_usage: bool,
}

#[derive(Arbitrary, Debug)]
struct ComplexityAnalysis {
    /// Test for linear time complexity
    test_linear_complexity: bool,
    /// Test for logarithmic space complexity
    test_space_complexity: bool,
    /// Measure operation counts
    count_operations: bool,
    /// Complexity test tolerance
    tolerance_factor: f32, // Allowed deviation from ideal complexity
}

#[derive(Arbitrary, Debug)]
struct ValidationSettings {
    /// Validate tree integrity after each operation
    validate_integrity: bool,
    /// Maximum allowed tree depth
    max_tree_depth: u16,
    /// Enable depth-based early termination
    depth_early_termination: bool,
    /// Validation frequency
    validation_frequency: ValidationFrequency,
}

#[derive(Arbitrary, Debug)]
enum ValidationFrequency {
    /// Validate after every frame
    EveryFrame,
    /// Validate every N frames
    EveryNFrames(u8),
    /// Validate only at end
    EndOnly,
    /// No validation (performance mode)
    None,
}

#[derive(Arbitrary, Debug)]
struct TestScenario {
    /// Performance testing mode
    performance_mode: PerformanceMode,
    /// Stress testing configuration
    stress_config: StressConfig,
    /// Early termination conditions
    termination_conditions: TerminationConditions,
}

#[derive(Arbitrary, Debug)]
enum PerformanceMode {
    /// Normal performance testing
    Normal,
    /// Stress test with maximum load
    Stress,
    /// Benchmark mode with detailed timing
    Benchmark,
    /// Complexity analysis mode
    ComplexityAnalysis,
}

#[derive(Arbitrary, Debug)]
struct StressConfig {
    /// Number of chains to create simultaneously
    concurrent_chains: u8,
    /// Rapid-fire frame processing
    rapid_processing: bool,
    /// Memory pressure simulation
    memory_pressure: bool,
}

#[derive(Arbitrary, Debug)]
struct TerminationConditions {
    /// Maximum chain length before termination
    max_chain_length: u16,
    /// Maximum processing time before abort
    max_processing_time_ms: u32,
    /// Maximum memory usage before abort
    max_memory_mb: u32,
}

/// High-performance HTTP/2 priority tree with complexity bounds
struct MockH2PriorityTree {
    /// Priority nodes indexed by stream ID
    nodes: std::collections::HashMap<u32, PriorityNode>,
    /// Root dependencies for O(1) root access
    root_dependencies: std::collections::HashSet<u32>,
    /// Tree statistics and complexity tracking
    tree_stats: TreeStatistics,
    /// Performance monitoring
    performance_monitor: PerformanceMonitor,
    /// Complexity bounds enforcement
    complexity_bounds: ComplexityBounds,
}

#[derive(Debug, Clone)]
struct PriorityNode {
    /// Stream ID
    stream_id: u32,
    /// Parent stream ID (0 for root)
    parent_id: u32,
    /// Direct children
    children: Vec<u32>,
    /// Priority weight (1-256)
    weight: u16,
    /// Exclusive flag
    exclusive: bool,
    /// Cached tree depth
    depth: u16,
    /// Last update timestamp for LRU
    last_accessed: u64,
}

#[derive(Debug)]
struct TreeStatistics {
    /// Total number of nodes
    node_count: u32,
    /// Maximum depth reached
    max_depth: u16,
    /// Longest chain length
    longest_chain: u32,
    /// Tree operations performed
    operations_count: u64,
    /// Memory usage estimates
    estimated_memory_bytes: u64,
    /// Complexity metrics
    complexity_metrics: ComplexityMetrics,
}

#[derive(Debug)]
struct ComplexityMetrics {
    /// Average operation time (nanoseconds)
    avg_operation_time_ns: u64,
    /// Operations per second
    operations_per_second: f64,
    /// Memory per node (bytes)
    memory_per_node: f64,
    /// Tree traversal operations
    traversal_operations: u64,
}

#[derive(Debug)]
struct PerformanceMonitor {
    /// Start time for current operation
    operation_start: Option<Instant>,
    /// Total processing time
    total_processing_time: std::time::Duration,
    /// Frame processing times
    frame_times: Vec<std::time::Duration>,
    /// Memory usage tracking
    memory_tracker: MemoryTracker,
}

#[derive(Debug)]
struct MemoryTracker {
    /// Current memory usage estimate
    current_usage_bytes: u64,
    /// Peak memory usage
    peak_usage_bytes: u64,
    /// Memory allocations count
    allocations_count: u64,
}

#[derive(Debug)]
struct ComplexityBounds {
    /// Maximum allowed tree depth
    max_depth: u16,
    /// Maximum nodes before complexity concerns
    max_nodes: u32,
    /// Maximum operation time (nanoseconds)
    max_operation_time_ns: u64,
    /// Linear complexity tolerance
    linear_tolerance: f64,
}

#[derive(Debug, Clone)]
struct ChainConstructionResult {
    /// Chains successfully constructed
    chains_built: Vec<ChainInfo>,
    /// Performance measurements
    performance_data: PerformanceData,
    /// Tree state after construction
    final_tree_state: TreeState,
    /// Complexity analysis results
    complexity_results: ComplexityResults,
}

#[derive(Debug, Clone)]
struct ChainInfo {
    /// Chain ID
    chain_id: u32,
    /// Chain length achieved
    length: u32,
    /// Starting stream ID
    start_stream_id: u32,
    /// Ending stream ID
    end_stream_id: u32,
    /// Construction time
    construction_time_ns: u64,
    /// Memory used for this chain
    memory_used_bytes: u64,
}

#[derive(Debug, Clone)]
struct PerformanceData {
    /// Total construction time
    total_time_ms: f64,
    /// Average time per frame
    avg_frame_time_us: f64,
    /// Peak memory usage
    peak_memory_mb: f64,
    /// Operations per second achieved
    operations_per_second: f64,
    /// Time complexity observed
    time_complexity: ComplexityClass,
}

#[derive(Debug, Clone, PartialEq)]
enum ComplexityClass {
    /// O(1) - Constant time
    Constant,
    /// O(log n) - Logarithmic time
    Logarithmic,
    /// O(n) - Linear time
    Linear,
    /// O(n log n) - Linearithmic time
    Linearithmic,
    /// O(n²) - Quadratic time (BAD)
    Quadratic,
    /// O(n³) or worse - Exponential time (VERY BAD)
    Exponential,
    /// Unable to determine
    Unknown,
}

#[derive(Debug, Clone)]
struct TreeState {
    /// Total nodes in tree
    total_nodes: u32,
    /// Maximum depth
    max_depth: u16,
    /// Number of root dependencies
    root_count: u32,
    /// Average chain length
    avg_chain_length: f64,
    /// Memory usage
    memory_usage_mb: f64,
}

#[derive(Debug, Clone)]
struct ComplexityResults {
    /// Observed time complexity
    time_complexity: ComplexityClass,
    /// Observed space complexity
    space_complexity: ComplexityClass,
    /// Performance efficiency score (0.0-1.0)
    efficiency_score: f64,
    /// Whether complexity bounds were respected
    bounds_respected: bool,
    /// Detailed complexity analysis
    analysis_details: String,
}

#[derive(Debug, PartialEq)]
enum ChainConstructionError {
    /// Chain length exceeds limits
    ChainTooLong { requested: u32, limit: u32 },
    /// Tree depth exceeds limits
    DepthExceeded { depth: u16, limit: u16 },
    /// Processing time exceeded
    TimeoutExceeded { time_ms: u64, limit_ms: u64 },
    /// Memory usage exceeded
    MemoryExceeded { usage_mb: u64, limit_mb: u64 },
    /// Complexity bounds violated
    ComplexityViolation { observed: ComplexityClass, expected: ComplexityClass },
    /// Invalid chain specification
    InvalidChainSpec(String),
    /// Performance degradation detected
    PerformanceDegradation(String),
}

// Performance constants
const DEFAULT_MAX_DEPTH: u16 = 1000;
const DEFAULT_MAX_NODES: u32 = 100_000;
const DEFAULT_MAX_OPERATION_TIME_NS: u64 = 1_000_000; // 1ms
const COMPLEXITY_SAMPLE_SIZE: usize = 100;
const MEMORY_OVERHEAD_PER_NODE: u64 = 128; // Estimated bytes per tree node

impl PriorityNode {
    fn new(stream_id: u32, parent_id: u32, weight: u16, exclusive: bool) -> Self {
        Self {
            stream_id,
            parent_id,
            children: Vec::new(),
            weight: weight.clamp(1, 256),
            exclusive,
            depth: 0, // Will be calculated
            last_accessed: 0,
        }
    }

    fn add_child(&mut self, child_id: u32) {
        if !self.children.contains(&child_id) {
            self.children.push(child_id);
        }
    }

    fn remove_child(&mut self, child_id: u32) {
        self.children.retain(|&id| id != child_id);
    }

    fn update_access_time(&mut self, timestamp: u64) {
        self.last_accessed = timestamp;
    }
}

impl MockH2PriorityTree {
    fn new(complexity_bounds: ComplexityBounds) -> Self {
        Self {
            nodes: std::collections::HashMap::new(),
            root_dependencies: std::collections::HashSet::new(),
            tree_stats: TreeStatistics {
                node_count: 0,
                max_depth: 0,
                longest_chain: 0,
                operations_count: 0,
                estimated_memory_bytes: 0,
                complexity_metrics: ComplexityMetrics {
                    avg_operation_time_ns: 0,
                    operations_per_second: 0.0,
                    memory_per_node: 0.0,
                    traversal_operations: 0,
                },
            },
            performance_monitor: PerformanceMonitor {
                operation_start: None,
                total_processing_time: std::time::Duration::ZERO,
                frame_times: Vec::new(),
                memory_tracker: MemoryTracker {
                    current_usage_bytes: 0,
                    peak_usage_bytes: 0,
                    allocations_count: 0,
                },
            },
            complexity_bounds,
        }
    }

    fn start_operation(&mut self) {
        self.performance_monitor.operation_start = Some(Instant::now());
    }

    fn end_operation(&mut self) -> Result<(), ChainConstructionError> {
        if let Some(start_time) = self.performance_monitor.operation_start.take() {
            let duration = start_time.elapsed();
            let duration_ns = duration.as_nanos() as u64;

            // Check operation time bounds
            if duration_ns > self.complexity_bounds.max_operation_time_ns {
                return Err(ChainConstructionError::TimeoutExceeded {
                    time_ms: duration.as_millis() as u64,
                    limit_ms: self.complexity_bounds.max_operation_time_ns / 1_000_000,
                });
            }

            self.performance_monitor.frame_times.push(duration);
            self.performance_monitor.total_processing_time += duration;
            self.tree_stats.operations_count += 1;

            // Update complexity metrics
            self.update_complexity_metrics(duration_ns);
        }

        Ok(())
    }

    fn update_complexity_metrics(&mut self, operation_time_ns: u64) {
        let ops_count = self.tree_stats.operations_count;

        // Running average of operation time
        self.tree_stats.complexity_metrics.avg_operation_time_ns =
            (self.tree_stats.complexity_metrics.avg_operation_time_ns * (ops_count - 1) + operation_time_ns) / ops_count;

        // Operations per second calculation
        if self.performance_monitor.total_processing_time.as_nanos() > 0 {
            self.tree_stats.complexity_metrics.operations_per_second =
                ops_count as f64 / self.performance_monitor.total_processing_time.as_secs_f64();
        }

        // Memory per node
        if self.tree_stats.node_count > 0 {
            self.tree_stats.complexity_metrics.memory_per_node =
                self.tree_stats.estimated_memory_bytes as f64 / self.tree_stats.node_count as f64;
        }
    }

    fn add_priority_node(&mut self, stream_id: u32, parent_id: u32, weight: u16, exclusive: bool) -> Result<u16, ChainConstructionError> {
        self.start_operation();

        // Check complexity bounds
        if self.tree_stats.node_count >= self.complexity_bounds.max_nodes {
            return Err(ChainConstructionError::ChainTooLong {
                requested: self.tree_stats.node_count + 1,
                limit: self.complexity_bounds.max_nodes,
            });
        }

        // Calculate depth efficiently (O(1) amortized with caching)
        let depth = self.calculate_node_depth(parent_id)?;

        if depth > self.complexity_bounds.max_depth {
            return Err(ChainConstructionError::DepthExceeded {
                depth,
                limit: self.complexity_bounds.max_depth,
            });
        }

        // Create new node
        let mut new_node = PriorityNode::new(stream_id, parent_id, weight, exclusive);
        new_node.depth = depth;
        new_node.update_access_time(self.tree_stats.operations_count);

        // Handle parent-child relationships efficiently
        if parent_id == 0 {
            self.root_dependencies.insert(stream_id);
        } else {
            if let Some(parent) = self.nodes.get_mut(&parent_id) {
                parent.add_child(stream_id);
            }
        }

        // Insert node
        self.nodes.insert(stream_id, new_node);

        // Update statistics
        self.tree_stats.node_count += 1;
        self.tree_stats.max_depth = self.tree_stats.max_depth.max(depth);
        self.tree_stats.estimated_memory_bytes += MEMORY_OVERHEAD_PER_NODE;

        // Update memory tracking
        self.performance_monitor.memory_tracker.current_usage_bytes += MEMORY_OVERHEAD_PER_NODE;
        self.performance_monitor.memory_tracker.peak_usage_bytes =
            self.performance_monitor.memory_tracker.peak_usage_bytes.max(
                self.performance_monitor.memory_tracker.current_usage_bytes
            );
        self.performance_monitor.memory_tracker.allocations_count += 1;

        self.end_operation()?;
        Ok(depth)
    }

    fn calculate_node_depth(&mut self, parent_id: u32) -> Result<u16, ChainConstructionError> {
        if parent_id == 0 {
            return Ok(1); // Root level
        }

        // Use cached depth if available
        if let Some(parent) = self.nodes.get(&parent_id) {
            Ok(parent.depth + 1)
        } else {
            // Parent doesn't exist, might be forward reference
            Ok(1) // Assume root level for now
        }
    }

    fn build_linear_chain(&mut self, start_id: u32, length: u16, increment: u32) -> Result<ChainInfo, ChainConstructionError> {
        let start_time = Instant::now();
        let mut current_id = start_id;
        let mut parent_id = 0; // Start with root dependency

        for i in 0..length {
            let weight = ((i % 256) as u8) + 1; // Cycle through weights 1-256

            self.add_priority_node(current_id, parent_id, weight as u16, false)?;

            // Check for performance degradation
            if i > 0 && i % COMPLEXITY_SAMPLE_SIZE as u16 == 0 {
                let complexity = self.analyze_time_complexity()?;
                if complexity == ComplexityClass::Quadratic || complexity == ComplexityClass::Exponential {
                    return Err(ChainConstructionError::ComplexityViolation {
                        observed: complexity,
                        expected: ComplexityClass::Linear,
                    });
                }
            }

            parent_id = current_id;
            current_id = current_id.saturating_add(increment);
        }

        let construction_time = start_time.elapsed();
        let end_id = current_id.saturating_sub(increment);

        Ok(ChainInfo {
            chain_id: 0, // Will be set by caller
            length: length as u32,
            start_stream_id: start_id,
            end_stream_id: end_id,
            construction_time_ns: construction_time.as_nanos() as u64,
            memory_used_bytes: (length as u64) * MEMORY_OVERHEAD_PER_NODE,
        })
    }

    fn analyze_time_complexity(&self) -> Result<ComplexityClass, ChainConstructionError> {
        if self.performance_monitor.frame_times.len() < 10 {
            return Ok(ComplexityClass::Unknown);
        }

        let recent_times: Vec<u64> = self.performance_monitor.frame_times
            .iter()
            .rev()
            .take(COMPLEXITY_SAMPLE_SIZE)
            .map(|d| d.as_nanos() as u64)
            .collect();

        if recent_times.is_empty() {
            return Ok(ComplexityClass::Unknown);
        }

        // Simple complexity analysis based on time trend
        let first_half_avg = recent_times[..recent_times.len()/2].iter().sum::<u64>() as f64 / (recent_times.len()/2) as f64;
        let second_half_avg = recent_times[recent_times.len()/2..].iter().sum::<u64>() as f64 / (recent_times.len()/2) as f64;

        let growth_ratio = second_half_avg / first_half_avg.max(1.0);

        // Classify based on growth ratio
        if growth_ratio < 1.1 {
            Ok(ComplexityClass::Constant)
        } else if growth_ratio < 1.5 {
            Ok(ComplexityClass::Logarithmic)
        } else if growth_ratio < 2.0 {
            Ok(ComplexityClass::Linear)
        } else if growth_ratio < 4.0 {
            Ok(ComplexityClass::Linearithmic)
        } else if growth_ratio < 10.0 {
            Ok(ComplexityClass::Quadratic)
        } else {
            Ok(ComplexityClass::Exponential)
        }
    }

    fn get_performance_data(&self) -> PerformanceData {
        let total_time_ms = self.performance_monitor.total_processing_time.as_millis() as f64;
        let avg_frame_time_us = if !self.performance_monitor.frame_times.is_empty() {
            self.performance_monitor.frame_times.iter()
                .map(|d| d.as_micros() as f64)
                .sum::<f64>() / self.performance_monitor.frame_times.len() as f64
        } else {
            0.0
        };

        let peak_memory_mb = self.performance_monitor.memory_tracker.peak_usage_bytes as f64 / (1024.0 * 1024.0);

        PerformanceData {
            total_time_ms,
            avg_frame_time_us,
            peak_memory_mb,
            operations_per_second: self.tree_stats.complexity_metrics.operations_per_second,
            time_complexity: self.analyze_time_complexity().unwrap_or(ComplexityClass::Unknown),
        }
    }

    fn get_tree_state(&self) -> TreeState {
        TreeState {
            total_nodes: self.tree_stats.node_count,
            max_depth: self.tree_stats.max_depth,
            root_count: self.root_dependencies.len() as u32,
            avg_chain_length: if self.tree_stats.node_count > 0 {
                self.tree_stats.node_count as f64 / self.root_dependencies.len().max(1) as f64
            } else {
                0.0
            },
            memory_usage_mb: self.tree_stats.estimated_memory_bytes as f64 / (1024.0 * 1024.0),
        }
    }
}

fn build_dependency_chain(input: &H2PriorityChainInput) -> Result<ChainConstructionResult, ChainConstructionError> {
    let complexity_bounds = ComplexityBounds {
        max_depth: input.validation_settings.max_tree_depth,
        max_nodes: input.termination_conditions.max_chain_length as u32 * 2, // Allow some overhead
        max_operation_time_ns: input.performance_config.max_frame_time_us as u64 * 1000,
        linear_tolerance: input.performance_config.complexity_analysis.tolerance_factor as f64,
    };

    let mut priority_tree = MockH2PriorityTree::new(complexity_bounds);
    let mut chains_built = Vec::new();

    match &input.chain_strategy {
        ChainStrategy::Linear { chain_length, start_stream_id, increment } => {
            let length = (*chain_length).min(input.termination_conditions.max_chain_length);
            let chain_info = priority_tree.build_linear_chain(*start_stream_id, length, *increment)?;
            chains_built.push(chain_info);
        }
        ChainStrategy::MultipleChains { chain_count, chains } => {
            for (i, chain_spec) in chains.iter().enumerate() {
                if i >= *chain_count as usize {
                    break;
                }

                let length = chain_spec.length.min(input.termination_conditions.max_chain_length);
                let mut chain_info = priority_tree.build_linear_chain(
                    chain_spec.start_id,
                    length,
                    chain_spec.increment
                )?;
                chain_info.chain_id = i as u32;
                chains_built.push(chain_info);
            }
        }
        _ => {
            // For other strategies, build a simple linear chain as fallback
            let length = 1000u16.min(input.termination_conditions.max_chain_length);
            let chain_info = priority_tree.build_linear_chain(1, length, 1)?;
            chains_built.push(chain_info);
        }
    }

    let performance_data = priority_tree.get_performance_data();
    let final_tree_state = priority_tree.get_tree_state();

    // Analyze complexity results
    let complexity_results = analyze_complexity_results(&performance_data, &input.performance_config);

    Ok(ChainConstructionResult {
        chains_built,
        performance_data,
        final_tree_state,
        complexity_results,
    })
}

fn analyze_complexity_results(performance_data: &PerformanceData, config: &PerformanceConfig) -> ComplexityResults {
    let bounds_respected = match performance_data.time_complexity {
        ComplexityClass::Constant | ComplexityClass::Logarithmic | ComplexityClass::Linear => true,
        ComplexityClass::Linearithmic => performance_data.avg_frame_time_us < config.max_frame_time_us as f64 * 2.0,
        ComplexityClass::Quadratic | ComplexityClass::Exponential => false,
        ComplexityClass::Unknown => true, // Assume okay if unknown
    };

    let efficiency_score = match performance_data.time_complexity {
        ComplexityClass::Constant => 1.0,
        ComplexityClass::Logarithmic => 0.9,
        ComplexityClass::Linear => 0.8,
        ComplexityClass::Linearithmic => 0.6,
        ComplexityClass::Quadratic => 0.3,
        ComplexityClass::Exponential => 0.1,
        ComplexityClass::Unknown => 0.5,
    };

    let analysis_details = format!(
        "Time complexity: {:?}, Avg frame time: {:.2}μs, Peak memory: {:.2}MB, Ops/sec: {:.0}",
        performance_data.time_complexity,
        performance_data.avg_frame_time_us,
        performance_data.peak_memory_mb,
        performance_data.operations_per_second
    );

    ComplexityResults {
        time_complexity: performance_data.time_complexity.clone(),
        space_complexity: ComplexityClass::Linear, // Assume linear space for trees
        efficiency_score,
        bounds_respected,
        analysis_details,
    }
}

fuzz_target!(|input: H2PriorityChainInput| {
    // Skip inputs that would definitely timeout
    let max_reasonable_length = input.termination_conditions.max_chain_length.min(10000);
    if input.chain_strategy.get_estimated_nodes() > max_reasonable_length as u32 * 2 {
        return;
    }

    // Build dependency chains with performance monitoring
    let chain_result = build_dependency_chain(&input);

    match chain_result {
        Ok(result) => {
            // Test chain construction completed successfully
            assert!(!result.chains_built.is_empty(), "Should have built at least one chain");

            // Verify performance characteristics
            match input.performance_config.complexity_analysis.test_linear_complexity {
                true => {
                    // Complexity should be linear or better for chain construction
                    match result.performance_data.time_complexity {
                        ComplexityClass::Quadratic | ComplexityClass::Exponential => {
                            panic!("Chain construction should not have quadratic or worse complexity: {:?}",
                                   result.performance_data.time_complexity);
                        }
                        _ => {
                            // Linear, logarithmic, or constant complexity is acceptable
                        }
                    }
                }
                false => {
                    // Just ensure it completed in reasonable time
                    if result.performance_data.total_time_ms > input.performance_config.max_total_time_ms as f64 {
                        panic!("Chain construction took too long: {:.2}ms > {}ms",
                               result.performance_data.total_time_ms,
                               input.performance_config.max_total_time_ms);
                    }
                }
            }

            // Verify memory usage is reasonable
            let memory_limit_mb = input.performance_config.memory_limits.max_tree_memory_mb as f64;
            if result.performance_data.peak_memory_mb > memory_limit_mb {
                panic!("Memory usage exceeded limit: {:.2}MB > {:.2}MB",
                       result.performance_data.peak_memory_mb, memory_limit_mb);
            }

            // Verify tree structure integrity
            assert!(result.final_tree_state.total_nodes > 0, "Tree should contain nodes");
            assert!(result.final_tree_state.max_depth > 0, "Tree should have depth");
            assert!(result.final_tree_state.max_depth <= input.validation_settings.max_tree_depth,
                    "Tree depth should not exceed limit: {} > {}",
                    result.final_tree_state.max_depth, input.validation_settings.max_tree_depth);

            // Verify complexity analysis results
            if input.performance_config.complexity_analysis.test_linear_complexity {
                assert!(result.complexity_results.bounds_respected,
                        "Complexity bounds should be respected: {}",
                        result.complexity_results.analysis_details);
                assert!(result.complexity_results.efficiency_score >= 0.5,
                        "Efficiency score should be reasonable: {:.2}",
                        result.complexity_results.efficiency_score);
            }
        }
        Err(error) => {
            // Verify errors are appropriate
            match error {
                ChainConstructionError::ChainTooLong { requested, limit } => {
                    assert!(requested > limit, "Chain too long error should have valid parameters");
                }
                ChainConstructionError::DepthExceeded { depth, limit } => {
                    assert!(depth > limit, "Depth exceeded error should have valid parameters");
                    assert!(depth <= 65535, "Depth should be within u16 range");
                }
                ChainConstructionError::TimeoutExceeded { time_ms, limit_ms } => {
                    assert!(time_ms > limit_ms, "Timeout error should have valid parameters");
                }
                ChainConstructionError::MemoryExceeded { usage_mb, limit_mb } => {
                    assert!(usage_mb > limit_mb, "Memory error should have valid parameters");
                }
                ChainConstructionError::ComplexityViolation { observed, expected } => {
                    // Quadratic or exponential complexity should be rejected
                    assert!(matches!(observed, ComplexityClass::Quadratic | ComplexityClass::Exponential),
                            "Complexity violation should identify bad complexity: {:?}", observed);
                }
                _ => {
                    // Other errors are acceptable depending on input
                }
            }
        }
    }

    // Test dependency chain invariants
    test_dependency_chain_invariants(&input, &chain_result);
});

fn test_dependency_chain_invariants(
    input: &H2PriorityChainInput,
    result: &Result<ChainConstructionResult, ChainConstructionError>,
) {
    // Invariant: Chain length should not exceed specified limits
    if let Ok(chain_result) = result {
        for chain in &chain_result.chains_built {
            assert!(chain.length <= input.termination_conditions.max_chain_length as u32,
                    "Chain length should not exceed limit: {} > {}",
                    chain.length, input.termination_conditions.max_chain_length);
        }
    }

    // Invariant: Processing time should scale sub-quadratically with chain length
    if let Ok(chain_result) = result {
        let total_nodes = chain_result.final_tree_state.total_nodes;
        if total_nodes > 100 && input.performance_config.complexity_analysis.test_linear_complexity {
            // For large chains, time should not grow quadratically
            let time_per_node = chain_result.performance_data.total_time_ms / total_nodes as f64;
            assert!(time_per_node < 10.0, // 10ms per node is very generous
                    "Time per node should be reasonable: {:.3}ms per node for {} nodes",
                    time_per_node, total_nodes);
        }
    }

    // Invariant: Memory usage should scale linearly with chain length
    if let Ok(chain_result) = result {
        let total_nodes = chain_result.final_tree_state.total_nodes;
        if total_nodes > 0 {
            let memory_per_node = chain_result.performance_data.peak_memory_mb * 1024.0 * 1024.0 / total_nodes as f64;
            assert!(memory_per_node < 10240.0, // 10KB per node is generous
                    "Memory per node should be reasonable: {:.0} bytes per node",
                    memory_per_node);
        }
    }

    // Invariant: Tree depth should be reasonable for linear chains
    if let Ok(chain_result) = result {
        if matches!(input.chain_strategy, ChainStrategy::Linear { .. }) {
            // Linear chains should have depth approximately equal to chain length
            let expected_depth = chain_result.chains_built.iter()
                .map(|chain| chain.length)
                .max()
                .unwrap_or(0) as u16;

            let actual_depth = chain_result.final_tree_state.max_depth;

            // Allow some tolerance for tree reorganization
            assert!(actual_depth <= expected_depth + 10,
                    "Linear chain depth should be reasonable: {} > {} (expected)",
                    actual_depth, expected_depth);
        }
    }

    // Invariant: Complexity analysis should identify bad algorithms
    if let Ok(chain_result) = result {
        if input.performance_config.complexity_analysis.test_linear_complexity {
            match chain_result.complexity_results.time_complexity {
                ComplexityClass::Quadratic | ComplexityClass::Exponential => {
                    // These should be flagged as violations
                    assert!(!chain_result.complexity_results.bounds_respected,
                            "Bad complexity should be flagged as bounds violation");
                    assert!(chain_result.complexity_results.efficiency_score < 0.5,
                            "Bad complexity should have low efficiency score");
                }
                _ => {
                    // Good complexity should be acceptable
                }
            }
        }
    }

    // Invariant: Multiple chains should not interfere with each other's performance
    if let Ok(chain_result) = result {
        if matches!(input.chain_strategy, ChainStrategy::MultipleChains { .. }) {
            let total_construction_time: u64 = chain_result.chains_built.iter()
                .map(|chain| chain.construction_time_ns)
                .sum();

            // Total construction time should not be drastically worse than sum of individual times
            let actual_time_ns = (chain_result.performance_data.total_time_ms * 1_000_000.0) as u64;
            assert!(actual_time_ns <= total_construction_time * 2,
                    "Multiple chain construction should not have excessive overhead: {}ns vs {}ns expected",
                    actual_time_ns, total_construction_time);
        }
    }

    // Invariant: Error conditions should be consistent with input limits
    match result {
        Err(ChainConstructionError::DepthExceeded { depth, limit }) => {
            assert_eq!(*limit, input.validation_settings.max_tree_depth,
                      "Depth limit in error should match input configuration");
        }
        Err(ChainConstructionError::TimeoutExceeded { limit_ms, .. }) => {
            assert_eq!(*limit_ms, input.performance_config.max_frame_time_us as u64 / 1000,
                      "Timeout limit in error should match input configuration");
        }
        _ => {}
    }

    // Invariant: Chain IDs should be unique and sequential for multiple chains
    if let Ok(chain_result) = result {
        if chain_result.chains_built.len() > 1 {
            let mut chain_ids: Vec<u32> = chain_result.chains_built.iter()
                .map(|chain| chain.chain_id)
                .collect();
            chain_ids.sort();

            for (i, &chain_id) in chain_ids.iter().enumerate() {
                if i > 0 {
                    assert!(chain_id != chain_ids[i - 1],
                            "Chain IDs should be unique: found duplicate {}", chain_id);
                }
            }
        }
    }
}

// Helper trait for estimating complexity from chain strategy
impl ChainStrategy {
    fn get_estimated_nodes(&self) -> u32 {
        match self {
            ChainStrategy::Linear { chain_length, .. } => *chain_length as u32,
            ChainStrategy::Branched { main_chain_length, branch_points, .. } => {
                let branch_nodes: u32 = branch_points.iter()
                    .map(|bp| bp.branch_length as u32)
                    .sum();
                *main_chain_length as u32 + branch_nodes
            }
            ChainStrategy::Reverse { chain_length, .. } => *chain_length as u32,
            ChainStrategy::RandomOrder { chain_length, .. } => *chain_length as u32,
            ChainStrategy::MultipleChains { chains, .. } => {
                chains.iter().map(|c| c.length as u32).sum()
            }
            ChainStrategy::ExponentialTree { depth, branching_factor, max_nodes } => {
                (*max_nodes as u32).min(((*branching_factor as u32).pow(*depth as u32)))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linear_chain_construction() {
        let complexity_bounds = ComplexityBounds {
            max_depth: 1000,
            max_nodes: 10000,
            max_operation_time_ns: 1_000_000,
            linear_tolerance: 2.0,
        };

        let mut tree = MockH2PriorityTree::new(complexity_bounds);
        let chain_info = tree.build_linear_chain(1, 100, 1).unwrap();

        assert_eq!(chain_info.length, 100);
        assert_eq!(chain_info.start_stream_id, 1);
        assert_eq!(chain_info.end_stream_id, 100);
        assert!(chain_info.construction_time_ns > 0);

        let tree_state = tree.get_tree_state();
        assert_eq!(tree_state.total_nodes, 100);
        assert_eq!(tree_state.max_depth, 100);
        assert_eq!(tree_state.root_count, 1);
    }

    #[test]
    fn test_complexity_analysis() {
        let complexity_bounds = ComplexityBounds {
            max_depth: 50,
            max_nodes: 1000,
            max_operation_time_ns: 100_000,
            linear_tolerance: 2.0,
        };

        let mut tree = MockH2PriorityTree::new(complexity_bounds);

        // Build a small chain to get some timing data
        for i in 1..=20 {
            tree.add_priority_node(i, if i == 1 { 0 } else { i - 1 }, 16, false).unwrap();
        }

        let complexity = tree.analyze_time_complexity().unwrap();
        // With small data set, should be constant or linear
        assert!(matches!(complexity,
                ComplexityClass::Constant |
                ComplexityClass::Logarithmic |
                ComplexityClass::Linear |
                ComplexityClass::Unknown));
    }

    #[test]
    fn test_depth_limits() {
        let complexity_bounds = ComplexityBounds {
            max_depth: 5,
            max_nodes: 1000,
            max_operation_time_ns: 1_000_000,
            linear_tolerance: 2.0,
        };

        let mut tree = MockH2PriorityTree::new(complexity_bounds);

        // Should be able to build chain up to depth limit
        for i in 1..=5 {
            let result = tree.add_priority_node(i, if i == 1 { 0 } else { i - 1 }, 16, false);
            assert!(result.is_ok());
        }

        // Adding one more should exceed depth limit
        let result = tree.add_priority_node(6, 5, 16, false);
        assert!(matches!(result, Err(ChainConstructionError::DepthExceeded { .. })));
    }

    #[test]
    fn test_node_limits() {
        let complexity_bounds = ComplexityBounds {
            max_depth: 1000,
            max_nodes: 5,
            max_operation_time_ns: 1_000_000,
            linear_tolerance: 2.0,
        };

        let mut tree = MockH2PriorityTree::new(complexity_bounds);

        // Should be able to add nodes up to limit
        for i in 1..=5 {
            let result = tree.add_priority_node(i, 0, 16, false); // All root dependencies
            assert!(result.is_ok());
        }

        // Adding one more should exceed node limit
        let result = tree.add_priority_node(6, 0, 16, false);
        assert!(matches!(result, Err(ChainConstructionError::ChainTooLong { .. })));
    }

    #[test]
    fn test_performance_monitoring() {
        let complexity_bounds = ComplexityBounds {
            max_depth: 100,
            max_nodes: 1000,
            max_operation_time_ns: 1_000_000,
            linear_tolerance: 2.0,
        };

        let mut tree = MockH2PriorityTree::new(complexity_bounds);

        // Build a chain and check performance data
        tree.build_linear_chain(1, 50, 1).unwrap();

        let performance_data = tree.get_performance_data();
        assert!(performance_data.total_time_ms >= 0.0);
        assert!(performance_data.avg_frame_time_us >= 0.0);
        assert!(performance_data.operations_per_second >= 0.0);
        assert!(performance_data.peak_memory_mb >= 0.0);
    }

    #[test]
    fn test_memory_tracking() {
        let complexity_bounds = ComplexityBounds {
            max_depth: 100,
            max_nodes: 1000,
            max_operation_time_ns: 1_000_000,
            linear_tolerance: 2.0,
        };

        let mut tree = MockH2PriorityTree::new(complexity_bounds);

        let initial_memory = tree.performance_monitor.memory_tracker.current_usage_bytes;

        // Add some nodes
        for i in 1..=10 {
            tree.add_priority_node(i, 0, 16, false).unwrap();
        }

        let final_memory = tree.performance_monitor.memory_tracker.current_usage_bytes;
        assert!(final_memory > initial_memory);
        assert_eq!(final_memory, initial_memory + (10 * MEMORY_OVERHEAD_PER_NODE));

        let peak_memory = tree.performance_monitor.memory_tracker.peak_usage_bytes;
        assert!(peak_memory >= final_memory);
    }

    #[test]
    fn test_chain_strategy_node_estimation() {
        let linear_strategy = ChainStrategy::Linear {
            chain_length: 100,
            start_stream_id: 1,
            increment: 1,
        };
        assert_eq!(linear_strategy.get_estimated_nodes(), 100);

        let multiple_chains = ChainStrategy::MultipleChains {
            chain_count: 3,
            chains: vec![
                ChainSpec { length: 50, start_id: 1, increment: 1, weight_pattern: WeightPattern::Uniform(16) },
                ChainSpec { length: 30, start_id: 100, increment: 1, weight_pattern: WeightPattern::Uniform(16) },
                ChainSpec { length: 20, start_id: 200, increment: 1, weight_pattern: WeightPattern::Uniform(16) },
            ],
        };
        assert_eq!(multiple_chains.get_estimated_nodes(), 100); // 50 + 30 + 20

        let exponential_tree = ChainStrategy::ExponentialTree {
            depth: 3,
            branching_factor: 2,
            max_nodes: 1000,
        };
        // 2^3 = 8, which is less than max_nodes
        assert_eq!(exponential_tree.get_estimated_nodes(), 8);
    }
}
*/

use arbitrary::Arbitrary;
use asupersync::bytes::{Bytes, BytesMut};
use asupersync::http::h2::{
    Connection, ErrorCode, Frame, Header, HpackEncoder, Settings,
    frame::{
        FrameHeader, FrameType, HeadersFrame, PriorityFrame, PrioritySpec, SettingsFrame,
        parse_frame,
    },
};
use libfuzzer_sys::fuzz_target;

const MAX_STREAMS: usize = 64;
const MAX_UPDATES: usize = 256;
const MAX_RAW_CASES: usize = 64;

#[derive(Arbitrary, Debug)]
struct Scenario {
    initial_streams: u8,
    updates: Vec<PriorityUpdate>,
    raw_cases: Vec<RawPriorityCase>,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
struct PriorityUpdate {
    stream_index: u8,
    dependency_index: u8,
    root_dependency: bool,
    self_dependency: bool,
    exclusive: bool,
    weight: u8,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
struct RawPriorityCase {
    stream_seed: u16,
    dependency_seed: u16,
    payload_len: u8,
    exclusive: bool,
    weight: u8,
}

fuzz_target!(|scenario: Scenario| {
    let mut scenario = scenario;
    scenario.updates.truncate(MAX_UPDATES);
    scenario.raw_cases.truncate(MAX_RAW_CASES);

    let stream_count = usize::from(scenario.initial_streams % MAX_STREAMS as u8).max(1);
    let stream_ids = opened_stream_ids(stream_count);
    let mut connection = open_server_connection(&stream_ids);

    for update in scenario.updates {
        exercise_priority_update(update, &stream_ids, &mut connection);
    }

    for raw in scenario.raw_cases {
        exercise_raw_priority_parse(raw);
    }
});

fn opened_stream_ids(count: usize) -> Vec<u32> {
    (0..count)
        .map(|idx| (idx as u32).saturating_mul(2).saturating_add(1))
        .collect()
}

fn open_server_connection(stream_ids: &[u32]) -> Connection {
    let mut connection = Connection::server(Settings::default());
    connection
        .process_frame(Frame::Settings(SettingsFrame::new(Vec::new())))
        .expect("initial SETTINGS should open the H2 connection");
    drain_pending(&mut connection);

    for &stream_id in stream_ids {
        let headers = request_headers(stream_id);
        connection
            .process_frame(Frame::Headers(headers))
            .expect("bounded, monotonic request HEADERS should open stream");
        drain_pending(&mut connection);
        assert!(
            connection.stream(stream_id).is_some(),
            "opened stream {stream_id} must exist"
        );
    }

    connection
}

fn request_headers(stream_id: u32) -> HeadersFrame {
    let mut encoder = HpackEncoder::new();
    let mut block = BytesMut::new();
    encoder.encode(
        &[
            Header::new(":method", "GET"),
            Header::new(":scheme", "https"),
            Header::new(":path", "/priority-fuzz"),
            Header::new(":authority", "priority.example"),
        ],
        &mut block,
    );
    HeadersFrame::new(stream_id, block.freeze(), false, true)
}

fn exercise_priority_update(
    update: PriorityUpdate,
    stream_ids: &[u32],
    connection: &mut Connection,
) {
    let stream_id = stream_ids[usize::from(update.stream_index) % stream_ids.len()];
    let dependency = if update.root_dependency {
        0
    } else if update.self_dependency {
        stream_id
    } else {
        stream_ids[usize::from(update.dependency_index) % stream_ids.len()]
    };

    if dependency == stream_id {
        assert_self_dependency_rejected_by_parser(stream_id, update.exclusive, update.weight);
        return;
    }

    let priority = PrioritySpec {
        exclusive: update.exclusive,
        dependency,
        weight: update.weight,
    };
    let frame = Frame::Priority(PriorityFrame {
        stream_id,
        priority,
    });
    connection
        .process_frame(frame)
        .expect("valid PRIORITY update for an open stream should not fail");

    let observed = connection
        .stream(stream_id)
        .expect("priority target stream should still exist")
        .priority();
    assert_eq!(
        observed, &priority,
        "Connection::process_frame must apply production PrioritySpec exactly"
    );
}

fn assert_self_dependency_rejected_by_parser(stream_id: u32, exclusive: bool, weight: u8) {
    let parsed = parse_priority_payload(stream_id, stream_id, 5, exclusive, weight);
    match parsed {
        Err(err) => {
            assert_eq!(err.code, ErrorCode::ProtocolError);
            assert_eq!(err.stream_id, Some(stream_id));
        }
        Ok(frame) => panic!("self-dependent PRIORITY parsed successfully: {frame:?}"),
    }
}

fn exercise_raw_priority_parse(raw: RawPriorityCase) {
    let stream_id = normalize_stream_id(raw.stream_seed);
    let dependency = normalize_dependency(raw.dependency_seed);
    let payload_len = usize::from(raw.payload_len % 8);
    let parsed = parse_priority_payload(
        stream_id,
        dependency,
        payload_len,
        raw.exclusive,
        raw.weight,
    );

    if stream_id == 0 {
        assert_priority_error(parsed, ErrorCode::ProtocolError, None);
    } else if payload_len != 5 {
        assert_priority_error(parsed, ErrorCode::FrameSizeError, Some(stream_id));
    } else if dependency == stream_id {
        assert_priority_error(parsed, ErrorCode::ProtocolError, Some(stream_id));
    } else {
        match parsed.expect("well-formed non-self PRIORITY must parse") {
            Frame::Priority(frame) => {
                assert_eq!(frame.stream_id, stream_id);
                assert_eq!(frame.priority.dependency, dependency);
                assert_eq!(frame.priority.exclusive, raw.exclusive);
                assert_eq!(frame.priority.weight, raw.weight);
            }
            other => panic!("PRIORITY parser returned unexpected frame: {other:?}"),
        }
    }
}

fn parse_priority_payload(
    stream_id: u32,
    dependency: u32,
    payload_len: usize,
    exclusive: bool,
    weight: u8,
) -> Result<Frame, asupersync::http::h2::H2Error> {
    let mut payload = Vec::with_capacity(5);
    let mut dependency_wire = dependency & 0x7fff_ffff;
    if exclusive {
        dependency_wire |= 0x8000_0000;
    }
    payload.extend_from_slice(&dependency_wire.to_be_bytes());
    payload.push(weight);
    payload.truncate(payload_len);
    while payload.len() < payload_len {
        payload.push(0);
    }

    let header = FrameHeader {
        length: payload_len as u32,
        frame_type: FrameType::Priority as u8,
        flags: 0,
        stream_id,
    };
    parse_frame(&header, Bytes::from(payload))
}

fn normalize_stream_id(seed: u16) -> u32 {
    if seed == 0 {
        0
    } else {
        (u32::from(seed % 1024) * 2).saturating_add(1)
    }
}

fn normalize_dependency(seed: u16) -> u32 {
    if seed.is_multiple_of(17) {
        0
    } else {
        (u32::from(seed % 1024) * 2).saturating_add(1)
    }
}

fn assert_priority_error(
    parsed: Result<Frame, asupersync::http::h2::H2Error>,
    code: ErrorCode,
    stream_id: Option<u32>,
) {
    match parsed {
        Err(err) => {
            assert_eq!(err.code, code);
            assert_eq!(err.stream_id, stream_id);
        }
        Ok(frame) => panic!("expected {code:?}, got frame {frame:?}"),
    }
}

fn drain_pending(connection: &mut Connection) {
    while connection.next_frame().is_some() {}
}

#[cfg(test)]
mod production_regressions {
    use super::*;

    #[test]
    fn parser_rejects_priority_self_dependency_as_stream_protocol_error() {
        assert_self_dependency_rejected_by_parser(1, false, 16);
    }

    #[test]
    fn parser_rejects_malformed_priority_lengths() {
        let parsed = parse_priority_payload(1, 0, 4, false, 16);
        assert_priority_error(parsed, ErrorCode::FrameSizeError, Some(1));
    }

    #[test]
    fn connection_applies_priority_updates_to_open_streams() {
        let ids = opened_stream_ids(3);
        let mut connection = open_server_connection(&ids);
        let update = PriorityUpdate {
            stream_index: 2,
            dependency_index: 0,
            root_dependency: false,
            self_dependency: false,
            exclusive: true,
            weight: 255,
        };
        exercise_priority_update(update, &ids, &mut connection);
        let priority = connection.stream(5).expect("stream 5").priority();
        assert_eq!(priority.dependency, 1);
        assert!(priority.exclusive);
        assert_eq!(priority.weight, 255);
    }
}
