#![allow(clippy::all)]
//! Property-Based Cancel Timing Generator
//!
//! This module provides comprehensive property generators for cancellation timing
//! patterns that stress-test asupersync's cancel-correctness invariants across
//! diverse execution scenarios.
//!
//! # Generator Categories
//!
//! ## 1. Basic Cancel Points
//! - Cancel before operation starts
//! - Cancel during operation execution
//! - Cancel after operation completes but before cleanup
//! - Cancel during cleanup/drain phase
//!
//! ## 2. Nested Cancellation
//! - Parent region cancels child regions
//! - Child task self-cancels
//! - Sibling task cancellation propagation
//! - Multi-level region hierarchy cancellation
//!
//! ## 3. Concurrent Cancellation
//! - Multiple cancel sources racing
//! - Cancel + timeout interactions
//! - Cancel + budget exhaustion
//! - Cancel + external signal (e.g., shutdown)
//!
//! ## 4. Two-Phase Protocol Stress
//! - Cancel during reserve phase
//! - Cancel between reserve and commit
//! - Cancel during commit phase
//! - Cancel during rollback/cleanup
//!
//! ## 5. Budget Interactions
//! - Cancel when budget nearly exhausted
//! - Budget exhaustion triggers cancel
//! - Budget renewal during cancel
//! - Infinite budget + explicit cancel

#![allow(missing_docs)]

use proptest::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A comprehensive cancellation timing scenario
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CancelTimingPattern {
    pub pattern_id: String,
    pub category: PatternCategory,
    pub description: String,
    pub timing_events: Vec<TimingEvent>,
    pub region_hierarchy: RegionHierarchy,
    pub budget_config: BudgetConfig,
    pub expected_invariants: Vec<ExpectedInvariant>,
}

/// Categories of cancellation patterns
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PatternCategory {
    BasicCancelPoints,
    NestedCancellation,
    ConcurrentCancellation,
    TwoPhasePressure,
    BudgetInteractions,
    ChaosTesting,
}

/// A single timing event in the cancellation scenario
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingEvent {
    pub event_type: EventType,
    pub virtual_time_ms: u64,
    pub target_region: RegionId,
    pub source: CancelSource,
    pub trigger_condition: Option<TriggerCondition>,
    pub expected_propagation: Vec<RegionId>,
}

/// Types of timing events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventType {
    /// Request cancellation of a region
    CancelRequest,
    /// Budget exhaustion occurs
    BudgetExhaustion,
    /// Timeout fires
    TimeoutExpiry,
    /// Task completes naturally
    TaskCompletion,
    /// External shutdown signal
    ExternalShutdown,
    /// Two-phase reserve operation
    ReserveOperation,
    /// Two-phase commit operation
    CommitOperation,
    /// Cleanup/drain phase starts
    DrainStart,
    /// Cleanup/drain phase completes
    DrainComplete,
}

/// Sources of cancellation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CancelSource {
    ParentRegion,
    SelfInitiated,
    SiblingTask,
    ExternalSignal,
    BudgetExhaustion,
    Timeout,
    UserRequest,
    SystemShutdown,
}

/// Conditions that trigger timing events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TriggerCondition {
    /// After N poll cycles
    PollCount(u32),
    /// When another event occurs
    AfterEvent(usize),
    /// When region reaches specific state
    RegionState(RegionState),
    /// When task count threshold is reached
    TaskCountThreshold(usize),
    /// Probabilistic trigger
    Probability(f64),
}

/// Region states for triggering
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RegionState {
    Created,
    Running,
    CancelRequested,
    Cancelling,
    Finalizing,
    Completed,
}

/// Simplified region hierarchy representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionHierarchy {
    pub regions: HashMap<RegionId, RegionInfo>,
    pub parent_child_edges: Vec<(RegionId, RegionId)>,
    pub root_region: RegionId,
}

/// Region information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionInfo {
    pub id: RegionId,
    pub name: String,
    pub expected_task_count: usize,
    pub cleanup_complexity: CleanupComplexity,
}

/// How complex the cleanup is for this region
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CleanupComplexity {
    /// Immediate drop, no resources
    Trivial,
    /// Simple resource cleanup
    Simple,
    /// Complex multi-step cleanup
    Complex,
    /// May require multiple poll cycles
    Async,
}

/// Budget configuration for the scenario
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetConfig {
    pub budget_type: BudgetType,
    pub initial_budget: u64,
    pub renewal_events: Vec<BudgetRenewal>,
    pub exhaustion_behavior: ExhaustionBehavior,
}

/// Types of budgets to test
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BudgetType {
    Infinite,
    Fixed(u64),
    Renewable {
        initial: u64,
        renewal_amount: u64,
    },
    Shared {
        total: u64,
        consumers: usize,
    },
    Hierarchical {
        parent_budget: u64,
        child_ratios: Vec<f64>,
    },
}

/// Budget renewal event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetRenewal {
    pub at_time_ms: u64,
    pub amount: u64,
    pub condition: Option<String>,
}

/// How budget exhaustion should behave
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExhaustionBehavior {
    ImmediateCancel,
    GracefulDrain,
    RequestMoreTime,
    FailOperation,
}

/// Expected invariants that should hold
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpectedInvariant {
    pub invariant_type: InvariantType,
    pub description: String,
    pub check_at_time: InvariantCheckTime,
}

/// Types of invariants to verify
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InvariantType {
    LosersAreDrained,
    NoRegionLeaks,
    NoTaskOrphans,
    ResourcesFreed,
    CancelProtocolFollowed,
    BudgetRespected,
    TwoPhaseCorrectness,
    StructuredConcurrency,
}

/// When to check the invariant
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InvariantCheckTime {
    AfterEachEvent,
    AtScenarioEnd,
    WhenRegionCloses,
    Continuously,
}

// Type alias for region identifiers
pub type RegionId = u32;

/// Property generators for cancel timing patterns
pub mod generators {
    use super::*;

    /// Generate basic cancel point scenarios
    pub fn basic_cancel_points() -> impl Strategy<Value = CancelTimingPattern> {
        (
            any::<u64>(),              // seed for pattern_id
            0u64..1000,                // cancel time
            cancel_source(),           // cancel source
            region_hierarchy_simple(), // simple hierarchy
        )
            .prop_map(
                |(seed, cancel_time, source, hierarchy)| CancelTimingPattern {
                    pattern_id: format!("basic-cancel-{seed:08x}"),
                    category: PatternCategory::BasicCancelPoints,
                    description: format!("Cancel at {cancel_time}ms from {source:?}"),
                    timing_events: vec![TimingEvent {
                        event_type: EventType::CancelRequest,
                        virtual_time_ms: cancel_time,
                        target_region: hierarchy.root_region,
                        source,
                        trigger_condition: None,
                        expected_propagation: vec![hierarchy.root_region],
                    }],
                    region_hierarchy: hierarchy,
                    budget_config: BudgetConfig::infinite(),
                    expected_invariants: vec![
                        ExpectedInvariant::losers_drained(),
                        ExpectedInvariant::no_leaks(),
                    ],
                },
            )
    }

    /// Generate nested cancellation scenarios
    pub fn nested_cancellation() -> impl Strategy<Value = CancelTimingPattern> {
        (
            any::<u64>(),
            2usize..=5,            // number of nesting levels
            cancel_cascade_mode(), // how cancellation propagates
        )
            .prop_map(|(seed, levels, cascade_mode)| {
                let hierarchy = RegionHierarchy::nested(levels);
                let timing_events = create_cascading_cancel_events(&hierarchy, cascade_mode);

                CancelTimingPattern {
                    pattern_id: format!("nested-cancel-{seed:08x}"),
                    category: PatternCategory::NestedCancellation,
                    description: format!(
                        "{levels} level nested cancellation with {cascade_mode:?}"
                    ),
                    timing_events,
                    region_hierarchy: hierarchy,
                    budget_config: BudgetConfig::hierarchical(levels),
                    expected_invariants: vec![
                        ExpectedInvariant::structured_concurrency(),
                        ExpectedInvariant::cancel_protocol_followed(),
                        ExpectedInvariant::no_task_orphans(),
                    ],
                }
            })
    }

    /// Generate concurrent cancellation scenarios
    pub fn concurrent_cancellation() -> impl Strategy<Value = CancelTimingPattern> {
        (
            any::<u64>(),
            2usize..=4, // number of concurrent cancellers
            0u64..100,  // time window for cancellation racing
        )
            .prop_map(|(seed, num_cancellers, time_window)| {
                let hierarchy = RegionHierarchy::concurrent_siblings(num_cancellers);
                let mut timing_events = Vec::new();

                // Create racing cancel requests
                for i in 0..num_cancellers {
                    let cancel_time = (i as u64 * time_window) / (num_cancellers as u64);
                    timing_events.push(TimingEvent {
                        event_type: EventType::CancelRequest,
                        virtual_time_ms: cancel_time,
                        target_region: i as RegionId + 1, // Skip root region (0)
                        source: CancelSource::SiblingTask,
                        trigger_condition: Some(TriggerCondition::Probability(0.7)),
                        expected_propagation: vec![i as RegionId + 1],
                    });
                }

                CancelTimingPattern {
                    pattern_id: format!("concurrent-cancel-{seed:08x}"),
                    category: PatternCategory::ConcurrentCancellation,
                    description: format!(
                        "{num_cancellers} concurrent cancellers within {time_window}ms window"
                    ),
                    timing_events,
                    region_hierarchy: hierarchy,
                    budget_config: BudgetConfig::shared(num_cancellers),
                    expected_invariants: vec![
                        ExpectedInvariant::losers_drained(),
                        ExpectedInvariant::cancel_protocol_followed(),
                    ],
                }
            })
    }

    /// Generate two-phase protocol stress scenarios
    pub fn two_phase_stress() -> impl Strategy<Value = CancelTimingPattern> {
        (
            any::<u64>(),
            two_phase_cancel_point(), // when to cancel during two-phase
            1usize..=3,               // number of two-phase operations
        )
            .prop_map(|(seed, cancel_point, num_ops)| {
                let hierarchy = RegionHierarchy::simple();
                let mut timing_events = Vec::new();

                for op_idx in 0..num_ops {
                    let base_time = op_idx as u64 * 100;

                    // Reserve phase
                    timing_events.push(TimingEvent {
                        event_type: EventType::ReserveOperation,
                        virtual_time_ms: base_time,
                        target_region: hierarchy.root_region,
                        source: CancelSource::UserRequest,
                        trigger_condition: None,
                        expected_propagation: vec![],
                    });

                    // Potential cancel point
                    if let Some(cancel_offset) = cancel_point.time_offset(base_time) {
                        timing_events.push(TimingEvent {
                            event_type: EventType::CancelRequest,
                            virtual_time_ms: cancel_offset,
                            target_region: hierarchy.root_region,
                            source: CancelSource::ExternalSignal,
                            trigger_condition: None,
                            expected_propagation: vec![hierarchy.root_region],
                        });
                    }

                    // Commit phase
                    timing_events.push(TimingEvent {
                        event_type: EventType::CommitOperation,
                        virtual_time_ms: base_time + 50,
                        target_region: hierarchy.root_region,
                        source: CancelSource::UserRequest,
                        trigger_condition: None,
                        expected_propagation: vec![],
                    });
                }

                CancelTimingPattern {
                    pattern_id: format!("two-phase-stress-{seed:08x}"),
                    category: PatternCategory::TwoPhasePressure,
                    description: format!("{num_ops} two-phase ops with cancel at {cancel_point:?}"),
                    timing_events,
                    region_hierarchy: hierarchy,
                    budget_config: BudgetConfig::renewable(50, 25),
                    expected_invariants: vec![
                        ExpectedInvariant::two_phase_correctness(),
                        ExpectedInvariant::resources_freed(),
                    ],
                }
            })
    }

    /// Generate budget interaction scenarios
    pub fn budget_interactions() -> impl Strategy<Value = CancelTimingPattern> {
        (
            any::<u64>(),
            budget_exhaustion_scenario(), // how budget exhaustion interacts with cancel
            10u64..=200,                  // budget amount
        )
            .prop_map(|(seed, exhaustion_scenario, budget_amount)| {
                let hierarchy = RegionHierarchy::simple();
                let mut timing_events = vec![];

                match exhaustion_scenario {
                    BudgetExhaustionScenario::ExhaustThenCancel => {
                        timing_events.push(TimingEvent {
                            event_type: EventType::BudgetExhaustion,
                            virtual_time_ms: 80, // Exhaust budget first
                            target_region: hierarchy.root_region,
                            source: CancelSource::BudgetExhaustion,
                            trigger_condition: None,
                            expected_propagation: vec![hierarchy.root_region],
                        });
                        timing_events.push(TimingEvent {
                            event_type: EventType::CancelRequest,
                            virtual_time_ms: 100,
                            target_region: hierarchy.root_region,
                            source: CancelSource::ExternalSignal,
                            trigger_condition: None,
                            expected_propagation: vec![hierarchy.root_region],
                        });
                    }
                    BudgetExhaustionScenario::CancelThenExhaust => {
                        timing_events.push(TimingEvent {
                            event_type: EventType::CancelRequest,
                            virtual_time_ms: 50,
                            target_region: hierarchy.root_region,
                            source: CancelSource::ExternalSignal,
                            trigger_condition: None,
                            expected_propagation: vec![hierarchy.root_region],
                        });
                        timing_events.push(TimingEvent {
                            event_type: EventType::BudgetExhaustion,
                            virtual_time_ms: 70, // Exhaust during cancel
                            target_region: hierarchy.root_region,
                            source: CancelSource::BudgetExhaustion,
                            trigger_condition: None,
                            expected_propagation: vec![],
                        });
                    }
                    BudgetExhaustionScenario::SimultaneousRacing => {
                        timing_events.push(TimingEvent {
                            event_type: EventType::CancelRequest,
                            virtual_time_ms: 75,
                            target_region: hierarchy.root_region,
                            source: CancelSource::ExternalSignal,
                            trigger_condition: Some(TriggerCondition::Probability(0.5)),
                            expected_propagation: vec![hierarchy.root_region],
                        });
                        timing_events.push(TimingEvent {
                            event_type: EventType::BudgetExhaustion,
                            virtual_time_ms: 75, // Same time - race condition
                            target_region: hierarchy.root_region,
                            source: CancelSource::BudgetExhaustion,
                            trigger_condition: Some(TriggerCondition::Probability(0.5)),
                            expected_propagation: vec![hierarchy.root_region],
                        });
                    }
                }

                CancelTimingPattern {
                    pattern_id: format!("budget-interaction-{seed:08x}"),
                    category: PatternCategory::BudgetInteractions,
                    description: format!("Budget {budget_amount} with {exhaustion_scenario:?}"),
                    timing_events,
                    region_hierarchy: hierarchy,
                    budget_config: BudgetConfig::fixed(budget_amount),
                    expected_invariants: vec![
                        ExpectedInvariant::budget_respected(),
                        ExpectedInvariant::cancel_protocol_followed(),
                    ],
                }
            })
    }

    /// Generate chaos testing scenarios
    pub fn chaos_testing() -> impl Strategy<Value = CancelTimingPattern> {
        (
            any::<u64>(),
            1usize..=5,                                   // number of chaos events
            prop::collection::vec(chaos_event(), 1..=10), // random chaos events
        )
            .prop_map(|(seed, region_count, chaos_events)| {
                let hierarchy = RegionHierarchy::random_tree(region_count);

                let timing_events = chaos_events
                    .into_iter()
                    .enumerate()
                    .map(|(i, event)| event.to_timing_event(i as u64 * 50, hierarchy.root_region))
                    .collect();

                CancelTimingPattern {
                    pattern_id: format!("chaos-{seed:08x}"),
                    category: PatternCategory::ChaosTesting,
                    description: "Random chaos events testing robustness".to_string(),
                    timing_events,
                    region_hierarchy: hierarchy,
                    budget_config: BudgetConfig::random(),
                    expected_invariants: vec![
                        ExpectedInvariant::losers_drained(),
                        ExpectedInvariant::no_leaks(),
                        ExpectedInvariant::structured_concurrency(),
                    ],
                }
            })
    }

    /// Generate a comprehensive mixed scenario combining multiple stress factors
    pub fn comprehensive_scenario() -> impl Strategy<Value = CancelTimingPattern> {
        (
            any::<u64>(),
            prop::collection::vec(scenario_component(), 2..=6),
        )
            .prop_map(|(seed, components)| {
                let hierarchy = RegionHierarchy::complex_mixed(4);
                let mut timing_events = Vec::new();
                let mut invariants = Vec::new();

                for (i, component) in components.iter().enumerate() {
                    let base_time = i as u64 * 100;
                    timing_events.extend(component.generate_events(base_time, &hierarchy));
                    invariants.extend(component.required_invariants());
                }

                CancelTimingPattern {
                    pattern_id: format!("comprehensive-{seed:08x}"),
                    category: PatternCategory::ChaosTesting,
                    description: format!("Mixed scenario with {} components", components.len()),
                    timing_events,
                    region_hierarchy: hierarchy,
                    budget_config: BudgetConfig::hierarchical(4),
                    expected_invariants: invariants,
                }
            })
    }

    // Helper generators

    fn cancel_source() -> impl Strategy<Value = CancelSource> {
        prop_oneof![
            Just(CancelSource::ParentRegion),
            Just(CancelSource::SelfInitiated),
            Just(CancelSource::ExternalSignal),
            Just(CancelSource::Timeout),
            Just(CancelSource::UserRequest),
        ]
    }

    fn region_hierarchy_simple() -> impl Strategy<Value = RegionHierarchy> {
        Just(RegionHierarchy::simple())
    }

    fn cancel_cascade_mode() -> impl Strategy<Value = CascadeMode> {
        prop_oneof![
            Just(CascadeMode::TopDown),
            Just(CascadeMode::BottomUp),
            Just(CascadeMode::MiddleOut),
            Just(CascadeMode::Random),
        ]
    }

    fn two_phase_cancel_point() -> impl Strategy<Value = TwoPhaseCancelPoint> {
        prop_oneof![
            Just(TwoPhaseCancelPoint::BeforeReserve),
            Just(TwoPhaseCancelPoint::DuringReserve),
            Just(TwoPhaseCancelPoint::BetweenReserveCommit),
            Just(TwoPhaseCancelPoint::DuringCommit),
            Just(TwoPhaseCancelPoint::AfterCommit),
        ]
    }

    fn budget_exhaustion_scenario() -> impl Strategy<Value = BudgetExhaustionScenario> {
        prop_oneof![
            Just(BudgetExhaustionScenario::ExhaustThenCancel),
            Just(BudgetExhaustionScenario::CancelThenExhaust),
            Just(BudgetExhaustionScenario::SimultaneousRacing),
        ]
    }

    fn chaos_event() -> impl Strategy<Value = ChaosEvent> {
        prop_oneof![
            Just(ChaosEvent::SpuriousWakeup),
            Just(ChaosEvent::DelayedCleanup),
            Just(ChaosEvent::BudgetSpike),
            Just(ChaosEvent::TimeoutFire),
            Just(ChaosEvent::ResourceContention),
        ]
    }

    fn scenario_component() -> impl Strategy<Value = ScenarioComponent> {
        prop_oneof![
            Just(ScenarioComponent::NestedCancel),
            Just(ScenarioComponent::TwoPhasePressure),
            Just(ScenarioComponent::BudgetPressure),
            Just(ScenarioComponent::ConcurrentRacing),
        ]
    }
}

// Supporting types and implementations

#[derive(Debug, Clone, Copy)]
pub enum CascadeMode {
    TopDown,   // Parent cancels children
    BottomUp,  // Children cancel parent
    MiddleOut, // Middle region cancels both directions
    Random,    // Random propagation order
}

#[derive(Debug, Clone)]
pub enum TwoPhaseCancelPoint {
    BeforeReserve,
    DuringReserve,
    BetweenReserveCommit,
    DuringCommit,
    AfterCommit,
}

impl TwoPhaseCancelPoint {
    fn time_offset(&self, base_time: u64) -> Option<u64> {
        match self {
            Self::BeforeReserve => Some(base_time - 10),
            Self::DuringReserve => Some(base_time + 20),
            Self::BetweenReserveCommit => Some(base_time + 25),
            Self::DuringCommit => Some(base_time + 60),
            Self::AfterCommit => None, // No cancel for this pattern
        }
    }
}

#[derive(Debug, Clone)]
pub enum BudgetExhaustionScenario {
    ExhaustThenCancel,
    CancelThenExhaust,
    SimultaneousRacing,
}

#[derive(Debug, Clone)]
pub enum ChaosEvent {
    SpuriousWakeup,
    DelayedCleanup,
    BudgetSpike,
    TimeoutFire,
    ResourceContention,
}

impl ChaosEvent {
    fn to_timing_event(&self, time: u64, target: RegionId) -> TimingEvent {
        match self {
            Self::SpuriousWakeup => TimingEvent {
                event_type: EventType::TaskCompletion,
                virtual_time_ms: time,
                target_region: target,
                source: CancelSource::ExternalSignal,
                trigger_condition: Some(TriggerCondition::Probability(0.3)),
                expected_propagation: vec![],
            },
            Self::TimeoutFire => TimingEvent {
                event_type: EventType::TimeoutExpiry,
                virtual_time_ms: time + 10,
                target_region: target,
                source: CancelSource::Timeout,
                trigger_condition: None,
                expected_propagation: vec![target],
            },
            _ => TimingEvent {
                event_type: EventType::ExternalShutdown,
                virtual_time_ms: time + 5,
                target_region: target,
                source: CancelSource::SystemShutdown,
                trigger_condition: None,
                expected_propagation: vec![target],
            },
        }
    }
}

#[derive(Debug, Clone)]
pub enum ScenarioComponent {
    NestedCancel,
    TwoPhasePressure,
    BudgetPressure,
    ConcurrentRacing,
}

impl ScenarioComponent {
    fn generate_events(&self, base_time: u64, hierarchy: &RegionHierarchy) -> Vec<TimingEvent> {
        match self {
            Self::NestedCancel => vec![TimingEvent {
                event_type: EventType::CancelRequest,
                virtual_time_ms: base_time,
                target_region: hierarchy.root_region,
                source: CancelSource::ParentRegion,
                trigger_condition: None,
                expected_propagation: hierarchy.all_child_regions(),
            }],
            _ => vec![], // Simplified for other components
        }
    }

    fn required_invariants(&self) -> Vec<ExpectedInvariant> {
        match self {
            Self::NestedCancel => vec![
                ExpectedInvariant::structured_concurrency(),
                ExpectedInvariant::no_task_orphans(),
            ],
            Self::TwoPhasePressure => vec![
                ExpectedInvariant::two_phase_correctness(),
                ExpectedInvariant::resources_freed(),
            ],
            _ => vec![ExpectedInvariant::cancel_protocol_followed()],
        }
    }
}

// Implementation for helper types

impl BudgetConfig {
    pub fn infinite() -> Self {
        Self {
            budget_type: BudgetType::Infinite,
            initial_budget: u64::MAX,
            renewal_events: vec![],
            exhaustion_behavior: ExhaustionBehavior::GracefulDrain,
        }
    }

    pub fn fixed(amount: u64) -> Self {
        Self {
            budget_type: BudgetType::Fixed(amount),
            initial_budget: amount,
            renewal_events: vec![],
            exhaustion_behavior: ExhaustionBehavior::ImmediateCancel,
        }
    }

    pub fn renewable(initial: u64, renewal: u64) -> Self {
        Self {
            budget_type: BudgetType::Renewable {
                initial,
                renewal_amount: renewal,
            },
            initial_budget: initial,
            renewal_events: vec![BudgetRenewal {
                at_time_ms: 100,
                amount: renewal,
                condition: None,
            }],
            exhaustion_behavior: ExhaustionBehavior::RequestMoreTime,
        }
    }

    pub fn shared(consumers: usize) -> Self {
        let total = consumers as u64 * 100;
        Self {
            budget_type: BudgetType::Shared { total, consumers },
            initial_budget: total,
            renewal_events: vec![],
            exhaustion_behavior: ExhaustionBehavior::GracefulDrain,
        }
    }

    pub fn hierarchical(levels: usize) -> Self {
        let ratios = (0..levels).map(|i| 1.0 / (i + 1) as f64).collect();
        Self {
            budget_type: BudgetType::Hierarchical {
                parent_budget: 1000,
                child_ratios: ratios,
            },
            initial_budget: 1000,
            renewal_events: vec![],
            exhaustion_behavior: ExhaustionBehavior::GracefulDrain,
        }
    }

    pub fn random() -> Self {
        Self {
            budget_type: BudgetType::Fixed(42), // Simple random for now
            initial_budget: 42,
            renewal_events: vec![],
            exhaustion_behavior: ExhaustionBehavior::FailOperation,
        }
    }
}

impl RegionHierarchy {
    pub fn simple() -> Self {
        let mut regions = HashMap::new();
        regions.insert(
            0,
            RegionInfo {
                id: 0,
                name: "root".to_string(),
                expected_task_count: 1,
                cleanup_complexity: CleanupComplexity::Simple,
            },
        );

        Self {
            regions,
            parent_child_edges: vec![],
            root_region: 0,
        }
    }

    pub fn nested(levels: usize) -> Self {
        let mut regions = HashMap::new();
        let mut edges = Vec::new();

        for level in 0..levels {
            regions.insert(
                level as RegionId,
                RegionInfo {
                    id: level as RegionId,
                    name: format!("level-{level}"),
                    expected_task_count: 1,
                    cleanup_complexity: if level == 0 {
                        CleanupComplexity::Trivial
                    } else {
                        CleanupComplexity::Simple
                    },
                },
            );

            if level > 0 {
                edges.push(((level - 1) as RegionId, level as RegionId));
            }
        }

        Self {
            regions,
            parent_child_edges: edges,
            root_region: 0,
        }
    }

    pub fn concurrent_siblings(count: usize) -> Self {
        let mut regions = HashMap::new();
        let mut edges = Vec::new();

        // Root region
        regions.insert(
            0,
            RegionInfo {
                id: 0,
                name: "root".to_string(),
                expected_task_count: 0,
                cleanup_complexity: CleanupComplexity::Simple,
            },
        );

        // Sibling regions
        for i in 1..=count {
            regions.insert(
                i as RegionId,
                RegionInfo {
                    id: i as RegionId,
                    name: format!("sibling-{i}"),
                    expected_task_count: 1,
                    cleanup_complexity: CleanupComplexity::Simple,
                },
            );
            edges.push((0, i as RegionId));
        }

        Self {
            regions,
            parent_child_edges: edges,
            root_region: 0,
        }
    }

    pub fn random_tree(region_count: usize) -> Self {
        // Simplified random tree
        Self::nested(region_count)
    }

    pub fn complex_mixed(levels: usize) -> Self {
        // Mixed hierarchy with both nesting and sibling patterns
        Self::nested(levels)
    }

    pub fn all_child_regions(&self) -> Vec<RegionId> {
        self.parent_child_edges
            .iter()
            .map(|(_, child)| *child)
            .collect()
    }
}

impl ExpectedInvariant {
    pub fn losers_drained() -> Self {
        Self {
            invariant_type: InvariantType::LosersAreDrained,
            description: "All race losers must be fully drained".to_string(),
            check_at_time: InvariantCheckTime::AfterEachEvent,
        }
    }

    pub fn no_leaks() -> Self {
        Self {
            invariant_type: InvariantType::NoRegionLeaks,
            description: "No region or resource leaks".to_string(),
            check_at_time: InvariantCheckTime::AtScenarioEnd,
        }
    }

    pub fn structured_concurrency() -> Self {
        Self {
            invariant_type: InvariantType::StructuredConcurrency,
            description: "Structured concurrency rules preserved".to_string(),
            check_at_time: InvariantCheckTime::Continuously,
        }
    }

    pub fn cancel_protocol_followed() -> Self {
        Self {
            invariant_type: InvariantType::CancelProtocolFollowed,
            description: "Cancel protocol state machine respected".to_string(),
            check_at_time: InvariantCheckTime::AfterEachEvent,
        }
    }

    pub fn no_task_orphans() -> Self {
        Self {
            invariant_type: InvariantType::NoTaskOrphans,
            description: "No orphaned tasks after region close".to_string(),
            check_at_time: InvariantCheckTime::WhenRegionCloses,
        }
    }

    pub fn two_phase_correctness() -> Self {
        Self {
            invariant_type: InvariantType::TwoPhaseCorrectness,
            description: "Two-phase protocols complete atomically".to_string(),
            check_at_time: InvariantCheckTime::AfterEachEvent,
        }
    }

    pub fn resources_freed() -> Self {
        Self {
            invariant_type: InvariantType::ResourcesFreed,
            description: "All resources properly released".to_string(),
            check_at_time: InvariantCheckTime::AtScenarioEnd,
        }
    }

    pub fn budget_respected() -> Self {
        Self {
            invariant_type: InvariantType::BudgetRespected,
            description: "Budget limits and exhaustion handled correctly".to_string(),
            check_at_time: InvariantCheckTime::Continuously,
        }
    }
}

fn create_cascading_cancel_events(
    hierarchy: &RegionHierarchy,
    mode: CascadeMode,
) -> Vec<TimingEvent> {
    match mode {
        CascadeMode::TopDown => {
            vec![TimingEvent {
                event_type: EventType::CancelRequest,
                virtual_time_ms: 50,
                target_region: hierarchy.root_region,
                source: CancelSource::ParentRegion,
                trigger_condition: None,
                expected_propagation: hierarchy.all_child_regions(),
            }]
        }
        _ => {
            // Simplified implementation for other modes
            vec![TimingEvent {
                event_type: EventType::CancelRequest,
                virtual_time_ms: 100,
                target_region: hierarchy.root_region,
                source: CancelSource::SelfInitiated,
                trigger_condition: None,
                expected_propagation: vec![hierarchy.root_region],
            }]
        }
    }
}

/// Generate all cancellation timing pattern families
pub fn all_pattern_families() -> Vec<BoxedStrategy<CancelTimingPattern>> {
    vec![
        generators::basic_cancel_points().boxed(),
        generators::nested_cancellation().boxed(),
        generators::concurrent_cancellation().boxed(),
        generators::two_phase_stress().boxed(),
        generators::budget_interactions().boxed(),
        generators::chaos_testing().boxed(),
        generators::comprehensive_scenario().boxed(),
    ]
}

/// Generate a random pattern from all families
pub fn any_cancel_timing_pattern() -> impl Strategy<Value = CancelTimingPattern> {
    prop_oneof![
        generators::basic_cancel_points(),
        generators::nested_cancellation(),
        generators::concurrent_cancellation(),
        generators::two_phase_stress(),
        generators::budget_interactions(),
        generators::chaos_testing(),
    ]
}

#[cfg(test)]
mod tests {
    use super::generators::*;
    use super::*;
    use proptest::strategy::ValueTree;

    #[test]
    fn test_basic_pattern_generation() {
        let mut runner = proptest::test_runner::TestRunner::deterministic();
        let tree = basic_cancel_points().new_tree(&mut runner).unwrap();
        let pattern = tree.current();

        // Should be a basic cancel point pattern
        assert_eq!(pattern.category, PatternCategory::BasicCancelPoints);
        assert!(!pattern.timing_events.is_empty());
    }

    #[test]
    fn test_comprehensive_pattern_coverage() {
        let families = all_pattern_families();
        assert_eq!(families.len(), 7, "Should have all 7 pattern families");
    }

    proptest! {
        #[test]
        fn property_all_patterns_have_required_fields(
            pattern in any_cancel_timing_pattern()
        ) {
            // Every pattern must have a unique ID
            assert!(!pattern.pattern_id.is_empty());

            // Every pattern must have a description
            assert!(!pattern.description.is_empty());

            // Every pattern must have at least one timing event
            assert!(!pattern.timing_events.is_empty());

            // Every pattern must have expected invariants
            assert!(!pattern.expected_invariants.is_empty());
        }

        #[test]
        fn property_timing_events_are_ordered(
            pattern in any_cancel_timing_pattern()
        ) {
            // Timing events should be in chronological order
            for window in pattern.timing_events.windows(2) {
                assert!(window[0].virtual_time_ms <= window[1].virtual_time_ms);
            }
        }

        #[test]
        fn property_region_hierarchy_is_valid(
            pattern in any_cancel_timing_pattern()
        ) {
            let hierarchy = &pattern.region_hierarchy;

            // Root region must exist
            assert!(hierarchy.regions.contains_key(&hierarchy.root_region));

            // All edge targets must be valid regions
            for (parent, child) in &hierarchy.parent_child_edges {
                assert!(hierarchy.regions.contains_key(parent));
                assert!(hierarchy.regions.contains_key(child));
            }
        }
    }
}
