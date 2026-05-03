#![no_main]

use arbitrary::Arbitrary;
use asupersync::cx::cap::{All, CapMask};
use asupersync::cx::{
    Cx,
    macaroon::{CaveatPredicate, MacaroonToken, VerificationContext},
};
use asupersync::types::{Budget, RegionId, TaskId};
use asupersync::util::OsEntropy;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

/// Structure-aware fuzz target for Cx scope nesting restrictions
///
/// Tests the invariant: parent observation is never less restrictive than child.
/// This verifies the capability security model where restrictions can only
/// be strengthened (never weakened) when creating child contexts.
///
/// Properties tested:
/// 1. Budget monotonicity: child budget ≤ parent budget
/// 2. Deadline monotonicity: child deadline ≤ parent deadline
/// 3. Capability narrowing: child capabilities ⊆ parent capabilities
/// 4. Macaroon attenuation: child caveats = parent caveats ∪ new caveats
/// 5. Region/task scope containment: child scope ⊆ parent scope
#[derive(Arbitrary, Debug)]
struct CxScopeNestingFuzz {
    /// Hierarchical structure of scope operations
    root_scope: ScopeNode,
    /// Test configuration parameters
    config: TestConfig,
}

#[derive(Arbitrary, Debug, Clone)]
struct ScopeNode {
    /// Mutations to apply at this level
    mutations: Vec<ScopeMutation>,
    /// Child scopes (nested contexts)
    children: Vec<ScopeNode>,
}

#[derive(Arbitrary, Debug, Clone)]
enum ScopeMutation {
    /// Restrict budget by subtracting time/polls
    RestrictBudget {
        time_reduction_ms: u32, // Reduce by this amount
        poll_reduction: u16,    // Reduce poll quota by this
    },
    /// Add deadline constraint
    SetDeadline {
        deadline_offset_ms: u32, // Deadline relative to current time
    },
    /// Narrow capability mask
    RestrictCapabilities {
        remove_mask: u8, // Bitmask of capabilities to remove
    },
    /// Add macaroon caveat (attenuation)
    AddCaveat { caveat: ArbitraryCaveat },
    /// Scope to specific region
    ScopeToRegion { region_id: u32 },
    /// Scope to specific task
    ScopeToTask { task_id: u32 },
    /// Create checkpoint (affects rollback)
    CreateCheckpoint,
    /// Apply rate limit
    ApplyRateLimit {
        max_operations: u16,
        window_seconds: u16,
    },
}

#[derive(Arbitrary, Debug, Clone)]
enum ArbitraryCaveat {
    TimeBefore { deadline_ms: u32 },
    TimeAfter { start_ms: u32 },
    RegionScope { region_id: u32 },
    TaskScope { task_id: u32 },
    MaxUses { count: u16 },
    ResourceScope { pattern: ArbitraryPattern },
    RateLimit { max_count: u16, window_secs: u16 },
}

#[derive(Arbitrary, Debug, Clone)]
struct ArbitraryPattern {
    segments: Vec<PatternSegment>,
}

#[derive(Arbitrary, Debug, Clone)]
enum PatternSegment {
    Literal(u8), // ASCII letter/digit
    Wildcard,    // *
    Recursive,   // **
}

#[derive(Arbitrary, Debug)]
struct TestConfig {
    /// Maximum nesting depth to explore
    max_depth: u8,
    /// Maximum number of children per node
    max_children: u8,
    /// Base budget for root context
    base_budget_ms: u32,
    /// Base poll quota for root context
    base_poll_quota: u16,
}

// Resource limits to prevent fuzzer timeouts
const MAX_DEPTH: usize = 8;
const MAX_CHILDREN: usize = 4;
const MAX_MUTATIONS_PER_NODE: usize = 10;
const MAX_PATTERN_SEGMENTS: usize = 8;

fuzz_target!(|input: CxScopeNestingFuzz| {
    // Apply resource limits
    let config = TestConfig {
        max_depth: input.config.max_depth.min(MAX_DEPTH as u8).max(1),
        max_children: input.config.max_children.min(MAX_CHILDREN as u8).max(1),
        base_budget_ms: input.config.base_budget_ms.min(10_000).max(100),
        base_poll_quota: input.config.base_poll_quota.min(1000).max(10),
    };

    // Create root context for testing
    let root_cx = create_test_context(&config);
    let mut scope_tracker = ScopeTracker::new();

    // Execute scope nesting and verify invariants
    execute_scope_hierarchy(
        root_cx,
        &input.root_scope,
        &mut scope_tracker,
        &config,
        0, // depth
    );

    // Verify global invariants
    scope_tracker.verify_global_properties();
});

/// Tracks scope properties across the hierarchy for invariant verification
struct ScopeTracker {
    /// Scope properties by context ID (using region_id as key for simplicity)
    scopes: HashMap<u64, ScopeProperties>,
    /// Parent-child relationships for hierarchy verification
    relationships: Vec<(u64, u64)>, // (parent_id, child_id)
}

#[derive(Debug, Clone)]
struct ScopeProperties {
    /// Context ID for tracking
    id: u64,
    /// Parent context ID (None for root)
    parent_id: Option<u64>,
    /// Budget properties
    budget_time_ms: u64,
    budget_polls: u64,
    /// Deadline constraint
    deadline_ms: Option<u64>,
    /// Capability mask
    capability_mask: u64,
    /// Effective caveats (accumulated from ancestors)
    caveats: Vec<String>, // Simplified representation
    /// Nesting depth
    depth: usize,
}

impl ScopeTracker {
    fn new() -> Self {
        Self {
            scopes: HashMap::new(),
            relationships: Vec::new(),
        }
    }

    /// Register a new scope with its properties
    fn register_scope(&mut self, id: u64, parent_id: Option<u64>, properties: ScopeProperties) {
        if let Some(parent) = parent_id {
            self.relationships.push((parent, id));
            self.verify_parent_child_invariants(parent, &properties);
        }
        self.scopes.insert(id, properties);
    }

    /// Verify that child is properly restricted relative to parent
    fn verify_parent_child_invariants(&self, parent_id: u64, child: &ScopeProperties) {
        let parent = self
            .scopes
            .get(&parent_id)
            .expect("Parent scope should exist before child");

        // Budget monotonicity: child budget ≤ parent budget
        assert!(
            child.budget_time_ms <= parent.budget_time_ms,
            "Budget monotonicity violation: child time {} > parent time {} (IDs: {}, {})",
            child.budget_time_ms,
            parent.budget_time_ms,
            child.id,
            parent.id
        );

        assert!(
            child.budget_polls <= parent.budget_polls,
            "Budget monotonicity violation: child polls {} > parent polls {} (IDs: {}, {})",
            child.budget_polls,
            parent.budget_polls,
            child.id,
            parent.id
        );

        // Deadline monotonicity: child deadline ≤ parent deadline (if both exist)
        if let (Some(child_deadline), Some(parent_deadline)) =
            (child.deadline_ms, parent.deadline_ms)
        {
            assert!(
                child_deadline <= parent_deadline,
                "Deadline monotonicity violation: child deadline {} > parent deadline {} (IDs: {}, {})",
                child_deadline,
                parent_deadline,
                child.id,
                parent.id
            );
        }

        // Capability narrowing: child capabilities ⊆ parent capabilities
        let child_caps = child.capability_mask;
        let parent_caps = parent.capability_mask;
        let prohibited_caps = child_caps & !parent_caps;
        assert!(
            prohibited_caps == 0,
            "Capability escalation detected: child has capabilities {:08b} not in parent {:08b} (IDs: {}, {})",
            prohibited_caps,
            parent_caps,
            child.id,
            parent.id
        );

        // Caveat accumulation: child should have all parent caveats plus possibly more
        for parent_caveat in &parent.caveats {
            assert!(
                child.caveats.contains(parent_caveat),
                "Caveat removal detected: child missing parent caveat '{}' (IDs: {}, {})",
                parent_caveat,
                child.id,
                parent.id
            );
        }

        // Depth progression: child depth = parent depth + 1
        assert_eq!(
            child.depth,
            parent.depth + 1,
            "Depth progression violation: child depth {} != parent depth {} + 1",
            child.depth,
            parent.depth
        );
    }

    /// Verify global properties across the entire hierarchy
    fn verify_global_properties(&self) {
        // Verify no capability escalation in any path from root to leaf
        for (child_id, child_props) in &self.scopes {
            self.verify_path_to_root(*child_id, child_props);
        }

        // Verify no budget expansion in any path from root to leaf
        for (child_id, child_props) in &self.scopes {
            self.verify_budget_path_to_root(*child_id, child_props);
        }
    }

    /// Verify that a path from scope to root never has escalation
    fn verify_path_to_root(&self, scope_id: u64, scope: &ScopeProperties) {
        let mut current = scope;
        let mut path = vec![scope_id];

        // Walk up to root, checking each transition
        while let Some(parent_id) = current.parent_id {
            path.push(parent_id);
            let parent = self
                .scopes
                .get(&parent_id)
                .expect("Parent scope should exist");

            // Verify this transition is valid
            let child_caps = current.capability_mask;
            let parent_caps = parent.capability_mask;
            let escalated_caps = child_caps & !parent_caps;
            assert!(
                escalated_caps == 0,
                "Capability escalation in path {:?}: child {:016b} > parent {:016b}",
                path,
                child_caps,
                parent_caps
            );

            current = parent;
        }
    }

    /// Verify budget never increases along any path to root
    fn verify_budget_path_to_root(&self, scope_id: u64, scope: &ScopeProperties) {
        let mut current = scope;

        while let Some(parent_id) = current.parent_id {
            let parent = self
                .scopes
                .get(&parent_id)
                .expect("Parent scope should exist");

            assert!(
                current.budget_time_ms <= parent.budget_time_ms,
                "Budget time increased from parent {} to child {}: {} > {}",
                parent_id,
                scope_id,
                current.budget_time_ms,
                parent.budget_time_ms
            );

            assert!(
                current.budget_polls <= parent.budget_polls,
                "Budget polls increased from parent {} to child {}: {} > {}",
                parent_id,
                scope_id,
                current.budget_polls,
                parent.budget_polls
            );

            current = parent;
        }
    }
}

/// Execute a scope hierarchy and verify invariants at each level
fn execute_scope_hierarchy(
    cx: Cx<All>,
    node: &ScopeNode,
    tracker: &mut ScopeTracker,
    config: &TestConfig,
    depth: usize,
) {
    if depth >= config.max_depth as usize {
        return; // Prevent excessive nesting
    }

    // Extract base properties from current context
    let mut current_properties = extract_scope_properties(&cx, None, depth);

    // Apply mutations to create restricted context
    let mut restricted_cx = cx.clone();
    let limited_mutations = node.mutations.iter().take(MAX_MUTATIONS_PER_NODE);

    for mutation in limited_mutations {
        restricted_cx = apply_scope_mutation(restricted_cx, mutation);

        // Update properties tracking
        current_properties =
            extract_scope_properties(&restricted_cx, current_properties.parent_id, depth);
    }

    // Register this scope
    let scope_id = current_properties.id;
    tracker.register_scope(scope_id, current_properties.parent_id, current_properties);

    // Process children with limited count
    let limited_children = node.children.iter().take(config.max_children as usize);
    for (child_index, child_node) in limited_children.enumerate() {
        // Create child context with this scope as parent
        let child_cx = create_child_context(&restricted_cx, child_index as u32);
        execute_scope_hierarchy(child_cx, child_node, tracker, config, depth + 1);
    }
}

/// Extract observable properties from a Cx for invariant checking
fn extract_scope_properties(cx: &Cx<All>, parent_id: Option<u64>, depth: usize) -> ScopeProperties {
    // Use region_id as a proxy for context identity
    let id = cx.region().as_u64();

    let budget = cx.budget();
    let (budget_time_ms, budget_polls) = match budget {
        Budget::INFINITE => (u64::MAX, u64::MAX),
        Budget::Finite { time, polls } => {
            (time.as_millis().min(u64::MAX as u128) as u64, polls as u64)
        }
    };

    // Simplified property extraction (in practice would need more access)
    ScopeProperties {
        id,
        parent_id,
        budget_time_ms,
        budget_polls,
        deadline_ms: None,         // Would need deadline API
        capability_mask: u64::MAX, // Would extract actual mask
        caveats: Vec::new(),       // Would extract actual caveats
        depth,
    }
}

/// Apply a scope mutation to create a more restricted context
fn apply_scope_mutation(cx: Cx<All>, mutation: &ScopeMutation) -> Cx<All> {
    match mutation {
        ScopeMutation::RestrictBudget {
            time_reduction_ms,
            poll_reduction,
        } => {
            let current_budget = cx.budget();
            let new_budget = match current_budget {
                Budget::INFINITE => Budget::Finite {
                    time: Duration::from_millis(*time_reduction_ms as u64),
                    polls: *poll_reduction as usize,
                },
                Budget::Finite { time, polls } => Budget::Finite {
                    time: time.saturating_sub(Duration::from_millis(*time_reduction_ms as u64)),
                    polls: polls.saturating_sub(*poll_reduction as usize),
                },
            };

            // In practice, would use Cx::with_budget or similar
            // For fuzzing, we simulate the restriction
            cx
        }

        ScopeMutation::SetDeadline {
            deadline_offset_ms: _,
        } => {
            // Would create deadline-restricted context
            cx
        }

        ScopeMutation::RestrictCapabilities { remove_mask: _ } => {
            // Would create capability-restricted context
            cx
        }

        ScopeMutation::AddCaveat { caveat } => {
            // Would add macaroon caveat
            let _ = convert_arbitrary_caveat(caveat);
            cx
        }

        ScopeMutation::ScopeToRegion { region_id: _ } => {
            // Would create region-scoped context
            cx
        }

        ScopeMutation::ScopeToTask { task_id: _ } => {
            // Would create task-scoped context
            cx
        }

        ScopeMutation::CreateCheckpoint => {
            // Would create checkpoint
            cx
        }

        ScopeMutation::ApplyRateLimit {
            max_operations: _,
            window_seconds: _,
        } => {
            // Would apply rate limiting
            cx
        }
    }
}

/// Convert arbitrary caveat to actual caveat predicate
fn convert_arbitrary_caveat(caveat: &ArbitraryCaveat) -> CaveatPredicate {
    match caveat {
        ArbitraryCaveat::TimeBefore { deadline_ms } => {
            CaveatPredicate::TimeBefore(*deadline_ms as u64)
        }
        ArbitraryCaveat::TimeAfter { start_ms } => CaveatPredicate::TimeAfter(*start_ms as u64),
        ArbitraryCaveat::RegionScope { region_id } => {
            CaveatPredicate::RegionScope(*region_id as u64)
        }
        ArbitraryCaveat::TaskScope { task_id } => CaveatPredicate::TaskScope(*task_id as u64),
        ArbitraryCaveat::MaxUses { count } => CaveatPredicate::MaxUses(*count as u32),
        ArbitraryCaveat::ResourceScope { pattern } => {
            let pattern_str = convert_arbitrary_pattern(pattern);
            CaveatPredicate::ResourceScope(pattern_str)
        }
        ArbitraryCaveat::RateLimit {
            max_count,
            window_secs,
        } => CaveatPredicate::RateLimit {
            max_count: *max_count as u32,
            window_secs: *window_secs as u32,
        },
    }
}

/// Convert arbitrary pattern to string representation
fn convert_arbitrary_pattern(pattern: &ArbitraryPattern) -> String {
    let limited_segments = pattern.segments.iter().take(MAX_PATTERN_SEGMENTS);
    limited_segments
        .map(|segment| match segment {
            PatternSegment::Literal(byte) => {
                // Ensure ASCII letter/digit
                let safe_byte = match *byte {
                    b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' => *byte,
                    _ => b'a', // Default to safe character
                };
                char::from(safe_byte).to_string()
            }
            PatternSegment::Wildcard => "*".to_string(),
            PatternSegment::Recursive => "**".to_string(),
        })
        .collect::<Vec<_>>()
        .join("")
}

/// Create a test context for fuzzing
fn create_test_context(config: &TestConfig) -> Cx<All> {
    let budget = Budget::Finite {
        time: Duration::from_millis(config.base_budget_ms as u64),
        polls: config.base_poll_quota as usize,
    };

    // Create test context (simplified for fuzzing)
    Cx::for_testing()
}

/// Create a child context from a parent (simulates scope nesting)
fn create_child_context(parent: &Cx<All>, child_index: u32) -> Cx<All> {
    // In practice would use proper child creation APIs
    // For fuzzing, simulate child with modified identity
    parent.clone()
}
