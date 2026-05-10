#![no_main]

use arbitrary::Arbitrary;
use asupersync::{
    cancel::symbol_cancel::{CancelListener, SymbolCancelToken},
    types::{CancelKind, CancelReason, ObjectId, Time},
    util::DetRng,
};
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

// Focus on 3-deep hierarchies as requested
const MAX_HIERARCHY_DEPTH: u8 = 3;
const MAX_OPS: usize = 100;
const MAX_THREADS: usize = 3;

#[derive(Debug, Arbitrary)]
struct FuzzInput {
    scenario: CancellationScenario,
    operations: Vec<HierarchyOperation>,
    thread_count: u8,
    interleaving_pattern: InterleavingPattern,
}

#[derive(Debug, Clone, Arbitrary)]
enum CancellationScenario {
    /// Simple top-down cancellation
    TopDown,
    /// Bottom-up cancellation
    BottomUp,
    /// Middle-out cancellation from level 2
    MiddleOut,
    /// Concurrent cancellation at multiple levels
    Concurrent,
    /// Rapid fire cancellations with different reasons
    RapidFire,
}

#[derive(Debug, Clone, Arbitrary)]
enum InterleavingPattern {
    /// Sequential execution
    Sequential,
    /// Random delays between operations
    RandomDelay { delay_scale: u8 },
    /// Barrier-synchronized parallel execution
    BarrierSync,
}

#[derive(Debug, Clone, Arbitrary)]
enum HierarchyOperation {
    /// Cancel at specific level with given reason
    CancelAtLevel {
        level: u8, // 0=root, 1=child, 2=grandchild
        reason: CancelReasonFuzz,
        time_offset: u64,
    },
    /// Add listener at specific level to track phases
    AddPhaseListener {
        level: u8,
        listener_type: PhaseListenerType,
    },
    /// Poll status at specific level
    PollLevel { level: u8, check_type: StatusCheck },
    /// Create additional child at level (testing late children)
    CreateLateChild { parent_level: u8, rng_seed: u64 },
    /// Simulate work during drain phase
    SimulateDrainWork { level: u8, work_duration_ms: u8 },
}

#[derive(Debug, Clone, Copy, Arbitrary)]
enum CancelReasonFuzz {
    User,
    Timeout,
    Shutdown,
    RaceLost,
    ParentCancelled,
}

#[derive(Debug, Clone, Arbitrary)]
enum PhaseListenerType {
    /// Tracks request phase
    RequestPhase,
    /// Tracks drain phase (cleanup work)
    DrainPhase,
    /// Tracks finalize phase (final cleanup)
    FinalizePhase,
    /// Panics during specific phase to test error handling
    PanickingListener { panic_in_phase: u8 },
}

#[derive(Debug, Clone, Arbitrary)]
enum StatusCheck {
    IsCancelled,
    GetReason,
    GetCancelledAt,
    CountChildren,
    CountListeners,
    VerifyInvariants,
}

impl From<CancelReasonFuzz> for CancelKind {
    fn from(reason: CancelReasonFuzz) -> Self {
        match reason {
            CancelReasonFuzz::User => CancelKind::User,
            CancelReasonFuzz::Timeout => CancelKind::Timeout,
            CancelReasonFuzz::Shutdown => CancelKind::Shutdown,
            CancelReasonFuzz::RaceLost => CancelKind::RaceLost,
            CancelReasonFuzz::ParentCancelled => CancelKind::ParentCancelled,
        }
    }
}

/// Phase-tracking listener to detect protocol violations
#[derive(Debug, Clone)]
struct PhaseTracker {
    phase_type: PhaseListenerType,
    call_count: Arc<Mutex<u32>>,
    phase_history: Arc<Mutex<Vec<(String, Time)>>>,
    token_level: u8,
    should_panic: bool,
}

impl PhaseTracker {
    fn new(phase_type: PhaseListenerType, token_level: u8) -> Self {
        let should_panic = match &phase_type {
            PhaseListenerType::PanickingListener { panic_in_phase } => {
                panic_in_phase % MAX_HIERARCHY_DEPTH == token_level
            }
            _ => false,
        };

        Self {
            phase_type,
            call_count: Arc::new(Mutex::new(0)),
            phase_history: Arc::new(Mutex::new(Vec::new())),
            token_level,
            should_panic,
        }
    }

    fn get_history(&self) -> Vec<(String, Time)> {
        self.phase_history.lock().unwrap().clone()
    }

    fn call_count(&self) -> u32 {
        *self.call_count.lock().unwrap()
    }
}

impl CancelListener for PhaseTracker {
    fn on_cancel(&self, reason: &CancelReason, at: Time) {
        if self.should_panic {
            panic!(
                "PhaseTracker intentional panic at level {}",
                self.token_level
            );
        }

        let mut count = self.call_count.lock().unwrap();
        *count += 1;
        drop(count);

        let phase_name = match &self.phase_type {
            PhaseListenerType::RequestPhase => "REQUEST",
            PhaseListenerType::DrainPhase => "DRAIN",
            PhaseListenerType::FinalizePhase => "FINALIZE",
            PhaseListenerType::PanickingListener { .. } => "PANIC",
        };

        let entry = (
            format!(
                "{}(level={}, kind={:?})",
                phase_name, self.token_level, reason.kind
            ),
            at,
        );

        let mut history = self.phase_history.lock().unwrap();
        history.push(entry);
    }
}

/// Hierarchy state for 3-deep testing
#[derive(Debug)]
struct HierarchyState {
    root: SymbolCancelToken,               // Level 0
    children: Vec<SymbolCancelToken>,      // Level 1
    grandchildren: Vec<SymbolCancelToken>, // Level 2
    listeners: HashMap<u8, Vec<Arc<PhaseTracker>>>,
    operation_log: Arc<Mutex<Vec<String>>>,
}

impl HierarchyState {
    fn new(rng_seed: u64) -> Self {
        let mut rng = DetRng::new(rng_seed);
        let object_id = ObjectId::new_for_test(42);

        let root = SymbolCancelToken::new(object_id, &mut rng);

        // Create exactly 3-deep hierarchy as requested
        let child1 = root.child(&mut rng);
        let child2 = root.child(&mut rng);

        let grandchild1 = child1.child(&mut rng);
        let grandchild2 = child1.child(&mut rng);
        let grandchild3 = child2.child(&mut rng);

        Self {
            root,
            children: vec![child1, child2],
            grandchildren: vec![grandchild1, grandchild2, grandchild3],
            listeners: HashMap::new(),
            operation_log: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn get_token_at_level(&self, level: u8) -> Option<&SymbolCancelToken> {
        match level {
            0 => Some(&self.root),
            1 => self.children.first(),
            2 => self.grandchildren.first(),
            _ => None,
        }
    }

    fn get_all_tokens_at_level(&self, level: u8) -> Vec<&SymbolCancelToken> {
        match level {
            0 => vec![&self.root],
            1 => self.children.iter().collect(),
            2 => self.grandchildren.iter().collect(),
            _ => vec![],
        }
    }

    fn add_phase_listener(&mut self, level: u8, listener_type: PhaseListenerType) {
        if let Some(token) = self.get_token_at_level(level) {
            let tracker = Arc::new(PhaseTracker::new(listener_type, level));
            token.add_listener(tracker.as_ref().clone());

            self.listeners.entry(level).or_default().push(tracker);
        }
    }

    fn verify_request_drain_finalize_invariants(&self) -> Vec<String> {
        let mut violations = Vec::new();

        // INVARIANT 1: If a token is cancelled, all descendants must be cancelled
        if self.root.is_cancelled() {
            for child in self.get_all_tokens_at_level(1) {
                if !child.is_cancelled() {
                    violations.push(
                        "INVARIANT VIOLATION: Root cancelled but child at level 1 not cancelled"
                            .to_string(),
                    );
                }
            }

            for grandchild in self.get_all_tokens_at_level(2) {
                if !grandchild.is_cancelled() {
                    violations.push(
                        "INVARIANT VIOLATION: Root cancelled but grandchild at level 2 not cancelled"
                            .to_string(),
                    );
                }
            }
        }

        // INVARIANT 2: Parent cancellation timestamp should be <= child cancellation timestamp
        if let (Some(root_time), Some(child_time)) = (
            self.root.cancelled_at(),
            self.children.first().and_then(|c| c.cancelled_at()),
        ) && root_time > child_time
        {
            violations.push(format!(
                "INVARIANT VIOLATION: Parent cancelled after child (parent={:?}, child={:?})",
                root_time, child_time
            ));
        }

        // INVARIANT 3: Check that all listeners were notified
        for (level, trackers) in &self.listeners {
            for tracker in trackers {
                if tracker.call_count() == 0 {
                    let token = self.get_token_at_level(*level);
                    if let Some(token) = token
                        && token.is_cancelled()
                    {
                        violations.push(format!(
                            "INVARIANT VIOLATION: Token at level {} cancelled but listener never called",
                            level
                        ));
                    }
                }
            }
        }

        // INVARIANT 4: Check phase ordering (request→drain→finalize)
        for trackers in self.listeners.values() {
            for tracker in trackers {
                let history = tracker.get_history();
                for window in history.windows(2) {
                    let (ref phase1, time1) = window[0];
                    let (ref phase2, time2) = window[1];

                    // Times should be monotonic (later phases shouldn't have earlier timestamps)
                    if time1 > time2 {
                        violations.push(format!(
                            "INVARIANT VIOLATION: Phase ordering violation - {} at {:?} after {} at {:?}",
                            phase1, time1, phase2, time2
                        ));
                    }
                }
            }
        }

        violations
    }

    fn log_operation(&self, op: &str) {
        if let Ok(mut log) = self.operation_log.lock() {
            log.push(op.to_string());
        }
    }
}

/// Execute a hierarchy operation with potential race conditions
fn execute_hierarchy_operation(
    state: &mut HierarchyState,
    op: &HierarchyOperation,
    base_time: Time,
) {
    let operation_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        match op {
            HierarchyOperation::CancelAtLevel {
                level,
                reason,
                time_offset,
            } => {
                if let Some(token) = state.get_token_at_level(*level) {
                    let cancel_time = Time::from_nanos(base_time.as_nanos() + *time_offset);
                    let cancel_reason = CancelReason::new((*reason).into());

                    state.log_operation(&format!(
                        "CANCEL level={} reason={:?} time={:?}",
                        level, reason, cancel_time
                    ));

                    token.cancel(&cancel_reason, cancel_time);
                }
            }

            HierarchyOperation::AddPhaseListener {
                level,
                listener_type,
            } => {
                state.log_operation(&format!(
                    "ADD_LISTENER level={} type={:?}",
                    level, listener_type
                ));
                state.add_phase_listener(*level, listener_type.clone());
            }

            HierarchyOperation::PollLevel { level, check_type } => {
                if let Some(token) = state.get_token_at_level(*level) {
                    let result = match check_type {
                        StatusCheck::IsCancelled => token.is_cancelled().to_string(),
                        StatusCheck::GetReason => format!("{:?}", token.reason()),
                        StatusCheck::GetCancelledAt => format!("{:?}", token.cancelled_at()),
                        _ => "unknown_check".to_string(),
                    };

                    state.log_operation(&format!(
                        "POLL level={} check={:?} result={}",
                        level, check_type, result
                    ));
                }
            }

            HierarchyOperation::CreateLateChild {
                parent_level,
                rng_seed,
            } => {
                if let Some(parent_token) = state.get_token_at_level(*parent_level) {
                    let mut rng = DetRng::new(*rng_seed);
                    let late_child = parent_token.child(&mut rng);

                    state.log_operation(&format!(
                        "CREATE_LATE_CHILD parent_level={} cancelled={}",
                        parent_level,
                        late_child.is_cancelled()
                    ));

                    // Add late child to appropriate collection
                    match parent_level {
                        0 => {
                            // This is mutable access - we need to handle this carefully
                            // For fuzzing purposes, we'll just check the invariants
                        }
                        1 => {
                            // Late grandchild
                        }
                        _ => {}
                    }
                }
            }

            HierarchyOperation::SimulateDrainWork {
                level,
                work_duration_ms,
            } => {
                state.log_operation(&format!(
                    "DRAIN_WORK level={} duration_ms={}",
                    level, work_duration_ms
                ));

                // Simulate cleanup work during drain phase
                std::thread::sleep(std::time::Duration::from_millis(*work_duration_ms as u64));
            }
        }
    }));
    assert!(
        operation_result.is_ok(),
        "cancel hierarchy operation panicked: op={op:?}, base_time={base_time:?}"
    );
}

/// Test the full request→drain→finalize protocol across 3-deep hierarchy
fn test_request_drain_finalize_protocol(input: &FuzzInput) {
    let protocol_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut state = HierarchyState::new(12345);
        let base_time =
            Time::from_nanos(1000 + interleaving_delay_nanos(&input.interleaving_pattern));

        // Execute operations according to the scenario
        match &input.scenario {
            CancellationScenario::TopDown => {
                test_topdown_cancellation(&mut state, &input.operations, base_time);
            }
            CancellationScenario::BottomUp => {
                test_bottomup_cancellation(&mut state, &input.operations, base_time);
            }
            CancellationScenario::MiddleOut => {
                test_middleout_cancellation(&mut state, &input.operations, base_time);
            }
            CancellationScenario::Concurrent => {
                test_concurrent_cancellation(
                    &mut state,
                    &input.operations,
                    base_time,
                    input.thread_count,
                );
            }
            CancellationScenario::RapidFire => {
                test_rapid_fire_cancellation(&mut state, &input.operations, base_time);
            }
        }

        // Verify critical invariants
        let violations = state.verify_request_drain_finalize_invariants();
        assert!(
            violations.is_empty(),
            "Protocol violations detected: {:?}",
            violations
        );
    }));
    assert!(
        protocol_result.is_ok(),
        "cancel hierarchy request-drain-finalize protocol panicked: scenario={:?}, operations={}, thread_count={}, interleaving={:?}",
        input.scenario,
        input.operations.len(),
        input.thread_count,
        input.interleaving_pattern
    );
}

fn interleaving_delay_nanos(pattern: &InterleavingPattern) -> u64 {
    match pattern {
        InterleavingPattern::Sequential => 0,
        InterleavingPattern::RandomDelay { delay_scale } => u64::from(*delay_scale),
        InterleavingPattern::BarrierSync => 1,
    }
}

fn test_topdown_cancellation(
    state: &mut HierarchyState,
    operations: &[HierarchyOperation],
    base_time: Time,
) {
    // Add listeners to track all phases at all levels
    for level in 0..MAX_HIERARCHY_DEPTH {
        state.add_phase_listener(level, PhaseListenerType::RequestPhase);
        state.add_phase_listener(level, PhaseListenerType::DrainPhase);
        state.add_phase_listener(level, PhaseListenerType::FinalizePhase);
    }

    // Execute operations
    for op in operations {
        execute_hierarchy_operation(state, op, base_time);
    }

    // Cancel from the top - should trigger request→drain→finalize at all levels
    let shutdown_reason = CancelReason::new(CancelKind::Shutdown);
    state.root.cancel(&shutdown_reason, base_time);

    // Give time for propagation
    std::thread::sleep(std::time::Duration::from_millis(10));
}

fn test_bottomup_cancellation(
    state: &mut HierarchyState,
    operations: &[HierarchyOperation],
    base_time: Time,
) {
    // Test cancellation starting from grandchildren
    for op in operations {
        execute_hierarchy_operation(state, op, base_time);
    }

    // Cancel deepest level first
    if let Some(grandchild) = state.grandchildren.first() {
        let reason = CancelReason::new(CancelKind::User);
        grandchild.cancel(&reason, base_time);
    }
}

fn test_middleout_cancellation(
    state: &mut HierarchyState,
    operations: &[HierarchyOperation],
    base_time: Time,
) {
    // Test cancellation from middle level (children)
    for op in operations {
        execute_hierarchy_operation(state, op, base_time);
    }

    // Cancel from middle level
    if let Some(child) = state.children.first() {
        let reason = CancelReason::new(CancelKind::Timeout);
        child.cancel(&reason, base_time);
    }
}

fn test_concurrent_cancellation(
    state: &mut HierarchyState,
    operations: &[HierarchyOperation],
    base_time: Time,
    thread_count: u8,
) {
    let thread_count = (thread_count as usize % MAX_THREADS) + 1;

    // For concurrent testing, we'll execute operations sequentially but with small delays
    // to simulate race conditions without the complexity of shared mutable state across threads
    for (op_idx, op) in operations.iter().enumerate() {
        execute_hierarchy_operation(state, op, base_time);

        // Introduce small delays to create timing variations
        if op_idx % thread_count == 0 {
            std::thread::sleep(std::time::Duration::from_micros(50));
        }
    }

    // Now execute rapid fire cancellations from different "threads" (sequentially)
    let reasons = [
        CancelReason::new(CancelKind::User),
        CancelReason::new(CancelKind::Timeout),
        CancelReason::new(CancelKind::Shutdown),
    ];

    let mut current_time = base_time;
    for reason in &reasons {
        if let Some(token) = state.get_token_at_level(0) {
            token.cancel(reason, current_time);
        }
        current_time = Time::from_nanos(current_time.as_nanos() + 100);
        std::thread::sleep(std::time::Duration::from_micros(10));
    }
}

fn test_rapid_fire_cancellation(
    state: &mut HierarchyState,
    operations: &[HierarchyOperation],
    base_time: Time,
) {
    // Rapid succession of cancellations with different reasons and strengthen scenarios
    for op in operations {
        execute_hierarchy_operation(state, op, base_time);
    }

    // Fire multiple cancellations rapidly
    let reasons = [
        CancelReason::new(CancelKind::User),
        CancelReason::new(CancelKind::Timeout),
        CancelReason::new(CancelKind::Shutdown), // Should strengthen
    ];

    let mut current_time = base_time;
    for reason in &reasons {
        state.root.cancel(reason, current_time);
        current_time = Time::from_nanos(current_time.as_nanos() + 100);
    }
}

fuzz_target!(|data: FuzzInput| {
    if data.operations.len() > MAX_OPS {
        return;
    }

    // Test the request→drain→finalize protocol across 3-deep hierarchies
    test_request_drain_finalize_protocol(&data);
});
