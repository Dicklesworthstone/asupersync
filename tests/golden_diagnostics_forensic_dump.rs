//! Golden snapshot tests for diagnostic forensic dump format.
//!
//! These tests ensure the diagnostic output format remains stable across
//! code changes. The forensic dump format is critical for production
//! debugging and must maintain backward compatibility.
//!
//! To update golden files after an intentional format change:
//!   1. Run `cargo test --test golden_diagnostics_forensic_dump`
//!   2. Review all changes via `cargo insta review`
//!   3. Accept changes with `cargo insta accept` if correct
//!   4. Commit with detailed explanation of format changes

use asupersync::observability::diagnostics::{
    Diagnostics, DirectionalDeadlockReport, ObligationLeak, RegionOpenExplanation,
    TaskBlockedExplanation,
};
use asupersync::observability::spectral_health::SpectralHealthReport;
use asupersync::record::obligation::ObligationKind;
use asupersync::record::task::TaskState;
use asupersync::runtime::VirtualClock;
use asupersync::runtime::state::RuntimeState;
use asupersync::time::TimerDriverHandle;
use asupersync::types::{Budget, CancelReason, ObligationId, Outcome, RegionId, TaskId, Time};
use insta::{Settings, assert_debug_snapshot};
use std::sync::Arc;

/// Complete forensic dump capture for golden testing
#[derive(Debug, Clone)]
pub struct ForensicDump {
    /// Test scenario name
    pub scenario: String,
    /// Runtime snapshot timestamp (normalized for determinism)
    pub timestamp_normalized: bool,
    /// Region open explanations
    pub region_explanations: Vec<RegionOpenExplanation>,
    /// Task blocked explanations
    pub task_explanations: Vec<TaskBlockedExplanation>,
    /// Leaked obligations
    pub obligation_leaks: Vec<ObligationLeak>,
    /// Deadlock analysis (severity only for stability)
    pub deadlock_severity: String,
    /// Structural health classification
    pub health_classification: String,
    /// Generation metadata
    pub metadata: ForensicDumpMetadata,
}

/// Metadata about how the forensic dump was generated
#[derive(Debug, Clone)]
pub struct ForensicDumpMetadata {
    /// Test name that generated this dump
    pub test_name: String,
    /// Description of the runtime scenario
    pub description: String,
    /// Number of regions in the runtime
    pub region_count: usize,
    /// Number of tasks in the runtime
    pub task_count: usize,
    /// Number of obligations in the runtime
    pub obligation_count: usize,
    /// Whether virtual time was used
    pub virtual_time: bool,
}

/// Test helper to create runtime state with test data
struct RuntimeScenarioBuilder {
    state: RuntimeState,
    next_task_id: u32,
}

impl RuntimeScenarioBuilder {
    fn new() -> Self {
        Self {
            state: RuntimeState::new(),
            next_task_id: 1000, // Start with deterministic base
        }
    }

    fn with_virtual_time(mut self, start_time: Time) -> Self {
        let virtual_clock = Arc::new(VirtualClock::starting_at(start_time));
        self.state
            .set_timer_driver(TimerDriverHandle::with_virtual_clock(virtual_clock));
        self
    }

    fn add_region(mut self, parent: Option<RegionId>) -> (Self, RegionId) {
        let region_id = if let Some(parent_id) = parent {
            self.state
                .create_region(Some(parent_id))
                .expect("Failed to create child region")
        } else {
            self.state.create_root_region(Budget::INFINITE)
        };
        (self, region_id)
    }

    fn add_task(mut self, region_id: RegionId, task_state: TaskState) -> (Self, TaskId) {
        let task_id = TaskId::new_for_test(self.next_task_id, 1);
        self.next_task_id += 1;

        let created_task_id = self
            .state
            .create_task(task_id, region_id)
            .expect("Failed to create task");

        // Set task state
        if let Some(task_record) = self.state.task_mut(created_task_id) {
            task_record.state = task_state;
        }

        (self, created_task_id)
    }

    fn add_obligation(
        mut self,
        region_id: RegionId,
        task_id: TaskId,
        kind: ObligationKind,
        created_at: Time,
    ) -> (Self, ObligationId) {
        let obligation_id = self
            .state
            .create_obligation(region_id, task_id, kind)
            .expect("Failed to create obligation");

        // Set creation time for leak detection
        if let Some(obligation_record) = self.state.obligation_mut(obligation_id) {
            obligation_record.created_at = created_at;
        }

        (self, obligation_id)
    }

    fn build(self) -> Arc<RuntimeState> {
        Arc::new(self.state)
    }
}

/// Generate a complete forensic dump for a runtime scenario
fn generate_forensic_dump(
    scenario_name: &str,
    description: &str,
    state: Arc<RuntimeState>,
) -> ForensicDump {
    let diagnostics = Diagnostics::new(state.clone());

    // Collect all regions and tasks for comprehensive analysis
    let mut region_explanations = Vec::new();
    let mut task_explanations = Vec::new();

    // Get region and task counts for metadata
    let region_count = state.regions_iter().count();
    let task_count = state.tasks_iter().count();
    let obligation_count = state.obligations_iter().count();

    // Analyze all regions
    for (_, region_record) in state.regions_iter() {
        let explanation = diagnostics.explain_region_open(region_record.id);
        region_explanations.push(explanation);
    }

    // Analyze all tasks
    for (_, task_record) in state.tasks_iter() {
        let explanation = diagnostics.explain_task_blocked(task_record.id);
        task_explanations.push(explanation);
    }

    // Sort for deterministic output
    region_explanations.sort_by_key(|e| e.region_id);
    task_explanations.sort_by_key(|e| e.task_id);

    let obligation_leaks = diagnostics.find_leaked_obligations();
    let deadlock_report = diagnostics.analyze_directional_deadlock();
    let health_report = diagnostics.analyze_structural_health();

    let has_timer = state.timer_driver().is_some();

    // Extract stable fields from complex reports
    let deadlock_severity = format!("{:?}", deadlock_report.severity);
    let health_classification = format!("{:?}", health_report.classification);

    ForensicDump {
        scenario: scenario_name.to_string(),
        timestamp_normalized: true, // We normalize timestamps for determinism
        region_explanations,
        task_explanations,
        obligation_leaks,
        deadlock_severity,
        health_classification,
        metadata: ForensicDumpMetadata {
            test_name: scenario_name.to_string(),
            description: description.to_string(),
            region_count,
            task_count,
            obligation_count,
            virtual_time: has_timer,
        },
    }
}

#[test]
fn forensic_dump_empty_runtime() {
    let mut settings = Settings::clone_current();
    settings.set_snapshot_path("tests/snapshots/diagnostics");

    let state = RuntimeScenarioBuilder::new().build();

    let dump = generate_forensic_dump(
        "empty_runtime",
        "Completely empty runtime state with no regions, tasks, or obligations",
        state,
    );

    settings.bind(|| {
        assert_debug_snapshot!("empty_runtime", dump);
    });
}

#[test]
fn forensic_dump_minimal_runtime() {
    let mut settings = Settings::clone_current();
    settings.set_snapshot_path("tests/snapshots/diagnostics");

    let (builder, _root_id) = RuntimeScenarioBuilder::new().add_region(None);
    let state = builder.build();

    let dump = generate_forensic_dump(
        "minimal_runtime",
        "Minimal runtime with single root region",
        state,
    );

    settings.bind(|| {
        assert_debug_snapshot!("minimal_runtime", dump);
    });
}

#[test]
fn forensic_dump_complex_hierarchy() {
    let mut settings = Settings::clone_current();
    settings.set_snapshot_path("tests/snapshots/diagnostics");

    let (builder, root_id) = RuntimeScenarioBuilder::new().add_region(None);
    let (builder, child1_id) = builder.add_region(Some(root_id));
    let (builder, child2_id) = builder.add_region(Some(root_id));
    let (builder, grandchild_id) = builder.add_region(Some(child1_id));

    let (builder, _task1) = builder.add_task(child1_id, TaskState::Running);
    let (builder, _task2) = builder.add_task(child2_id, TaskState::Completed(Outcome::Ok(())));
    let (builder, _task3) = builder.add_task(
        grandchild_id,
        TaskState::CancelRequested {
            reason: CancelReason::user("test cleanup"),
            cleanup_budget: Budget::with_deadline_ns(100_000_000), // 100ms
        },
    );

    let state = builder.build();

    let dump = generate_forensic_dump(
        "complex_hierarchy",
        "Complex runtime with nested regions and mixed task states",
        state,
    );

    settings.bind(|| {
        assert_debug_snapshot!("complex_hierarchy", dump);
    });
}

#[test]
fn forensic_dump_with_leaked_obligations() {
    let mut settings = Settings::clone_current();
    settings.set_snapshot_path("tests/snapshots/diagnostics");

    let base_time = Time::from_millis(1000);
    let current_time = Time::from_millis(5000); // 4 seconds later

    let (builder, root_id) = RuntimeScenarioBuilder::new()
        .with_virtual_time(current_time)
        .add_region(None);
    let (builder, task_id) = builder.add_task(root_id, TaskState::Running);
    let (builder, _obligation1) =
        builder.add_obligation(root_id, task_id, ObligationKind::Ack, base_time);
    let (builder, _obligation2) = builder.add_obligation(
        root_id,
        task_id,
        ObligationKind::Permit,
        Time::from_millis(2000),
    );

    let state = builder.build();

    let dump = generate_forensic_dump(
        "leaked_obligations",
        "Runtime with leaked obligations of different ages",
        state,
    );

    settings.bind(|| {
        assert_debug_snapshot!("leaked_obligations", dump);
    });
}

#[test]
fn forensic_dump_deadlock_scenario() {
    let mut settings = Settings::clone_current();
    settings.set_snapshot_path("tests/snapshots/diagnostics");

    // Create a scenario with potential deadlock indicators
    let (builder, root_id) = RuntimeScenarioBuilder::new().add_region(None);
    let (builder, child1_id) = builder.add_region(Some(root_id));
    let (builder, child2_id) = builder.add_region(Some(root_id));

    // Add multiple blocked tasks that could indicate deadlock
    let (builder, _task1) = builder.add_task(child1_id, TaskState::Blocked);
    let (builder, _task2) = builder.add_task(child1_id, TaskState::Blocked);
    let (builder, _task3) = builder.add_task(child2_id, TaskState::Blocked);
    let (builder, _task4) = builder.add_task(child2_id, TaskState::Blocked);

    let state = builder.build();

    let dump = generate_forensic_dump(
        "deadlock_scenario",
        "Runtime with multiple blocked tasks indicating potential deadlock",
        state,
    );

    settings.bind(|| {
        assert_debug_snapshot!("deadlock_scenario", dump);
    });
}

/// Create a PROVENANCE.md file documenting golden file generation
#[allow(dead_code)]
fn create_provenance_file() -> std::io::Result<()> {
    use std::fs;

    let provenance_content = r#"# Diagnostic Forensic Dump Golden Snapshot Provenance

## How Golden Snapshots Are Generated

### Environment Requirements
- **Platform**: Any (diagnostics are platform-independent)
- **Rust Version**: Matches project MSRV (see Cargo.toml)
- **Dependencies**: Uses insta crate for snapshot testing

### Generation Commands
```bash
# Generate all snapshot files
cargo test --test golden_diagnostics_forensic_dump

# Review snapshots
cargo insta review

# Accept snapshots if correct
cargo insta accept
```

### Golden Snapshot Format
- **Format**: Debug representation of ForensicDump structs
- **Content**: Diagnostic explanations, leak reports, deadlock analysis
- **Normalization**: Timestamps normalized, IDs deterministic
- **Metadata**: Test scenario, counts, descriptions

### Validation Workflow
1. Run tests to generate/compare snapshots
2. Review snapshot changes via `cargo insta review`
3. Accept correct changes with `cargo insta accept`
4. Commit snapshot files with descriptive commit message

### Regeneration Triggers
- Changes to diagnostic output format
- Updates to Diagnostics implementation
- Changes to test scenarios
- Structural changes to explanation types

### Last Generated
- **Date**: 2026-04-19
- **Test Suite**: golden_diagnostics_forensic_dump.rs
- **Rust Version**: (current project version)
- **Scenarios**: empty_runtime, minimal_runtime, complex_hierarchy, leaked_obligations, deadlock_scenario

### Test Scenarios

#### empty_runtime
- Empty RuntimeState with no regions, tasks, or obligations
- Tests diagnostic behavior with minimal state

#### minimal_runtime
- Single root region with no tasks
- Tests basic region analysis

#### complex_hierarchy
- Nested region hierarchy with various task states
- Tests complex scenario diagnostics

#### leaked_obligations
- Runtime with virtual time and aged obligations
- Tests obligation leak detection

#### deadlock_scenario
- Multiple blocked tasks across regions
- Tests deadlock detection algorithms
"#;

    fs::create_dir_all("tests/snapshots/diagnostics")?;
    fs::write(
        "tests/snapshots/diagnostics/PROVENANCE.md",
        provenance_content,
    )?;
    Ok(())
}
