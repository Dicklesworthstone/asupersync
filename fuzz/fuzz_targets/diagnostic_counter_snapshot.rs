//! Fuzz runtime diagnostic counter snapshots against real state transitions.
//!
//! The snapshot surface is `StateSnapshot::from_runtime_state`, which backs the
//! scheduler governor and diagnostic views. This target mutates `RuntimeState`
//! through public creation, completion, and obligation-resolution APIs, then
//! checks that every sampled aggregate matches an independently tracked model.

#![no_main]

use arbitrary::Arbitrary;
use asupersync::obligation::lyapunov::StateSnapshot;
use asupersync::record::obligation::{ObligationAbortReason, ObligationKind};
use asupersync::runtime::state::RuntimeState;
use asupersync::types::{Budget, ObligationId, Outcome, RegionId, TaskId, Time};
use libfuzzer_sys::fuzz_target;

const MAX_OPERATIONS: usize = 96;
const MAX_REGIONS: usize = 24;
const MAX_TASKS: usize = 64;
const MAX_OBLIGATIONS: usize = 96;
const MAX_INITIAL_TIME_MILLIS: u64 = 1_000_000;
const MAX_ADVANCE_MILLIS: u64 = 10_000;

#[derive(Debug, Arbitrary)]
struct DiagnosticCounterCase {
    initial_time_millis: u64,
    operations: Vec<DiagnosticOperation>,
}

#[derive(Debug, Clone, Arbitrary)]
enum DiagnosticOperation {
    EnsureRoot,
    CreateChildRegion {
        parent_idx: u8,
    },
    CreateTask {
        region_idx: u8,
    },
    CompleteTask {
        task_idx: u8,
    },
    CreateObligation {
        task_idx: u8,
        kind: ObligationKindChoice,
    },
    CommitObligation {
        obligation_idx: u8,
    },
    AbortObligation {
        obligation_idx: u8,
    },
    AdvanceTime {
        millis: u16,
    },
    TakeSnapshot,
}

#[derive(Debug, Clone, Copy, Arbitrary)]
enum ObligationKindChoice {
    SendPermit,
    Ack,
    Lease,
    IoOp,
    SemaphorePermit,
    Transaction,
}

impl ObligationKindChoice {
    fn into_kind(self) -> ObligationKind {
        match self {
            Self::SendPermit => ObligationKind::SendPermit,
            Self::Ack => ObligationKind::Ack,
            Self::Lease => ObligationKind::Lease,
            Self::IoOp => ObligationKind::IoOp,
            Self::SemaphorePermit => ObligationKind::SemaphorePermit,
            Self::Transaction => ObligationKind::Transaction,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct TaskSlot {
    id: TaskId,
    region: RegionId,
    live: bool,
}

#[derive(Debug, Clone, Copy)]
struct ObligationSlot {
    id: ObligationId,
    kind: ObligationKind,
    holder: TaskId,
    reserved_at: Time,
    pending: bool,
}

struct DiagnosticCounterHarness {
    state: RuntimeState,
    regions: Vec<RegionId>,
    tasks: Vec<TaskSlot>,
    obligations: Vec<ObligationSlot>,
}

impl DiagnosticCounterHarness {
    fn new(initial_time: Time) -> Self {
        let mut state = RuntimeState::new();
        state.now = initial_time;
        Self {
            state,
            regions: Vec::new(),
            tasks: Vec::new(),
            obligations: Vec::new(),
        }
    }

    fn apply(&mut self, operation: DiagnosticOperation) {
        match operation {
            DiagnosticOperation::EnsureRoot => {
                self.ensure_root();
            }
            DiagnosticOperation::CreateChildRegion { parent_idx } => {
                self.create_child_region(parent_idx);
            }
            DiagnosticOperation::CreateTask { region_idx } => {
                self.create_task(region_idx);
            }
            DiagnosticOperation::CompleteTask { task_idx } => {
                self.complete_task(task_idx);
            }
            DiagnosticOperation::CreateObligation { task_idx, kind } => {
                self.create_obligation(task_idx, kind.into_kind());
            }
            DiagnosticOperation::CommitObligation { obligation_idx } => {
                self.resolve_obligation(obligation_idx, ObligationResolution::Commit);
            }
            DiagnosticOperation::AbortObligation { obligation_idx } => {
                self.resolve_obligation(obligation_idx, ObligationResolution::Abort);
            }
            DiagnosticOperation::AdvanceTime { millis } => {
                let bounded = u64::from(millis).min(MAX_ADVANCE_MILLIS);
                self.state.now = self
                    .state
                    .now
                    .saturating_add_nanos(bounded.saturating_mul(1_000_000));
            }
            DiagnosticOperation::TakeSnapshot => {}
        }
    }

    fn ensure_root(&mut self) {
        if self.regions.is_empty() {
            let root = self.state.create_root_region(Budget::INFINITE);
            self.regions.push(root);
        }
    }

    fn create_child_region(&mut self, parent_idx: u8) {
        if self.regions.len() >= MAX_REGIONS {
            return;
        }
        self.ensure_root();
        let parent = self.regions[usize::from(parent_idx) % self.regions.len()];
        if let Ok(region) = self.state.create_child_region(parent, Budget::INFINITE) {
            self.regions.push(region);
        }
    }

    fn create_task(&mut self, region_idx: u8) {
        if self.tasks.len() >= MAX_TASKS {
            return;
        }
        self.ensure_root();
        let region = self.regions[usize::from(region_idx) % self.regions.len()];
        if let Ok((task_id, _handle)) = self.state.create_task(region, Budget::INFINITE, async {}) {
            self.tasks.push(TaskSlot {
                id: task_id,
                region,
                live: true,
            });
        }
    }

    fn complete_task(&mut self, task_idx: u8) {
        let Some(index) = self.live_task_index(task_idx) else {
            return;
        };
        let task_id = self.tasks[index].id;
        if !self.state.complete_task(task_id, Outcome::Ok(())) {
            return;
        }
        let (waiters, completion_observer) = self.state.task_completed(task_id).into_parts();
        assert!(
            waiters.is_empty(),
            "diagnostic counter harness never installs task waiters"
        );
        completion_observer.dispatch();
        self.tasks[index].live = false;

        for obligation in &mut self.obligations {
            if obligation.holder == task_id {
                obligation.pending = false;
            }
        }
    }

    fn create_obligation(&mut self, task_idx: u8, kind: ObligationKind) {
        if self.obligations.len() >= MAX_OBLIGATIONS {
            return;
        }
        let Some(index) = self.live_task_index(task_idx) else {
            return;
        };
        let task = self.tasks[index];
        if let Ok(id) = self
            .state
            .create_obligation(kind, task.id, task.region, None)
        {
            self.obligations.push(ObligationSlot {
                id,
                kind,
                holder: task.id,
                reserved_at: self.state.now,
                pending: true,
            });
        }
    }

    fn resolve_obligation(&mut self, obligation_idx: u8, resolution: ObligationResolution) {
        let Some(index) = self.pending_obligation_index(obligation_idx) else {
            return;
        };
        let id = self.obligations[index].id;
        let resolved = match resolution {
            ObligationResolution::Commit => self.state.commit_obligation(id).is_ok(),
            ObligationResolution::Abort => self
                .state
                .abort_obligation(id, ObligationAbortReason::Explicit)
                .is_ok(),
        };
        if resolved {
            self.obligations[index].pending = false;
        }
    }

    fn live_task_index(&self, selector: u8) -> Option<usize> {
        select_index(
            self.tasks
                .iter()
                .enumerate()
                .filter_map(|(index, task)| task.live.then_some(index)),
            selector,
        )
    }

    fn pending_obligation_index(&self, selector: u8) -> Option<usize> {
        select_index(
            self.obligations
                .iter()
                .enumerate()
                .filter_map(|(index, obligation)| obligation.pending.then_some(index)),
            selector,
        )
    }

    fn assert_snapshot_matches_model(&self) {
        let snapshot = StateSnapshot::from_runtime_state(&self.state);
        let expected = ExpectedSnapshot::from_model(self);

        assert_eq!(
            snapshot.live_tasks, expected.live_tasks,
            "live task counter diverged from runtime model"
        );
        assert_eq!(
            snapshot.pending_obligations, expected.pending_obligations,
            "pending obligation counter diverged from runtime model"
        );
        assert_eq!(
            snapshot.pending_send_permits, expected.pending_send_permits,
            "send-permit obligation counter diverged"
        );
        assert_eq!(
            snapshot.pending_acks, expected.pending_acks,
            "ack obligation counter diverged"
        );
        assert_eq!(
            snapshot.pending_leases, expected.pending_leases,
            "lease obligation counter diverged"
        );
        assert_eq!(
            snapshot.pending_io_ops, expected.pending_io_ops,
            "I/O obligation counter diverged"
        );
        assert_eq!(
            snapshot.obligation_age_sum_ns, expected.obligation_age_sum_ns,
            "pending obligation age sum diverged"
        );
        assert_eq!(
            snapshot.total_cancelling_tasks(),
            0,
            "target never drives cancellation phases"
        );
        assert!(
            snapshot.deadline_pressure >= 0.0,
            "deadline pressure should not be negative"
        );
    }
}

#[derive(Debug, Clone, Copy)]
enum ObligationResolution {
    Commit,
    Abort,
}

#[derive(Debug, Default)]
struct ExpectedSnapshot {
    live_tasks: u32,
    pending_obligations: u32,
    obligation_age_sum_ns: u64,
    pending_send_permits: u32,
    pending_acks: u32,
    pending_leases: u32,
    pending_io_ops: u32,
}

impl ExpectedSnapshot {
    fn from_model(harness: &DiagnosticCounterHarness) -> Self {
        let mut expected = Self {
            live_tasks: harness.tasks.iter().filter(|task| task.live).count() as u32,
            ..Self::default()
        };

        for obligation in harness
            .obligations
            .iter()
            .filter(|obligation| obligation.pending)
        {
            expected.pending_obligations = expected.pending_obligations.saturating_add(1);
            expected.obligation_age_sum_ns = expected
                .obligation_age_sum_ns
                .saturating_add(harness.state.now.duration_since(obligation.reserved_at));

            match obligation.kind {
                ObligationKind::SendPermit => {
                    expected.pending_send_permits = expected.pending_send_permits.saturating_add(1);
                }
                ObligationKind::Ack => {
                    expected.pending_acks = expected.pending_acks.saturating_add(1);
                }
                ObligationKind::Lease
                | ObligationKind::SemaphorePermit
                | ObligationKind::Transaction => {
                    expected.pending_leases = expected.pending_leases.saturating_add(1);
                }
                ObligationKind::IoOp => {
                    expected.pending_io_ops = expected.pending_io_ops.saturating_add(1);
                }
            }
        }

        expected
    }
}

fn select_index<I>(indices: I, selector: u8) -> Option<usize>
where
    I: Iterator<Item = usize>,
{
    let collected: Vec<usize> = indices.collect();
    if collected.is_empty() {
        None
    } else {
        Some(collected[usize::from(selector) % collected.len()])
    }
}

fuzz_target!(|case: DiagnosticCounterCase| {
    let initial_time = Time::from_millis(case.initial_time_millis.min(MAX_INITIAL_TIME_MILLIS));
    let mut harness = DiagnosticCounterHarness::new(initial_time);
    harness.assert_snapshot_matches_model();

    for operation in case.operations.into_iter().take(MAX_OPERATIONS) {
        harness.apply(operation);
        harness.assert_snapshot_matches_model();
    }
});
