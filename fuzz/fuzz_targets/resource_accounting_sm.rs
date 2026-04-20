#![no_main]

use arbitrary::Arbitrary;
use asupersync::observability::resource_accounting::ResourceAccounting;
use asupersync::record::ObligationKind;
use asupersync::record::region::AdmissionKind;
use libfuzzer_sys::fuzz_target;

const OBLIGATION_KIND_COUNT: usize = 5;
const ADMISSION_KIND_COUNT: usize = 4;

#[derive(Arbitrary, Clone, Copy, Debug)]
enum FuzzObligationKind {
    SendPermit,
    Ack,
    Lease,
    IoOp,
    SemaphorePermit,
}

#[derive(Arbitrary, Clone, Copy, Debug)]
enum FuzzAdmissionKind {
    Child,
    Task,
    Obligation,
    HeapBytes,
}

#[derive(Arbitrary, Clone, Copy, Debug)]
enum Operation {
    Reserve(FuzzObligationKind),
    Commit(FuzzObligationKind),
    Abort(FuzzObligationKind),
    Leak(FuzzObligationKind),
    PollConsumed(u8),
    CostConsumed(u8),
    PollExhausted,
    CostExhausted,
    DeadlineMissed,
    AdmissionSucceeded(FuzzAdmissionKind),
    AdmissionRejected(FuzzAdmissionKind),
    UpdateTasksPeak(i16),
    UpdateChildrenPeak(i16),
    UpdateHeapBytesPeak(i16),
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    operations: Vec<Operation>,
}

#[derive(Clone, Debug, Default)]
struct ShadowAccounting {
    reserved: [u64; OBLIGATION_KIND_COUNT],
    committed: [u64; OBLIGATION_KIND_COUNT],
    aborted: [u64; OBLIGATION_KIND_COUNT],
    leaked: [u64; OBLIGATION_KIND_COUNT],
    pending: i64,
    pending_peak: i64,
    poll_quota_consumed: u64,
    cost_quota_consumed: u64,
    poll_quota_exhaustions: u64,
    cost_quota_exhaustions: u64,
    deadline_misses: u64,
    admission_successes: [u64; ADMISSION_KIND_COUNT],
    admission_rejections: [u64; ADMISSION_KIND_COUNT],
    tasks_peak: i64,
    children_peak: i64,
    heap_bytes_peak: i64,
}

fuzz_target!(|input: FuzzInput| {
    if input.operations.len() > 64 {
        return;
    }

    let accounting = ResourceAccounting::new();
    let mut shadow = ShadowAccounting::default();

    for operation in input.operations {
        apply_operation(&accounting, &mut shadow, operation);
        assert_matches_shadow(&accounting, &shadow);
    }
});

fn apply_operation(
    accounting: &ResourceAccounting,
    shadow: &mut ShadowAccounting,
    operation: Operation,
) {
    match operation {
        Operation::Reserve(kind) => {
            let kind = obligation_kind(kind);
            accounting.obligation_reserved(kind);
            shadow.reserved[obligation_index(kind)] += 1;
            shadow.pending += 1;
            shadow.pending_peak = shadow.pending_peak.max(shadow.pending);
        }
        Operation::Commit(kind) => {
            let kind = obligation_kind(kind);
            accounting.obligation_committed(kind);
            shadow.committed[obligation_index(kind)] += 1;
            shadow.pending = shadow.pending.saturating_sub(1).max(0);
        }
        Operation::Abort(kind) => {
            let kind = obligation_kind(kind);
            accounting.obligation_aborted(kind);
            shadow.aborted[obligation_index(kind)] += 1;
            shadow.pending = shadow.pending.saturating_sub(1).max(0);
        }
        Operation::Leak(kind) => {
            let kind = obligation_kind(kind);
            accounting.obligation_leaked(kind);
            shadow.leaked[obligation_index(kind)] += 1;
            shadow.pending = shadow.pending.saturating_sub(1).max(0);
        }
        Operation::PollConsumed(amount) => {
            let amount = u64::from(amount);
            accounting.poll_consumed(amount);
            shadow.poll_quota_consumed += amount;
        }
        Operation::CostConsumed(amount) => {
            let amount = u64::from(amount);
            accounting.cost_consumed(amount);
            shadow.cost_quota_consumed += amount;
        }
        Operation::PollExhausted => {
            accounting.poll_quota_exhausted();
            shadow.poll_quota_exhaustions += 1;
        }
        Operation::CostExhausted => {
            accounting.cost_quota_exhausted();
            shadow.cost_quota_exhaustions += 1;
        }
        Operation::DeadlineMissed => {
            accounting.deadline_missed();
            shadow.deadline_misses += 1;
        }
        Operation::AdmissionSucceeded(kind) => {
            let kind = admission_kind(kind);
            accounting.admission_succeeded(kind);
            shadow.admission_successes[admission_index(kind)] += 1;
        }
        Operation::AdmissionRejected(kind) => {
            let kind = admission_kind(kind);
            accounting.admission_rejected(kind);
            shadow.admission_rejections[admission_index(kind)] += 1;
        }
        Operation::UpdateTasksPeak(current) => {
            let current = i64::from(current);
            accounting.update_tasks_peak(current);
            shadow.tasks_peak = shadow.tasks_peak.max(current);
        }
        Operation::UpdateChildrenPeak(current) => {
            let current = i64::from(current);
            accounting.update_children_peak(current);
            shadow.children_peak = shadow.children_peak.max(current);
        }
        Operation::UpdateHeapBytesPeak(current) => {
            let current = i64::from(current);
            accounting.update_heap_bytes_peak(current);
            shadow.heap_bytes_peak = shadow.heap_bytes_peak.max(current);
        }
    }
}

fn assert_matches_shadow(accounting: &ResourceAccounting, shadow: &ShadowAccounting) {
    let snapshot = accounting.snapshot();

    for kind in all_obligation_kinds() {
        let idx = obligation_index(kind);
        let stats = snapshot
            .obligation_stats
            .iter()
            .find(|stats| stats.kind == kind)
            .expect("obligation kind must be present in snapshot");
        assert_eq!(
            accounting.obligations_reserved_by_kind(kind),
            shadow.reserved[idx]
        );
        assert_eq!(
            accounting.obligations_committed_by_kind(kind),
            shadow.committed[idx]
        );
        assert_eq!(
            accounting.obligations_aborted_by_kind(kind),
            shadow.aborted[idx]
        );
        assert_eq!(
            accounting.obligations_leaked_by_kind(kind),
            shadow.leaked[idx]
        );
        assert_eq!(stats.reserved, shadow.reserved[idx]);
        assert_eq!(stats.committed, shadow.committed[idx]);
        assert_eq!(stats.aborted, shadow.aborted[idx]);
        assert_eq!(stats.leaked, shadow.leaked[idx]);
        assert_eq!(stats.pending(), pending_for_kind(shadow, idx));
    }

    for kind in all_admission_kinds() {
        let idx = admission_index(kind);
        let stats = snapshot
            .admission_stats
            .iter()
            .find(|stats| stats.kind == kind)
            .expect("admission kind must be present in snapshot");
        assert_eq!(
            accounting.admissions_succeeded_by_kind(kind),
            shadow.admission_successes[idx]
        );
        assert_eq!(
            accounting.admissions_rejected_by_kind(kind),
            shadow.admission_rejections[idx]
        );
        assert_eq!(stats.successes, shadow.admission_successes[idx]);
        assert_eq!(stats.rejections, shadow.admission_rejections[idx]);
    }

    assert_eq!(
        accounting.obligations_reserved_total(),
        shadow.reserved.iter().sum::<u64>()
    );
    assert_eq!(
        accounting.obligations_committed_total(),
        shadow.committed.iter().sum::<u64>()
    );
    assert_eq!(
        accounting.obligations_leaked_total(),
        shadow.leaked.iter().sum::<u64>()
    );
    assert_eq!(accounting.obligations_pending(), shadow.pending);
    assert_eq!(accounting.obligations_peak(), shadow.pending_peak);
    assert_eq!(accounting.total_poll_consumed(), shadow.poll_quota_consumed);
    assert_eq!(accounting.total_cost_consumed(), shadow.cost_quota_consumed);
    assert_eq!(
        accounting.total_poll_exhaustions(),
        shadow.poll_quota_exhaustions
    );
    assert_eq!(
        accounting.total_cost_exhaustions(),
        shadow.cost_quota_exhaustions
    );
    assert_eq!(accounting.total_deadline_misses(), shadow.deadline_misses);
    assert_eq!(
        accounting.admissions_rejected_total(),
        shadow.admission_rejections.iter().sum::<u64>()
    );
    assert_eq!(accounting.tasks_peak(), shadow.tasks_peak.max(0));
    assert_eq!(accounting.children_peak(), shadow.children_peak.max(0));
    assert_eq!(accounting.heap_bytes_peak(), shadow.heap_bytes_peak.max(0));

    assert_eq!(
        snapshot.total_reserved(),
        shadow.reserved.iter().sum::<u64>()
    );
    assert_eq!(
        snapshot.total_committed(),
        shadow.committed.iter().sum::<u64>()
    );
    assert_eq!(snapshot.total_aborted(), shadow.aborted.iter().sum::<u64>());
    assert_eq!(snapshot.total_leaked(), shadow.leaked.iter().sum::<u64>());
    assert_eq!(
        snapshot.total_pending_by_stats(),
        total_pending_by_stats(shadow)
    );
    assert_eq!(snapshot.obligations_pending, shadow.pending);
    assert_eq!(snapshot.obligations_peak, shadow.pending_peak);
    assert_eq!(
        snapshot.total_rejections(),
        shadow.admission_rejections.iter().sum::<u64>()
    );
    assert_eq!(snapshot.poll_quota_consumed, shadow.poll_quota_consumed);
    assert_eq!(snapshot.cost_quota_consumed, shadow.cost_quota_consumed);
    assert_eq!(
        snapshot.poll_quota_exhaustions,
        shadow.poll_quota_exhaustions
    );
    assert_eq!(
        snapshot.cost_quota_exhaustions,
        shadow.cost_quota_exhaustions
    );
    assert_eq!(snapshot.deadline_misses, shadow.deadline_misses);
    assert_eq!(snapshot.tasks_peak, shadow.tasks_peak.max(0));
    assert_eq!(snapshot.children_peak, shadow.children_peak.max(0));
    assert_eq!(snapshot.heap_bytes_peak, shadow.heap_bytes_peak.max(0));

    let derived_pending = total_pending_by_stats(shadow);
    let mismatch = u64::try_from(shadow.pending).map_or(true, |pending| pending != derived_pending);
    assert_eq!(snapshot.has_accounting_mismatch(), mismatch);
    assert_eq!(
        snapshot.has_unresolved_obligations(),
        shadow.pending > 0 || derived_pending > 0
    );
    assert_eq!(
        snapshot.is_leak_free(),
        shadow.leaked.iter().sum::<u64>() == 0
    );
    assert_eq!(
        snapshot.is_cleanup_complete(),
        shadow.leaked.iter().sum::<u64>() == 0
            && !mismatch
            && !(shadow.pending > 0 || derived_pending > 0)
    );
}

fn pending_for_kind(shadow: &ShadowAccounting, idx: usize) -> u64 {
    shadow.reserved[idx]
        .saturating_sub(shadow.committed[idx])
        .saturating_sub(shadow.aborted[idx])
        .saturating_sub(shadow.leaked[idx])
}

fn total_pending_by_stats(shadow: &ShadowAccounting) -> u64 {
    (0..OBLIGATION_KIND_COUNT)
        .map(|idx| pending_for_kind(shadow, idx))
        .sum()
}

fn obligation_kind(kind: FuzzObligationKind) -> ObligationKind {
    match kind {
        FuzzObligationKind::SendPermit => ObligationKind::SendPermit,
        FuzzObligationKind::Ack => ObligationKind::Ack,
        FuzzObligationKind::Lease => ObligationKind::Lease,
        FuzzObligationKind::IoOp => ObligationKind::IoOp,
        FuzzObligationKind::SemaphorePermit => ObligationKind::SemaphorePermit,
    }
}

fn admission_kind(kind: FuzzAdmissionKind) -> AdmissionKind {
    match kind {
        FuzzAdmissionKind::Child => AdmissionKind::Child,
        FuzzAdmissionKind::Task => AdmissionKind::Task,
        FuzzAdmissionKind::Obligation => AdmissionKind::Obligation,
        FuzzAdmissionKind::HeapBytes => AdmissionKind::HeapBytes,
    }
}

fn obligation_index(kind: ObligationKind) -> usize {
    match kind {
        ObligationKind::SendPermit => 0,
        ObligationKind::Ack => 1,
        ObligationKind::Lease => 2,
        ObligationKind::IoOp => 3,
        ObligationKind::SemaphorePermit => 4,
    }
}

fn admission_index(kind: AdmissionKind) -> usize {
    match kind {
        AdmissionKind::Child => 0,
        AdmissionKind::Task => 1,
        AdmissionKind::Obligation => 2,
        AdmissionKind::HeapBytes => 3,
    }
}

fn all_obligation_kinds() -> [ObligationKind; OBLIGATION_KIND_COUNT] {
    [
        ObligationKind::SendPermit,
        ObligationKind::Ack,
        ObligationKind::Lease,
        ObligationKind::IoOp,
        ObligationKind::SemaphorePermit,
    ]
}

fn all_admission_kinds() -> [AdmissionKind; ADMISSION_KIND_COUNT] {
    [
        AdmissionKind::Child,
        AdmissionKind::Task,
        AdmissionKind::Obligation,
        AdmissionKind::HeapBytes,
    ]
}
