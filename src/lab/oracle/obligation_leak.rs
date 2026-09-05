//! Obligation leak oracle.
//!
//! Tracks obligation lifecycle events and ensures that all obligations are
//! resolved before their owning region closes. Runtime snapshots also retain
//! explicit leak diagnoses made when a holder completes, including after its
//! region record has been reclaimed.

use crate::record::{ObligationKind, ObligationState};
use crate::runtime::RuntimeState;
use crate::types::{ObligationId, RegionId, TaskId, Time};
use std::collections::BTreeMap;
use std::fmt;

/// Diagnostic record for a leaked obligation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObligationLeak {
    /// The leaked obligation id.
    pub obligation: ObligationId,
    /// The kind of obligation (permit/ack/lease/io).
    pub kind: ObligationKind,
    /// The task that held the obligation.
    pub holder: TaskId,
    /// The region that owned the obligation.
    pub region: RegionId,
}

impl fmt::Display for ObligationLeak {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?} {:?} holder={:?} region={:?}",
            self.obligation, self.kind, self.holder, self.region
        )
    }
}

/// Violation raised for an explicitly diagnosed leak or a region closing with
/// unresolved obligations.
#[derive(Debug, Clone)]
pub struct ObligationLeakViolation {
    /// The region owning the leaked obligations.
    pub region: RegionId,
    /// Leaked obligations for the region.
    pub leaked: Vec<ObligationLeak>,
    /// Time when the region closed, or the earliest recorded leak time when
    /// the diagnosis does not come from an observed region close.
    pub region_close_time: Time,
}

impl fmt::Display for ObligationLeakViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "region={:?} leaked={} at {:?}",
            self.region,
            self.leaked.len(),
            self.region_close_time
        )
    }
}

impl std::error::Error for ObligationLeakViolation {}

#[derive(Debug, Clone)]
struct ObligationSnapshot {
    kind: ObligationKind,
    holder: TaskId,
    region: RegionId,
    state: ObligationState,
}

/// Oracle that tracks obligation lifecycle events and checks for leaks.
#[derive(Debug, Default)]
pub struct ObligationLeakOracle {
    obligations: BTreeMap<ObligationId, ObligationSnapshot>,
    region_closes: Vec<(RegionId, Time)>,
    violations: Vec<ObligationLeakViolation>,
}

impl ObligationLeakOracle {
    /// Creates a new obligation leak oracle.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Resets the oracle to its initial state.
    pub fn reset(&mut self) {
        self.obligations.clear();
        self.region_closes.clear();
        self.violations.clear();
    }

    /// Records an obligation creation event.
    pub fn on_create(
        &mut self,
        id: ObligationId,
        kind: ObligationKind,
        holder: TaskId,
        region: RegionId,
    ) {
        self.obligations.insert(
            id,
            ObligationSnapshot {
                kind,
                holder,
                region,
                state: ObligationState::Reserved,
            },
        );
    }

    /// Records an obligation resolution event (commit/abort).
    pub fn on_resolve(&mut self, id: ObligationId, state: ObligationState) {
        if let Some(snapshot) = self.obligations.get_mut(&id) {
            snapshot.state = state;
        }
    }

    /// Records a region close event for leak checking.
    pub fn on_region_close(&mut self, region: RegionId, time: Time) {
        self.region_closes.push((region, time));

        let mut leaked = Vec::new();
        for (id, snapshot) in &self.obligations {
            if snapshot.region == region && !snapshot.state.is_success() {
                leaked.push(ObligationLeak {
                    obligation: *id,
                    kind: snapshot.kind,
                    holder: snapshot.holder,
                    region: snapshot.region,
                });
            }
        }
        leaked.sort_by_key(|leak| leak.obligation);

        if !leaked.is_empty() {
            self.violations.push(ObligationLeakViolation {
                region,
                leaked,
                region_close_time: time,
            });
        }
    }

    /// Builds oracle state from a runtime snapshot.
    pub fn snapshot_from_state(&mut self, state: &RuntimeState, now: Time) {
        self.reset();

        let mut recorded_leaks: BTreeMap<RegionId, (Time, Vec<ObligationLeak>)> = BTreeMap::new();
        for (_, obligation) in state.obligations_iter() {
            self.obligations.insert(
                obligation.id,
                ObligationSnapshot {
                    kind: obligation.kind,
                    holder: obligation.holder,
                    region: obligation.region,
                    state: obligation.state,
                },
            );
            if obligation.state == ObligationState::Leaked {
                let diagnosed_at = obligation.resolved_at.unwrap_or(now);
                let (first_diagnosis, leaked) = recorded_leaks
                    .entry(obligation.region)
                    .or_insert_with(|| (diagnosed_at, Vec::new()));
                *first_diagnosis = (*first_diagnosis).min(diagnosed_at);
                leaked.push(ObligationLeak {
                    obligation: obligation.id,
                    kind: obligation.kind,
                    holder: obligation.holder,
                    region: obligation.region,
                });
            }
        }

        let mut closed_regions = Vec::new();
        for (_, region) in state.regions_iter() {
            if region.state().is_terminal() {
                closed_regions.push(region.id);
            }
        }
        closed_regions.sort();

        for region in closed_regions {
            self.on_region_close(region, now);
            // The actual close already reports every non-successful record
            // in this region, including any prior explicit leak diagnosis.
            recorded_leaks.remove(&region);
        }
        for (region, (diagnosed_at, mut leaked)) in recorded_leaks {
            leaked.sort_by_key(|leak| leak.obligation);
            self.violations.push(ObligationLeakViolation {
                region,
                leaked,
                region_close_time: diagnosed_at,
            });
        }
    }

    /// Returns the number of tracked obligations.
    #[must_use]
    pub fn obligation_count(&self) -> usize {
        self.obligations.len()
    }

    /// Returns the number of closed regions tracked.
    #[must_use]
    pub fn closed_region_count(&self) -> usize {
        self.region_closes.len()
    }

    /// Checks for explicitly diagnosed leaks and unresolved obligations at
    /// region close. A live pending obligation in an open region is permitted.
    pub fn check(&self, _now: Time) -> Result<(), ObligationLeakViolation> {
        if let Some(violation) = self
            .violations
            .iter()
            .min_by_key(|violation| (violation.region, violation.region_close_time))
        {
            return Err(violation.clone());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::record::TaskRecord;
    use crate::types::{Budget, ObligationId, RegionId, TaskId};
    use crate::util::ArenaIndex;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn test_region(index: u32) -> RegionId {
        RegionId::from_arena(ArenaIndex::new(index, 1))
    }

    #[test]
    fn detects_leak_on_region_close() {
        init_test("detects_leak_on_region_close");
        let mut oracle = ObligationLeakOracle::new();

        let region = test_region(0);
        let task = TaskId::from_arena(ArenaIndex::new(1, 0));
        let obligation = ObligationId::from_arena(ArenaIndex::new(2, 0));

        oracle.on_create(obligation, ObligationKind::SendPermit, task, region);
        oracle.on_region_close(region, Time::ZERO);

        let err = oracle.check(Time::ZERO).expect_err("expected leak");
        crate::assert_with_log!(err.region == region, "region", region, err.region);
        let len = err.leaked.len();
        crate::assert_with_log!(len == 1, "leaked len", 1, len);
        let leaked = err.leaked[0].obligation;
        crate::assert_with_log!(leaked == obligation, "obligation", obligation, leaked);
        crate::test_complete!("detects_leak_on_region_close");
    }

    #[test]
    fn snapshot_from_state_catches_reserved_obligation() {
        init_test("snapshot_from_state_catches_reserved_obligation");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let region = state
            .create_child_region(root, Budget::INFINITE)
            .expect("create child region");

        let task_idx = state.insert_task(TaskRecord::new(
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            region,
            Budget::INFINITE,
        ));
        let task_id = TaskId::from_arena(task_idx);
        state.task_mut(task_id).unwrap().id = task_id;

        let obl_id = state
            .create_obligation(ObligationKind::Ack, task_id, region, None)
            .expect("create obligation");

        let mut oracle = ObligationLeakOracle::new();
        oracle.snapshot_from_state(&state, Time::ZERO);
        oracle.on_region_close(region, Time::ZERO);

        let err = oracle.check(Time::ZERO).expect_err("expected leak");
        let len = err.leaked.len();
        crate::assert_with_log!(len == 1, "leaked len", 1, len);
        let leaked = err.leaked[0].obligation;
        crate::assert_with_log!(leaked == obl_id, "obligation", obl_id, leaked);
        crate::test_complete!("snapshot_from_state_catches_reserved_obligation");
    }

    #[test]
    fn snapshot_preserves_actual_holder_leaks_after_region_reclamation() {
        use crate::cx::Cx;
        use crate::lab::{LabConfig, LabRuntime};
        use crate::sync::{Mutex, OwnedMutexGuard};
        use std::sync::Arc;

        // Collect the deliberate leak as a report instead of panicking at its
        // producer. The positive, live-reservation phase must still pass.
        let mut lab = LabRuntime::new(
            LabConfig::new(0x29_1ea0)
                .max_steps(128)
                .panic_on_leak(false),
        );
        let root = lab.state.create_root_region(Budget::INFINITE);
        let mutex = Arc::new(Mutex::new(()));
        let guard = mutex.try_lock_owned().unwrap();
        let task_mutex = Arc::clone(&mutex);
        let (holder, mut handle) = lab
            .state
            .create_task(root, Budget::INFINITE, async move {
                let cx = Cx::current().expect("real scheduled obligation holder");
                let first = cx
                    .try_register_obligation_checked(ObligationKind::Ack, cx.task_id())
                    .unwrap()
                    .unwrap();
                let second = cx
                    .try_register_obligation_checked(ObligationKind::Lease, cx.task_id())
                    .unwrap()
                    .unwrap();
                drop(OwnedMutexGuard::lock(task_mutex, &cx).await.unwrap());
                // Returning tokens moves physical ownership through the real join
                // channel; it does not transfer their original holder liability.
                (first, second)
            })
            .unwrap();
        lab.scheduler.lock().schedule(holder, 0);
        lab.run_until_idle();
        assert_eq!(mutex.waiters(), 1);
        assert!(handle.try_join().unwrap().is_none());
        let mut oracle = ObligationLeakOracle::new();
        oracle.snapshot_from_state(&lab.state, Time::ZERO);
        assert_eq!(oracle.obligation_count(), 2);
        assert_eq!(oracle.closed_region_count(), 0);
        assert!(
            oracle.check(Time::ZERO).is_ok(),
            "live reservations are not leaks"
        );
        let mut original_leaks: Vec<_> = lab
            .state
            .obligations_iter()
            .map(|(_, record)| ObligationLeak {
                obligation: record.id,
                kind: record.kind,
                holder: record.holder,
                region: record.region,
            })
            .collect();
        original_leaks.sort_by_key(|leak| leak.obligation);
        let original_ids: Vec<_> = original_leaks.iter().map(|leak| leak.obligation).collect();
        assert_eq!(original_ids.len(), 2);
        assert!(
            original_leaks
                .iter()
                .any(|leak| leak.kind == ObligationKind::Ack)
        );
        assert!(
            original_leaks
                .iter()
                .any(|leak| leak.kind == ObligationKind::Lease)
        );

        drop(guard);
        let report = lab.run_until_quiescent_with_report();
        let (first, second) = handle
            .try_join()
            .unwrap()
            .expect("actual completed task result");
        assert!(lab.state.task(holder).is_none());
        assert_eq!(lab.state.leak_count(), 2);
        assert_eq!(lab.state.pending_obligation_count(), 0);
        assert!(!report.lab_test_passed());
        assert!(
            !report
                .oracle_report
                .entry("obligation_leak")
                .unwrap()
                .passed
        );
        assert!(
            report
                .invariant_violations
                .iter()
                .any(|failure| failure == "oracle:obligation_leak")
        );
        let diagnosed_at = lab
            .state
            .obligation(original_ids[0])
            .unwrap()
            .resolved_at
            .unwrap();
        oracle.snapshot_from_state(&lab.state, Time::from_nanos(999));
        assert_eq!(
            oracle.closed_region_count(),
            0,
            "diagnosis must not fabricate a region close"
        );
        let violation = oracle.check(Time::from_nanos(999)).unwrap_err();
        assert_eq!(violation.region, root);
        assert_eq!(violation.region_close_time, diagnosed_at);
        assert_eq!(violation.leaked, original_leaks);
        assert_eq!(
            violation
                .leaked
                .iter()
                .map(|leak| leak.obligation)
                .collect::<Vec<_>>(),
            original_ids
        );
        assert!(
            violation
                .leaked
                .iter()
                .all(|leak| leak.holder == holder && leak.region == root)
        );

        assert!(lab.state.region(root).unwrap().begin_close(None));
        lab.state.advance_region_state(root);
        assert!(
            lab.state.region(root).is_none(),
            "normal close reclaims the actual region"
        );
        assert!(lab.state.region_was_closed(root));
        oracle.snapshot_from_state(&lab.state, Time::from_nanos(1999));
        assert_eq!(
            oracle.closed_region_count(),
            0,
            "reclaimed record is not a synthesized close event"
        );
        let after_close = oracle.check(Time::from_nanos(1999)).unwrap_err();
        assert_eq!(after_close.leaked, violation.leaked);
        assert_eq!(after_close.region_close_time, diagnosed_at);
        let gateway = lab.state.obligation_gateway().unwrap();
        let mailbox = gateway.mailbox();
        let before = mailbox.stats();
        assert!(
            !first.commit(),
            "the original holder audit already terminalized this token"
        );
        drop(second);
        assert_eq!(mailbox.stats(), before);
        assert_eq!(mailbox.open_tickets(), 0);
        assert_eq!(lab.state.leak_count(), 2);
    }

    #[test]
    fn resolved_obligation_is_not_leak() {
        init_test("resolved_obligation_is_not_leak");
        let mut oracle = ObligationLeakOracle::new();

        let region = test_region(0);
        let task = TaskId::from_arena(ArenaIndex::new(1, 0));
        let obligation = ObligationId::from_arena(ArenaIndex::new(2, 0));

        oracle.on_create(obligation, ObligationKind::Lease, task, region);
        oracle.on_resolve(obligation, ObligationState::Committed);
        oracle.on_region_close(region, Time::ZERO);

        let ok = oracle.check(Time::ZERO).is_ok();
        crate::assert_with_log!(ok, "ok", true, ok);
        crate::test_complete!("resolved_obligation_is_not_leak");
    }

    // Pure data-type tests (wave 12 – CyanBarn)

    #[test]
    fn obligation_leak_display() {
        let region = test_region(0);
        let task = TaskId::from_arena(ArenaIndex::new(1, 0));
        let obligation = ObligationId::from_arena(ArenaIndex::new(2, 0));

        let leak = ObligationLeak {
            obligation,
            kind: ObligationKind::SendPermit,
            holder: task,
            region,
        };
        let display = leak.to_string();
        assert!(display.contains("SendPermit"));
    }

    #[test]
    fn obligation_leak_debug_clone_eq() {
        let region = test_region(0);
        let task = TaskId::from_arena(ArenaIndex::new(1, 0));
        let obligation = ObligationId::from_arena(ArenaIndex::new(2, 0));

        let leak = ObligationLeak {
            obligation,
            kind: ObligationKind::Ack,
            holder: task,
            region,
        };
        let dbg = format!("{leak:?}");
        assert!(dbg.contains("ObligationLeak"));

        let cloned = leak.clone();
        assert_eq!(leak, cloned);
    }

    #[test]
    fn obligation_leak_violation_display_debug_error() {
        let region = test_region(0);
        let task = TaskId::from_arena(ArenaIndex::new(1, 0));
        let obligation = ObligationId::from_arena(ArenaIndex::new(2, 0));

        let violation = ObligationLeakViolation {
            region,
            leaked: vec![ObligationLeak {
                obligation,
                kind: ObligationKind::Lease,
                holder: task,
                region,
            }],
            region_close_time: Time::ZERO,
        };
        let display = violation.to_string();
        assert!(display.contains("leaked=1"));

        let dbg = format!("{violation:?}");
        assert!(dbg.contains("ObligationLeakViolation"));

        // std::error::Error
        let err: &dyn std::error::Error = &violation;
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn obligation_leak_violation_clone() {
        let region = test_region(0);
        let violation = ObligationLeakViolation {
            region,
            leaked: vec![],
            region_close_time: Time::ZERO,
        };
        let cloned = violation;
        assert_eq!(cloned.leaked.len(), 0);
    }

    #[test]
    fn oracle_default_new_counts() {
        let oracle = ObligationLeakOracle::new();
        assert_eq!(oracle.obligation_count(), 0);
        assert_eq!(oracle.closed_region_count(), 0);
    }

    #[test]
    fn oracle_debug() {
        let oracle = ObligationLeakOracle::default();
        let dbg = format!("{oracle:?}");
        assert!(dbg.contains("ObligationLeakOracle"));
    }

    #[test]
    fn oracle_reset() {
        let mut oracle = ObligationLeakOracle::new();
        let region = test_region(0);
        let task = TaskId::from_arena(ArenaIndex::new(1, 0));
        let obligation = ObligationId::from_arena(ArenaIndex::new(2, 0));

        oracle.on_create(obligation, ObligationKind::IoOp, task, region);
        oracle.on_region_close(region, Time::ZERO);
        assert_eq!(oracle.obligation_count(), 1);
        assert_eq!(oracle.closed_region_count(), 1);

        oracle.reset();
        assert_eq!(oracle.obligation_count(), 0);
        assert_eq!(oracle.closed_region_count(), 0);
    }

    #[test]
    fn oracle_no_leaks_without_region_close() {
        let mut oracle = ObligationLeakOracle::new();
        let region = test_region(0);
        let task = TaskId::from_arena(ArenaIndex::new(1, 0));
        let obligation = ObligationId::from_arena(ArenaIndex::new(2, 0));

        oracle.on_create(obligation, ObligationKind::SendPermit, task, region);
        // Don't close the region
        assert!(oracle.check(Time::ZERO).is_ok());
    }

    #[test]
    fn oracle_aborted_not_leaked() {
        let mut oracle = ObligationLeakOracle::new();
        let region = test_region(0);
        let task = TaskId::from_arena(ArenaIndex::new(1, 0));
        let obligation = ObligationId::from_arena(ArenaIndex::new(2, 0));

        oracle.on_create(obligation, ObligationKind::Lease, task, region);
        oracle.on_resolve(obligation, ObligationState::Aborted);
        oracle.on_region_close(region, Time::ZERO);
        assert!(oracle.check(Time::ZERO).is_ok());
    }

    #[test]
    fn oracle_leaked_state_is_reported_as_violation() {
        let mut oracle = ObligationLeakOracle::new();
        let region = test_region(0);
        let task = TaskId::from_arena(ArenaIndex::new(1, 0));
        let obligation = ObligationId::from_arena(ArenaIndex::new(2, 0));

        oracle.on_create(obligation, ObligationKind::Lease, task, region);
        oracle.on_resolve(obligation, ObligationState::Leaked);
        oracle.on_region_close(region, Time::ZERO);

        let err = oracle
            .check(Time::ZERO)
            .expect_err("leaked obligation must still violate the invariant");
        assert_eq!(err.region, region);
        assert_eq!(err.leaked.len(), 1);
        assert_eq!(err.leaked[0].obligation, obligation);
        assert_eq!(err.leaked[0].kind, ObligationKind::Lease);
    }

    #[test]
    fn resolution_after_close_still_violates() {
        let mut oracle = ObligationLeakOracle::new();
        let region = test_region(0);
        let task = TaskId::from_arena(ArenaIndex::new(1, 0));
        let obligation = ObligationId::from_arena(ArenaIndex::new(2, 0));

        oracle.on_create(obligation, ObligationKind::Lease, task, region);
        oracle.on_region_close(region, Time::ZERO);
        oracle.on_resolve(obligation, ObligationState::Committed);

        let err = oracle
            .check(Time::ZERO)
            .expect_err("resolving after close must not erase the violation");
        assert_eq!(err.region, region);
        assert_eq!(err.leaked.len(), 1);
        assert_eq!(err.leaked[0].obligation, obligation);
        assert_eq!(err.leaked[0].kind, ObligationKind::Lease);
    }
}
