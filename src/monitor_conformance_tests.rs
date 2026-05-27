//! Monitor Conformance Test Harness
//!
//! Implements Pattern 4 (Spec-Derived Test Matrix) to verify monitor contracts
//! against the deterministic down notification specification. Tests cover:
//!
//! - Monitor establishment and unique reference generation
//! - Deterministic ordering (DOWN-ORDER) contract
//! - Batch delivery (DOWN-BATCH) contract
//! - Content contract (DOWN-CONTENT)
//! - Region cleanup (DOWN-CLEANUP) contract
//! - Index consistency and synchronization
//! - DownReason mapping and predicates
//! - Monitor removal and lifecycle management

#![allow(dead_code, clippy::vec_init_then_push)]

use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

use crate::monitor::{DownBatch, DownNotification, DownReason, MonitorRef, MonitorSet};
use crate::types::cancel::CancelReason;
use crate::types::outcome::PanicPayload;
use crate::types::{Outcome, RegionId, TaskId, Time};

/// Test verdict for conformance checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TestVerdict {
    Pass,
    Fail(String),
}

/// Test result with metadata.
#[derive(Debug, Clone)]
pub struct ConformanceTestResult {
    pub test_name: &'static str,
    pub requirement_level: RequirementLevel,
    pub category: TestCategory,
    pub verdict: TestVerdict,
}

/// RFC-style requirement levels for coverage tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequirementLevel {
    Must,   // MUST comply
    Should, // SHOULD comply
    May,    // MAY implement
}

/// Test categories for organizational purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestCategory {
    MonitorEstablishment,
    DeterministicOrdering,
    BatchDelivery,
    ContentContract,
    RegionCleanup,
    IndexConsistency,
    ReasonMapping,
    LifecycleManagement,
    ReferenceUniqueness,
}

/// Mock virtual time for deterministic testing.
#[derive(Debug, Clone)]
struct MockTime {
    current: Arc<Mutex<Time>>,
}

impl MockTime {
    fn new() -> Self {
        Self {
            current: Arc::new(Mutex::new(Time::from_nanos(0))),
        }
    }

    fn now(&self) -> Time {
        *self.current.lock().unwrap()
    }

    fn advance_nanos(&self, nanos: u64) {
        let mut current = self.current.lock().unwrap();
        *current = current.saturating_add_nanos(nanos);
    }

    fn set(&self, time: Time) {
        *self.current.lock().unwrap() = time;
    }
}

/// Test utilities for creating TaskId and RegionId.
fn test_task_id(index: u32) -> TaskId {
    TaskId::new_for_test(index, 0)
}

fn test_region_id(index: u32) -> RegionId {
    RegionId::new_for_test(index, 0)
}

/// Main conformance test harness for monitor contracts.
pub struct MonitorConformanceHarness {
    mock_time: MockTime,
    monitor_counter: Arc<AtomicU64>,
}

impl MonitorConformanceHarness {
    /// Create a new monitor conformance test harness.
    pub fn new() -> Self {
        Self {
            mock_time: MockTime::new(),
            monitor_counter: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Run the complete monitor conformance test suite.
    pub fn run_full_suite(&mut self) -> Vec<ConformanceTestResult> {
        let mut results = Vec::new();

        // Monitor Establishment
        results.push(self.test_monitor_establishment());
        results.push(self.test_monitor_ref_uniqueness());
        results.push(self.test_multiple_monitors_same_target());

        // Deterministic Ordering (DOWN-ORDER)
        results.push(self.test_down_order_virtual_time());
        results.push(self.test_down_order_task_id());
        results.push(self.test_down_order_monitor_ref());

        // Batch Delivery (DOWN-BATCH)
        results.push(self.test_batch_sorting());
        results.push(self.test_batch_stable_sort());
        results.push(self.test_empty_batch_handling());

        // Content Contract (DOWN-CONTENT)
        results.push(self.test_notification_content());
        results.push(self.test_monitor_ref_preservation());
        results.push(self.test_monitored_task_preservation());

        // Region Cleanup (DOWN-CLEANUP)
        results.push(self.test_region_cleanup());
        results.push(self.test_region_cleanup_isolation());
        results.push(self.test_cleanup_returns_removed_refs());

        // Index Consistency
        results.push(self.test_index_synchronization());
        results.push(self.test_demonitor_consistency());
        results.push(self.test_remove_monitored_consistency());

        // Reason Mapping
        results.push(self.test_down_reason_from_outcome());
        results.push(self.test_down_reason_predicates());
        results.push(self.test_down_reason_display());

        // Lifecycle Management
        results.push(self.test_watchers_of_lookup());
        results.push(self.test_monitor_removal());
        results.push(self.test_termination_cleanup());

        results
    }

    /// Test basic monitor establishment contract.
    fn test_monitor_establishment(&mut self) -> ConformanceTestResult {
        // MUST: establish() creates monitor relationship and returns unique MonitorRef
        let mut monitor_set = MonitorSet::new();
        let watcher = test_task_id(1);
        let region = test_region_id(1);
        let monitored = test_task_id(2);

        let monitor_ref = monitor_set.establish(watcher, region, monitored);

        let is_valid_ref = monitor_ref.id() > 0;
        let can_lookup_watcher = monitor_set.watcher_of(monitor_ref) == Some(watcher);
        let can_lookup_monitored = monitor_set.monitored_of(monitor_ref) == Some(monitored);

        let verdict = if is_valid_ref && can_lookup_watcher && can_lookup_monitored {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail(format!(
                "Monitor establishment failed: valid_ref={}, watcher_lookup={}, monitored_lookup={}",
                is_valid_ref, can_lookup_watcher, can_lookup_monitored
            ))
        };

        ConformanceTestResult {
            test_name: "monitor_establishment",
            requirement_level: RequirementLevel::Must,
            category: TestCategory::MonitorEstablishment,
            verdict,
        }
    }

    /// Test MonitorRef uniqueness across multiple establishments.
    fn test_monitor_ref_uniqueness(&mut self) -> ConformanceTestResult {
        // MUST: Each establish() call returns unique MonitorRef
        let mut monitor_set = MonitorSet::new();
        let watcher1 = test_task_id(1);
        let watcher2 = test_task_id(2);
        let region = test_region_id(1);
        let monitored = test_task_id(3);

        let ref1 = monitor_set.establish(watcher1, region, monitored);
        let ref2 = monitor_set.establish(watcher2, region, monitored);
        let ref3 = monitor_set.establish(watcher1, region, monitored); // Same watcher, different ref

        let all_unique = ref1 != ref2 && ref2 != ref3 && ref1 != ref3;
        let monotonic_increasing = ref1.id() < ref2.id() && ref2.id() < ref3.id();

        let verdict = if all_unique && monotonic_increasing {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail(format!(
                "MonitorRef uniqueness failed: unique={}, monotonic={}",
                all_unique, monotonic_increasing
            ))
        };

        ConformanceTestResult {
            test_name: "monitor_ref_uniqueness",
            requirement_level: RequirementLevel::Must,
            category: TestCategory::ReferenceUniqueness,
            verdict,
        }
    }

    /// Test multiple monitors on same target.
    fn test_multiple_monitors_same_target(&mut self) -> ConformanceTestResult {
        // MUST: Multiple watchers can monitor same target
        let mut monitor_set = MonitorSet::new();
        let region = test_region_id(1);
        let monitored = test_task_id(1);
        let watcher1 = test_task_id(2);
        let watcher2 = test_task_id(3);

        let ref1 = monitor_set.establish(watcher1, region, monitored);
        let ref2 = monitor_set.establish(watcher2, region, monitored);

        let watchers = monitor_set.watchers_of(monitored);
        let has_both_watchers = watchers.len() == 2;
        let contains_watcher1 = watchers.iter().any(|(r, w)| *r == ref1 && *w == watcher1);
        let contains_watcher2 = watchers.iter().any(|(r, w)| *r == ref2 && *w == watcher2);

        let verdict = if has_both_watchers && contains_watcher1 && contains_watcher2 {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail(format!(
                "Multiple monitors failed: count={}, has_w1={}, has_w2={}",
                watchers.len(),
                contains_watcher1,
                contains_watcher2
            ))
        };

        ConformanceTestResult {
            test_name: "multiple_monitors_same_target",
            requirement_level: RequirementLevel::Must,
            category: TestCategory::MonitorEstablishment,
            verdict,
        }
    }

    /// Test DOWN-ORDER contract: virtual time first.
    fn test_down_order_virtual_time(&mut self) -> ConformanceTestResult {
        // MUST: Notifications sorted by (completion_vt, monitored_tid, monitor_ref)
        let mut batch = DownBatch::new();
        let task1 = test_task_id(1);
        let task2 = test_task_id(2);
        let ref1 = MonitorRef::new_for_test(1);
        let ref2 = MonitorRef::new_for_test(2);

        // Add in reverse time order
        batch.push(
            Time::from_nanos(200),
            DownNotification {
                monitored: task2,
                reason: DownReason::Normal,
                monitor_ref: ref2,
            },
        );
        batch.push(
            Time::from_nanos(100),
            DownNotification {
                monitored: task1,
                reason: DownReason::Normal,
                monitor_ref: ref1,
            },
        );

        let sorted = batch.into_sorted();

        // Earlier virtual time should come first
        let correct_order = sorted[0].monitored == task1 && sorted[1].monitored == task2;

        let verdict = if correct_order {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail(format!(
                "Virtual time ordering failed: first={:?}, second={:?}",
                sorted[0].monitored, sorted[1].monitored
            ))
        };

        ConformanceTestResult {
            test_name: "down_order_virtual_time",
            requirement_level: RequirementLevel::Must,
            category: TestCategory::DeterministicOrdering,
            verdict,
        }
    }

    /// Test DOWN-ORDER contract: TaskId secondary sort.
    fn test_down_order_task_id(&mut self) -> ConformanceTestResult {
        // MUST: When virtual times equal, sort by monitored TaskId
        let mut batch = DownBatch::new();
        let time = Time::from_nanos(100);
        let task1 = test_task_id(1);
        let task2 = test_task_id(2);
        let ref1 = MonitorRef::new_for_test(1);

        // Same time, different tasks - add in reverse order
        batch.push(
            time,
            DownNotification {
                monitored: task2, // Higher TaskId
                reason: DownReason::Normal,
                monitor_ref: ref1,
            },
        );
        batch.push(
            time,
            DownNotification {
                monitored: task1, // Lower TaskId
                reason: DownReason::Normal,
                monitor_ref: ref1,
            },
        );

        let sorted = batch.into_sorted();

        // Lower TaskId should come first
        let correct_order = sorted[0].monitored == task1 && sorted[1].monitored == task2;

        let verdict = if correct_order {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail(format!(
                "TaskId ordering failed: first={:?}, second={:?}",
                sorted[0].monitored, sorted[1].monitored
            ))
        };

        ConformanceTestResult {
            test_name: "down_order_task_id",
            requirement_level: RequirementLevel::Must,
            category: TestCategory::DeterministicOrdering,
            verdict,
        }
    }

    /// Test DOWN-ORDER contract: MonitorRef tertiary sort.
    fn test_down_order_monitor_ref(&mut self) -> ConformanceTestResult {
        // MUST: When time and TaskId equal, sort by MonitorRef
        let mut batch = DownBatch::new();
        let time = Time::from_nanos(100);
        let task = test_task_id(1);
        let ref1 = MonitorRef::new_for_test(1);
        let ref2 = MonitorRef::new_for_test(2);

        // Same time and task, different refs - add in reverse order
        batch.push(
            time,
            DownNotification {
                monitored: task,
                reason: DownReason::Normal,
                monitor_ref: ref2, // Higher ref
            },
        );
        batch.push(
            time,
            DownNotification {
                monitored: task,
                reason: DownReason::Normal,
                monitor_ref: ref1, // Lower ref
            },
        );

        let sorted = batch.into_sorted();

        // Lower MonitorRef should come first
        let correct_order = sorted[0].monitor_ref == ref1 && sorted[1].monitor_ref == ref2;

        let verdict = if correct_order {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail(format!(
                "MonitorRef ordering failed: first={:?}, second={:?}",
                sorted[0].monitor_ref, sorted[1].monitor_ref
            ))
        };

        ConformanceTestResult {
            test_name: "down_order_monitor_ref",
            requirement_level: RequirementLevel::Must,
            category: TestCategory::DeterministicOrdering,
            verdict,
        }
    }

    /// Test batch sorting preserves stable sort property.
    fn test_batch_stable_sort(&mut self) -> ConformanceTestResult {
        // MUST: Sort is stable - equal items preserve insertion order
        let mut batch = DownBatch::new();
        let time = Time::from_nanos(100);
        let task = test_task_id(1);
        let monitor_ref = MonitorRef::new_for_test(1);

        // Add identical notifications - should preserve insertion order
        batch.push(
            time,
            DownNotification {
                monitored: task,
                reason: DownReason::Error("first".into()),
                monitor_ref,
            },
        );
        batch.push(
            time,
            DownNotification {
                monitored: task,
                reason: DownReason::Error("second".into()),
                monitor_ref,
            },
        );

        let sorted = batch.into_sorted();

        // Insertion order should be preserved (stable sort)
        let stable_order = matches!(&sorted[0].reason, DownReason::Error(msg) if msg == "first")
            && matches!(&sorted[1].reason, DownReason::Error(msg) if msg == "second");

        let verdict = if stable_order {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail("Stable sort property violated".into())
        };

        ConformanceTestResult {
            test_name: "batch_stable_sort",
            requirement_level: RequirementLevel::Must,
            category: TestCategory::BatchDelivery,
            verdict,
        }
    }

    /// Test batch sorting operation.
    fn test_batch_sorting(&mut self) -> ConformanceTestResult {
        // MUST: Batch sorting works correctly with multiple criteria
        let mut batch = DownBatch::new();
        let task = test_task_id(1);
        let monitor_ref = MonitorRef::new_for_test(1);

        // Add notifications
        batch.push(
            Time::from_nanos(100),
            DownNotification {
                monitored: task,
                reason: DownReason::Normal,
                monitor_ref,
            },
        );

        let sorted = batch.into_sorted();
        let correct_length = sorted.len() == 1;
        let correct_content = sorted[0].monitored == task;

        let verdict = if correct_length && correct_content {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail("Batch sorting failed".into())
        };

        ConformanceTestResult {
            test_name: "batch_sorting",
            requirement_level: RequirementLevel::Must,
            category: TestCategory::BatchDelivery,
            verdict,
        }
    }

    /// Test empty batch handling.
    fn test_empty_batch_handling(&mut self) -> ConformanceTestResult {
        // MUST: Empty batch produces empty sorted result
        let batch = DownBatch::new();

        let is_empty = batch.is_empty();
        let zero_len = batch.len() == 0;
        let sorted = batch.into_sorted();
        let sorted_empty = sorted.is_empty();

        let verdict = if is_empty && zero_len && sorted_empty {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail("Empty batch handling failed".into())
        };

        ConformanceTestResult {
            test_name: "empty_batch_handling",
            requirement_level: RequirementLevel::Must,
            category: TestCategory::BatchDelivery,
            verdict,
        }
    }

    /// Test DOWN-CONTENT contract.
    fn test_notification_content(&mut self) -> ConformanceTestResult {
        // MUST: Notifications contain monitored TaskId, reason, and MonitorRef
        let notification = DownNotification {
            monitored: test_task_id(42),
            reason: DownReason::Error("test error".into()),
            monitor_ref: MonitorRef::new_for_test(123),
        };

        let correct_task = notification.monitored == test_task_id(42);
        let correct_reason =
            matches!(&notification.reason, DownReason::Error(msg) if msg == "test error");
        let correct_ref = notification.monitor_ref.id() == 123;

        let verdict = if correct_task && correct_reason && correct_ref {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail("Notification content validation failed".into())
        };

        ConformanceTestResult {
            test_name: "notification_content",
            requirement_level: RequirementLevel::Must,
            category: TestCategory::ContentContract,
            verdict,
        }
    }

    /// Test monitor ref preservation in notifications.
    fn test_monitor_ref_preservation(&mut self) -> ConformanceTestResult {
        // MUST: MonitorRef from establishment preserved in notifications
        let mut monitor_set = MonitorSet::new();
        let watcher = test_task_id(1);
        let region = test_region_id(1);
        let monitored = test_task_id(2);

        let monitor_ref = monitor_set.establish(watcher, region, monitored);
        let watchers = monitor_set.watchers_of(monitored);

        let ref_preserved = watchers.iter().any(|(r, _)| *r == monitor_ref);

        let verdict = if ref_preserved {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail("MonitorRef not preserved in watcher lookup".into())
        };

        ConformanceTestResult {
            test_name: "monitor_ref_preservation",
            requirement_level: RequirementLevel::Must,
            category: TestCategory::ContentContract,
            verdict,
        }
    }

    /// Test monitored task preservation.
    fn test_monitored_task_preservation(&mut self) -> ConformanceTestResult {
        // MUST: Monitored TaskId correctly preserved and accessible
        let mut monitor_set = MonitorSet::new();
        let watcher = test_task_id(1);
        let region = test_region_id(1);
        let monitored = test_task_id(42);

        let monitor_ref = monitor_set.establish(watcher, region, monitored);
        let retrieved_monitored = monitor_set.monitored_of(monitor_ref);

        let verdict = if retrieved_monitored == Some(monitored) {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail(format!(
                "Monitored task not preserved: expected={:?}, got={:?}",
                Some(monitored),
                retrieved_monitored
            ))
        };

        ConformanceTestResult {
            test_name: "monitored_task_preservation",
            requirement_level: RequirementLevel::Must,
            category: TestCategory::ContentContract,
            verdict,
        }
    }

    /// Test DOWN-CLEANUP contract: region cleanup.
    fn test_region_cleanup(&mut self) -> ConformanceTestResult {
        // MUST: cleanup_region() removes all monitors from specified region
        let mut monitor_set = MonitorSet::new();
        let region1 = test_region_id(1);
        let region2 = test_region_id(2);
        let monitored = test_task_id(1);

        let ref1 = monitor_set.establish(test_task_id(10), region1, monitored);
        let ref2 = monitor_set.establish(test_task_id(20), region2, monitored);
        let ref3 = monitor_set.establish(test_task_id(30), region1, monitored);

        let removed = monitor_set.cleanup_region(region1);

        let correct_removal_count = removed.len() == 2;
        let contains_ref1 = removed.contains(&ref1);
        let contains_ref3 = removed.contains(&ref3);
        let no_ref2 = !removed.contains(&ref2);
        let region2_still_monitored = monitor_set.watcher_of(ref2).is_some();

        let verdict = if correct_removal_count
            && contains_ref1
            && contains_ref3
            && no_ref2
            && region2_still_monitored
        {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail(format!(
                "Region cleanup failed: removed_count={}, has_ref1={}, has_ref3={}, no_ref2={}, region2_active={}",
                removed.len(),
                contains_ref1,
                contains_ref3,
                no_ref2,
                region2_still_monitored
            ))
        };

        ConformanceTestResult {
            test_name: "region_cleanup",
            requirement_level: RequirementLevel::Must,
            category: TestCategory::RegionCleanup,
            verdict,
        }
    }

    /// Test region cleanup isolation.
    fn test_region_cleanup_isolation(&mut self) -> ConformanceTestResult {
        // MUST: Region cleanup only affects specified region
        let mut monitor_set = MonitorSet::new();
        let region1 = test_region_id(1);
        let region2 = test_region_id(2);

        let ref1 = monitor_set.establish(test_task_id(1), region1, test_task_id(10));
        let ref2 = monitor_set.establish(test_task_id(2), region2, test_task_id(20));

        let initial_count = monitor_set.len();
        monitor_set.cleanup_region(region1);
        let after_cleanup_count = monitor_set.len();

        let correct_removal = initial_count == 2 && after_cleanup_count == 1;
        let region1_removed = monitor_set.watcher_of(ref1).is_none();
        let region2_preserved = monitor_set.watcher_of(ref2).is_some();

        let verdict = if correct_removal && region1_removed && region2_preserved {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail("Region cleanup isolation failed".into())
        };

        ConformanceTestResult {
            test_name: "region_cleanup_isolation",
            requirement_level: RequirementLevel::Must,
            category: TestCategory::RegionCleanup,
            verdict,
        }
    }

    /// Test cleanup returns removed refs.
    fn test_cleanup_returns_removed_refs(&mut self) -> ConformanceTestResult {
        // MUST: cleanup_region() returns list of removed MonitorRefs
        let mut monitor_set = MonitorSet::new();
        let region = test_region_id(1);

        let ref1 = monitor_set.establish(test_task_id(1), region, test_task_id(10));
        let ref2 = monitor_set.establish(test_task_id(2), region, test_task_id(20));

        let removed = monitor_set.cleanup_region(region);

        let correct_count = removed.len() == 2;
        let contains_both = removed.contains(&ref1) && removed.contains(&ref2);

        let verdict = if correct_count && contains_both {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail("Cleanup removed refs validation failed".into())
        };

        ConformanceTestResult {
            test_name: "cleanup_returns_removed_refs",
            requirement_level: RequirementLevel::Must,
            category: TestCategory::RegionCleanup,
            verdict,
        }
    }

    /// Test index synchronization across operations.
    fn test_index_synchronization(&mut self) -> ConformanceTestResult {
        // MUST: All three indexes stay synchronized during operations
        let mut monitor_set = MonitorSet::new();
        let watcher = test_task_id(1);
        let region = test_region_id(1);
        let monitored = test_task_id(2);

        let monitor_ref = monitor_set.establish(watcher, region, monitored);

        // Check all indexes have the monitor
        let has_by_ref = monitor_set.watcher_of(monitor_ref).is_some();
        let has_by_monitored = !monitor_set.watchers_of(monitored).is_empty();
        let has_consistent_lookup = monitor_set.watcher_of(monitor_ref) == Some(watcher);

        let verdict = if has_by_ref && has_by_monitored && has_consistent_lookup {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail("Index synchronization failed".into())
        };

        ConformanceTestResult {
            test_name: "index_synchronization",
            requirement_level: RequirementLevel::Must,
            category: TestCategory::IndexConsistency,
            verdict,
        }
    }

    /// Test demonitor index consistency.
    fn test_demonitor_consistency(&mut self) -> ConformanceTestResult {
        // MUST: demonitor() maintains index consistency
        let mut monitor_set = MonitorSet::new();
        let watcher = test_task_id(1);
        let region = test_region_id(1);
        let monitored = test_task_id(2);

        let monitor_ref = monitor_set.establish(watcher, region, monitored);
        let removed = monitor_set.demonitor(monitor_ref);

        let was_removed = removed;
        let no_by_ref = monitor_set.watcher_of(monitor_ref).is_none();
        let no_by_monitored = monitor_set.watchers_of(monitored).is_empty();

        let verdict = if was_removed && no_by_ref && no_by_monitored {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail("Demonitor consistency failed".into())
        };

        ConformanceTestResult {
            test_name: "demonitor_consistency",
            requirement_level: RequirementLevel::Must,
            category: TestCategory::IndexConsistency,
            verdict,
        }
    }

    /// Test remove_monitored index consistency.
    fn test_remove_monitored_consistency(&mut self) -> ConformanceTestResult {
        // MUST: remove_monitored() maintains index consistency
        let mut monitor_set = MonitorSet::new();
        let monitored = test_task_id(1);

        let ref1 = monitor_set.establish(test_task_id(10), test_region_id(1), monitored);
        let ref2 = monitor_set.establish(test_task_id(20), test_region_id(2), monitored);

        let removed = monitor_set.remove_monitored(monitored);

        let correct_count = removed.len() == 2;
        let contains_both = removed.contains(&ref1) && removed.contains(&ref2);
        let no_watchers = monitor_set.watchers_of(monitored).is_empty();
        let no_ref_lookup =
            monitor_set.watcher_of(ref1).is_none() && monitor_set.watcher_of(ref2).is_none();

        let verdict = if correct_count && contains_both && no_watchers && no_ref_lookup {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail("Remove monitored consistency failed".into())
        };

        ConformanceTestResult {
            test_name: "remove_monitored_consistency",
            requirement_level: RequirementLevel::Must,
            category: TestCategory::IndexConsistency,
            verdict,
        }
    }

    /// Test DownReason mapping from Outcome.
    fn test_down_reason_from_outcome(&mut self) -> ConformanceTestResult {
        // MUST: DownReason correctly maps from task outcomes
        let normal = DownReason::from_task_outcome(&Outcome::Ok(()));
        let error = DownReason::from_task_outcome(&Outcome::Err(
            crate::error::Error::new(crate::error::ErrorKind::InvalidStateTransition)
                .with_message("test"),
        ));
        let cancelled = DownReason::from_task_outcome(&Outcome::Cancelled(CancelReason::default()));
        let panicked = DownReason::from_task_outcome(&Outcome::Panicked(PanicPayload::new("test")));

        let correct_normal = matches!(normal, DownReason::Normal);
        let correct_error = matches!(error, DownReason::Error(_));
        let correct_cancelled = matches!(cancelled, DownReason::Cancelled(_));
        let correct_panicked = matches!(panicked, DownReason::Panicked(_));

        let verdict = if correct_normal && correct_error && correct_cancelled && correct_panicked {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail("DownReason mapping failed".into())
        };

        ConformanceTestResult {
            test_name: "down_reason_from_outcome",
            requirement_level: RequirementLevel::Must,
            category: TestCategory::ReasonMapping,
            verdict,
        }
    }

    /// Test DownReason predicate methods.
    fn test_down_reason_predicates(&mut self) -> ConformanceTestResult {
        // MUST: DownReason predicate methods work correctly
        let normal = DownReason::Normal;
        let error = DownReason::Error("test".into());
        let cancelled = DownReason::Cancelled(CancelReason::default());
        let panicked = DownReason::Panicked(PanicPayload::new("test"));

        let normal_checks = normal.is_normal()
            && !normal.is_error()
            && !normal.is_cancelled()
            && !normal.is_panicked();
        let error_checks =
            !error.is_normal() && error.is_error() && !error.is_cancelled() && !error.is_panicked();
        let cancelled_checks = !cancelled.is_normal()
            && !cancelled.is_error()
            && cancelled.is_cancelled()
            && !cancelled.is_panicked();
        let panicked_checks = !panicked.is_normal()
            && !panicked.is_error()
            && !panicked.is_cancelled()
            && panicked.is_panicked();

        let verdict = if normal_checks && error_checks && cancelled_checks && panicked_checks {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail("DownReason predicates failed".into())
        };

        ConformanceTestResult {
            test_name: "down_reason_predicates",
            requirement_level: RequirementLevel::Must,
            category: TestCategory::ReasonMapping,
            verdict,
        }
    }

    /// Test DownReason display formatting.
    fn test_down_reason_display(&mut self) -> ConformanceTestResult {
        // SHOULD: DownReason display formatting is informative
        let normal = format!("{}", DownReason::Normal);
        let error = format!("{}", DownReason::Error("test error".into()));

        let normal_ok = normal.contains("normal");
        let error_ok = error.contains("error") && error.contains("test error");

        let verdict = if normal_ok && error_ok {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail("DownReason display formatting failed".into())
        };

        ConformanceTestResult {
            test_name: "down_reason_display",
            requirement_level: RequirementLevel::Should,
            category: TestCategory::ReasonMapping,
            verdict,
        }
    }

    /// Test watchers_of lookup functionality.
    fn test_watchers_of_lookup(&mut self) -> ConformanceTestResult {
        // MUST: watchers_of() returns all monitors watching a task
        let mut monitor_set = MonitorSet::new();
        let monitored = test_task_id(1);
        let watcher1 = test_task_id(2);
        let watcher2 = test_task_id(3);
        let region = test_region_id(1);

        let ref1 = monitor_set.establish(watcher1, region, monitored);
        let ref2 = monitor_set.establish(watcher2, region, monitored);

        let watchers = monitor_set.watchers_of(monitored);

        let correct_count = watchers.len() == 2;
        let has_watcher1 = watchers.iter().any(|(r, w)| *r == ref1 && *w == watcher1);
        let has_watcher2 = watchers.iter().any(|(r, w)| *r == ref2 && *w == watcher2);

        let verdict = if correct_count && has_watcher1 && has_watcher2 {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail("watchers_of lookup failed".into())
        };

        ConformanceTestResult {
            test_name: "watchers_of_lookup",
            requirement_level: RequirementLevel::Must,
            category: TestCategory::LifecycleManagement,
            verdict,
        }
    }

    /// Test individual monitor removal.
    fn test_monitor_removal(&mut self) -> ConformanceTestResult {
        // MUST: demonitor() removes specific monitor
        let mut monitor_set = MonitorSet::new();
        let watcher = test_task_id(1);
        let region = test_region_id(1);
        let monitored = test_task_id(2);

        let monitor_ref = monitor_set.establish(watcher, region, monitored);
        let initial_count = monitor_set.len();
        let removed = monitor_set.demonitor(monitor_ref);
        let final_count = monitor_set.len();

        let was_removed = removed;
        let count_decreased = final_count == initial_count - 1;
        let no_longer_exists = monitor_set.watcher_of(monitor_ref).is_none();

        let verdict = if was_removed && count_decreased && no_longer_exists {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail("Monitor removal failed".into())
        };

        ConformanceTestResult {
            test_name: "monitor_removal",
            requirement_level: RequirementLevel::Must,
            category: TestCategory::LifecycleManagement,
            verdict,
        }
    }

    /// Test termination cleanup workflow.
    fn test_termination_cleanup(&mut self) -> ConformanceTestResult {
        // MUST: remove_monitored() removes all monitors of terminated task
        let mut monitor_set = MonitorSet::new();
        let terminated_task = test_task_id(1);
        let other_task = test_task_id(2);

        monitor_set.establish(test_task_id(10), test_region_id(1), terminated_task);
        monitor_set.establish(test_task_id(20), test_region_id(2), terminated_task);
        let other_ref = monitor_set.establish(test_task_id(30), test_region_id(3), other_task);

        let initial_count = monitor_set.len();
        let removed = monitor_set.remove_monitored(terminated_task);
        let final_count = monitor_set.len();

        let correct_removal_count = removed.len() == 2;
        let correct_total_count = final_count == initial_count - 2;
        let no_watchers_left = monitor_set.watchers_of(terminated_task).is_empty();
        let other_task_unaffected = monitor_set.watcher_of(other_ref).is_some();

        let verdict = if correct_removal_count
            && correct_total_count
            && no_watchers_left
            && other_task_unaffected
        {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail("Termination cleanup failed".into())
        };

        ConformanceTestResult {
            test_name: "termination_cleanup",
            requirement_level: RequirementLevel::Must,
            category: TestCategory::LifecycleManagement,
            verdict,
        }
    }
}

impl Default for MonitorConformanceHarness {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conformance_harness_creation() {
        let harness = MonitorConformanceHarness::new();
        assert_eq!(harness.mock_time.now(), Time::from_nanos(0));
    }

    #[test]
    fn mock_time_advancement() {
        let mock_time = MockTime::new();
        let initial = mock_time.now();

        mock_time.advance_nanos(1000);
        let after = mock_time.now();

        assert!(after > initial);
        assert_eq!(after.as_nanos(), 1000);
    }

    #[test]
    fn test_task_creation() {
        let task1 = test_task_id(1);
        let task2 = test_task_id(2);
        assert_ne!(task1, task2);
    }

    #[test]
    fn test_verdict_types() {
        let pass = TestVerdict::Pass;
        let fail = TestVerdict::Fail("error".into());

        assert_eq!(pass, TestVerdict::Pass);
        assert_ne!(pass, fail);
    }

    #[test]
    fn conformance_result_structure() {
        let result = ConformanceTestResult {
            test_name: "test",
            requirement_level: RequirementLevel::Must,
            category: TestCategory::MonitorEstablishment,
            verdict: TestVerdict::Pass,
        };

        assert_eq!(result.test_name, "test");
        assert_eq!(result.requirement_level, RequirementLevel::Must);
        assert_eq!(result.category, TestCategory::MonitorEstablishment);
        assert_eq!(result.verdict, TestVerdict::Pass);
    }
}
