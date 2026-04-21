#![allow(clippy::all)]
#![allow(missing_docs)]
//! Regression test for priority scheduler denial of service with cancel priority tasks.

use asupersync::runtime::scheduler::priority::Scheduler;
use asupersync::types::TaskId;

#[test]
fn test_scheduler_dos() {
    let mut sched = Scheduler::new();
    let count = 50_000_u32;

    for i in 0..count {
        sched.schedule(TaskId::new_for_test(i, 0), 10);
    }

    // This will take a long time if pop_with_rng_hint is O(N log N)
    for i in 0_u64..100 {
        sched.pop_with_rng_hint(i);
    }
}
