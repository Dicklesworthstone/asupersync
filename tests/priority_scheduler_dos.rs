//! Regression test for priority scheduler denial of service with cancel priority tasks.

use asupersync::runtime::scheduler::priority::Scheduler;
use asupersync::types::TaskId;

#[test]
fn test_scheduler_dos() {
    let mut sched = Scheduler::new();
    let count = 50_000;
    
    for i in 0..count {
        sched.schedule(TaskId::new_for_test(i as u32, 0), 10);
    }
    
    // This will take a long time if pop_with_rng_hint is O(N log N)
    for i in 0..100 {
        sched.pop_with_rng_hint(i as u64);
    }
}
