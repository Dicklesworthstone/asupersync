//! Regression test for bulkhead queued-entry cancellation.

use asupersync::combinator::bulkhead::{Bulkhead, BulkheadPolicy};
use asupersync::types::Time;

#[test]
fn cancelling_head_of_line_waiter_unblocks_next_queued_entry() {
    let bh = Bulkhead::new(BulkheadPolicy {
        max_concurrent: 10,
        max_queue: 10,
        ..Default::default()
    });
    let now = Time::from_millis(0);

    let _blocking_permit = bh.try_acquire(7).unwrap();

    let a_id = bh.enqueue(5, now).unwrap();
    let b_id = bh.enqueue(2, now).unwrap();

    assert_eq!(bh.process_queue(now), None);

    assert!(matches!(bh.check_entry(a_id, now), Ok(None)));
    assert!(matches!(bh.check_entry(b_id, now), Ok(None)));
    assert_eq!(bh.metrics().queue_depth, 2);

    bh.cancel_entry(a_id, now);

    let b_permit = bh
        .check_entry(b_id, now)
        .expect("B should still be tracked")
        .expect("B should be granted after A is cancelled");
    assert_eq!(b_permit.weight(), 2);
    assert_eq!(bh.available(), 1);

    let metrics = bh.metrics();
    assert_eq!(metrics.queue_depth, 0);
    assert_eq!(metrics.total_cancelled, 1);

    drop(b_permit);
    assert_eq!(bh.available(), 3);
}
